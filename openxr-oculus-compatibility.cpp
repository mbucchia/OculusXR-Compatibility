#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>

#define XR_NO_PROTOTYPES
#include <openxr/openxr.h>
#include "loader_interfaces.h"

namespace {
    const std::string LayerName = "XR_APILAYER_VIRTUALDESKTOP_oculus_compatibility";

    struct Instance {
        std::string applicationName;
        std::string exeName;
        PFN_xrGetInstanceProcAddr nextGetInstanceProcAddr{nullptr};
        PFN_xrGetInstanceProperties nextGetInstanceProperties{nullptr};
        PFN_xrGetSystemProperties nextGetSystemProperties{nullptr};
    };

    std::mutex g_instancesMutex;
    std::unordered_map<XrInstance, Instance> g_instances;

    // https://stackoverflow.com/questions/865152/how-can-i-get-a-process-handle-by-its-name-in-c
    bool IsServiceRunning(const std::wstring_view& name) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);

        bool found = false;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (Process32First(snapshot, &entry) == TRUE) {
            while (Process32Next(snapshot, &entry) == TRUE) {
                if (std::wstring_view(entry.szExeFile) == name) {
                    found = true;
                    break;
                }
            }
        }
        CloseHandle(snapshot);

        return found;
    }

    // https://www.khronos.org/registry/OpenXR/specs/1.0/html/xrspec.html#xrGetInstanceProperties
    XrResult xrGetInstanceProperties(XrInstance instance, XrInstanceProperties* instanceProperties) {
        PFN_xrGetInstanceProperties nextGetInstanceProperties = nullptr;
        std::string applicationName;
        std::string exeName;
        {
            std::unique_lock lock(g_instancesMutex);
            const auto it = g_instances.find(instance);
            if (it != g_instances.cend()) {
                nextGetInstanceProperties = it->second.nextGetInstanceProperties;
                applicationName = it->second.applicationName;
                exeName = it->second.exeName;
            }
        }
        if (!nextGetInstanceProperties) {
            return XR_ERROR_INSTANCE_LOST;
        }

        // Chain the call to the next implementation.
        const XrResult result = nextGetInstanceProperties(instance, instanceProperties);

        // The OculusXR Plugin only loads successfully when the returned OpenXR runtime name is "Oculus". We fake that
        // if the caller is the OculusXR Plugin, but we return the real runtime name otherwise.
        // Some games (like 7th Guest VR) do not play well when forcing the runtime name, so we exclude them.
        if (XR_SUCCEEDED(result)) {
            const bool needOculusXrPluginWorkaround =
                applicationName.find("Oculus VR Plugin") == 0 && exeName != "The7thGuestVR-Win64-Shipping.exe";
            if (needOculusXrPluginWorkaround) {
                sprintf_s(instanceProperties->runtimeName, sizeof(instanceProperties->runtimeName), "Oculus");
            }
        }

        return result;
    }

    // https://www.khronos.org/registry/OpenXR/specs/1.0/html/xrspec.html#xrGetSystemProperties
    XrResult xrGetSystemProperties(XrInstance instance, XrSystemId systemId, XrSystemProperties* properties) {
        PFN_xrGetSystemProperties nextGetSystemProperties = nullptr;
        PFN_xrGetInstanceProperties nextGetInstanceProperties = nullptr;
        {
            std::unique_lock lock(g_instancesMutex);
            const auto it = g_instances.find(instance);
            if (it != g_instances.cend()) {
                nextGetSystemProperties = it->second.nextGetSystemProperties;
                nextGetInstanceProperties = it->second.nextGetInstanceProperties;
            }
        }
        if (!nextGetSystemProperties || !nextGetInstanceProperties) {
            return XR_ERROR_INSTANCE_LOST;
        }

        // Chain the call to the next implementation.
        const XrResult result = nextGetSystemProperties(instance, systemId, properties);

        // When Virtual Desktop is used with SteamVR, we force un-advertise the hand joints capability.
        if (XR_SUCCEEDED(result)) {
            // We can cache whether the service is running, because even if the application is polling xrGetSystem() and
            // the XrSystem in use could technically change over time, it would require a restart of SteamVR, and taking
            // down the XrInstance.
            static const bool isVirtualDesktopServiceRunning = IsServiceRunning(L"VirtualDesktop.Server.exe");

            // We do not want this override behavior with VDXR, since it may correctly support hand joints in the
            // future. So we check for SteamVR.
            XrInstanceProperties instanceProperties{XR_TYPE_INSTANCE_PROPERTIES};
            // We intentionally allow this call to fail for robnustness.
            nextGetInstanceProperties(instance, &instanceProperties);
            const std::string_view runtimeName(instanceProperties.runtimeName);
            const bool isSteamVR = runtimeName == "SteamVR/OpenXR";

            if (isSteamVR && isVirtualDesktopServiceRunning) {
                XrSystemHandTrackingPropertiesEXT* handTrackingProperties =
                    reinterpret_cast<XrSystemHandTrackingPropertiesEXT*>(properties->next);
                while (handTrackingProperties) {
                    if (handTrackingProperties->type == XR_TYPE_SYSTEM_HAND_TRACKING_PROPERTIES_EXT) {
                        break;
                    }
                    handTrackingProperties =
                        reinterpret_cast<XrSystemHandTrackingPropertiesEXT*>(handTrackingProperties->next);
                }

                if (handTrackingProperties) {
                    handTrackingProperties->supportsHandTracking = XR_FALSE;
                }
            }
        }

        return result;
    }

    // Entry point for OpenXR calls.
    XrResult xrGetInstanceProcAddr(const XrInstance instance,
                                   const char* const name,
                                   PFN_xrVoidFunction* const function) {
        PFN_xrGetInstanceProcAddr nextGetInstanceProcAddr = nullptr;
        {
            std::unique_lock lock(g_instancesMutex);
            const auto it = g_instances.find(instance);
            if (it != g_instances.cend()) {
                nextGetInstanceProcAddr = it->second.nextGetInstanceProcAddr;
            }
        }
        if (!nextGetInstanceProcAddr) {
            return XR_ERROR_INSTANCE_LOST;
        }

        // Call the chain to resolve the next function pointer.
        const XrResult result = nextGetInstanceProcAddr(instance, name, function);
        if (XR_SUCCEEDED(result)) {
            const std::string_view apiName(name);

            // Intercept the calls handled by our layer.
            if (apiName == "xrGetInstanceProperties") {
                *function = reinterpret_cast<PFN_xrVoidFunction>(xrGetInstanceProperties);
            } else if (apiName == "xrGetSystemProperties") {
                *function = reinterpret_cast<PFN_xrVoidFunction>(xrGetSystemProperties);
            }

            // Leave all unhandled calls to the next layer.
        }

        return result;
    }

    // Entry point for creating the layer.
    XrResult xrCreateApiLayerInstance(const XrInstanceCreateInfo* const instanceCreateInfo,
                                      const struct XrApiLayerCreateInfo* const apiLayerInfo,
                                      XrInstance* const instance) {
        if (!apiLayerInfo || apiLayerInfo->structType != XR_LOADER_INTERFACE_STRUCT_API_LAYER_CREATE_INFO ||
            apiLayerInfo->structVersion != XR_API_LAYER_CREATE_INFO_STRUCT_VERSION ||
            apiLayerInfo->structSize != sizeof(XrApiLayerCreateInfo) || !apiLayerInfo->nextInfo ||
            apiLayerInfo->nextInfo->structType != XR_LOADER_INTERFACE_STRUCT_API_LAYER_NEXT_INFO ||
            apiLayerInfo->nextInfo->structVersion != XR_API_LAYER_NEXT_INFO_STRUCT_VERSION ||
            apiLayerInfo->nextInfo->structSize != sizeof(XrApiLayerNextInfo) ||
            apiLayerInfo->nextInfo->layerName != LayerName || !apiLayerInfo->nextInfo->nextGetInstanceProcAddr ||
            !apiLayerInfo->nextInfo->nextCreateApiLayerInstance) {
            return XR_ERROR_INITIALIZATION_FAILED;
        }

        Instance newInstance{};

        // Store the next xrGetInstanceProcAddr to resolve the functions handled by our layer.
        newInstance.nextGetInstanceProcAddr = apiLayerInfo->nextInfo->nextGetInstanceProcAddr;

        // Call the chain to create the instance.
        XrApiLayerCreateInfo chainApiLayerInfo = *apiLayerInfo;
        chainApiLayerInfo.nextInfo = apiLayerInfo->nextInfo->next;
        const XrResult result =
            apiLayerInfo->nextInfo->nextCreateApiLayerInstance(instanceCreateInfo, &chainApiLayerInfo, instance);
        if (XR_SUCCEEDED(result)) {
            // Fill out the context state.
            newInstance.applicationName = instanceCreateInfo->applicationInfo.applicationName;
            {
                char path[_MAX_PATH];
                GetModuleFileNameA(nullptr, path, sizeof(path));
                std::filesystem::path fullPath(path);
                newInstance.exeName = fullPath.filename().string();
            }
            newInstance.nextGetInstanceProcAddr(
                *instance,
                "xrGetInstanceProperties",
                reinterpret_cast<PFN_xrVoidFunction*>(&newInstance.nextGetInstanceProperties));
            newInstance.nextGetInstanceProcAddr(
                *instance,
                "xrGetSystemProperties",
                reinterpret_cast<PFN_xrVoidFunction*>(&newInstance.nextGetSystemProperties));

            std::unique_lock lock(g_instancesMutex);
            g_instances.insert_or_assign(*instance, std::move(newInstance));
        }
        return result;
    }

} // namespace

extern "C" {

// Entry point for the loader.
XrResult __declspec(dllexport) XRAPI_CALL
    xrNegotiateLoaderApiLayerInterface(const XrNegotiateLoaderInfo* const loaderInfo,
                                       const char* const apiLayerName,
                                       XrNegotiateApiLayerRequest* const apiLayerRequest) {
    if (!loaderInfo || !apiLayerName || !apiLayerRequest ||
        loaderInfo->structType != XR_LOADER_INTERFACE_STRUCT_LOADER_INFO ||
        loaderInfo->structVersion != XR_LOADER_INFO_STRUCT_VERSION ||
        loaderInfo->structSize != sizeof(XrNegotiateLoaderInfo) ||
        apiLayerRequest->structType != XR_LOADER_INTERFACE_STRUCT_API_LAYER_REQUEST ||
        apiLayerRequest->structVersion != XR_API_LAYER_INFO_STRUCT_VERSION ||
        apiLayerRequest->structSize != sizeof(XrNegotiateApiLayerRequest) || apiLayerName != LayerName ||
        loaderInfo->minInterfaceVersion > XR_CURRENT_LOADER_API_LAYER_VERSION ||
        loaderInfo->maxInterfaceVersion < XR_CURRENT_LOADER_API_LAYER_VERSION ||
        loaderInfo->maxInterfaceVersion > XR_CURRENT_LOADER_API_LAYER_VERSION ||
        loaderInfo->maxApiVersion < XR_CURRENT_API_VERSION || loaderInfo->minApiVersion > XR_CURRENT_API_VERSION) {
        return XR_ERROR_INITIALIZATION_FAILED;
    }

    // Setup our layer to intercept OpenXR calls.
    apiLayerRequest->layerInterfaceVersion = XR_CURRENT_LOADER_API_LAYER_VERSION;
    apiLayerRequest->layerApiVersion = XR_CURRENT_API_VERSION;
    apiLayerRequest->getInstanceProcAddr = reinterpret_cast<PFN_xrGetInstanceProcAddr>(xrGetInstanceProcAddr);
    apiLayerRequest->createApiLayerInstance = reinterpret_cast<PFN_xrCreateApiLayerInstance>(xrCreateApiLayerInstance);

    return XR_SUCCESS;
}
}
