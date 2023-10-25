#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>

#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

#define XR_NO_PROTOTYPES
#include <openxr/openxr.h>
#include "loader_interfaces.h"

namespace {
    const std::string LayerName = "XR_APILAYER_VIRTUALDESKTOP_oculus_compatibility";

    PFN_xrGetInstanceProcAddr nextGetInstanceProcAddr = nullptr;
    PFN_xrGetInstanceProperties nextGetInstanceProperties = nullptr;

    // https://www.khronos.org/registry/OpenXR/specs/1.0/html/xrspec.html#xrGetInstanceProperties
    XrResult xrGetInstanceProperties(XrInstance instance, XrInstanceProperties* instanceProperties) {
        // Chain the call to the next implementation.
        const XrResult result = nextGetInstanceProperties(instance, instanceProperties);

        // The OculusXR Plugin only loads successfully when the returned OpenXR runtime name is "Oculus". We fake that
        // if the caller is the OculusXR Plugin, but we return the real runtime name otherwise.
        if (XR_SUCCEEDED(result)) {
            HMODULE oculusXrPlugin, ovrPlugin, callerModule;
            if (GetModuleHandleExA(
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, "OculusXRPlugin.dll", &oculusXrPlugin) &&
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, "OVRPlugin.dll", &ovrPlugin) &&
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)_ReturnAddress(),
                                   &callerModule) &&
                (callerModule == oculusXrPlugin || callerModule == ovrPlugin)) {
                sprintf_s(instanceProperties->runtimeName, sizeof(instanceProperties->runtimeName), "Oculus");
            }
        }

        return result;
    }

    // Entry point for OpenXR calls.
    XrResult xrGetInstanceProcAddr(const XrInstance instance,
                                   const char* const name,
                                   PFN_xrVoidFunction* const function) {
        // Call the chain to resolve the next function pointer.
        const XrResult result = nextGetInstanceProcAddr(instance, name, function);
        if (XR_SUCCEEDED(result)) {
            const std::string_view apiName(name);

            // Intercept the calls handled by our layer.
            if (apiName == "xrGetInstanceProperties") {
                nextGetInstanceProperties = reinterpret_cast<PFN_xrGetInstanceProperties>(*function);
                *function = reinterpret_cast<PFN_xrVoidFunction>(xrGetInstanceProperties);
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

        // Store the next xrGetInstanceProcAddr to resolve the functions no handled by our layer.
        nextGetInstanceProcAddr = apiLayerInfo->nextInfo->nextGetInstanceProcAddr;

        // Call the chain to create the instance.
        XrApiLayerCreateInfo chainApiLayerInfo = *apiLayerInfo;
        chainApiLayerInfo.nextInfo = apiLayerInfo->nextInfo->next;
        return apiLayerInfo->nextInfo->nextCreateApiLayerInstance(instanceCreateInfo, &chainApiLayerInfo, instance);
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
