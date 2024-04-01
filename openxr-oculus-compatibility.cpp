// MIT License
//
// Copyright(c) 2023 Matthieu Bucchianeri
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this softwareand associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright noticeand this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <traceloggingactivity.h>
#include <traceloggingprovider.h>

#define XR_NO_PROTOTYPES
#include <openxr/openxr.h>
#include "loader_interfaces.h"

namespace {
    const std::string LayerName = "XR_APILAYER_VIRTUALDESKTOP_oculus_compatibility";

#pragma region "Tracelogging"

    // {cbf3adcd-42b1-4c38-830b-95980af201f6}
    TRACELOGGING_DEFINE_PROVIDER(g_traceProvider,
                                 "VirtualDesktopOculusCompat",
                                 (0xcbf3adcd, 0x42b1, 0x4c38, 0x93, 0x0b, 0x95, 0x98, 0x0a, 0xf2, 0x01, 0xf6));

#define TraceLocalActivity(activity) TraceLoggingActivity<g_traceProvider> activity;
#define TLArg(var, ...) TraceLoggingValue(var, ##__VA_ARGS__)
#define TLPArg(var, ...) TraceLoggingPointer(var, ##__VA_ARGS__)
#ifdef _M_IX86
#define TLXArg TLArg
#else
#define TLXArg TLPArg
#endif

#pragma endregion

    struct Instance {
        std::string applicationName;
        std::string exeName;
        bool isOculusXR{false};
        bool isSystemQueried{false};
        bool isSteamVRwithVirtualDesktop{false};

        XrSession activeSession{XR_NULL_HANDLE};

        std::vector<XrAction> actionsForMenu;
        std::vector<XrAction> actionsForX;
        std::vector<XrAction> actionsForY;

        // Functions we override.
        PFN_xrGetInstanceProcAddr nextGetInstanceProcAddr{nullptr};
        PFN_xrGetInstanceProperties nextGetInstanceProperties{nullptr};
        PFN_xrGetSystem nextGetSystem{nullptr};
        PFN_xrGetSystemProperties nextGetSystemProperties{nullptr};
        PFN_xrSuggestInteractionProfileBindings nextSuggestInteractionProfileBindings{nullptr};
        PFN_xrCreateSession nextCreateSession{nullptr};
        PFN_xrGetActionStateBoolean nextGetActionStateBoolean{nullptr};

        // Dependencies.
        PFN_xrStringToPath nextStringToPath{nullptr};
        PFN_xrPathToString nextPathToString{nullptr};
    };

    // NOTE: We do not retire instances/sessions from these sets. Creating instances and sessions is uncommon-enough
    // that we let them leak overtime without a significant impact.
    std::mutex g_instancesMutex;
    std::unordered_map<XrInstance, Instance> g_instances;
    std::unordered_map<XrSession, XrInstance> g_sessionsToInstances;

    inline bool startsWith(const std::string& str, const std::string& substr) {
        return str.find(substr) == 0;
    }

    inline bool endsWith(const std::string& str, const std::string& substr) {
        const auto pos = str.find(substr);
        return pos != std::string::npos && pos == str.size() - substr.size();
    }

    std::string rreplace(const std::string& str, const std::string& from, const std::string& to) {
        std::string copy(str);
        const size_t start_pos = str.rfind(from);
        copy.replace(start_pos, from.length(), to);

        return copy;
    }

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
        TraceLocalActivity(local);
        TraceLoggingWriteStart(local, "xrGetInstanceProperties");

        PFN_xrGetInstanceProperties nextGetInstanceProperties = nullptr;
        bool isOculusXR = false;
        std::string exeName;
        {
            std::unique_lock lock(g_instancesMutex);
            const auto it = g_instances.find(instance);
            if (it != g_instances.cend()) {
                const Instance& state = it->second;
                nextGetInstanceProperties = state.nextGetInstanceProperties;
                isOculusXR = state.isOculusXR;
                exeName = state.exeName;
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
            const bool needOculusXrPluginWorkaround = isOculusXR && exeName != "The7thGuestVR-Win64-Shipping.exe";
            if (needOculusXrPluginWorkaround) {
                TraceLoggingWriteTagged(local, "xrGetInstanceProperties", TLArg("OverrideRuntimeName", "Action"));
                sprintf_s(instanceProperties->runtimeName, sizeof(instanceProperties->runtimeName), "Oculus");
            }
        }

        TraceLoggingWriteStop(local, "xrGetInstanceProperties", TLArg((int)result, "Result"));

        return result;
    }

    // https://www.khronos.org/registry/OpenXR/specs/1.0/html/xrspec.html#xrGetSystem
    XrResult xrGetSystem(XrInstance instance, const XrSystemGetInfo* getInfo, XrSystemId* systemId) {
        TraceLocalActivity(local);
        TraceLoggingWriteStart(local, "xrGetSystem");

        PFN_xrGetSystem nextGetSystem = nullptr;
        PFN_xrGetInstanceProperties nextGetInstanceProperties = nullptr;
        bool isSystemQueried = false;
        {
            std::unique_lock lock(g_instancesMutex);
            const auto it = g_instances.find(instance);
            if (it != g_instances.cend()) {
                const Instance& state = it->second;
                nextGetSystem = state.nextGetSystem;
                nextGetInstanceProperties = state.nextGetInstanceProperties;
                isSystemQueried = state.isSystemQueried;
            }
        }
        if (!nextGetSystem || !nextGetInstanceProperties) {
            return XR_ERROR_INSTANCE_LOST;
        }

        // Chain the call to the next implementation.
        const XrResult result = nextGetSystem(instance, getInfo, systemId);

        if (XR_SUCCEEDED(result) && getInfo->formFactor == XR_FORM_FACTOR_HEAD_MOUNTED_DISPLAY) {
            if (!isSystemQueried) {
                // We can cache whether the service is running, because even if the application is polling xrGetSystem()
                // and the XrSystem in use could technically change over time, it would require a restart of SteamVR,
                // and taking down the XrInstance.
                static const bool isVirtualDesktopServiceRunning = IsServiceRunning(L"VirtualDesktop.Server.exe");

                // Check that the runtime is SteamVR.
                XrInstanceProperties instanceProperties{XR_TYPE_INSTANCE_PROPERTIES};
                // We intentionally allow this call to fail for robustness.
                nextGetInstanceProperties(instance, &instanceProperties);
                const std::string_view runtimeName(instanceProperties.runtimeName);
                const bool isSteamVR = runtimeName == "SteamVR/OpenXR";

                TraceLoggingWriteTagged(local,
                                        "xrGetSystem",
                                        TLArg(isVirtualDesktopServiceRunning, "IsVirtualDesktop"),
                                        TLArg(isSteamVR, "IsSteamVR"));

                {
                    std::unique_lock lock(g_instancesMutex);
                    const auto it = g_instances.find(instance);
                    if (it != g_instances.cend()) {
                        Instance& state = it->second;
                        state.isSystemQueried = true;
                        state.isSteamVRwithVirtualDesktop = isSteamVR && isVirtualDesktopServiceRunning;
                    }
                }
            }
        }

        TraceLoggingWriteStop(local, "xrGetSystem", TLArg((int)result, "Result"));

        return result;
    }

    // https://www.khronos.org/registry/OpenXR/specs/1.0/html/xrspec.html#xrGetSystemProperties
    XrResult xrGetSystemProperties(XrInstance instance, XrSystemId systemId, XrSystemProperties* properties) {
        TraceLocalActivity(local);
        TraceLoggingWriteStart(local, "xrGetSystemProperties");

        PFN_xrGetSystemProperties nextGetSystemProperties = nullptr;
        bool isSteamVRwithVirtualDesktop = false;
        bool isOculusXR = false;
        {
            std::unique_lock lock(g_instancesMutex);
            const auto it = g_instances.find(instance);
            if (it != g_instances.cend()) {
                const Instance& state = it->second;
                nextGetSystemProperties = state.nextGetSystemProperties;
                isSteamVRwithVirtualDesktop = state.isSteamVRwithVirtualDesktop;
                isOculusXR = state.isOculusXR;
            }
        }
        if (!nextGetSystemProperties) {
            return XR_ERROR_INSTANCE_LOST;
        }

        // Chain the call to the next implementation.
        const XrResult result = nextGetSystemProperties(instance, systemId, properties);

        // When Virtual Desktop is used with SteamVR and the OculusXR plugin is detected, we force un-advertise the hand
        // joints capability.
        if (XR_SUCCEEDED(result)) {
            if (isSteamVRwithVirtualDesktop && isOculusXR) {
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
                    TraceLoggingWriteTagged(
                        local, "xrGetSystemProperties", TLArg("OverrideSupportsHandTracking", "Action"));
                    handTrackingProperties->supportsHandTracking = XR_FALSE;
                }
            }
        }

        TraceLoggingWriteStop(local, "xrGetSystemProperties", TLArg((int)result, "Result"));

        return result;
    }

    // https://www.khronos.org/registry/OpenXR/specs/1.0/html/xrspec.html#xrSuggestInteractionProfileBindings
    XrResult xrSuggestInteractionProfileBindings(XrInstance instance,
                                                 const XrInteractionProfileSuggestedBinding* suggestedBindings) {
        TraceLocalActivity(local);
        TraceLoggingWriteStart(local, "xrSuggestInteractionProfileBindings");

        PFN_xrSuggestInteractionProfileBindings nextSuggestInteractionProfileBindings = nullptr;
        PFN_xrStringToPath nextStringToPath = nullptr;
        PFN_xrPathToString nextPathToString = nullptr;
        bool isSteamVRwithVirtualDesktop = false;
        {
            std::unique_lock lock(g_instancesMutex);
            const auto it = g_instances.find(instance);
            if (it != g_instances.cend()) {
                const Instance& state = it->second;
                nextSuggestInteractionProfileBindings = state.nextSuggestInteractionProfileBindings;
                nextStringToPath = state.nextStringToPath;
                nextPathToString = state.nextPathToString;
                isSteamVRwithVirtualDesktop = state.isSteamVRwithVirtualDesktop;
            }
        }
        if (!nextSuggestInteractionProfileBindings || !nextStringToPath || !nextPathToString) {
            return XR_ERROR_INSTANCE_LOST;
        }

        const auto getPath = [nextPathToString, instance](XrPath path) {
            char buf[XR_MAX_PATH_LENGTH];
            uint32_t count = 0;
            // We intentionally allow this call to fail for robustness.
            nextPathToString(instance, path, sizeof(buf), &count, buf);
            std::string str;
            if (count) {
                str.assign(buf, count - 1);
            }
            return str;
        };

        XrInteractionProfileSuggestedBinding copySuggestedBindings = *suggestedBindings;
        std::vector<XrActionSuggestedBinding> actionBindings;

        // When the OculusXR Plugin is used on Virtual Desktop with SteamVR, we remap the Menu button to deconflict with
        // SteamVR dashboard.
        // We only do this for the Oculus Touch Interaction profile, since we assume OculusXR will always provide
        // bindings for it.
        const bool isOculusTouchInteractionProfile =
            getPath(copySuggestedBindings.interactionProfile) == "/interaction_profiles/oculus/touch_controller";
        if (isSteamVRwithVirtualDesktop && isOculusTouchInteractionProfile) {
            std::vector<uint32_t> entriesForMenuAction;
            std::vector<uint32_t> entriesForXAction;
            std::vector<uint32_t> entriesForYAction;
            for (uint32_t i = 0; i < copySuggestedBindings.countSuggestedBindings; i++) {
                const auto actionPath = getPath(copySuggestedBindings.suggestedBindings[i].binding);
                if (endsWith(actionPath, "/input/menu/click") || endsWith(actionPath, "/input/menu")) {
                    entriesForMenuAction.push_back(i);
                } else if (endsWith(actionPath, "/input/x/click") || endsWith(actionPath, "/input/x")) {
                    entriesForXAction.push_back(i);
                } else if (endsWith(actionPath, "/input/y/click") || endsWith(actionPath, "/input/y")) {
                    entriesForYAction.push_back(i);
                }
            }

            TraceLoggingWriteTagged(local,
                                    "xrSuggestInteractionProfileBindings",
                                    TLArg(entriesForMenuAction.size(), "NumMenuActions"),
                                    TLArg(entriesForXAction.size(), "NumXActions"),
                                    TLArg(entriesForYAction.size(), "NumYActions"));

            if (!entriesForMenuAction.empty()) {
                actionBindings.assign(copySuggestedBindings.suggestedBindings,
                                      copySuggestedBindings.suggestedBindings +
                                          copySuggestedBindings.countSuggestedBindings);

                // Determine our best remapping option.
                const bool remapXtoMenu = entriesForXAction.empty();
                const bool remapYtoMenu = !remapXtoMenu && entriesForYAction.empty();
                const bool remapXYtoMenu = !remapXtoMenu && !remapYtoMenu;

                for (uint32_t index : entriesForMenuAction) {
                    if (remapXtoMenu || remapXYtoMenu) {
                        // We intentionally allow this call to fail for robustness.
                        if (XR_FAILED(nextStringToPath(
                                instance, "/user/hand/left/input/x/click", &actionBindings[index].binding))) {
                            TraceLoggingWriteTagged(local, "xrSuggestInteractionProfileBindings_InternalError");
                        }
                        if (remapXtoMenu) {
                            TraceLoggingWriteTagged(local,
                                                    "xrSuggestInteractionProfileBindings",
                                                    TLArg("RemapToX", "Action"),
                                                    TLXArg(actionBindings[index].action, "Action"));
                        }
                    } else if (remapYtoMenu) {
                        // We intentionally allow this call to fail for robustness.
                        if (XR_FAILED(nextStringToPath(
                                instance, "/user/hand/left/input/y/click", &actionBindings[index].binding))) {
                            TraceLoggingWriteTagged(local, "xrSuggestInteractionProfileBindings_InternalError");
                        }
                        TraceLoggingWriteTagged(local,
                                                "xrSuggestInteractionProfileBindings",
                                                TLArg("RemapToY", "Action"),
                                                TLXArg(actionBindings[index].action, "Action"));
                    }
                }

                {
                    std::unique_lock lock(g_instancesMutex);
                    const auto it = g_instances.find(instance);
                    if (it != g_instances.cend()) {
                        Instance& state = it->second;
                        state.actionsForMenu.clear();
                        state.actionsForX.clear();
                        state.actionsForY.clear();

                        if (remapXYtoMenu) {
                            for (uint32_t index : entriesForMenuAction) {
                                state.actionsForMenu.push_back(actionBindings[index].action);
                                TraceLoggingWriteTagged(local,
                                                        "xrSuggestInteractionProfileBindings",
                                                        TLArg("RemapToXY", "Action"),
                                                        TLXArg(actionBindings[index].action, "Action"));
                            }

                            // Make sure we will block X and Y when X+Y is pressed.
                            for (uint32_t index : entriesForXAction) {
                                state.actionsForX.push_back(actionBindings[index].action);
                                TraceLoggingWriteTagged(local,
                                                        "xrSuggestInteractionProfileBindings",
                                                        TLArg("BlockOnXY", "Action"),
                                                        TLXArg(actionBindings[index].action, "Action"));
                            }
                            for (uint32_t index : entriesForYAction) {
                                state.actionsForY.push_back(actionBindings[index].action);
                                TraceLoggingWriteTagged(local,
                                                        "xrSuggestInteractionProfileBindings",
                                                        TLArg("BlockOnXY", "Action"),
                                                        TLXArg(actionBindings[index].action, "Action"));
                            }
                        }
                    }
                }

                copySuggestedBindings.suggestedBindings = actionBindings.data();
                copySuggestedBindings.countSuggestedBindings = (uint32_t)actionBindings.size();
            }
        }

        // Chain the call to the next implementation.
        const XrResult result = nextSuggestInteractionProfileBindings(instance, &copySuggestedBindings);

        TraceLoggingWriteStop(local, "xrSuggestInteractionProfileBindings", TLArg((int)result, "Result"));

        return result;
    }

    // https://www.khronos.org/registry/OpenXR/specs/1.0/html/xrspec.html#xrCreateSession
    XrResult xrCreateSession(XrInstance instance, const XrSessionCreateInfo* createInfo, XrSession* session) {
        TraceLocalActivity(local);
        TraceLoggingWriteStart(local, "xrCreateSession");

        PFN_xrCreateSession nextCreateSession = nullptr;
        {
            std::unique_lock lock(g_instancesMutex);
            const auto it = g_instances.find(instance);
            if (it != g_instances.cend()) {
                const Instance& state = it->second;
                nextCreateSession = state.nextCreateSession;
            }
        }
        if (!nextCreateSession) {
            return XR_ERROR_INSTANCE_LOST;
        }

        // Chain the call to the next implementation.
        const XrResult result = nextCreateSession(instance, createInfo, session);

        if (XR_SUCCEEDED(result)) {
            std::unique_lock lock(g_instancesMutex);
            g_sessionsToInstances.insert_or_assign(*session, instance);
        }

        TraceLoggingWriteStop(local, "xrCreateSession", TLArg((int)result, "Result"));

        return result;
    }

    // https://www.khronos.org/registry/OpenXR/specs/1.0/html/xrspec.html#xrGetActionStateBoolean
    XrResult xrGetActionStateBoolean(XrSession session,
                                     const XrActionStateGetInfo* getInfo,
                                     XrActionStateBoolean* state) {
        TraceLocalActivity(local);
        TraceLoggingWriteStart(local, "xrGetActionStateBoolean");

        XrInstance instance = XR_NULL_HANDLE;
        PFN_xrGetActionStateBoolean nextGetActionStateBoolean = nullptr;
        PFN_xrStringToPath nextStringToPath = nullptr;
        bool isMenuAction = false;
        bool isXAction = false;
        bool isYAction = false;
        XrAction actionForX = XR_NULL_HANDLE;
        XrAction actionForY = XR_NULL_HANDLE;
        {
            std::unique_lock lock(g_instancesMutex);
            const auto it = g_sessionsToInstances.find(session);
            if (it != g_sessionsToInstances.cend()) {
                instance = it->second;
            }
            const auto it2 = g_instances.find(instance);
            if (it2 != g_instances.cend()) {
                const Instance& state = it2->second;
                nextGetActionStateBoolean = state.nextGetActionStateBoolean;
                nextStringToPath = state.nextStringToPath;
                if (getInfo) {
                    isMenuAction =
                        std::find(state.actionsForMenu.cbegin(), state.actionsForMenu.cend(), getInfo->action) !=
                        state.actionsForMenu.cend();
                    isXAction = std::find(state.actionsForX.cbegin(), state.actionsForX.cend(), getInfo->action) !=
                                state.actionsForX.cend();
                    isYAction = std::find(state.actionsForY.cbegin(), state.actionsForY.cend(), getInfo->action) !=
                                state.actionsForY.cend();
                }
                if (!state.actionsForX.empty()) {
                    actionForX = state.actionsForX[0];
                }
                if (!state.actionsForY.empty()) {
                    actionForY = state.actionsForY[0];
                }
            }
        }
        if (!nextGetActionStateBoolean || !nextStringToPath) {
            return XR_ERROR_INSTANCE_LOST;
        }

        // Chain the call to the next implementation.
        const XrResult result = nextGetActionStateBoolean(session, getInfo, state);

        // Apply our remapping when needed.
        if (XR_SUCCEEDED(result)) {
            TraceLoggingWriteTagged(local,
                                    "xrGetActionStateBoolean",
                                    TLXArg(getInfo->action, "XrAction"),
                                    TLArg(isMenuAction, "IsMenuAction"),
                                    TLArg(isXAction, "IsXAction"),
                                    TLArg(isYAction, "IsYAction"));

            if ((isMenuAction || isXAction || isYAction) && state->isActive && state->currentState == XR_TRUE) {
                // Check the other button.
                XrActionStateBoolean stateForOther{XR_TYPE_ACTION_STATE_BOOLEAN};
                XrActionStateGetInfo getInfoForOther{XR_TYPE_ACTION_STATE_GET_INFO};
                getInfoForOther.action = isYAction ? actionForX : actionForY;
                // Try using the left subaction path, fallback to no subaction path on failure.
                nextStringToPath(instance, "/user/hand/left", &getInfoForOther.subactionPath);
                if (XR_FAILED(nextGetActionStateBoolean(session, &getInfoForOther, &stateForOther))) {
                    getInfoForOther.subactionPath = XR_NULL_PATH;
                    // We intentionally allow this call to fail for robustness.
                    if (XR_FAILED(nextGetActionStateBoolean(session, &getInfoForOther, &stateForOther))) {
                        TraceLoggingWriteTagged(local, "xrGetActionStateBoolean_InternalError");
                    }
                }
                TraceLoggingWriteTagged(local,
                                        "xrGetActionStateBoolean",
                                        TLArg(!!stateForOther.isActive, "OtherActive"),
                                        TLArg(!!stateForOther.currentState, "OtherCurrentState"));
                if (stateForOther.isActive) {
                    if (isMenuAction) {
                        // Couple the inputs to emulate the Menu button.
                        state->currentState = stateForOther.currentState;
                        state->changedSinceLastSync =
                            state->changedSinceLastSync == XR_TRUE || stateForOther.changedSinceLastSync == XR_TRUE;
                        state->lastChangeTime = std::max(state->lastChangeTime, stateForOther.lastChangeTime);
                        TraceLoggingWriteTagged(local, "xrGetActionStateBoolean", TLArg("PropagateOther", "Action"));
                    } else if (stateForOther.currentState) {
                        // Block the input when X+Y is pressed.
                        state->currentState = XR_FALSE;
                        state->changedSinceLastSync =
                            state->changedSinceLastSync == XR_TRUE || stateForOther.changedSinceLastSync == XR_TRUE;
                        state->lastChangeTime = std::max(state->lastChangeTime, stateForOther.lastChangeTime);
                        TraceLoggingWriteTagged(local, "xrGetActionStateBoolean", TLArg("Block", "Action"));
                    }
                }
            }
        }

        TraceLoggingWriteStop(local, "xrGetActionStateBoolean", TLArg((int)result, "Result"));

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
                const Instance& state = it->second;
                nextGetInstanceProcAddr = state.nextGetInstanceProcAddr;
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

#define REDIRECT_XR_PROC(proc)                                                                                         \
    else if (apiName == "xr" #proc) {                                                                                  \
        *function = reinterpret_cast<PFN_xrVoidFunction>(xr##proc);                                                    \
    }

            if (false) {
            }
            REDIRECT_XR_PROC(GetInstanceProperties)
            REDIRECT_XR_PROC(GetSystem)
            REDIRECT_XR_PROC(GetSystemProperties)
            REDIRECT_XR_PROC(SuggestInteractionProfileBindings)
            REDIRECT_XR_PROC(CreateSession)
            REDIRECT_XR_PROC(GetActionStateBoolean)

#undef REDIRECT_XR_PROC

            // Leave all unhandled calls to the next layer.
        }

        return result;
    }

    // Entry point for creating the layer.
    XrResult xrCreateApiLayerInstance(const XrInstanceCreateInfo* const instanceCreateInfo,
                                      const struct XrApiLayerCreateInfo* const apiLayerInfo,
                                      XrInstance* const instance) {
        TraceLocalActivity(local);
        TraceLoggingWriteStart(local, "xrCreateApiLayerInstance");

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
            HMODULE ovrPlugin;
            newInstance.isOculusXR =
                startsWith(newInstance.applicationName, "Oculus VR Plugin") ||
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, "OVRPlugin.dll", &ovrPlugin);
            TraceLoggingWriteTagged(local, "xrCreateApiLayerInstance", TLArg(newInstance.isOculusXR, "IsOculusXR"));

#define GET_XR_PROC(proc)                                                                                              \
    newInstance.nextGetInstanceProcAddr(                                                                               \
        *instance, "xr" #proc, reinterpret_cast<PFN_xrVoidFunction*>(&newInstance.next##proc));

            GET_XR_PROC(GetInstanceProperties);
            GET_XR_PROC(GetSystem);
            GET_XR_PROC(GetSystemProperties);
            GET_XR_PROC(SuggestInteractionProfileBindings);
            GET_XR_PROC(CreateSession);
            GET_XR_PROC(GetActionStateBoolean);
            GET_XR_PROC(StringToPath);
            GET_XR_PROC(PathToString);

#undef GET_XR_PROC

            std::unique_lock lock(g_instancesMutex);
            g_instances.insert_or_assign(*instance, std::move(newInstance));
        }

        TraceLoggingWriteStop(
            local, "xrCreateApiLayerInstance", TLXArg(*instance, "Instance"), TLArg((int)result, "Result"));

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

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        TraceLoggingRegister(g_traceProvider);
        break;

    case DLL_PROCESS_DETACH:
        TraceLoggingUnregister(g_traceProvider);
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
