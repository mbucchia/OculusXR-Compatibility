# Compatibility layer for OculusXR with Virtual Desktop

This software addresses some compatibility issues with the OculusXR plugin for Unity/Unreal Engine.

**This tool is built into [Virtual Desktop](https://www.vrdesktop.net/).** You do not need to build/install it separately. The source code is provided here as-is for educational purposes.

It is only active when an OpenXR application using the OculusXR plugin is launched with SteamVR OpenXR and Virtual Desktop is in use.

The following issues are addressed:

- It fakes the OpenXR runtime name as "Oculus" to bypass the checks at initialization of the OculusXR plugin.

- It remaps the left controller X, Y or X+Y buttons (whichever is available first) to the Menu button, to allow bringing in-game menus (as opposed to bringing up the SteamVR dashboard).

- It disables support for `XR_EXT_hand_tracking` with the OculusXR plugin, which is causing incorrect motion controller orientation in some games.

DISCLAIMER: This software is distributed as-is, without any warranties or conditions of any kind. Use at your own risks.
