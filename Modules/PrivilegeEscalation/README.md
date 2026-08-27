# Module: Privilege Escalation and UAC Handling

## Technical Description
This module handles execution context analysis and user privilege verification. It determines whether the current process context runs with administrative rights and implements standard User Account Control (UAC) elevation routines.

## Mechanics
- **Token Elevation Query:** `IsElevated` opens the primary access token of the current process via `OpenProcessToken` and queries `TokenElevation` to check the execution integrity level.
- **UAC Prompt Generation:** `ElevateSelf` invokes `ShellExecuteExW` utilizing the `runas` verb parameter. This forces the Windows Shell execution handler to prompt the user interactively with a consent dialog box, requesting administrative authorization to relaunch the binary with elevated security context.