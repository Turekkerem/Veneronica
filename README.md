# Project "veneronika" — Academic Proof-of-Concept (PoC) Overview

---

## Executive Summary & Safety Warning
> **DISCLAIMER:** This software is provided strictly for **educational and academic research purposes**. The code contains a built-in safety prompt warning the user before execution. However, if this warning dialog is bypassed or removed, the persistence module will execute silently and autonomously in the background, which poses severe risks to system integrity. 
> 
> * **Execution Environment:** Run this software **exclusively within isolated virtualized test environments** (e.g., air-gapped virtual machines).
> * **Kill Switch & Script Kiddie Advisory:** A kill switch mechanism is embedded within the source file. To any novice or unauthorized operator attempting deployment: 
>   ```text
>   35 0ur 5cr1pt k1dd13, d0 n0t 4tt3mpt t0 r3l3453 0r 3x3cut3 th15 c0d3 w1th0ut full und3r5t4nd1ng.
>   ```
  
---

## Detailed Component Analysis & Author Insights

### 1. Polymorphism Engine (`MakePolymorphic`)
* **Technical Design:** The module dynamically renames the executing binary image to a temporary `.tmp` file (`MoveFileExA`) to bypass file locks, loads its content into memory, searches for an embedded structural anchor string, and injects freshly generated cryptographic randomness (`CryptGenRandom`) to change the file hash.
* **Author's Notes & Limitations:** Polymorphism can be further obfuscated by substituting the static placeholder string (`POLYMORPHIC01`) with dynamic pseudo-random values to make static analysis more tedious for malware analysts. While this prototype implementation does not clean up the `.tmp` file ideally in every edge case, it serves its function adequately for a basic Proof-of-Concept.

### 2. Cryptographic Downgrade & Posture Reduction (`ApplyDowngradeFull` / `ApplyDowngradeUserOnly`)
* **Technical Design:** Systematically overrides Windows Registry values across `HKCU` and `HKLM` to weaken Schannel protocols, cipher suites, SMB communication, and .NET Framework security profiles.
* **Author's Notes & Limitations:** It is technically possible to attempt a much heavier downgrade; however, certain registry keys enforce strict cryptographic dependencies. If an operator forces the inclusion of obsolete primitives (such as `NULL` ciphers or specific legacy RC4 configurations) without proper cipher suite ordering, key negotiation fails completely and network sockets hang. Consequently, the registry keys selected represent a balanced subset that lowers security posture while maintaining active connection handshakes.

### 3. File Timestamp Manipulation — Timestomping (`TimestompAllAccessibleFiles`)
* **Technical Design:** Recursively traverses attached physical and removable drives, generating random synthetic timestamps (`FILETIME`) ranging between 1990 and 2030 to overwrite file system metadata.
* **Author's Notes & Limitations:** Timestomping execution time scales directly with system privilege levels. When run with elevated administrator rights, the routine scans deeper system directories, causing the process to take significantly longer—which makes sense logically. Because scanning the entire filesystem yields minimal unique forensic obfuscation value for an analyst tracking disk alterations, operators can optimize performance by tuning the skip flag parameter. To modify this behavior, look at the `TimestompAllAccessibleFiles(bool skipSystemDirs)` function call inside `WinMain`: changing the argument from `is_elevated` to a hardcoded `true` forces the routine to skip heavy system directories and execute much faster.

### 4. Persistence Simulation (`PersistenceSimulation`)
* **Technical Design:** Copies the executable into a masked system or user directory under a randomized legitimate process name (e.g., `svchost.exe`, `csrss.exe`) and registers it into persistence vectors.
* **Author's Notes & Limitations:** While standard persistence vectors like the `CurrentVersion\Run` registry key or the standard user Startup folder work reliably, advanced simulations can leverage non-obvious persistence paths. Alternative deep integration vectors include screen saver execution settings (`Control Panel\Desktop` -> `SCRNSAVE.EXE`) or COM object hijacking. Below are registry paths commonly referenced for advanced persistence research:
  * Screen Saver Persistence: `HKEY_CURRENT_USER\Control Panel\Desktop` (Values: `SCRNSAVE.EXE`, `ScreenSaveActive`)
  * Image File Execution Options (IFEO): `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>` (Value: `Debugger`)
  * Winlogon Shell/Userinit: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` (Values: `Shell`, `Userinit`)

### 5. Privilege Escalation & UAC Interaction (`IsElevated`, `ElevateSelf`)
* **Technical Design:** Analyzes access tokens to check integrity levels and prompts for administrative privileges using Windows Shell execution verbs.
* **Author's Notes & Limitations:** Labeling this a fully-fledged "Privilege Escalation" module is technically an overstatement. In reality, it consists of two straightforward helper functions: `IsElevated` queries the process token via `OpenProcessToken` and `GetTokenInformation`, while `ElevateSelf` invokes `ShellExecuteExW` with the `runas` verb parameter. This triggers the native Windows User Account Control (UAC) consent dialog (`consent.exe`), requesting the user to manually authorize administrative elevation.

### 6. Visual/Auditory Payload Module (`ShowSkull`)
* **Technical Design:** Spawns a multi-threaded swarm of top-most windows displaying animated ASCII art skulls with real-time GDI screen glitches and asynchronous resource audio loops.
* **Author's Notes & Limitations:** To compile audio and graphical resources correctly using resource script compilers (like GNU `windres` or MSVC RC), resources must be defined inside a `.rc` script file linked against the project. 
  * *Resource Script Definition Example (`resources.rc`):*
    ```rc
    101 WAVE "glitch_audio.wav"
    102 WAVE "laugh_audio.wav"
    ```
  * *Compilation via MinGW (`windres`):*
    ```bash
    windres resources.rc -O coff -o resources.o
    g++ -o weneronika.exe weneronika.cpp resources.o -mwindows -static -ladvapi32 -luser32 -lshell32 -lwinmm
    ```


---
*Note: Yes, this description was generated with the assistance of AI because formatting everything manually in Markdown became entirely too tedious. I supplied the core concepts, but the final editing was handled by an AI collaborator. Truly, only a deracinated imbecile or an obtuse simpleton would fail to leverage such efficiency.*