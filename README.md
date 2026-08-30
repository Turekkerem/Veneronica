# Veneronica — Academic Proof-of-Concept Malware

<div style="background-color:#1a1a1a; color:#b0b0b0; padding:15px; border-left:4px solid #8b0000; border-radius:4px; font-family:Consolas, monospace;">

**WARNING — EDUCATIONAL USE ONLY**  
This software is a malware proof-of-concept created for academic research and security training.  
It deliberately weakens system security, installs persistence, manipulates file metadata, and attempts privilege escalation.  
**DO NOT RUN THIS ON ANY PRODUCTION OR NETWORKED MACHINE.**  
Use only in an isolated virtual machine with no network access and no valuable data.  
The author assumes no liability for any damage caused by misuse.
**5cr1p7 k1dd13 w4rn1ng:** 1f y0u d0 n07 fully und3r574nd wh47 7h15 c0d3 d035, d0 n07 u53 17. 7h15 15 n07 4 700l f0r 3v3ry0n3.

</div>

---

## 1. Project Overview

Veneronica is a multi-module malicious executable that demonstrates several techniques commonly found in real-world malware. The code is intentionally unpolished and includes multiple redundant functions, simulating the work of an amateur threat actor. This README provides a thorough analysis of each component.

**Key features:**

- **Polymorphism** — self-modification of the binary to alter its hash and evade static signatures.
- **Persistence** — installation of the malware into various autostart locations, both per-user and system-wide.
- **Security downgrade** — mass modification of Windows registry to weaken cryptographic protocols, authentication, network security, and system hardening mechanisms.
- **Timestomping** — randomisation of file timestamps to hinder forensic analysis.
- **Shortcut hijacking** — replacement of desktop `.lnk` targets to trick the victim into executing the malware.
- **Privilege escalation** — attempts to obtain administrative rights via UAC prompt.
- **Installation flag** — prevents repeated UAC prompts and controls post-reboot behaviour.

> **Note:** The original source included a `ReplaceOriginalWithDecoy` function that overwrote the original executable with a fake text file. That function has been **removed** in this version and is **not described further**.

---

## 2. Execution Behaviour

When the executable is launched, the following sequence occurs:

1. **Initial privilege check** — if the process is not elevated, it calls `ElevateSelf()` to spawn a new elevated instance via UAC. If accepted, the original process terminates and the new one continues.
2. **Polymorphism** — the binary modifies itself on disk (details below).
3. **Installation flag check** — the value `Installed` is read from `HKEY_CURRENT_USER\Software\MyMalware`. If it is **not set**, this is the first run, and the full infection routine proceeds. If it is **set**, the program simply exits (silent mode for subsequent launches).
4. **First run (no flag):**
   - If the process is **not elevated** (UAC rejected), it hijacks all desktop shortcuts and then exits.
   - If **elevated**:
     - Ensures Explorer is running (needed for Shell replacement persistence).
     - Installs persistence via a randomly chosen method.
     - Sets the `Installed` flag.
     - Performs full system downgrade.
     - Opens additional attack vectors (network ports, services).
     - Runs timestomping.
     - Exits.

**Post-reboot behaviour:** When the system restarts and the malware is launched through any persistence mechanism, the `Installed` flag is already set, so the code immediately jumps to the “silent payload” branch and returns `0`. In this PoC that branch does nothing — the program simply exits. This demonstrates how an attacker could use the flag to perform one-time installation and then remain inactive or execute a different, quieter payload.

---

## 3. Detailed Module Analysis

### 3.1 Polymorphism (`MakePolymorphic`)

The goal of this module is to change the file hash of the executable after every run, making static signature detection more difficult.

**How it works:**

1. Retrieves its own path via `GetModuleFileNameA`.
2. Copies the running executable to `<self>.tmp`.
3. Opens the temporary copy with read/write access.
4. Allocates a buffer and reads the whole file into memory.
5. Searches for the marker `"POLYMORPHIC01"` (13 bytes) by scanning the entire file.
   - The marker is **built dynamically** character by character inside the function, so the literal string `"POLYMORPHIC01"` appears only as part of the global `PolymorphicData` structure in the data section, and not as a separate duplicate in the code section. This reduces the chance of finding multiple occurrences during the scan.
6. Once found, the function treats the memory immediately after the marker (`found + markerLen`) as an array of 1000 integers.
7. Fills that array with cryptographically random bytes using `CryptGenRandom` (or `rand()` as fallback).
8. Writes the modified buffer back to the `.tmp` file.
9. Attempts to replace the original executable with the modified one using `MoveFileEx` with `MOVEFILE_DELAY_UNTIL_REBOOT`.
   - Because the file is running and locked, immediate replacement is impossible; the flag schedules the replacement for the next reboot.
10. If `MoveFileEx` fails, it tries `CopyFile` and then deletes the temporary file.

**Limitations and notes:**

- The hash changes **only after the system reboots**, because the replacement is delayed.
- The polymorphic buffer (`int data[1000]`) is stored in the `.data` section, so the file modification is limited to that region.
- To be more stealthy, an attacker could encrypt or randomise different sections, but this is sufficient for a PoC.

---

### 3.2 Persistence (`InstallPersistenceRandom`)

This module ensures the malware survives reboots by registering itself in various autostart locations. The method is selected randomly from a pool depending on the current privileges.

#### 3.2.1 User‑level methods (no admin rights)

| # | Method | Description |
|---|--------|-------------|
| 1 | **Run key with null‑terminated name** | Writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with a value name preceded by `\0` (see section 3.7). The displayed name in `regedit` becomes empty or invisible. |
| 2 | **RunOnce** | Classic one‑time autostart entry under `HKCU\...\RunOnce`. |
| 3 | **UserInitMprLogonScript** | Creates a `.cmd` script that launches the malware and sets it as the logon script value under `HKCU\Environment`. The script is necessary because this value expects a script file, not an executable. |
| 4 | **Screensaver** | Copies the malware as `screensaver.scr` and sets it as the active screensaver via `HKCU\Control Panel\Desktop\SCRNSAVE.EXE`. When the user is idle, the screensaver (malware) runs. |
| 5 | **Startup folder** | Copies the malware into the user’s Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`). |
| 6 | **IFEO (user)** | Uses Image File Execution Options under HKCU to set the malware as the debugger for `notepad.exe`. Whenever Notepad is launched, the malware runs instead. |
| 7 | **App Paths** | Hijacks the `winword.exe` application path under `HKCU\...\App Paths` so that launching Word triggers the malware. |
| 8 | **Protocol handler** | Creates a custom URL protocol (`myapp:`) that executes the malware when invoked from a browser or other application. |
| 9 | **Scheduled Task (user)** | Uses `schtasks` command to create a task that runs the malware at user logon. |

#### 3.2.2 Administrator‑level methods

| # | Method | Description |
|---|--------|-------------|
| 1 | **Winlogon Shell** | Replaces the `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` value with the malware path. The malware then must start `explorer.exe` itself to avoid breaking the desktop (handled by `EnsureExplorerRunning`). |
| 2 | **Windows service** | Creates a new service named `Windows Update Helper` with `SERVICE_AUTO_START` and `SERVICE_WIN32_OWN_PROCESS`. This is the most powerful persistence because it starts before user login with SYSTEM privileges. |
| 3 | **IFEO (admin)** | Sets the malware as the debugger for `notepad.exe` under `HKLM\...\Image File Execution Options`. Same principle as user‑level, but system‑wide. |
| 4 | **Winlogon Userinit** | Appends the malware path to the existing `Userinit` value under `HKLM\...\Winlogon`. This ensures it runs at every logon. |
| 5 | **AppCertDlls** | Writes the malware path to `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`, causing it to be loaded by any process that uses certain cryptographic APIs. |
| 6 | **AppInit_DLLs** | Sets `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` to the malware path. This injects the DLL into every process that loads `user32.dll`. |
| 7 | **BootExecute** | Adds the malware to `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute`, which runs it during system boot. |
| 8 | **Scheduled Task (SYSTEM)** | Creates a scheduled task that runs at system startup with `SYSTEM` privileges. |
| 9 | **Image hijack** | Copies the malware over `notepad.exe` in `System32`. This is a crude but effective way to replace a legitimate binary. |

**Random selection:**  
The function uses `rand() % 9` to pick one method. In a real attack, an actor might prefer one method over another, but randomisation makes analysis less predictable.

---

### 3.3 Security Downgrade (`PerformFullSystemDowngrade`)

This module systematically weakens Windows security by modifying dozens of registry keys. It is divided into five logical categories (after refactoring from the original messy code).

#### 3.3.1 Crypto & protocols (`DowngradeCryptoProtocols`)

- **Enabled legacy protocols:** SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, PCT 1.0 (client and server).
- **Disabled modern protocols:** TLS 1.2, TLS 1.3, Multi‑Protocol Unified Hello.
- **Weak symmetric ciphers:** NULL, DES, RC2, RC4, 3DES – all set to `Enabled=0xffffffff`.
- **Weak hashes:** MD5, SHA – enabled.
- **Key exchange weakening:** ECDHE and ECDH disabled; Diffie‑Hellman minimum key length forced to 512 bits; RSA minimum 384 bits.
- **Weak cipher suite order:** sets only export‑grade and NULL suites.
- **Certificate verification disabled:** `CertificateRevocation=0` in both Internet Settings and Schannel.
- **.NET Framework:** `SchUseStrongCrypto=0`, `SystemDefaultTlsVersions=0` for both 32‑ and 64‑bit.
- **EFS:** Algorithm set to 3DES (`AlgorithmID=0x6603`) and provider changed to “Microsoft Base Cryptographic Provider v1.0”.
- **BitLocker:** weak encryption (AES‑CBC 128), TPM usage disabled, key can be stored on USB.
- **IPsec:** `AssumeWeakAlgorithms=1`, DH minimum 512 bits.

#### 3.3.2 Authentication (`DowngradeAuthentication`)

- **LM / NTLM weakened:** `LmCompatibilityLevel=0`, `NoLMHash=0`, `ClearTextPassword=1`, all NTLM restrictions removed.
- **WDigest enabled:** `UseLogonCredential=1` – passwords stored in plaintext in LSASS.
- **Kerberos downgraded:** only DES and RC4 encryption types (`SupportedEncryptionTypes=0x1B`), PAC signature validation disabled, weak checksum types, ticket age reduced to 10 minutes, session key export allowed.
- **Credential Guard / LSASS protection disabled:** `RunAsPPL=0`, `LsaCfgFlags=0`, `EnableVirtualizationBasedSecurity=0`.
- **Cached logons increased:** `CachedLogonsCount=50`.
- **Blank password use allowed:** `LimitBlankPasswordUse=0`.
- **Auto‑admin logon:** `AutoAdminLogon=1`, `DefaultUserName` and empty `DefaultPassword` set.
- **Anonymous sessions enabled:** `RestrictAnonymous=0`, `RestrictAnonymousSAM=0`.

#### 3.3.3 Network & remote access (`DowngradeNetwork`)

- **SMB:** SMB1 re‑enabled (`SMB1=1`), security signatures disabled (server and workstation), encryption disabled, null sessions allowed, admin shares forced on.
- **RDP:** security layer set to 0 (native RDP), minimum encryption level 1, NLA disabled, password prompt disabled.
- **WinRM:** Basic authentication and unencrypted messages allowed (service and client).
- **LDAP:** client integrity disabled, server signing/integrity disabled.
- **NetBIOS / LLMNR / WPAD:** NodeType = 1 (broadcast), LMHOSTS enabled, multicast enabled, WPAD override disabled, AutoDetect enabled in IE.
- **Firewall:** all profiles (Domain, Standard, Public) disabled, then `netsh advfirewall set allprofiles state off` executed.
- **Additional ports/services:** The `OpenAttackVectors` function (if called separately) adds firewall rules for Telnet, FTP, SMB, RDP, WinRM, SSH, SNMP, VNC, MySQL, MSSQL, NetBIOS, and starts/enables those services if present.

#### 3.3.4 System hardening (`DowngradeSystemHardening`)

- **Exploit mitigations disabled:** ASLR (`MoveImages=0`), CFG (`EnableCfg=0`), CET shadow stacks, SEHOP (`DisableExceptionChainValidation=1`), stack pivot protection, heap termination, kernel protection mode all turned off.
- **UAC completely turned off:** `EnableLUA=0`, `ConsentPromptBehaviorAdmin=0`, `FilterAdministratorToken=0`, `PromptOnSecureDesktop=0`, `EnableVirtualization=0`, plus `LocalAccountTokenFilterPolicy=1` and `EnableLinkedConnections=1` to allow remote administration without elevation.
- **Windows Defender:** all real‑time protection components disabled, tamper protection source set to 0, cloud reporting/submission disabled.
- **AMSI:** disabled system‑wide and for the current user.
- **PowerShell:** execution policy set to `Bypass`.
- **SmartScreen:** turned off.
- **Driver signing:** policy set to 0 (ignore).
- **Windows Update:** completely disabled (`NoAutoUpdate=1`, `DisableWindowsUpdateAccess=1`).
- **Event logs:** EventLog service start type set to 4 (disabled), Security log max size 64 KB, retention 0, Windows Error Reporting disabled.

#### 3.3.5 Misc (`DowngradeMisc`)

- **IE zones:** all five security zones set to minimum protection (values `1406=0`, `2500=0`).
- **AutoRun:** re‑enabled for all drives.
- **DCOM/RPC:** legacy authentication and impersonation levels set to 1, integrity activation requirement removed.
- **AppLocker:** enforcement mode set to 0 (audit only).
- **Telnet/TFTP/SNMP:** Telnet client and TFTP enabled via `dism`; Telnet server start set to auto; SNMP `public` community with READ_WRITE access.

---

### 3.4 Timestomping (`TimestompAllAccessibleFiles`)

- Generates random `FILETIME` values between 1990 and 2030 using `std::random_device` and `std::mt19937_64`.
- Recursively walks a limited set of directories:
  - `%APPDATA%`
  - `%LOCALAPPDATA%`
  - `%TEMP%`
  - The directory containing the malware executable.
- Limits recursion depth to **5** and total processed files to **2000** to avoid excessively long execution.
- Skips reparse points and a list of system directories (e.g., `Windows`, `Program Files`, `Boot`, `Recovery`, etc.) when `skipSystemDirs` is `true`.
- Uses `CreateFileW` with `FILE_FLAG_BACKUP_SEMANTICS` and the `\\?\` prefix to handle long paths.

This is a **simplified and optimised** version of the original code, which scanned every drive and could take hours. The current implementation is fast enough for a PoC and still demonstrates the technique.

---

### 3.5 Shortcut Hijacking (`HijackAllShortcuts`)

This module targets the victim’s desktop shortcuts to trick them into running the malware.

**Workflow:**

1. Retrieves the desktop directory path.
2. Searches for all `*.lnk` files using `FindFirstFileW`.
3. For each shortcut:
   - Calls `GetShortcutInfo` to read the original target path and icon location.
   - If the original icon path is empty, it uses the original target as the icon source.
   - Calls `ModifyShortcut` to change the shortcut’s **target** to the malware path, while preserving the **icon** and **description** (description is set to empty in this version).
4. The shortcut name remains the same (e.g., “Notatnik.lnk”).

**Result:**  
When the user double‑clicks the altered shortcut, they see a familiar icon and name, but the malware is executed instead of the legitimate program. Because the malware immediately attempts UAC elevation (see section 3.6), the user may be prompted for administrator credentials, which they are likely to accept.

**Technical notes:**

- `IShellLinkW` and `IPersistFile` COM interfaces are used.
- The code correctly uses the wide‑string versions (`IShellLinkW`) to avoid ANSI/Unicode mismatches.
- Libraries `ole32` and `uuid` must be linked.

---

### 3.6 Privilege Escalation (`IsElevated` & `ElevateSelf`)

- `IsElevated()` opens the current process token and queries `TokenElevation`.
- `ElevateSelf()` obtains the current executable path and calls `ShellExecuteExW` with the `runas` verb, which triggers the Windows UAC consent dialog.
- If the user accepts, a new elevated process is spawned, and the original exits (`return 0`).
- If the user rejects, the original continues with **non‑elevated** privileges. In this case:
  - It hijacks desktop shortcuts.
  - Performs user‑level timestomping.
  - Exits without setting the `Installed` flag, so the attack can be retried later.

This is not a true privilege escalation exploit; it relies on social engineering (the user must click “Yes” in UAC).

---

### 3.7 Null‑Terminated Registry Value Names

One of the persistence methods (user‑level Run key) utilises a **null‑terminated string trick** to hide the value name from `regedit.exe`.

**How it works:**

- A standard registry value name is a sequence of wide characters terminated by a `L'\0'`.
- The Windows registry API (`RegSetValueExW`) accepts a pointer to the name and a length (in bytes).  
  If the name contains an embedded null character at the beginning, e.g., `"\0MicrosoftEdgeUpdate"`, the API will treat the entire buffer as the name, including the leading null.
- However, applications that display registry names (like `regedit`) typically treat the name as a null‑terminated string and stop at the first `L'\0'`. As a result, a name starting with `\0` appears **empty** or **invisible**.
- This technique has been used by malware to hide autostart entries.

**In this PoC:**

The function `SetRegistryString` (used by `InstallRunHidden`) builds the name by:

```
std::wstring hidden;
hidden.push_back(L'\0');
hidden += valueName;   // e.g., L"SecurityHealth"
```

When passed to `RegSetValueExW`, the full length (`(hidden.size() + 1) * sizeof(wchar_t)`) is provided, so the registry stores the entire name including the leading null. `regedit.exe` shows the value as if it had no name, making it much harder to spot.

---

## 4. Installation Flag and Post‑Reboot Behaviour

The flag `Installed` is stored as a DWORD value under `HKEY_CURRENT_USER\Software\MyMalware`.

- **First run** (flag not set):
  - The malware installs persistence, sets the flag, and performs the downgrade.
- **Subsequent runs** (flag set):
  - The program immediately enters the `else` branch of `if (!IsInstalledFlagSet())` and does nothing except return 0. This simulates a “silent mode” where the attacker could later replace the empty block with a real payload (e.g., backdoor, keylogger).

**Purpose of the flag:**

- Prevents repeated UAC prompts (if the malware is launched again from a shortcut or manually).
- Ensures that expensive or noisy operations (downgrade, persistence installation) are executed only once.
- Allows the malware to “disappear” after installation, reducing the chance of detection.

---

## 5. Plans with Veneronica

### 5.1 Decoy Replacement (`ReplaceOriginalWithDecoy`)

**Current status:** This feature was partially implemented in the original source but has been removed from the current build due to issues with file handling. It is planned for reintroduction in a future iteration.

**Planned functionality:**

- After the malware installs itself and ensures persistence, the original executable (the one the victim launched) is replaced with a **decoy file** to disguise the infection.
- The decoy is a small, harmless file (e.g., a fake installer, error message, or system utility) that matches the original filename, so the victim does not notice that the malware has disappeared.
- A pool of 10 decoys is planned, each with a different name, message, and optional icon:
  - `setup.exe` – displays “Avast Free Antivirus Installer” style message.
  - `error.exe` – shows a critical system error.
  - `update.exe` – mimics Windows Update Assistant.
  - `install.exe` – pretends to be Adobe Reader Setup.
  - `cleaner.exe` – imitates CCleaner.
  - `patch.exe` – simulates a game patch.
  - `driver.exe` – fakes NVIDIA driver installation.
  - `firewall.exe` – pretends to configure Windows Firewall.
  - `uninstall.exe` – masquerades as a program uninstaller.
  - `diagnostic.exe` – shows a system diagnostic tool.
- The decoy is selected randomly using `rand() % 10`.
- The replacement is performed by copying the decoy over the original path (`CopyFileW`), then deleting the temporary decoy file.
- In a more sophisticated implementation, the decoy would be a real executable embedded as a resource, not a plain text file, to better mimic legitimate software and avoid suspicion.

**Goal:** Hide the fact that the original malware executable has been moved or changed. The user sees a familiar-looking file and does not suspect that the malware is still active through persistence mechanisms.

### 5.2 Other Future Enhancements

- **Dynamic decoy generation** – compile decoys into resources and extract them at runtime.
- **Icon spoofing** – assign real icons (e.g., Notepad, Word, Adobe) to decoys for greater authenticity.
- **Anti‑forensics improvements** – expand timestomping to include additional user directories and more sophisticated timestamp randomisation.
- **Modular payload** – replace the empty “silent payload” branch with configurable modules (e.g., keylogger, backdoor, screen capture).

---

## 6. Summary of Technical Highlights

| Feature | Implementation |
|---------|----------------|
| **Polymorphism** | Self‑copy to `.tmp`, search for marker, randomise data, replace on reboot. |
| **Persistence (user)** | 9 methods incl. null‑terminated Run, screensaver, IFEO, App Paths, protocol handler. |
| **Persistence (admin)** | 9 methods incl. service, Shell replacement, BootExecute, AppInit_DLLs. |
| **Downgrade** | Over 90 unique registry modifications across 5 categories. |
| **Timestomp** | Random timestamps in user directories, depth/limit capped. |
| **Shortcut hijack** | COM‑based modification of all desktop `.lnk` files, preserving icons. |
| **UAC elevation** | `ShellExecuteExW` with `runas`; user must accept. |
| **Install flag** | Prevents re‑installation; post‑reboot runs are silent. |
| **Registry hiding** | Null‑terminated value names invisible in `regedit`. |

---

## 7. Final Remarks

This PoC is intentionally messy and redundant in places, reflecting how a novice malware author might write code. The refactored sections (downgrade categories, shortcut hijacking) show how the original functionality could be organised more cleanly. **It is intended solely for controlled environments and educational analysis.**

---

## 8. Build Instructions

Compile the source with MinGW‑w64 or MSVC. The following command uses G++ and links all required libraries:

```
g++ -o veneronica.exe veneronica.cpp -mwindows -static -ladvapi32 -luser32 -lshell32 -lwinmm -lole32 -luuid
```
---

## 9. Origin of the Name




| Bogdan Boner (left) | Mężczyzna (right) |
|----------------------|-------------------|
| <span style="color:#3399ff;">**Bogdan Boner:** Dziewczyna, najtańsza jaką macie.</span> | |
| | <span style="color:#ff6600;">**Mężczyzna:** Eee... jesteś pewien?</span> |
| <span style="color:#3399ff;">**Bogdan Boner:** Jak sraczki po czereśniach.</span> | |
| | <span style="color:#ff6600;">**Mężczyzna:** No nic. Nasz klient, nasz pan. Czyli Weneronika.</span> |
| <span style="color:#3399ff;">**Bogdan Boner:** No dobra, to pisz pan adres. Dyktuję.</span> | |
| | <span style="color:#ff6600;">**Mężczyzna:** Nie trzeba, znam. Przecież numer mi się wyświetlił.</span> |

The name was chosen as an inside joke — dark, slightly vulgar, and not immediately associated with malware, which fits the overall PoC character of this project.

<div style="background-color:#141414; border-left:6px solid #b8860b; padding:20px 25px; border-radius:8px; font-family:Georgia, 'Times New Roman', serif;">

<p style="font-size:1.2em; font-style:italic; color:#e6d5a8; line-height:1.6;">

“Veneronica — this is interesting, in some moments beautiful, but it is cheap, and in time it can be destructive.”

</p>

<p style="text-align:right; color:#8b7d5b; font-size:0.9em; letter-spacing:1px;"></p>

</div>
<div align="center">
<sub>Veneronica — Academic PoC. Use responsibly.</sub>
</div>