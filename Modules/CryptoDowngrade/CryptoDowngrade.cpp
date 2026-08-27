#include <windows.h>
#include <string>

// Forward declarations of helper functions
bool SetDword(HKEY root, const wchar_t* subkey, const wchar_t* valueName, DWORD value);
bool SetString(HKEY root, const wchar_t* subkey, const wchar_t* valueName, const std::wstring& value);
void SetProtocolSettings(const wchar_t* protocol, const wchar_t* direction);

// Forward declarations of core registry modification functions
void ApplyDowngradeUserOnly();
void ApplyDowngradeFull();

// --------------------------------------------------------------
// Helper Function Implementations
// --------------------------------------------------------------
bool SetDword(HKEY root, const wchar_t* subkey, const wchar_t* valueName, DWORD value) {
    return RegSetKeyValueW(root, subkey, valueName, REG_DWORD, &value, sizeof(value)) == ERROR_SUCCESS;
}

bool SetString(HKEY root, const wchar_t* subkey, const wchar_t* valueName, const std::wstring& value) {
    return RegSetKeyValueW(root, subkey, valueName, REG_SZ,
                         value.c_str(), (value.size() + 1) * sizeof(wchar_t)) == ERROR_SUCCESS;
}

void SetProtocolSettings(const wchar_t* protocol, const wchar_t* direction) {
    std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\";
    keyPath += protocol;
    keyPath += L"\\";
    keyPath += direction;

    SetDword(HKEY_LOCAL_MACHINE, keyPath.c_str(), L"Enabled", 1);
    SetDword(HKEY_LOCAL_MACHINE, keyPath.c_str(), L"DisabledByDefault", 0);
}

// --------------------------------------------------------------
// ApplyDowngradeUserOnly Implementation
// --------------------------------------------------------------
void ApplyDowngradeUserOnly() {
    HKEY hKey;
    DWORD dwDisposition;

    if (RegCreateKeyExW(HKEY_CURRENT_USER, 
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS) {
        
        DWORD value = 0x00000AA8; 
        RegSetValueExW(hKey, L"SecureProtocols", 0, REG_DWORD, (BYTE*)&value, sizeof(DWORD));
        RegCloseKey(hKey);
    }

    if (RegCreateKeyExW(HKEY_CURRENT_USER, 
        L"SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS) {
        
        DWORD zero = 0;
        RegSetValueExW(hKey, L"SchUseStrongCrypto", 0, REG_DWORD, (BYTE*)&zero, sizeof(DWORD));
        RegSetValueExW(hKey, L"SystemDefaultTlsVersions", 0, REG_DWORD, (BYTE*)&zero, sizeof(DWORD));
        RegCloseKey(hKey);
    }

    if (RegCreateKeyExW(HKEY_CURRENT_USER, 
        L"SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS) {
        
        DWORD zero = 0;
        RegSetValueExW(hKey, L"SchUseStrongCrypto", 0, REG_DWORD, (BYTE*)&zero, sizeof(DWORD));
        RegSetValueExW(hKey, L"SystemDefaultTlsVersions", 0, REG_DWORD, (BYTE*)&zero, sizeof(DWORD));
        RegCloseKey(hKey);
    }

    if (RegCreateKeyExW(HKEY_CURRENT_USER, 
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS) {
        
        DWORD value = 0x00000AA8;
        RegSetValueExW(hKey, L"DefaultSecureProtocols", 0, REG_DWORD, (BYTE*)&value, sizeof(DWORD));
        RegCloseKey(hKey);
    }
}

// --------------------------------------------------------------
// ApplyDowngradeFull Implementation
// --------------------------------------------------------------
void ApplyDowngradeFull() {
    const wchar_t* protocols[] = {
        L"Multi-Protocol Unified Hello",
        L"PCT 1.0",
        L"SSL 2.0",
        L"SSL 3.0",
        L"TLS 1.0",
        L"TLS 1.1",
        L"TLS 1.2",
        L"TLS 1.3"
    };

    for (auto proto : protocols) {
        SetProtocolSettings(proto, L"Client");
        SetProtocolSettings(proto, L"Server");
    }

    const wchar_t* ciphers[] = {
        L"NULL", L"DES 56/56", L"RC2 40/128", L"RC2 56/128", L"RC2 128/128",
        L"RC4 40/128", L"RC4 56/128", L"RC4 64/128", L"RC4 128/128",
        L"Triple DES 168", L"AES 128/128", L"AES 256/256"
    };
    for (auto cipher : ciphers) {
        std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\";
        keyPath += cipher;
        SetDword(HKEY_LOCAL_MACHINE, keyPath.c_str(), L"Enabled", 0xffffffff);
    }

    const wchar_t* hashes[] = { L"MD5", L"SHA", L"SHA256", L"SHA384", L"SHA512" };
    for (auto hash : hashes) {
        std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\";
        keyPath += hash;
        SetDword(HKEY_LOCAL_MACHINE, keyPath.c_str(), L"Enabled", 0xffffffff);
    }

    const wchar_t* kexAlgos[] = { L"Diffie-Hellman", L"PKCS", L"ECDH" };
    for (auto kex : kexAlgos) {
        std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\";
        keyPath += kex;
        SetDword(HKEY_LOCAL_MACHINE, keyPath.c_str(), L"Enabled", 0xffffffff);
    }

    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman",
        L"ServerMinKeyBitLength", 512);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman",
        L"ClientMinKeyBitLength", 512);

    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL",
        L"AllowInsecureRenegotiation", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL",
        L"DisableRenegoOnClient", 0);

    std::wstring cipherPriority =
        L"TLS_RSA_WITH_NULL_MD5,TLS_RSA_WITH_NULL_SHA,TLS_RSA_WITH_DES_CBC_SHA,"
        L"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,TLS_RSA_WITH_RC4_128_MD5,"
        L"TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA,"
        L"TLS_RSA_WITH_AES_128_CBC_SHA,TLS_AES_256_GCM_SHA384";
    SetString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002",
        L"Functions", cipherPriority);

    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy", L"Enabled", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config",
        L"MinRsaPubKeyBitLength", 384);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot", L"DisableRootAutoUpdate", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters", L"EnableHttp3", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters", L"EnableAltSvc", 1);

    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"SMB1", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"SMB2", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"EncryptData", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"RejectUnencryptedAccess", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"EnableSecuritySignature", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"RequireSecuritySignature", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters", L"EnableSecuritySignature", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters", L"RequireSecuritySignature", 0);
    SetString(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        L"Smb3SupportedEncryptionAlgorithms", L"");

    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service", L"AllowUnencryptedMessages", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service", L"AllowBasic", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client", L"AllowUnencryptedMessages", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client", L"AllowBasic", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", L"SecurityLayer", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", L"MinEncryptionLevel", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", L"UserAuthentication", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"System\\CurrentControlSet\\Control\\Lsa", L"DisableRestrictedAdmin", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation", L"RequireRemoteCredentialGuard", 0);

    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319", L"SchUseStrongCrypto", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319", L"SystemDefaultTlsVersions", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319", L"SchUseStrongCrypto", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319", L"SystemDefaultTlsVersions", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp",
        L"DefaultSecureProtocols", 0x00002A80);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp",
        L"DefaultSecureProtocols", 0x00002A80);

    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", L"UseLogonCredential", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LsaCfgFlags", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"System\\CurrentControlSet\\Control\\Lsa", L"NoLMHash", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"CachedLogonsCount", 50);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LmCompatibilityLevel", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"RestrictSendingNTLMTraffic", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"RestrictReceivingNTLMTraffic", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"NtlmMinClientSec", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"NtlmMinServerSec", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters",
        L"SupportedEncryptionTypes", 31);
    SetDword(HKEY_LOCAL_MACHINE,
        L"System\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters", L"allowtgtsessionkey", 1);

    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", L"RequireStrongKey", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", L"RequireSignOrSeal", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", L"SealSecureChannel", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", L"SignSecureChannel", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LDAP", L"LDAPClientIntegrity", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters", L"LDAPServerIntegrity", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters", L"LdapEnforceChannelBinding", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc", L"RestrictRemoteClients", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\RpcEptMapper\\Parameters", L"RestrictRemoteClients", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc", L"Integrity", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Ole\\AppCompat", L"RequireIntegrityActivationAuthenticationLevel", 0);

    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EFS", L"AlgorithmID", 0x6603);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EFS", L"EfsConfiguration", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\FVE", L"EncryptionMethodWithXtsOs", 3);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\FVE", L"EncryptionMethodWithXtsFd", 3);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\FVE", L"EncryptionMethodWithXtsRdv", 3);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\FVE", L"DisableHardwareEncryption", 0);

    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\RasMan\\Parameters", L"AllowPPTPWeakCrypto", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\RasMan\\Parameters", L"AllowLmAuthentication", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\RasMan\\PPP\\EAP\\4", L"RolesSupported", 1);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\RasMan\\PPP\\EAP\\13", L"TlsVersion", 0xC0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"System\\CurrentControlSet\\Services\\Rasman\\Parameters\\IKEv2",
        L"CustomPolicyAuthTransformConstants", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"System\\CurrentControlSet\\Services\\Rasman\\Parameters\\IKEv2",
        L"CustomPolicyCipherTransformConstants", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"System\\CurrentControlSet\\Services\\Rasman\\Parameters\\IKEv2",
        L"CustomPolicyMacTransformConstants", 0);

    SetDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", L"EnableMulticast", 0);
    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", L"EnableAutoDoh", 1);

    wchar_t username[256] = {0};
    DWORD userSize = 256;
    if (GetUserNameW(username, &userSize)) {
        wchar_t domain[256] = {0};
        DWORD domSize = GetEnvironmentVariableW(L"USERDOMAIN", domain, 256);
        if (domSize == 0) {
            domSize = GetEnvironmentVariableW(L"COMPUTERNAME", domain, 256);
        }

        if (domSize > 0) {
            SetString(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                L"AutoAdminLogon", L"1");
            SetString(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                L"DefaultUserName", username);
            SetString(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                L"DefaultDomainName", domain);
            SetString(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                L"DefaultPassword", L"");
        }
    }

    SetDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"LimitBlankPasswordUse", 0);
}

// --------------------------------------------------------------
// WinMain Entry Point
// --------------------------------------------------------------
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                    LPSTR lpCmdLine, int nCmdShow)
{
    // Apply user-level configurations (HKCU)
    ApplyDowngradeUserOnly();

    // Apply full system-level configurations (HKLM - requires Administrator privileges)
    ApplyDowngradeFull();

    MessageBoxA(NULL, "Registry modifications completed successfully.", "Info", MB_OK);

    return 0;
}