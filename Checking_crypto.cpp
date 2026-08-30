// SecurityChecker_file.cpp
// Compile: g++ -std=c++11 -O2 -Wall -mconsole -municode -o SecurityChecker.exe SecurityChecker_file.cpp -ladvapi32 -luser32

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winreg.h>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <ctime>

// ---- Utility functions ----

bool ReadDWORD(HKEY root, LPCWSTR subkey, LPCWSTR valueName, DWORD& outValue) {
    HKEY hKey;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;
    DWORD type = 0, size = sizeof(DWORD);
    bool ok = (RegQueryValueExW(hKey, valueName, nullptr, &type, (LPBYTE)&outValue, &size) == ERROR_SUCCESS && type == REG_DWORD);
    RegCloseKey(hKey);
    return ok;
}

bool ReadString(HKEY root, LPCWSTR subkey, LPCWSTR valueName, std::wstring& outValue) {
    HKEY hKey;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;
    WCHAR buf[4096] = {0};
    DWORD size = sizeof(buf), type = 0;
    bool ok = (RegQueryValueExW(hKey, valueName, nullptr, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ));
    if (ok) outValue = buf;
    RegCloseKey(hKey);
    return ok;
}

bool KeyExists(HKEY root, LPCWSTR subkey) {
    HKEY hKey;
    LONG res = RegOpenKeyExW(root, subkey, 0, KEY_READ, &hKey);
    if (res == ERROR_SUCCESS) RegCloseKey(hKey);
    return (res == ERROR_SUCCESS);
}

// ---- Status enum ----

enum class Status {
    SECURE, DOWNGRADED, WARNING, INFO, MISSING
};

std::wstring StatusToString(Status s) {
    switch (s) {
        case Status::SECURE:     return L"✅ SECURE";
        case Status::DOWNGRADED: return L"❌ DOWNGRADED";
        case Status::WARNING:    return L"⚠️  WARNING";
        case Status::INFO:       return L"ℹ️  INFO";
        case Status::MISSING:    return L"➖ MISSING (secure default)";
    }
    return L"UNKNOWN";
}

// ---- Check item ----

struct CheckItem {
    std::wstring category;
    std::wstring name;
    std::wstring description;
    Status status;
    std::wstring details;
    std::wstring recommendation;

    CheckItem(const std::wstring& cat, const std::wstring& n, const std::wstring& desc)
        : category(cat), name(n), description(desc), status(Status::MISSING), details(L""), recommendation(L"") {}
};

// ---- Check functions (identical to before) ----

void CheckProtocol(CheckItem& item, LPCWSTR protocol, LPCWSTR direction) {
    std::wstring base = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\";
    std::wstring key = base + protocol + L"\\" + direction;
    DWORD enabled = 0, disabledByDefault = 0;
    bool hasEnabled = ReadDWORD(HKEY_LOCAL_MACHINE, key.c_str(), L"Enabled", enabled);
    bool hasDisabled = ReadDWORD(HKEY_LOCAL_MACHINE, key.c_str(), L"DisabledByDefault", disabledByDefault);

    if (!hasEnabled && !hasDisabled) {
        item.status = Status::SECURE;
        item.details = L"Not configured (default secure).";
        item.recommendation = L"Keep default (disabled).";
    } else if (hasEnabled && hasDisabled) {
        std::wstring details = L"Enabled=" + std::to_wstring(enabled) + L", DisabledByDefault=" + std::to_wstring(disabledByDefault);
        item.details = details;
        if (enabled == 1 && disabledByDefault == 0) {
            item.status = Status::DOWNGRADED;
            item.recommendation = L"Disable this protocol (set Enabled=0, DisabledByDefault=1).";
        } else if (enabled == 0 && disabledByDefault == 1) {
            item.status = Status::SECURE;
            item.recommendation = L"Secure configuration.";
        } else {
            item.status = Status::WARNING;
            item.recommendation = L"Check configuration; may be partially insecure.";
        }
    } else {
        item.status = Status::WARNING;
        item.details = L"Incomplete configuration.";
        item.recommendation = L"Set both Enabled and DisabledByDefault appropriately.";
    }
}

void CheckDWORD(CheckItem& item, HKEY root, LPCWSTR subkey, LPCWSTR valueName,
                DWORD secureValue, bool exactMatch = true,
                const std::wstring& secureDesc = L"", const std::wstring& downgradeDesc = L"") {
    DWORD val = 0;
    bool exists = ReadDWORD(root, subkey, valueName, val);
    if (!exists) {
        item.status = Status::SECURE;
        item.details = L"Value not present (default secure).";
        item.recommendation = L"Keep default.";
        return;
    }
    std::wstring details = L"Value = " + std::to_wstring(val);
    item.details = details;

    bool isSecure = exactMatch ? (val == secureValue) : (val >= secureValue);
    if (isSecure) {
        item.status = Status::SECURE;
        item.recommendation = secureDesc.empty() ? L"Secure configuration." : secureDesc;
    } else {
        item.status = Status::DOWNGRADED;
        item.recommendation = downgradeDesc.empty() ? L"Change to secure value (" + std::to_wstring(secureValue) + L")." : downgradeDesc;
    }
}

void CheckDWORDRange(CheckItem& item, HKEY root, LPCWSTR subkey, LPCWSTR valueName,
                     DWORD minSecure, DWORD maxSecure,
                     const std::wstring& secureDesc = L"", const std::wstring& downgradeDesc = L"") {
    DWORD val = 0;
    bool exists = ReadDWORD(root, subkey, valueName, val);
    if (!exists) {
        item.status = Status::SECURE;
        item.details = L"Value not present (default secure).";
        item.recommendation = L"Keep default.";
        return;
    }
    std::wstring details = L"Value = " + std::to_wstring(val);
    item.details = details;

    if (val >= minSecure && val <= maxSecure) {
        item.status = Status::SECURE;
        item.recommendation = secureDesc.empty() ? L"Secure configuration." : secureDesc;
    } else {
        item.status = Status::DOWNGRADED;
        item.recommendation = downgradeDesc.empty() ? L"Change to value between " + std::to_wstring(minSecure) + L" and " + std::to_wstring(maxSecure) + L"." : downgradeDesc;
    }
}

void CheckString(CheckItem& item, HKEY root, LPCWSTR subkey, LPCWSTR valueName,
                 const std::wstring& secureValue, bool caseSensitive = false,
                 const std::wstring& secureDesc = L"", const std::wstring& downgradeDesc = L"") {
    std::wstring val;
    bool exists = ReadString(root, subkey, valueName, val);
    if (!exists) {
        item.status = Status::SECURE;
        item.details = L"Value not present (default secure).";
        item.recommendation = L"Keep default.";
        return;
    }
    std::wstring details = L"Value = \"" + val + L"\"";
    item.details = details;

    bool isSecure = caseSensitive ? (val == secureValue) : (_wcsicmp(val.c_str(), secureValue.c_str()) == 0);
    if (isSecure) {
        item.status = Status::SECURE;
        item.recommendation = secureDesc.empty() ? L"Secure configuration." : secureDesc;
    } else {
        item.status = Status::DOWNGRADED;
        item.recommendation = downgradeDesc.empty() ? L"Change to \"" + secureValue + L"\"." : downgradeDesc;
    }
}

// ---- The main check function (unchanged logic) ----

void RunSecurityCheck(std::vector<CheckItem>& results) {
    // ====================================================================
    // 1. TLS / SSL PROTOCOLS
    // ====================================================================
    auto addProtocolCheck = [&](const wchar_t* proto, const wchar_t* dir, const wchar_t* desc) {
        CheckItem item(L"TLS/SSL Protocols", desc, L"");
        CheckProtocol(item, proto, dir);
        results.push_back(item);
    };

    addProtocolCheck(L"SSL 2.0", L"Server", L"SSL 2.0 (Server)");
    addProtocolCheck(L"SSL 2.0", L"Client", L"SSL 2.0 (Client)");
    addProtocolCheck(L"SSL 3.0", L"Server", L"SSL 3.0 (Server)");
    addProtocolCheck(L"SSL 3.0", L"Client", L"SSL 3.0 (Client)");
    addProtocolCheck(L"TLS 1.0", L"Server", L"TLS 1.0 (Server)");
    addProtocolCheck(L"TLS 1.0", L"Client", L"TLS 1.0 (Client)");
    addProtocolCheck(L"TLS 1.1", L"Server", L"TLS 1.1 (Server)");
    addProtocolCheck(L"TLS 1.1", L"Client", L"TLS 1.1 (Client)");
    addProtocolCheck(L"TLS 1.2", L"Server", L"TLS 1.2 (Server)");
    addProtocolCheck(L"TLS 1.2", L"Client", L"TLS 1.2 (Client)");
    addProtocolCheck(L"TLS 1.3", L"Server", L"TLS 1.3 (Server)");
    addProtocolCheck(L"TLS 1.3", L"Client", L"TLS 1.3 (Client)");
    addProtocolCheck(L"PCT 1.0", L"Server", L"PCT 1.0 (Server)");
    addProtocolCheck(L"PCT 1.0", L"Client", L"PCT 1.0 (Client)");
    addProtocolCheck(L"Multi-Protocol Unified Hello", L"Server", L"Multi-Protocol Unified Hello (Server)");
    addProtocolCheck(L"Multi-Protocol Unified Hello", L"Client", L"Multi-Protocol Unified Hello (Client)");

    // ====================================================================
    // 2. SCHANNEL CIPHERS
    // ====================================================================
    struct CipherCheck { LPCWSTR cipher; bool weak; };
    std::vector<CipherCheck> ciphers = {
        { L"NULL", true },
        { L"DES 56/56", true },
        { L"RC2 40/128", true },
        { L"RC2 56/128", true },
        { L"RC2 128/128", false },
        { L"RC4 40/128", true },
        { L"RC4 56/128", true },
        { L"RC4 64/128", true },
        { L"RC4 128/128", true },
        { L"Triple DES 168", false },
        { L"AES 128/128", false },
        { L"AES 256/256", false }
    };
    for (auto& c : ciphers) {
        std::wstring key = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\";
        key += c.cipher;
        CheckItem item(L"SCHANNEL Ciphers", c.cipher, L"");
        DWORD enabled = 0;
        bool exists = ReadDWORD(HKEY_LOCAL_MACHINE, key.c_str(), L"Enabled", enabled);
        if (!exists) {
            item.status = Status::SECURE;
            item.details = L"Not configured (default secure).";
            item.recommendation = L"Keep default.";
        } else {
            item.details = L"Enabled = " + std::to_wstring(enabled);
            if (c.weak) {
                if (enabled == 0xffffffff) {
                    item.status = Status::DOWNGRADED;
                    item.recommendation = L"Disable this weak cipher (set Enabled=0).";
                } else {
                    item.status = Status::SECURE;
                    item.recommendation = L"Secure configuration.";
                }
            } else {
                if (enabled == 0xffffffff) {
                    item.status = Status::SECURE;
                    item.recommendation = L"Secure (strong cipher enabled).";
                } else {
                    item.status = Status::WARNING;
                    item.recommendation = L"Strong cipher disabled; consider enabling.";
                }
            }
        }
        results.push_back(item);
    }

    // ====================================================================
    // 3. SCHANNEL HASHES
    // ====================================================================
    struct HashCheck { LPCWSTR hash; bool weak; };
    std::vector<HashCheck> hashes = {
        { L"MD5", true },
        { L"SHA", false },
        { L"SHA256", false },
        { L"SHA384", false },
        { L"SHA512", false }
    };
    for (auto& h : hashes) {
        std::wstring key = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Hashes\\";
        key += h.hash;
        CheckItem item(L"SCHANNEL Hashes", h.hash, L"");
        DWORD enabled = 0;
        bool exists = ReadDWORD(HKEY_LOCAL_MACHINE, key.c_str(), L"Enabled", enabled);
        if (!exists) {
            item.status = Status::SECURE;
            item.details = L"Not configured (default secure).";
            item.recommendation = L"Keep default.";
        } else {
            item.details = L"Enabled = " + std::to_wstring(enabled);
            if (h.weak) {
                if (enabled == 0xffffffff) {
                    item.status = Status::DOWNGRADED;
                    item.recommendation = L"Disable weak MD5 hash (set Enabled=0).";
                } else {
                    item.status = Status::SECURE;
                    item.recommendation = L"Secure configuration.";
                }
            } else {
                if (enabled == 0xffffffff) {
                    item.status = Status::SECURE;
                    item.recommendation = L"Secure (hash enabled).";
                } else {
                    item.status = Status::WARNING;
                    item.recommendation = L"Hash disabled; consider enabling for strong ciphers.";
                }
            }
        }
        results.push_back(item);
    }

    // ====================================================================
    // 4. SCHANNEL KEY EXCHANGE
    // ====================================================================
    struct KexCheck { LPCWSTR kex; bool weak; };
    std::vector<KexCheck> kexes = {
        { L"Diffie-Hellman", false },
        { L"PKCS", false },
        { L"ECDH", false },
        { L"ECDHE", false }
    };
    for (auto& k : kexes) {
        std::wstring key = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\";
        key += k.kex;
        CheckItem item(L"SCHANNEL Key Exchange", k.kex, L"");
        DWORD enabled = 0;
        bool exists = ReadDWORD(HKEY_LOCAL_MACHINE, key.c_str(), L"Enabled", enabled);
        if (!exists) {
            item.status = Status::SECURE;
            item.details = L"Not configured (default secure).";
            item.recommendation = L"Keep default.";
        } else {
            item.details = L"Enabled = " + std::to_wstring(enabled);
            if (enabled == 0xffffffff) {
                item.status = Status::SECURE;
                item.recommendation = L"Key exchange enabled (secure).";
            } else {
                if (wcscmp(k.kex, L"ECDHE") == 0 || wcscmp(k.kex, L"ECDH") == 0) {
                    item.status = Status::WARNING;
                    item.recommendation = L"Modern key exchange disabled; consider enabling.";
                } else {
                    item.status = Status::SECURE;
                    item.recommendation = L"Key exchange disabled (may be fine).";
                }
            }
        }
        results.push_back(item);
    }

    // DH min key lengths
    {
        CheckItem item(L"Diffie-Hellman", L"DH Minimum Key Length (Server)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman",
                   L"ServerMinKeyBitLength", 2048, false, L"ServerMinKeyBitLength >= 2048 (secure).", L"Set to 2048 or higher.");
        results.push_back(item);
    }
    {
        CheckItem item(L"Diffie-Hellman", L"DH Minimum Key Length (Client)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\KeyExchangeAlgorithms\\Diffie-Hellman",
                   L"ClientMinKeyBitLength", 2048, false, L"ClientMinKeyBitLength >= 2048 (secure).", L"Set to 2048 or higher.");
        results.push_back(item);
    }

    // ====================================================================
    // 5. SCHANNEL MISCELLANEOUS
    // ====================================================================
    {
        CheckItem item(L"SCHANNEL Misc", L"Allow Insecure Renegotiation", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL",
                   L"AllowInsecureRenegotiation", 0, true, L"Disabled (secure).", L"Disable (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"SCHANNEL Misc", L"Disable Renegotiation on Client", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL",
                   L"DisableRenegoOnClient", 1, true, L"Disabled (secure).", L"Enable (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"SCHANNEL Misc", L"Certificate Revocation Check", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL",
                   L"CertificateRevocation", 1, true, L"CRL check enabled (secure).", L"Enable CRL check (set 1).");
        results.push_back(item);
    }

    // ====================================================================
    // 6. SYSTEM CRYPTOGRAPHY
    // ====================================================================
    {
        CheckItem item(L"System Crypto", L"FIPS Algorithm Policy", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy",
                   L"Enabled", 0, true, L"FIPS disabled (not required, but fine).", L"FIPS enabled may break compatibility; consider disabling unless required.");
        results.push_back(item);
    }
    {
        CheckItem item(L"System Crypto", L"Minimum RSA Public Key Length", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllCreateCertificateChainEngine\\Config",
                   L"MinRsaPubKeyBitLength", 2048, false, L"MinRsaPubKeyBitLength >= 2048 (secure).", L"Set to 2048 or higher.");
        results.push_back(item);
    }
    {
        CheckItem item(L"System Crypto", L"Root Certificate Auto-Update", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot",
                   L"DisableRootAutoUpdate", 0, true, L"Auto-update enabled (secure).", L"Enable auto-update (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"System Crypto", L"HTTP/3 Enable", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters",
                   L"EnableHttp3", 0, true, L"HTTP/3 disabled (secure, unless needed).", L"Enable only if needed.");
        results.push_back(item);
    }
    {
        CheckItem item(L"System Crypto", L"HTTP Alt-Svc Enable", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters",
                   L"EnableAltSvc", 0, true, L"Alt-Svc disabled (secure).", L"Enable only if needed.");
        results.push_back(item);
    }

    // ====================================================================
    // 7. SMB
    // ====================================================================
    {
        CheckItem item(L"SMB", L"SMBv1 Enabled", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                   L"SMB1", 0, true, L"SMBv1 disabled (secure).", L"Disable SMBv1 (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"SMB", L"SMBv2 Enabled", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                   L"SMB2", 1, true, L"SMBv2 enabled (secure).", L"Enable SMBv2 (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"SMB", L"SMB Encryption (Server)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                   L"EncryptData", 1, true, L"SMB encryption enabled (secure).", L"Enable SMB encryption (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"SMB", L"Reject Unencrypted Access", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                   L"RejectUnencryptedAccess", 1, true, L"Unencrypted access rejected (secure).", L"Reject unencrypted access (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"SMB", L"Server Signing Required", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                   L"RequireSecuritySignature", 1, true, L"Server signing required (secure).", L"Require signing (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"SMB", L"Client Signing Required", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
                   L"RequireSecuritySignature", 1, true, L"Client signing required (secure).", L"Require signing (set 1).");
        results.push_back(item);
    }

    // ====================================================================
    // 8. WINRM
    // ====================================================================
    {
        CheckItem item(L"WinRM", L"Allow Unencrypted Messages (Service)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
                   L"AllowUnencryptedMessages", 0, true, L"Unencrypted messages disallowed (secure).", L"Disallow unencrypted (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"WinRM", L"Allow Basic Auth (Service)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
                   L"AllowBasic", 0, true, L"Basic auth disabled (secure).", L"Disable Basic auth (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"WinRM", L"Allow Unencrypted Messages (Client)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client",
                   L"AllowUnencryptedMessages", 0, true, L"Unencrypted messages disallowed (secure).", L"Disallow unencrypted (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"WinRM", L"Allow Basic Auth (Client)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client",
                   L"AllowBasic", 0, true, L"Basic auth disabled (secure).", L"Disable Basic auth (set 0).");
        results.push_back(item);
    }

    // ====================================================================
    // 9. RDP
    // ====================================================================
    {
        CheckItem item(L"RDP", L"Security Layer", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                   L"SecurityLayer", 2, true, L"SSL/TLS security layer (secure).", L"Set to 2 (SSL/TLS).");
        results.push_back(item);
    }
    {
        CheckItem item(L"RDP", L"Minimum Encryption Level", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                   L"MinEncryptionLevel", 3, true, L"High encryption level (secure).", L"Set to 3 (High).");
        results.push_back(item);
    }
    {
        CheckItem item(L"RDP", L"Network Level Authentication (NLA)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                   L"UserAuthentication", 1, true, L"NLA enabled (secure).", L"Enable NLA (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"RDP", L"Restricted Admin Mode Disabled", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                   L"DisableRestrictedAdmin", 0, true, L"Restricted Admin mode enabled (secure).", L"Disable Restricted Admin (set 0).");
        results.push_back(item);
    }

    // ====================================================================
    // 10. .NET FRAMEWORK & WINHTTP
    // ====================================================================
    std::vector<std::wstring> netPaths = {
        L"SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319",
        L"SOFTWARE\\Microsoft\\.NETFramework\\v2.0.50727",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v2.0.50727"
    };
    for (auto& path : netPaths) {
        std::wstring name = L".NET " + path;
        {
            CheckItem item(L".NET Framework", name + L" SchUseStrongCrypto", L"");
            CheckDWORD(item, HKEY_LOCAL_MACHINE, path.c_str(), L"SchUseStrongCrypto", 1, true,
                       L"Strong crypto enabled (secure).", L"Enable strong crypto (set 1).");
            results.push_back(item);
        }
        {
            CheckItem item(L".NET Framework", name + L" SystemDefaultTlsVersions", L"");
            CheckDWORD(item, HKEY_LOCAL_MACHINE, path.c_str(), L"SystemDefaultTlsVersions", 1, true,
                       L"System default TLS versions used (secure).", L"Set to 1 to use system defaults.");
            results.push_back(item);
        }
    }

    {
        CheckItem item(L"WinHTTP", L"Default Secure Protocols (HKLM)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp",
                   L"DefaultSecureProtocols", 0x00000800, true, L"TLS 1.2 only (secure).", L"Set to 0x00000800 (TLS 1.2).");
        results.push_back(item);
    }
    {
        CheckItem item(L"WinHTTP", L"Default Secure Protocols (HKLM Wow6432)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp",
                   L"DefaultSecureProtocols", 0x00000800, true, L"TLS 1.2 only (secure).", L"Set to 0x00000800 (TLS 1.2).");
        results.push_back(item);
    }
    {
        CheckItem item(L"WinINET", L"Secure Protocols (HKCU)", L"");
        CheckDWORD(item, HKEY_CURRENT_USER,
                   L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                   L"SecureProtocols", 0x00000800, true, L"TLS 1.2 only (secure).", L"Set to 0x00000800 (TLS 1.2).");
        results.push_back(item);
    }

    // ====================================================================
    // 11. LSASS, NTLM, KERBEROS
    // ====================================================================
    {
        CheckItem item(L"LSASS", L"WDigest UseLogonCredential", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
                   L"UseLogonCredential", 0, true, L"WDigest disabled (secure).", L"Disable WDigest (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"LSASS", L"RunAsPPL (LSA Protection)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                   L"RunAsPPL", 1, true, L"LSA Protection enabled (secure).", L"Enable LSA Protection (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"LSASS", L"Credential Guard (LsaCfgFlags)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                   L"LsaCfgFlags", 1, true, L"Credential Guard enabled (secure).", L"Enable Credential Guard (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"LSASS", L"LM Hash Storage (NoLMHash)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                   L"NoLMHash", 1, true, L"LM hash disabled (secure).", L"Disable LM hash (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"LSASS", L"LmCompatibilityLevel", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                   L"LmCompatibilityLevel", 5, true, L"Send NTLMv2 only (secure).", L"Set to 5 (NTLMv2 only).");
        results.push_back(item);
    }
    {
        CheckItem item(L"LSASS", L"NTLM Client Minimum Security", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
                   L"NtlmMinClientSec", 0x20080000, true, L"Client requires NTLMv2, 128-bit encryption (secure).", L"Set to 0x20080000.");
        results.push_back(item);
    }
    {
        CheckItem item(L"LSASS", L"NTLM Server Minimum Security", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
                   L"NtlmMinServerSec", 0x20080000, true, L"Server requires NTLMv2, 128-bit encryption (secure).", L"Set to 0x20080000.");
        results.push_back(item);
    }
    {
        CheckItem item(L"Kerberos", L"Supported Encryption Types", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters",
                   L"SupportedEncryptionTypes", 0x7ffffff8, true, L"AES and RC4 supported (secure).", L"Set to 0x7ffffff8 (all strong).");
        results.push_back(item);
    }
    {
        CheckItem item(L"Kerberos", L"Allow TGT Session Key", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters",
                   L"allowtgtsessionkey", 0, true, L"TGT session key extraction disabled (secure).", L"Disable (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"Kerberos", L"Validate KDC PAC Signature", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters",
                   L"ValidateKdcPacSignature", 1, true, L"PAC signature validation enabled (secure).", L"Enable (set 1).");
        results.push_back(item);
    }

    // ====================================================================
    // 12. NETLOGON, LDAP, RPC
    // ====================================================================
    {
        CheckItem item(L"Netlogon", L"Require Strong Key", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                   L"RequireStrongKey", 1, true, L"Strong key required (secure).", L"Enable (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"Netlogon", L"Require Sign or Seal", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
                   L"RequireSignOrSeal", 1, true, L"Sign/seal required (secure).", L"Enable (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"LDAP", L"Client Integrity", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\LDAP",
                   L"LDAPClientIntegrity", 1, true, L"LDAP signing required (secure).", L"Enable (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"LDAP", L"Server Integrity", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
                   L"LDAPServerIntegrity", 1, true, L"LDAP server signing required (secure).", L"Enable (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"LDAP", L"Enforce Channel Binding", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
                   L"LdapEnforceChannelBinding", 1, true, L"Channel binding enforced (secure).", L"Enable (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"RPC", L"Restrict Remote Clients (Policies)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc",
                   L"RestrictRemoteClients", 1, true, L"Remote clients restricted (secure).", L"Enable (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"RPC", L"RPC Integrity", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc",
                   L"Integrity", 1, true, L"RPC integrity enabled (secure).", L"Enable (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"DCOM", L"Legacy Authentication Level", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Ole",
                   L"LegacyAuthenticationLevel", 2, true, L"Default authentication level (secure).", L"Set to 2 (default).");
        results.push_back(item);
    }

    // ====================================================================
    // 13. EFS & BITLOCKER
    // ====================================================================
    {
        CheckItem item(L"EFS", L"Algorithm ID", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EFS",
                   L"AlgorithmID", 0x6610, true, L"AES-256 (secure).", L"Set to 0x6610 (AES-256).");
        results.push_back(item);
    }
    {
        CheckItem item(L"EFS", L"EFS Configuration", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EFS",
                   L"EfsConfiguration", 0, true, L"EFS enabled (secure).", L"Enable EFS (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"BitLocker", L"OS Encryption Method", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\FVE",
                   L"EncryptionMethodWithXtsOs", 7, true, L"XTS-AES 256 (secure).", L"Set to 7 (XTS-AES 256).");
        results.push_back(item);
    }
    {
        CheckItem item(L"BitLocker", L"Fixed Disk Encryption Method", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\FVE",
                   L"EncryptionMethodWithXtsFd", 7, true, L"XTS-AES 256 (secure).", L"Set to 7 (XTS-AES 256).");
        results.push_back(item);
    }
    {
        CheckItem item(L"BitLocker", L"Removable Disk Encryption Method", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\FVE",
                   L"EncryptionMethodWithXtsRdv", 7, true, L"XTS-AES 256 (secure).", L"Set to 7 (XTS-AES 256).");
        results.push_back(item);
    }
    {
        CheckItem item(L"BitLocker", L"Save External Key to USB", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\FVE",
                   L"SaveExternalKeyToUSB", 0, true, L"Key not saved to USB (secure).", L"Disable (set 0).");
        results.push_back(item);
    }

    // ====================================================================
    // 14. VPN / RAS
    // ====================================================================
    {
        CheckItem item(L"VPN/RAS", L"Allow PPTP Weak Crypto", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\RasMan\\Parameters",
                   L"AllowPPTPWeakCrypto", 0, true, L"Weak PPTP crypto disabled (secure).", L"Disable (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"VPN/RAS", L"Allow L2TP Weak Crypto", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\RasMan\\Parameters",
                   L"AllowL2TPWeakCrypto", 0, true, L"Weak L2TP crypto disabled (secure).", L"Disable (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"VPN/RAS", L"PPP Control Protocols (PAP)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\services\\RasMan\\PPP\\ControlProtocols\\BuiltIn\\00000001",
                   L"Supported", 0, true, L"PAP disabled (secure).", L"Disable PAP (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"VPN/RAS", L"PPP Control Protocols (SPAP)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\services\\RasMan\\PPP\\ControlProtocols\\BuiltIn\\00000002",
                   L"Supported", 0, true, L"SPAP disabled (secure).", L"Disable SPAP (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"VPN/RAS", L"PPP Control Protocols (CHAP)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\services\\RasMan\\PPP\\ControlProtocols\\BuiltIn\\00000003",
                   L"Supported", 0, true, L"CHAP disabled (secure).", L"Disable CHAP (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"VPN/RAS", L"PPP Control Protocols (MS-CHAP v1)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\services\\RasMan\\PPP\\ControlProtocols\\BuiltIn\\00000004",
                   L"Supported", 0, true, L"MS-CHAP v1 disabled (secure).", L"Disable MS-CHAP v1 (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"VPN/RAS", L"EAP MD5-Challenge (type 4)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\services\\RasMan\\PPP\\EAP\\4",
                   L"Enabled", 0, true, L"MD5-Challenge disabled (secure).", L"Disable MD5-Challenge (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"VPN/RAS", L"EAP-TLS (type 13)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\services\\RasMan\\PPP\\EAP\\13",
                   L"Enabled", 1, true, L"EAP-TLS enabled (secure).", L"Enable EAP-TLS (set 1).");
        results.push_back(item);
    }

    // ====================================================================
    // 15. LLMNR, NETBIOS, WPAD
    // ====================================================================
    {
        CheckItem item(L"Network", L"LLMNR (EnableMulticast)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
                   L"EnableMulticast", 0, true, L"LLMNR disabled (secure).", L"Disable LLMNR (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"Network", L"NetBIOS Node Type", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters",
                   L"NodeType", 2, true, L"NodeType = 2 (P-node) or 8 (H-node) (secure).", L"Set to 2 (P-node) or 8 (H-node).");
        results.push_back(item);
    }
    {
        CheckItem item(L"Network", L"WPAD Auto-Detect", L"");
        CheckDWORD(item, HKEY_CURRENT_USER,
                   L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                   L"AutoDetect", 0, true, L"WPAD disabled (secure).", L"Disable WPAD (set 0).");
        results.push_back(item);
    }

    // ====================================================================
    // 16. FIREWALL
    // ====================================================================
    {
        CheckItem item(L"Firewall", L"Domain Profile", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
                   L"EnableFirewall", 1, true, L"Firewall enabled (secure).", L"Enable firewall (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"Firewall", L"Private Profile", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
                   L"EnableFirewall", 1, true, L"Firewall enabled (secure).", L"Enable firewall (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"Firewall", L"Public Profile", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile",
                   L"EnableFirewall", 1, true, L"Firewall enabled (secure).", L"Enable firewall (set 1).");
        results.push_back(item);
    }

    // ====================================================================
    // 17. WINDOWS DEFENDER
    // ====================================================================
    {
        CheckItem item(L"Windows Defender", L"DisableAntiSpyware", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                   L"DisableAntiSpyware", 0, true, L"Defender enabled (secure).", L"Enable Defender (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"Windows Defender", L"Real-Time Monitoring", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                   L"DisableRealtimeMonitoring", 0, true, L"Real-time monitoring enabled (secure).", L"Enable real-time monitoring (set 0).");
        results.push_back(item);
    }

    // ====================================================================
    // 18. UAC
    // ====================================================================
    {
        CheckItem item(L"UAC", L"EnableLUA", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                   L"EnableLUA", 1, true, L"UAC enabled (secure).", L"Enable UAC (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"UAC", L"ConsentPromptBehaviorAdmin", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                   L"ConsentPromptBehaviorAdmin", 5, true, L"Prompt for consent (secure).", L"Set to 5 (default).");
        results.push_back(item);
    }
    {
        CheckItem item(L"UAC", L"FilterAdministratorToken", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                   L"FilterAdministratorToken", 1, true, L"Admin token filtered (secure).", L"Enable filtering (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"UAC", L"PromptOnSecureDesktop", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                   L"PromptOnSecureDesktop", 1, true, L"Prompt on secure desktop (secure).", L"Enable (set 1).");
        results.push_back(item);
    }

    // ====================================================================
    // 19. AUTORUN
    // ====================================================================
    {
        CheckItem item(L"AutoRun", L"NoDriveTypeAutoRun", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                   L"NoDriveTypeAutoRun", 0xff, true, L"AutoRun disabled for all drives (secure).", L"Set to 0xff.");
        results.push_back(item);
    }

    // ====================================================================
    // 20. SMARTSCREEN
    // ====================================================================
    {
        CheckItem item(L"SmartScreen", L"SmartScreenEnabled", L"");
        CheckString(item, HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                    L"SmartScreenEnabled", L"RequireAdmin", false,
                    L"SmartScreen enabled (secure).", L"Set to 'RequireAdmin' or 'On'.");
        results.push_back(item);
    }

    // ====================================================================
    // 21. POWERSHELL LOGGING
    // ====================================================================
    {
        CheckItem item(L"PowerShell", L"ScriptBlockLogging", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
                   L"EnableScriptBlockLogging", 1, true, L"Script block logging enabled (secure).", L"Enable (set 1).");
        results.push_back(item);
    }

    // ====================================================================
    // 22. WINDOWS SCRIPT HOST
    // ====================================================================
    {
        CheckItem item(L"Windows Script Host", L"Enabled", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Windows Script Host\\Settings",
                   L"Enabled", 0, true, L"WSH disabled (secure).", L"Disable WSH (set 0).");
        results.push_back(item);
    }

    // ====================================================================
    // 23. AUTOMATIC LOGON
    // ====================================================================
    {
        CheckItem item(L"AutoLogon", L"AutoAdminLogon", L"");
        std::wstring val;
        bool exists = ReadString(HKEY_LOCAL_MACHINE,
                                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                                 L"AutoAdminLogon", val);
        std::wstring pass;
        bool hasPass = ReadString(HKEY_LOCAL_MACHINE,
                                  L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                                  L"DefaultPassword", pass);
        if (!exists || val != L"1") {
            item.status = Status::SECURE;
            item.details = L"AutoAdminLogon not enabled.";
            item.recommendation = L"Keep disabled.";
        } else if (hasPass && !pass.empty()) {
            item.status = Status::DOWNGRADED;
            item.details = L"AutoAdminLogon=1, password stored in plaintext.";
            item.recommendation = L"Disable AutoAdminLogon and clear stored password.";
        } else {
            item.status = Status::WARNING;
            item.details = L"AutoAdminLogon=1 but password empty or missing.";
            item.recommendation = L"Disable AutoAdminLogon.";
        }
        results.push_back(item);
    }

    // ====================================================================
    // 24. EXPLOIT MITIGATIONS (ASLR, DEP, SEHOP, CFG, etc.)
    // ====================================================================
    {
        CheckItem item(L"Exploit Mitigations", L"ASLR (MoveImages)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
                   L"MoveImages", 1, true, L"ASLR enabled (secure).", L"Enable ASLR (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"Exploit Mitigations", L"SEHOP (DisableExceptionChainValidation)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
                   L"DisableExceptionChainValidation", 0, true, L"SEHOP enabled (secure).", L"Enable SEHOP (set 0).");
        results.push_back(item);
    }
    {
        CheckItem item(L"Exploit Mitigations", L"Control Flow Guard (EnableCfg)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
                   L"EnableCfg", 1, true, L"CFG enabled (secure).", L"Enable CFG (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"Exploit Mitigations", L"Safe DLL Search Mode", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                   L"SafeDllSearchMode", 1, true, L"Safe DLL search enabled (secure).", L"Enable (set 1).");
        results.push_back(item);
    }

    // ====================================================================
    // 25. CREDENTIAL GUARD / VBS
    // ====================================================================
    {
        CheckItem item(L"Virtualization Security", L"VBS (EnableVirtualizationBasedSecurity)", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                   L"EnableVirtualizationBasedSecurity", 1, true, L"VBS enabled (secure).", L"Enable VBS (set 1).");
        results.push_back(item);
    }
    {
        CheckItem item(L"Virtualization Security", L"Credential Guard", L"");
        CheckDWORD(item, HKEY_LOCAL_MACHINE,
                   L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\CredentialGuard",
                   L"Enabled", 1, true, L"Credential Guard enabled (secure).", L"Enable Credential Guard (set 1).");
        results.push_back(item);
    }
}

// ---- Write report to file and show message ----

#include <codecvt>
#include <locale>

// Helper: convert wstring to UTF-8 string
std::string WStringToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(),
                                          nullptr, 0, nullptr, nullptr);
    std::string utf8_str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(),
                        &utf8_str[0], size_needed, nullptr, nullptr);
    return utf8_str;
}

void WriteReportToFile(const std::vector<CheckItem>& results, const std::wstring& filename) {
    // Open as binary to avoid any extra conversions; we write UTF-8 ourselves
    std::ofstream file(filename.c_str(), std::ios::binary);
    if (!file.is_open()) {
        MessageBoxW(nullptr, L"Could not create report file.", L"Error", MB_ICONERROR);
        return;
    }

    // Write UTF-8 BOM (optional, but helps editors detect UTF-8)
    const unsigned char bom[] = {0xEF, 0xBB, 0xBF};
    file.write(reinterpret_cast<const char*>(bom), sizeof(bom));

    // Helper lambda to write a wide string as UTF-8
    auto writeLine = [&](const std::wstring& line) {
        std::string utf8 = WStringToUTF8(line);
        file.write(utf8.c_str(), utf8.size());
        file.put('\n');  // add newline
    };

    // Write timestamp
    time_t now = time(nullptr);
    char timeBuf[100];
    ctime_s(timeBuf, sizeof(timeBuf), &now);
    writeLine(L"Security Report - " + std::wstring(timeBuf, timeBuf + strlen(timeBuf) - 1)); // remove trailing newline
    writeLine(L"═══════════════════════════════════════════════════════════════════════════════");
    writeLine(L"");

    // Group by category
    std::vector<std::wstring> categories;
    for (auto& item : results) {
        if (std::find(categories.begin(), categories.end(), item.category) == categories.end())
            categories.push_back(item.category);
    }

    for (auto& cat : categories) {
        writeLine(L"■ " + cat);
        writeLine(L"  ────────────────────────────────────────────────────────────────");

        for (auto& item : results) {
            if (item.category != cat) continue;
            writeLine(L"  " + item.name);
            writeLine(L"    " + StatusToString(item.status));
            if (!item.details.empty())
                writeLine(L"    Details: " + item.details);
            if (!item.recommendation.empty())
                writeLine(L"    Suggestion: " + item.recommendation);
            writeLine(L"");
        }
    }

    // Summary
    int downgraded = 0, secure = 0, warning = 0, info = 0, missing = 0;
    for (auto& item : results) {
        switch (item.status) {
            case Status::DOWNGRADED: downgraded++; break;
            case Status::SECURE: secure++; break;
            case Status::WARNING: warning++; break;
            case Status::INFO: info++; break;
            case Status::MISSING: missing++; break;
        }
    }

    writeLine(L"");
    writeLine(L"═══════════════════════════════════════════════════════════════════════════════");
    writeLine(L"SUMMARY");
    writeLine(L"  ✅ SECURE      : " + std::to_wstring(secure));
    writeLine(L"  ❌ DOWNGRADED  : " + std::to_wstring(downgraded));
    writeLine(L"  ⚠️  WARNING    : " + std::to_wstring(warning));
    writeLine(L"  ℹ️  INFO       : " + std::to_wstring(info));
    writeLine(L"  ➖ MISSING     : " + std::to_wstring(missing));
    writeLine(L"  ────────────────────────────────────────────────");
    writeLine(L"  Total checks   : " + std::to_wstring(results.size()));

    if (downgraded > 0) {
        writeLine(L"");
        writeLine(L"⚠️  SECURITY RISK: " + std::to_wstring(downgraded) + L" downgrade indicators found!");
        writeLine(L"   The system appears to have been intentionally weakened.");
    } else {
        writeLine(L"");
        writeLine(L"✅ No downgrade indicators found. System is in a secure state.");
    }
    writeLine(L"");

    file.close();
}

// ---- Entry point ----

int wmain() {
    // Run checks
    std::vector<CheckItem> results;
    RunSecurityCheck(results);

    // Write to file in the same directory as the executable
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring dir = exePath;
    size_t pos = dir.find_last_of(L'\\');
    if (pos != std::wstring::npos) dir = dir.substr(0, pos + 1);
    std::wstring reportFile = dir + L"SecurityReport.txt";

    WriteReportToFile(results, reportFile);

    // Show completion message
    std::wstring msg = L"Security check completed.\nReport saved to:\n" + reportFile;
    MessageBoxW(nullptr, msg.c_str(), L"Security Checker", MB_OK | MB_ICONINFORMATION);

    return 0;
}