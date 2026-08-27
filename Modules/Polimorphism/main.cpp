#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstring>
#include <ctime>

#pragma comment(lib, "advapi32.lib")

struct PolymorphicData {
    char marker[16];
    int data[1000];
};

__declspec(selectany) PolymorphicData poly = { "POLYMORPHIC01", {0} };

void MakePolymorphic()
{
    char selfPath[MAX_PATH];
    char tempPath[MAX_PATH];

    if (GetModuleFileNameA(NULL, selfPath, MAX_PATH) == 0)
        return;

    strcpy(tempPath, selfPath);
    strcat(tempPath, ".tmp");

    if (!MoveFileExA(selfPath, tempPath, MOVEFILE_REPLACE_EXISTING))
    {
        return;
    }

    HANDLE hTemp = CreateFileA(tempPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTemp == INVALID_HANDLE_VALUE)
    {
        MoveFileExA(tempPath, selfPath, MOVEFILE_REPLACE_EXISTING);
        return;
    }

    DWORD fileSize = GetFileSize(hTemp, NULL);
    if (fileSize == INVALID_FILE_SIZE)
    {
        CloseHandle(hTemp);
        MoveFileExA(tempPath, selfPath, MOVEFILE_REPLACE_EXISTING);
        return;
    }

    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
    if (!buffer)
    {
        CloseHandle(hTemp);
        MoveFileExA(tempPath, selfPath, MOVEFILE_REPLACE_EXISTING);
        return;
    }

    DWORD bytesRead;
    if (!ReadFile(hTemp, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize)
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hTemp);
        MoveFileExA(tempPath, selfPath, MOVEFILE_REPLACE_EXISTING);
        return;
    }
    CloseHandle(hTemp);

    const char marker[] = "POLYMORPHIC01";
    const DWORD markerLen = sizeof(marker) - 1;
    BYTE* found = NULL;

    for (DWORD i = 0; i <= fileSize - markerLen; i++)
    {
        if (memcmp(buffer + i, marker, markerLen) == 0)
        {
            found = buffer + i;
            break;
        }
    }

    if (!found)
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        MoveFileExA(tempPath, selfPath, MOVEFILE_REPLACE_EXISTING);
        return;
    }

    int* polyArray = (int*)(found + markerLen);
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        CryptGenRandom(hProv, 1000 * sizeof(int), (BYTE*)polyArray);
        CryptReleaseContext(hProv, 0);
    }
    else
    {
        srand(GetTickCount());
        for (int i = 0; i < 1000; i++)
            polyArray[i] = rand();
    }

    HANDLE hNew = CreateFileA(selfPath, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hNew != INVALID_HANDLE_VALUE)
    {
        DWORD written;
        WriteFile(hNew, buffer, fileSize, &written, NULL);
        CloseHandle(hNew);
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    DeleteFileA(tempPath);
    MoveFileExA(tempPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                    LPSTR lpCmdLine, int nCmdShow)
{
    MakePolymorphic();

    int sum = 0;
    for (int i = 0; i < 1000; i++)
        sum += poly.data[i];

    char msg[256];
    sprintf(msg, "Suma 1000 losowych liczb: %d", sum);
    MessageBoxA(NULL, msg, "Polimorfizm", MB_OK);

    return 0;
}