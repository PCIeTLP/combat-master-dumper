#include "dumper.h"
#include "ui.h"

#include <deque>
#include <cstdarg>

static const char* kClass = "cm_dumper_progress";
static const int kStages = 19;
static const size_t kTailMax = 14;
static const int kW = 560, kH = 352, kLineH = 17;

static SRWLOCK g_lock = SRWLOCK_INIT;
static HANDLE g_thread = nullptr;
static HWND g_hwnd = nullptr;
static volatile LONG g_on = 0;

static std::string g_headline;
static std::string g_outDir;
static std::deque<std::string> g_tail;
static int g_stage = 0;
static int g_rc = -1;
static bool g_done = false;
static ULONGLONG g_t0 = 0;

static HFONT g_fTitle = nullptr, g_fBody = nullptr, g_fMono = nullptr;
static int g_dpi = 96;

static int S(int v) { return MulDiv(v, g_dpi, 96); }

static void Text(HDC dc, HFONT f, COLORREF c, RECT r, const char* s, UINT flags) {
    SelectObject(dc, f);
    SetTextColor(dc, c);
    DrawTextA(dc, s, -1, &r, flags | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
}

static void Fill(HDC dc, RECT r, COLORREF c) {
    HBRUSH b = CreateSolidBrush(c);
    FillRect(dc, &r, b);
    DeleteObject(b);
}

static void Paint(HWND h) {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(h, &ps);

    RECT cr;
    GetClientRect(h, &cr);
    HDC mem = CreateCompatibleDC(dc);
    HBITMAP bmp = CreateCompatibleBitmap(dc, cr.right, cr.bottom);
    HGDIOBJ oldBmp = SelectObject(mem, bmp);
    SetBkMode(mem, TRANSPARENT);

    std::string headline, outDir;
    std::deque<std::string> tail;
    int stage, rc;
    bool done;
    ULONGLONG t0;
    AcquireSRWLockShared(&g_lock);
    headline = g_headline; outDir = g_outDir; tail = g_tail;
    stage = g_stage; rc = g_rc; done = g_done; t0 = g_t0;
    ReleaseSRWLockShared(&g_lock);

    const COLORREF bg = RGB(20, 20, 22);
    const COLORREF edge = RGB(58, 58, 64);
    const COLORREF bright = RGB(236, 236, 238);
    const COLORREF dim = RGB(136, 136, 144);
    const COLORREF faint = RGB(96, 96, 104);
    const COLORREF track = RGB(44, 44, 50);
    COLORREF accent = RGB(86, 166, 255);
    if (done) accent = rc == 0 ? RGB(88, 200, 124) : rc == 10 ? RGB(232, 182, 84) : RGB(232, 104, 104);

    Fill(mem, cr, bg);
    HBRUSH eb = CreateSolidBrush(edge);
    FrameRect(mem, &cr, eb);
    DeleteObject(eb);

    const int pad = S(14);
    const int w = cr.right;

    RECT r{ pad, S(12), w - pad, S(32) };
    Text(mem, g_fTitle, bright, r, "combat-master-dumper", DT_LEFT);

    char elapsed[32] = "";
    sprintf_s(elapsed, "%.1fs", (GetTickCount64() - t0) / 1000.0);
    Text(mem, g_fBody, faint, r, elapsed, DT_RIGHT);

    RECT bar{ pad, S(40), w - pad, S(46) };
    Fill(mem, bar, track);
    int span = bar.right - bar.left;
    int filled = stage <= 0 ? 0 : stage >= kStages ? span : MulDiv(span, stage, kStages);
    if (filled > 0) {
        RECT f{ bar.left, bar.top, bar.left + filled, bar.bottom };
        Fill(mem, f, accent);
    }

    RECT hr{ pad, S(54), w - pad, S(72) };
    Text(mem, g_fBody, done ? accent : bright, hr, headline.c_str(), DT_LEFT);

    int y = S(80);
    const int lh = S(kLineH);
    for (size_t i = 0; i < tail.size(); i++) {
        RECT lr{ pad, y, w - pad, y + lh };
        Text(mem, g_fMono, dim, lr, tail[i].c_str(), DT_LEFT);
        y += lh;
    }

    RECT fr{ pad, cr.bottom - S(24), w - pad, cr.bottom - S(8) };
    Text(mem, g_fMono, faint, fr, outDir.c_str(), DT_LEFT);

    BitBlt(dc, 0, 0, cr.right, cr.bottom, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldBmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(h, &ps);
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_ERASEBKGND: return 1;
    case WM_TIMER:      InvalidateRect(h, nullptr, FALSE); return 0;
    case WM_PAINT:      Paint(h); return 0;
    case WM_NCHITTEST:  return HTCAPTION;
    case WM_CLOSE:      DestroyWindow(h); return 0;
    case WM_DESTROY:    KillTimer(h, 1); PostQuitMessage(0); return 0;
    }
    return DefWindowProcA(h, m, w, l);
}

static DWORD WINAPI UiThread(LPVOID) {
    HINSTANCE inst = GetModuleHandleA(nullptr);

    WNDCLASSEXA wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wc.lpszClassName = kClass;
    RegisterClassExA(&wc);

    HDC screen = GetDC(nullptr);
    if (screen) {
        g_dpi = GetDeviceCaps(screen, LOGPIXELSX);
        ReleaseDC(nullptr, screen);
    }
    if (g_dpi < 96) g_dpi = 96;

    g_fTitle = CreateFontA(-S(15), 0, 0, 0, 600, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                           CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, 0, "Segoe UI");
    g_fBody = CreateFontA(-S(12), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                          CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, 0, "Segoe UI");
    g_fMono = CreateFontA(-S(12), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                          CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

    int w = S(kW), h = S(kH);
    RECT work{};
    if (!SystemParametersInfoA(SPI_GETWORKAREA, 0, &work, 0)) {
        work.left = 0; work.top = 0;
        work.right = GetSystemMetrics(SM_CXSCREEN);
        work.bottom = GetSystemMetrics(SM_CYSCREEN);
    }
    int x = work.right - w - S(24);
    int y = work.top + S(24);

    HWND hwnd = CreateWindowExA(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                                kClass, "combat-master-dumper", WS_POPUP,
                                x, y, w, h, nullptr, nullptr, inst, nullptr);
    if (hwnd) {
        g_hwnd = hwnd;
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        SetTimer(hwnd, 1, 100, nullptr);

        MSG msg;
        while (GetMessageA(&msg, nullptr, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        g_hwnd = nullptr;
    }

    if (g_fTitle) { DeleteObject(g_fTitle); g_fTitle = nullptr; }
    if (g_fBody) { DeleteObject(g_fBody); g_fBody = nullptr; }
    if (g_fMono) { DeleteObject(g_fMono); g_fMono = nullptr; }
    UnregisterClassA(kClass, inst);
    return 0;
}

void UiStart(const std::string& outDir, bool enabled) {
    if (!enabled || g_on) return;

    AcquireSRWLockExclusive(&g_lock);
    g_outDir = outDir;
    g_headline = "starting";
    g_stage = 0;
    g_rc = -1;
    g_done = false;
    g_t0 = GetTickCount64();
    g_tail.clear();
    ReleaseSRWLockExclusive(&g_lock);

    InterlockedExchange(&g_on, 1);
    g_thread = CreateThread(nullptr, 0, UiThread, nullptr, 0, nullptr);
    if (!g_thread) InterlockedExchange(&g_on, 0);
}

void UiStage(const char* fmt, ...) {
    if (!g_on) return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    AcquireSRWLockExclusive(&g_lock);
    g_headline = buf;
    if (g_stage < kStages) g_stage++;
    ReleaseSRWLockExclusive(&g_lock);
}

void UiLogLine(const char* text) {
    if (!g_on || !text || !*text) return;

    AcquireSRWLockExclusive(&g_lock);
    g_tail.push_back(text);
    while (g_tail.size() > kTailMax) g_tail.pop_front();
    ReleaseSRWLockExclusive(&g_lock);
}

void UiDone(int rc) {
    if (!g_on) return;

    AcquireSRWLockExclusive(&g_lock);
    g_done = true;
    g_rc = rc;
    g_stage = kStages;
    g_headline = rc == 0 ? "done" :
                 rc == 10 ? "done, but a critical offset did not fit" :
                 "failed - read dump.log";
    ReleaseSRWLockExclusive(&g_lock);
}

void UiStop() {
    if (!g_on) return;

    HWND h = g_hwnd;
    if (h) PostMessageA(h, WM_CLOSE, 0, 0);
    if (g_thread) {
        if (WaitForSingleObject(g_thread, 5000) == WAIT_TIMEOUT && g_hwnd)
            PostMessageA(g_hwnd, WM_CLOSE, 0, 0), WaitForSingleObject(g_thread, 2000);
        CloseHandle(g_thread);
        g_thread = nullptr;
    }
    InterlockedExchange(&g_on, 0);
}
