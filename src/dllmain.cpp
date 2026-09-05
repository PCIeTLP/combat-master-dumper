#include "dumper.h"
#include "ui.h"
#include <shlobj.h>
#include <shellapi.h>
#include <chrono>
#include <cstring>

static std::string EnvOr(const char* name, const char* fallback) {
    char* env = nullptr;
    if (_dupenv_s(&env, nullptr, name) == 0 && env) {
        std::string s(env); free(env);
        if (!s.empty()) return s;
    }
    return fallback;
}

static HMODULE g_self = nullptr;
static std::string g_outDir;

static void EnsureDir(const std::string& d) {
    SHCreateDirectoryExA(nullptr, d.c_str(), nullptr);
}

static std::string SelfDir() {
    char path[MAX_PATH]{};
    if (!g_self || !GetModuleFileNameA(g_self, path, MAX_PATH)) return "";
    std::string s(path);
    size_t cut = s.find_last_of("\\/");
    return cut == std::string::npos ? "" : s.substr(0, cut);
}

static bool Writable(const std::string& d) {
    std::string probe = d + "\\.write_probe";
    FILE* f = nullptr;
    if (fopen_s(&f, probe.c_str(), "w") != 0 || !f) return false;
    fclose(f);
    DeleteFileA(probe.c_str());
    return true;
}

static std::string DefaultOutDir() {
    std::string s = EnvOr("IL2CPP_DUMP_OUT", "");
    if (!s.empty()) return s;

    std::string self = SelfDir();
    if (!self.empty()) {
        std::string d = self + "\\il2cpp_dump";
        EnsureDir(d);
        if (Writable(d)) return d;
    }

    char path[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path)))
        return std::string(path) + "\\il2cpp_dump";

    if (GetTempPathA(MAX_PATH, path))
        return std::string(path) + "il2cpp_dump";

    return "il2cpp_dump";
}

static void ReadBuildIdentity(Context& ctx) {
    uint32_t e_lfanew = ctx.mem.U32(ctx.gaBase + 0x3C);
    if (e_lfanew && e_lfanew < 0x1000 && ctx.mem.U32(ctx.gaBase + e_lfanew) == 0x00004550) {
        ctx.gaTimeStamp = ctx.mem.U32(ctx.gaBase + e_lfanew + 0x08);
        ctx.gaCheckSum = ctx.mem.U32(ctx.gaBase + e_lfanew + 0x58);
    }

    HMODULE up = GetModuleHandleA("UnityPlayer.dll");
    char file[MAX_PATH]{};
    if (up && GetModuleFileNameA(up, file, MAX_PATH)) {
        DWORD dummy = 0, size = GetFileVersionInfoSizeA(file, &dummy);
        if (size) {
            std::vector<uint8_t> buf(size);
            VS_FIXEDFILEINFO* ffi = nullptr;
            UINT len = 0;
            if (GetFileVersionInfoA(file, 0, size, buf.data()) &&
                VerQueryValueA(buf.data(), "\\", (LPVOID*)&ffi, &len) && ffi) {
                char v[64];
                sprintf_s(v, "%u.%u.%u.%u", HIWORD(ffi->dwFileVersionMS), LOWORD(ffi->dwFileVersionMS),
                          HIWORD(ffi->dwFileVersionLS), LOWORD(ffi->dwFileVersionLS));
                ctx.unityVersion = v;
            }
        }
    }
    Log("[+] GameAssembly.dll base 0x%llX size 0x%llX  build %08X  Unity %s",
        ctx.gaBase, ctx.gaSize, ctx.gaTimeStamp,
        ctx.unityVersion.empty() ? "unknown" : ctx.unityVersion.c_str());
}

int RunDump(const std::string& outDirIn) {
    std::string outDir = outDirIn.empty() ? DefaultOutDir() : outDirIn;
    g_outDir = outDir;
    EnsureDir(outDir);
    LogInit(outDir + "\\dump.log");
    UiStart(outDir, EnvOr("IL2CPP_DUMP_UI", "1") != "0");

    auto t0 = std::chrono::steady_clock::now();
    Log("combat-master-dumper (injected)");
    Log("[*] output -> %s", outDir.c_str());

    Context ctx;
    ctx.mem.Open();

    int wait = atoi(EnvOr("IL2CPP_DUMP_WAIT", "30").c_str());
    UiStage("waiting for the il2cpp runtime");
    if (!WaitForRuntime(ctx, wait < 0 ? 0 : wait)) { LogClose(); return 2; }

    UiStage("reading build identity");
    ReadBuildIdentity(ctx);

    UiStage("mapping readable memory");
    uint64_t total = 0;
    for (const auto& r : ctx.mem.Regions()) total += r.size;
    Log("[+] %zu readable regions, %llu MB", ctx.mem.Regions().size(), total / (1024 * 1024));

    UiStage("fitting Il2CppClass identity");
    if (!FitClassIdentity(ctx)) { LogClose(); return 3; }

    UiStage("scanning for classes");
    ScanClasses(ctx);
    if (ctx.classes.size() < 100) { Log("[!] only %zu classes found", ctx.classes.size()); LogClose(); return 4; }

    UiStage("fitting Il2CppClass layout (%zu classes)", ctx.classes.size());
    FitClassLayout(ctx);

    UiStage("fitting FieldInfo / MethodInfo");
    FitMemberLayout(ctx);

    UiStage("resolving assemblies");
    ResolveImages(ctx);

    UiStage("reading members");
    ReadMembers(ctx);

    UiStage("fitting metadata tables");
    FitMetadataTables(ctx);

    UiStage("filling from metadata");
    FillFromMetadata(ctx);

    UiStage("writing layout.json");
    EmitLayoutJson(ctx, outDir + "\\layout.json");
    UiStage("writing il2cpp_structs.h");
    EmitIl2CppHeader(ctx, outDir + "\\il2cpp_structs.h");
    UiStage("writing dump.cs");
    EmitDumpCs(ctx, outDir + "\\dump.cs");
    UiStage("writing script.json");
    EmitScriptJson(ctx, outDir + "\\script.json");
    UiStage("writing summary.txt");
    EmitSummary(ctx, outDir + "\\summary.txt");
    UiStage("writing ida_apply.py");
    EmitIdaScript(outDir + "\\ida_apply.py");
    UiStage("writing health.json");
    EmitHealthJson(ctx, outDir + "\\health.json");

    int criticalFailures = 0;
    for (const auto& r : ctx.fits) if (!r.fitted && r.critical) criticalFailures++;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();
    Log("[+] done in %lld ms", (long long)ms);
    LogClose();
    ctx.mem.Close();
    return criticalFailures ? 10 : 0;
}

static int RunDumpDefault() { return RunDump(""); }

static int SafeRunDump() {
    __try {
        return RunDumpDefault();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 99;
    }
}

struct ExplorerHit { const char* leaf; HWND hwnd; };

static BOOL CALLBACK FindExplorerWindow(HWND h, LPARAM p) {
    ExplorerHit* hit = (ExplorerHit*)p;
    if (!IsWindowVisible(h)) return TRUE;

    char cls[64]{};
    GetClassNameA(h, cls, (int)sizeof(cls));
    if (strcmp(cls, "CabinetWClass") != 0 && strcmp(cls, "ExploreWClass") != 0) return TRUE;

    char title[MAX_PATH]{};
    GetWindowTextA(h, title, (int)sizeof(title));
    if (_stricmp(title, hit->leaf) == 0) { hit->hwnd = h; return FALSE; }
    return TRUE;
}

static void ForceForeground(HWND h) {
    if (!h) return;
    if (IsIconic(h)) ShowWindow(h, SW_RESTORE);

    DWORD me = GetCurrentThreadId();
    DWORD fg = GetWindowThreadProcessId(GetForegroundWindow(), nullptr);
    bool attached = fg && fg != me && AttachThreadInput(me, fg, TRUE);

    BringWindowToTop(h);
    SetForegroundWindow(h);
    SetActiveWindow(h);

    if (attached) AttachThreadInput(me, fg, FALSE);
}

static void OpenOutputFolder(const std::string& dir) {
    AllowSetForegroundWindow(ASFW_ANY);
    ShellExecuteA(nullptr, "open", dir.c_str(), nullptr, nullptr, SW_SHOWNORMAL);

    size_t cut = dir.find_last_of("\\/");
    std::string leaf = cut == std::string::npos ? dir : dir.substr(cut + 1);

    for (int i = 0; i < 40; i++) {
        Sleep(100);
        ExplorerHit hit{ leaf.c_str(), nullptr };
        EnumWindows(FindExplorerWindow, (LPARAM)&hit);
        if (hit.hwnd) { ForceForeground(hit.hwnd); return; }
    }
}

static DWORD WINAPI DumpThread(LPVOID param) {
    HMODULE self = (HMODULE)param;
    int rc = SafeRunDump();

    std::string dir = g_outDir.empty() ? DefaultOutDir() : g_outDir;
    FILE* f = nullptr;
    if (fopen_s(&f, (dir + "\\DONE.txt").c_str(), "w") == 0 && f) {
        fprintf(f, "exit code %d\n", rc);
        fprintf(f, "%s\n", rc == 0 ? "ok" : rc == 10 ? "dumped, but a critical offset did not fit - read health.json"
                                                     : "failed - read dump.log");
        fclose(f);
    }
    UiDone(rc);
    int linger = atoi(EnvOr("IL2CPP_DUMP_UI_LINGER", "3").c_str());
    if (linger > 0) Sleep((DWORD)linger * 1000);
    UiStop();

    if (EnvOr("IL2CPP_DUMP_OPEN", "1") != "0")
        OpenOutputFolder(dir);

    if (EnvOr("IL2CPP_DUMP_MSGBOX", "0") == "1") {
        char msg[512];
        sprintf_s(msg, "combat-master-dumper finished (code %d)\n\nOutput:\n%s", rc, dir.c_str());
        MessageBoxA(nullptr, msg, "combat-master-dumper", rc == 0 ? MB_ICONINFORMATION : MB_ICONWARNING);
    }
    FreeLibraryAndExitThread(self, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        g_self = hModule;

        CloseHandle(CreateThread(nullptr, 0, DumpThread, hModule, 0, nullptr));
    }
    return TRUE;
}
