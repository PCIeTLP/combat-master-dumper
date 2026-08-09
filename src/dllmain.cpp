#include "dumper.h"
#include <shlobj.h>
#include <chrono>

static std::string EnvOr(const char* name, const char* fallback) {
    char* env = nullptr;
    if (_dupenv_s(&env, nullptr, name) == 0 && env) {
        std::string s(env); free(env);
        if (!s.empty()) return s;
    }
    return fallback;
}

static std::string DefaultOutDir() {
    std::string s = EnvOr("IL2CPP_DUMP_OUT", "");
    if (!s.empty()) return s;

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

static void EnsureDir(const std::string& d) {
    SHCreateDirectoryExA(nullptr, d.c_str(), nullptr);
}

int RunDump(const std::string& outDirIn) {
    std::string outDir = outDirIn.empty() ? DefaultOutDir() : outDirIn;
    EnsureDir(outDir);
    LogInit(outDir + "\\dump.log");

    auto t0 = std::chrono::steady_clock::now();
    Log("combat-master-dumper (injected)");
    Log("[*] output -> %s", outDir.c_str());

    Context ctx;
    ctx.mem.Open();

    int wait = atoi(EnvOr("IL2CPP_DUMP_WAIT", "30").c_str());
    if (!WaitForRuntime(ctx, wait < 0 ? 0 : wait)) { LogClose(); return 2; }
    ReadBuildIdentity(ctx);

    uint64_t total = 0;
    for (const auto& r : ctx.mem.Regions()) total += r.size;
    Log("[+] %zu readable regions, %llu MB", ctx.mem.Regions().size(), total / (1024 * 1024));

    if (!FitClassIdentity(ctx)) { LogClose(); return 3; }

    ScanClasses(ctx);
    if (ctx.classes.size() < 100) { Log("[!] only %zu classes found", ctx.classes.size()); LogClose(); return 4; }

    FitClassLayout(ctx);
    FitMemberLayout(ctx);
    ResolveImages(ctx);
    ReadMembers(ctx);
    FitMetadataTables(ctx);
    FillFromMetadata(ctx);

    EmitLayoutJson(ctx, outDir + "\\layout.json");
    EmitIl2CppHeader(ctx, outDir + "\\il2cpp_structs.h");
    EmitDumpCs(ctx, outDir + "\\dump.cs");
    EmitScriptJson(ctx, outDir + "\\script.json");
    EmitSummary(ctx, outDir + "\\summary.txt");
    EmitIdaScript(outDir + "\\ida_apply.py");
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

static DWORD WINAPI DumpThread(LPVOID param) {
    HMODULE self = (HMODULE)param;
    int rc = SafeRunDump();

    std::string dir = DefaultOutDir();
    FILE* f = nullptr;
    if (fopen_s(&f, (dir + "\\DONE.txt").c_str(), "w") == 0 && f) {
        fprintf(f, "exit code %d\n", rc);
        fprintf(f, "%s\n", rc == 0 ? "ok" : rc == 10 ? "dumped, but a critical offset did not fit - read health.json"
                                                     : "failed - read dump.log");
        fclose(f);
    }
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

        CloseHandle(CreateThread(nullptr, 0, DumpThread, hModule, 0, nullptr));
    }
    return TRUE;
}
