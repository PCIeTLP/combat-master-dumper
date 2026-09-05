#include "dumper.h"
#include "sweep.h"
#include "ui.h"
#include <algorithm>
#include <cstdarg>
#include <tlhelp32.h>

static FILE* g_log = nullptr;

void LogInit(const std::string& path) {
    fopen_s(&g_log, path.c_str(), "w");
}

void Log(const char* fmt, ...) {
    char buf[4096];
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    if (g_log) { fputs(buf, g_log); fputc('\n', g_log); fflush(g_log); }
    OutputDebugStringA(buf); OutputDebugStringA("\n");
    UiLogLine(buf);
}

void LogClose() { if (g_log) { fclose(g_log); g_log = nullptr; } }

void Context::Note(const char* what, const std::string& value, int agree, int total,
                   bool fitted, bool critical) {
    fits.push_back({ what, value, agree, total, fitted, critical });

    char pct[40] = "";
    if (total > 0 && agree <= total) sprintf_s(pct, " (%d/%d, %.0f%%)", agree, total, 100.0 * agree / total);
    else if (total > 0) sprintf_s(pct, " (score %d over %d)", agree, total);

    if (fitted) Log("[+] %-34s %s%s", what, value.c_str(), pct);
    else Log("[!] %-34s NOT FITTED, using %s%s", what, value.c_str(), pct);
}

static bool RawCopy(const void* src, void* dst, size_t n) {
    __try {
        memcpy(dst, src, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool Mem::Open() {
    pid_ = GetCurrentProcessId();
    RefreshRegions();
    return true;
}

void Mem::Close() { regions_.clear(); }

void Mem::RefreshRegions() {
    regions_.clear();
    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t addr = 0;
    while (addr < 0x7FFFFFFF0000ULL) {
        if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) break;
        uint64_t rs = (uint64_t)mbi.RegionSize;
        if (rs == 0) break;
        const uint32_t readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                  PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & readable) && !(mbi.Protect & PAGE_GUARD)) {
            Region r;
            r.base = (uint64_t)mbi.BaseAddress;
            r.size = rs;
            r.protect = mbi.Protect;
            r.type = mbi.Type;
            r.writable = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            r.executable = (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                           PAGE_EXECUTE_WRITECOPY)) != 0;
            r.isImage = mbi.Type == MEM_IMAGE;
            regions_.push_back(r);
        }
        addr = (uint64_t)mbi.BaseAddress + rs;
    }
    std::sort(regions_.begin(), regions_.end(),
              [](const Region& a, const Region& b) { return a.base < b.base; });
}

const Region* Mem::RegionOf(uint64_t a) const {
    size_t lo = 0, hi = regions_.size();
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (a < regions_[mid].base) hi = mid;
        else if (a >= regions_[mid].base + regions_[mid].size) lo = mid + 1;
        else return &regions_[mid];
    }
    return nullptr;
}

bool Mem::Contains(uint64_t a) const { return RegionOf(a) != nullptr; }

bool Mem::Read(uint64_t addr, void* out, size_t n) const {
    if (addr < 0x10000 || n == 0) return false;
    return RawCopy((const void*)addr, out, n);
}

bool Mem::CStr(uint64_t a, std::string& out, size_t max) const {
    out.clear();
    if (a < 0x10000) return false;
    char buf[512];
    size_t want = (std::min)(max, sizeof(buf));
    const size_t step = 64;
    for (size_t done = 0; done < want; done += step) {
        size_t n = (std::min)(step, want - done);
        if (!Read(a + done, buf, n)) return false;
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)buf[i];
            if (c == 0) return true;
            if (c < 0x20 || c > 0x7E) return false;
            out.push_back((char)c);
            if (out.size() > max) return false;
        }
    }
    return false;
}

bool Mem::FindModule(const char* name, uint64_t& base, uint64_t& size) const {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32 me{}; me.dwSize = sizeof(me);
    bool ok = false;
    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(me.szModule, name) == 0) {
                base = (uint64_t)me.modBaseAddr;
                size = me.modBaseSize;
                ok = true;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return ok;
}

bool WaitForRuntime(Context& ctx, int seconds) {
    for (int i = 0; i < seconds * 2 + 1; i++) {
        ctx.mem.RefreshRegions();
        if (ctx.mem.FindModule("GameAssembly.dll", ctx.gaBase, ctx.gaSize)) {
            ctx.heapRanges.clear();
            if (DetectStringHeap(ctx)) {
                if (i) Log("[+] runtime ready after %.1f s", i * 0.5);
                return true;
            }
        }
        Sleep(500);
    }
    Log("[!] GameAssembly.dll and a metadata string heap did not both appear in %d s", seconds);
    return false;
}

static bool FindBytes(const uint8_t* hay, size_t n, const char* needle, size_t nl) {
    if (nl > n) return false;
    for (size_t i = 0; i + nl <= n; i++)
        if (hay[i] == (uint8_t)needle[0] && memcmp(hay + i, needle, nl) == 0) return true;
    return false;
}

static bool LooksLikeStringBlob(const Mem& mem, uint64_t base, uint64_t size, double& frac, double& meanRun) {
    const int PAGES = 64;
    uint64_t stride = size / PAGES;
    if (stride < 0x1000) stride = 0x1000;
    stride &= ~0xFFFull;

    uint8_t buf[0x1000];
    uint64_t total = 0, printableOrNul = 0, zeros = 0, runs = 0, runBytes = 0, cur = 0;
    for (uint64_t off = 0; off + 0x1000 <= size && total < (uint64_t)PAGES * 0x1000; off += stride) {
        if (!mem.Read(base + off, buf, sizeof(buf))) continue;
        for (int i = 0; i < 0x1000; i++) {
            uint8_t c = buf[i];
            total++;
            if (c == 0) {
                zeros++; printableOrNul++;
                if (cur) { runs++; runBytes += cur; cur = 0; }
            } else if (c >= 0x20 && c <= 0x7E) {
                printableOrNul++; cur++;
            } else {
                cur = 0;
            }
        }
    }
    if (total < 0x8000) return false;
    frac = (double)printableOrNul / total;
    meanRun = runs ? (double)runBytes / runs : 0.0;
    double zf = (double)zeros / total;
    return frac >= 0.85 && zf <= 0.60 && meanRun >= 3.0 && meanRun <= 96.0;
}

bool DetectStringHeap(Context& ctx) {
    struct Anchor { const char* s; size_t n; int w; };
    static const Anchor anchors[] = {
        { "<Module>\0",               9, 3 },
        { "mscorlib\0",               9, 2 },
        { "System.Private.CoreLib\0", 23, 2 },
        { "UnityEngine.CoreModule\0", 23, 2 },
        { "Assembly-CSharp\0",       16, 2 },
        { ".ctor\0",                  6, 1 },
        { "get_Item\0",               9, 1 },
        { "ToString\0",               9, 1 },
        { "GetHashCode\0",           12, 1 },
        { "MonoBehaviour\0",         14, 1 },
    };

    struct Cand { uint64_t lo, hi; int score; double frac, run; };
    std::vector<Cand> cands;
    for (const auto& r : ctx.mem.Regions()) {
        if (r.size < (32u << 10) || r.size > (512u << 20)) continue;
        if (r.isImage || r.executable) continue;
        size_t probe = (size_t)(std::min)(r.size, (uint64_t)(24u << 20));
        std::vector<uint8_t> buf(probe);
        if (!ctx.mem.Read(r.base, buf.data(), probe)) continue;
        int score = 0;
        for (const Anchor& a : anchors)
            if (FindBytes(buf.data(), probe, a.s, a.n)) score += a.w;
        if (score < 4) continue;
        double frac = 0, run = 0;
        if (!LooksLikeStringBlob(ctx.mem, r.base, r.size, frac, run)) {
            Log("    rejected 0x%llX (%llu KB, score %d): %.0f%% printable, mean run %.1f",
                r.base, r.size / 1024, score, frac * 100, run);
            continue;
        }
        cands.push_back({ r.base, r.base + r.size, score, frac, run });
    }
    if (cands.empty()) return false;

    std::sort(cands.begin(), cands.end(), [](const Cand& a, const Cand& b) {
        return a.score != b.score ? a.score > b.score : (a.hi - a.lo) > (b.hi - b.lo);
    });
    ctx.heapLo = cands[0].lo;
    ctx.heapHi = cands[0].hi;
    ctx.heapRanges.push_back({ cands[0].lo, cands[0].hi });

    uint64_t primary = cands[0].hi - cands[0].lo;
    for (size_t i = 1; i < cands.size(); i++) {
        uint64_t size = cands[i].hi - cands[i].lo;
        if (size > primary * 4 || cands[i].score + 4 < cands[0].score) {
            Log("    ignoring secondary 0x%llX (%llu KB, score %d)", cands[i].lo, size / 1024, cands[i].score);
            continue;
        }
        ctx.heapRanges.push_back({ cands[i].lo, cands[i].hi });
    }
    std::sort(ctx.heapRanges.begin(), ctx.heapRanges.end());

    uint64_t total = 0;
    for (const auto& r : ctx.heapRanges) total += r.second - r.first;
    Log("[+] metadata string heap: %zu region(s), %llu KB, primary 0x%llX-0x%llX (score %d, %.0f%% printable, mean run %.1f)",
        ctx.heapRanges.size(), total / 1024, ctx.heapLo, ctx.heapHi, cands[0].score, cands[0].frac * 100, cands[0].run);
    return true;
}

void ScanClasses(Context& ctx) {
    const Layout& L = ctx.L;
    uint32_t need = (std::max)((std::max)(L.cls_self, L.cls_name), L.cls_namespaze) + 8;
    std::unordered_set<uint64_t> seen;
    std::string name, ns;

    Sweep(ctx.mem, L.cls_span, [&](const Region& r, uint64_t base, const uint8_t* buf, size_t len) {
        if (r.isImage || r.executable) return;
        for (size_t i = 0; i + need <= len; i += 8) {
            uint64_t cb = base + i;
            uint64_t self; memcpy(&self, buf + i + L.cls_self, 8);
            if (self != cb) continue;
            uint64_t nm, nsp;
            memcpy(&nm, buf + i + L.cls_name, 8);
            memcpy(&nsp, buf + i + L.cls_namespaze, 8);
            if (!ctx.InHeap(nm) || !ctx.InHeap(nsp)) continue;
            if (!seen.insert(cb).second) continue;
            if (!ctx.mem.CStr(nm, name) || name.empty()) continue;
            ctx.mem.CStr(nsp, ns);

            ClassDump c;
            c.addr = cb;
            c.name = name;
            c.ns = ns;
            ctx.classes.push_back(std::move(c));
        }
    });

    std::sort(ctx.classes.begin(), ctx.classes.end(),
              [](const ClassDump& a, const ClassDump& b) { return a.addr < b.addr; });
    for (size_t i = 0; i < ctx.classes.size(); i++) ctx.byAddr[ctx.classes[i].addr] = i;
    Log("[+] %zu Il2CppClass discovered", ctx.classes.size());
}

static const char* PrimName(uint8_t t) {
    switch (t) {
    case IL2CPP_TYPE_VOID: return "void";
    case IL2CPP_TYPE_BOOLEAN: return "bool";
    case IL2CPP_TYPE_CHAR: return "char";
    case IL2CPP_TYPE_I1: return "sbyte";
    case IL2CPP_TYPE_U1: return "byte";
    case IL2CPP_TYPE_I2: return "short";
    case IL2CPP_TYPE_U2: return "ushort";
    case IL2CPP_TYPE_I4: return "int";
    case IL2CPP_TYPE_U4: return "uint";
    case IL2CPP_TYPE_I8: return "long";
    case IL2CPP_TYPE_U8: return "ulong";
    case IL2CPP_TYPE_R4: return "float";
    case IL2CPP_TYPE_R8: return "double";
    case IL2CPP_TYPE_STRING: return "string";
    case IL2CPP_TYPE_I: return "IntPtr";
    case IL2CPP_TYPE_U: return "UIntPtr";
    case IL2CPP_TYPE_OBJECT: return "object";
    case IL2CPP_TYPE_TYPEDBYREF: return "TypedReference";
    default: return nullptr;
    }
}

std::string ClassFullName(Context& ctx, size_t idx) {
    const ClassDump& c = ctx.classes[idx];
    std::string n = c.name;
    const ClassDump* out = &c;
    uint64_t d = c.declaring;
    int guard = 0;
    while (d && guard++ < 8) {
        auto it = ctx.byAddr.find(d);
        if (it == ctx.byAddr.end()) break;
        out = &ctx.classes[it->second];
        n = out->name + "." + n;
        d = out->declaring;
    }
    if (!out->ns.empty()) n = out->ns + "." + n;
    return n;
}

std::string TypeName(Context& ctx, uint64_t type, int depth) {
    if (!type || depth > 6) return "object";
    uint64_t data = ctx.mem.U64(type + ctx.L.typ_data);
    uint32_t bits = ctx.mem.U32(type + (ctx.L.typ_typeByte & ~3u));
    uint8_t t = ctx.mem.U8(type + ctx.L.typ_typeByte);
    bool byref = ((bits >> ctx.L.typ_byrefBit) & 1) != 0;

    std::string s;
    if (const char* p = PrimName(t)) s = p;
    else switch (t) {
    case IL2CPP_TYPE_CLASS:
    case IL2CPP_TYPE_VALUETYPE: {
        auto it = ctx.byHandle.find(data);
        if (it != ctx.byHandle.end()) s = ClassFullName(ctx, it->second);
        else {
            auto ia = ctx.byAddr.find(data);
            s = ia != ctx.byAddr.end() ? ClassFullName(ctx, ia->second) : "object";
        }
        break;
    }
    case IL2CPP_TYPE_SZARRAY: s = TypeName(ctx, data, depth + 1) + "[]"; break;
    case IL2CPP_TYPE_ARRAY: {
        uint64_t et = ctx.mem.U64(data);
        uint8_t rank = ctx.mem.U8(data + 8);
        s = TypeName(ctx, et, depth + 1) + "[";
        for (int i = 1; i < (int)rank && i < 32; i++) s += ",";
        s += "]";
        break;
    }
    case IL2CPP_TYPE_PTR: s = TypeName(ctx, data, depth + 1) + "*"; break;
    case IL2CPP_TYPE_BYREF: s = TypeName(ctx, data, depth + 1); byref = true; break;
    case IL2CPP_TYPE_GENERICINST: {
        uint64_t handle = ctx.mem.U64(data + ctx.L.gc_typeHandle);
        uint64_t inst = ctx.mem.U64(data + ctx.L.gc_classInst);
        uint64_t cached = ctx.mem.U64(data + ctx.L.gc_cachedClass);
        std::string base = "object";
        auto it = ctx.byHandle.find(handle);
        if (it != ctx.byHandle.end()) base = ClassFullName(ctx, it->second);
        else {
            auto ic = ctx.byAddr.find(cached);
            if (ic != ctx.byAddr.end()) base = ClassFullName(ctx, ic->second);
        }
        size_t tick = base.rfind('`');
        if (tick != std::string::npos) base = base.substr(0, tick);
        s = base + "<";
        if (inst > 0x10000) {
            uint32_t argc = ctx.mem.U32(inst + ctx.L.gi_argc);
            uint64_t argv = ctx.mem.U64(inst + ctx.L.gi_argv);
            if (argc < 32 && argv > 0x10000)
                for (uint32_t i = 0; i < argc; i++) {
                    if (i) s += ", ";
                    s += TypeName(ctx, ctx.mem.U64(argv + (uint64_t)i * 8), depth + 1);
                }
        }
        s += ">";
        break;
    }
    case IL2CPP_TYPE_VAR: s = "T"; break;
    case IL2CPP_TYPE_MVAR: s = "TMethod"; break;
    case IL2CPP_TYPE_FNPTR: s = "IntPtr"; break;
    default: {
        char b[32]; sprintf_s(b, "type_0x%02X", t); s = b; break;
    }
    }
    if (byref) s += "&";
    return s;
}
