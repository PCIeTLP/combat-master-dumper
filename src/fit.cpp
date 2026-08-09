#include "dumper.h"
#include "sweep.h"
#include <algorithm>
#include <map>

namespace {

constexpr uint32_t SPAN = 0x200;
constexpr uint32_t MSPAN = 0x80;

template <typename K>
struct Poll {
    std::map<K, int> v;
    void Add(const K& k, int n = 1) { v[k] += n; }
    bool Best(K& outK, int& outN) const {
        outN = 0; bool any = false;
        for (const auto& kv : v) if (kv.second > outN) { outN = kv.second; outK = kv.first; any = true; }
        return any;
    }
};

std::string Off(uint32_t o) { char b[24]; sprintf_s(b, "+0x%X", o); return b; }
std::string Hex(uint64_t v) { char b[32]; sprintf_s(b, "0x%llX", v); return b; }

std::vector<size_t> SampleClasses(const Context& ctx, size_t want) {
    std::vector<size_t> out;
    size_t n = ctx.classes.size();
    if (!n) return out;
    size_t step = n > want ? n / want : 1;
    for (size_t i = 0; i < n; i += step) out.push_back(i);
    return out;
}

bool HasHeapPtr(const Context& ctx, uint64_t rec, uint32_t span) {
    for (uint32_t o = 0; o < span; o += 8)
        if (ctx.InHeap(ctx.mem.U64(rec + o))) return true;
    return false;
}

bool LooksLikeTypeName(const std::string& s) {
    if (s.empty() || s.size() > 250) return false;
    char c0 = s[0];
    if (!(isalpha((unsigned char)c0) || c0 == '_' || c0 == '<')) return false;
    for (char c : s) {
        if (isalnum((unsigned char)c) || c == '_' || c == '`' || c == '<' || c == '>' ||
            c == '.' || c == ',' || c == '[' || c == ']' || c == '+' ||
            c == '$' || c == '-' || c == '=' || c == '|') continue;
        return false;
    }
    return true;
}

bool LooksLikeNamespace(const std::string& s) {
    if (s.empty()) return true;
    return LooksLikeTypeName(s) && s.find('`') == std::string::npos;
}

}

bool FitClassIdentity(Context& ctx) {
    const size_t NSLOT = SPAN / 8 + 1;
    const uint32_t PROBE_CAP = 20000;
    const size_t SAMPLE_CAP = 800;

    struct Stat {
        uint64_t hits = 0;
        uint32_t probed = 0;
        std::vector<uint32_t> heap;
        std::vector<uint64_t> bases;
    };
    std::vector<Stat> st(NSLOT);
    for (auto& s : st) s.heap.assign(NSLOT, 0);

    Log("[*] probing for the Il2CppClass self-pointer...");
    Sweep(ctx.mem, SPAN, [&](const Region& r, uint64_t base, const uint8_t* buf, size_t len) {
        if (r.isImage || r.executable) return;
        for (size_t i = 0; i + 8 <= len; i += 8) {
            uint64_t a = base + i, v;
            memcpy(&v, buf + i, 8);
            if (v > a) continue;
            uint64_t d = a - v;
            if (d > SPAN || (d & 7)) continue;
            Stat& s = st[(size_t)(d / 8)];
            s.hits++;
            if (s.probed >= PROBE_CAP) continue;

            if (i < d || i - d + SPAN + 8 > len) continue;
            s.probed++;
            const uint8_t* rec = buf + (i - d);
            for (size_t k = 0; k < NSLOT; k++) {
                uint64_t p; memcpy(&p, rec + k * 8, 8);
                if (ctx.InHeap(p)) s.heap[k]++;
            }
            if (s.bases.size() < SAMPLE_CAP) s.bases.push_back(v);
        }
    });

    auto backRefScore = [&](const std::vector<uint64_t>& bases, uint32_t self) {
        std::map<uint64_t, int> vote;
        for (uint64_t b : bases) {
            for (uint32_t co = 0; co <= SPAN; co += 8) {
                if (co == self) continue;
                uint64_t p = ctx.mem.U64(b + co);
                if (!ctx.Ptr(p) || p == b) continue;
                for (uint32_t bo = 0; bo <= 0x38; bo += 8)
                    if (ctx.mem.U64(p + bo) == b) vote[((uint64_t)co << 16) | bo]++;
                uint64_t q = ctx.mem.U64(p);
                if (!ctx.Ptr(q) || q == b) continue;
                for (uint32_t bo = 0; bo <= 0x60; bo += 8)
                    if (ctx.mem.U64(q + bo) == b) vote[0x8000000000ull | ((uint64_t)co << 16) | bo]++;
            }
        }
        int best = 0;
        for (const auto& kv : vote) best = (std::max)(best, kv.second);
        return bases.empty() ? 0.0 : (double)best / bases.size();
    };

    struct Best {
        uint32_t self = 0, name = 0, ns = 0;
        uint64_t hits = 0;
        double quality = 0, backRef = 0;
    } best;

    for (size_t k = 0; k < NSLOT; k++) {
        const Stat& s = st[k];
        if (s.hits < 200 || s.probed < 50) continue;

        std::vector<uint32_t> cand;
        for (size_t j = 0; j < NSLOT; j++) {
            if (j == k) continue;
            if (s.heap[j] * 100 >= s.probed * 75) cand.push_back((uint32_t)(j * 8));
        }
        if (cand.size() < 2) continue;

        uint32_t nameOff = 0, nsOff = 0;
        double bestScore = -2, worstScore = 2, nameQ = 0, nsQ = 0;
        for (uint32_t o : cand) {
            std::unordered_set<std::string> distinct;
            size_t seen = 0, empty = 0, ident = 0, nsish = 0;
            for (uint64_t b : s.bases) {
                uint64_t p = ctx.mem.U64(b + o);
                std::string str;
                if (!ctx.InHeap(p) || !ctx.mem.CStr(p, str)) continue;
                seen++;
                if (str.empty()) empty++; else distinct.insert(str);
                if (LooksLikeTypeName(str)) ident++;
                if (LooksLikeNamespace(str)) nsish++;
            }
            if (seen < 20) continue;
            double score = (double)distinct.size() / seen - (double)empty / seen;
            if (score > bestScore) { bestScore = score; nameOff = o; nameQ = (double)ident / seen; }
            if (score < worstScore) { worstScore = score; nsOff = o; nsQ = (double)nsish / seen; }
        }
        if (!nameOff || !nsOff || nameOff == nsOff) continue;
        if (nameQ < 0.85 || nsQ < 0.85) continue;

        double br = backRefScore(s.bases, (uint32_t)(k * 8));
        Log("    self=+0x%-3X name=+0x%-3X ns=+0x%-3X  %8llu hits  names %.0f%%  member arrays %.0f%%",
            (uint32_t)(k * 8), nameOff, nsOff, s.hits, nameQ * 100, br * 100);
        if (br > best.backRef || (br == best.backRef && s.hits > best.hits))
            best = { (uint32_t)(k * 8), nameOff, nsOff, s.hits, nameQ, br };
    }

    if (!best.hits || best.backRef < 0.15) {
        Log("[!] no Il2CppClass-shaped structure found. Either the runtime has not");
        Log("    initialised yet, or the metadata string blob was misidentified.");
        return false;
    }
    ctx.L.cls_self = best.self;
    ctx.L.cls_name = best.name;
    ctx.L.cls_namespaze = best.ns;
    ctx.L.cls_span = SPAN;
    char buf[128];
    sprintf_s(buf, "self=+0x%X name=+0x%X namespaze=+0x%X (member arrays %.0f%%)",
              best.self, best.name, best.ns, best.backRef * 100);
    ctx.Note("Il2CppClass identity", buf, (int)best.hits, (int)best.hits, true, true);
    return true;
}

namespace {

void FitTypeHandle(Context& ctx, const std::vector<size_t>& sample) {
    struct Cand { uint32_t ho, no; uint64_t base; int n; };
    std::vector<Cand> cands;
    int bestN = 0;
    for (uint32_t ho = 0; ho <= SPAN; ho += 8) {
        if (ho == ctx.L.cls_self) continue;
        for (uint32_t no = 0; no <= 0x08; no += 4) {
            std::map<uint64_t, int> tally;
            for (size_t i : sample) {
                const ClassDump& c = ctx.classes[i];
                uint64_t h = ctx.mem.U64(c.addr + ho);
                if (!ctx.Ptr(h)) continue;
                uint32_t idx = ctx.mem.U32(h + no);
                if (idx == 0xFFFFFFFF) continue;
                uint64_t np = ctx.mem.U64(c.addr + ctx.L.cls_name);
                if (idx > np) continue;
                uint64_t origin = np - idx;
                if (origin < ctx.heapLo || origin >= ctx.heapHi) continue;
                tally[origin]++;
            }
            uint64_t base = 0; int n = 0;
            for (const auto& kv : tally) if (kv.second > n) { n = kv.second; base = kv.first; }
            if (n) { cands.push_back({ ho, no, base, n }); bestN = (std::max)(bestN, n); }
        }
    }

    auto typeLike = [&](uint32_t o) {
        double best = 0;
        for (uint32_t bp = 8; bp < 16; bp++) {
            int hit = 0;
            for (size_t i : sample) {
                uint8_t k = ctx.mem.U8(ctx.classes[i].addr + o + bp);
                if (k == IL2CPP_TYPE_CLASS || k == IL2CPP_TYPE_VALUETYPE || k == IL2CPP_TYPE_GENERICINST) hit++;
            }
            best = (std::max)(best, sample.empty() ? 0.0 : (double)hit / sample.size());
        }
        return best;
    };
    uint32_t bestHo = 0, bestNo = 0; uint64_t bestBase = 0;
    double bestTypeLike = 2.0;
    for (const Cand& c : cands) {
        if (c.n * 10 < bestN * 9) continue;
        double tl = typeLike(c.ho);
        if (tl < bestTypeLike - 0.05 || (tl < bestTypeLike + 0.05 && c.ho > bestHo)) {
            bestTypeLike = (std::min)(tl, bestTypeLike);
            bestHo = c.ho; bestNo = c.no; bestBase = c.base;
        }
    }
    if (!bestHo) bestN = 0;

    bool ok = bestN >= 50 && bestN * 100 >= (int)sample.size() * 20;
    if (ok) {
        ctx.L.cls_handle = bestHo;
        ctx.L.td_nameIndex = bestNo;
        ctx.strBase = bestBase;
    } else {
        ctx.strBase = ctx.heapLo;
    }
    ctx.Note("Il2CppClass.typeMetadataHandle", Off(ctx.L.cls_handle), bestN, (int)sample.size(), ok, true);
    ctx.Note("Il2CppTypeDefinition.nameIndex", Off(ctx.L.td_nameIndex), bestN, (int)sample.size(), ok, true);
    ctx.Note("string blob origin", Hex(ctx.strBase), bestN, (int)sample.size(), ok, true);

    if (!ok) return;
    Poll<uint32_t> nsp;
    for (size_t i : sample) {
        const ClassDump& c = ctx.classes[i];
        uint64_t h = ctx.mem.U64(c.addr + ctx.L.cls_handle);
        uint64_t np = ctx.mem.U64(c.addr + ctx.L.cls_namespaze);
        if (!ctx.Ptr(h) || np < ctx.strBase) continue;
        for (uint32_t no = 0; no <= 0x10; no += 4)
            if ((uint64_t)ctx.mem.U32(h + no) == np - ctx.strBase) nsp.Add(no);
    }
    uint32_t no = 0; int n = 0;
    bool nsOk = nsp.Best(no, n) && n >= 50 && n * 100 >= (int)sample.size() * 20;
    if (nsOk) ctx.L.td_namespaceIndex = no;
    ctx.Note("Il2CppTypeDefinition.namespaceIndex", Off(ctx.L.td_namespaceIndex), n, (int)sample.size(), nsOk, false);
}

void FitEmbeddedTypes(Context& ctx, const std::vector<size_t>& sample) {
    Poll<uint32_t> p;
    int usable = 0;
    for (size_t i : sample) {
        const ClassDump& c = ctx.classes[i];
        uint64_t h = ctx.mem.U64(c.addr + ctx.L.cls_handle);
        if (!ctx.Ptr(h)) continue;
        usable++;
        for (uint32_t o = 0; o <= SPAN; o += 8) {
            if (o == ctx.L.cls_handle) continue;
            if (ctx.mem.U64(c.addr + o) == h) p.Add(o);
        }
    }
    std::vector<std::pair<int, uint32_t>> ranked;
    for (const auto& kv : p.v) ranked.push_back({ kv.second, kv.first });
    std::sort(ranked.rbegin(), ranked.rend());

    bool ok = ranked.size() >= 2 && ranked[0].first >= 50 && ranked[0].first * 100 >= usable * 60;
    if (ok) {
        uint32_t a = ranked[0].second, b = ranked[1].second;
        ctx.L.cls_byval = (std::min)(a, b);
        ctx.L.cls_this = (std::max)(a, b);
        uint32_t delta = ctx.L.cls_this - ctx.L.cls_byval;
        if (delta == 0x10 || delta == 0x18 || delta == 0x20) ctx.L.typ_size = delta;
    }
    ctx.Note("Il2CppClass.byval_arg", Off(ctx.L.cls_byval), ok ? ranked[0].first : 0, usable, ok, true);

    Poll<uint32_t> bp;
    for (size_t i : sample) {
        uint64_t t = ctx.classes[i].addr + ctx.L.cls_byval;
        for (uint32_t o = 8; o < ctx.L.typ_size; o++) {
            uint8_t k = ctx.mem.U8(t + o);
            if (k == IL2CPP_TYPE_CLASS || k == IL2CPP_TYPE_VALUETYPE || k == IL2CPP_TYPE_GENERICINST) bp.Add(o);
        }
    }
    uint32_t off = 0; int n = 0;
    bool bok = bp.Best(off, n) && n * 100 >= (int)sample.size() * 60;
    if (bok) { ctx.L.typ_typeByte = off; ctx.L.typ_bits = off & ~3u; }
    ctx.Note("Il2CppType.type", Off(ctx.L.typ_typeByte), n, (int)sample.size(), bok, true);

    int bits[32] = {}, votes = 0;
    for (size_t i : sample) {
        uint64_t base = ctx.classes[i].addr;
        uint32_t x = ctx.mem.U32(base + ctx.L.cls_byval + ctx.L.typ_bits) ^
                     ctx.mem.U32(base + ctx.L.cls_this + ctx.L.typ_bits);
        if (!x) continue;
        votes++;
        for (int k = 0; k < 32; k++) if ((x >> k) & 1) bits[k]++;
    }
    int bb = -1, bn = 0;
    for (int k = 24; k < 32; k++) if (bits[k] > bn) { bn = bits[k]; bb = k; }
    bool yok = bb >= 0 && votes >= 20 && bn * 100 >= votes * 80;
    if (yok) ctx.L.typ_byrefBit = (uint32_t)bb;
    char buf[24]; sprintf_s(buf, "bit %u", ctx.L.typ_byrefBit);
    ctx.Note("Il2CppType.byref", buf, bn, votes, yok, false);
}

void FitMemberArrays(Context& ctx, const std::vector<size_t>& sample) {
    Poll<uint64_t> fp, mp;
    for (size_t i : sample) {
        uint64_t ca = ctx.classes[i].addr;
        for (uint32_t co = 0; co <= SPAN; co += 8) {
            if (co == ctx.L.cls_self || co == ctx.L.cls_handle ||
                co == ctx.L.cls_byval || co == ctx.L.cls_this) continue;
            uint64_t p = ctx.mem.U64(ca + co);
            if (!ctx.Ptr(p) || p == ca) continue;

            if (HasHeapPtr(ctx, p, 0x40))
                for (uint32_t bo = 0; bo <= 0x38; bo += 8)
                    if (ctx.mem.U64(p + bo) == ca) fp.Add(((uint64_t)co << 16) | bo);

            uint64_t m0 = ctx.mem.U64(p);
            if (ctx.Ptr(m0) && m0 != ca && HasHeapPtr(ctx, m0, MSPAN))
                for (uint32_t bo = 0; bo <= 0x60; bo += 8)
                    if (ctx.mem.U64(m0 + bo) == ca) mp.Add(((uint64_t)co << 16) | bo);
        }
    }
    uint64_t k = 0; int n = 0;
    bool ok = fp.Best(k, n) && n >= 20;
    if (ok) { ctx.L.cls_fields = (uint32_t)(k >> 16); ctx.L.fld_parent = (uint32_t)(k & 0xFFFF); }
    ctx.Note("Il2CppClass.fields", Off(ctx.L.cls_fields), n, (int)sample.size(), ok, true);
    ctx.Note("FieldInfo.parent", Off(ctx.L.fld_parent), n, (int)sample.size(), ok, true);

    n = 0;
    bool mok = mp.Best(k, n) && n >= 20;
    if (mok) { ctx.L.cls_methods = (uint32_t)(k >> 16); ctx.L.mth_klass = (uint32_t)(k & 0xFFFF); }
    ctx.Note("Il2CppClass.methods", Off(ctx.L.cls_methods), n, (int)sample.size(), mok, true);
    ctx.Note("MethodInfo.klass", Off(ctx.L.mth_klass), n, (int)sample.size(), mok, true);

    Poll<uint32_t> sp;
    for (size_t i : sample) {
        uint64_t ca = ctx.classes[i].addr;
        uint64_t arr = ctx.mem.U64(ca + ctx.L.cls_fields);
        if (!ctx.Ptr(arr) || ctx.mem.U64(arr + ctx.L.fld_parent) != ca) continue;
        for (uint32_t s = 8; s <= 0x60; s += 8)
            if (ctx.mem.U64(arr + s + ctx.L.fld_parent) == ca) sp.Add(s);
    }
    uint32_t stride = 0; int sn = 0;
    if (sp.Best(stride, sn) && sn >= 10) {
        for (const auto& kv : sp.v)
            if (kv.second * 10 >= sn * 7) { stride = kv.first; sn = kv.second; break; }
        ctx.L.fld_size = stride;
        ctx.Note("FieldInfo stride", Off(stride), sn, (int)sample.size(), true, true);
    } else {
        ctx.Note("FieldInfo stride", Off(ctx.L.fld_size), sn, (int)sample.size(), false, true);
    }
}

uint16_t WalkFields(const Context& ctx, uint64_t ca) {
    uint64_t arr = ctx.mem.U64(ca + ctx.L.cls_fields);
    if (!ctx.Ptr(arr)) return 0;
    uint32_t n = 0;
    while (n < 4096 && ctx.mem.U64(arr + (uint64_t)n * ctx.L.fld_size + ctx.L.fld_parent) == ca) n++;
    return (uint16_t)n;
}

uint16_t WalkMethods(const Context& ctx, uint64_t ca) {
    uint64_t arr = ctx.mem.U64(ca + ctx.L.cls_methods);
    if (!ctx.Ptr(arr)) return 0;
    uint32_t n = 0;
    while (n < 4096) {
        uint64_t mi = ctx.mem.U64(arr + (uint64_t)n * 8);
        if (!ctx.Ptr(mi) || ctx.mem.U64(mi + ctx.L.mth_klass) != ca) break;
        n++;
    }
    return (uint16_t)n;
}

void FitCounts(Context& ctx, const std::vector<size_t>& sample) {
    Poll<uint32_t> fc, mc;
    int fn = 0, mn = 0;
    for (size_t i : sample) {
        uint64_t ca = ctx.classes[i].addr;
        uint16_t nf = WalkFields(ctx, ca), nm = WalkMethods(ctx, ca);
        if (nf) { fn++; for (uint32_t o = 0; o <= SPAN; o += 2) if (ctx.mem.U16(ca + o) == nf) fc.Add(o); }
        if (nm) { mn++; for (uint32_t o = 0; o <= SPAN; o += 2) if (ctx.mem.U16(ca + o) == nm) mc.Add(o); }
    }
    uint32_t o = 0; int n = 0;
    bool ok = fc.Best(o, n) && n * 10 >= fn * 8;
    if (ok) ctx.L.cls_fieldCount = o;
    ctx.Note("Il2CppClass.field_count", Off(ctx.L.cls_fieldCount), n, fn, ok, true);

    n = 0;
    ok = mc.Best(o, n) && n * 10 >= mn * 8;
    if (ok) ctx.L.cls_methodCount = o;
    ctx.Note("Il2CppClass.method_count", Off(ctx.L.cls_methodCount), n, mn, ok, true);
}

void FitImagePointer(Context& ctx, const std::vector<size_t>& sample) {
    struct Col { int cov = 0; std::unordered_set<uint64_t> vals; };
    std::map<uint32_t, Col> col;
    for (size_t i : sample) {
        uint64_t ca = ctx.classes[i].addr;
        for (uint32_t o = 0; o <= SPAN; o += 8) {
            uint64_t v = ctx.mem.U64(ca + o);
            if (!ctx.Ptr(v) || ctx.byAddr.count(v)) continue;
            Col& c = col[o];
            c.cov++;
            if (c.vals.size() < 4000) c.vals.insert(v);
        }
    }
    uint32_t best = 0; size_t bestDistinct = SIZE_MAX; int bestCov = 0;
    for (const auto& kv : col) {
        if (kv.second.cov * 100 < (int)sample.size() * 90) continue;
        if (kv.second.vals.size() >= 4000 || kv.second.vals.empty()) continue;

        int named = 0, tried = 0;
        for (uint64_t v : kv.second.vals) {
            if (++tried > 12) break;
            for (uint32_t io = 0; io <= 0x60; io += 8) {
                std::string s;
                uint64_t sp = ctx.mem.U64(v + io);
                if (!ctx.mem.CStr(sp, s) || s.size() < 5) continue;
                if (_stricmp(s.c_str() + s.size() - 4, ".dll") == 0) { named++; break; }
            }
        }
        if (named * 2 < tried) continue;
        if (kv.second.vals.size() < bestDistinct) {
            bestDistinct = kv.second.vals.size(); best = kv.first; bestCov = kv.second.cov;
        }
    }
    bool ok = bestDistinct != SIZE_MAX;
    if (ok) ctx.L.cls_image = best;
    ctx.Note("Il2CppClass.image", Off(ctx.L.cls_image), bestCov, (int)sample.size(), ok, true);
}

void FitHierarchy(Context& ctx, const std::vector<size_t>& sample) {
    struct Stat { int other = 0, self = 0, nul = 0; };
    std::map<uint32_t, Stat> stat;
    for (size_t i : sample) {
        uint64_t ca = ctx.classes[i].addr;
        for (uint32_t o = 0; o <= SPAN; o += 8) {
            if (o == ctx.L.cls_self) continue;
            uint64_t v = ctx.mem.U64(ca + o);
            Stat& s = stat[o];
            if (v == 0) s.nul++;
            else if (v == ca) s.self++;
            else if (ctx.byAddr.count(v)) s.other++;
        }
    }
    std::vector<std::pair<int, uint32_t>> ranked;
    for (const auto& kv : stat)
        if (kv.second.other + kv.second.self + kv.second.nul >= (int)sample.size() * 9 / 10)
            ranked.push_back({ kv.second.other, kv.first });
    std::sort(ranked.rbegin(), ranked.rend());

    auto chainOk = [&](uint32_t off) {
        int good = 0, tried = 0, toObject = 0;
        for (size_t i : sample) {
            if (++tried > 300) break;
            uint64_t v = ctx.classes[i].addr;
            int steps = 0;
            uint64_t last = 0;
            while (steps++ < 24) {
                uint64_t p = ctx.mem.U64(v + off);
                if (!p) break;
                auto it = ctx.byAddr.find(p);
                if (it == ctx.byAddr.end()) { steps = 99; break; }
                last = p; v = p;
            }
            if (steps < 24) {
                good++;
                if (last) {
                    const ClassDump& root = ctx.classes[ctx.byAddr[last]];
                    if (root.name == "Object" && root.ns == "System") toObject++;
                }
            }
        }
        return good * 10 >= tried * 9 && toObject * 2 >= good;
    };

    bool ok = false;
    int agree = 0;
    for (size_t i = 0; i < ranked.size() && i < 4; i++) {
        if (chainOk(ranked[i].second)) {
            ctx.L.cls_parent = ranked[i].second; agree = ranked[i].first; ok = true; break;
        }
    }
    ctx.Note("Il2CppClass.parent", Off(ctx.L.cls_parent), agree, (int)sample.size(), ok, true);

    uint32_t bestD = 0; int bestN = 0;
    for (const auto& kv : stat) {
        uint32_t o = kv.first;
        if (o == ctx.L.cls_parent || o == ctx.L.cls_self) continue;
        const Stat& s = kv.second;
        if (s.other + s.self + s.nul < (int)sample.size() * 95 / 100) continue;
        if (s.self * 20 > (int)sample.size()) continue;
        if (s.other == 0 || s.other * 100 > (int)sample.size() * 40) continue;
        int notParent = 0;
        for (size_t i : sample) {
            uint64_t ca = ctx.classes[i].addr;
            uint64_t v = ctx.mem.U64(ca + o);
            if (v && v != ca && ctx.byAddr.count(v) && v != ctx.mem.U64(ca + ctx.L.cls_parent)) notParent++;
        }
        if (notParent > bestN) { bestN = notParent; bestD = o; }
    }
    bool dok = bestN > 0;
    if (dok) ctx.L.cls_declaring = bestD;
    ctx.Note("Il2CppClass.declaringType", Off(ctx.L.cls_declaring), bestN, (int)sample.size(), dok, false);
}

void FitTypeFlags(Context& ctx, const std::vector<size_t>& sample) {
    std::vector<char> isIface;
    int ifaces = 0;
    for (size_t i : sample) {
        const ClassDump& c = ctx.classes[i];
        bool ifc = ctx.mem.U64(c.addr + ctx.L.cls_parent) == 0 &&
                   !(c.name == "Object" && c.ns == "System");
        isIface.push_back(ifc ? 1 : 0);
        if (ifc) ifaces++;
    }
    uint32_t best = 0; int bestScore = 0, bestHit = 0;
    for (uint32_t o = 0; o <= SPAN; o += 4) {
        int score = 0, hit = 0, bad = 0;
        for (size_t j = 0; j < sample.size(); j++) {
            uint32_t v = ctx.mem.U32(ctx.classes[sample[j]].addr + o);
            if (v >= 0x00400000) { bad++; continue; }
            bool bit = (v & TYPE_ATTRIBUTE_INTERFACE) != 0;
            if (bit == (isIface[j] != 0)) score++;
            if (bit && isIface[j]) hit++;
        }
        if (bad * 20 > (int)sample.size()) continue;
        if (ifaces && hit * 10 < ifaces * 9) continue;
        if (score > bestScore) { bestScore = score; best = o; bestHit = hit; }
    }
    bool ok = bestScore * 100 >= (int)sample.size() * 95 && bestHit > 0;
    if (ok) ctx.L.cls_flags = best;
    ctx.Note("Il2CppClass.flags", Off(ctx.L.cls_flags), bestScore, (int)sample.size(), ok, false);
}

void FitInterfaces(Context& ctx, const std::vector<size_t>& sample) {
    auto isIfaceClass = [&](uint64_t k) {
        auto it = ctx.byAddr.find(k);
        if (it == ctx.byAddr.end()) return false;
        return (ctx.mem.U32(k + ctx.L.cls_flags) & TYPE_ATTRIBUTE_INTERFACE) != 0;
    };
    std::map<uint32_t, int> runSum;
    for (size_t i : sample) {
        uint64_t ca = ctx.classes[i].addr;
        for (uint32_t o = 0; o <= SPAN; o += 8) {
            if (o == ctx.L.cls_self || o == ctx.L.cls_methods || o == ctx.L.cls_fields) continue;
            uint64_t arr = ctx.mem.U64(ca + o);
            if (!ctx.Ptr(arr)) continue;
            int run = 0;
            while (run < 64 && isIfaceClass(ctx.mem.U64(arr + (uint64_t)run * 8))) run++;
            if (run) runSum[o] += run;
        }
    }
    uint32_t best = 0; int bestN = 0;
    for (const auto& kv : runSum) if (kv.second > bestN) { bestN = kv.second; best = kv.first; }
    bool ok = bestN >= 20;
    if (ok) ctx.L.cls_interfaces = best;
    ctx.Note("Il2CppClass.implementedInterfaces", Off(ctx.L.cls_interfaces), bestN, (int)sample.size(), ok, false);
    if (!ok) return;

    Poll<uint32_t> cp;
    int have = 0;
    for (size_t i : sample) {
        uint64_t ca = ctx.classes[i].addr;
        uint64_t arr = ctx.mem.U64(ca + ctx.L.cls_interfaces);
        if (!ctx.Ptr(arr)) continue;
        int run = 0;
        while (run < 64 && isIfaceClass(ctx.mem.U64(arr + (uint64_t)run * 8))) run++;
        if (!run) continue;
        have++;
        for (uint32_t o = 0; o <= SPAN; o += 2)
            if (ctx.mem.U16(ca + o) == run) cp.Add(o);
    }
    uint32_t o = 0; int n = 0;
    bool cok = cp.Best(o, n) && n * 10 >= have * 7;
    if (cok) ctx.L.cls_interfaceCount = o;
    ctx.Note("Il2CppClass.interfaces_count", Off(ctx.L.cls_interfaceCount), n, have, cok, false);
}

void FitGenericClass(Context& ctx) {
    Poll<uint32_t> cached, inst, handle;
    int n = 0;
    for (const ClassDump& c : ctx.classes) {
        if (n >= 400) break;
        if (!c.isGenericInst) continue;
        uint64_t g = ctx.mem.U64(c.addr + ctx.L.cls_byval + ctx.L.typ_data);
        if (!ctx.Ptr(g)) continue;
        n++;
        for (uint32_t o = 0; o <= 0x40; o += 8) {
            uint64_t v = ctx.mem.U64(g + o);
            if (v == c.addr) cached.Add(o);
            else if (ctx.byHandle.count(v)) handle.Add(o);
            else if (ctx.Ptr(v)) {
                uint32_t argc = ctx.mem.U32(v + ctx.L.gi_argc);
                uint64_t argv = ctx.mem.U64(v + ctx.L.gi_argv);
                if (argc >= 1 && argc <= 32 && ctx.Ptr(argv) && ctx.IsType(ctx.mem.U64(argv))) inst.Add(o);
            }
        }
    }
    if (!n) return;
    uint32_t o = 0; int k = 0;
    if (cached.Best(o, k) && k * 2 >= n) { ctx.L.gc_cachedClass = o; ctx.Note("Il2CppGenericClass.cached_class", Off(o), k, n, true, false); }
    if (handle.Best(o, k) && k * 2 >= n) ctx.L.gc_typeHandle = o;
    if (inst.Best(o, k) && k * 2 >= n) ctx.L.gc_classInst = o;
}

}

void FitClassLayout(Context& ctx) {
    std::vector<size_t> sample = SampleClasses(ctx, 900);
    Log("[*] fitting Il2CppClass over %zu sampled classes...", sample.size());

    FitTypeHandle(ctx, sample);
    for (auto& c : ctx.classes) c.handle = ctx.mem.U64(c.addr + ctx.L.cls_handle);

    FitEmbeddedTypes(ctx, sample);

    size_t gen = 0;
    for (auto& c : ctx.classes) {
        c.isGenericInst = ctx.mem.U8(c.addr + ctx.L.cls_byval + ctx.L.typ_typeByte) == IL2CPP_TYPE_GENERICINST;
        if (c.isGenericInst) gen++;
    }
    for (size_t i = 0; i < ctx.classes.size(); i++) {
        uint64_t h = ctx.classes[i].handle;
        if (h && !ctx.classes[i].isGenericInst && !ctx.byHandle.count(h)) ctx.byHandle[h] = i;
    }
    Log("[+] %zu source types, %zu generic instantiations", ctx.classes.size() - gen, gen);

    FitMemberArrays(ctx, sample);
    FitCounts(ctx, sample);
    FitImagePointer(ctx, sample);
    FitHierarchy(ctx, sample);
    FitTypeFlags(ctx, sample);
    FitInterfaces(ctx, sample);
    FitGenericClass(ctx);

    for (auto& c : ctx.classes) {
        c.image = ctx.mem.U64(c.addr + ctx.L.cls_image);
        c.parent = ctx.mem.U64(c.addr + ctx.L.cls_parent);
        c.declaring = ctx.mem.U64(c.addr + ctx.L.cls_declaring);
        c.flags = ctx.mem.U32(c.addr + ctx.L.cls_flags);
        c.declaredMethods = ctx.mem.U16(c.addr + ctx.L.cls_methodCount);
        c.declaredFields = ctx.mem.U16(c.addr + ctx.L.cls_fieldCount);
        if (!ctx.byAddr.count(c.parent)) c.parent = 0;
        if (!ctx.byAddr.count(c.declaring)) c.declaring = 0;

        uint64_t ifp = ctx.mem.U64(c.addr + ctx.L.cls_interfaces);
        uint16_t ifn = ctx.mem.U16(c.addr + ctx.L.cls_interfaceCount);
        if (ctx.Ptr(ifp) && ifn > 0 && ifn < 128)
            for (uint16_t i = 0; i < ifn; i++) {
                uint64_t k = ctx.mem.U64(ifp + (uint64_t)i * 8);
                if (ctx.byAddr.count(k)) c.interfaces.push_back(k);
            }
    }
}

namespace {

struct MethodSite { uint64_t klass, mi; };

std::vector<MethodSite> CollectMethods(const Context& ctx, size_t want) {
    std::vector<MethodSite> out;
    for (size_t i = 0; i < ctx.classes.size() && out.size() < want; i++) {
        uint64_t ca = ctx.classes[i].addr;
        uint64_t arr = ctx.mem.U64(ca + ctx.L.cls_methods);
        if (!ctx.Ptr(arr)) continue;
        uint16_t n = WalkMethods(ctx, ca);
        for (uint16_t k = 0; k < n && out.size() < want; k++)
            out.push_back({ ca, ctx.mem.U64(arr + (uint64_t)k * 8) });
    }
    return out;
}

uint32_t FitNamePtr(Context& ctx, const std::vector<uint64_t>& recs, uint32_t skip,
                    uint32_t span, const char* what, uint32_t fallback, bool critical) {
    Poll<uint32_t> p;
    for (uint64_t r : recs) {
        for (uint32_t o = 0; o < span; o += 8) {
            if (o == skip) continue;
            std::string s;
            uint64_t v = ctx.mem.U64(r + o);
            if (ctx.InHeap(v) && ctx.mem.CStr(v, s) && !s.empty()) p.Add(o);
        }
    }
    uint32_t o = 0; int n = 0;
    bool ok = p.Best(o, n) && n * 10 >= (int)recs.size() * 8;
    ctx.Note(what, Off(ok ? o : fallback), n, (int)recs.size(), ok, critical);
    return ok ? o : fallback;
}

uint32_t FitToken(Context& ctx, const std::vector<uint64_t>& recs, uint8_t table,
                  uint32_t span, const char* what, uint32_t fallback, bool critical) {
    Poll<uint32_t> p;
    for (uint64_t r : recs)
        for (uint32_t o = 0; o + 4 <= span; o += 4) {
            uint32_t v = ctx.mem.U32(r + o);
            if ((v >> 24) == table && (v & 0xFFFFFF) != 0) p.Add(o);
        }
    uint32_t o = 0; int n = 0;
    bool ok = p.Best(o, n) && n * 10 >= (int)recs.size() * 8;
    ctx.Note(what, Off(ok ? o : fallback), n, (int)recs.size(), ok, critical);
    return ok ? o : fallback;
}

void FitFieldInfo(Context& ctx) {

    std::vector<uint64_t> recs;
    std::vector<size_t> owner;
    for (size_t i = 0; i < ctx.classes.size() && recs.size() < 1500; i++) {
        uint64_t ca = ctx.classes[i].addr;
        uint64_t arr = ctx.mem.U64(ca + ctx.L.cls_fields);
        if (!ctx.Ptr(arr) || ctx.mem.U64(arr + ctx.L.fld_parent) != ca) continue;
        uint16_t n = WalkFields(ctx, ca);
        for (uint16_t k = 0; k < n && recs.size() < 1500; k++) {
            recs.push_back(arr + (uint64_t)k * ctx.L.fld_size);
            owner.push_back(i);
        }
    }
    if (recs.size() < 20) { Log("[!] too few FieldInfo records to fit"); return; }

    ctx.L.fld_name = FitNamePtr(ctx, recs, ctx.L.fld_parent, ctx.L.fld_size, "FieldInfo.name", ctx.L.fld_name, true);
    ctx.L.fld_token = FitToken(ctx, recs, 0x04, ctx.L.fld_size, "FieldInfo.token", ctx.L.fld_token, false);

    Poll<uint32_t> tp;
    for (uint64_t r : recs)
        for (uint32_t o = 0; o + 8 <= ctx.L.fld_size; o += 8) {
            if (o == ctx.L.fld_parent || o == ctx.L.fld_name) continue;
            if (ctx.IsType(ctx.mem.U64(r + o))) tp.Add(o);
        }
    uint32_t o = 0; int n = 0;
    bool ok = tp.Best(o, n) && n * 10 >= (int)recs.size() * 8;
    if (ok) ctx.L.fld_type = o;
    ctx.Note("FieldInfo.type", Off(ctx.L.fld_type), n, (int)recs.size(), ok, true);

    uint32_t bestO = 0; int bestScore = 0;
    for (uint32_t c = 0; c + 4 <= ctx.L.fld_size; c += 4) {
        if (c == ctx.L.fld_parent || c == ctx.L.fld_name || c == ctx.L.fld_type || c == ctx.L.fld_token) continue;
        int score = 0;
        size_t prevOwner = SIZE_MAX; uint32_t prev = 0;
        for (size_t i = 0; i < recs.size(); i++) {
            uint32_t v = ctx.mem.U32(recs[i] + c);
            if (v >= 0x200000) { score -= 4; continue; }
            if (owner[i] == prevOwner) { if (v >= prev) score++; else score -= 2; }
            else if (v == 0x10) score += 3;
            prevOwner = owner[i]; prev = v;
        }
        if (score > bestScore) { bestScore = score; bestO = c; }
    }
    ok = bestScore > (int)recs.size() / 4;
    if (ok) ctx.L.fld_offset = bestO;
    ctx.Note("FieldInfo.offset", Off(ctx.L.fld_offset), bestScore, (int)recs.size(), ok, true);
}

void FitMethodInfo(Context& ctx) {
    std::vector<MethodSite> sites = CollectMethods(ctx, 3000);
    if (sites.size() < 50) { Log("[!] too few live MethodInfos to fit"); return; }
    std::vector<uint64_t> recs;
    for (const auto& s : sites) recs.push_back(s.mi);

    ctx.L.mth_name = FitNamePtr(ctx, recs, ctx.L.mth_klass, MSPAN, "MethodInfo.name", ctx.L.mth_name, true);
    ctx.L.mth_token = FitToken(ctx, recs, 0x06, MSPAN, "MethodInfo.token", ctx.L.mth_token, true);

    Poll<uint32_t> rp, pp;
    for (uint64_t r : recs)
        for (uint32_t o = 0; o + 8 <= MSPAN; o += 8) {
            if (o == ctx.L.mth_klass || o == ctx.L.mth_name) continue;
            uint64_t v = ctx.mem.U64(r + o);
            if (ctx.IsType(v)) rp.Add(o);
            else if (ctx.Ptr(v) && ctx.IsType(ctx.mem.U64(v))) pp.Add(o);
        }
    uint32_t o = 0; int n = 0;
    bool ok = rp.Best(o, n) && n * 10 >= (int)recs.size() * 8;
    if (ok) ctx.L.mth_ret = o;
    ctx.Note("MethodInfo.return_type", Off(ctx.L.mth_ret), n, (int)recs.size(), ok, true);

    n = 0;
    bool pok = pp.Best(o, n) && n * 10 >= (int)recs.size() * 2;
    if (pok) ctx.L.mth_params = o;
    ctx.Note("MethodInfo.parameters", Off(ctx.L.mth_params), n, (int)recs.size(), pok, false);

    Poll<uint64_t> hp;
    int pairs = 0;
    for (size_t i = 1; i < sites.size(); i++) {
        if (sites[i].klass != sites[i - 1].klass) continue;
        pairs++;
        for (uint32_t c = 0; c + 8 <= MSPAN; c += 8) {
            uint64_t a = ctx.mem.U64(sites[i - 1].mi + c), b = ctx.mem.U64(sites[i].mi + c);
            if (!ctx.Ptr(a) || b <= a || b - a > 0x100) continue;
            hp.Add(((uint64_t)c << 16) | (b - a));
        }
    }
    uint64_t k = 0; n = 0;
    ok = hp.Best(k, n) && n * 10 >= pairs * 7;
    if (ok) {
        ctx.L.mth_handle = (uint32_t)(k >> 16);
        ctx.L.md_size = (uint32_t)(k & 0xFFFF);
    }
    ctx.Note("MethodInfo.metadataHandle", Off(ctx.L.mth_handle), n, pairs, ok, true);
    ctx.Note("Il2CppMethodDefinition stride", Off(ctx.L.md_size), n, pairs, ok, true);

    std::vector<char> isCtor;
    int ctors = 0;
    for (uint64_t r : recs) {
        std::string nm = ctx.mem.CStrOr(ctx.mem.U64(r + ctx.L.mth_name));
        bool c = nm == ".ctor" || nm == ".cctor";
        isCtor.push_back(c ? 1 : 0);
        if (c) ctors++;
    }
    uint32_t bestF = 0; int bestScore = 0, bestHit = 0;
    for (uint32_t c = 0; c + 2 <= MSPAN; c += 2) {
        int score = 0, hit = 0;
        for (size_t i = 0; i < recs.size(); i++) {
            uint16_t v = ctx.mem.U16(recs[i] + c);
            bool rt = (v & METHOD_ATTRIBUTE_RT_SPECIAL_NAME) != 0;
            if (rt == (isCtor[i] != 0)) score++;
            if (rt && isCtor[i]) hit++;
            if ((v & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) == 0) score--;
        }
        if (ctors && hit * 10 < ctors * 9) continue;
        if (score > bestScore) { bestScore = score; bestF = c; bestHit = hit; }
    }
    ok = bestHit > 0 && bestScore * 100 >= (int)recs.size() * 90;
    if (ok) { ctx.L.mth_flags = bestF; ctx.L.mth_iflags = bestF + 2; }
    ctx.Note("MethodInfo.flags", Off(ctx.L.mth_flags), bestScore, (int)recs.size(), ok, false);

    Poll<uint32_t> cp;
    int measured = 0, expectOne = 0, gotOne = 0;
    std::map<uint32_t, int> oneHits;
    for (uint64_t r : recs) {
        std::string nm = ctx.mem.CStrOr(ctx.mem.U64(r + ctx.L.mth_name));
        int want = -1;
        if (nm == ".cctor" || nm == "ToString" || nm == "GetHashCode" || nm == "MoveNext" ||
            nm == "Dispose" || nm == "get_Current" || nm == "Finalize") want = 0;
        else if (nm.size() > 4 && nm.compare(0, 4, "get_") == 0 && nm != "get_Item") want = 0;
        else if (nm.size() > 4 && nm.compare(0, 4, "set_") == 0 && nm != "set_Item") want = 1;
        else if (nm.size() > 4 && nm.compare(0, 4, "add_") == 0) want = 1;
        else if (nm.size() > 7 && nm.compare(0, 7, "remove_") == 0) want = 1;
        if (want < 0) continue;
        measured++;
        if (want == 1) expectOne++;
        for (uint32_t c = 0; c + 2 <= MSPAN; c += 2) {
            if (ctx.mem.U16(r + c) == (uint16_t)want) { cp.Add(c << 1); if (want) oneHits[c << 1]++; }
            if (ctx.mem.U8(r + c) == (uint8_t)want)   { cp.Add((c << 1) | 1); if (want) oneHits[(c << 1) | 1]++; }
        }
    }

    n = 0; o = 0;
    for (const auto& kv : cp.v) {
        int one = oneHits.count(kv.first) ? oneHits.at(kv.first) : 0;
        if (expectOne && one * 10 < expectOne * 9) continue;
        if (kv.second > n) { n = kv.second; o = kv.first; }
    }
    ok = n * 10 >= measured * 8 && measured >= 50;
    if (ok) {
        ctx.L.mth_paramCount = o >> 1;
        ctx.L.mth_paramCountWidth = (o & 1) ? 1 : 2;
    }
    char pcbuf[32];
    sprintf_s(pcbuf, "+0x%X (u%u)", ctx.L.mth_paramCount, ctx.L.mth_paramCountWidth * 8);
    ctx.Note("MethodInfo.parameters_count", pcbuf, n, measured, ok, false);

    uint32_t bestS = 0; int bestSn = 0;
    for (uint32_t c = 0; c + 2 <= MSPAN; c += 2) {
        if (c == ctx.L.mth_flags || c == ctx.L.mth_paramCount) continue;
        int score = 0, virt = 0;
        for (uint64_t r : recs) {
            uint16_t fl = ctx.mem.U16(r + ctx.L.mth_flags);
            bool isVirt = (fl & METHOD_ATTRIBUTE_VIRTUAL) != 0;
            bool none = ctx.mem.U16(r + c) == 0xFFFF;
            if (none != isVirt) score++;
            if (isVirt && !none) virt++;
        }
        if (!virt) continue;
        if (score > bestSn) { bestSn = score; bestS = c; }
    }
    ok = bestSn * 100 >= (int)recs.size() * 90;
    if (ok) ctx.L.mth_slot = bestS;
    ctx.Note("MethodInfo.slot", Off(ctx.L.mth_slot), bestSn, (int)recs.size(), ok, false);

    Poll<uint32_t> gp;
    for (uint64_t r : recs)
        for (uint32_t c = 0; c + 8 <= MSPAN; c += 8) {
            uint64_t v = ctx.mem.U64(r + c);
            if (!ctx.InGA(v)) continue;
            const Region* rg = ctx.mem.RegionOf(v);
            if (rg && rg->executable) gp.Add(c);
        }
    n = 0;
    if (gp.Best(o, n) && n * 10 >= (int)recs.size() * 7) ctx.L.mth_ptr = o;

    uint32_t maxOff = ctx.L.mth_paramCount + 2;
    for (uint32_t v : { ctx.L.mth_ptr + 8, ctx.L.mth_klass + 8, ctx.L.mth_name + 8, ctx.L.mth_ret + 8,
                        ctx.L.mth_params + 8, ctx.L.mth_handle + 8, ctx.L.mth_token + 4, ctx.L.mth_slot + 2 })
        maxOff = (std::max)(maxOff, v);
    ctx.L.mth_size = (maxOff + 7) & ~7u;
}

}

void FitMemberLayout(Context& ctx) {
    Log("[*] fitting FieldInfo / MethodInfo...");
    FitFieldInfo(ctx);
    FitMethodInfo(ctx);
}

void ResolveImages(Context& ctx) {
    std::unordered_map<uint64_t, size_t> counts;
    for (auto& c : ctx.classes) if (c.image) counts[c.image]++;

    for (auto& kv : counts) {
        ImageDump im;
        im.addr = kv.first;

        std::vector<std::pair<uint32_t, std::string>> strs;
        for (uint32_t off = 0; off <= 0x60; off += 8) {
            std::string s;
            uint64_t p = ctx.mem.U64(kv.first + off);
            if (!ctx.mem.CStr(p, s) || s.empty() || s.size() > 200) continue;
            strs.push_back({ off, s });
        }
        for (auto& s : strs)
            if (s.second.size() > 4 && _stricmp(s.second.c_str() + s.second.size() - 4, ".dll") == 0) {
                im.name = s.second; ctx.L.img_name = s.first; break;
            }
        if (!im.name.empty()) {
            std::string stem = im.name.substr(0, im.name.size() - 4);
            for (auto& s : strs)
                if (s.second == stem) { im.nameNoExt = stem; ctx.L.img_nameNoExt = s.first; break; }
            if (im.nameNoExt.empty()) im.nameNoExt = stem;
        } else if (!strs.empty()) {
            im.nameNoExt = strs[0].second;
            im.name = im.nameNoExt + ".dll";
        } else {
            im.name = "unknown.dll"; im.nameNoExt = "unknown";
        }
        ctx.imageByAddr[kv.first] = ctx.images.size();
        ctx.images.push_back(std::move(im));
    }

    std::sort(ctx.images.begin(), ctx.images.end(),
              [](const ImageDump& a, const ImageDump& b) { return a.name < b.name; });
    ctx.imageByAddr.clear();
    for (size_t i = 0; i < ctx.images.size(); i++) ctx.imageByAddr[ctx.images[i].addr] = i;
    for (size_t i = 0; i < ctx.classes.size(); i++) {
        auto it = ctx.imageByAddr.find(ctx.classes[i].image);
        if (it != ctx.imageByAddr.end()) ctx.images[it->second].classIdx.push_back(i);
    }

    Poll<uint32_t> cgmName;
    for (const ImageDump& im : ctx.images)
        for (uint32_t off = 0; off <= 0x60; off += 8) {
            uint64_t p = ctx.mem.U64(im.addr + off);
            if (!ctx.InGA(p)) continue;
            for (uint32_t no = 0; no <= 0x18; no += 8)
                if (ctx.mem.CStrOr(ctx.mem.U64(p + no)) == im.name) cgmName.Add((off << 8) | no);
        }
    uint32_t key = 0; int n = 0;
    if (cgmName.Best(key, n) && n >= 1) {
        ctx.L.img_codeGenModule = key >> 8;
        ctx.L.cgm_name = key & 0xFF;
    }
    for (ImageDump& im : ctx.images) {
        uint64_t p = ctx.mem.U64(im.addr + ctx.L.img_codeGenModule);
        if (ctx.InGA(p) && ctx.mem.CStrOr(ctx.mem.U64(p + ctx.L.cgm_name)) == im.name) im.codeGenModule = p;
    }
    ctx.Note("Il2CppImage.codeGenModule", Off(ctx.L.img_codeGenModule), n, (int)ctx.images.size(), n > 0, false);

    Poll<uint64_t> joint;
    int tried = 0;
    for (const ClassDump& c : ctx.classes) {
        if (tried > 1500) break;
        auto it = ctx.imageByAddr.find(c.image);
        if (it == ctx.imageByAddr.end() || !ctx.images[it->second].codeGenModule) continue;
        uint64_t cgm = ctx.images[it->second].codeGenModule;
        uint64_t arr = ctx.mem.U64(c.addr + ctx.L.cls_methods);
        if (!ctx.Ptr(arr)) continue;
        uint16_t nm = WalkMethods(ctx, c.addr);
        for (uint16_t k = 0; k < nm && tried < 1500; k++) {
            uint64_t mi = ctx.mem.U64(arr + (uint64_t)k * 8);
            uint32_t rid = ctx.mem.U32(mi + ctx.L.mth_token) & 0xFFFFFF;
            if (!rid || rid > 4000000) continue;
            tried++;
            for (uint32_t mo = 0; mo <= 0x40; mo += 8) {
                uint64_t table = ctx.mem.U64(cgm + mo);
                if (!ctx.InGA(table)) continue;
                uint64_t fn = ctx.mem.U64(table + (uint64_t)(rid - 1) * 8);
                if (!ctx.InGA(fn)) continue;
                for (uint32_t po = 0; po + 8 <= MSPAN; po += 8)
                    if (ctx.mem.U64(mi + po) == fn) joint.Add(((uint64_t)po << 16) | mo);
            }
        }
    }
    uint64_t jk = 0; n = 0;
    bool ok = joint.Best(jk, n) && n * 10 >= tried * 5;
    if (ok) {
        ctx.L.mth_ptr = (uint32_t)(jk >> 16);
        ctx.L.cgm_methodPointers = (uint32_t)(jk & 0xFFFF);
    }
    ctx.Note("Il2CppCodeGenModule.methodPointers", Off(ctx.L.cgm_methodPointers), n, tried, ok, true);
    ctx.Note("MethodInfo.methodPointer (confirmed)", Off(ctx.L.mth_ptr), n, tried, ok, true);

    Poll<uint32_t> cnt;
    for (const ImageDump& im : ctx.images) {
        if (!im.codeGenModule) continue;
        uint64_t table = ctx.mem.U64(im.codeGenModule + ctx.L.cgm_methodPointers);
        if (!ctx.InGA(table)) continue;
        for (uint32_t o = 0; o <= 0x40; o += 4) {
            uint32_t v = ctx.mem.U32(im.codeGenModule + o);
            if (v < 4 || v > 2000000) continue;
            if (ctx.InGA(ctx.mem.U64(table + (uint64_t)(v - 1) * 8))) cnt.Add(o);
        }
    }
    uint32_t co = 0; n = 0;
    if (cnt.Best(co, n) && n >= 2) ctx.L.cgm_methodCount = co;

    int withCgm = 0;
    for (ImageDump& im : ctx.images) {
        if (!im.codeGenModule) continue;
        im.methodPointers = ctx.mem.U64(im.codeGenModule + ctx.L.cgm_methodPointers);
        im.methodPointerCount = ctx.mem.U32(im.codeGenModule + ctx.L.cgm_methodCount);
        if (ctx.InGA(im.methodPointers)) withCgm++; else im.methodPointers = 0;
    }
    Log("[+] %zu assemblies (%d with a usable code-gen module)", ctx.images.size(), withCgm);
}

namespace {

void ReadFields(Context& ctx, ClassDump& c) {
    uint64_t arr = ctx.mem.U64(c.addr + ctx.L.cls_fields);
    if (!ctx.Ptr(arr)) return;
    for (uint32_t i = 0; i < 4096; i++) {
        uint64_t f = arr + (uint64_t)i * ctx.L.fld_size;
        if (ctx.mem.U64(f + ctx.L.fld_parent) != c.addr) break;
        FieldDump fd;
        if (!ctx.mem.CStr(ctx.mem.U64(f + ctx.L.fld_name), fd.name)) continue;
        fd.token = ctx.mem.U32(f + ctx.L.fld_token);
        fd.type = ctx.mem.U64(f + ctx.L.fld_type);
        fd.offset = ctx.mem.U32(f + ctx.L.fld_offset);
        if (fd.type) {
            uint32_t bits = ctx.mem.U32(fd.type + ctx.L.typ_bits);
            fd.attrs = (uint16_t)(bits & 0xFFFF);
            fd.isStatic = (fd.attrs & FIELD_ATTRIBUTE_STATIC) != 0;
            fd.isLiteral = (fd.attrs & FIELD_ATTRIBUTE_LITERAL) != 0;
        }
        c.fields.push_back(std::move(fd));
    }
}

void ReadRuntimeMethods(Context& ctx, ClassDump& c) {
    uint64_t arr = ctx.mem.U64(c.addr + ctx.L.cls_methods);
    if (!ctx.Ptr(arr)) return;
    for (uint32_t i = 0; i < 4096; i++) {
        uint64_t mi = ctx.mem.U64(arr + (uint64_t)i * 8);
        if (!ctx.Ptr(mi) || ctx.mem.U64(mi + ctx.L.mth_klass) != c.addr) break;
        MethodDump m;
        if (!ctx.mem.CStr(ctx.mem.U64(mi + ctx.L.mth_name), m.name)) continue;
        m.methodPtr = ctx.mem.U64(mi + ctx.L.mth_ptr);
        if (ctx.InGA(m.methodPtr)) m.rva = m.methodPtr - ctx.gaBase; else m.methodPtr = 0;
        m.returnType = ctx.mem.U64(mi + ctx.L.mth_ret);
        m.token = ctx.mem.U32(mi + ctx.L.mth_token);
        m.flags = ctx.mem.U16(mi + ctx.L.mth_flags);
        m.iflags = ctx.mem.U16(mi + ctx.L.mth_iflags);
        m.slot = ctx.mem.U16(mi + ctx.L.mth_slot);
        m.paramCount = ctx.L.mth_paramCountWidth == 1 ? ctx.mem.U8(mi + ctx.L.mth_paramCount)
                                                      : (uint8_t)ctx.mem.U16(mi + ctx.L.mth_paramCount);
        uint64_t pars = ctx.mem.U64(mi + ctx.L.mth_params);
        if (ctx.Ptr(pars) && m.paramCount > 0 && m.paramCount < 64)
            for (uint8_t p = 0; p < m.paramCount; p++)
                m.paramTypes.push_back(ctx.mem.U64(pars + (uint64_t)p * 8));
        m.fromRuntime = true;
        c.methods.push_back(std::move(m));
    }
}

void FitStaticFields(Context& ctx) {
    std::map<uint32_t, int> good, bad;
    int tried = 0;
    for (const auto& c : ctx.classes) {
        bool hasStatic = false, hasInstance = false;
        for (const auto& f : c.fields) (f.isStatic && !f.isLiteral ? hasStatic : hasInstance) = true;
        if (!hasStatic && !hasInstance) continue;
        if (++tried > 4000) break;
        for (uint32_t off = 0; off <= SPAN; off += 8) {
            uint64_t v = ctx.mem.U64(c.addr + off);
            bool set = ctx.Ptr(v) && !ctx.InGA(v) && !ctx.byAddr.count(v) && !ctx.InHeap(v);
            if (hasStatic && set) good[off]++;
            else if (!hasStatic && set) bad[off]++;
        }
    }
    uint32_t best = 0; int bestScore = 0;
    for (const auto& kv : good) {
        int b = bad.count(kv.first) ? bad.at(kv.first) : 0;
        if (kv.second - b > bestScore) { bestScore = kv.second - b; best = kv.first; }
    }
    bool ok = bestScore * 4 > tried;
    if (ok) ctx.L.cls_staticFields = best;
    ctx.Note("Il2CppClass.static_fields", Off(ctx.L.cls_staticFields), bestScore, tried, ok, false);
    for (auto& c : ctx.classes) {
        uint64_t v = ctx.mem.U64(c.addr + ctx.L.cls_staticFields);
        bool any = false;
        for (const auto& f : c.fields) if (f.isStatic && !f.isLiteral) { any = true; break; }
        if (any && ctx.Ptr(v) && !ctx.InGA(v)) c.staticFields = v;
    }
}

void FitInstanceSize(Context& ctx) {
    std::vector<std::pair<uint64_t, uint32_t>> want;
    for (const auto& c : ctx.classes) {
        uint32_t hi = 0;
        for (const auto& f : c.fields) if (!f.isStatic && !f.isLiteral) hi = (std::max)(hi, f.offset);
        if (hi) want.push_back({ c.addr, hi + 1 });
        if (want.size() >= 2000) break;
    }
    if (want.size() < 20) return;

    uint32_t best = 0; int bestN = 0;
    for (uint32_t o = 0; o <= SPAN; o += 4) {
        int n = 0;
        for (const auto& w : want) {
            uint32_t v = ctx.mem.U32(w.first + o);
            if (v >= w.second && v <= w.second + 0x80) n++;
        }
        if (n > bestN) { bestN = n; best = o; }
    }
    bool ok = bestN * 100 >= (int)want.size() * 95;
    if (ok) ctx.L.cls_instanceSize = best;
    ctx.Note("Il2CppClass.instance_size", Off(ctx.L.cls_instanceSize), bestN, (int)want.size(), ok, false);
    for (auto& c : ctx.classes) c.instanceSize = ctx.mem.U32(c.addr + ctx.L.cls_instanceSize);
}

}

void ReadMembers(Context& ctx) {
    size_t nf = 0, live = 0;
    for (auto& c : ctx.classes) {
        ReadFields(ctx, c);
        nf += c.fields.size();
        ReadRuntimeMethods(ctx, c);
        if (!c.methods.empty()) live++;
    }
    Log("[+] live runtime pass: %zu fields, %zu of %zu classes have method tables",
        nf, live, ctx.classes.size());
    FitStaticFields(ctx);
    FitInstanceSize(ctx);
}

namespace {

void FitMethodDefTable(Context& ctx) {
    std::map<uint32_t, std::map<uint64_t, int>> tally;
    int tried = 0;
    for (const auto& c : ctx.classes) {
        if (!c.handle || c.isGenericInst || c.methods.empty() || !c.methods[0].fromRuntime) continue;
        uint64_t arr = ctx.mem.U64(c.addr + ctx.L.cls_methods);
        if (!ctx.Ptr(arr)) continue;
        uint64_t mdh = ctx.mem.U64(ctx.mem.U64(arr) + ctx.L.mth_handle);
        if (!ctx.Ptr(mdh)) continue;
        if (++tried > 600) break;
        for (uint32_t off = 0; off <= 0x40; off += 4) {
            uint32_t start = ctx.mem.U32(c.handle + off);
            if (start == 0xFFFFFFFF || start > 4000000) continue;
            tally[off][mdh - (uint64_t)start * ctx.L.md_size]++;
        }
    }
    uint32_t bestOff = 0; uint64_t bestBase = 0; int bestN = 0;
    for (auto& a : tally)
        for (auto& b : a.second)
            if (b.second > bestN) { bestN = b.second; bestOff = a.first; bestBase = b.first; }
    bool ok = bestN * 10 >= tried * 7 && bestN >= 20;
    if (ok) {
        ctx.L.td_methodStart = bestOff;
        ctx.methodDefTable = bestBase;
        ctx.methodDefTableValid = true;
    }
    ctx.Note("Il2CppTypeDefinition.methodStart", Off(ctx.L.td_methodStart), bestN, tried, ok, true);
    ctx.Note("Il2CppMethodDefinition table", Hex(ctx.methodDefTable), bestN, tried, ok, true);
}

void FitTypeDefFields(Context& ctx) {
    std::vector<uint64_t> handles;
    std::vector<const ClassDump*> owners;
    for (const auto& c : ctx.classes) {
        if (!c.handle || c.isGenericInst) continue;
        handles.push_back(c.handle);
        owners.push_back(&c);
        if (handles.size() >= 1200) break;
    }
    if (handles.size() < 20) return;

    ctx.L.td_token = FitToken(ctx, handles, 0x02, 0x80, "Il2CppTypeDefinition.token", ctx.L.td_token, false);

    Poll<uint32_t> mc, fc, fl;
    int liveCounts = 0;
    for (size_t i = 0; i < handles.size(); i++) {
        const ClassDump& c = *owners[i];
        if (c.methods.empty() && c.fields.empty()) continue;
        liveCounts++;
        for (uint32_t o = 0; o + 2 <= 0x80; o += 2) {
            if (!c.methods.empty() && ctx.mem.U16(handles[i] + o) == c.methods.size()) mc.Add(o);
            if (!c.fields.empty() && ctx.mem.U16(handles[i] + o) == c.fields.size()) fc.Add(o);
        }
        for (uint32_t o = 0; o + 4 <= 0x80; o += 4)
            if (c.flags && ctx.mem.U32(handles[i] + o) == c.flags) fl.Add(o);
    }
    uint32_t o = 0; int n = 0;
    if (mc.Best(o, n) && n * 10 >= liveCounts * 7) ctx.L.td_methodCount = o;
    ctx.Note("Il2CppTypeDefinition.method_count", Off(ctx.L.td_methodCount), n, liveCounts, n * 10 >= liveCounts * 7, false);
    n = 0;
    if (fc.Best(o, n) && n * 10 >= liveCounts * 7) ctx.L.td_fieldCount = o;
    ctx.Note("Il2CppTypeDefinition.field_count", Off(ctx.L.td_fieldCount), n, liveCounts, n * 10 >= liveCounts * 7, false);
    n = 0;
    if (fl.Best(o, n) && n * 10 >= liveCounts * 7) ctx.L.td_flags = o;

    std::vector<uint64_t> sorted = handles;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());
    Poll<uint64_t> stride;
    for (size_t i = 1; i < sorted.size(); i++) {
        uint64_t d = sorted[i] - sorted[i - 1];
        if (d && d <= 0x200) stride.Add(d);
    }
    uint64_t s = 0; n = 0;
    if (stride.Best(s, n) && n >= 20) ctx.L.td_size = (uint32_t)s;
}

void FitTypesTable(Context& ctx, const std::unordered_set<uint64_t>& known) {
    if (known.size() < 200) { Log("[!] too few known Il2CppType* to locate the types table"); return; }
    const size_t WIN = 128;
    uint64_t bestBase = 0;
    size_t bestLen = 0;

    for (const auto& r : ctx.mem.Regions()) {
        if (r.base < ctx.gaBase || r.base >= ctx.gaBase + ctx.gaSize) continue;
        if (r.executable) continue;
        std::vector<uint64_t> buf(r.size / 8);
        if (buf.empty() || !ctx.mem.Read(r.base, buf.data(), buf.size() * 8)) continue;

        size_t i = 0;
        while (i + WIN <= buf.size()) {
            size_t hits = 0;
            for (size_t k = 0; k < WIN; k++) if (known.count(buf[i + k])) hits++;
            if (hits < WIN / 2) { i += WIN / 2; continue; }
            size_t lo = i, hi = i + WIN;
            auto plausible = [&](size_t idx) {
                return idx < buf.size() && ctx.InGA(buf[idx]) && ctx.IsType(buf[idx]);
            };
            while (lo > 0 && plausible(lo - 1)) lo--;
            while (hi < buf.size() && plausible(hi)) hi++;
            if (hi - lo > bestLen) { bestLen = hi - lo; bestBase = r.base + lo * 8; }
            i = hi;
        }
    }
    bool ok = bestLen >= 1000;
    if (ok) { ctx.typesArray = bestBase; ctx.typesCount = (uint32_t)bestLen; }
    char buf[64]; sprintf_s(buf, "GA+0x%llX, %zu entries", ok ? bestBase - ctx.gaBase : 0, bestLen);
    ctx.Note("Il2CppMetadataRegistration.types", buf, (int)bestLen, (int)bestLen, ok, false);
}

struct MdSample {
    uint64_t md = 0, namePtr = 0, returnType = 0;
    uint32_t token = 0;
    uint16_t flags = 0, iflags = 0, slot = 0;
    uint8_t paramCount = 0;
};

void FitMethodDefLayout(Context& ctx, const std::vector<MdSample>& s) {
    if (s.size() < 50) { Log("[!] not enough samples to fit Il2CppMethodDefinition"); return; }
    Layout& L = ctx.L;
    const uint32_t N = L.md_size;

    Poll<uint32_t> np;
    for (const auto& x : s)
        for (uint32_t o = 0; o + 4 <= N; o += 2)
            if (ctx.strBase + ctx.mem.U32(x.md + o) == x.namePtr) np.Add(o);
    uint32_t o = 0; int n = 0;
    bool ok = np.Best(o, n) && n * 10 >= (int)s.size() * 8;
    if (ok) L.md_nameIndex = (int32_t)o;
    ctx.Note("Il2CppMethodDefinition.nameIndex", Off((uint32_t)L.md_nameIndex), n, (int)s.size(), ok, true);

    auto fitU = [&](auto getter, int width, int32_t& off, int32_t* widthOut) {
        std::map<int32_t, int> score;
        for (const auto& x : s)
            for (uint32_t p = 0; p + (uint32_t)width <= N; p += 2) {
                uint64_t v = width == 4 ? ctx.mem.U32(x.md + p) : ctx.mem.U16(x.md + p);
                if (v == (uint64_t)getter(x)) score[(int32_t)p]++;
            }
        int best = 0; int32_t bestOff = -1;
        for (const auto& kv : score) if (kv.second > best) { best = kv.second; bestOff = kv.first; }
        bool good = bestOff >= 0 && best * 10 >= (int)s.size() * 8;
        if (good) { off = bestOff; if (widthOut) *widthOut = width; }
        return std::make_pair(good, best);
    };
    auto fitNote = [&](auto getter, int width, const char* what, int32_t& off, int32_t* widthOut, bool crit) {
        auto r = fitU(getter, width, off, widthOut);
        ctx.Note(what, r.first ? Off((uint32_t)off) : std::string("none"), r.second, (int)s.size(), r.first, crit);
    };

    auto tok32 = fitU([](const MdSample& x) { return x.token & 0xFFFFFF; }, 4, L.md_token, &L.md_tokenWidth);
    if (L.md_token < 0)
        fitNote([](const MdSample& x) { return x.token & 0xFFFF; }, 2, "Il2CppMethodDefinition.token(u16)", L.md_token, &L.md_tokenWidth, true);
    else
        ctx.Note("Il2CppMethodDefinition.token(u32)", Off((uint32_t)L.md_token), tok32.second, (int)s.size(), true, true);

    fitNote([](const MdSample& x) { return x.flags; }, 2, "Il2CppMethodDefinition.flags", L.md_flags, nullptr, false);
    fitNote([](const MdSample& x) { return x.iflags; }, 2, "Il2CppMethodDefinition.iflags", L.md_iflags, nullptr, false);
    fitNote([](const MdSample& x) { return x.slot; }, 2, "Il2CppMethodDefinition.slot", L.md_slot, nullptr, false);
    fitNote([](const MdSample& x) { return x.paramCount; }, 2, "Il2CppMethodDefinition.parameters_count", L.md_paramCount, nullptr, false);

    if (ctx.typesArray) {
        std::map<std::pair<int32_t, int32_t>, int> score;
        for (const auto& x : s) {
            if (!x.returnType) continue;
            for (uint32_t p = 0; p + 2 <= N; p += 2) {
                if (p + 4 <= N && ctx.TypeAt(ctx.mem.U32(x.md + p)) == x.returnType) score[{ (int32_t)p, 4 }]++;
                if (ctx.TypeAt(ctx.mem.U16(x.md + p)) == x.returnType) score[{ (int32_t)p, 2 }]++;
            }
        }
        int best = 0; std::pair<int32_t, int32_t> bestK{ -1, 0 };
        for (const auto& kv : score) if (kv.second > best) { best = kv.second; bestK = kv.first; }
        bool good = bestK.first >= 0 && best * 10 >= (int)s.size() * 7;
        if (good) { L.md_returnType = bestK.first; L.md_returnWidth = bestK.second; }
        ctx.Note("Il2CppMethodDefinition.returnType",
                 good ? Off((uint32_t)bestK.first) : std::string("none"), best, (int)s.size(), good, false);
    }
}

void VerifyMetadataPath(Context& ctx) {
    if (!ctx.methodDefTableValid || ctx.L.md_nameIndex < 0) return;
    size_t checked = 0, agree = 0;
    for (const auto& c : ctx.classes) {
        if (c.methods.empty() || !c.methods[0].fromRuntime || !c.handle || c.isGenericInst) continue;
        uint32_t start = ctx.mem.U32(c.handle + ctx.L.td_methodStart);
        if (start == 0xFFFFFFFF || start > 8000000) continue;
        for (size_t i = 0; i < c.methods.size(); i++) {
            uint64_t md = ctx.methodDefTable + (uint64_t)(start + i) * ctx.L.md_size;
            std::string nm;
            if (!ctx.mem.CStr(ctx.strBase + ctx.mem.U32(md + ctx.L.md_nameIndex), nm)) continue;
            checked++;
            if (nm == c.methods[i].name) agree++;
        }
        if (checked > 20000) break;
    }
    ctx.metaCheckAgree = (int)agree;
    ctx.metaCheckTotal = (int)checked;
    if (checked)
        Log("[+] metadata cross-check: %zu/%zu method names match the live runtime (%.1f%%)",
            agree, checked, 100.0 * agree / checked);
}

}

void FitMetadataTables(Context& ctx) {
    Log("[*] fitting the metadata tables...");
    FitMethodDefTable(ctx);
    FitTypeDefFields(ctx);

    std::unordered_set<uint64_t> knownTypes;
    for (const auto& c : ctx.classes) {
        for (const auto& f : c.fields) if (f.type) knownTypes.insert(f.type);
        for (const auto& m : c.methods) {
            if (m.returnType) knownTypes.insert(m.returnType);
            for (uint64_t p : m.paramTypes) if (p) knownTypes.insert(p);
        }
    }
    FitTypesTable(ctx, knownTypes);

    std::vector<MdSample> samples;
    if (ctx.methodDefTableValid) {
        for (const auto& c : ctx.classes) {
            if (samples.size() >= 3000) break;
            if (!c.handle || c.isGenericInst || c.methods.empty() || !c.methods[0].fromRuntime) continue;
            uint32_t start = ctx.mem.U32(c.handle + ctx.L.td_methodStart);
            if (start == 0xFFFFFFFF || start > 8000000) continue;
            uint64_t arr = ctx.mem.U64(c.addr + ctx.L.cls_methods);
            if (!ctx.Ptr(arr)) continue;
            for (size_t i = 0; i < c.methods.size() && samples.size() < 3000; i++) {
                uint64_t mi = ctx.mem.U64(arr + i * 8);
                uint64_t mdh = ctx.mem.U64(mi + ctx.L.mth_handle);
                if (mdh != ctx.methodDefTable + (uint64_t)(start + i) * ctx.L.md_size) continue;
                const MethodDump& m = c.methods[i];
                samples.push_back({ mdh, ctx.mem.U64(mi + ctx.L.mth_name), m.returnType,
                                    m.token, m.flags, m.iflags, m.slot, m.paramCount });
            }
        }
    }
    FitMethodDefLayout(ctx, samples);
    VerifyMetadataPath(ctx);
}

void FillFromMetadata(Context& ctx) {
    if (!ctx.methodDefTableValid) {
        Log("[!] no method-definition table: uninitialised classes will have no methods");
        return;
    }
    const Layout& L = ctx.L;
    size_t filled = 0, empty = 0;

    for (auto& c : ctx.classes) {
        if (!c.declaredMethods || !c.methods.empty() || !c.handle || c.isGenericInst) continue;
        uint32_t start = ctx.mem.U32(c.handle + L.td_methodStart);
        if (start == 0xFFFFFFFF || start > 8000000) { empty++; continue; }

        const ImageDump* im = nullptr;
        auto it = ctx.imageByAddr.find(c.image);
        if (it != ctx.imageByAddr.end()) im = &ctx.images[it->second];

        for (uint16_t i = 0; i < c.declaredMethods; i++) {
            uint64_t md = ctx.methodDefTable + (uint64_t)(start + i) * L.md_size;
            MethodDump m;
            if (!ctx.mem.CStr(ctx.strBase + ctx.mem.U32(md + L.md_nameIndex), m.name) || m.name.empty()) continue;
            if (L.md_token >= 0) {
                uint32_t rid = L.md_tokenWidth == 4 ? ctx.mem.U32(md + L.md_token) : ctx.mem.U16(md + L.md_token);
                m.token = 0x06000000u | (rid & 0xFFFFFF);
            }
            if (L.md_flags >= 0) m.flags = ctx.mem.U16(md + L.md_flags);
            if (L.md_iflags >= 0) m.iflags = ctx.mem.U16(md + L.md_iflags);
            if (L.md_slot >= 0) m.slot = ctx.mem.U16(md + L.md_slot);
            if (L.md_paramCount >= 0) m.paramCount = (uint8_t)ctx.mem.U16(md + L.md_paramCount);
            if (L.md_returnType >= 0)
                m.returnType = ctx.TypeAt(L.md_returnWidth == 4 ? ctx.mem.U32(md + L.md_returnType)
                                                                : ctx.mem.U16(md + L.md_returnType));
            if (m.token && im && im->methodPointers && im->methodPointerCount) {
                uint32_t rid = m.token & 0xFFFFFF;
                if (rid >= 1 && rid <= im->methodPointerCount) {
                    uint64_t p = ctx.mem.U64(im->methodPointers + (uint64_t)(rid - 1) * 8);
                    if (ctx.InGA(p)) { m.methodPtr = p; m.rva = p - ctx.gaBase; }
                }
            }
            c.methods.push_back(std::move(m));
        }
        if (!c.methods.empty()) filled++; else empty++;
    }

    size_t nm = 0, nf = 0, withRva = 0;
    for (const auto& c : ctx.classes) {
        nm += c.methods.size(); nf += c.fields.size();
        for (const auto& m : c.methods) if (m.rva) withRva++;
    }
    Log("[+] members: %zu fields, %zu methods (%zu with an RVA)", nf, nm, withRva);
    Log("    %zu classes filled from metadata, %zu left without methods", filled, empty);
}
