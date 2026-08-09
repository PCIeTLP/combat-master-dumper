#pragma once
#include "dumper.h"
#include <algorithm>

template <typename F>
static void Sweep(const Mem& mem, size_t overlap, F&& fn) {
    const size_t CH = 8u << 20;
    std::vector<uint8_t> buf(CH + overlap);
    for (const auto& r : mem.Regions()) {
        if (r.size > (1ull << 32)) continue;
        uint64_t off = 0;
        while (off < r.size) {
            size_t want = (size_t)(std::min)((uint64_t)CH + overlap, r.size - off);
            if (!mem.Read(r.base + off, buf.data(), want)) {
                bool any = false;
                for (size_t p = 0; p + 0x1000 <= want; p += 0x1000)
                    if (mem.Read(r.base + off + p, buf.data() + p, 0x1000)) any = true;
                    else memset(buf.data() + p, 0, 0x1000);
                if (!any) { off += CH; continue; }
            }
            fn(r, r.base + off, buf.data(), want);
            if (want <= overlap) break;
            off += want - overlap;
        }
    }
}
