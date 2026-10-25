#include "AotRelink.h"

#include "../loader/elf/ElfLoader.h"
#include "../loader/pe/PeParser.h"
#include "../memory/MemoryManager.h"
#include "../diagnostics/Logger.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>

namespace nexus {
namespace aot {

namespace {

std::string hex(uint64_t v) {
    std::ostringstream o;
    o << "0x" << std::hex << v;
    return o.str();
}

void mergeInto(std::vector<std::string>& dst, const std::vector<std::string>& src) {
    for (const auto& s : src) {
        const std::string key = s.substr(0, s.find(' '));
        bool seen = false;
        for (const auto& d : dst) {
            if (d.rfind(key + " ", 0) == 0 || d == key) { seen = true; break; }
        }
        if (!seen) dst.push_back(s);
    }
}

} // namespace

std::string ModuleTranslation::summary() const {
    std::ostringstream o;
    o << "aot[" << name << "]: ";
    if (!ok) {
        o << "no image";
        if (!error.empty()) o << " (" << error << ")";
        if (!unsupported.empty()) {
            o << " unsupported:";
            for (size_t i = 0; i < unsupported.size() && i < 6; ++i)
                o << " " << unsupported[i];
            if (unsupported.size() > 6) o << " …";
        }
        return o.str();
    }
    o << segments.size() << (segments.size() == 1 ? " segment" : " segments")
      << ", " << blocks << " blocks, ";
    if (image_bytes >= 1024) o << (image_bytes / 1024) << " KB";
    else o << image_bytes << " B";
    return o.str();
}

bool readGuestRange(MemoryManager& mm, uint64_t base, uint64_t end,
                    std::vector<uint8_t>* out) {
    if (!out || end <= base) return false;
    out->clear();
    out->reserve(static_cast<size_t>(end - base));
    uint64_t at = base;
    while (at < end) {
        auto region = mm.query(at);
        if (!region || region->is_guard) return false;
        const uint64_t stop = std::min(end, region->guest_end);
        if (stop <= at) return false;
        const auto* host = static_cast<const uint8_t*>(mm.guestToHost(at));
        if (!host) return false;
        out->insert(out->end(), host, host + (stop - at));
        at = stop;
    }
    return out->size() == static_cast<size_t>(end - base);
}

std::vector<ExecRange> execRanges(const LoadedElf& loaded) {
    std::vector<ExecRange> out;
    for (const auto& ph : loaded.parsed.phdrs) {
        if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_X)) continue;
        const uint64_t align = ph.p_align ? ph.p_align : MemoryManager::kPageSize;
        const uint64_t start = (ph.p_vaddr & ~(align - 1)) + loaded.load_bias;
        const uint64_t stop = ((ph.p_vaddr + ph.p_memsz + align - 1) & ~(align - 1))
                              + loaded.load_bias;
        if (stop > start) out.push_back({start, stop});
    }
    std::sort(out.begin(), out.end(), [](const ExecRange& a, const ExecRange& b) {
        return a.base < b.base;
    });
    return out;
}

std::vector<ExecRange> execRanges(const ParsedPe& pe) {
    std::vector<ExecRange> out;
    for (const auto& s : pe.sections) {
        if (!s.executable() || s.virtual_size == 0) continue;
        const uint64_t start = pe.opt.image_base + s.virtual_address;
        const uint64_t stop = start + s.virtual_size;
        out.push_back({start, stop});
    }
    return out;
}

ModuleTranslation translate(MemoryManager& mm,
                            const std::vector<ExecRange>& ranges,
                            uint64_t entry,
                            const std::string& name,
                            const std::string& out_dir) {
    ModuleTranslation report;
    report.name = name;
    if (ranges.empty()) {
        report.error = "no executable ranges";
        return report;
    }

    size_t index = 0;
    bool any = false;
    for (const ExecRange& r : ranges) {
        SegmentTranslation seg;
        seg.base = r.base;
        seg.end = r.end;

        std::vector<uint8_t> bytes;
        if (!readGuestRange(mm, r.base, r.end, &bytes)) {
            report.unsupported.push_back("unreadable segment " + hex(r.base));
            report.segments.push_back(seg);
            ++index;
            continue;
        }

        const uint64_t seg_entry = (entry >= r.base && entry < r.end) ? entry : 0;
        AotResult res = compile(bytes.data(), bytes.size(), r.base, seg_entry);
        seg.ok = res.ok;
        seg.blocks = res.block_count;
        seg.code_bytes = res.code_bytes;

        if (!res.ok) {
            mergeInto(report.unsupported, res.unsupported);
            if (report.error.empty()) report.error = res.error;
            report.segments.push_back(seg);
            ++index;
            continue;
        }

        std::ostringstream fname;
        fname << out_dir << "/" << name << "." << index << ".nine.aot";
        std::ofstream f(fname.str(), std::ios::binary | std::ios::trunc);
        if (!f) {
            report.error = "cannot write " + fname.str();
            report.segments.push_back(seg);
            ++index;
            continue;
        }
        f.write(reinterpret_cast<const char*>(res.image.data()),
                static_cast<std::streamsize>(res.image.size()));
        f.close();
        if (!f) {
            report.error = "short write " + fname.str();
            report.segments.push_back(seg);
            ++index;
            continue;
        }

        seg.path = fname.str();
        seg.image_bytes = res.image.size();
        report.blocks += res.block_count;
        report.image_bytes += res.image.size();
        any = true;
        Logger::instance().infof(LogCategory::TRANSLATOR,
            "aot: %s compiled %s-%s -> %u blocks, %u bytes of code",
            name.c_str(), hex(r.base).c_str(), hex(r.end).c_str(),
            res.block_count, res.code_bytes);
        report.segments.push_back(seg);
        ++index;
    }

    // A program is only runnable without a translator when every executable
    // segment produced an image.
    report.ok = any && std::all_of(report.segments.begin(), report.segments.end(),
                                   [](const SegmentTranslation& s) { return s.ok; });
    if (!report.ok && report.error.empty()) report.error = "unsupported instruction";
    return report;
}

} // namespace aot
} // namespace nexus
