#pragma once
/*
 * stack_resolver.hpp
 *
 * Resolves BPF stack_trace map IDs → ordered vector<string> of symbol names.
 * Frame order: index 0 = outermost caller (closest to root),
 *              back()  = innermost / leaf.
 *
 * Usage:
 *   StackResolver resolver(bpf_map__fd(user_stacks_map), target_pid);
 *   std::string folded = resolver.folded(stack_id, "do_cpu_work");
 *   // → "root;main;do_cpu_work"
 */

#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <bpf/bpf.h>

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 127
#endif

/* ─── /proc/pid/maps segment ──────────────────────────────────────── */
struct MapSegment {
    uint64_t    start  = 0;
    uint64_t    end    = 0;
    uint64_t    offset = 0;
    std::string path;
};

static std::vector<MapSegment> load_proc_maps(uint32_t pid)
{
    std::vector<MapSegment> segs;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/maps", pid);
    std::ifstream f(path);
    if (!f.is_open()) return segs;

    std::string line;
    while (std::getline(f, line)) {
        MapSegment seg{};
        char perms[8]{};
        char pathname[512]{};
        if (sscanf(line.c_str(), "%lx-%lx %7s %lx %*s %*s %511s",
                   &seg.start, &seg.end, perms, &seg.offset, pathname) >= 4) {
            if (perms[2] == 'x' && pathname[0] == '/') {
                seg.path = pathname;
                segs.push_back(seg);
            }
        }
    }
    return segs;
}

static const MapSegment* find_segment(const std::vector<MapSegment>& segs,
                                      uint64_t ip)
{
    for (const auto& s : segs)
        if (ip >= s.start && ip < s.end) return &s;
    return nullptr;
}

/* ─── Symbolize one IP ────────────────────────────────────────────── */
static std::string symbolize_ip(uint64_t ip,
                                 const std::vector<MapSegment>& segs)
{
    if (ip == 0) return "";
    if (ip >= 0xffff000000000000ULL) return ""; // kernel — skip

    // dladdr: works for shared libs loaded in our own process space.
    // For the target binary itself we fall through to the maps fallback.
    Dl_info dli{};
    if (dladdr(reinterpret_cast<void*>(ip), &dli) && dli.dli_sname)
        return std::string(dli.dli_sname);

    // /proc/pid/maps fallback → "libname+offset"
    const MapSegment* seg = find_segment(segs, ip);
    if (seg) {
        size_t slash = seg->path.rfind('/');
        std::string lib = (slash == std::string::npos)
                          ? seg->path
                          : seg->path.substr(slash + 1);
        // Strip .so version suffixes: libpthread.so.0 → libpthread
        size_t dot = lib.find(".so");
        if (dot != std::string::npos) lib = lib.substr(0, dot);

        char buf[32];
        uint64_t file_off = (ip - seg->start) + seg->offset;
        snprintf(buf, sizeof(buf), "+0x%lx", (unsigned long)file_off);
        return lib + buf;
    }

    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ip);
    return buf;
}

/* ─── Filter noisy boilerplate frames ────────────────────────────── */
static bool is_boilerplate(const std::string& sym)
{
    static const char* noise[] = {
        "__libc_start_main", "__libc_start_call_main",
        "_start", "__GI___libc_start_main",
        "clone", "__clone",
        nullptr
    };
    for (int i = 0; noise[i]; ++i)
        if (sym.find(noise[i]) != std::string::npos) return true;
    return false;
}

/* ═══════════════════════════════════════════════════════════════════
 * StackResolver
 * ═══════════════════════════════════════════════════════════════════ */
class StackResolver {
public:
    /* stack_map_fd : fd of BPF_MAP_TYPE_STACK_TRACE map (pass -1 to disable)
     * pid          : target PID for /proc/pid/maps symbol resolution         */
    StackResolver(int stack_map_fd, uint32_t pid)
        : stack_map_fd_(stack_map_fd), pid_(pid)
    {
        refresh_maps();
    }

    /* Re-read /proc/pid/maps — call every few seconds, not per-event */
    void refresh_maps()
    {
        proc_maps_ = load_proc_maps(pid_);
    }

    /* Resolve stack_id → frames ordered outermost→innermost.
     * Returns empty vector when stack_id < 0 or lookup fails.         */
    std::vector<std::string> resolve(int32_t stack_id)
    {
        if (stack_id < 0 || stack_map_fd_ < 0) return {};

        auto it = cache_.find(stack_id);
        if (it != cache_.end()) return it->second;

        uint64_t ips[MAX_STACK_DEPTH] = {};
        uint32_t key = static_cast<uint32_t>(stack_id);
        if (bpf_map_lookup_elem(stack_map_fd_, &key, ips) != 0) {
            cache_[stack_id] = {};
            return {};
        }

        std::vector<std::string> frames;
        frames.reserve(16);

        // BPF stores frames leaf-first; skip zeroes
        for (int i = 0; i < MAX_STACK_DEPTH; i++) {
            if (ips[i] == 0) break;
            std::string sym = symbolize_ip(ips[i], proc_maps_);
            if (sym.empty() || is_boilerplate(sym)) continue;
            frames.push_back(std::move(sym));
        }

        // Reverse → [0] = outermost, back() = leaf
        std::reverse(frames.begin(), frames.end());

        cache_[stack_id] = frames;
        return frames;
    }

    /* Build folded-stack string for a .folded file.
     *
     * leaf_func : the instrumented function name (from g_func_names)
     *
     * Examples:
     *   stack_id valid   → "root;main;do_cpu_work"
     *   stack_id invalid → "root;do_cpu_work"          (graceful fallback)
     */
    std::string folded(int32_t stack_id, const std::string& leaf_func)
    {
        auto frames = resolve(stack_id);

        std::string result = "root";
        for (const auto& f : frames) {
            if (f == leaf_func) continue; // avoid duplicate leaf
            result += ';';
            result += f;
        }
        result += ';';
        result += leaf_func;
        return result;
    }

private:
    int                                          stack_map_fd_;
    uint32_t                                     pid_;
    std::vector<MapSegment>                      proc_maps_;
    std::unordered_map<int32_t,
                       std::vector<std::string>> cache_;
};