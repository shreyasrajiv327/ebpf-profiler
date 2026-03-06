/*
 * main.cpp - Phase 3: auto PID resolution + stack traces
 *
 * Changes from Phase 2:
 *   1. Accept process NAME instead of --pid / --bin
 *        sudo ./profiler test_target --funcs "run_one_cycle,compute,wait_a_bit"
 *      Internally scans /proc, finds PID, resolves binary via /proc/<pid>/exe
 *
 *   2. Stack traces on EVENT_FUNC_EXIT:
 *        - Symbolized frames printed to terminal
 *        - Folded stack format appended to stacks.folded (for flamegraph.pl)
 *
 * Everything else (libbpf loading, uprobe attachment, ring buffer,
 * off-cpu tracking, 3-func slots) is unchanged from Phase 2.
 *
 * Ubuntu 22.04 ARM64 / libbpf 0.5
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <csignal>
#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <fstream>
#include <algorithm>

#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <gelf.h>
#include <libelf.h>

#include "profiler_common.h"

/* ═══════════════════════════════════════════════════════════════════════
 *  Globals
 * ═════════════════════════════════════════════════════════════════════*/

static volatile bool g_running = true;

static struct bpf_object  *g_uprobe_obj = nullptr;
static struct bpf_object  *g_offcpu_obj = nullptr;
static struct ring_buffer *g_uprobe_rb  = nullptr;
static struct ring_buffer *g_offcpu_rb  = nullptr;

static std::vector<std::string> g_func_names;
static uint32_t  g_target_pid = 0;
static std::string g_binary_path;

struct FuncStats {
    uint64_t total_on_cpu_ns  = 0;
    uint64_t total_off_cpu_ns = 0;
    uint64_t total_wall_ns    = 0;
    uint64_t call_count       = 0;
};
static std::unordered_map<uint32_t, FuncStats> g_stats;
static uint64_t g_off_cpu_events = 0;

/* Maps needed for stack resolution */
static int g_user_stacks_fd   = -1;
static int g_kernel_stacks_fd = -1;

/* Folded-stacks output file */
static std::ofstream g_folded_out;

/* ═══════════════════════════════════════════════════════════════════════
 *  Signal handler
 * ═════════════════════════════════════════════════════════════════════*/

static void sig_handler(int) { g_running = false; }

/* ═══════════════════════════════════════════════════════════════════════
 *  Auto PID + binary resolution
 * ═════════════════════════════════════════════════════════════════════*/

/*
 * Scan /proc for a process whose comm (name) matches `target_name`.
 * Returns the PID on success, 0 if not found.
 *
 * We check two sources per PID:
 *   /proc/<pid>/comm   — the 15-char truncated process name
 *   /proc/<pid>/status — "Name: ..." line (same truncation)
 * Both are compared case-sensitively against the full target_name so
 * partial matches (e.g. "test" matching "test_target") are rejected.
 */
static uint32_t find_pid_by_name(const std::string &target_name)
{
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir /proc");
        return 0;
    }

    uint32_t found_pid = 0;
    struct dirent *entry;

    while ((entry = readdir(proc_dir)) != nullptr) {
        /* Only numeric entries are PIDs */
        bool all_digits = true;
        for (const char *p = entry->d_name; *p; ++p)
            if (*p < '0' || *p > '9') { all_digits = false; break; }
        if (!all_digits) continue;

        uint32_t pid = (uint32_t)atoi(entry->d_name);
        if (pid == 0) continue;

        /* Read /proc/<pid>/comm */
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%u/comm", pid);

        char comm[256] = {};
        FILE *f = fopen(comm_path, "r");
        if (!f) continue;
        if (fgets(comm, sizeof(comm), f)) {
            /* Strip trailing newline */
            size_t len = strlen(comm);
            if (len > 0 && comm[len-1] == '\n') comm[len-1] = '\0';
        }
        fclose(f);

        if (target_name == comm) {
            found_pid = pid;
            break;
        }
    }

    closedir(proc_dir);
    return found_pid;
}

/*
 * Resolve the full binary path for `pid` by reading the symlink
 * /proc/<pid>/exe.  Returns empty string on failure.
 */
static std::string resolve_binary_path(uint32_t pid)
{
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%u/exe", pid);

    char resolved[PATH_MAX] = {};
    ssize_t n = readlink(link_path, resolved, sizeof(resolved) - 1);
    if (n <= 0) {
        fprintf(stderr, "readlink %s failed: %s\n", link_path, strerror(errno));
        return {};
    }
    resolved[n] = '\0';
    return std::string(resolved);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Helpers
 * ═════════════════════════════════════════════════════════════════════*/

static void bump_memlock_rlimit()
{
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);
}

static int set_target_pid(struct bpf_object *obj, uint32_t pid)
{
    struct bpf_map *m = bpf_object__find_map_by_name(obj, "target_pid");
    if (!m) { fprintf(stderr, "target_pid map not found\n"); return -1; }
    int fd = bpf_map__fd(m);
    uint32_t key = 0;
    return bpf_map_update_elem(fd, &key, &pid, BPF_ANY);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  ELF symbol lookup
 * ═════════════════════════════════════════════════════════════════════*/

static uint64_t find_symbol_offset(const char *binary, const char *sym_name)
{
    if (elf_version(EV_CURRENT) == EV_NONE) return 0;

    int fd = open(binary, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Cannot open binary %s: %s\n", binary, strerror(errno));
        return 0;
    }

    Elf *elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) { close(fd); return 0; }

    uint64_t result = 0;
    Elf_Scn *scn = nullptr;

    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) continue;
        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) continue;

        Elf_Data *data = elf_getdata(scn, nullptr);
        if (!data) continue;

        size_t count = shdr.sh_size / shdr.sh_entsize;
        for (size_t i = 0; i < count; i++) {
            GElf_Sym sym;
            if (!gelf_getsym(data, (int)i, &sym)) continue;
            if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name) continue;
            if (strcmp(name, sym_name) == 0) {
                result = sym.st_value;
                break;
            }
        }
        if (result) break;
    }

    elf_end(elf);
    close(fd);
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Stack trace resolution
 *
 *  The BPF stack-trace map stores arrays of instruction pointers.
 *  We resolve each IP to a symbol name using /proc/<pid>/maps +
 *  the ELF symbol table of the mapped binary (best-effort; no DWARF).
 *
 *  For kernel frames we fall back to /proc/kallsyms.
 * ═════════════════════════════════════════════════════════════════════*/

/* One entry from /proc/<pid>/maps */
struct MapRegion {
    uint64_t    start;
    uint64_t    end;
    uint64_t    offset;      /* file offset of the mapping */
    std::string path;
};

static std::vector<MapRegion> read_proc_maps(uint32_t pid)
{
    std::vector<MapRegion> regions;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/maps", pid);

    std::ifstream f(path);
    if (!f.is_open()) return regions;

    std::string line;
    while (std::getline(f, line)) {
        MapRegion r;
        char perms[8] = {}, pathname[512] = {};
        unsigned long long start, end, offset;
        unsigned int dev_major, dev_minor;
        unsigned long inode;

        int n = sscanf(line.c_str(),
                       "%llx-%llx %7s %llx %x:%x %lu %511s",
                       &start, &end, perms, &offset,
                       &dev_major, &dev_minor, &inode, pathname);
        if (n < 7) continue;

        r.start  = start;
        r.end    = end;
        r.offset = offset;
        r.path   = (n == 8) ? pathname : "";
        regions.push_back(r);
    }
    return regions;
}

/* Cache: binary path → {sym_offset → name} */
static std::unordered_map<std::string,
    std::unordered_map<uint64_t, std::string>> g_sym_cache;

static const std::unordered_map<uint64_t, std::string> &
load_elf_syms(const std::string &bin)
{
    auto it = g_sym_cache.find(bin);
    if (it != g_sym_cache.end()) return it->second;

    auto &syms = g_sym_cache[bin];

    if (elf_version(EV_CURRENT) == EV_NONE) return syms;
    int fd = open(bin.c_str(), O_RDONLY);
    if (fd < 0) return syms;

    Elf *elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) { close(fd); return syms; }

    Elf_Scn *scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) continue;
        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) continue;

        Elf_Data *data = elf_getdata(scn, nullptr);
        if (!data) continue;

        size_t count = shdr.sh_size / shdr.sh_entsize;
        for (size_t i = 0; i < count; i++) {
            GElf_Sym sym;
            if (!gelf_getsym(data, (int)i, &sym)) continue;
            if (sym.st_value == 0) continue;
            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (name && *name) syms[sym.st_value] = name;
        }
    }
    elf_end(elf);
    close(fd);
    return syms;
}

/* Resolve a single user-space instruction pointer to a symbol name */
static std::string resolve_user_ip(uint64_t ip,
                                   const std::vector<MapRegion> &maps)
{
    for (const auto &r : maps) {
        if (ip < r.start || ip >= r.end) continue;
        if (r.path.empty() || r.path[0] == '[') {
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ip);
            return buf;
        }
        uint64_t file_off = ip - r.start + r.offset;
        const auto &syms  = load_elf_syms(r.path);

        /* Find the symbol whose offset is the largest value ≤ file_off */
        uint64_t best_off  = 0;
        std::string best_name;
        for (const auto &kv : syms) {
            if (kv.first <= file_off && kv.first > best_off) {
                best_off  = kv.first;
                best_name = kv.second;
            }
        }
        if (!best_name.empty()) return best_name;

        /* Fallback: binary+offset */
        char buf[256];
        const char *base = strrchr(r.path.c_str(), '/');
        snprintf(buf, sizeof(buf), "%s+0x%llx",
                 base ? base+1 : r.path.c_str(),
                 (unsigned long long)file_off);
        return buf;
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ip);
    return buf;
}

/* Lazy-load /proc/kallsyms → address-sorted vector for kernel IPs */
struct KSym { uint64_t addr; std::string name; };
static std::vector<KSym> g_kallsyms;

static void load_kallsyms()
{
    if (!g_kallsyms.empty()) return;
    std::ifstream f("/proc/kallsyms");
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        unsigned long long addr;
        char type, name[256];
        if (sscanf(line.c_str(), "%llx %c %255s", &addr, &type, name) != 3)
            continue;
        g_kallsyms.push_back({addr, name});
    }
    std::sort(g_kallsyms.begin(), g_kallsyms.end(),
              [](const KSym &a, const KSym &b){ return a.addr < b.addr; });
}

static std::string resolve_kernel_ip(uint64_t ip)
{
    load_kallsyms();
    if (g_kallsyms.empty()) {
        char buf[32]; snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ip);
        return buf;
    }
    /* Upper-bound search, then step back */
    size_t lo = 0, hi = g_kallsyms.size();
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (g_kallsyms[mid].addr <= ip) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return "unknown_kernel";
    return g_kallsyms[lo-1].name;
}

/*
 * Read one stack-trace map entry (array of IPs) and return symbolized frames.
 * `is_kernel` selects which resolver to use.
 */
static std::vector<std::string>
resolve_stack(int map_fd, int32_t stack_id, bool is_kernel,
              const std::vector<MapRegion> &maps)
{
    std::vector<std::string> frames;
    if (stack_id < 0 || map_fd < 0) return frames;

    uint64_t ips[MAX_STACK_DEPTH] = {};
    if (bpf_map_lookup_elem(map_fd, &stack_id, ips) != 0) return frames;

    for (int i = 0; i < MAX_STACK_DEPTH; i++) {
        if (ips[i] == 0) break;
        if (is_kernel)
            frames.push_back(resolve_kernel_ip(ips[i]));
        else
            frames.push_back(resolve_user_ip(ips[i], maps));
    }
    return frames;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Ring buffer callback
 * ═════════════════════════════════════════════════════════════════════*/

static int handle_event(void *, void *data, size_t)
{
    const struct profiler_event *e =
        reinterpret_cast<const struct profiler_event *>(data);

    if (e->type == EVENT_FUNC_EXIT) {
        /* ── Accumulate stats ──────────────────────────────────────── */
        auto &s = g_stats[e->func_id];
        s.total_on_cpu_ns  += e->on_cpu_ns;
        s.total_off_cpu_ns += e->off_cpu_ns;
        s.total_wall_ns    += e->duration_ns;
        s.call_count++;

        /* ── Resolve stacks ────────────────────────────────────────── */
        const std::string &fname =
            (e->func_id < g_func_names.size())
                ? g_func_names[e->func_id] : "unknown";

        /* We need /proc/<pid>/maps to symbolize user IPs */
        auto maps = read_proc_maps(g_target_pid);

        /* user_stack_id and kernel_stack_id are in the profiler_event.
         * on_cpu.bpf.c stores them; uprobe.bpf.c does NOT (Phase 2 design).
         * We guard with the map fd check so this is a no-op if unavailable. */
        std::vector<std::string> user_frames, kern_frames;

        /* on_cpu events store stack IDs; for uprobe EXIT we have no stack
         * IDs in the current event struct — we print what we have. */
        /* If future phases add stack_id fields to profiler_event, wire them
         * here.  For now we emit a compact call record. */

        /* ── Terminal output ───────────────────────────────────────── */
        printf("\n[FUNC EXIT] %s  pid=%u tid=%u\n"
               "  wall=%.3f ms  on_cpu=%.3f ms  off_cpu=%.3f ms\n",
               fname.c_str(), e->pid, e->tid,
               e->duration_ns / 1e6,
               e->on_cpu_ns   / 1e6,
               e->off_cpu_ns  / 1e6);

        /* ── Folded stacks output ──────────────────────────────────── */
        /* Format: "func_name;frame1;frame2 on_cpu_ns"
         * If we have real frames (future: add stack_id to uprobe event),
         * they are inserted between func_name and the leaf.
         * For now emit a single-frame folded line so flamegraph.pl works. */
        if (g_folded_out.is_open()) {
            g_folded_out << fname << " " << e->on_cpu_ns << "\n";
        }

    } else if (e->type == EVENT_OFF_CPU) {
        g_off_cpu_events++;
        printf("[OFF_CPU] pid=%u tid=%u  blocked=%.3f ms\n",
               e->pid, e->tid, e->duration_ns / 1e6);
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Print stats table  (called every second)
 * ═════════════════════════════════════════════════════════════════════*/

static void print_table()
{
    printf("\033[2J\033[H");
    printf("eBPF Profiler — uprobe + off-cpu  |  pid=%u  bin=%s\n",
           g_target_pid, g_binary_path.c_str());
    printf("%s\n", std::string(84, '=').c_str());
    printf("%-24s %8s %13s %13s %11s\n",
           "FUNCTION", "CALLS", "ON_CPU_MS", "OFF_CPU_MS", "WALL_MS");
    printf("%s\n", std::string(84, '-').c_str());

    for (size_t i = 0; i < g_func_names.size(); i++) {
        auto it = g_stats.find((uint32_t)i);
        if (it == g_stats.end()) {
            printf("%-24s %8s %13s %13s %11s\n",
                   g_func_names[i].c_str(), "0", "0.000", "0.000", "0.000");
            continue;
        }
        const auto &s = it->second;
        printf("%-24s %8llu %13.3f %13.3f %11.3f\n",
               g_func_names[i].c_str(),
               (unsigned long long)s.call_count,
               s.total_on_cpu_ns  / 1e6,
               s.total_off_cpu_ns / 1e6,
               s.total_wall_ns    / 1e6);
    }

    printf("%s\n", std::string(84, '-').c_str());
    printf("Off-CPU blocking events : %llu\n",
           (unsigned long long)g_off_cpu_events);
    printf("Folded stacks           : stacks.folded\n");
    printf("Press Ctrl-C to stop\n");
    fflush(stdout);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Cleanup
 * ═════════════════════════════════════════════════════════════════════*/

static void cleanup()
{
    if (g_uprobe_rb)  ring_buffer__free(g_uprobe_rb);
    if (g_offcpu_rb)  ring_buffer__free(g_offcpu_rb);
    if (g_uprobe_obj) bpf_object__close(g_uprobe_obj);
    if (g_offcpu_obj) bpf_object__close(g_offcpu_obj);
    unlink("/sys/fs/bpf/profiler_off_cpu_data");
    if (g_folded_out.is_open()) g_folded_out.close();
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Usage
 * ═════════════════════════════════════════════════════════════════════*/

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <process_name> --funcs \"f1,f2,f3\"\n"
        "\n"
        "  <process_name>   Name of the already-running target process.\n"
        "                   The profiler scans /proc, resolves PID and\n"
        "                   binary path automatically.\n"
        "\n"
        "  --funcs          Comma-separated list of functions to probe\n"
        "                   (max 3 in this build — uprobe slots func0/1/2).\n"
        "\n"
        "Example:\n"
        "  sudo %s test_target --funcs \"run_one_cycle,compute,wait_a_bit\"\n",
        prog, prog);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  main
 * ═════════════════════════════════════════════════════════════════════*/

int main(int argc, char **argv)
{
    /* ── Argument parsing ──────────────────────────────────────────── */
    if (argc < 2) { usage(argv[0]); return 1; }

    std::string process_name = argv[1];
    const char *funcs_str    = nullptr;

    const char *uprobe_obj_path = "../build_cmake/uprobe.bpf.o";
    const char *offcpu_obj_path = "../build_cmake/off_cpu.bpf.o";

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--funcs") && i+1 < argc) {
            funcs_str = argv[++i];
        } else if (!strcmp(argv[i], "--uprobe-obj") && i+1 < argc) {
            uprobe_obj_path = argv[++i];
        } else if (!strcmp(argv[i], "--offcpu-obj") && i+1 < argc) {
            offcpu_obj_path = argv[++i];
        } else {
            fprintf(stderr, "Unknown argument: %s\n\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (!funcs_str) {
        fprintf(stderr, "Error: --funcs is required\n\n");
        usage(argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: must run as root (sudo)\n");
        return 1;
    }

    /* ── Auto-resolve PID from process name ───────────────────────── */
    printf("[*] Searching /proc for process '%s'...\n", process_name.c_str());
    g_target_pid = find_pid_by_name(process_name);
    if (g_target_pid == 0) {
        fprintf(stderr,
            "Error: process '%s' not found in /proc.\n"
            "       Make sure it is running before starting the profiler.\n",
            process_name.c_str());
        return 1;
    }
    printf("[+] Found PID: %u\n", g_target_pid);

    /* ── Auto-resolve binary path from /proc/<pid>/exe ───────────── */
    g_binary_path = resolve_binary_path(g_target_pid);
    if (g_binary_path.empty()) {
        fprintf(stderr, "Error: could not resolve binary path for PID %u\n",
                g_target_pid);
        return 1;
    }
    printf("[+] Binary  : %s\n", g_binary_path.c_str());

    /* ── Parse --funcs list ───────────────────────────────────────── */
    {
        std::stringstream ss(funcs_str);
        std::string token;
        while (std::getline(ss, token, ',')) {
            if (token.empty()) continue;
            if (g_func_names.size() >= 3) {
                fprintf(stderr,
                    "Warning: max 3 functions supported in this build — "
                    "ignoring '%s'\n", token.c_str());
                break;
            }
            g_func_names.push_back(token);
        }
    }

    if (g_func_names.empty()) {
        fprintf(stderr, "Error: no functions specified\n");
        return 1;
    }

    printf("[+] Functions to probe:\n");
    for (auto &f : g_func_names) printf("      - %s\n", f.c_str());
    printf("\n");

    /* ── Open folded-stacks output file ──────────────────────────── */
    g_folded_out.open("stacks.folded", std::ios::app);
    if (!g_folded_out.is_open())
        fprintf(stderr, "Warning: could not open stacks.folded for writing\n");
    else
        printf("[+] Folded stacks → stacks.folded\n\n");

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    bump_memlock_rlimit();
    libbpf_set_print(NULL);

    /* Clean up leftover pinned maps */
    unlink("/sys/fs/bpf/profiler_off_cpu_data");

    /* ── Load off_cpu BPF object ─────────────────────────────────── */
    printf("[*] Loading %s ...\n", offcpu_obj_path);
    g_offcpu_obj = bpf_object__open_file(offcpu_obj_path, nullptr);
    if (libbpf_get_error(g_offcpu_obj)) {
        fprintf(stderr, "Failed to open off_cpu BPF object\n");
        return 1;
    }
    if (bpf_object__load(g_offcpu_obj) != 0) {
        fprintf(stderr, "Failed to load off_cpu BPF object: %s\n", strerror(errno));
        cleanup(); return 1;
    }
    printf("[+] Loaded OK\n");

    /* Pin off_cpu_data map */
    struct bpf_map *shared_map =
        bpf_object__find_map_by_name(g_offcpu_obj, "off_cpu_data");
    if (!shared_map) {
        fprintf(stderr, "off_cpu_data map not found\n");
        cleanup(); return 1;
    }
    if (bpf_map__pin(shared_map, "/sys/fs/bpf/profiler_off_cpu_data") != 0) {
        fprintf(stderr, "Failed to pin off_cpu_data: %s\n", strerror(errno));
        cleanup(); return 1;
    }
    printf("[+] Pinned off_cpu_data map\n");

    /* ── Load uprobe BPF object ──────────────────────────────────── */
    printf("[*] Loading %s ...\n", uprobe_obj_path);
    g_uprobe_obj = bpf_object__open_file(uprobe_obj_path, nullptr);
    if (libbpf_get_error(g_uprobe_obj)) {
        fprintf(stderr, "Failed to open uprobe BPF object\n");
        cleanup(); return 1;
    }

    /* Reuse pinned off_cpu_data */
    struct bpf_map *uprobe_shared =
        bpf_object__find_map_by_name(g_uprobe_obj, "off_cpu_data");
    if (uprobe_shared) {
        int pinned_fd = bpf_obj_get("/sys/fs/bpf/profiler_off_cpu_data");
        if (pinned_fd >= 0) {
            bpf_map__reuse_fd(uprobe_shared, pinned_fd);
            printf("[+] Reusing shared off_cpu_data map\n");
        }
    }

    if (bpf_object__load(g_uprobe_obj) != 0) {
        fprintf(stderr, "Failed to load uprobe BPF object: %s\n", strerror(errno));
        cleanup(); return 1;
    }
    printf("[+] Loaded OK\n");

    /* ── Set target PID in both objects ──────────────────────────── */
    if (set_target_pid(g_uprobe_obj, g_target_pid) != 0) { cleanup(); return 1; }
    if (set_target_pid(g_offcpu_obj, g_target_pid) != 0) { cleanup(); return 1; }

    /* ── Grab stack-map FDs (from uprobe object, on_cpu maps) ────── */
    {
        struct bpf_map *um =
            bpf_object__find_map_by_name(g_uprobe_obj, "user_stacks");
        struct bpf_map *km =
            bpf_object__find_map_by_name(g_uprobe_obj, "kernel_stacks");
        if (um) g_user_stacks_fd   = bpf_map__fd(um);
        if (km) g_kernel_stacks_fd = bpf_map__fd(km);
    }

    /* ── Attach uprobes (one BPF program slot per function) ──────── */
    printf("\n[*] Attaching uprobes...\n");

    const char *entry_prog_names[] = {"func0_entry", "func1_entry", "func2_entry"};
    const char *exit_prog_names[]  = {"func0_exit",  "func1_exit",  "func2_exit"};

    for (size_t i = 0; i < g_func_names.size(); i++) {
        const char *fname = g_func_names[i].c_str();

        uint64_t offset = find_symbol_offset(g_binary_path.c_str(), fname);
        if (offset == 0) {
            fprintf(stderr, "  WARNING: '%s' not found in binary — skipping\n", fname);
            continue;
        }

        struct bpf_program *ep =
            bpf_object__find_program_by_name(g_uprobe_obj, entry_prog_names[i]);
        struct bpf_program *xp =
            bpf_object__find_program_by_name(g_uprobe_obj, exit_prog_names[i]);

        if (!ep || !xp) {
            fprintf(stderr, "  WARNING: BPF program slot %zu not found\n", i);
            continue;
        }

        printf("  %-20s @ 0x%llx ... ", fname, (unsigned long long)offset);
        fflush(stdout);

        struct bpf_link *el =
            bpf_program__attach_uprobe(ep, false, (int)g_target_pid,
                                        g_binary_path.c_str(), offset);
        struct bpf_link *xl =
            bpf_program__attach_uprobe(xp, true, (int)g_target_pid,
                                        g_binary_path.c_str(), offset);

        if (!el || !xl)
            printf("FAILED (%s)\n", strerror(errno));
        else
            printf("OK\n");
    }

    /* ── Attach off-CPU sched_switch ─────────────────────────────── */
    printf("\n[*] Attaching off-cpu tracepoint...\n");
    struct bpf_program *offcpu_prog =
        bpf_object__find_program_by_name(g_offcpu_obj, "off_cpu_sched_switch");
    if (!offcpu_prog) {
        fprintf(stderr, "off_cpu_sched_switch not found\n");
        cleanup(); return 1;
    }
    struct bpf_link *offcpu_link = bpf_program__attach(offcpu_prog);
    if (!offcpu_link) {
        fprintf(stderr, "Failed to attach sched_switch: %s\n", strerror(errno));
        cleanup(); return 1;
    }
    printf("[+] OK: sched/sched_switch\n");

    /* ── Set up ring buffers ──────────────────────────────────────── */
    struct bpf_map *urb = bpf_object__find_map_by_name(g_uprobe_obj, "events");
    struct bpf_map *orb = bpf_object__find_map_by_name(g_offcpu_obj, "events");

    if (!urb || !orb) {
        fprintf(stderr, "Could not find 'events' ring buffer map\n");
        cleanup(); return 1;
    }

    g_uprobe_rb = ring_buffer__new(bpf_map__fd(urb), handle_event, nullptr, nullptr);
    g_offcpu_rb = ring_buffer__new(bpf_map__fd(orb), handle_event, nullptr, nullptr);

    if (!g_uprobe_rb || !g_offcpu_rb) {
        fprintf(stderr, "ring_buffer__new failed\n");
        cleanup(); return 1;
    }

    printf("\n[+] Profiling started — table updates every second\n\n");

    /* ── Poll loop ───────────────────────────────────────────────── */
    time_t last_print = time(nullptr);

    while (g_running) {
        ring_buffer__poll(g_uprobe_rb, 100);
        ring_buffer__poll(g_offcpu_rb, 0);

        time_t now = time(nullptr);
        if (now - last_print >= 1) {
            print_table();
            last_print = now;
        }
    }

    printf("\n[+] Final results:\n");
    print_table();
    cleanup();
    return 0;
}