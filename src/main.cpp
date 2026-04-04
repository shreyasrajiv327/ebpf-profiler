/*
 * main.cpp - V2: Userspace derivation + metrics
 *
 * CHANGES:
 * - Integrated DerivationEngine
 * - Updated event handler to route events by type
 * - Removed old g_stats accumulation
 * - Handle both profiler_event and off_cpu_event
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
#include <time.h>

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
#include "types.hpp"
#include "derivation.hpp"

/* ═══════════════════════════════════════════════════════════════════════
 *  Globals
 * ═════════════════════════════════════════════════════════════════════*/

static volatile bool g_running = true;

static struct bpf_object  *g_uprobe_obj = nullptr;
static struct bpf_object  *g_offcpu_obj = nullptr;
static struct ring_buffer *g_uprobe_rb  = nullptr;
static struct ring_buffer *g_offcpu_rb  = nullptr;
static struct bpf_object *g_oncpu_obj = nullptr;
static struct ring_buffer *g_oncpu_rb = nullptr;

static std::vector<std::string> g_func_names;
static uint32_t  g_target_pid = 0;
static std::string g_binary_path;

/* V2: Derivation engine replaces g_stats */
static DerivationEngine *g_derivation = nullptr;

/* Folded-stacks output file */
static std::ofstream g_folded_out;

/* Statistics */
static uint64_t g_total_func_entries = 0;
static uint64_t g_total_func_exits = 0;
static uint64_t g_total_off_cpu_events = 0;
static uint64_t g_total_on_cpu_samples = 0;

static uint64_t g_profiler_start_ns = 0;

/* ═══════════════════════════════════════════════════════════════════════
 *  Signal handler
 * ═════════════════════════════════════════════════════════════════════*/

static void sig_handler(int) { g_running = false; }

/* ═══════════════════════════════════════════════════════════════════════
 *  Auto PID + binary resolution
 * ═════════════════════════════════════════════════════════════════════*/

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
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

        uint32_t pid = (uint32_t)atoi(entry->d_name);
        if (pid == 0) continue;

        // Read full command line (more reliable than /proc/<pid>/comm)
        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%u/cmdline", pid);

        FILE *f = fopen(cmdline_path, "r");
        if (!f) continue;

        char cmdline[512] = {};
        if (fread(cmdline, 1, sizeof(cmdline)-1, f) > 0) {
            // Replace null bytes with spaces for easier matching
            for (size_t i = 0; i < sizeof(cmdline); ++i) {
                if (cmdline[i] == '\0') cmdline[i] = ' ';
            }

            if (strstr(cmdline, target_name.c_str())) {
                found_pid = pid;
                fclose(f);
                break;   // take the first (usually the main server)
            }
        }
        fclose(f);
    }

    closedir(proc_dir);
    return found_pid;
}

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

static void resolve_user_stack(int32_t stack_id, const struct bpf_object *obj, char *buf, size_t bufsz)
{
    if (stack_id < 0) {
        snprintf(buf, bufsz, "[unknown]");
        return;
    }
    struct bpf_map *stack_map = bpf_object__find_map_by_name((struct bpf_object*)obj, "user_stacks");
    if (!stack_map) {
        snprintf(buf, bufsz, "[no-stack-map]");
        return;
    }
    __u64 ips[MAX_STACK_DEPTH] = {};
    if (bpf_map_lookup_elem(bpf_map__fd(stack_map), &stack_id, ips) != 0) {
        snprintf(buf, bufsz, "[lookup-failed]");
        return;
    }
    // For now we only show the top frame (most useful for quick debug)
    uint64_t top_ip = ips[0];
    // You already have func_id for uprobe events; for generic stacks we can improve later
    snprintf(buf, bufsz, "0x%llx", (unsigned long long)top_ip);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Get runtime load base from /proc/<pid>/maps
 * ═════════════════════════════════════════════════════════════════════*/

static uint64_t get_load_base(uint32_t pid, const std::string &binary_path)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open %s: %s\n", maps_path, strerror(errno));
        return 0;
    }

    uint64_t base = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, binary_path.c_str()) && strstr(line, "r-xp")) {
            sscanf(line, "%lx-", &base);
            break;
        }
    }
    fclose(f);
    return base;
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
 *  Derivation callback - receives derived metrics
 * ═════════════════════════════════════════════════════════════════════*/

static void on_derived_metrics(const DerivedFunctionMetrics& metrics)
{
    static uint64_t call_count = 0;
    call_count++;

    const std::string &fname =
        (metrics.func_id < g_func_names.size())
            ? g_func_names[metrics.func_id] : "unknown_func";

    printf("[DERIVED #%llu] %s  wall=%.3f ms (%.0f µs)  on=%.3f ms  off=%.3f ms  eff=%.1f%%  block=%.2fx\n"
           "                 io=%.3f  lock=%.3f  sleep=%.3f  sched=%.3f ms\n\n",
           (unsigned long long)call_count, fname.c_str(),
           metrics.wall_time_ns / 1e6,
           metrics.wall_time_ns / 1000.0,
           metrics.on_cpu_ns / 1e6,
           metrics.off_cpu_total_ns / 1e6,
           metrics.cpu_efficiency * 100.0,
           metrics.blocking_ratio,
           metrics.io_wait_ns / 1e6,
           metrics.lock_contention_ns / 1e6,
           metrics.sleep_ns / 1e6,
           metrics.scheduler_ns / 1e6);

    char stack_buf[64];
    resolve_user_stack(metrics.user_stack_id, g_uprobe_obj, stack_buf, sizeof(stack_buf));
    printf("... stack_top=%s\n", stack_buf);

    if (g_folded_out.is_open()) {
        g_folded_out << fname << " " << (metrics.wall_time_ns / 1000) << "\n";
        g_folded_out.flush();
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Ring buffer callback - V2: Route events to derivation engine
 * ═════════════════════════════════════════════════════════════════════*/

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    if (data_sz < 13) {
        fprintf(stderr, "Event too small: %zu bytes\n", data_sz);
        return 0;
    }

    const uint8_t* bytes = static_cast<const uint8_t*>(data);

    /* Try profiler_event first (type byte is always at offset 12) */
    uint8_t type_profiler = bytes[12];
    if (type_profiler == EVENT_FUNC_ENTRY ||
        type_profiler == EVENT_FUNC_EXIT ||
        type_profiler == EVENT_ON_CPU) {

        if (data_sz < sizeof(profiler_event)) {
            fprintf(stderr, "profiler_event truncated (%zu < %zu)\n", data_sz, sizeof(profiler_event));
            return 0;
        }

        const profiler_event *evt = reinterpret_cast<const profiler_event*>(data);
        switch (evt->type) {
        case EVENT_FUNC_ENTRY:
            g_total_func_entries++;
            g_derivation->process_function_entry(*evt);
            break;
        case EVENT_FUNC_EXIT:
            g_total_func_exits++;
            g_derivation->process_function_exit(*evt);
            break;
        case EVENT_ON_CPU:
            g_total_on_cpu_samples++;
            g_derivation->process_on_cpu_sample(*evt);
            break;
        }
        return 0;
    }

    /* Try off_cpu_event (type byte is at offset 24) */
    if (data_sz >= sizeof(off_cpu_event) && bytes[24] == EVENT_OFF_CPU) {
        const off_cpu_event *evt = reinterpret_cast<const off_cpu_event*>(data);
        g_total_off_cpu_events++;
        g_derivation->process_off_cpu_event(*evt);
        return 0;
    }

    /* Debug unknown events */
    uint32_t pid = *reinterpret_cast<const uint32_t*>(data);
    uint32_t tid = *reinterpret_cast<const uint32_t*>((char*)data + 4);
    fprintf(stderr, "Unknown event type: profiler_candidate=%u off_candidate=%u (pid=%u tid=%u data_sz=%zu)\n",
            type_profiler, (data_sz >= 25 ? bytes[24] : 0), pid, tid, data_sz);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Print stats table
 * ═══════════════════════════════════════════════════════════════════════*/

static void print_table()
{
    printf("\033[2J\033[H");
    printf("eBPF Profiler V2 — Userspace Derivation  |  pid=%u  bin=%s\n",
           g_target_pid, g_binary_path.c_str());
    printf("%s\n", std::string(90, '=').c_str());
    printf("Event Statistics:\n");
    printf("  Function entries : %llu\n", (unsigned long long)g_total_func_entries);
    printf("  Function exits   : %llu\n", (unsigned long long)g_total_func_exits);
    printf("  Off-CPU events   : %llu\n", (unsigned long long)g_total_off_cpu_events);
    printf("  On-CPU samples   : %llu\n", (unsigned long long)g_total_on_cpu_samples);
    printf("\n");
    printf("Derivation Engine:\n");
    printf("  Total processed  : %llu\n", 
           (unsigned long long)g_derivation->get_total_processed());
    printf("  Dropped (short)  : %llu\n", 
           (unsigned long long)g_derivation->get_dropped_short_calls());
    printf("  Errors           : %llu\n", 
           (unsigned long long)g_derivation->get_error_count());
    printf("%s\n", std::string(90, '-').c_str());
    printf("Press Ctrl-C to stop\n");

    /* Show profiler runtime */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    double runtime_sec = (now_ns - g_profiler_start_ns) / 1e9;

    printf("Profiler runtime: %.1f s\n", runtime_sec);
    fflush(stdout);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Cleanup
 * ═════════════════════════════════════════════════════════════════════*/

static void cleanup()
{
    if (g_derivation) {
        delete g_derivation;
        g_derivation = nullptr;
    }
    if (g_uprobe_rb)  ring_buffer__free(g_uprobe_rb);
    if (g_offcpu_rb)  ring_buffer__free(g_offcpu_rb);
    if (g_oncpu_rb) ring_buffer__free(g_oncpu_rb);
    if (g_oncpu_obj) bpf_object__close(g_oncpu_obj);
    if (g_uprobe_obj) bpf_object__close(g_uprobe_obj);
    if (g_offcpu_obj) bpf_object__close(g_offcpu_obj);
    if (g_folded_out.is_open()) g_folded_out.close();
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Usage
 * ═════════════════════════════════════════════════════════════════════*/

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <process_name> --funcs \"f1,f2,f3,...\"\n"
        "\n"
        "  <process_name>   Name of the already-running target process.\n"
        "  --funcs          Comma-separated list of functions to probe.\n"
        "\n"
        "Example:\n"
        "  sudo %s redis-server --funcs \"processCommand,lookupCommand,setCommand\"\n",
        prog, prog);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  libbpf print callback
 * ═════════════════════════════════════════════════════════════════════*/

static int libbpf_print(enum libbpf_print_level level,
                        const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, fmt, args);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  main
 * ═════════════════════════════════════════════════════════════════════*/

int main(int argc, char **argv)
{
    /* === START OF MAIN — initialize timing === */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    g_profiler_start_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    /* === END OF TIMING INIT === */

    if (argc < 2) { usage(argv[0]); return 1; }

    std::string process_name = argv[1];
    const char *funcs_str    = nullptr;

    const char *uprobe_obj_path = "./uprobe.bpf.o";
    const char *offcpu_obj_path = "./off_cpu.bpf.o";

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--funcs") && i+1 < argc) {
            funcs_str = argv[++i];
        } else if (!strcmp(argv[i], "--uprobe-obj") && i+1 < argc) {
            uprobe_obj_path = argv[++i];
        } else if (!strcmp(argv[i], "--offcpu-obj") && i+1 < argc) {
            offcpu_obj_path = argv[++i];
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

    printf("[*] Searching /proc for process '%s'...\n", process_name.c_str());
    g_target_pid = find_pid_by_name(process_name);
    if (g_target_pid == 0) {
        fprintf(stderr, "Error: process '%s' not found in /proc.\n", process_name.c_str());
        return 1;
    }
    printf("[+] Found PID: %u\n", g_target_pid);

    g_binary_path = resolve_binary_path(g_target_pid);
    if (g_binary_path.empty()) {
        fprintf(stderr, "Error: could not resolve binary path for PID %u\n", g_target_pid);
        cleanup(); return 1;
    }
    printf("[+] Binary : %s\n", g_binary_path.c_str());

    /* Quick sanity check - Redis often shows as redis-server or redis-check-rdb */
    std::string basename = g_binary_path.substr(g_binary_path.find_last_of('/') + 1);
    if (basename != process_name && basename != "redis-server") {
        printf("[!] Warning: resolved binary is '%s' (expected something with '%s')\n",
            basename.c_str(), process_name.c_str());
    }

    /* Parse function list */
    {
        std::stringstream ss(funcs_str);
        std::string token;
        while (std::getline(ss, token, ',')) {
            if (token.empty()) continue;
            g_func_names.push_back(token);
        }
    }

    if (g_func_names.empty()) {
        fprintf(stderr, "Error: no functions specified\n");
        return 1;
    }

    printf("[+] Functions to probe: %zu\n", g_func_names.size());
    for (auto &f : g_func_names) printf("      - %s\n", f.c_str());
    printf("\n");

    g_folded_out.open("stacks.folded", std::ios::app);
    if (g_folded_out.is_open()) printf("[+] Folded stacks → stacks.folded\n\n");

    /* V2: Initialize derivation engine */
    printf("[*] Initializing derivation engine...\n");
    g_derivation = new DerivationEngine(on_derived_metrics);
    g_derivation->set_min_duration_ns(0);     // Keep this
    g_derivation->set_min_off_cpu_ns(500);
    printf("[+] Derivation engine ready\n\n");

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    bump_memlock_rlimit();
    libbpf_set_print(libbpf_print);

    /* Load off_cpu BPF object */
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

    /* === Load on_cpu BPF object === */
    printf("[*] Loading on_cpu.bpf.o ...\n");
    const char *oncpu_obj_path = "./on_cpu.bpf.o";
    g_oncpu_obj = bpf_object__open_file(oncpu_obj_path, nullptr);
    if (libbpf_get_error(g_oncpu_obj)) {
        fprintf(stderr, "Failed to open on_cpu BPF object\n");
        cleanup(); return 1;
    }
    if (bpf_object__load(g_oncpu_obj) != 0) {
        fprintf(stderr, "Failed to load on_cpu BPF object: %s\n", strerror(errno));
        cleanup(); return 1;
    }
    printf("[+] Loaded on_cpu.bpf.o OK\n");

    if (set_target_pid(g_oncpu_obj, g_target_pid) != 0) {
        cleanup(); return 1;
    }

    /* Load uprobe BPF object */
    printf("[*] Loading %s ...\n", uprobe_obj_path);
    g_uprobe_obj = bpf_object__open_file(uprobe_obj_path, nullptr);
    if (libbpf_get_error(g_uprobe_obj)) {
        fprintf(stderr, "Failed to open uprobe BPF object\n");
        cleanup(); return 1;
    }

    if (bpf_object__load(g_uprobe_obj) != 0) {
        fprintf(stderr, "Failed to load uprobe BPF object: %s\n", strerror(errno));
        cleanup(); return 1;
    }
    printf("[+] Loaded OK\n");

    if (set_target_pid(g_uprobe_obj, g_target_pid) != 0) { cleanup(); return 1; }
    if (set_target_pid(g_offcpu_obj, g_target_pid) != 0) { cleanup(); return 1; }

    /* Resolve PIE load base */
    uint64_t load_base = get_load_base(g_target_pid, g_binary_path);
    if (load_base == 0) {
        fprintf(stderr, "ERROR: could not determine binary load base for PID %u\n",
                g_target_pid);
        cleanup(); return 1;
    }
    printf("[+] Binary load base : 0x%llx\n\n", (unsigned long long)load_base);

    /* Attach uprobes with metadata map */
    printf("[*] Attaching uprobes...\n");

    struct bpf_program *generic_entry =
        bpf_object__find_program_by_name(g_uprobe_obj, "generic_entry");
    struct bpf_program *generic_exit =
        bpf_object__find_program_by_name(g_uprobe_obj, "generic_exit");

    if (!generic_entry || !generic_exit) {
        fprintf(stderr, "ERROR: generic_entry/generic_exit not found.\n");
        cleanup(); return 1;
    }

    struct bpf_map *metadata_map = bpf_object__find_map_by_name(g_uprobe_obj, "uprobe_metadata");
    if (!metadata_map) {
        fprintf(stderr, "ERROR: uprobe_metadata map not found.\n");
        cleanup(); return 1;
    }
    int metadata_fd = bpf_map__fd(metadata_map);

    for (size_t i = 0; i < g_func_names.size(); i++) {
        const char *fname = g_func_names[i].c_str();

        uint64_t offset = find_symbol_offset(g_binary_path.c_str(), fname);
        if (offset == 0) {
            fprintf(stderr, "  WARNING: '%s' not found in binary — skipping\n", fname);
            continue;
        }

        printf("  %-32s @ offset=0x%llx  runtime=0x%llx ... ",
               fname,
               (unsigned long long)offset,
               (unsigned long long)(load_base + offset));
        fflush(stdout);

        uint64_t runtime_addr = load_base + offset;
        uint32_t func_id = (uint32_t)i;
        if (bpf_map_update_elem(metadata_fd, &runtime_addr, &func_id, BPF_ANY) != 0) {
            printf("FAILED (metadata: %s)\n", strerror(errno));
            continue;
        }

        struct bpf_link *el = bpf_program__attach_uprobe(generic_entry, false,
                                             (int)g_target_pid,
                                             g_binary_path.c_str(), offset);
        struct bpf_link *xl = bpf_program__attach_uprobe(generic_exit, true,
                                             (int)g_target_pid,
                                             g_binary_path.c_str(), offset);

        if (!el || !xl)
            printf("FAILED (attach: %s)\n", strerror(errno));
        else
            printf("OK\n");
    }

    /* Attach off-CPU tracepoints */
    printf("\n[*] Attaching off-cpu tracepoints...\n");

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

    struct bpf_program *io_start_prog =
        bpf_object__find_program_by_name(g_offcpu_obj, "io_start");
    if (io_start_prog) {
        struct bpf_link *l = bpf_program__attach(io_start_prog);
        printf("[+] %s: block/block_rq_insert\n", l ? "OK" : "FAILED");
    }

    struct bpf_program *io_end_prog =
        bpf_object__find_program_by_name(g_offcpu_obj, "io_end");
    if (io_end_prog) {
        struct bpf_link *l = bpf_program__attach(io_end_prog);
        printf("[+] %s: block/block_rq_complete\n", l ? "OK" : "FAILED");
    }

    struct bpf_program *lock_start_prog =
        bpf_object__find_program_by_name(g_offcpu_obj, "lock_start");
    if (lock_start_prog) {
        struct bpf_link *l = bpf_program__attach(lock_start_prog);
        printf("[+] %s: lock/contention_begin\n", l ? "OK" : "FAILED");
    }

    struct bpf_program *lock_end_prog =
        bpf_object__find_program_by_name(g_offcpu_obj, "lock_end");
    if (lock_end_prog) {
        struct bpf_link *l = bpf_program__attach(lock_end_prog);
        printf("[+] %s: lock/contention_end\n", l ? "OK" : "FAILED");
    }

    struct bpf_program *sleep_start_prog =
        bpf_object__find_program_by_name(g_offcpu_obj, "sleep_start");
    if (sleep_start_prog) {
        struct bpf_link *l = bpf_program__attach(sleep_start_prog);
        printf("[+] %s: syscalls/sys_enter_epoll_pwait\n", l ? "OK" : "FAILED");
    }

    struct bpf_program *sleep_end_prog =
        bpf_object__find_program_by_name(g_offcpu_obj, "sleep_end");
    if (sleep_end_prog) {
        struct bpf_link *l = bpf_program__attach(sleep_end_prog);
        printf("[+] %s: syscalls/sys_exit_epoll_pwait\n", l ? "OK" : "FAILED");
    }

    /* === Attach on-CPU profiler (perf_event sampling) === */
    printf("\n[*] Attaching on-CPU profiler (perf_event sampling ~500Hz)...\n");
    struct bpf_program *oncpu_prog =
        bpf_object__find_program_by_name(g_oncpu_obj, "on_cpu_sample");
    if (!oncpu_prog) {
        fprintf(stderr, "on_cpu_sample program not found\n");
        cleanup(); return 1;
    }

    int nr_cpus = libbpf_num_possible_cpus();
    struct bpf_link *oncpu_links[128] = {nullptr};
    bool attached = false;

    struct perf_event_attr pea = {};
    pea.type          = PERF_TYPE_SOFTWARE;
    pea.config        = PERF_COUNT_SW_CPU_CLOCK;
    pea.sample_period = 2000000ULL;     // ~500 Hz)
    pea.wakeup_events = 1;

    for (int cpu = 0; cpu < nr_cpus && cpu < 128; cpu++) {
        int pfd = syscall(__NR_perf_event_open, &pea, g_target_pid, cpu, -1, 0);
        if (pfd < 0) continue;

        struct bpf_link *link = bpf_program__attach_perf_event(oncpu_prog, pfd);
        if (link) {
            oncpu_links[cpu] = link;
            attached = true;
        } else {
            close(pfd);
        }
    }

    if (!attached) {
        fprintf(stderr, "Failed to attach on-CPU sampling on any CPU\n");
        cleanup(); return 1;
    }
    printf("[+] OK: on-CPU sampling attached (~500 Hz on %d CPUs)\n", nr_cpus);

    /* Setup ring buffers */
    struct bpf_map *urb = bpf_object__find_map_by_name(g_uprobe_obj, "events");
    struct bpf_map *orb = bpf_object__find_map_by_name(g_offcpu_obj, "events");
    struct bpf_map *onrb = bpf_object__find_map_by_name(g_oncpu_obj, "rb"); 

    if (!urb || !orb || !onrb) {
        fprintf(stderr, "Could not find ring buffer maps\n");
        cleanup(); return 1;
    }

    g_uprobe_rb = ring_buffer__new(bpf_map__fd(urb), handle_event, nullptr, nullptr);
    g_offcpu_rb = ring_buffer__new(bpf_map__fd(orb), handle_event, nullptr, nullptr);
    g_oncpu_rb  = ring_buffer__new(bpf_map__fd(onrb), handle_event, nullptr, nullptr);

    if (!g_uprobe_rb || !g_offcpu_rb || !g_oncpu_rb) {
        fprintf(stderr, "ring_buffer__new failed for one of the rings\n");
        cleanup(); return 1;
    }
    printf("[+] All ring buffers ready\n");

    printf("\n[+] Profiling started — table updates every second\n\n");

    /* Main poll loop */
    time_t last_print = time(nullptr);
    while (g_running) {
        ring_buffer__poll(g_uprobe_rb, 100);
        ring_buffer__poll(g_offcpu_rb, 0);
        ring_buffer__poll(g_oncpu_rb, 0);

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