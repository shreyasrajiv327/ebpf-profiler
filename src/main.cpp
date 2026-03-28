/*
 * main.cpp - Phase 4: off-CPU reason classification
 *
 * Adds I/O wait, lock contention, and sleep detection
 * on top of Phase 3 (auto PID + dynamic unlimited functions)
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
    uint64_t total_io_ns      = 0;   /* time waiting for block I/O */
    uint64_t total_lock_ns    = 0;   /* time waiting for locks     */
    uint64_t total_sleep_ns   = 0;   /* time in sleep calls        */
    uint64_t call_count       = 0;
};
static std::unordered_map<uint32_t, FuncStats> g_stats;
static uint64_t g_off_cpu_events = 0;

/* Folded-stacks output file */
static std::ofstream g_folded_out;

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
        bool all_digits = true;
        for (const char *p = entry->d_name; *p; ++p)
            if (*p < '0' || *p > '9') { all_digits = false; break; }
        if (!all_digits) continue;

        uint32_t pid = (uint32_t)atoi(entry->d_name);
        if (pid == 0) continue;

        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%u/comm", pid);

        char comm[256] = {};
        FILE *f = fopen(comm_path, "r");
        if (!f) continue;
        if (fgets(comm, sizeof(comm), f)) {
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
 *  Ring buffer callback
 * ═════════════════════════════════════════════════════════════════════*/

static int handle_event(void *, void *data, size_t)
{
    const struct profiler_event *e =
        reinterpret_cast<const struct profiler_event *>(data);

    if (e->type == EVENT_FUNC_EXIT) {
        auto &s = g_stats[e->func_id];
        s.total_on_cpu_ns  += e->on_cpu_ns;
        s.total_off_cpu_ns += e->off_cpu_ns;
        s.total_wall_ns    += e->duration_ns;
        s.total_io_ns      += e->io_ns;
        s.total_lock_ns    += e->lock_ns;
        s.total_sleep_ns   += e->sleep_ns;
        s.call_count++;

        const std::string &fname =
            (e->func_id < g_func_names.size())
                ? g_func_names[e->func_id] : "unknown";

        printf("\n[FUNC EXIT] %s  pid=%u tid=%u\n"
               "  wall=%.3f ms  on_cpu=%.3f ms  off_cpu=%.3f ms\n"
               "  io=%.3f ms  lock=%.3f ms  sleep=%.3f ms\n",
               fname.c_str(), e->pid, e->tid,
               e->duration_ns / 1e6,
               e->on_cpu_ns   / 1e6,
               e->off_cpu_ns  / 1e6,
               e->io_ns       / 1e6,
               e->lock_ns     / 1e6,
               e->sleep_ns    / 1e6);

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
 *  Print stats table
 * ═════════════════════════════════════════════════════════════════════*/

static void print_table()
{
    printf("\033[2J\033[H");
    printf("eBPF Profiler — uprobe + off-cpu  |  pid=%u  bin=%s\n",
           g_target_pid, g_binary_path.c_str());
    printf("%s\n", std::string(110, '=').c_str());
    printf("%-24s %8s %12s %12s %11s %10s %10s %10s\n",
           "FUNCTION", "CALLS", "ON_CPU_MS", "OFF_CPU_MS",
           "WALL_MS", "IO_MS", "LOCK_MS", "SLEEP_MS");
    printf("%s\n", std::string(110, '-').c_str());

    for (size_t i = 0; i < g_func_names.size(); i++) {
        auto it = g_stats.find((uint32_t)i);
        if (it == g_stats.end()) {
            printf("%-24s %8s %12s %12s %11s %10s %10s %10s\n",
                   g_func_names[i].c_str(),
                   "0", "0.000", "0.000", "0.000", "0.000", "0.000", "0.000");
            continue;
        }
        const auto &s = it->second;
        printf("%-24s %8llu %12.3f %12.3f %11.3f %10.3f %10.3f %10.3f\n",
               g_func_names[i].c_str(),
               (unsigned long long)s.call_count,
               s.total_on_cpu_ns  / 1e6,
               s.total_off_cpu_ns / 1e6,
               s.total_wall_ns    / 1e6,
               s.total_io_ns      / 1e6,
               s.total_lock_ns    / 1e6,
               s.total_sleep_ns   / 1e6);
    }

    printf("%s\n", std::string(110, '-').c_str());
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
        return 1;
    }
    printf("[+] Binary  : %s\n", g_binary_path.c_str());

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

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    bump_memlock_rlimit();
    libbpf_set_print(libbpf_print);

    unlink("/sys/fs/bpf/profiler_off_cpu_data");

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

    struct bpf_map *shared_map = bpf_object__find_map_by_name(g_offcpu_obj, "off_cpu_data");
    if (!shared_map) { fprintf(stderr, "off_cpu_data map not found\n"); cleanup(); return 1; }
    if (bpf_map__pin(shared_map, "/sys/fs/bpf/profiler_off_cpu_data") != 0) {
        fprintf(stderr, "Failed to pin off_cpu_data: %s\n", strerror(errno));
        cleanup(); return 1;
    }
    printf("[+] Pinned off_cpu_data map\n");

    /* Load uprobe BPF object */
    printf("[*] Loading %s ...\n", uprobe_obj_path);
    g_uprobe_obj = bpf_object__open_file(uprobe_obj_path, nullptr);
    if (libbpf_get_error(g_uprobe_obj)) {
        fprintf(stderr, "Failed to open uprobe BPF object\n");
        cleanup(); return 1;
    }

    struct bpf_map *uprobe_shared = bpf_object__find_map_by_name(g_uprobe_obj, "off_cpu_data");
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

    /* Attach off-CPU tracepoint */
    printf("\n[*] Attaching off-cpu tracepoints...\n");

    /* sched_switch — main off-CPU detector */
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

    /* block I/O start */
    struct bpf_program *io_start_prog =
        bpf_object__find_program_by_name(g_offcpu_obj, "io_start");
    if (io_start_prog) {
        struct bpf_link *l = bpf_program__attach(io_start_prog);
        printf("[+] %s: block/block_rq_insert\n", l ? "OK" : "FAILED");
    }

    /* block I/O end */
    struct bpf_program *io_end_prog =
        bpf_object__find_program_by_name(g_offcpu_obj, "io_end");
    if (io_end_prog) {
        struct bpf_link *l = bpf_program__attach(io_end_prog);
        printf("[+] %s: block/block_rq_complete\n", l ? "OK" : "FAILED");
    }

    /* lock contention start */
    struct bpf_program *lock_start_prog =
        bpf_object__find_program_by_name(g_offcpu_obj, "lock_start");
    if (lock_start_prog) {
        struct bpf_link *l = bpf_program__attach(lock_start_prog);
        printf("[+] %s: lock/contention_begin\n", l ? "OK" : "FAILED");
    }

    /* lock contention end */
    struct bpf_program *lock_end_prog =
        bpf_object__find_program_by_name(g_offcpu_obj, "lock_end");
    if (lock_end_prog) {
        struct bpf_link *l = bpf_program__attach(lock_end_prog);
        printf("[+] %s: lock/contention_end\n", l ? "OK" : "FAILED");
    }

    /* sleep start */
    struct bpf_program *sleep_start_prog =
        bpf_object__find_program_by_name(g_offcpu_obj, "sleep_start");
    if (sleep_start_prog) {
        struct bpf_link *l = bpf_program__attach(sleep_start_prog);
        printf("[+] %s: syscalls/sys_enter_nanosleep\n", l ? "OK" : "FAILED");
    }

    /* sleep end */
    struct bpf_program *sleep_end_prog =
        bpf_object__find_program_by_name(g_offcpu_obj, "sleep_end");
    if (sleep_end_prog) {
        struct bpf_link *l = bpf_program__attach(sleep_end_prog);
        printf("[+] %s: syscalls/sys_exit_epoll_pwait\n", l ? "OK" : "FAILED");
    }

    /* Setup ring buffers */
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

    /* Main poll loop */
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