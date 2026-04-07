/*
 * main.cpp - V2: Userspace derivation + metrics + flamegraph support
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
#include <dlfcn.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>

#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

/* httplib (single header) */
#include "httplib.h"

/* JSON */
#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <gelf.h>
#include <libelf.h>

#include "profiler_common.h"
#include "types.hpp"
#include "derivation.hpp"
#include "stack_resolver.hpp"

/* ═══════════════════════════════════════════════════════════════════════
 *  Globals
 * ═══════════════════════════════════════════════════════════════════════*/

static std::atomic<bool> g_running{true};
static std::atomic<bool> g_web_server_ready{false};
static std::atomic<bool> g_paused{false};

static struct bpf_object  *g_uprobe_obj = nullptr;
static struct bpf_object  *g_offcpu_obj = nullptr;
static struct bpf_object *g_oncpu_obj = nullptr;
static struct ring_buffer *g_uprobe_rb = nullptr;
static struct ring_buffer *g_offcpu_rb = nullptr;
static struct ring_buffer *g_oncpu_rb = nullptr;

static std::vector<std::string> g_func_names;
static uint32_t g_target_pid = 0;
static std::string g_binary_path;

static DerivationEngine *g_derivation = nullptr;
static StackResolver *g_stack_resolver = nullptr;

static std::ofstream g_oncpu_folded;
static std::ofstream g_offcpu_folded;

static std::atomic<uint64_t> g_total_func_entries{0};
static std::atomic<uint64_t> g_total_func_exits{0};
static std::atomic<uint64_t> g_total_off_cpu_events{0};
static std::atomic<uint64_t> g_total_on_cpu_samples{0};

static uint64_t g_profiler_start_ns = 0;

/* Web server */
static httplib::Server svr;
static std::thread web_thread;
static std::mutex data_mutex;
static json live_data = json::object();

/* ═══════════════════════════════════════════════════════════════════════
 *  Signal handler
 * ═══════════════════════════════════════════════════════════════════════*/

static void sig_handler(int) { g_running = false; }

/* ═══════════════════════════════════════════════════════════════════════
 *  PID and binary resolution (your original code)
 * ═══════════════════════════════════════════════════════════════════════*/

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

        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%u/cmdline", pid);

        FILE *f = fopen(cmdline_path, "r");
        if (!f) continue;

        char cmdline[512] = {};
        if (fread(cmdline, 1, sizeof(cmdline)-1, f) > 0) {
            for (size_t i = 0; i < sizeof(cmdline); ++i) {
                if (cmdline[i] == '\0') cmdline[i] = ' ';
            }
            if (strstr(cmdline, target_name.c_str())) {
                found_pid = pid;
                fclose(f);
                break;
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
    if (n <= 0) return {};
    resolved[n] = '\0';
    return std::string(resolved);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Get runtime load base
 * ═══════════════════════════════════════════════════════════════════════*/

static uint64_t get_load_base(uint32_t pid, const std::string &binary_path)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;

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
 *  Helpers (your original code)
 * ═══════════════════════════════════════════════════════════════════════*/

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

static uint64_t find_symbol_offset(const char *binary, const char *sym_name)
{
    if (elf_version(EV_CURRENT) == EV_NONE) return 0;

    int fd = open(binary, O_RDONLY);
    if (fd < 0) return 0;

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
            if (name && strcmp(name, sym_name) == 0) {
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
 *  Derivation callback - generates folded stacks for flamegraphs
 * ═══════════════════════════════════════════════════════════════════════*/

static void on_derived_metrics(const DerivedFunctionMetrics& metrics)
{
    static uint64_t call_count = 0;
    call_count++;
 
    const std::string& fname =
        (metrics.func_id < g_func_names.size())
            ? g_func_names[metrics.func_id] : "unknown_func";
 
    printf("[DERIVED #%llu] %s  wall=%.3f on=%.3f off=%.3f eff=%.1f%%\n",
           (unsigned long long)call_count, fname.c_str(),
           metrics.wall_time_ns / 1e6,
           metrics.on_cpu_ns    / 1e6,
           metrics.off_cpu_total_ns / 1e6,
           metrics.cpu_efficiency * 100.0);
 
    // ── Build folded stack ──────────────────────────────────────────
    // g_stack_resolver uses the user_stacks map from uprobe.bpf.o.
    // Falls back to "root;fname" when stack_id < 0 or resolver is null.
    std::string folded_stack;
    if (g_stack_resolver && metrics.user_stack_id >= 0)
        folded_stack = g_stack_resolver->folded(metrics.user_stack_id, fname);
    else
        folded_stack = "root;" + fname;
 
    // ── Write to folded files ───────────────────────────────────────
    // On-CPU file: weighted by on_cpu time
    // Off-CPU file: weighted by off_cpu time
    // Both in microseconds (standard flamegraph weight unit)
    uint64_t oncpu_us  = metrics.on_cpu_ns  / 1000;
    uint64_t offcpu_us = metrics.off_cpu_total_ns / 1000;
 
    static uint64_t write_count = 0;
    write_count++;

    if (g_oncpu_folded.is_open() && oncpu_us > 0) {
        g_oncpu_folded << folded_stack << ' ' << oncpu_us << '\n';
    }

    if (g_offcpu_folded.is_open() && offcpu_us > 0) {
        g_offcpu_folded << folded_stack << ' ' << offcpu_us << '\n';
    }

    /* Flush every N events */
    if (write_count % 1000 == 0) {
        if (g_oncpu_folded.is_open())  g_oncpu_folded.flush();
        if (g_offcpu_folded.is_open()) g_offcpu_folded.flush();
    }
 
    // ── Update live JSON for Web UI ─────────────────────────────────
    {
        std::lock_guard<std::mutex> lock(data_mutex);
 
        if (!live_data.contains("functions") || !live_data["functions"].is_object())
            live_data["functions"] = json::object();
 
        json& fn = live_data["functions"][fname];
        if (fn.is_null() || !fn.is_object()) fn = json::object();
 
        fn["calls"]  = fn.value("calls", 0) + 1;
        fn["wall"]   = metrics.wall_time_ns / 1e6;
        fn["oncpu"]  = metrics.on_cpu_ns / 1e6;
        fn["offcpu"] = metrics.off_cpu_total_ns / 1e6;
        fn["io"]     = metrics.io_wait_ns / 1e6;
        fn["lock"]   = metrics.lock_contention_ns / 1e6;
        fn["sleep"]  = metrics.sleep_ns / 1e6;
        fn["sched"]  = metrics.scheduler_ns / 1e6;
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Ring buffer callback - V2: Route events to derivation engine
 * ═════════════════════════════════════════════════════════════════════*/

static int handle_uprobe_event(void * /*ctx*/, void *data, size_t data_sz)
{
    if (data_sz < sizeof(profiler_event)) {
        fprintf(stderr, "[uprobe] event too small: %zu\n", data_sz);
        return 0;
    }
    const profiler_event *evt = static_cast<const profiler_event*>(data);
    switch (evt->type) {
    case EVENT_FUNC_ENTRY:
        g_total_func_entries++;
        g_derivation->process_function_entry(*evt);
        break;
    case EVENT_FUNC_EXIT:
        g_total_func_exits++;
        g_derivation->process_function_exit(*evt);
        break;
    default:
        fprintf(stderr, "[uprobe] unexpected type=%u\n", evt->type);
    }
    return 0;
}

static int handle_offcpu_event(void * /*ctx*/, void *data, size_t data_sz)
{
    if (data_sz < sizeof(off_cpu_event)) {
        fprintf(stderr, "[offcpu] event too small: %zu\n", data_sz);
        return 0;
    }
    const off_cpu_event *evt = static_cast<const off_cpu_event*>(data);
    if (evt->type != EVENT_OFF_CPU) {
        fprintf(stderr, "[offcpu] unexpected type=%u\n", evt->type);
        return 0;
    }
    g_total_off_cpu_events++;
    g_derivation->process_off_cpu_event(*evt);
    return 0;
}

static int handle_oncpu_event(void * /*ctx*/, void *data, size_t data_sz)
{
    if (data_sz < sizeof(profiler_event)) {
        fprintf(stderr, "[oncpu] event too small: %zu\n", data_sz);
        return 0;
    }
    const profiler_event *evt = static_cast<const profiler_event*>(data);
    if (evt->type == EVENT_ON_CPU) {
        g_total_on_cpu_samples++;
        g_derivation->process_on_cpu_sample(*evt);
    }
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
    printf("  Total processed  : %llu\n", (unsigned long long)g_derivation->get_total_processed());
    printf("  Dropped (short)  : %llu\n", (unsigned long long)g_derivation->get_dropped_short_calls());
    printf("  Errors           : %llu\n", (unsigned long long)g_derivation->get_error_count());
    printf("%s\n", std::string(90, '-').c_str());
    printf("Press Ctrl-C to stop\n");
    printf("Pause status     : %s\n", g_paused ? "PAUSED" : "RUNNING");

    /* Show profiler runtime */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    printf("  Runtime       : %.1f s\n", (now_ns - g_profiler_start_ns) / 1e9);
    printf("  Paused        : %s\n", g_paused.load() ? "YES" : "no");
    printf("%s\n", std::string(90, '-').c_str());
    fflush(stdout);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Cleanup
 * ═════════════════════════════════════════════════════════════════════*/

static void cleanup()
{
    printf("\n[*] Shutting down...\n");

    if (g_web_server_ready) {
        svr.stop();
        // Tiny wait so httplib can clean up the socket cleanly
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    if (g_derivation) {
        delete g_derivation;
        g_derivation = nullptr;
    }

    if (g_uprobe_rb)  ring_buffer__free(g_uprobe_rb);
    if (g_offcpu_rb)  ring_buffer__free(g_offcpu_rb);
    if (g_oncpu_rb)   ring_buffer__free(g_oncpu_rb);

    if (g_oncpu_obj)  bpf_object__close(g_oncpu_obj);
    if (g_uprobe_obj) bpf_object__close(g_uprobe_obj);
    if (g_offcpu_obj) bpf_object__close(g_offcpu_obj);

    if (g_oncpu_folded.is_open())  { g_oncpu_folded.flush();  g_oncpu_folded.close();  }
    if (g_offcpu_folded.is_open()) { g_offcpu_folded.flush(); g_offcpu_folded.close(); }

    if (g_stack_resolver) { delete g_stack_resolver; g_stack_resolver = nullptr; }

    if (web_thread.joinable()) {
        web_thread.join();
        printf("[+] Web server thread stopped\n");
    }

    printf("[+] Cleanup complete.\n");
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
 *  Attach helper — logs result, never fatal
 * ═══════════════════════════════════════════════════════════════════════*/

static void attach_prog(struct bpf_object *obj, const char *prog_name,
                        const char *label)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        printf("  [SKIP] %-30s (program not found)\n", label);
        return;
    }
    struct bpf_link *link = bpf_program__attach(prog);
    printf("  [%s] %s\n", link ? " OK " : "FAIL", label);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  main
 * ═════════════════════════════════════════════════════════════════════*/

int main(int argc, char **argv)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    g_profiler_start_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    if (argc < 2) { usage(argv[0]); return 1; }

    std::string process_name = argv[1];
    const char *funcs_str       = nullptr;
    const char *uprobe_obj_path = "./uprobe.bpf.o";
    const char *offcpu_obj_path = "./off_cpu.bpf.o";
    const char *oncpu_obj_path  = "./on_cpu.bpf.o";

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--funcs")       && i+1 < argc) funcs_str       = argv[++i];
        else if (!strcmp(argv[i], "--uprobe-obj") && i+1 < argc) uprobe_obj_path = argv[++i];
        else if (!strcmp(argv[i], "--offcpu-obj") && i+1 < argc) offcpu_obj_path = argv[++i];
        else if (!strcmp(argv[i], "--oncpu-obj")  && i+1 < argc) oncpu_obj_path  = argv[++i];
    }

    if (!funcs_str) { fprintf(stderr, "--funcs required\n"); usage(argv[0]); return 1; }
    if (geteuid() != 0) { fprintf(stderr, "Must run as root\n"); return 1; }

    printf("[*] Looking for '%s'...\n", process_name.c_str());
    g_target_pid = find_pid_by_name(process_name);
    if (!g_target_pid) {
        fprintf(stderr, "Process '%s' not found\n", process_name.c_str());
        return 1;
    }
    printf("[+] PID: %u\n", g_target_pid);

    g_binary_path = resolve_binary_path(g_target_pid);
    if (g_binary_path.empty()) {
        fprintf(stderr, "Cannot resolve binary for PID %u\n", g_target_pid);
        return 1;
    }
    printf("[+] Binary: %s\n", g_binary_path.c_str());

    /* Parse function list */
    {
        std::stringstream ss(funcs_str);
        std::string tok;
        while (std::getline(ss, tok, ','))
            if (!tok.empty()) g_func_names.push_back(tok);
    }
    if (g_func_names.empty()) { fprintf(stderr, "No functions specified\n"); return 1; }
    printf("[+] Functions: %zu\n", g_func_names.size());
    for (auto &f : g_func_names) printf("    - %s\n", f.c_str());

    /* Open folded stack files */
    g_oncpu_folded.open("../www/on_cpu.folded",   std::ios::out | std::ios::app);
    g_offcpu_folded.open("../www/off_cpu.folded", std::ios::out | std::ios::app);

    /* Init derivation engine */
    g_derivation = new DerivationEngine(on_derived_metrics);
    g_derivation->set_min_duration_ns(0);
    g_derivation->set_min_off_cpu_ns(500);

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    bump_memlock_rlimit();
    libbpf_set_print(libbpf_print);

    /* ── Load BPF objects ── */
    auto load_obj = [](const char *path, struct bpf_object **out) -> bool {
        *out = bpf_object__open_file(path, nullptr);
        if (libbpf_get_error(*out)) {
            fprintf(stderr, "Failed to open %s\n", path); return false;
        }
        if (bpf_object__load(*out) != 0) {
            fprintf(stderr, "Failed to load %s: %s\n", path, strerror(errno)); return false;
        }
        printf("[+] Loaded %s\n", path);
        return true;
    };

    if (!load_obj(offcpu_obj_path, &g_offcpu_obj)) { cleanup(); return 1; }
    if (!load_obj(oncpu_obj_path,  &g_oncpu_obj))  { cleanup(); return 1; }
    if (!load_obj(uprobe_obj_path, &g_uprobe_obj)) { cleanup(); return 1; }

    if (set_target_pid(g_offcpu_obj, g_target_pid) != 0) { cleanup(); return 1; }
    if (set_target_pid(g_oncpu_obj,  g_target_pid) != 0) { cleanup(); return 1; }
    if (set_target_pid(g_uprobe_obj, g_target_pid) != 0) { cleanup(); return 1; }

    /* ── Resolve load base ── */
    uint64_t load_base = get_load_base(g_target_pid, g_binary_path);
    if (!load_base) {
        fprintf(stderr, "Cannot determine load base for PID %u\n", g_target_pid);
        cleanup(); return 1;
    }
    printf("[+] Load base: 0x%llx\n", (unsigned long long)load_base);

    /* ── Attach uprobes ── */
    printf("\n[*] Attaching uprobes...\n");
    struct bpf_program *generic_entry =
        bpf_object__find_program_by_name(g_uprobe_obj, "generic_entry");
    struct bpf_program *generic_exit  =
        bpf_object__find_program_by_name(g_uprobe_obj, "generic_exit");

    if (!generic_entry || !generic_exit) {
        fprintf(stderr, "generic_entry/generic_exit not found\n");
        cleanup(); return 1;
    }

    struct bpf_map *metadata_map =
        bpf_object__find_map_by_name(g_uprobe_obj, "uprobe_metadata");
    if (!metadata_map) { fprintf(stderr, "uprobe_metadata not found\n"); cleanup(); return 1; }
    int metadata_fd = bpf_map__fd(metadata_map);

    for (size_t i = 0; i < g_func_names.size(); i++) {
        const char *fname  = g_func_names[i].c_str();
        uint64_t    offset = find_symbol_offset(g_binary_path.c_str(), fname);
        if (!offset) {
            fprintf(stderr, "  WARNING: '%s' not found in binary\n", fname);
            continue;
        }

        uint64_t runtime_addr = load_base + offset;
        uint32_t func_id      = (uint32_t)i;
        bpf_map_update_elem(metadata_fd, &runtime_addr, &func_id, BPF_ANY);

        struct bpf_link *el = bpf_program__attach_uprobe(
            generic_entry, false, (int)g_target_pid, g_binary_path.c_str(), offset);
        struct bpf_link *xl = bpf_program__attach_uprobe(
            generic_exit,  true,  (int)g_target_pid, g_binary_path.c_str(), offset);

        printf("  [%s] %s @ 0x%llx\n",
               (el && xl) ? " OK " : "FAIL", fname, (unsigned long long)offset);
    }

    /* ── Attach off-CPU probes ── */
    printf("\n[*] Attaching off-CPU probes...\n");

    /* Core scheduler probe — must succeed */
    struct bpf_program *sw =
        bpf_object__find_program_by_name(g_offcpu_obj, "off_cpu_sched_switch");
    if (!sw) { fprintf(stderr, "off_cpu_sched_switch not found\n"); cleanup(); return 1; }
    if (!bpf_program__attach(sw)) {
        fprintf(stderr, "Failed to attach sched_switch: %s\n", strerror(errno));
        cleanup(); return 1;
    }
    printf("  [ OK ] sched/sched_switch\n");

    /* Syscall probes — best effort, log result */
    attach_prog(g_offcpu_obj, "futex_start",    "syscalls/sys_enter_futex");
    attach_prog(g_offcpu_obj, "futex_end",      "syscalls/sys_exit_futex");
    attach_prog(g_offcpu_obj, "nanosleep_start","syscalls/sys_enter_nanosleep");
    attach_prog(g_offcpu_obj, "nanosleep_end",  "syscalls/sys_exit_nanosleep");
    attach_prog(g_offcpu_obj, "epoll_start",    "syscalls/sys_enter_epoll_pwait");
    attach_prog(g_offcpu_obj, "epoll_end",      "syscalls/sys_exit_epoll_pwait");
    attach_prog(g_offcpu_obj, "read_start",     "syscalls/sys_enter_read");
    attach_prog(g_offcpu_obj, "read_end",       "syscalls/sys_exit_read");
    attach_prog(g_offcpu_obj, "write_start",    "syscalls/sys_enter_write");
    attach_prog(g_offcpu_obj, "write_end",      "syscalls/sys_exit_write");

    /* Block-level I/O probes removed — covered by read/write syscall probes */

    /* ── Attach on-CPU perf sampling ── */
    printf("\n[*] Attaching on-CPU sampler...\n");
    struct bpf_program *oncpu_prog =
        bpf_object__find_program_by_name(g_oncpu_obj, "on_cpu_sample");
    if (!oncpu_prog) { fprintf(stderr, "on_cpu_sample not found\n"); cleanup(); return 1; }

    int nr_cpus = libbpf_num_possible_cpus();
    bool oncpu_attached = false;

    struct perf_event_attr pea = {};
    pea.type          = PERF_TYPE_SOFTWARE;
    pea.config        = PERF_COUNT_SW_TASK_CLOCK;   // ← CHANGED (better for per-process)
    pea.sample_period = 500000ULL;                  // ← CHANGED (~2000 Hz)
    pea.wakeup_events = 1;

    for (int cpu = 0; cpu < nr_cpus && cpu < 128; cpu++) {
        int pfd = syscall(__NR_perf_event_open, &pea, (pid_t)g_target_pid, cpu, -1, 0);
        if (pfd < 0) {
            // printf("  [skip] perf_event_open on CPU %d failed: %s\n", cpu, strerror(errno));
            continue;
        }
        struct bpf_link *link = bpf_program__attach_perf_event(oncpu_prog, pfd);
        if (link) {
            oncpu_attached = true;
            // printf("  [ OK ] on-CPU sampling on CPU %d\n", cpu);
        } else {
            close(pfd);
            // printf("  [FAIL] attach on CPU %d: %s\n", cpu, strerror(errno));
        }
    }

    if (!oncpu_attached) {
        fprintf(stderr, "WARNING: Failed to attach on-CPU sampler on any CPU\n");
        fprintf(stderr, "         On-CPU Samples will stay at 0 (but derivation still works)\n");
    } else {
        printf("  [ OK ] on-CPU sampling (~2000 Hz, %d CPUs)\n", nr_cpus);
    }


    /* ── Ring buffers — BUG FIX #5: separate callbacks ── */
    struct bpf_map *urb  = bpf_object__find_map_by_name(g_uprobe_obj, "events");
    struct bpf_map *orb  = bpf_object__find_map_by_name(g_offcpu_obj, "events");
    struct bpf_map *onrb = bpf_object__find_map_by_name(g_oncpu_obj,  "rb");

    if (!urb || !orb || !onrb) {
        fprintf(stderr, "Ring buffer map not found\n");
        cleanup(); return 1;
    }

    g_uprobe_rb = ring_buffer__new(bpf_map__fd(urb),  handle_uprobe_event,  nullptr, nullptr);
    g_offcpu_rb = ring_buffer__new(bpf_map__fd(orb),  handle_offcpu_event,  nullptr, nullptr);
    g_oncpu_rb  = ring_buffer__new(bpf_map__fd(onrb), handle_oncpu_event,   nullptr, nullptr);

    if (!g_uprobe_rb || !g_offcpu_rb || !g_oncpu_rb) {
        fprintf(stderr, "ring_buffer__new failed\n");
        cleanup(); return 1;
    }
    printf("[+] All ring buffers ready\n");

    {
        struct bpf_map *stack_map =
            bpf_object__find_map_by_name(g_uprobe_obj, "user_stacks");
 
        if (stack_map) {
            int fd = bpf_map__fd(stack_map);
            g_stack_resolver = new StackResolver(fd, g_target_pid);
            printf("[+] Stack resolver ready (fd=%d) — real folded stacks enabled\n", fd);
        } else {
            // Should not happen given the uprobe.bpf.c we have, but be safe
            fprintf(stderr, "[!] user_stacks map not found in uprobe object\n");
            fprintf(stderr, "    Folded output will be depth-2 (root;func) only\n");
        }
    }

    printf("\n[+] Profiling started — table updates every second\n\n");

    /* Start Web UI with pause/resume control */
    web_thread = std::thread([]() {

        svr.Get("/data", [](const httplib::Request&, httplib::Response& res) {
            std::lock_guard<std::mutex> lock(data_mutex);
            res.set_content(live_data.dump(), "application/json");
        });

        svr.set_mount_point("/", "../www");

        // NEW: Control endpoint for Pause/Resume
        svr.Post("/control", [](const httplib::Request& req, httplib::Response& res) {
            auto body = json::parse(req.body);
            std::string cmd = body.value("command", "");
            if (cmd == "pause") {
                g_paused = true;
                res.set_content(R"({"status":"paused"})", "application/json");
            } else if (cmd == "resume") {
                g_paused = false;
                res.set_content(R"({"status":"resumed"})", "application/json");
            } else {
                res.status = 400;
                res.set_content(R"({"error":"unknown command"})", "application/json");
            }
        });

        printf("[+] Web UI started → http://localhost:9000\n");
        g_web_server_ready = true;
        svr.listen("0.0.0.0", 9000);
        g_web_server_ready = false;
    });

    // Give the web server thread time to bind the socket
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    /* Main poll loop */
 time_t last_print = time(nullptr);
    while (g_running) {
        if (!g_paused) {
            ring_buffer__poll(g_uprobe_rb, 10);
            ring_buffer__poll(g_offcpu_rb, 10);
            ring_buffer__poll(g_oncpu_rb,  10);

            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            uint64_t now_ns = (uint64_t)ts.tv_sec * 1'000'000'000ULL + ts.tv_nsec;
            g_derivation->flush_pending(now_ns);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        time_t now = time(nullptr);
        if (now - last_print >= 1) {
            print_table();
            if (g_stack_resolver) g_stack_resolver->refresh_maps();

            /* === UPDATE WEB UI LIVE DATA (THIS BLOCK WAS UPDATED) === */
            {
                std::lock_guard<std::mutex> lock(data_mutex);

                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);
                uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

                live_data["start_ns"]     = g_profiler_start_ns;
                live_data["runtime_sec"]  = (now_ns - g_profiler_start_ns) / 1e9;

                live_data["entries"]      = g_total_func_entries.load();
                live_data["exits"]        = g_total_func_exits.load();
                live_data["oncpu_samples"]= g_total_on_cpu_samples.load();
                live_data["offcpu_events"]= g_total_off_cpu_events.load();   // ← NEW: This was missing!

                live_data["processed"]    = g_derivation->get_total_processed();
                live_data["dropped"]      = g_derivation->get_dropped_short_calls();
                live_data["errors"]       = g_derivation->get_error_count();

                live_data["pid"]          = g_target_pid;
                std::string basename = g_binary_path.empty() ? "unknown" 
                                     : g_binary_path.substr(g_binary_path.find_last_of('/') + 1);
                live_data["binary"]       = basename;
            }
            last_print = now;
        }
    }

    printf("\n[+] Final results:\n");
    print_table();
    cleanup();
    return 0;
}