/*
 * main.cpp - Phase 2: uprobe + kprobe profiler
 *
 * Attaches separate BPF programs per function (func0, func1, func2)
 * so each uprobe knows exactly which function it belongs to.
 *
 * Run:
 *   sudo ./profiler --pid <PID> --bin <binary> --funcs "main,compute,wait_a_bit"
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
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <gelf.h>
#include <libelf.h>

#include "profiler_common.h"

/* ── Globals ──────────────────────────────────────────────────────────── */

static volatile bool g_running = true;

static struct bpf_object  *g_uprobe_obj = nullptr;
static struct bpf_object  *g_offcpu_obj = nullptr;
static struct ring_buffer *g_uprobe_rb  = nullptr;
static struct ring_buffer *g_offcpu_rb  = nullptr;

static std::vector<std::string> g_func_names;

struct FuncStats {
    uint64_t total_on_cpu_ns  = 0;
    uint64_t total_off_cpu_ns = 0;
    uint64_t total_wall_ns    = 0;
    uint64_t call_count       = 0;
};
static std::unordered_map<uint32_t, FuncStats> g_stats;
static uint64_t g_off_cpu_events = 0;

/* ── Signal handler ───────────────────────────────────────────────────── */

static void sig_handler(int) { g_running = false; }

/* ── Helpers ──────────────────────────────────────────────────────────── */

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

/* ── ELF symbol lookup ────────────────────────────────────────────────── */

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

/* ── Ring buffer callback ─────────────────────────────────────────────── */

static int handle_event(void *, void *data, size_t)
{
    const struct profiler_event *e =
        reinterpret_cast<const struct profiler_event *>(data);

    if (e->type == EVENT_FUNC_EXIT) {
        auto &s = g_stats[e->func_id];
        s.total_on_cpu_ns  += e->on_cpu_ns;
        s.total_off_cpu_ns += e->off_cpu_ns;
        s.total_wall_ns    += e->duration_ns;
        s.call_count++;
    } else if (e->type == EVENT_OFF_CPU) {
        g_off_cpu_events++;
    }
    return 0;
}

/* ── Print stats table ────────────────────────────────────────────────── */

static void print_table()
{
    printf("\033[2J\033[H");
    printf("eBPF Profiler — uprobe + kprobe mode\n");
    printf("%s\n", std::string(80, '=').c_str());
    printf("%-20s %10s %12s %12s %10s\n",
           "FUNCTION", "CALLS", "ON_CPU_MS", "OFF_CPU_MS", "WALL_MS");
    printf("%s\n", std::string(80, '-').c_str());

    for (size_t i = 0; i < g_func_names.size(); i++) {
        auto it = g_stats.find((uint32_t)i);
        if (it == g_stats.end()) {
            printf("%-20s %10s %12s %12s %10s\n",
                   g_func_names[i].c_str(), "0", "0.00", "0.00", "0.00");
            continue;
        }
        const auto &s = it->second;
        printf("%-20s %10llu %12.2f %12.2f %10.2f\n",
               g_func_names[i].c_str(),
               (unsigned long long)s.call_count,
               s.total_on_cpu_ns  / 1e6,
               s.total_off_cpu_ns / 1e6,
               s.total_wall_ns    / 1e6);
    }

    printf("%s\n", std::string(80, '-').c_str());
    printf("Off-CPU blocking events: %llu\n",
           (unsigned long long)g_off_cpu_events);
    printf("Press Ctrl-C to stop\n");
    fflush(stdout);
}

/* ── Cleanup ──────────────────────────────────────────────────────────── */

static void cleanup()
{
    if (g_uprobe_rb)  ring_buffer__free(g_uprobe_rb);
    if (g_offcpu_rb)  ring_buffer__free(g_offcpu_rb);
    if (g_uprobe_obj) bpf_object__close(g_uprobe_obj);
    if (g_offcpu_obj) bpf_object__close(g_offcpu_obj);
    unlink("/sys/fs/bpf/profiler_off_cpu_data");
}

/* ── Usage ────────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --pid <PID> --bin <path> --funcs <f1,f2,f3>\n"
        "\n"
        "  --pid    PID of the target process (required)\n"
        "  --bin    path to the target binary  (required)\n"
        "  --funcs  comma-separated list of up to 3 functions (required)\n"
        "\n"
        "Example:\n"
        "  %s --pid 1234 --bin /tmp/test_target --funcs \"main,compute,wait_a_bit\"\n",
        prog, prog);
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    uint32_t    target_pid      = 0;
    const char *binary_path     = nullptr;
    const char *funcs_str       = nullptr;
    const char *uprobe_obj_path = "../build_cmake/uprobe.bpf.o";
    const char *offcpu_obj_path = "../build_cmake/off_cpu.bpf.o";

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--pid")   && i+1 < argc) target_pid  = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--bin")   && i+1 < argc) binary_path = argv[++i];
        else if (!strcmp(argv[i], "--funcs") && i+1 < argc) funcs_str   = argv[++i];
        else { usage(argv[0]); return 1; }
    }

    if (!target_pid || !binary_path || !funcs_str) {
        fprintf(stderr, "Error: --pid, --bin and --funcs are all required\n\n");
        usage(argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: must run as root\n");
        return 1;
    }

    /* Parse comma-separated function list (max 3) */
    {
        std::stringstream ss(funcs_str);
        std::string token;
        while (std::getline(ss, token, ',')) {
            if (!token.empty()) {
                if (g_func_names.size() >= 3) {
                    fprintf(stderr, "Warning: max 3 functions supported\n");
                    break;
                }
                g_func_names.push_back(token);
            }
        }
    }

    if (g_func_names.empty()) {
        fprintf(stderr, "Error: no functions specified\n");
        return 1;
    }

    printf("eBPF Profiler — uprobe mode\n");
    printf("  PID     : %u\n", target_pid);
    printf("  Binary  : %s\n", binary_path);
    printf("  Functions:\n");
    for (auto &f : g_func_names) printf("    - %s\n", f.c_str());
    printf("\n");

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    bump_memlock_rlimit();
    libbpf_set_print(NULL);

    /* Clean up leftover pinned maps from previous runs */
    unlink("/sys/fs/bpf/profiler_off_cpu_data");

    /* ── Load off_cpu object FIRST so we can pin its shared map ─────── */
    printf("Loading %s ...\n", offcpu_obj_path);
    g_offcpu_obj = bpf_object__open_file(offcpu_obj_path, nullptr);
    if (libbpf_get_error(g_offcpu_obj)) {
        fprintf(stderr, "Failed to open off_cpu BPF object\n");
        return 1;
    }
    if (bpf_object__load(g_offcpu_obj) != 0) {
        fprintf(stderr, "Failed to load off_cpu BPF object: %s\n", strerror(errno));
        cleanup(); return 1;
    }
    printf("  Loaded OK\n");

    /* Pin off_cpu_data map so uprobe object can reuse it */
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
    printf("  Pinned off_cpu_data map\n");

    /* ── Load uprobe object and reuse the pinned map ─────────────────── */
    printf("Loading %s ...\n", uprobe_obj_path);
    g_uprobe_obj = bpf_object__open_file(uprobe_obj_path, nullptr);
    if (libbpf_get_error(g_uprobe_obj)) {
        fprintf(stderr, "Failed to open uprobe BPF object\n");
        cleanup(); return 1;
    }

    /* Reuse pinned off_cpu_data in the uprobe object */
    struct bpf_map *uprobe_shared =
        bpf_object__find_map_by_name(g_uprobe_obj, "off_cpu_data");
    if (uprobe_shared) {
        int pinned_fd = bpf_obj_get("/sys/fs/bpf/profiler_off_cpu_data");
        if (pinned_fd >= 0) {
            bpf_map__reuse_fd(uprobe_shared, pinned_fd);
            printf("  Reusing shared off_cpu_data map\n");
        }
    }

    if (bpf_object__load(g_uprobe_obj) != 0) {
        fprintf(stderr, "Failed to load uprobe BPF object: %s\n", strerror(errno));
        cleanup(); return 1;
    }
    printf("  Loaded OK\n");

    /* ── Set target PID in both objects ─────────────────────────────── */
    if (set_target_pid(g_uprobe_obj, target_pid) != 0) { cleanup(); return 1; }
    if (set_target_pid(g_offcpu_obj, target_pid) != 0) { cleanup(); return 1; }

    /* ── Attach uprobes — dedicated program pair per function ────────── */
    printf("\nAttaching uprobes...\n");

    /*
     * Each function slot has its own BPF entry+exit program.
     * func0 = first function in --funcs list
     * func1 = second function
     * func2 = third function
     * Names must match SEC() declarations in uprobe.bpf.c exactly.
     */
    const char *entry_prog_names[] = {"func0_entry", "func1_entry", "func2_entry"};
    const char *exit_prog_names[]  = {"func0_exit",  "func1_exit",  "func2_exit"};

    for (size_t i = 0; i < g_func_names.size(); i++) {
        const char *fname = g_func_names[i].c_str();

        uint64_t offset = find_symbol_offset(binary_path, fname);
        if (offset == 0) {
            fprintf(stderr, "  WARNING: '%s' not found in binary — skipping\n", fname);
            continue;
        }

        struct bpf_program *ep =
            bpf_object__find_program_by_name(g_uprobe_obj, entry_prog_names[i]);
        struct bpf_program *xp =
            bpf_object__find_program_by_name(g_uprobe_obj, exit_prog_names[i]);

        if (!ep || !xp) {
            fprintf(stderr, "  WARNING: BPF programs for slot %zu not found\n", i);
            continue;
        }

        printf("  %-15s @ 0x%llx ... ", fname, (unsigned long long)offset);

        struct bpf_link *el =
            bpf_program__attach_uprobe(ep, false, (int)target_pid,
                                        binary_path, offset);
        struct bpf_link *xl =
            bpf_program__attach_uprobe(xp, true, (int)target_pid,
                                        binary_path, offset);

        if (!el || !xl)
            printf("FAILED (%s)\n", strerror(errno));
        else
            printf("OK\n");
    }

    /* ── Attach off-CPU sched_switch tracepoint ──────────────────────── */
    printf("\nAttaching off-cpu tracepoint...\n");
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
    printf("  OK: sched/sched_switch\n");

    /* ── Set up ring buffers ─────────────────────────────────────────── */
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

    printf("\nProfiling started — table updates every second\n\n");

    /* ── Poll loop ──────────────────────────────────────────────────── */
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

    printf("\nFinal results:\n");
    print_table();
    cleanup();
    return 0;
}