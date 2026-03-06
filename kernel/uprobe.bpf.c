// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "profiler_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, struct func_entry);
} func_entries SEC(".maps");

/* Shared with off_cpu.bpf.c via pinning */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, struct off_cpu_val);
} off_cpu_data SEC(".maps");

/*
 * Stack trace map — stores arrays of instruction pointers.
 * Key = stack_id (returned by bpf_get_stackid)
 * Value = array of MAX_STACK_DEPTH instruction pointers
 * Userspace reads this to resolve addresses to function names.
 */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 8192);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

/* ── Helper macro — common pid check ───────────────────────────────── */
#define CHECK_PID(ret)                                          \
    __u32 key = 0;                                              \
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);      \
    if (!tpid || *tpid == 0) return ret;                        \
    __u64 pid_tgid = bpf_get_current_pid_tgid();               \
    __u32 pid = pid_tgid >> 32;                                 \
    __u32 tid = (__u32)pid_tgid;                                \
    if (pid != *tpid) return ret;

/* ── Entry handler (same logic for all 3 functions) ─────────────────── */
static __always_inline int handle_entry(struct pt_regs *ctx, __u32 func_id)
{
    CHECK_PID(0)

    /* Capture user stack at function entry */
    __s32 stack_id = bpf_get_stackid(ctx, &stack_traces,
                                      BPF_F_USER_STACK);

    struct func_entry entry = {};
    entry.entry_ts     = bpf_ktime_get_ns();
    entry.func_id      = func_id;
    entry.user_stack_id = stack_id;
    entry.pad          = 0;

    /* Reset off-cpu accumulator for this thread */
    struct off_cpu_val reset = {};
    bpf_map_update_elem(&off_cpu_data, &tid, &reset, BPF_ANY);

    bpf_map_update_elem(&func_entries, &tid, &entry, BPF_ANY);
    return 0;
}

/* ── Exit handler (same logic for all 3 functions) ──────────────────── */
static __always_inline int handle_exit(struct pt_regs *ctx, __u32 expected_id)
{
    CHECK_PID(0)

    struct func_entry *fe = bpf_map_lookup_elem(&func_entries, &tid);
    if (!fe || fe->func_id != expected_id) return 0;

    __u64 exit_ts  = bpf_ktime_get_ns();
    __u64 total_ns = exit_ts - fe->entry_ts;
    __s32 stack_id = fe->user_stack_id;

    __u64 off_cpu_ns = 0;
    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (oval) off_cpu_ns = oval->total_off_cpu_ns;

    __u64 on_cpu_ns = (off_cpu_ns < total_ns) ? (total_ns - off_cpu_ns) : 0;

    struct profiler_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid           = pid;
        e->tid           = tid;
        e->func_id       = expected_id;
        e->type          = EVENT_FUNC_EXIT;
        e->timestamp_ns  = exit_ts;
        e->duration_ns   = total_ns;
        e->on_cpu_ns     = on_cpu_ns;
        e->off_cpu_ns    = off_cpu_ns;
        e->cpu           = bpf_get_smp_processor_id();
        e->user_stack_id = stack_id;
        e->pad           = 0;
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&func_entries, &tid);
    return 0;
}

/* ── func0 ──────────────────────────────────────────────────────────── */
SEC("uprobe/func0_entry")
int func0_entry(struct pt_regs *ctx) { return handle_entry(ctx, 0); }

SEC("uretprobe/func0_exit")
int func0_exit(struct pt_regs *ctx)  { return handle_exit(ctx, 0); }

/* ── func1 ──────────────────────────────────────────────────────────── */
SEC("uprobe/func1_entry")
int func1_entry(struct pt_regs *ctx) { return handle_entry(ctx, 1); }

SEC("uretprobe/func1_exit")
int func1_exit(struct pt_regs *ctx)  { return handle_exit(ctx, 1); }

/* ── func2 ──────────────────────────────────────────────────────────── */
SEC("uprobe/func2_entry")
int func2_entry(struct pt_regs *ctx) { return handle_entry(ctx, 2); }

SEC("uretprobe/func2_exit")
int func2_exit(struct pt_regs *ctx)  { return handle_exit(ctx, 2); }

char LICENSE[] SEC("license") = "GPL";
