// SPDX-License-Identifier: GPL-2.0
/*
 * uprobe.bpf.c - Dynamic function probing via metadata map
 *
 * Supports unlimited functions via metadata map approach.
 * Works on kernel 4.4+ (no cookies required).
 *
 * Userspace stores: offset → func_id mapping in uprobe_metadata map
 * Kernel reads: offset from context → func_id lookup
 */

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

/* Shared with off_cpu.bpf.c */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, struct off_cpu_val);
} off_cpu_data SEC(".maps");

/* Metadata: runtime address → func_id */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u64);  /* runtime address */
    __type(value, __u32);  /* func_id */
} uprobe_metadata SEC(".maps");

/* Stack trace maps */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 8192);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} user_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 8192);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} kernel_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

/* ── Generic entry handler ─────────────────────────────────────────── */
SEC("uprobe/")
int generic_entry(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    if (pid != *tpid) return 0;

    /* Get runtime instruction pointer and look up func_id */
    __u64 ip = PT_REGS_IP(ctx);
    __u32 *func_id_ptr = bpf_map_lookup_elem(&uprobe_metadata, &ip);
    if (!func_id_ptr) return 0;
    __u32 func_id = *func_id_ptr;

    /* Capture user stack trace */
    __s32 stack_id = bpf_get_stackid(ctx, &user_stacks, BPF_F_USER_STACK);

    /* Record entry timestamp */
    struct func_entry entry = {};
    entry.entry_ts      = bpf_ktime_get_ns();
    entry.func_id       = func_id;
    entry.user_stack_id = stack_id;
    bpf_map_update_elem(&func_entries, &tid, &entry, BPF_ANY);

    /* Reset ALL off-CPU counters for this new invocation */
    struct off_cpu_val reset = {};
    reset.start_ns        = 0;
    reset.total_off_cpu_ns = 0;
    reset.total_io_ns     = 0;
    reset.total_lock_ns   = 0;
    reset.total_sleep_ns  = 0;
    reset.io_start_ns     = 0;
    reset.lock_start_ns   = 0;
    reset.sleep_start_ns  = 0;
    bpf_map_update_elem(&off_cpu_data, &tid, &reset, BPF_ANY);

    return 0;
}

/* ── Generic exit handler ──────────────────────────────────────────── */
SEC("uretprobe/")
int generic_exit(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    if (pid != *tpid) return 0;

    /* Look up entry info */
    struct func_entry *fe = bpf_map_lookup_elem(&func_entries, &tid);
    if (!fe) return 0;

    __u32 func_id  = fe->func_id;
    __u64 exit_ts  = bpf_ktime_get_ns();
    __u64 total_ns = exit_ts - fe->entry_ts;
    __s32 stack_id = fe->user_stack_id;

    /* Read all off-CPU reason breakdown fields */
    __u64 off_cpu_ns = 0;
    __u64 io_ns      = 0;
    __u64 lock_ns    = 0;
    __u64 sleep_ns   = 0;

    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (oval) {
        off_cpu_ns = oval->total_off_cpu_ns;
        io_ns      = oval->total_io_ns;
        lock_ns    = oval->total_lock_ns;
        sleep_ns   = oval->total_sleep_ns;
    }

    __u64 on_cpu_ns = (off_cpu_ns < total_ns) ? (total_ns - off_cpu_ns) : 0;

    /* Emit event to ring buffer */
    struct profiler_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid             = pid;
        e->tid             = tid;
        e->func_id         = func_id;
        e->type            = EVENT_FUNC_EXIT;
        e->timestamp_ns    = exit_ts;
        e->duration_ns     = total_ns;
        e->on_cpu_ns       = on_cpu_ns;
        e->off_cpu_ns      = off_cpu_ns;
        e->io_ns           = io_ns;
        e->lock_ns         = lock_ns;
        e->sleep_ns        = sleep_ns;
        e->cpu             = bpf_get_smp_processor_id();
        e->user_stack_id   = stack_id;
        e->kernel_stack_id = -1;
        e->pad             = 0;
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&func_entries, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";