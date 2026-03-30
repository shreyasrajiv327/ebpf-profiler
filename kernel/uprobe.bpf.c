// SPDX-License-Identifier: GPL-2.0
/*
 * uprobe.bpf.c - V2: Raw event emission for userspace derivation
 *
 * CHANGES:
 * - Removed on-CPU/off-CPU calculation logic
 * - Emit raw timestamps (entry_ts, exit_ts)
 * - Removed reads from off_cpu_data map
 * - Simplified to just collect raw data
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

/* ══════════════════════════════════════════════════════════════════════
 *  Generic entry handler
 * ════════════════════════════════════════════════════════════════════ */
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

    __u64 entry_ts = bpf_ktime_get_ns();

    /* Record entry timestamp */
    struct func_entry entry = {};
    entry.entry_ts      = entry_ts;
    entry.func_id       = func_id;
    entry.user_stack_id = stack_id;
    bpf_map_update_elem(&func_entries, &tid, &entry, BPF_ANY);

    /* Optional: Emit ENTRY event for tracking */
    struct profiler_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid             = pid;
        e->tid             = tid;
        e->func_id         = func_id;
        e->type            = EVENT_FUNC_ENTRY;
        e->timestamp_ns    = entry_ts;
        e->entry_ts        = entry_ts;
        e->exit_ts         = 0;
        e->user_stack_id   = stack_id;
        e->kernel_stack_id = -1;
        e->cpu             = bpf_get_smp_processor_id();
        e->pad2            = 0;
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Generic exit handler
 * ════════════════════════════════════════════════════════════════════ */
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
    __u64 entry_ts = fe->entry_ts;
    __u64 exit_ts  = bpf_ktime_get_ns();
    __s32 stack_id = fe->user_stack_id;

    /* ────────────────────────────────────────────────────────────────
     * V2 CHANGE: Just emit raw timestamps
     * All derivation happens in userspace
     * ──────────────────────────────────────────────────────────────── */

    /* Emit event to ring buffer */
    struct profiler_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid             = pid;
        e->tid             = tid;
        e->func_id         = func_id;
        e->type            = EVENT_FUNC_EXIT;
        e->timestamp_ns    = exit_ts;
        e->entry_ts        = entry_ts;      // ✓ Raw entry timestamp
        e->exit_ts         = exit_ts;       // ✓ Raw exit timestamp
        e->user_stack_id   = stack_id;
        e->kernel_stack_id = -1;
        e->cpu             = bpf_get_smp_processor_id();
        e->pad2            = 0;
        
        /* REMOVED: on_cpu_ns, off_cpu_ns, duration_ns computation */
        
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&func_entries, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";