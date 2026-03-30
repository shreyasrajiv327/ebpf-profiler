// SPDX-License-Identifier: GPL-2.0
/*
 * off_cpu.bpf.c - V2: Raw event emission for userspace derivation
 *
 * CHANGES:
 * - Emit off_cpu_event (not profiler_event)
 * - Add reason codes (REASON_IO_WAIT, REASON_LOCK, etc.)
 * - Removed accumulation logic (total_off_cpu_ns, total_io_ns, etc.)
 * - Simplified to just detect and emit raw events
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "profiler_common.h"

/* ── Maps ──────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

/* Simplified off-CPU tracking - just timestamps, no accumulation */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, struct off_cpu_val);
} off_cpu_data SEC(".maps");

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

/* ── sched_switch handler (main off-CPU detector) ───────────────────────── */

SEC("tracepoint/sched/sched_switch")
int off_cpu_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0)
        return 0;

    __u64 ts = bpf_ktime_get_ns();

    __u32 prev_tid = BPF_CORE_READ(ctx, prev_pid);
    __u32 next_tid = BPF_CORE_READ(ctx, next_pid);

    /* ── Target going OFF-CPU ───────────────────────────────────────── */
    if (prev_tid == *tpid) {
        struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &prev_tid);
        if (oval) {
            /* Already tracking — just update start time */
            oval->start_ns = ts;
            oval->active_reason = REASON_SCHEDULER;  // Default reason
        } else {
            /* First time seeing this thread go off-CPU */
            struct off_cpu_val new_val = {};
            new_val.start_ns      = ts;
            new_val.active_reason = REASON_SCHEDULER;
            bpf_map_update_elem(&off_cpu_data, &prev_tid, &new_val, BPF_ANY);
        }
    }

    /* ── Target coming back ON-CPU ──────────────────────────────────── */
    if (next_tid == *tpid) {
        struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &next_tid);
        if (!oval || oval->start_ns == 0)
            return 0;

        __u64 duration = ts - oval->start_ns;

        /* Ignore very short waits < 100 microseconds (noise filter) */
        if (duration < 100000ULL) {
            oval->start_ns = 0;
            return 0;
        }

        /* ────────────────────────────────────────────────────────────
         * V2 CHANGE: Emit off_cpu_event structure (not profiler_event)
         * ──────────────────────────────────────────────────────────── */
        struct off_cpu_event *e =
            bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid          = *tpid;
            e->tid          = next_tid;
            e->off_start_ts = oval->start_ns;
            e->off_end_ts   = ts;
            e->type = EVENT_OFF_CPU;
            e->reason       = oval->active_reason;  // ✓ Reason code
            e->cpu          = bpf_get_smp_processor_id();
            e->pad2         = 0;
            bpf_ringbuf_submit(e, 0);
        }

        /* Reset for next off-CPU period */
        oval->start_ns = 0;
        oval->active_reason = REASON_UNKNOWN;
    }

    return 0;
}

/* ── Block I/O tracking ──────────────────────────────────────────────── */

SEC("tracepoint/block/block_rq_insert")
int io_start(struct trace_event_raw_block_rq_insert *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;

    __u64 pidtid = bpf_get_current_pid_tgid();
    __u32 pid = pidtid >> 32;
    __u32 tid = pidtid & 0xFFFFFFFF;
    if (pid != *tpid) return 0;

    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval) {
        struct off_cpu_val new_val = {};
        bpf_map_update_elem(&off_cpu_data, &tid, &new_val, BPF_ANY);
        oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    }
    
    if (oval) {
        oval->io_start_ns = bpf_ktime_get_ns();
        oval->active_reason = REASON_IO_WAIT;  // ✓ Mark as I/O wait
    }
    
    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int io_end(struct trace_event_raw_block_rq_complete *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;

    __u64 pidtid = bpf_get_current_pid_tgid();
    __u32 pid = pidtid >> 32;
    __u32 tid = pidtid & 0xFFFFFFFF;
    if (pid != *tpid) return 0;

    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval || oval->io_start_ns == 0) return 0;

    __u64 ts = bpf_ktime_get_ns();
    __u64 duration = ts - oval->io_start_ns;

    /* V2: Emit I/O wait event */
    struct off_cpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid          = *tpid;
        e->tid          = tid;
        e->off_start_ts = oval->io_start_ns;
        e->off_end_ts   = ts;
        e->type = EVENT_OFF_CPU;
        e->reason       = REASON_IO_WAIT;  // ✓ Specific I/O reason
        e->cpu          = bpf_get_smp_processor_id();
        e->pad2         = 0;
        bpf_ringbuf_submit(e, 0);
    }

    oval->io_start_ns = 0;
    return 0;
}

/* ── Lock contention tracking ────────────────────────────────────────── */

SEC("tracepoint/lock/contention_begin")
int lock_start(struct trace_event_raw_contention_begin *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;

    __u64 pidtid = bpf_get_current_pid_tgid();
    __u32 pid = pidtid >> 32;
    __u32 tid = pidtid & 0xFFFFFFFF;
    if (pid != *tpid) return 0;

    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval) {
        struct off_cpu_val new_val = {};
        bpf_map_update_elem(&off_cpu_data, &tid, &new_val, BPF_ANY);
        oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    }
    
    if (oval) {
        oval->lock_start_ns = bpf_ktime_get_ns();
        oval->active_reason = REASON_LOCK;  // ✓ Mark as lock contention
    }
    
    return 0;
}

SEC("tracepoint/lock/contention_end")
int lock_end(struct trace_event_raw_contention_end *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;

    __u64 pidtid = bpf_get_current_pid_tgid();
    __u32 pid = pidtid >> 32;
    __u32 tid = pidtid & 0xFFFFFFFF;
    if (pid != *tpid) return 0;

    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval || oval->lock_start_ns == 0) return 0;

    __u64 ts = bpf_ktime_get_ns();
    __u64 duration = ts - oval->lock_start_ns;

    /* V2: Emit lock contention event */
    struct off_cpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid          = *tpid;
        e->tid          = tid;
        e->off_start_ts = oval->lock_start_ns;
        e->off_end_ts   = ts;
        e->type = EVENT_OFF_CPU;
        e->reason       = REASON_LOCK;  // ✓ Specific lock reason
        e->cpu          = bpf_get_smp_processor_id();
        e->pad2         = 0;
        bpf_ringbuf_submit(e, 0);
    }

    oval->lock_start_ns = 0;
    return 0;
}

/* ── Sleep/poll tracking ─────────────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_epoll_pwait")
int sleep_start(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;

    __u64 pidtid = bpf_get_current_pid_tgid();
    __u32 pid = pidtid >> 32;
    __u32 tid = pidtid & 0xFFFFFFFF;
    if (pid != *tpid) return 0;

    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval) {
        struct off_cpu_val new_val = {};
        bpf_map_update_elem(&off_cpu_data, &tid, &new_val, BPF_ANY);
        oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    }
    
    if (oval) {
        oval->sleep_start_ns = bpf_ktime_get_ns();
        oval->active_reason = REASON_SLEEP;  // ✓ Mark as sleep
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_pwait")
int sleep_end(struct trace_event_raw_sys_exit *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;

    __u64 pidtid = bpf_get_current_pid_tgid();
    __u32 pid = pidtid >> 32;
    __u32 tid = pidtid & 0xFFFFFFFF;
    if (pid != *tpid) return 0;

    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval || oval->sleep_start_ns == 0) return 0;

    __u64 ts = bpf_ktime_get_ns();
    __u64 duration = ts - oval->sleep_start_ns;

    /* V2: Emit sleep event */
    struct off_cpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid          = *tpid;
        e->tid          = tid;
        e->off_start_ts = oval->sleep_start_ns;
        e->off_end_ts   = ts;
        e->type = EVENT_OFF_CPU;
        e->reason       = REASON_SLEEP;  // ✓ Specific sleep reason
        e->cpu          = bpf_get_smp_processor_id();
        e->pad2         = 0;
        bpf_ringbuf_submit(e, 0);
    }

    oval->sleep_start_ns = 0;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";