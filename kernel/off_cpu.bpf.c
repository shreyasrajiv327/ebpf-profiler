// SPDX-License-Identifier: GPL-2.0
/*
 * off_cpu.bpf.c
 *
 * Tracks when the target thread goes off-CPU and for how long.
 * Uses sched_switch tracepoint (no PMU needed, works in UTM VM).
 *
 * Key change from Phase 1:
 * Instead of emitting an event immediately, we ACCUMULATE
 * off-CPU time into off_cpu_data map (shared with uprobe.bpf.c).
 * The uprobe exit handler reads this to compute exact on-CPU time.
 *
 * Ubuntu 22.04 ARM64 / libbpf 0.5 / BPF CO-RE
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

/*
 * off_cpu_data: shared with uprobe.bpf.c
 * Key = tid
 * Value = {start_ns, total_off_cpu_ns}
 *
 * When thread goes off-CPU: record start_ns
 * When thread comes back:   total_off_cpu_ns += (now - start_ns)
 * uprobe exit reads total_off_cpu_ns to compute on-CPU time
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, struct off_cpu_val);
} off_cpu_data SEC(".maps");

/* Ring buffer — for emitting standalone OFF_CPU events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

/* ── sched_switch handler ───────────────────────────────────────────────── */

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
        } else {
            /* First time seeing this thread go off-CPU */
            struct off_cpu_val new_val = {};
            new_val.start_ns         = ts;
            new_val.total_off_cpu_ns = 0;
            bpf_map_update_elem(&off_cpu_data, &prev_tid, &new_val, BPF_ANY);
        }
    }

    /* ── Target coming back ON-CPU ──────────────────────────────────── */
    if (next_tid == *tpid) {
        struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &next_tid);
        if (!oval || oval->start_ns == 0)
            return 0;

        __u64 duration = ts - oval->start_ns;

        /* Ignore very short waits < 100 microseconds */
        if (duration < 100000ULL) {
            oval->start_ns = 0;
            return 0;
        }

        /* Accumulate into total */
        oval->total_off_cpu_ns += duration;
        oval->start_ns          = 0;

        /* Also emit a standalone OFF_CPU event so
         * userspace can see blocking events in real time */
        struct profiler_event *e =
            bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid          = *tpid;
            e->tid          = next_tid;
            e->func_id      = 0;
            e->type         = EVENT_OFF_CPU;
            e->timestamp_ns = oval->start_ns;
            e->duration_ns  = duration;
            e->on_cpu_ns    = 0;
            e->off_cpu_ns   = duration;
            e->cpu          = bpf_get_smp_processor_id();
            e->pad          = 0;
            bpf_ringbuf_submit(e, 0);
        }
    }

    return 0;
}
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
    if (oval) oval->io_start_ns = bpf_ktime_get_ns();
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
    __u64 duration = bpf_ktime_get_ns() - oval->io_start_ns;
    oval->total_io_ns += duration;
    oval->io_start_ns  = 0;
    return 0;
}

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
    if (oval) oval->lock_start_ns = bpf_ktime_get_ns();
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
    __u64 duration = bpf_ktime_get_ns() - oval->lock_start_ns;
    oval->total_lock_ns += duration;
    oval->lock_start_ns  = 0;
    return 0;
}

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
    if (oval) oval->sleep_start_ns = bpf_ktime_get_ns();
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

    __u64 duration = bpf_ktime_get_ns() - oval->sleep_start_ns;
    oval->total_sleep_ns += duration;
    oval->sleep_start_ns  = 0;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
