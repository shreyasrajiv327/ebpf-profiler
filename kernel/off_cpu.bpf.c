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
    __type(value, struct off_cpu_val);
} off_cpu_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

static inline __u32 get_current_tid(void) {
    return (__u32)bpf_get_current_pid_tgid();
}

/* sched_switch */
SEC("tracepoint/sched/sched_switch")
int off_cpu_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;

    __u32 prev_tid = BPF_CORE_READ(ctx, prev_pid);
    __u32 next_tid = BPF_CORE_READ(ctx, next_pid);
    __u64 ts = bpf_ktime_get_ns();

    if (prev_tid == *tpid) {
        struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &prev_tid);
        if (!oval) {
            struct off_cpu_val z = {};
            bpf_map_update_elem(&off_cpu_data, &prev_tid, &z, BPF_ANY);
            oval = bpf_map_lookup_elem(&off_cpu_data, &prev_tid);
        }
        if (oval) {
            oval->start_ns = ts;
            oval->active_reason = REASON_SCHEDULER;
        }
    }

    if (next_tid == *tpid) {
        struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &next_tid);
        if (!oval || oval->start_ns == 0) return 0;

        __u64 start_ts = oval->start_ns;
        __u64 duration = ts - start_ts;

        if (duration < 100000ULL) {
            oval->start_ns = 0;
            return 0;
        }

        oval->total_off_cpu_ns += duration;
        oval->start_ns = 0;

        struct off_cpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = *tpid;
            e->tid = next_tid;
            e->off_start_ts = start_ts;
            e->off_end_ts = ts;
            e->type = EVENT_OFF_CPU;
            e->reason = REASON_SCHEDULER;
            e->cpu = bpf_get_smp_processor_id();
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}

/* IO */
SEC("tracepoint/block/block_rq_complete")
int io_end(struct trace_event_raw_block_rq_complete *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    __u32 tid = get_current_tid();
    if (tid != *tpid) return 0;

    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval || oval->io_start_ns == 0) return 0;

    __u64 duration = bpf_ktime_get_ns() - oval->io_start_ns;
    oval->total_io_ns += duration;

    struct off_cpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = *tpid; e->tid = tid;
        e->off_start_ts = oval->io_start_ns;
        e->off_end_ts = bpf_ktime_get_ns();
        e->type = EVENT_OFF_CPU;
        e->reason = REASON_IO_WAIT;
        e->cpu = bpf_get_smp_processor_id();
        bpf_ringbuf_submit(e, 0);
    }
    oval->io_start_ns = 0;
    return 0;
}

/* Lock */
SEC("tracepoint/lock/contention_end")
int lock_end(struct trace_event_raw_contention_end *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    __u32 tid = get_current_tid();
    if (tid != *tpid) return 0;

    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval || oval->lock_start_ns == 0) return 0;

    __u64 duration = bpf_ktime_get_ns() - oval->lock_start_ns;
    oval->total_lock_ns += duration;

    struct off_cpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = *tpid; e->tid = tid;
        e->off_start_ts = oval->lock_start_ns;
        e->off_end_ts = bpf_ktime_get_ns();
        e->type = EVENT_OFF_CPU;
        e->reason = REASON_LOCK;
        e->cpu = bpf_get_smp_processor_id();
        bpf_ringbuf_submit(e, 0);
    }
    oval->lock_start_ns = 0;
    return 0;
}

/* Sleep - this is the most important one for Redis */
SEC("tracepoint/syscalls/sys_exit_epoll_pwait")
int sleep_end(struct trace_event_raw_sys_exit *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    __u32 tid = get_current_tid();
    if (tid != *tpid) return 0;

    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval || oval->sleep_start_ns == 0) return 0;

    __u64 duration = bpf_ktime_get_ns() - oval->sleep_start_ns;
    oval->total_sleep_ns += duration;          // ← THIS WAS MISSING

    struct off_cpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = *tpid; e->tid = tid;
        e->off_start_ts = oval->sleep_start_ns;
        e->off_end_ts = bpf_ktime_get_ns();
        e->type = EVENT_OFF_CPU;
        e->reason = REASON_SLEEP;
        e->cpu = bpf_get_smp_processor_id();
        bpf_ringbuf_submit(e, 0);
    }
    oval->sleep_start_ns = 0;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";