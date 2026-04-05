// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "profiler_common.h"

/* ── Maps ────────────────────────────────────────────────────────────── */

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

/*
 * known_tids — THE FIX FOR PID/TID MISMATCH
 *
 * sched_switch gives prev_pid/next_pid which are Linux TIDs.
 * A multithreaded app has one TGID (stored in target_pid) but many TIDs.
 * Syscall probes run in correct thread context → they filter by TGID and
 * register each TID they see here. sched_switch looks up this map to know
 * whether a switching thread belongs to our target process.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);   /* TID */
    __type(value, __u8);    /* presence flag = 1 */
} known_tids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

/* ── Helpers ─────────────────────────────────────────────────────────── */

static inline __u32 get_current_tid(void) {
    return (__u32)bpf_get_current_pid_tgid();
}

static inline __u32 get_current_pid(void) {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

/* Register tid as belonging to target process. BPF_NOEXIST = only insert
 * if not already there, avoids unnecessary writes on hot paths. */
static inline void register_tid(__u32 tid) {
    __u8 one = 1;
    bpf_map_update_elem(&known_tids, &tid, &one, BPF_NOEXIST);
}

/* Get or create off_cpu_val. Also registers tid so sched_switch finds it. */
static inline struct off_cpu_val *get_or_create_oval(__u32 tid) {
    register_tid(tid);
    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval) {
        struct off_cpu_val z = {};
        bpf_map_update_elem(&off_cpu_data, &tid, &z, BPF_ANY);
        oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    }
    return oval;
}

/* Check if a raw TID belongs to our target process */
static inline int is_target_tid(__u32 tid) {
    __u8 *present = bpf_map_lookup_elem(&known_tids, &tid);
    return present != NULL;
}

/* ── FUTEX (mutex / condvar / std::mutex) ────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_futex")
int futex_start(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    if (get_current_pid() != *tpid) return 0;

    __u32 tid = get_current_tid();
    struct off_cpu_val *oval = get_or_create_oval(tid); /* registers tid */
    if (!oval) return 0;

    oval->lock_start_ns = bpf_ktime_get_ns();
    oval->active_reason = REASON_LOCK;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int futex_end(struct trace_event_raw_sys_exit *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    if (get_current_pid() != *tpid) return 0;

    __u32 tid = get_current_tid();
    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval || oval->lock_start_ns == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 duration = now - oval->lock_start_ns;
    oval->total_lock_ns += duration;

    struct off_cpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid          = *tpid;
        e->tid          = tid;
        e->off_start_ts = oval->lock_start_ns;
        e->off_end_ts   = now;
        e->type         = EVENT_OFF_CPU;
        e->reason       = REASON_LOCK;
        e->cpu          = bpf_get_smp_processor_id();
        bpf_ringbuf_submit(e, 0);
    }
    oval->lock_start_ns = 0;
    oval->active_reason = REASON_UNKNOWN;
    return 0;
}

/* ── NANOSLEEP (std::this_thread::sleep_for etc.) ────────────────────── */

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int nanosleep_start(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    if (get_current_pid() != *tpid) return 0;

    __u32 tid = get_current_tid();
    struct off_cpu_val *oval = get_or_create_oval(tid);
    if (!oval) return 0;

    oval->sleep_start_ns = bpf_ktime_get_ns();
    oval->active_reason  = REASON_SLEEP;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_nanosleep")
int nanosleep_end(struct trace_event_raw_sys_exit *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    if (get_current_pid() != *tpid) return 0;

    __u32 tid = get_current_tid();
    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval || oval->sleep_start_ns == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 duration = now - oval->sleep_start_ns;
    oval->total_sleep_ns += duration;

    struct off_cpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid          = *tpid;
        e->tid          = tid;
        e->off_start_ts = oval->sleep_start_ns;
        e->off_end_ts   = now;
        e->type         = EVENT_OFF_CPU;
        e->reason       = REASON_SLEEP;
        e->cpu          = bpf_get_smp_processor_id();
        bpf_ringbuf_submit(e, 0);
    }
    oval->sleep_start_ns = 0;
    oval->active_reason  = REASON_UNKNOWN;
    return 0;
}

/* ── EPOLL_PWAIT (event loop / Redis main thread) ────────────────────── */

SEC("tracepoint/syscalls/sys_enter_epoll_pwait")
int epoll_start(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    if (get_current_pid() != *tpid) return 0;

    __u32 tid = get_current_tid();
    struct off_cpu_val *oval = get_or_create_oval(tid);
    if (!oval) return 0;

    oval->sleep_start_ns = bpf_ktime_get_ns();
    oval->active_reason  = REASON_SLEEP;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_epoll_pwait")
int epoll_end(struct trace_event_raw_sys_exit *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    if (get_current_pid() != *tpid) return 0;

    __u32 tid = get_current_tid();
    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval || oval->sleep_start_ns == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 duration = now - oval->sleep_start_ns;
    oval->total_sleep_ns += duration;

    struct off_cpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid          = *tpid;
        e->tid          = tid;
        e->off_start_ts = oval->sleep_start_ns;
        e->off_end_ts   = now;
        e->type         = EVENT_OFF_CPU;
        e->reason       = REASON_SLEEP;
        e->cpu          = bpf_get_smp_processor_id();
        bpf_ringbuf_submit(e, 0);
    }
    oval->sleep_start_ns = 0;
    oval->active_reason  = REASON_UNKNOWN;
    return 0;
}

/* ── READ / WRITE syscalls (file + network I/O) ──────────────────────── */

SEC("tracepoint/syscalls/sys_enter_read")
int read_start(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    if (get_current_pid() != *tpid) return 0;

    __u32 tid = get_current_tid();
    struct off_cpu_val *oval = get_or_create_oval(tid);
    if (!oval) return 0;

    oval->io_start_ns   = bpf_ktime_get_ns();
    oval->active_reason = REASON_IO_WAIT;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int read_end(struct trace_event_raw_sys_exit *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    if (get_current_pid() != *tpid) return 0;

    __u32 tid = get_current_tid();
    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval || oval->io_start_ns == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 duration = now - oval->io_start_ns;
    oval->total_io_ns += duration;

    struct off_cpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid          = *tpid;
        e->tid          = tid;
        e->off_start_ts = oval->io_start_ns;
        e->off_end_ts   = now;
        e->type         = EVENT_OFF_CPU;
        e->reason       = REASON_IO_WAIT;
        e->cpu          = bpf_get_smp_processor_id();
        bpf_ringbuf_submit(e, 0);
    }
    oval->io_start_ns   = 0;
    oval->active_reason = REASON_UNKNOWN;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int write_start(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    if (get_current_pid() != *tpid) return 0;

    __u32 tid = get_current_tid();
    struct off_cpu_val *oval = get_or_create_oval(tid);
    if (!oval) return 0;

    oval->io_start_ns   = bpf_ktime_get_ns();
    oval->active_reason = REASON_IO_WAIT;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int write_end(struct trace_event_raw_sys_exit *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    if (get_current_pid() != *tpid) return 0;

    __u32 tid = get_current_tid();
    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (!oval || oval->io_start_ns == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 duration = now - oval->io_start_ns;
    oval->total_io_ns += duration;

    struct off_cpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid          = *tpid;
        e->tid          = tid;
        e->off_start_ts = oval->io_start_ns;
        e->off_end_ts   = now;
        e->type         = EVENT_OFF_CPU;
        e->reason       = REASON_IO_WAIT;
        e->cpu          = bpf_get_smp_processor_id();
        bpf_ringbuf_submit(e, 0);
    }
    oval->io_start_ns   = 0;
    oval->active_reason = REASON_UNKNOWN;
    return 0;
}

/* ── SCHED_SWITCH ────────────────────────────────────────────────────── */

SEC("tracepoint/sched/sched_switch")
int off_cpu_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u32 prev_tid = BPF_CORE_READ(ctx, prev_pid);
    __u32 next_tid = BPF_CORE_READ(ctx, next_pid);
    __u64 ts = bpf_ktime_get_ns();

    /* Thread going OFF-CPU — check known_tids not target_pid */
    if (is_target_tid(prev_tid)) {
        struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &prev_tid);
        if (!oval) {
            struct off_cpu_val z = {};
            bpf_map_update_elem(&off_cpu_data, &prev_tid, &z, BPF_ANY);
            oval = bpf_map_lookup_elem(&off_cpu_data, &prev_tid);
        }
        if (oval) {
            oval->start_ns = ts;
            /* Only set SCHEDULER if no syscall probe already set a reason */
            if (oval->active_reason == REASON_UNKNOWN)
                oval->active_reason = REASON_SCHEDULER;
        }
    }

    /* Thread coming back ON-CPU */
    if (is_target_tid(next_tid)) {
        struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &next_tid);
        if (!oval || oval->start_ns == 0) return 0;

        __u64 duration = ts - oval->start_ns;

        /* Drop tiny preemptions < 100µs */
        if (duration < 100000ULL) {
            oval->start_ns      = 0;
            oval->active_reason = REASON_UNKNOWN;
            return 0;
        }

        oval->total_off_cpu_ns += duration;
        __u8 reason = oval->active_reason;

        /* Get pid from target_pid map for the event */
        __u32 key = 0;
        __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
        __u32 pid = tpid ? *tpid : 0;

        struct off_cpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid          = pid;
            e->tid          = next_tid;
            e->off_start_ts = oval->start_ns;
            e->off_end_ts   = ts;
            e->type         = EVENT_OFF_CPU;
            e->reason       = reason;
            e->cpu          = bpf_get_smp_processor_id();
            bpf_ringbuf_submit(e, 0);
        }

        oval->start_ns      = 0;
        oval->active_reason = REASON_UNKNOWN;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";