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

/*
 * attach_seq: incremented by userspace before each attach.
 * Key = 0 → current sequence number = func_id
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} func_id_override SEC(".maps");

/*
 * func_entries: key = tid, value = {entry_ts, func_id}
 * Written on entry, read+deleted on exit.
 */
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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

/* ── func 0 entry/exit ──────────────────────────────────────────────── */
SEC("uprobe/func0_entry")
int func0_entry(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    if (pid != *tpid) return 0;

    struct func_entry e = {};
    e.entry_ts = bpf_ktime_get_ns();
    e.func_id  = 0;
    bpf_map_update_elem(&func_entries, &tid, &e, BPF_ANY);

    struct off_cpu_val reset = {};
    bpf_map_update_elem(&off_cpu_data, &tid, &reset, BPF_ANY);
    return 0;
}

SEC("uretprobe/func0_exit")
int func0_exit(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    if (pid != *tpid) return 0;

    struct func_entry *fe = bpf_map_lookup_elem(&func_entries, &tid);
    if (!fe || fe->func_id != 0) return 0;

    __u64 exit_ts  = bpf_ktime_get_ns();
    __u64 total_ns = exit_ts - fe->entry_ts;

    __u64 off_cpu_ns = 0;
    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (oval) off_cpu_ns = oval->total_off_cpu_ns;

    __u64 on_cpu_ns = (off_cpu_ns < total_ns) ? (total_ns - off_cpu_ns) : 0;

    struct profiler_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev) {
        ev->pid = pid; ev->tid = tid; ev->func_id = 0;
        ev->type = EVENT_FUNC_EXIT;
        ev->timestamp_ns = exit_ts;
        ev->duration_ns  = total_ns;
        ev->on_cpu_ns    = on_cpu_ns;
        ev->off_cpu_ns   = off_cpu_ns;
        ev->cpu = bpf_get_smp_processor_id();
        ev->pad = 0;
        bpf_ringbuf_submit(ev, 0);
    }
    bpf_map_delete_elem(&func_entries, &tid);
    return 0;
}

/* ── func 1 entry/exit ──────────────────────────────────────────────── */
SEC("uprobe/func1_entry")
int func1_entry(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    if (pid != *tpid) return 0;

    struct func_entry e = {};
    e.entry_ts = bpf_ktime_get_ns();
    e.func_id  = 1;
    bpf_map_update_elem(&func_entries, &tid, &e, BPF_ANY);

    struct off_cpu_val reset = {};
    bpf_map_update_elem(&off_cpu_data, &tid, &reset, BPF_ANY);
    return 0;
}

SEC("uretprobe/func1_exit")
int func1_exit(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    if (pid != *tpid) return 0;

    struct func_entry *fe = bpf_map_lookup_elem(&func_entries, &tid);
    if (!fe || fe->func_id != 1) return 0;

    __u64 exit_ts  = bpf_ktime_get_ns();
    __u64 total_ns = exit_ts - fe->entry_ts;

    __u64 off_cpu_ns = 0;
    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (oval) off_cpu_ns = oval->total_off_cpu_ns;

    __u64 on_cpu_ns = (off_cpu_ns < total_ns) ? (total_ns - off_cpu_ns) : 0;

    struct profiler_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev) {
        ev->pid = pid; ev->tid = tid; ev->func_id = 1;
        ev->type = EVENT_FUNC_EXIT;
        ev->timestamp_ns = exit_ts;
        ev->duration_ns  = total_ns;
        ev->on_cpu_ns    = on_cpu_ns;
        ev->off_cpu_ns   = off_cpu_ns;
        ev->cpu = bpf_get_smp_processor_id();
        ev->pad = 0;
        bpf_ringbuf_submit(ev, 0);
    }
    bpf_map_delete_elem(&func_entries, &tid);
    return 0;
}

/* ── func 2 entry/exit ──────────────────────────────────────────────── */
SEC("uprobe/func2_entry")
int func2_entry(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    if (pid != *tpid) return 0;

    struct func_entry e = {};
    e.entry_ts = bpf_ktime_get_ns();
    e.func_id  = 2;
    bpf_map_update_elem(&func_entries, &tid, &e, BPF_ANY);

    struct off_cpu_val reset = {};
    bpf_map_update_elem(&off_cpu_data, &tid, &reset, BPF_ANY);
    return 0;
}

SEC("uretprobe/func2_exit")
int func2_exit(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    if (pid != *tpid) return 0;

    struct func_entry *fe = bpf_map_lookup_elem(&func_entries, &tid);
    if (!fe || fe->func_id != 2) return 0;

    __u64 exit_ts  = bpf_ktime_get_ns();
    __u64 total_ns = exit_ts - fe->entry_ts;

    __u64 off_cpu_ns = 0;
    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);
    if (oval) off_cpu_ns = oval->total_off_cpu_ns;

    __u64 on_cpu_ns = (off_cpu_ns < total_ns) ? (total_ns - off_cpu_ns) : 0;

    struct profiler_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev) {
        ev->pid = pid; ev->tid = tid; ev->func_id = 2;
        ev->type = EVENT_FUNC_EXIT;
        ev->timestamp_ns = exit_ts;
        ev->duration_ns  = total_ns;
        ev->on_cpu_ns    = on_cpu_ns;
        ev->off_cpu_ns   = off_cpu_ns;
        ev->cpu = bpf_get_smp_processor_id();
        ev->pad = 0;
        bpf_ringbuf_submit(ev, 0);
    }
    bpf_map_delete_elem(&func_entries, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
