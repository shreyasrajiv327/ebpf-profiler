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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, struct off_cpu_val);
} off_cpu_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u64);
    __type(value, __u32);
} uprobe_metadata SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 8192);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} user_stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

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

    __u64 ip = PT_REGS_IP(ctx);
    __u32 *func_id_ptr = bpf_map_lookup_elem(&uprobe_metadata, &ip);
    if (!func_id_ptr) return 0;

    __u32 func_id = *func_id_ptr;
    __s32 stack_id = bpf_get_stackid(ctx, &user_stacks, BPF_F_USER_STACK);

    /* Take snapshot for derivation */
    struct off_cpu_val *oval = bpf_map_lookup_elem(&off_cpu_data, &tid);

    struct func_entry entry = {};
    entry.entry_ts      = bpf_ktime_get_ns();
    entry.func_id       = func_id;
    entry.user_stack_id = stack_id;

    if (oval) {
        entry.off_cpu_snapshot = oval->total_off_cpu_ns;
        entry.io_snapshot      = oval->total_io_ns;
        entry.lock_snapshot    = oval->total_lock_ns;
        entry.sleep_snapshot   = oval->total_sleep_ns;
    }

    bpf_map_update_elem(&func_entries, &tid, &entry, BPF_ANY);

    /* Emit entry event */
    struct profiler_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = pid;
        e->tid = tid;
        e->func_id = func_id;
        e->type = EVENT_FUNC_ENTRY;
        e->timestamp_ns = entry.entry_ts;
        e->entry_ts = entry.entry_ts;
        e->user_stack_id = stack_id;
        e->cpu = bpf_get_smp_processor_id();
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

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

    struct func_entry *fe = bpf_map_lookup_elem(&func_entries, &tid);
    if (!fe) return 0;

    __u64 exit_ts = bpf_ktime_get_ns();

    struct profiler_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = pid;
        e->tid = tid;
        e->func_id = fe->func_id;
        e->type = EVENT_FUNC_EXIT;
        e->timestamp_ns = exit_ts;
        e->entry_ts = fe->entry_ts;
        e->exit_ts = exit_ts;
        e->user_stack_id = fe->user_stack_id;
        e->cpu = bpf_get_smp_processor_id();
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&func_entries, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";