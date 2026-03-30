// SPDX-License-Identifier: GPL-2.0

/*
 * on_cpu.bpf.c — On-CPU profiling via perf_event sampling (~99 Hz).
 *
 * Attaches to perf_event (PERF_TYPE_SOFTWARE / PERF_COUNT_SW_CPU_CLOCK).
 * On each sample, checks if the current PID matches our target, then
 * pushes a profiler_event into the ring buffer.
 *
 * Build:
 *   clang-14 -target bpf -O2 -g \
 *     -D__TARGET_ARCH_x86 \
 *     -I./kernel \
 *     -I/usr/include/bpf \
 *     -c kernel/on_cpu.bpf.c -o build/on_cpu.bpf.o
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "profiler_common.h"

char LICENSE[] SEC("license") = "GPL";

/* ------------------------------------------------------------------ */
/*  BPF maps                                                           */
/* ------------------------------------------------------------------ */

/*
 * target_pid — single-element array holding the PID to profile.
 * Userspace writes [0] = target PID before attaching the program.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       __u32);
} target_pid SEC(".maps");

/*
 * user_stacks / kernel_stacks — stack-trace maps.
 * bpf_get_stackid() hashes the stack and returns an ID we store in the
 * event; userspace resolves the IPs later via bpf_map_lookup_elem().
 */
struct {
    __uint(type,        BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 8192);
    __uint(key_size,    sizeof(__u32));
    __uint(value_size,  MAX_STACK_DEPTH * sizeof(__u64));
} user_stacks SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 8192);
    __uint(key_size,    sizeof(__u32));
    __uint(value_size,  MAX_STACK_DEPTH * sizeof(__u64));
} kernel_stacks SEC(".maps");

/*
 * rb — ring buffer for on-CPU events.
 * 64 MB; userspace drains it with ring_buffer__poll().
 */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} rb SEC(".maps");

/* ------------------------------------------------------------------ */
/*  Perf-event program                                                 */
/* ------------------------------------------------------------------ */

SEC("perf_event")
int on_cpu_sample(struct bpf_perf_event_data *ctx)
{
    /* --- PID filter ------------------------------------------------ */
    __u32 zero = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &zero);
    if (!tpid)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32; /* process ID */
    __u32 tid = (__u32)pid_tgid; /* thread ID */

    if (tgid != *tpid)
        return 0;

    /* --- Reserve ring-buffer slot ---------------------------------- */
    struct profiler_event *e =
        bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* --- Populate event -------------------------------------------- */
    e->pid = tgid;
    e->tid = tid;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->type = EVENT_ON_CPU;

    /* V2 compatible fields */
    e->func_id = 0;           /* not applicable for on-CPU samples */
    e->entry_ts = 0;
    e->exit_ts = 0;

    /* Stack traces */
    e->user_stack_id = bpf_get_stackid(ctx, &user_stacks, BPF_F_USER_STACK);
    e->kernel_stack_id = bpf_get_stackid(ctx, &kernel_stacks, 0);

    /* Context */
    e->cpu = bpf_get_smp_processor_id();
    e->pad2 = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}