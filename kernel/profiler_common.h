#ifndef PROFILER_COMMON_H
#define PROFILER_COMMON_H

#define MAX_STACK_DEPTH  127
#define FUNC_NAME_LEN    64

enum event_type {
    EVENT_FUNC_ENTRY  = 1,   /* uprobe: function entered */
    EVENT_FUNC_EXIT   = 2,   /* uprobe: function exited  */
    EVENT_OFF_CPU     = 3,   /* kprobe: thread blocked   */
};

struct profiler_event {
    __u32 pid;
    __u32 tid;
    __u32 func_id;        /* index into function list userspace gave us */
    __u32 type;           /* enum event_type */
    __u64 timestamp_ns;   /* ktime_get_ns() at event time */
    __u64 duration_ns;    /* EXIT: total wall time, OFF_CPU: block duration */
    __u64 on_cpu_ns;      /* EXIT only: wall time minus off-cpu time */
    __u64 off_cpu_ns;     /* EXIT only: total time spent blocked */
    __u32 cpu;
    __u32 pad;
};

/*
 * Shared between off_cpu.bpf.c and uprobe.bpf.c:
 * tracks when a thread went off-CPU and for how long
 */
struct off_cpu_val {
    __u64 start_ns;
    __u64 total_off_cpu_ns;  /* accumulated off-cpu time for this thread */
};

/*
 * Tracks active function calls per thread
 * Key: tid, Value: entry info
 */
struct func_entry {
    __u64 entry_ts;          /* when function was entered */
    __u32 func_id;
    __u32 pad;
};

#endif /* PROFILER_COMMON_H */
