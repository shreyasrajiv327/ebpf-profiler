#ifndef PROFILER_COMMON_H
#define PROFILER_COMMON_H

#define MAX_STACK_DEPTH  127
#define FUNC_NAME_LEN    64

enum event_type {
    EVENT_FUNC_ENTRY  = 1,
    EVENT_FUNC_EXIT   = 2,
    EVENT_OFF_CPU     = 3,
    EVENT_ON_CPU      = 4,
    EVENT_IO_START    = 5,
    EVENT_IO_END      = 6,
    EVENT_LOCK_START  = 7,
    EVENT_LOCK_END    = 8,
    EVENT_SLEEP_START = 9,
    EVENT_SLEEP_END   = 10,
};

struct profiler_event {
    __u32 pid;
    __u32 tid;
    __u32 func_id;
    __u32 type;
    __u64 timestamp_ns;
    __u64 duration_ns;
    __u64 on_cpu_ns;
    __u64 off_cpu_ns;
    /* breakdown of off-cpu reason */
    __u64 io_ns;           /* NEW */
    __u64 lock_ns;         /* NEW */
    __u64 sleep_ns;        /* NEW */
    __u32 cpu;
    __u32 pad;
    __s32 user_stack_id;
    __s32 kernel_stack_id;
};
/*
 * Shared between off_cpu.bpf.c and uprobe.bpf.c:
 * tracks when a thread went off-CPU and for how long
 */
struct off_cpu_val {
    __u64 start_ns;
    __u64 total_off_cpu_ns;
    /* off-CPU reason breakdown */
    __u64 total_io_ns;        /* time waiting for block I/O */
    __u64 total_lock_ns;      /* time waiting for locks */
    __u64 total_sleep_ns;     /* time in sleep/nanosleep */
    /* per-reason start timestamps */
    __u64 io_start_ns;
    __u64 lock_start_ns;
    __u64 sleep_start_ns;
};

/*
 * Tracks active function calls per thread
 * Key: tid, Value: entry info
 */
struct func_entry {
    __u64 entry_ts;
    __u32 func_id;
    __u32 pad;
    __s32 user_stack_id; 
};

#endif /* PROFILER_COMMON_H */