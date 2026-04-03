// SPDX-License-Identifier: GPL-2.0
#ifndef PROFILER_COMMON_H
#define PROFILER_COMMON_H

#ifdef __BPF__
typedef __u8  uint8_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
typedef __s32 int32_t;
#else
#include <stdint.h>
#endif

#define MAX_STACK_DEPTH 127

enum event_type {
    EVENT_FUNC_ENTRY = 1,
    EVENT_FUNC_EXIT  = 2,
    EVENT_OFF_CPU    = 3,
    EVENT_ON_CPU     = 4,
};

enum off_cpu_reason {
    REASON_UNKNOWN    = 0,
    REASON_IO_WAIT    = 1,
    REASON_LOCK       = 2,
    REASON_SLEEP      = 3,
    REASON_SCHEDULER  = 4,
};

struct profiler_event {
    uint32_t pid;
    uint32_t tid;
    uint32_t func_id;
    uint8_t  type;
    uint8_t  pad[3];
    uint64_t timestamp_ns;
    uint64_t entry_ts;
    uint64_t exit_ts;
    int32_t  user_stack_id;
    int32_t  kernel_stack_id;
    uint32_t cpu;
    uint32_t pad2;
} __attribute__((packed));

struct off_cpu_event {
    uint32_t pid;
    uint32_t tid;
    uint64_t off_start_ts;
    uint64_t off_end_ts;
    uint8_t  type;
    uint8_t  reason;
    uint8_t  pad[6];
    uint32_t cpu;
    uint32_t pad2;
} __attribute__((packed));

/* Added snapshot fields */
struct func_entry {
    uint64_t entry_ts;
    uint32_t func_id;
    int32_t  user_stack_id;

    uint64_t off_cpu_snapshot;
    uint64_t io_snapshot;
    uint64_t lock_snapshot;
    uint64_t sleep_snapshot;
};

struct off_cpu_val {
    uint64_t start_ns;
    uint8_t  active_reason;
    uint8_t  pad[7];

    /* Accumulation - this is what was missing */
    uint64_t total_off_cpu_ns;
    uint64_t total_io_ns;
    uint64_t total_lock_ns;
    uint64_t total_sleep_ns;

    uint64_t io_start_ns;
    uint64_t lock_start_ns;
    uint64_t sleep_start_ns;
};

#endif /* PROFILER_COMMON_H */