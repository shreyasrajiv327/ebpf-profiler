// SPDX-License-Identifier: GPL-2.0
/*
 * profiler_common.h - Shared definitions for BPF and userspace
 *
 * IMPORTANT: This file is included by BOTH BPF programs and userspace C++
 * Do NOT use standard library headers (stdint.h, stdio.h, etc.)
 */

#ifndef PROFILER_COMMON_H
#define PROFILER_COMMON_H

/* Use kernel types instead of stdint.h for BPF compatibility */
#ifdef __BPF__
/* BPF programs use kernel types from vmlinux.h */
typedef __u8  uint8_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
typedef __s32 int32_t;
#else
/* Userspace can use standard types */
#include <stdint.h>
#endif

#define MAX_STACK_DEPTH 127

/* ═══════════════════════════════════════════════════════════════════════
 *  Event Types
 * ═════════════════════════════════════════════════════════════════════*/

enum event_type {
    EVENT_FUNC_ENTRY  = 1,  /* Function entry event */
    EVENT_FUNC_EXIT   = 2,  /* Function exit (with raw timestamps) */
    EVENT_OFF_CPU     = 3,  /* Thread went off-CPU (blocking) */
    EVENT_ON_CPU      = 4,  /* On-CPU sample */
};

/* ═══════════════════════════════════════════════════════════════════════
 *  Off-CPU Reason Codes
 * ═════════════════════════════════════════════════════════════════════*/

enum off_cpu_reason {
    REASON_UNKNOWN    = 0,
    REASON_IO_WAIT    = 1,  /* Waiting for block I/O */
    REASON_LOCK       = 2,  /* Lock contention */
    REASON_SLEEP      = 3,  /* Explicit sleep/poll */
    REASON_SCHEDULER  = 4,  /* Generic scheduling delay */
};

/* ═══════════════════════════════════════════════════════════════════════
 *  Main Event Structure (for uprobe + on-cpu events)
 * ═════════════════════════════════════════════════════════════════════*/

struct profiler_event {
    uint32_t pid;
    uint32_t tid;
    uint32_t func_id;
    uint8_t  type;          /* event_type enum */
    uint8_t  pad[3];
    
    uint64_t timestamp_ns;  /* Event timestamp */
    
    /* Raw timestamps instead of computed durations */
    uint64_t entry_ts;      /* Function entry timestamp (for EXIT events) */
    uint64_t exit_ts;       /* Function exit timestamp */
    
    /* Stack traces */
    int32_t  user_stack_id;
    int32_t  kernel_stack_id;
    
    /* Context */
    uint32_t cpu;
    uint32_t pad2;
} __attribute__((packed));

/* ═══════════════════════════════════════════════════════════════════════
 *  Off-CPU Event Structure
 * ═════════════════════════════════════════════════════════════════════*/

struct off_cpu_event {
    uint32_t pid;
    uint32_t tid;
    
    uint64_t off_start_ts;  /* When thread went off-CPU */
    uint64_t off_end_ts;    /* When thread came back on-CPU */
    
    uint8_t  type;
    uint8_t  reason;        /* off_cpu_reason enum */
    uint8_t  pad[7];
    
    uint32_t cpu;           /* CPU where event occurred */
    uint32_t pad2;
} __attribute__((packed));

/* ═══════════════════════════════════════════════════════════════════════
 *  BPF Map Structures (used in kernel only)
 * ═════════════════════════════════════════════════════════════════════*/

struct func_entry {
    uint64_t entry_ts;
    uint32_t func_id;
    int32_t  user_stack_id;
};

/* Off-CPU tracking (simplified - less accumulation in kernel) */
struct off_cpu_val {
    uint64_t start_ns;       /* When went off-CPU */
    uint8_t  active_reason;  /* Current blocking reason */
    uint8_t  pad[7];
    
    /* Reason-specific start times (for nested tracking) */
    uint64_t io_start_ns;
    uint64_t lock_start_ns;
    uint64_t sleep_start_ns;
};

#endif /* PROFILER_COMMON_H */