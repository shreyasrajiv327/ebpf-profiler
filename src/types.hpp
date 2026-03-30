#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <optional>

/* ═══════════════════════════════════════════════════════════════════════
 *  Core Types for Userspace Processing
 * ═════════════════════════════════════════════════════════════════════*/

enum class OffCpuReason : uint8_t {
    UNKNOWN = 0,
    IO_WAIT = 1,
    LOCK_CONTENTION = 2,
    SLEEP = 3,
    SCHEDULER = 4
};

/* ─────────────────────────────────────────────────────────────────────
 *  Off-CPU Period
 * ───────────────────────────────────────────────────────────────────── */

struct OffCpuPeriod {
    uint64_t start_ts;
    uint64_t end_ts;
    OffCpuReason reason;
    
    uint64_t duration_ns() const { return end_ts - start_ts; }
};

/* ─────────────────────────────────────────────────────────────────────
 *  Function Execution (in-flight call tracking)
 * ───────────────────────────────────────────────────────────────────── */

struct FunctionExecution {
    uint32_t func_id;
    uint64_t entry_ts;
    int32_t  user_stack_id;
    
    // Off-CPU periods that occurred during this function call
    std::vector<OffCpuPeriod> off_cpu_periods;
};

/* ─────────────────────────────────────────────────────────────────────
 *  Thread Timeline (execution state per thread)
 * ───────────────────────────────────────────────────────────────────── */

struct ThreadTimeline {
    uint32_t tid;
    
    // Call stack (nested function invocations)
    std::vector<FunctionExecution> call_stack;
    
    // Current state
    bool is_on_cpu = true;
    uint64_t last_event_ts = 0;
    
    // Stats
    uint64_t context_switches = 0;
};

/* ═══════════════════════════════════════════════════════════════════════
 *  Derived Metrics (output from derivation engine)
 * ═════════════════════════════════════════════════════════════════════*/

struct DerivedFunctionMetrics {
    uint32_t func_id;
    uint32_t tid;
    uint32_t pid;
    
    // Time breakdown
    uint64_t wall_time_ns;
    uint64_t on_cpu_ns;
    uint64_t off_cpu_total_ns;
    
    // Off-CPU breakdown by reason
    uint64_t io_wait_ns;
    uint64_t lock_contention_ns;
    uint64_t sleep_ns;
    uint64_t scheduler_ns;
    
    // Derived ratios
    double cpu_efficiency;     // on_cpu / wall_time
    double blocking_ratio;     // off_cpu / on_cpu
    
    // Context
    int32_t  user_stack_id;
    int32_t  kernel_stack_id;
    uint64_t exit_ts;
    uint32_t cpu;
};

/* ═══════════════════════════════════════════════════════════════════════
 *  Histogram (for percentile calculations)
 * ═════════════════════════════════════════════════════════════════════*/

class Histogram {
public:
    void add_sample(uint64_t value);
    uint64_t percentile(double p) const;  // p in [0, 1]
    uint64_t min() const;
    uint64_t max() const;
    double mean() const;
    uint64_t count() const;
    void clear();
    
private:
    mutable std::vector<uint64_t> samples_;
    mutable bool sorted_ = false;
    
    void ensure_sorted() const;
};

/* ═══════════════════════════════════════════════════════════════════════
 *  Aggregated Metrics (for metrics collector)
 * ═════════════════════════════════════════════════════════════════════*/

struct FunctionMetrics {
    uint32_t func_id;
    std::string name;
    
    // Call statistics
    uint64_t call_count = 0;
    uint64_t total_wall_ns = 0;
    uint64_t total_on_cpu_ns = 0;
    uint64_t total_off_cpu_ns = 0;
    
    // Off-CPU breakdown
    uint64_t total_io_ns = 0;
    uint64_t total_lock_ns = 0;
    uint64_t total_sleep_ns = 0;
    uint64_t total_sched_ns = 0;
    
    // Latency distribution
    mutable Histogram wall_time_hist;
    mutable Histogram on_cpu_hist;
    
    // Computed metrics
    double avg_wall_ms = 0.0;
    double avg_on_cpu_ms = 0.0;
    double cpu_utilization_pct = 0.0;  // on_cpu / wall
    double calls_per_sec = 0.0;
    
    // Efficiency metrics
    double avg_cpu_efficiency = 0.0;
    double avg_blocking_ratio = 0.0;
    
    // Off-CPU breakdown percentages
    double io_wait_pct = 0.0;
    double lock_contention_pct = 0.0;
    double sleep_pct = 0.0;
    
    // Latency percentiles (cached)
    uint64_t p50_wall_ns = 0;
    uint64_t p95_wall_ns = 0;
    uint64_t p99_wall_ns = 0;
    
    // Concurrency
    uint32_t max_concurrent_calls = 0;
    uint32_t current_concurrent_calls = 0;
    
    void update_computed_metrics(double duration_sec);
};

struct ThreadMetrics {
    uint32_t tid;
    
    // Execution time
    uint64_t total_on_cpu_ns = 0;
    uint64_t total_off_cpu_ns = 0;
    
    // Breakdown
    uint64_t total_io_ns = 0;
    uint64_t total_lock_ns = 0;
    uint64_t total_sleep_ns = 0;
    
    // Thread state distribution
    double cpu_busy_pct = 0.0;
    double io_wait_pct = 0.0;
    double lock_wait_pct = 0.0;
    
    // Scheduling
    uint64_t context_switches = 0;
};

struct GlobalMetrics {
    // Event counts
    uint64_t total_function_entries = 0;
    uint64_t total_function_exits = 0;
    uint64_t total_off_cpu_events = 0;
    uint64_t total_on_cpu_samples = 0;
    
    // Processing performance
    uint64_t events_per_sec = 0;
    uint64_t ring_buffer_drops = 0;
    double processing_latency_us = 0.0;
    
    // System-wide
    double overall_cpu_utilization = 0.0;
    double profiler_overhead_pct = 0.0;
    
    // Resource usage
    uint64_t memory_usage_mb = 0;
    
    // Coverage
    uint64_t unique_functions_seen = 0;
    uint64_t unique_stacks_seen = 0;
};