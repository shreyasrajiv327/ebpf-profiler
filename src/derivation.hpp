#pragma once

#include "types.hpp"
#include "profiler_common.h"
#include <unordered_map>
#include <functional>
#include <optional>

/* ═══════════════════════════════════════════════════════════════════════
 *  DerivationEngine
 *  
 *  Takes raw events from BPF programs and derives:
 *  - On-CPU vs off-CPU time
 *  - Off-CPU reason breakdown
 *  - CPU efficiency metrics
 *  
 *  Strategy:
 *  1. Track function call stack per thread
 *  2. Accumulate off-CPU periods into current function
 *  3. On function exit, compute derived metrics
 * ═════════════════════════════════════════════════════════════════════*/

class DerivationEngine {
public:
    using MetricsCallback = std::function<void(const DerivedFunctionMetrics&)>;
    
    explicit DerivationEngine(MetricsCallback callback);
    
    // Process incoming events from ring buffers
    void process_function_entry(const profiler_event& evt);
    void process_function_exit(const profiler_event& evt);
    void process_off_cpu_event(const off_cpu_event& evt);
    void process_on_cpu_sample(const profiler_event& evt);
    
    // Configuration
    void set_min_duration_ns(uint64_t min_ns);
    void set_min_off_cpu_ns(uint64_t min_ns);
    
    // Stats
    uint64_t get_total_processed() const { return total_events_processed_; }
    uint64_t get_dropped_short_calls() const { return dropped_short_calls_; }
    uint64_t get_error_count() const { return error_count_; }
    
private:
    // Per-thread state
    std::unordered_map<uint32_t, ThreadTimeline> timelines_;
    
    // Callback to emit derived metrics
    MetricsCallback metrics_callback_;
    
    // Configuration
    uint64_t min_duration_ns_ = 0;      // Filter calls shorter than this
    uint64_t min_off_cpu_ns_ = 100000;  // Ignore off-CPU < 100μs (noise)
    
    // Statistics
    uint64_t total_events_processed_ = 0;
    uint64_t dropped_short_calls_ = 0;
    uint64_t error_count_ = 0;
    
    // Helper methods
    void derive_and_emit(uint32_t tid, const FunctionExecution& exec,
                        const profiler_event& exit_evt);
    
    std::vector<OffCpuPeriod> merge_overlapping_periods(
        const std::vector<OffCpuPeriod>& periods);
    
    void handle_error(const std::string& msg, uint32_t tid);
    // Add to private section of DerivationEngine:
struct PendingExit {
    uint32_t tid;
    FunctionExecution exec;
    profiler_event exit_evt;
    uint64_t queued_at_ns;  // monotonic ns when exit was received
};
std::vector<PendingExit> pending_exits_;
static constexpr uint64_t FLUSH_GRACE_NS = 5'000'000ULL; // 5ms grace window

public:
    void flush_pending(uint64_t now_ns);  // call after all rb polls
};