#include "derivation.hpp"
#include <algorithm>
#include <cstdio>

#include "derivation.hpp"
#include <algorithm>
#include <cstdio>

DerivationEngine::DerivationEngine(MetricsCallback callback)
    : metrics_callback_(std::move(callback))
{
    min_duration_ns_ = 0;      // No filtering during debugging
    min_off_cpu_ns_  = 500;    // Allow short off-CPU periods (0.5 µs)
}

void DerivationEngine::set_min_duration_ns(uint64_t min_ns) {
    min_duration_ns_ = min_ns;
}

void DerivationEngine::set_min_off_cpu_ns(uint64_t min_ns) {
    min_off_cpu_ns_ = min_ns;
}
/* ═══════════════════════════════════════════════════════════════════════
 * Process Function Entry
 * ═══════════════════════════════════════════════════════════════════════ */
void DerivationEngine::process_function_entry(const profiler_event& evt) {
    total_events_processed_++;
    auto& timeline = timelines_[evt.tid];
    timeline.tid = evt.tid;

    FunctionExecution exec;
    exec.func_id       = evt.func_id;
    exec.entry_ts      = evt.timestamp_ns;
    exec.user_stack_id = evt.user_stack_id;

    timeline.call_stack.push_back(exec);
    timeline.last_event_ts = evt.timestamp_ns;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Process Function Exit
 * ═════════════════════════════════════════════════════════════════════*/

void DerivationEngine::process_function_exit(const profiler_event& evt)
{
    total_events_processed_++;
    auto it = timelines_.find(evt.tid);
    if (it == timelines_.end()) {
        handle_error("Function exit without timeline", evt.tid);
        return;
    }

    auto& timeline = it->second;
    if (timeline.call_stack.empty()) {
        handle_error("Function exit without entry", evt.tid);
        return;
    }

    FunctionExecution exec = timeline.call_stack.back();
    timeline.call_stack.pop_back();

    // DEBUG: Check if entry_ts is reasonable
    if (exec.entry_ts == 0) {
        handle_error("Entry timestamp was 0", evt.tid);
    }

    derive_and_emit(evt.tid, exec, evt);
    timeline.last_event_ts = evt.timestamp_ns;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Process Off-CPU Event
 * ═════════════════════════════════════════════════════════════════════*/

void DerivationEngine::process_off_cpu_event(const off_cpu_event& evt)
{
    total_events_processed_++;
    auto& timeline = timelines_[evt.tid];
    timeline.tid = evt.tid;

    uint64_t duration = evt.off_end_ts - evt.off_start_ts;
    if (duration < min_off_cpu_ns_)
        return;

    if (!timeline.call_stack.empty()) {
        OffCpuPeriod period;
        period.start_ts = evt.off_start_ts;
        period.end_ts = evt.off_end_ts;
        period.reason = static_cast<OffCpuReason>(evt.reason);
        timeline.call_stack.back().off_cpu_periods.push_back(period);
    }
    // else: orphan off-CPU at start/end of profiling — ignore

    timeline.context_switches++;
    timeline.last_event_ts = evt.off_end_ts;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Process On-CPU Sample
 * ═════════════════════════════════════════════════════════════════════*/

void DerivationEngine::process_on_cpu_sample(const profiler_event& evt)
{
    total_events_processed_++;
    // TODO: Correlate with current function on stack for flamegraph weight
    // For now we just count them
    auto it = timelines_.find(evt.tid);
    if (it != timelines_.end()) {
        it->second.last_event_ts = evt.timestamp_ns;
    }
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Derive Metrics and Emit
 * ═════════════════════════════════════════════════════════════════════*/

void DerivationEngine::derive_and_emit(uint32_t tid,
                                       const FunctionExecution& exec,
                                       const profiler_event& exit_evt)
{
    uint64_t wall_ns = exit_evt.timestamp_ns - exec.entry_ts;

    // === DEBUG: Print raw timestamps ===
    printf("[DEBUG] func_id=%u  entry_ts=%llu  exit_ts=%llu  diff=%llu ns (%.3f ms)\n",
           exec.func_id,
           (unsigned long long)exec.entry_ts,
           (unsigned long long)exit_evt.timestamp_ns,
           (unsigned long long)wall_ns,
           wall_ns / 1e6);

    // if (wall_ns < min_duration_ns_) {
    //     dropped_short_calls_++;
    //     return;
    // }
    
    // Merge overlapping off-CPU periods
    auto merged_periods = merge_overlapping_periods(exec.off_cpu_periods);
    
    // Sum off-CPU time by reason
    uint64_t total_off_cpu = 0;
    uint64_t io_ns = 0;
    uint64_t lock_ns = 0;
    uint64_t sleep_ns = 0;
    uint64_t sched_ns = 0;
    
    for (const auto& period : merged_periods) {
        uint64_t dur = period.duration_ns();
        total_off_cpu += dur;
        
        switch (period.reason) {
            case OffCpuReason::IO_WAIT:
                io_ns += dur;
                break;
            case OffCpuReason::LOCK_CONTENTION:
                lock_ns += dur;
                break;
            case OffCpuReason::SLEEP:
                sleep_ns += dur;
                break;
            case OffCpuReason::SCHEDULER:
            case OffCpuReason::UNKNOWN:
            default:
                sched_ns += dur;
                break;
        }
    }
    
    // Derive on-CPU time (clamped to avoid negative)
    uint64_t on_cpu_ns = (total_off_cpu < wall_ns) 
        ? (wall_ns - total_off_cpu) 
        : 0;
    
    // If off-CPU exceeds wall time, something went wrong (clock skew?)
    if (total_off_cpu > wall_ns) {
        // Cap off-CPU to wall time and set on-CPU to zero
        total_off_cpu = wall_ns;
        on_cpu_ns = 0;
    }
    
    // Compute efficiency metrics
    double cpu_efficiency = (wall_ns > 0) 
        ? static_cast<double>(on_cpu_ns) / wall_ns 
        : 0.0;
    
    double blocking_ratio = (on_cpu_ns > 0)
        ? static_cast<double>(total_off_cpu) / on_cpu_ns
        : 0.0;
    
    // Build derived metrics
    DerivedFunctionMetrics metrics;
    metrics.func_id = exec.func_id;
    metrics.tid = tid;
    metrics.pid = exit_evt.pid;
    metrics.wall_time_ns = wall_ns;
    metrics.on_cpu_ns = on_cpu_ns;
    metrics.off_cpu_total_ns = total_off_cpu;
    metrics.io_wait_ns = io_ns;
    metrics.lock_contention_ns = lock_ns;
    metrics.sleep_ns = sleep_ns;
    metrics.scheduler_ns = sched_ns;
    metrics.cpu_efficiency = cpu_efficiency;
    metrics.blocking_ratio = blocking_ratio;
    metrics.user_stack_id = exec.user_stack_id;
    metrics.kernel_stack_id = exit_evt.kernel_stack_id;
    metrics.exit_ts = exit_evt.timestamp_ns;
    metrics.cpu = exit_evt.cpu;
    
    // Emit to metrics collector
    metrics_callback_(metrics);
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Merge Overlapping Off-CPU Periods
 * ═════════════════════════════════════════════════════════════════════*/

std::vector<OffCpuPeriod> DerivationEngine::merge_overlapping_periods(
    const std::vector<OffCpuPeriod>& periods)
{
    if (periods.empty()) {
        return {};
    }
    
    // Sort by start time
    std::vector<OffCpuPeriod> sorted = periods;
    std::sort(sorted.begin(), sorted.end(),
              [](const OffCpuPeriod& a, const OffCpuPeriod& b) {
                  return a.start_ts < b.start_ts;
              });
    
    std::vector<OffCpuPeriod> merged;
    OffCpuPeriod current = sorted[0];
    
    for (size_t i = 1; i < sorted.size(); i++) {
        if (sorted[i].start_ts <= current.end_ts) {
            // Overlapping - merge
            current.end_ts = std::max(current.end_ts, sorted[i].end_ts);
            // Keep the more specific reason (prefer IO > LOCK > SLEEP > UNKNOWN)
            if (sorted[i].reason < current.reason) {
                current.reason = sorted[i].reason;
            }
        } else {
            // No overlap - save current and start new
            merged.push_back(current);
            current = sorted[i];
        }
    }
    
    merged.push_back(current);
    return merged;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Error Handling
 * ═════════════════════════════════════════════════════════════════════*/

void DerivationEngine::handle_error(const std::string& msg, uint32_t tid) {
    error_count_++;
    fprintf(stderr, "[DerivationEngine ERROR] TID=%u: %s\n", tid, msg.c_str());
}