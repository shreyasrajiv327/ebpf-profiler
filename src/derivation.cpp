#include "derivation.hpp"
#include <algorithm>
#include <cstdio>

DerivationEngine::DerivationEngine(MetricsCallback callback)
    : metrics_callback_(std::move(callback))
{
    min_duration_ns_ = 0;
    min_off_cpu_ns_  = 500;
}

void DerivationEngine::set_min_duration_ns(uint64_t min_ns) { min_duration_ns_ = min_ns; }
void DerivationEngine::set_min_off_cpu_ns(uint64_t min_ns)  { min_off_cpu_ns_  = min_ns; }

/* ── Function Entry ─────────────────────────────────────────────────── */

void DerivationEngine::process_function_entry(const profiler_event &evt)
{
    total_events_processed_++;
    auto &timeline  = timelines_[evt.tid];
    timeline.tid    = evt.tid;

    FunctionExecution exec;
    exec.func_id       = evt.func_id;
    exec.entry_ts      = evt.timestamp_ns;
    exec.user_stack_id = evt.user_stack_id;

    timeline.call_stack.push_back(exec);
    timeline.last_event_ts = evt.timestamp_ns;
}

/* ── Function Exit ──────────────────────────────────────────────────── */

void DerivationEngine::process_function_exit(const profiler_event &evt)
{
    total_events_processed_++;

    auto it = timelines_.find(evt.tid);
    if (it == timelines_.end()) {
        handle_error("exit without timeline", evt.tid);
        return;
    }
    auto &timeline = it->second;
    if (timeline.call_stack.empty()) {
        handle_error("exit without entry", evt.tid);
        return;
    }

    FunctionExecution exec = timeline.call_stack.back();
    timeline.call_stack.pop_back();

    if (exec.entry_ts == 0)
        handle_error("entry_ts was 0", evt.tid);

    derive_and_emit(evt.tid, exec, evt);
    timeline.last_event_ts = evt.timestamp_ns;
}

/* ── Off-CPU Event ──────────────────────────────────────────────────── */

void DerivationEngine::process_off_cpu_event(const off_cpu_event &evt)
{
    total_events_processed_++;

    uint64_t duration = evt.off_end_ts - evt.off_start_ts;
    if (duration < min_off_cpu_ns_)
        return;

    auto &timeline = timelines_[evt.tid];
    timeline.tid   = evt.tid;

    if (!timeline.call_stack.empty()) {
        OffCpuPeriod period;
        period.start_ts = evt.off_start_ts;
        period.end_ts   = evt.off_end_ts;
        period.reason   = static_cast<OffCpuReason>(evt.reason);

        timeline.call_stack.back().off_cpu_periods.push_back(period);

        static const char *reason_names[] = {
            "UNKNOWN", "IO_WAIT", "LOCK", "SLEEP", "SCHEDULER"
        };
        const char *rname = (evt.reason < 5) ? reason_names[evt.reason] : "?";
        printf("[OFF-CPU] %.3f ms  reason=%-9s  func_id=%u  tid=%u\n",
               duration / 1e6, rname,
               timeline.call_stack.back().func_id, evt.tid);
    } else {
        printf("[OFF-CPU] %.3f ms  reason=%u  orphan (no active func)  tid=%u\n",
               duration / 1e6, evt.reason, evt.tid);
    }

    timeline.context_switches++;
    timeline.last_event_ts = evt.off_end_ts;
}

/* ── On-CPU Sample ──────────────────────────────────────────────────── */

void DerivationEngine::process_on_cpu_sample(const profiler_event &evt)
{
    total_events_processed_++;
    auto it = timelines_.find(evt.tid);
    if (it != timelines_.end())
        it->second.last_event_ts = evt.timestamp_ns;
}

/* ── Derive & Emit ──────────────────────────────────────────────────── */

void DerivationEngine::derive_and_emit(uint32_t tid,
                                       const FunctionExecution &exec,
                                       const profiler_event &exit_evt)
{
    uint64_t wall_ns = exit_evt.timestamp_ns - exec.entry_ts;

    auto merged = merge_overlapping_periods(exec.off_cpu_periods);

    uint64_t total_off = 0, io_ns = 0, lock_ns = 0, sleep_ns = 0, sched_ns = 0;

    for (const auto &p : merged) {
        uint64_t dur = p.duration_ns();
        total_off += dur;

        switch (p.reason) {
        case OffCpuReason::IO_WAIT:          io_ns    += dur; break;
        case OffCpuReason::LOCK_CONTENTION:  lock_ns  += dur; break;
        case OffCpuReason::SLEEP:            sleep_ns += dur; break;
        case OffCpuReason::SCHEDULER:        sched_ns += dur; break;
        /*
         * BUG FIX #6: UNKNOWN means the sched_switch fired but no syscall
         * probe ran first (e.g. voluntary preemption, page fault).
         * Do NOT classify by func_id — that was a test-only hack.
         * Treat as scheduler latency since we genuinely don't know.
         */
        case OffCpuReason::UNKNOWN:
        default:
            sched_ns += dur;
            break;
        }
    }

    uint64_t on_cpu_ns = (total_off < wall_ns) ? (wall_ns - total_off) : 0;

    DerivedFunctionMetrics m;
    m.func_id            = exec.func_id;
    m.tid                = tid;
    m.pid                = exit_evt.pid;
    m.wall_time_ns       = wall_ns;
    m.on_cpu_ns          = on_cpu_ns;
    m.off_cpu_total_ns   = total_off;
    m.io_wait_ns         = io_ns;
    m.lock_contention_ns = lock_ns;
    m.sleep_ns           = sleep_ns;
    m.scheduler_ns       = sched_ns;
    m.cpu_efficiency     = (wall_ns > 0) ? (double)on_cpu_ns / wall_ns : 0.0;
    m.blocking_ratio     = (on_cpu_ns > 0) ? (double)total_off / on_cpu_ns : 0.0;
    m.user_stack_id      = exec.user_stack_id;
    m.kernel_stack_id    = exit_evt.kernel_stack_id;
    m.exit_ts            = exit_evt.timestamp_ns;
    m.cpu                = exit_evt.cpu;

    metrics_callback_(m);
}

/* ── Merge Overlapping Periods ──────────────────────────────────────── */

std::vector<OffCpuPeriod> DerivationEngine::merge_overlapping_periods(
    const std::vector<OffCpuPeriod> &periods)
{
    if (periods.empty()) return {};

    auto sorted = periods;
    std::sort(sorted.begin(), sorted.end(),
              [](const OffCpuPeriod &a, const OffCpuPeriod &b) {
                  return a.start_ts < b.start_ts;
              });

    std::vector<OffCpuPeriod> merged;
    OffCpuPeriod cur = sorted[0];

    for (size_t i = 1; i < sorted.size(); i++) {
        if (sorted[i].start_ts <= cur.end_ts) {
            cur.end_ts = std::max(cur.end_ts, sorted[i].end_ts);
            /* Keep more specific reason: lower enum value = more specific */
            if (sorted[i].reason < cur.reason)
                cur.reason = sorted[i].reason;
        } else {
            merged.push_back(cur);
            cur = sorted[i];
        }
    }
    merged.push_back(cur);
    return merged;
}

/* ── Error Handling ─────────────────────────────────────────────────── */

void DerivationEngine::handle_error(const std::string &msg, uint32_t tid)
{
    error_count_++;
    fprintf(stderr, "[DerivationEngine] TID=%u: %s\n", tid, msg.c_str());
}