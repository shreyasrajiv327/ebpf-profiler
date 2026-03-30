#include "types.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>

/* ═══════════════════════════════════════════════════════════════════════
 *  Histogram Implementation
 * ═════════════════════════════════════════════════════════════════════*/

void Histogram::add_sample(uint64_t value) {
    samples_.push_back(value);
    sorted_ = false;
}

void Histogram::ensure_sorted() const{
    if (!sorted_ && !samples_.empty()) {
        std::sort(samples_.begin(), samples_.end());
        sorted_ = true;
    }
}

uint64_t Histogram::percentile(double p) const {
    if (samples_.empty()) return 0;
    
    ensure_sorted();
    
    if (p <= 0.0) return samples_.front();
    if (p >= 1.0) return samples_.back();
    
    double index = p * (samples_.size() - 1);
    size_t lower = static_cast<size_t>(std::floor(index));
    size_t upper = static_cast<size_t>(std::ceil(index));
    
    if (lower == upper) {
        return samples_[lower];
    }
    
    // Linear interpolation
    double weight = index - lower;
    return static_cast<uint64_t>(
        samples_[lower] * (1.0 - weight) + samples_[upper] * weight
    );
}

uint64_t Histogram::min() const {
    if (samples_.empty()) return 0;
    ensure_sorted();
    return samples_.front();
}

uint64_t Histogram::max() const {
    if (samples_.empty()) return 0;
    ensure_sorted();
    return samples_.back();
}

double Histogram::mean() const {
    if (samples_.empty()) return 0.0;
    
    uint64_t sum = std::accumulate(samples_.begin(), samples_.end(), 0ULL);
    return static_cast<double>(sum) / samples_.size();
}

uint64_t Histogram::count() const {
    return samples_.size();
}

void Histogram::clear() {
    samples_.clear();
    sorted_ = false;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  FunctionMetrics - Compute Derived Metrics
 * ═════════════════════════════════════════════════════════════════════*/

void FunctionMetrics::update_computed_metrics(double duration_sec) {
    if (call_count == 0) return;
    
    // Averages
    avg_wall_ms = (total_wall_ns / 1e6) / call_count;
    avg_on_cpu_ms = (total_on_cpu_ns / 1e6) / call_count;
    
    // Rates
    calls_per_sec = (duration_sec > 0.0) ? (call_count / duration_sec) : 0.0;
    
    // CPU utilization
    cpu_utilization_pct = (total_wall_ns > 0)
        ? (100.0 * total_on_cpu_ns / total_wall_ns)
        : 0.0;
    
    // Efficiency
    avg_cpu_efficiency = (total_wall_ns > 0)
        ? (static_cast<double>(total_on_cpu_ns) / total_wall_ns)
        : 0.0;
    
    avg_blocking_ratio = (total_on_cpu_ns > 0)
        ? (static_cast<double>(total_off_cpu_ns) / total_on_cpu_ns)
        : 0.0;
    
    // Off-CPU breakdown percentages
    if (total_off_cpu_ns > 0) {
        io_wait_pct = 100.0 * total_io_ns / total_off_cpu_ns;
        lock_contention_pct = 100.0 * total_lock_ns / total_off_cpu_ns;
        sleep_pct = 100.0 * total_sleep_ns / total_off_cpu_ns;
    } else {
        io_wait_pct = 0.0;
        lock_contention_pct = 0.0;
        sleep_pct = 0.0;
    }
    
    // Percentiles
    p50_wall_ns = wall_time_hist.percentile(0.50);
    p95_wall_ns = wall_time_hist.percentile(0.95);
    p99_wall_ns = wall_time_hist.percentile(0.99);
}