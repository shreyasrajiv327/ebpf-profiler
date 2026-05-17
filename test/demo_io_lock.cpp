// demo_io_lock.cpp - eBPF PROFILER DEMO: HIGH IO + LOCK VARIANT
// Dominant workload: do_io_work (5x, large writes) + do_lock_work (4x, heavy contention)
// Minor workload:    do_cpu_work (1x, light loop), do_sleep_work (1x, very short)
// Expected flamegraph: do_io_work + do_lock_work dominate; mutex contention visible in lock analysis

#include <iostream>
#include <mutex>
#include <fstream>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <unistd.h>
#include <string>

std::mutex global_lock;
std::atomic<bool> running{true};
std::atomic<int> thread_counter{0};

// ====================== PROBED FUNCTIONS (extern "C" for uprobes) ======================

extern "C" void do_cpu_work() {
    // MINOR: short loop — token presence in profile only
    volatile double x = 0.0;
    for (int i = 0; i < 300000; ++i) x += i * 0.0001;
}

extern "C" void do_lock_work() {
    // HEAVY: many threads contending on global_lock simultaneously
    // With 12 threads each calling this 4x per iteration, contention is severe
    std::lock_guard<std::mutex> guard(global_lock);
    volatile int x = 0;
    for (int i = 0; i < 1200000; ++i) x += i;
}

extern "C" void do_sleep_work() {
    // MINOR: very short sleep, barely visible
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
}

extern "C" void do_io_work() {
    // HEAVY: large write payload per call to create real I/O pressure
    // 5 calls per iteration = significant syscall + disk activity
    std::ofstream f("demo_io.log", std::ios::app);
    if (f) {
        // Write a larger chunk to stress the I/O subsystem
        std::string payload(512, 'X');
        f << "IO pid=" << getpid()
          << " tid=" << std::this_thread::get_id()
          << " data=" << payload << "\n";
    }
}

// Call stack depth for flamegraph readability
extern "C" void worker_inner() {
    // IO called 5x — open/write/close syscalls visible in profiler
    do_io_work();
    do_io_work();
    do_io_work();
    do_io_work();
    do_io_work();
    // Lock called 4x — mutex wait time shows up in off-CPU / lock contention view
    do_lock_work();
    do_lock_work();
    do_lock_work();
    do_lock_work();
    // Others present once each — thin slivers
    do_cpu_work();
    do_sleep_work();
}

void worker_thread() {
    int tid = thread_counter.fetch_add(1);
    std::cout << "[THREAD " << tid << "] started (PID=" << getpid() << ")\n";
    while (running) {
        worker_inner();
        // Minimal pause — keep IO and lock pressure high
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

int main(int argc, char** argv) {
    int n_threads    = argc > 1 ? atoi(argv[1]) : 12;
    int duration_sec = argc > 2 ? atoi(argv[2]) : 45;

    std::cout << "=== eBPF PROFILER DEMO: HIGH IO + LOCK ===\n";
    std::cout << "PID = " << getpid() << "\n";
    std::cout << "Threads = " << n_threads << " | Duration = " << duration_sec << "s\n";
    std::cout << "Expected: do_io_work + do_lock_work dominate; mutex contention on global_lock\n";
    std::cout << "Probe: do_cpu_work, do_lock_work, do_sleep_work, do_io_work, worker_inner\n\n";
    std::cout << "Tip: run with higher thread count (e.g. 16) to amplify lock contention\n\n";

    std::vector<std::thread> threads;
    for (int i = 0; i < n_threads; ++i)
        threads.emplace_back(worker_thread);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(duration_sec);
    while (std::chrono::steady_clock::now() < deadline && running)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    running = false;
    for (auto& t : threads) t.join();

    std::cout << "\n=== Demo finished ===\n";
    std::cout << "Check profiler output + stacks.folded\n";
    return 0;
}