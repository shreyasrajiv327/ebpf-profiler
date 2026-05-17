// demo_sleep.cpp - eBPF PROFILER DEMO: HIGH SLEEP VARIANT
// Dominant workload: do_sleep_work (120ms sleep, called 5x per iteration)
// Minor workload:    do_cpu_work (1x, lighter loop), do_lock_work (1x), do_io_work (1x)
// Expected flamegraph: do_sleep_work dominates wall-clock; off-cpu analysis will show it clearly

#include <iostream>
#include <mutex>
#include <fstream>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <unistd.h>

std::mutex global_lock;
std::atomic<bool> running{true};
std::atomic<int> thread_counter{0};

// ====================== PROBED FUNCTIONS (extern "C" for uprobes) ======================

extern "C" void do_cpu_work() {
    // MINOR: lighter loop so it doesn't compete with sleep for wall-time
    volatile double x = 0.0;
    for (int i = 0; i < 500000; ++i) x += i * 0.0001;
}

extern "C" void do_lock_work() {
    // MINOR: present for signal, not dominant
    std::lock_guard<std::mutex> guard(global_lock);
    volatile int x = 0;
    for (int i = 0; i < 300000; ++i) x += i;
}

extern "C" void do_sleep_work() {
    // HEAVY: 120ms per call, called 5x = ~600ms blocked per iteration
    // Off-CPU profiler / nanosleep tracing will show this clearly
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
}

extern "C" void do_io_work() {
    // MINOR: single small write
    std::ofstream f("demo_io.log", std::ios::app);
    if (f) {
        f << "IO " << getpid() << "\n";
    }
}

// Call stack depth for flamegraph readability
extern "C" void worker_inner() {
    // Sleep called 5x — profiler should show threads mostly off-CPU here
    do_sleep_work();
    do_sleep_work();
    do_sleep_work();
    do_sleep_work();
    do_sleep_work();
    // Others present once each
    do_cpu_work();
    do_lock_work();
    do_io_work();
}

void worker_thread() {
    int tid = thread_counter.fetch_add(1);
    std::cout << "[THREAD " << tid << "] started (PID=" << getpid() << ")\n";
    while (running) {
        worker_inner();
        // Normal inter-iteration pause
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

int main(int argc, char** argv) {
    int n_threads    = argc > 1 ? atoi(argv[1]) : 12;
    int duration_sec = argc > 2 ? atoi(argv[2]) : 45;

    std::cout << "=== eBPF PROFILER DEMO: HIGH SLEEP ===\n";
    std::cout << "PID = " << getpid() << "\n";
    std::cout << "Threads = " << n_threads << " | Duration = " << duration_sec << "s\n";
    std::cout << "Expected: do_sleep_work dominates off-CPU / wall-clock profile\n";
    std::cout << "Probe: do_cpu_work, do_lock_work, do_sleep_work, do_io_work, worker_inner\n\n";

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