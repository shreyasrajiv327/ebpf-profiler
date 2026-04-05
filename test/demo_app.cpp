// demo_app.cpp - PROFESSOR-READY eBPF PROFILER DEMO
#include <iostream>
#include <mutex>
#include <fstream>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <unistd.h>
#include <random>

std::mutex global_lock;
std::atomic<bool> running{true};
std::atomic<int> thread_counter{0};

// ====================== PROBED FUNCTIONS (extern "C" for uprobes) ======================

extern "C" void do_cpu_work() {
    // Simulate heavy computation
    volatile double x = 0.0;
    for (int i = 0; i < 2500000; ++i) x += i * 0.0001;
}

extern "C" void do_lock_work() {
    std::lock_guard<std::mutex> guard(global_lock);
    // Contended lock + some work
    volatile int x = 0;
    for (int i = 0; i < 1200000; ++i) x += i;
}

extern "C" void do_sleep_work() {
    // Realistic sleep (nanosleep under the hood)
    std::this_thread::sleep_for(std::chrono::milliseconds(42));
}

extern "C" void do_io_work() {
    // File I/O (will generate real block I/O events)
    std::lock_guard<std::mutex> guard(global_lock);  // extra contention
    std::ofstream f("demo_io.log", std::ios::app);
    if (f) {
        f << "IO[" << getpid() << ":" << std::this_thread::get_id() << "] t=" 
          << std::chrono::system_clock::now().time_since_epoch().count() << "\n";
    }
}

// Helper to create nice call-stack depth for flamegraphs
extern "C" void worker_inner() {
    do_cpu_work();
    do_lock_work();
    do_sleep_work();
    do_io_work();
}

void worker_thread() {
    int tid = thread_counter.fetch_add(1);
    std::cout << "[THREAD " << tid << "] started (PID=" << getpid() << ")\n";

    while (running) {
        worker_inner();                    // nice stack depth
        std::this_thread::sleep_for(std::chrono::milliseconds(3));
    }
}

int main(int argc, char** argv) {
    int n_threads = argc > 1 ? atoi(argv[1]) : 12;
    int duration_sec = argc > 2 ? atoi(argv[2]) : 45;

    std::cout << "=== eBPF PROFILER FINAL DEMO APP ===\n";
    std::cout << "PID = " << getpid() << "\n";
    std::cout << "Threads = " << n_threads << " | Duration = " << duration_sec << "s\n";
    std::cout << "Probe these functions:\n";
    std::cout << "   do_cpu_work, do_lock_work, do_sleep_work, do_io_work, worker_inner\n\n";

    std::vector<std::thread> threads;
    for (int i = 0; i < n_threads; ++i) {
        threads.emplace_back(worker_thread);
    }

    // Let it run
    std::this_thread::sleep_for(std::chrono::seconds(duration_sec));

    running = false;
    for (auto& t : threads) t.join();

    std::cout << "\n=== Demo finished ===\n";
    std::cout << "Check your profiler output + stacks.folded\n";
    return 0;
}