// test_app.cpp - Minimal Reliable Demo (shows all 4 functions clearly)
#include <iostream>
#include <mutex>
#include <fstream>
#include <chrono>
#include <random>
#include <atomic>      // ← REQUIRED for std::atomic
#include <unistd.h>    // for getpid()
#include <thread>      // for std::this_thread::sleep_for

std::mutex mtx;
std::atomic<bool> running{true};

// ====================== PROBED FUNCTIONS ======================

extern "C" void do_cpu_work() {
    std::cout << "[DEBUG] >>> do_cpu_work called (on-CPU)\n";
    for (volatile int i = 0; i < 1500000; ++i) {}
}

extern "C" void do_lock_work() {
    std::cout << "[DEBUG] >>> do_lock_work called (LOCK)\n";
    std::lock_guard<std::mutex> lock(mtx);
    for (volatile int i = 0; i < 800000; ++i) {}
}

extern "C" void do_sleep_work() {
    std::cout << "[DEBUG] >>> do_sleep_work called (SLEEP)\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(35));
}

extern "C" void do_io_work() {
    std::cout << "[DEBUG] >>> do_io_work called (IO)\n";
    std::lock_guard<std::mutex> lock(mtx);
    std::ofstream out("demo_io.log", std::ios::app);
    if (out) out << "IO at " << time(nullptr) << "\n";
}

// ======================================================================

int main() {
    std::cout << "=== Minimal Reliable Demo Started ===\n";
    std::cout << "PID = " << getpid() << "\n";
    std::cout << "Probe these 4 functions:\n";
    std::cout << "   do_cpu_work, do_lock_work, do_sleep_work, do_io_work\n\n";

    while (running) {
        do_cpu_work();
        do_lock_work();
        do_sleep_work();
        do_io_work();
        std::this_thread::sleep_for(std::chrono::milliseconds(8));
    }
    return 0;
}