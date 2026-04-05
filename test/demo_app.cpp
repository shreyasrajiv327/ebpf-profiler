// demo_app.cpp - eBPF profiler test app
// Each function cleanly exercises exactly one off-CPU category.
//
// Build:
//   g++ -O0 -g -fno-omit-frame-pointer -o demo_app demo_app.cpp -lpthread
//
// Run:
//   ./demo_app [n_threads] [duration_sec]
//
// Profile with:
//   sudo ./profiler demo_app \
//     --funcs "do_cpu_work,do_lock_work,do_sleep_work,do_io_work,worker_inner"

#include <iostream>
#include <mutex>
#include <fstream>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>

/* Separate mutexes so lock and IO don't interfere with each other */
std::mutex lock_mutex;
std::mutex io_mutex;

std::atomic<bool>  running{true};
std::atomic<int>   thread_counter{0};

/* ─── PROBED FUNCTIONS ──────────────────────────────────────────────────
 *
 *  extern "C" is critical — prevents C++ name mangling so your ELF
 *  symbol lookup (find_symbol_offset) can find them by plain name.
 *
 *  -O0 and -fno-omit-frame-pointer are critical for correct uprobes
 *  and stack unwinding.
 * ────────────────────────────────────────────────────────────────────── */

/* CATEGORY: ON-CPU
 * Pure computation, no syscalls, no blocking.
 * Should show up as ~100% cpu_efficiency in the profiler.
 */
extern "C" void do_cpu_work()
{
    volatile double x = 0.0;
    for (int i = 0; i < 2500000; ++i)
        x += i * 0.0001;
    (void)x;
}

/* CATEGORY: LOCK (REASON_LOCK)
 * Acquires a mutex that other threads are also trying to acquire.
 * With 12 threads this will be heavily contended.
 * The futex enter/exit probes should classify this as REASON_LOCK.
 *
 * NOTE: No I/O inside here — we keep concerns separated.
 */
extern "C" void do_lock_work()
{
    std::lock_guard<std::mutex> guard(lock_mutex);
    /* Small amount of work while holding the lock */
    volatile int x = 0;
    for (int i = 0; i < 500000; ++i)
        x += i;
    (void)x;
}

/* CATEGORY: SLEEP (REASON_SLEEP)
 * Calls nanosleep directly. The nanosleep_start/nanosleep_end
 * probes should classify this as REASON_SLEEP.
 * 42ms is long enough to clearly show up in the profiler output.
 */
extern "C" void do_sleep_work()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(42));
}

/* CATEGORY: I/O WAIT (REASON_IO_WAIT)
 *
 * KEY FIX: We use fsync() to force the kernel to flush to disk.
 * Without fsync, writes go to the page cache and return immediately
 * — no blocking, no block_rq_insert event, profiler sees nothing.
 *
 * We also use a separate io_mutex, not the same one as do_lock_work,
 * so the futex time here is minimal and doesn't pollute the I/O bucket.
 *
 * The read() syscall at the end also generates REASON_IO_WAIT via
 * the sys_enter_read probe.
 */
extern "C" void do_io_work()
{
    {
        std::lock_guard<std::mutex> guard(io_mutex);  /* very low contention */

        /* Open with O_SYNC to guarantee each write blocks on disk */
        int fd = open("demo_io.log", O_WRONLY | O_CREAT | O_APPEND | O_SYNC, 0644);
        if (fd < 0) return;

        char buf[128];
        int n = snprintf(buf, sizeof(buf),
                         "IO pid=%d tid=%lu\n",
                         (int)getpid(),
                         (unsigned long)pthread_self());
        write(fd, buf, n);

        /* fsync forces a real block I/O flush — triggers block_rq_insert */
        fsync(fd);
        close(fd);
    }

    /* Also do a read so sys_enter_read fires */
    int fd = open("demo_io.log", O_RDONLY);
    if (fd >= 0) {
        char rbuf[256];
        read(fd, rbuf, sizeof(rbuf));
        close(fd);
    }
}

/* ─── CALL STACK DEPTH ───────────────────────────────────────────────
 * worker_inner calls all 4 functions in sequence.
 * This gives the profiler a realistic nested call stack to attribute
 * off-CPU periods to the correct enclosing frame.
 *
 * Expected profiler output for worker_inner:
 *   wall   ≈ cpu_work + lock_wait + 42ms_sleep + io_wait
 *   oncpu  ≈ cpu_work time only
 *   lock   ≈ time spent blocked in lock_mutex.lock()
 *   sleep  ≈ ~42ms
 *   io     ≈ fsync + read block time
 *   sched  ≈ small residual preemption noise
 */
extern "C" void worker_inner()
{
    do_cpu_work();
    do_lock_work();
    do_sleep_work();
    do_io_work();
}

/* ─── WORKER THREAD ─────────────────────────────────────────────────── */

void worker_thread()
{
    int tid = thread_counter.fetch_add(1);
    std::cout << "[THREAD " << tid << "] started\n";

    while (running) {
        worker_inner();
        /* Small gap between iterations so the profiler can see
         * clean entry/exit boundaries on worker_inner */
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    std::cout << "[THREAD " << tid << "] done\n";
}

/* ─── MAIN ──────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    int n_threads    = (argc > 1) ? atoi(argv[1]) : 4;
    int duration_sec = (argc > 2) ? atoi(argv[2]) : 45;

    /* 4 threads is enough to see lock contention without overwhelming it.
     * You can increase to 12 once you've verified basic classification works. */

    std::cout << "=== eBPF Profiler Demo App ===\n";
    std::cout << "PID      = " << getpid()      << "\n";
    std::cout << "Threads  = " << n_threads      << "\n";
    std::cout << "Duration = " << duration_sec   << "s\n\n";
    std::cout << "Probe these functions:\n";
    std::cout << "  do_cpu_work do_lock_work do_sleep_work do_io_work worker_inner\n\n";
    std::cout << "Expected classification:\n";
    std::cout << "  do_cpu_work   → high on-CPU,  ~0 off-CPU\n";
    std::cout << "  do_lock_work  → off-CPU reason=LOCK\n";
    std::cout << "  do_sleep_work → off-CPU reason=SLEEP (~42ms each call)\n";
    std::cout << "  do_io_work    → off-CPU reason=IO_WAIT\n";
    std::cout << "  worker_inner  → mix of all above\n\n";
    std::cout << "Run profiler with:\n";
    std::cout << "  sudo ./profiler demo_app \\\n";
    std::cout << "    --funcs \"do_cpu_work,do_lock_work,do_sleep_work,do_io_work,worker_inner\"\n\n";

    std::vector<std::thread> threads;
    threads.reserve(n_threads);
    for (int i = 0; i < n_threads; ++i)
        threads.emplace_back(worker_thread);

    std::this_thread::sleep_for(std::chrono::seconds(duration_sec));
    running = false;

    for (auto &t : threads) t.join();

    std::cout << "\n=== Done ===\n";
    return 0;
}