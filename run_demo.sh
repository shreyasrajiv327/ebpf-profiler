#!/bin/bash
cd "$(dirname "$0")/build_cmake"

# Compile test target if not present
if [ ! -f /tmp/test_target ]; then
    echo "Compiling test_target..."
    cat > /tmp/test_target.c << 'CSRC'
#include <stdio.h>
#include <unistd.h>
#include <math.h>

void compute() {
    double x = 0;
    for (long i = 0; i < 100000000L; i++)
        x += sqrt((double)i);
    printf("   result: %f\n", x);
}

void wait_a_bit() {
    printf(">> sleeping...\n");
    sleep(2);
}

void run_one_cycle() {
    printf(">> computing...\n");
    compute();
    wait_a_bit();
}

int main() {
    while (1) {
        run_one_cycle();
    }
    return 0;
}
CSRC
    gcc -O0 -g -fno-omit-frame-pointer /tmp/test_target.c -lm -o /tmp/test_target
    echo "Compiled OK"
fi

# Kill any previous instance
pkill test_target 2>/dev/null
sudo rm -f /sys/fs/bpf/profiler_off_cpu_data
sleep 0.2

# Start target
/tmp/test_target &
TARGET_PID=$!
echo "Started test_target with PID: $TARGET_PID"
sleep 0.5

# Run profiler
sudo ./profiler --pid $TARGET_PID --bin /tmp/test_target --funcs "run_one_cycle,compute,wait_a_bit"

# Cleanup on exit
pkill test_target 2>/dev/null
sudo rm -f /sys/fs/bpf/profiler_off_cpu_data
