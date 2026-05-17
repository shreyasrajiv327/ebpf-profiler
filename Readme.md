<div align="center">

# 🔬 eBPF Function-Level Profiler

**High-accuracy, function-level profiler for multithreaded Linux applications**

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL%202.0-blue.svg)](https://opensource.org/licenses/GPL-2.0)
[![Kernel](https://img.shields.io/badge/Kernel-5.8%2B-orange.svg)](https://kernel.org/)
[![Built with libbpf](https://img.shields.io/badge/Built%20with-libbpf%20%2B%20CO--RE-green.svg)](https://github.com/libbpf/libbpf)

Captures **wall time**, **on-CPU time** (with full stack traces), and a **detailed off-CPU breakdown** — mutex contention, I/O, sleeps, and scheduler preemptions — all via eBPF. No kernel modules. No `ptrace`.

[Quick Start](#-quick-start) · [Architecture](#-architecture) · [Output](#-output) · [Roadmap](#-roadmap)

</div>

---

## ✨ Features

| Category | Details |
|---|---|
| **Tracing** | Function-level via generic uprobes / uretprobes |
| **On-CPU** | ~1000 Hz sampling with full user + kernel stack traces |
| **Off-CPU** | Mutex/condvar (`futex`), sleeps (`nanosleep`), epoll (`epoll_pwait`), file & network I/O (`read`/`write`), scheduler preemptions (`sched_switch`) |
| **Threading** | Correct TID/TGID handling for multithreaded workloads |
| **ASLR** | Works with position-independent binaries |
| **Overhead** | Very low — only the target process is instrumented |
| **Visualization** | Flamegraphs (on-CPU & off-CPU) + live web dashboard |

---

## 🏗️ Architecture

```
Target Process (multithreaded)
    │
    ├── Uprobes (generic_entry / generic_exit)   → function boundaries
    ├── Tracepoints (sys_enter/exit_*)            → off-CPU sources
    └── Tracepoint (sched_switch)                → scheduler events
         │
         ▼
   3 BPF Objects → 3 Ring Buffers (64 MB each)
         │
         ▼
   Userspace C++ (libbpf)
         ├── DerivationEngine   — merges & buckets time periods
         ├── StackResolver      — produces folded stack traces
         └── Outputs
              ├── on_cpu.folded / off_cpu.folded  (flamegraphs)
              └── Live JSON Web UI on port 9000
```

### How It Works

1. **Startup** — Resolves target PID, binary path, and load base (ASLR-aware).
2. **Uprobes** — Attaches `generic_entry`/`generic_exit` on selected functions; uses the `uprobe_metadata` map to translate runtime addresses → function IDs.
3. **Off-CPU probes** — Attaches tracepoints for `futex`, `nanosleep`, `epoll_pwait`, `read`/`write`, and `sched_switch`.
4. **Multithreading** — A `known_tids` map registers every TID seen in syscall probes so `sched_switch` correctly identifies target threads.
5. **On-CPU sampling** — `perf_event` (CPU clock) fires at ~1000 Hz and captures full stack traces.
6. **DerivationEngine** — Merges overlapping off-CPU periods, applies heuristics, and computes wall time, on-CPU time, off-CPU time, CPU efficiency, and blocking ratio.
7. **Output** — Writes folded stacks and updates live JSON for the web UI.

---

## 📋 Prerequisites

- Linux kernel **5.8+** (CO-RE support required)
- `clang` + `llvm`
- `libbpf` development headers
- `libelf` + `zlib`
- **Root privileges** (required for loading eBPF programs and attaching uprobes)
- `flamegraph.pl` from [FlameGraph](https://github.com/brendangregg/FlameGraph) *(optional, for SVG generation)*

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Ubuntu / Debian
sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev
```

### 2. Build

```bash
# Build BPF objects
make bpf

# Build userspace
make
```

> BPF object paths can be overridden with `--uprobe-obj`, `--offcpu-obj`, and `--oncpu-obj` flags.

### 3. Run the Profiler

```bash
sudo ./profiler <process_name> --funcs "func1,func2,func3"
```

**Example — profiling Redis:**

```bash
sudo ./profiler redis-server --funcs "processCommand,lookupCommand,setCommand"
```

### 4. View Results

- **Terminal** — live statistics table, refreshes every second
- **Web UI** — open [http://localhost:9000](http://localhost:9000) for real-time metrics with pause/resume
- **Flamegraphs:**

```bash
flamegraph.pl < on_cpu.folded  > on_cpu.svg
flamegraph.pl < off_cpu.folded > off_cpu.svg
```

---

## ⚙️ Usage Options

```
Usage: ./profiler <process_name> --funcs "func1,func2,..."

Options:
  --funcs "f1,f2,f3"     Comma-separated list of functions to trace
  --uprobe-obj <path>    Path to uprobe.bpf.o     (default: uprobe.bpf.o)
  --offcpu-obj <path>    Path to off_cpu.bpf.o    (default: off_cpu.bpf.o)
  --oncpu-obj  <path>    Path to on_cpu.bpf.o     (default: on_cpu.bpf.o)
```

---

## 📂 Output

| File | Description | Time Basis |
|---|---|---|
| `on_cpu.folded` | Folded stacks for on-CPU flamegraph | On-CPU time |
| `off_cpu.folded` | Folded stacks for off-CPU flamegraph | Off-CPU time |
| `www/` | Live web dashboard assets | Real-time |

---


<div align="center">
Made with ❤️ using eBPF
</div>
