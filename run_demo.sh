#!/bin/bash
# =============================================================================
# run_demo.sh — Full demo orchestrator
#
# Starts demo app → starts profiler → runs metrics → kills profiler cleanly
#
# Usage (from project root):
#   sudo bash run_demo.sh <variant> [threads] [duration_sec]
#
# Examples:
#   sudo bash run_demo.sh demo_cpu
#   sudo bash run_demo.sh demo_sleep 8 60
#   sudo bash run_demo.sh demo_io_lock 16 45
#
# Arguments:
#   variant      : demo_cpu | demo_sleep | demo_io_lock
#   threads      : number of threads for demo app (default: 4)
#   duration_sec : how long demo app runs in seconds (default: 60)
#                  metrics are collected for (duration - 15) seconds
# =============================================================================

VARIANT=${1:?"Usage: sudo bash $0 <demo_cpu|demo_sleep|demo_io_lock> [threads] [duration_sec]"}
THREADS=${2:-4}
DURATION=${3:-60}

# Metrics collection = demo duration minus startup overhead
METRICS_DURATION=$(( DURATION - 15 ))
[ $METRICS_DURATION -lt 10 ] && METRICS_DURATION=10

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_APP="$SCRIPT_DIR/test/$VARIANT"
PROFILER="$SCRIPT_DIR/build_cmake/profiler"
METRICS_SCRIPT="$SCRIPT_DIR/measure_metrics.sh"
FUNCS="do_cpu_work,do_lock_work,do_sleep_work,do_io_work,worker_inner"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

log() { echo -e "$1"; }
separator() { log "${CYAN}$(printf '─%.0s' {1..65})${NC}"; }

# =============================================================================
# Sanity checks
# =============================================================================
separator
log "${BOLD}${CYAN}  eBPF PROFILER — DEMO ORCHESTRATOR${NC}"
separator

[ "$EUID" -ne 0 ] && {
    log "${RED}✘ Must run as root. Use: sudo bash $0 $*${NC}"
    exit 1
}

[ ! -f "$DEMO_APP" ] && {
    log "${RED}✘ Demo app not found: $DEMO_APP${NC}"
    log "${YELLOW}  Build it first: cd test && g++ -O2 -o $VARIANT ${VARIANT}.cpp -lpthread${NC}"
    exit 1
}

[ ! -f "$PROFILER" ] && {
    log "${RED}✘ Profiler not found: $PROFILER${NC}"
    log "${YELLOW}  Build it first from build_cmake/${NC}"
    exit 1
}

[ ! -f "$METRICS_SCRIPT" ] && {
    log "${RED}✘ measure_metrics.sh not found: $METRICS_SCRIPT${NC}"
    exit 1
}

log ""
log "  Variant   : ${YELLOW}$VARIANT${NC}"
log "  Threads   : ${YELLOW}$THREADS${NC}"
log "  Duration  : ${YELLOW}${DURATION}s${NC}"
log "  Metrics   : ${YELLOW}${METRICS_DURATION}s window${NC}"
log ""

# =============================================================================
# Cleanup handler — always kill profiler on exit/Ctrl+C
# =============================================================================
PROFILER_PID=""
TARGET_PID=""

cleanup() {
    log "\n${YELLOW}Cleaning up...${NC}"
    if [ -n "$PROFILER_PID" ] && kill -0 "$PROFILER_PID" 2>/dev/null; then
        log "  Stopping profiler (PID $PROFILER_PID)..."
        kill -INT "$PROFILER_PID" 2>/dev/null
        sleep 1
        kill -9  "$PROFILER_PID" 2>/dev/null
        log "  ${GREEN}Profiler stopped${NC}"
    fi
    if [ -n "$TARGET_PID" ] && kill -0 "$TARGET_PID" 2>/dev/null; then
        log "  Stopping demo app (PID $TARGET_PID)..."
        kill "$TARGET_PID" 2>/dev/null
        log "  ${GREEN}Demo app stopped${NC}"
    fi
    log ""
}
trap cleanup EXIT

# =============================================================================
# Step 1 — Start demo app
# =============================================================================
separator
log "${BOLD}[1/4] Starting demo app${NC}"
log "  Command : $DEMO_APP $THREADS $DURATION"

"$DEMO_APP" "$THREADS" "$DURATION" &
TARGET_PID=$!

sleep 0.5   # give it a moment to print its PID line

if ! kill -0 "$TARGET_PID" 2>/dev/null; then
    log "${RED}✘ Demo app failed to start${NC}"
    exit 1
fi

log "  ${GREEN}✔ Demo app running — PID: $TARGET_PID${NC}\n"

# =============================================================================
# Step 2 — Start profiler
# =============================================================================
separator
log "${BOLD}[2/4] Starting profiler${NC}"
log "  Command : $PROFILER $DEMO_APP --funcs \"$FUNCS\""

( cd "$SCRIPT_DIR/build_cmake" && \
  ./profiler "$DEMO_APP" --funcs "$FUNCS" \
      > "$SCRIPT_DIR/profiler_out.txt" 2>&1 ) &
PROFILER_PID=$!

sleep 2   # give profiler time to attach and write first stacks

if ! kill -0 "$PROFILER_PID" 2>/dev/null; then
    log "${RED}✘ Profiler failed to start. Check profiler_out.txt for errors:${NC}"
    tail -5 "$SCRIPT_DIR/profiler_out.txt"
    exit 1
fi

log "  ${GREEN}✔ Profiler running  — PID: $PROFILER_PID${NC}"
log "  Profiler output saved to: profiler_out.txt\n"

# =============================================================================
# Step 3 — Run metrics
# =============================================================================
separator
log "${BOLD}[3/4] Running metrics (${METRICS_DURATION}s)${NC}\n"

bash "$METRICS_SCRIPT" \
    "$TARGET_PID" \
    "$PROFILER_PID" \
    "$VARIANT" \
    "$METRICS_DURATION"

# =============================================================================
# Step 4 — Stop profiler (demo app exits on its own)
# =============================================================================
separator
log "${BOLD}[4/4] Stopping profiler${NC}"

if kill -0 "$PROFILER_PID" 2>/dev/null; then
    kill -INT "$PROFILER_PID" 2>/dev/null
    sleep 1
    kill -9  "$PROFILER_PID" 2>/dev/null
    PROFILER_PID=""   # prevent double-kill in cleanup
    log "  ${GREEN}✔ Profiler stopped${NC}"
fi

log "  Waiting for demo app to finish..."
wait "$TARGET_PID" 2>/dev/null
TARGET_PID=""
log "  ${GREEN}✔ Demo app exited${NC}"

separator
log "${GREEN}${BOLD}  All done! Check metrics_report_*.txt for results.${NC}"
separator