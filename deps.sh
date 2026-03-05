#!/usr/bin/env bash
# install_deps.sh — Install all build dependencies on Ubuntu 22.04
set -euo pipefail

echo "[+] Updating apt..."
sudo apt update

echo "[+] Installing build tools and BPF dependencies..."
sudo apt install -y \
    clang-14         \
    llvm-14          \
    libbpf-dev       \
    libelf-dev       \
    linux-tools-common \
    linux-tools-generic \
    bpftool          \
    cmake            \
    ninja-build      \
    g++              \
    pkg-config       \
    libz-dev

echo ""
echo "[+] Verifying BTF is available on this kernel..."
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "    ✓ /sys/kernel/btf/vmlinux exists — CO-RE will work"
else
    echo "    ✗ /sys/kernel/btf/vmlinux NOT found"
    echo "      Try: sudo apt install linux-image-$(uname -r)-dbg"
    echo "      Or boot with the HWE kernel: linux-generic-hwe-22.04"
fi

echo ""
echo "[+] Done. Build with:"
echo "    mkdir build && cd build"
echo "    cmake .. -G Ninja"
echo "    ninja"