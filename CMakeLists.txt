cmake_minimum_required(VERSION 3.20)
project(ebpf-profiler LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Find dependencies ────────────────────────────────────────────────────
find_library(LIBBPF_LIB NAMES bpf REQUIRED)
find_library(LIBELF_LIB NAMES elf REQUIRED)
find_library(LIBZ_LIB NAMES z REQUIRED)
find_path(LIBBPF_INCLUDE NAMES bpf/libbpf.h REQUIRED)

message(STATUS "libbpf : ${LIBBPF_LIB}")
message(STATUS "libelf : ${LIBELF_LIB}")
message(STATUS "libz   : ${LIBZ_LIB}")

# ── Find clang and bpftool ───────────────────────────────────────────────
find_program(CLANG clang-14 REQUIRED HINTS /usr/bin)
find_program(BPFTOOL bpftool HINTS /usr/sbin /usr/lib/linux-tools)
message(STATUS "clang  : ${CLANG}")
message(STATUS "bpftool: ${BPFTOOL}")

# ── Generate vmlinux.h if not present ───────────────────────────────────
set(VMLINUX_H "${CMAKE_SOURCE_DIR}/kernel/vmlinux.h")
if(NOT EXISTS "${VMLINUX_H}")
    message(STATUS "Generating vmlinux.h via bpftool...")
    execute_process(
        COMMAND ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c
        OUTPUT_FILE "${VMLINUX_H}"
        RESULT_VARIABLE BPFTOOL_RESULT
    )
    if(NOT BPFTOOL_RESULT EQUAL 0)
        message(FATAL_ERROR "bpftool failed to generate vmlinux.h")
    endif()
endif()

# ── BPF compile flags ────────────────────────────────────────────────────
# Important: You are on ARM64 (aarch64), so use arm64, not x86
set(BPF_CFLAGS
    -target bpf
    -O2
    -g
    -D__TARGET_ARCH_arm64
    -I${CMAKE_SOURCE_DIR}/kernel
    -I${LIBBPF_INCLUDE}
    -I/usr/include
    -Wno-unused-value
    -Wno-pointer-sign
)

# ── Compile on_cpu.bpf.c ─────────────────────────────────────────────────
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/on_cpu.bpf.o
    COMMAND ${CLANG} ${BPF_CFLAGS}
            -c ${CMAKE_SOURCE_DIR}/kernel/on_cpu.bpf.c
            -o ${CMAKE_BINARY_DIR}/on_cpu.bpf.o
    DEPENDS ${CMAKE_SOURCE_DIR}/kernel/on_cpu.bpf.c
            ${CMAKE_SOURCE_DIR}/kernel/profiler_common.h
            ${VMLINUX_H}
    COMMENT "Compiling on_cpu.bpf.c → on_cpu.bpf.o"
    VERBATIM
)

# ── Compile off_cpu.bpf.c ────────────────────────────────────────────────
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/off_cpu.bpf.o
    COMMAND ${CLANG} ${BPF_CFLAGS}
            -c ${CMAKE_SOURCE_DIR}/kernel/off_cpu.bpf.c
            -o ${CMAKE_BINARY_DIR}/off_cpu.bpf.o
    DEPENDS ${CMAKE_SOURCE_DIR}/kernel/off_cpu.bpf.c
            ${CMAKE_SOURCE_DIR}/kernel/profiler_common.h
            ${VMLINUX_H}
    COMMENT "Compiling off_cpu.bpf.c → off_cpu.bpf.o"
    VERBATIM
)

# ── Compile uprobe.bpf.c ─────────────────────────────────────────────────
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/uprobe.bpf.o
    COMMAND ${CLANG} ${BPF_CFLAGS}
            -c ${CMAKE_SOURCE_DIR}/kernel/uprobe.bpf.c
            -o ${CMAKE_BINARY_DIR}/uprobe.bpf.o
    DEPENDS ${CMAKE_SOURCE_DIR}/kernel/uprobe.bpf.c
            ${CMAKE_SOURCE_DIR}/kernel/profiler_common.h
            ${VMLINUX_H}
    COMMENT "Compiling uprobe.bpf.c → uprobe.bpf.o"
    VERBATIM
)

add_custom_target(bpf_objects ALL
    DEPENDS
        ${CMAKE_BINARY_DIR}/on_cpu.bpf.o
        ${CMAKE_BINARY_DIR}/off_cpu.bpf.o
        ${CMAKE_BINARY_DIR}/uprobe.bpf.o
)

# ── C++ userspace binary ─────────────────────────────────────────────────
add_executable(profiler
    src/main.cpp
    src/types.cpp
    src/derivation.cpp
)

add_dependencies(profiler bpf_objects)

target_include_directories(profiler PRIVATE
    ${CMAKE_SOURCE_DIR}/kernel
    ${LIBBPF_INCLUDE}
)

target_link_libraries(profiler PRIVATE
    ${LIBBPF_LIB}
    ${LIBELF_LIB}
    ${LIBZ_LIB}
    pthread
)

target_compile_options(profiler PRIVATE
    -Wall -Wextra -Wno-unused-parameter
)

# ── Copy all BPF objects next to the binary after build ──────────────────
add_custom_command(TARGET profiler POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_BINARY_DIR}/on_cpu.bpf.o
        ${CMAKE_BINARY_DIR}/off_cpu.bpf.o
        ${CMAKE_BINARY_DIR}/uprobe.bpf.o
        ${CMAKE_BINARY_DIR}/
    COMMENT "Copying all BPF objects to build directory"
)