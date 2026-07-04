/*
 * File Notes:
 * - Aggregates the domain-specific kernel modules into one BPF translation unit.
 * - Keeps the build entrypoint stable while splitting code by concern.
 */

#include "event_logger_process.bpf.c"
#include "event_logger_file.bpf.c"
#include "event_logger_syscall.bpf.c"
