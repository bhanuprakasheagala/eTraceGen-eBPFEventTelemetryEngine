# Kernel eBPF Side

This document explains the current kernel-side implementation and why it is intentionally compact. It is treated as a transitional reference while the project shifts toward a signal-first policy model in user space.

## 0. Module Layout
The build still starts from `../bpf/event_logger.bpf.c`, but that file now only aggregates the domain modules:
- `../bpf/event_logger_common.bpf.h`
- `../bpf/event_logger_process.bpf.c`
- `../bpf/event_logger_file.bpf.c`
- `../bpf/event_logger_syscall.bpf.c`
- `../bpf/event_logger_network.bpf.c`

Keeping the entrypoint stable matters because CMake, loading logic, and docs can continue to reference one BPF object path while the code itself remains split by concern.

## 1. Current Program Scope
Entry point: `../bpf/event_logger.bpf.c`

Implemented today:
- ring buffer map `events`
- shared header fill helper for all event families
- process tracepoint handlers: `sched_process_exec`, `sched_process_fork`, `sched_process_exit`
- process syscall-exit handlers: `clone`, `clone3`, `vfork`
- file syscall enter/exit handlers: `openat`, `unlinkat`, `renameat2`
- broad syscall telemetry via `raw_syscalls/sys_enter` + `raw_syscalls/sys_exit`
- network socket lifecycle and transport I/O enter/exit handlers: `socket`, `connect`, `accept4`, `bind`, `listen`, `close`, `sendto`, `recvfrom`, `shutdown`
- enter/exit correlation maps for file/syscall/network with accurate `ret`
- runtime domain/probe toggles:
  - `file_probe_enabled`
  - `process_probe_enabled`
  - `syscall_probe_enabled`
  - `network_probe_enabled`
- kernel per-CPU stats map (`bpf_stats`) for reserve/correlation visibility

## 2. Capture-First Behavior
Current runtime mode is capture-first for sandbox telemetry:
- PID/UID allowlist filtering is disabled in active logic
- syscall allowlist gating is disabled in active logic
- network port allowlist gating is disabled in active logic

Domain toggles are still active and are the primary runtime controls.

## 3. Why Tracepoints
Tracepoints are more stable than kprobes across kernel variants and are better for distro portability.

## 4. Ring Buffer Emission Pattern
For each event:
1. reserve ring-buffer record
2. zero/init payload
3. fill header and family fields
4. submit record

This keeps kernel work bounded and verifier-friendly.

## 5. Design Guardrails
- keep kernel logic small and deterministic
- keep payload size bounded
- tolerate pressure-related drops and measure them via `bpf_stats`
- keep expensive parsing/enrichment in user space
