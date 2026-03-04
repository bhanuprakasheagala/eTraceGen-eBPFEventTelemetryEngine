# Kernel eBPF Side

This document explains current kernel-side logic and why it is intentionally small.

## 1. Current Program Scope
File: `../bpf/event_logger.bpf.c`

Implemented today:
- ring buffer map `events`
- helper to fill common header fields
- process tracepoint handlers: `sched_process_exec`, `sched_process_fork`, `sched_process_exit`
- file syscall-enter handlers: `sys_enter_openat`, `sys_enter_unlinkat`, `sys_enter_renameat2`
- file syscall-exit handlers: `sys_exit_openat`, `sys_exit_unlinkat`, `sys_exit_renameat2`
- syscall tracepoint handlers: `raw_syscalls/sys_enter`, `raw_syscalls/sys_exit`
- network syscall handlers: `socket`, `connect`, `accept4`, `bind`, `listen`, `close` (enter/exit)
- in-kernel file/syscall/network enter/exit correlation maps for accurate `ret` outcomes
- runtime file-probe toggle map (`file_probe_enabled`) driven by config
- runtime syscall allowlist map (`syscall_allowlist`) driven by config
- runtime PID/UID allowlist maps (`pid_allowlist`, `uid_allowlist`) driven by config
- runtime PID/UID filter activation maps (`pid_filter_enabled`, `uid_filter_enabled`)
- runtime network probe toggle map (`network_probe_enabled`)
- runtime network port allowlist map (`network_port_allowlist`) and activation map (`network_port_filter_enabled`)
- kernel-side per-CPU stats map (`bpf_stats`) for reserve/correlation visibility

## 2. Why Tracepoint First
Tracepoints are generally more stable than kprobes across kernels.
For a portability-focused design, tracepoints are the safest default.

## 3. Ring Buffer Emission Pattern
For each event:
1. reserve space in ring buffer
2. zero/init struct
3. fill header and payload
4. submit event

Why this pattern:
- avoids dynamic allocations
- verifier-friendly
- bounded and predictable

## 4. Kernel Filtering
A unified `is_event_allowed()` gate is applied at probe entry for process, file, syscall, and network handlers.

Behavior:
- PID filter disabled when `pid_filter_enabled[0] == 0`
- UID filter disabled when `uid_filter_enabled[0] == 0`
- when enabled, event passes only if current task identity matches allowlist map entries

Network behavior:
- per-kind probe toggles from `network_probe_enabled`
- optional port allowlist filter controlled by `network_port_filter_enabled`

## 5. Current Gaps (Planned)
- validate and harden process payload fidelity across kernel variants
- validate file/syscall/network correlation behavior under sustained pressure using `bpf_stats` counters
- expand network metadata quality (better fd-to-socket context without heavy kernel overhead)

## 6. Design Guardrails
- avoid expensive string/path resolution in kernel where possible
- keep event size bounded
- tolerate missed events under pressure and measure drops
