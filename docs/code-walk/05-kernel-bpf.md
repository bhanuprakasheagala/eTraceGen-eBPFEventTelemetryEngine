# Kernel eBPF Program Walk

Source entrypoint: `../../bpf/event_logger.bpf.c`

## Source Layout
- `../../bpf/event_logger_common.bpf.h`: shared maps, helpers, schema glue, and event builders
- `../../bpf/event_logger_process.bpf.c`: process lifecycle handlers
- `../../bpf/event_logger_file.bpf.c`: file enter/exit handlers
- `../../bpf/event_logger_syscall.bpf.c`: raw syscall telemetry
- `../../bpf/event_logger_network.bpf.c`: socket-level network handlers

The aggregator file exists so the build only needs one BPF object path even though the implementation is split into domain-specific translation units.

## Program Intent
Capture high-value kernel events with bounded logic and emit typed ring-buffer records.

## Key Maps
- `events` (ring buffer)
- `file_enter_state` (LRU hash)
- `syscall_enter_state` (LRU hash)
- `network_enter_state` (LRU hash)
- `file_probe_enabled` (array)
- `process_probe_enabled` (array)
- `syscall_probe_enabled` (array)
- `network_probe_enabled` (array)
- `bpf_stats` (per-CPU array)

## Handlers
- process: `on_sched_exec`, `on_sched_fork`, `on_sched_exit`, clone-family exits
- file: `openat`, `unlinkat`, `renameat2` enter/exit
- syscall: `on_raw_sys_enter`, `on_raw_sys_exit`
- network: `socket`, `connect`, `accept4`, `bind`, `listen`, `close`, `sendto`, `recvfrom`, `shutdown`

## Event Lifecycle
1. check domain/probe gate
2. reserve ring-buffer record
3. fill header + payload
4. submit

For file/syscall/network:
1. enter stores state in map
2. exit resolves state, fills `ret`, emits final event
3. state entry deleted

## Current Runtime Mode
Capture-first mode is active:
- PID/UID allowlist filtering disabled
- syscall allowlist gating disabled
- network port allowlist gating disabled

Domain toggles remain active controls.
