# Kernel eBPF Program Walk

Source: `../../bpf/event_logger.bpf.c`

## Program Intent
Capture kernel events with minimal processing and emit typed records via ring buffer.

## Sections and Components
- BPF map `events` (ring buffer)
- BPF map `file_enter_state` (LRU hash) for file enter/exit correlation
- BPF map `syscall_enter_state` (LRU hash) for syscall enter/exit correlation
- BPF map `network_enter_state` (LRU hash) for network enter/exit correlation
- BPF map `file_probe_enabled` (array) for runtime file probe toggles
- BPF map `pid_allowlist` + `uid_allowlist` (hash) for identity filters
- BPF map `pid_filter_enabled` + `uid_filter_enabled` (array) for filter activation gates
- BPF map `syscall_allowlist` (hash) for allowlist-first syscall telemetry
- BPF map `network_probe_enabled` (array) for network probe toggles
- BPF map `network_port_allowlist` (hash) for port filter rules
- BPF map `network_port_filter_enabled` (array) for port filter activation
- BPF map `bpf_stats` (per-CPU array) for drop/correlation observability
- helpers: `fill_header`, process/file/syscall/network reserve helpers, bounded user-path copy, sockaddr parsing
- policy helpers: `is_current_pid_allowed`, `is_current_uid_allowed`, `is_event_allowed`
- process handlers: `on_sched_exec`, `on_sched_fork`, `on_sched_exit`
- file handlers: `on_sys_enter_*` + `on_sys_exit_*`
- syscall handlers: `on_raw_sys_enter`, `on_raw_sys_exit`
- network handlers: `on_sys_enter/exit_socket`, `connect`, `accept4`, `bind`, `listen`, `close`

## Current Event Lifecycle in Kernel
1. handler checks coarse gate (`is_event_allowed`) and probe-specific gate
2. reserve ring buffer slot
3. zero struct
4. fill common header
5. fill payload
6. submit to ring buffer

For file/syscall/network telemetry:
1. enter handler captures request details and stores them in correlation state map
2. exit handler looks up stored state, updates timestamp/return value, emits one complete event
3. correlation state is deleted

Why this is verifier-friendly:
- bounded operations
- fixed-size structs
- no unbounded loops

## Network Minimal Scope
Active minimal network coverage:
- socket lifecycle syscalls (`socket`, `connect`, `accept4`, `bind`, `listen`, `close`)
- metadata only (fd/domain/type/protocol/family/ports/address bytes)
- no payload parsing, no TLS inspection

## Current Gaps and Technical Debt
- process payload should be validated on target kernel matrix
- file/syscall/network correlation behavior under map pressure should be measured via `bpf_stats`
- network metadata can be improved with lightweight fd context where verifier cost permits

## Next Kernel Additions
- stabilize cross-kernel behavior across distro matrix
- add minimal DNS/HTTP metadata layers in userspace after current network events prove stable
