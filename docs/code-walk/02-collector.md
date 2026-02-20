# Collector Interface and Backends Walk

Sources:
- `../../src/collector/collector.h`
- `../../src/collector/collector_libbpf.cpp`
- `../../src/collector/collector_stub.cpp`

## Why Collector Exists
Collector isolates ingress mechanics from processing logic.
The rest of the system never cares whether events came from real eBPF or a fallback mode.

## Interface Contract
`Collector` methods:
- `Start(RawEventCallback cb)`
- `PollOnce(int timeout_ms)`
- `ReadKernelBpfStats(KernelBpfStats* out)`
- `ReadStartupReport(CollectorStartupReport* out)`
- `Stop()`

Invariants:
- callback ownership is internal to collector
- callback receives immutable raw bytes span
- collector can be polled repeatedly with bounded blocking

## libbpf Collector Walk
### Startup path
- configure libbpf strict/log policy
- resolve object/config paths
- open/load BPF object
- detect map availability (`events`, `bpf_stats`, `file_probe_enabled`, `pid_allowlist`, `uid_allowlist`, `syscall_allowlist`, network maps)
- apply runtime config into map toggles/allowlists
- set PID/UID/network-port filter activation flags (`pid_filter_enabled`, `uid_filter_enabled`, `network_port_filter_enabled`)
- attach programs best-effort and track failures by program name
- require at least one attached program
- create ring buffer reader
- materialize startup report with degraded reason when needed

Why best-effort attach is used:
- improves cross-kernel behavior where some hooks may be unavailable.

### Poll path
- ring buffer poll
- ignores `EINTR`, logs other poll errors.

### Event bridge
- `OnRingBufferEvent` converts `(void*, size)` to `std::span<const unsigned char>` and calls pipeline callback.

### Stop path
- free ring buffer, destroy links, close object, clear callback.

## Stub Collector Walk
- logs fallback mode at startup.
- poll is implemented as sleep only.
- emits a degraded startup report that explains kernel ingress is not active.

Why it exists:
- compile/run on environments without libbpf.
- lets the rest of the pipeline be developed independently.

## Runtime Config Application (Current)
At startup, the libbpf collector applies kernel-side runtime controls before polling:
- `file_probes` toggles into map `file_probe_enabled`
- `filters.pid_allowlist` into map `pid_allowlist`
- `filters.uid_allowlist` into map `uid_allowlist`
- `filters.syscall_allowlist` into map `syscall_allowlist`
- `domains.network_socket` into map `network_probe_enabled`
- `network_filters.port_allowlist` into map `network_port_allowlist`
- PID/UID/network-port filter activation via `pid_filter_enabled`, `uid_filter_enabled`, `network_port_filter_enabled`

Why this matters:
- behavior can be changed without recompiling BPF object
- syscall telemetry remains opt-in by default (empty allowlist)
- PID/UID filters are zero-cost when disabled (empty allowlists)
- network socket telemetry can be enabled in a controlled, config-driven way

## Kernel Stats Surface (Current)
The collector aggregates kernel counters from `bpf_stats`, including:
- ring-buffer reserve failures
- file enter/exit state failures and misses
- syscall enter/exit state failures, collisions, and misses
- network enter/exit state failures, collisions, and misses

## Failure Surface Summary
- open/load failures: startup fails immediately.
- all attaches fail: startup fails.
- some attaches fail: continue with partial functionality and explicit degraded report.
- ring buffer creation fails: startup fails.
