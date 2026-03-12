# User-Space Pipeline (Modern C++)

This document explains each C++ block and why it exists.

## 1. Collector Interface
`Collector` defines backend-agnostic control surface:
- `Start(cb)`
- `PollOnce(timeout_ms)`
- `ReadKernelBpfStats(out)`
- `ReadStartupReport(out)`
- `Stop()`

Why interface:
- isolates backend specifics (libbpf vs stub)
- preserves same processing pipeline regardless of source

## 2. libbpf Collector
`collector_libbpf.cpp` performs:
1. configure libbpf logging/strict mode
2. resolve BPF object path
3. open/load BPF object
4. probe startup capabilities (program inventory + required/optional maps)
5. apply runtime config into kernel maps (`file_probe_enabled`, `pid_allowlist`, `uid_allowlist`, `syscall_allowlist`)
6. apply runtime network config into maps (`network_probe_enabled`, `network_port_allowlist`)
7. apply PID/UID/network-port filter activation flags (`pid_filter_enabled`, `uid_filter_enabled`, `network_port_filter_enabled`)
8. attach all programs (best-effort)
9. create ring buffer reader on map `events`
10. poll and forward payload bytes to callback
11. read/aggregate kernel-side counters from `bpf_stats` map
12. expose one-shot startup report for operator diagnostics

Best-effort attach behavior:
- if one program fails attach, continue
- if none attach, fail startup

Why this behavior:
- improves partial compatibility across kernels

## 3. Stub Collector
`collector_stub.cpp` provides a non-eBPF fallback.
It keeps process lifecycle and pipeline testable when libbpf is missing.

It also exposes a startup report with degraded status so operators can tell they are not in kernel-eBPF mode.

## 4. Decoder
`Decoder::Decode` maps raw payload into typed variant.
This is the ABI boundary consumer.

Current variant families:
- process
- file
- syscall
- network

## 5. Enricher
Current placeholder. Intended for:
- `/proc` lookups
- cgroup/container metadata
- host-level contextual tags

## 6. PolicyEngine
Current implementation remains pass-through.
Primary filtering for v1 is done in kernel to minimize user-space CPU cost for dropped events.

## 7. JsonSink
Converts typed events into NDJSON-like output.
Current sink is stdout; interfaces allow more sinks later.

Network events are serialized as metadata-only records (no payload parsing).

## 8. Metrics
Simple counters:
- received
- decoded
- dropped

Why this matters:
- immediate observability of pipeline health

## 9. Output Correctness
1. JSON sink escapes string fields (`comm`, file paths, filenames) to keep output valid JSON under arbitrary input.

## 10. Kernel Stats Exposure
1. Kernel-side counters from `bpf_stats` are aggregated in user-space via collector interface and printed periodically and at shutdown when available.

## 11. Runtime Hardening Hooks
1. Main loop reports kernel BPF stats periodically (every 30 seconds) and once at shutdown.
2. Collector reads `file_probes` toggles from config and applies them at startup.
3. Collector reads `filters.pid_allowlist` and `filters.uid_allowlist` from config, then toggles kernel filter activation maps based on list emptiness.
4. Collector reads `filters.syscall_allowlist` from config and applies syscall gating at startup (empty list disables syscall events).
5. Collector reads `domains.network_socket` and `network_filters.port_allowlist` from config and applies network toggles/filters at startup.
6. `ETRACEGEN_CONFIG` can override config path at runtime.

## 12. Startup Capability Report
At startup, user space prints a single structured report line with:
- backend mode (`libbpf` or `stub`)
- object/config path used
- program attach coverage (total/attached/failed)
- map availability (`events`, `bpf_stats`, `file_probe_enabled`, `pid_allowlist`, `uid_allowlist`, `syscall_allowlist`, network maps)
- config application summary (allowlist applied counts + probe toggle results)
- explicit degraded reason string when any capability is reduced

Why this matters:
- operators can detect partial functionality at boot, before relying on telemetry completeness.
