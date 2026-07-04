# System Architecture

This document explains what eTraceGen is architecturally, why it is split this way, and how components relate.

## 1. Problem Model
Linux systems generate high-value events across process lifecycle, file activity, syscalls, and socket lifecycle. We want:
- low-overhead collection
- stable typing
- evolvable user-space processing
- compatibility across many Linux kernels and distributions

## 2. Core Split: Kernel vs User Space
The project is split by responsibility, not by language preference alone.

### Kernel (eBPF)
- Observe tracepoints.
- Capture minimal event context.
- Emit typed payloads into ring buffer.
- Keep verifier-safe logic and bounded execution.

### User Space (C++)
- Receive raw ring-buffer payloads.
- Decode via shared schema.
- Enrich, filter, and serialize.
- Own lifecycle and operator-facing diagnostics.

## 3. Domain Strategy
### v1 active scope
- Process
- File
- Syscall
- Socket lifecycle and transport I/O hooks (metadata-only records)

### later scope
- DNS
- HTTP/HTTPS correlation
- deeper flow/protocol context

## 4. Component Graph

```text
+---------------- Linux Kernel ----------------+
| eBPF Programs -> Ring Buffer Map (events)    |
+----------------------+------------------------+
                       |
                       v
+---------------------- User Space -----------------------------+
| Collector -> Decoder -> Enricher -> PolicyEngine -> JsonSink |
|                  \-> Metrics counters                        |
+---------------------------------------------------------------+
```

## 5. Kernel Source Layout
The kernel side is split by domain, but the build entrypoint stays stable:
- Entry point / aggregator: `../bpf/event_logger.bpf.c`
- Shared helpers and maps: `../bpf/event_logger_common.bpf.h`
- Process domain: `../bpf/event_logger_process.bpf.c`
- File domain: `../bpf/event_logger_file.bpf.c`
- Syscall domain: `../bpf/event_logger_syscall.bpf.c`
- Network domain: `../bpf/event_logger_network.bpf.c`

This keeps CMake, loader wiring, and documentation anchored to one BPF object path while the actual handlers stay small and reviewable.

## 6. File-Level Architecture Map
- Entry point: `../src/main.cpp`
- Collector abstraction: `../src/collector/collector.h`
- libbpf collector: `../src/collector/collector_libbpf.cpp`
- schema: `../include/event_schema.h`
- decoder: `../src/decoder/decoder.*`
- enrichment: `../src/enricher/enricher.*`
- policy: `../src/policy/policy.*`
- sink: `../src/sinks/json_sink.*`
- metrics: `../src/metrics/metrics.*`
- kernel entrypoint: `../bpf/event_logger.bpf.c`
