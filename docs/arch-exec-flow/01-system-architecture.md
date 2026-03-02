# System Architecture

This document explains what eTraceGen is architecturally, why it is split this way, and how components relate.

## 1. Problem Model
Linux systems generate high-value events across process lifecycle, file activity, and syscalls. We want:
- low-overhead collection
- stable typing
- evolvable user-space processing
- portability across many kernels

## 2. Core Split: Kernel vs User Space
The project is split by responsibility, not just implementation language.

### Kernel (eBPF)
- Observe hook points.
- Capture minimal context.
- Emit typed event payloads into ring buffer.

### User Space (C++)
- Receive raw events.
- Decode using shared schema.
- Enrich, filter, and serialize.
- Own lifecycle, policy, and outputs.

Why this split:
- kernel-side complexity is expensive and verifier-constrained
- user space is easier for iteration, testing, and richer logic

## 3. Domain Strategy (Now vs Later)
### v1 domain scope (active)
- Process
- File
- Syscall

### future domains (planned, inactive)
- Socket/network lifecycle
- DNS
- HTTP/HTTPS correlation

Design intent:
- architecture is domain-extensible, but code implementation follows milestone scope
- this prevents speculative code burden and keeps runtime overhead focused

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

## 5. File-Level Architecture Map
- Entry point: `../src/main.cpp`
- Collector abstraction: `../src/collector/collector.h`
- libbpf collector: `../src/collector/collector_libbpf.cpp`
- fallback collector: `../src/collector/collector_stub.cpp`
- schema: `../include/event_schema.h`
- decoder: `../src/decoder/decoder.*`
- enrichment: `../src/enricher/enricher.*`
- policy: `../src/policy/policy.*`
- sink: `../src/sinks/json_sink.*`
- metrics: `../src/metrics/metrics.*`
- kernel program: `../bpf/event_logger.bpf.c`

