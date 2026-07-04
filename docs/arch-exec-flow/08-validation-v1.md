# v1 Validation Suite (Linux)

This document defines acceptance checks for the current capture-first v1 scope.

## 1. Purpose
`./scripts/linux.sh validate` verifies:
- baseline capture for process/file/syscall domains
- syscall domain toggle behavior (`domains.syscall: false` disables syscall output)
- baseline network telemetry attempt (`domains.network_socket: true`)

Artifacts:
- `build/validate_v1/*.ndjson`
- `build/validate_v1/*.stderr.log`

## 2. Preconditions
- Linux host
- built userspace binary: `build/etracegen`
- built BPF object: `bpf/event_logger.bpf.o`

Build helpers:
- `./scripts/linux.sh build`
- `./scripts/linux.sh bpf`

## 3. Scenarios Covered
1. `baseline_all`
- `process/file/syscall/network_socket` enabled
- expected: process + file + syscall events
- network events are attempted and logged when generated on host

2. `syscall_domain_off`
- same as baseline, but `domains.syscall: false`
- expected: no syscall events

## 4. Notes
- network event presence can vary by host/network policy and available socket activity.
- this suite is functional validation, not performance benchmarking.
