# eTraceGen: eBPF Event Telemetry Engine

`eTraceGen` is a Linux-only event telemetry engine built with eBPF (kernel space) and Modern C++ (user space).

It captures runtime telemetry for sandbox and malware-analysis workflows:
- process lifecycle activity
- file operations (paired enter/exit with syscall outcomes)
- broad syscall telemetry (`raw_syscalls/sys_enter` + `sys_exit`)
- network socket lifecycle metadata

## Linux-Only Scope
- Linux distributions with kernel eBPF + BTF support.
- libbpf backend only.
- single operational script: `./scripts/linux.sh`.

## Kernel Module Layout
The BPF build still starts from `bpf/event_logger.bpf.c`, but that file is now a thin aggregator. The real logic is split by concern:

- `bpf/event_logger_common.bpf.h`: shared maps, helpers, schema glue, and safety checks
- `bpf/event_logger_process.bpf.c`: process lifecycle tracepoints and clone-family exits
- `bpf/event_logger_file.bpf.c`: file-enter/file-exit pairing
- `bpf/event_logger_syscall.bpf.c`: broad raw syscall telemetry
- `bpf/event_logger_network.bpf.c`: socket-level network metadata

Why this split matters:
- keeps verifier-facing code smaller and easier to scan
- isolates future network expansion from process/file code
- preserves the same build entrypoint and runtime behavior
- makes it easier to review and harden one domain at a time

## Dependencies (Linux)
- gcc/g++ (userspace build)
- clang/llvm (BPF object build)
- libbpf
- bpftool
- kernel BTF at `/sys/kernel/btf/vmlinux`

## Single Script Workflow
```bash
./scripts/linux.sh help
```

Core commands:
- `./scripts/linux.sh build`
- `./scripts/linux.sh bpf`
- `./scripts/linux.sh all`
- `./scripts/linux.sh check`
- `./scripts/linux.sh preflight`
- `./scripts/linux.sh smoke`
- `./scripts/linux.sh validate`
- `./scripts/linux.sh verify`
- `./scripts/linux.sh run`

## Quick Start (Linux)
```bash
cmake -S . -B build
cmake --build build -j
./scripts/linux.sh bpf
sudo ./scripts/linux.sh run
```

## File Logging + Rollover (Mandatory)
Configured in `config/default.yaml`:

```yaml
sink:
  path: /var/log/etracegen/events.ndjson
  max_file_size_bytes: 104857600
```

Behavior:
- if log file does not exist, it is created
- if log file exists, new events are appended
- when file size reaches `max_file_size_bytes`, collector deletes the existing file and starts a fresh one
- collector does not emit event records to stdout

## Current v1 Coverage
- process: `exec`, `fork`, `exit`, `clone`, `clone3`, `vfork`
- file: `openat`, `unlinkat`, `renameat2`
- syscall: broad capture (no syscall allowlist gating)
- network: socket lifecycle and transport I/O hooks (`socket`, `connect`, `accept4`, `bind`, `listen`, `close`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `read`, `write`, `readv`, `writev`, `sendmmsg`, `recvmmsg`, `shutdown`) with metadata-only records; DNS/HTTP/HTTPS deferred
- all emitted records include `process_info` (userspace-enriched with bounded cache)

## Default Runtime Mode
- capture-first configuration in `config/default.yaml`
- no PID/UID/syscall/network allowlist filtering in active flow
- domain toggles remain available (`domains.process`, `domains.file`, `domains.syscall`, `domains.network_socket`)

## Runtime Safety Guards
- in-kernel self-suppression map (`suppress_tgid`) is set to the collector PID at startup
- userspace also drops any event with `pid/tgid` equal to the collector PID (defensive fallback for older BPF objects)
