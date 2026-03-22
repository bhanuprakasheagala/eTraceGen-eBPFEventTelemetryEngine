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
./scripts/linux.sh run
```

Optional runtime overrides:
```bash
ETRACEGEN_BPF_OBJECT=/absolute/path/to/event_logger.bpf.o ./build/etracegen
ETRACEGEN_CONFIG=/absolute/path/to/config.yaml ./build/etracegen
```

## Current v1 Coverage
- process: `exec`, `fork`, `exit`, `clone`, `clone3`, `vfork`
- file: `openat`, `unlinkat`, `renameat2`
- syscall: broad capture (no syscall allowlist gating)
- network: metadata-only socket lifecycle for `socket`, `connect`, `accept4`, `bind`, `listen`, `close`, `sendto`, `recvfrom`, `shutdown`

## Default Runtime Mode
- capture-first configuration in `config/default.yaml`
- no PID/UID/syscall/network allowlist filtering in active flow
- domain toggles remain available (`domains.process`, `domains.file`, `domains.syscall`, `domains.network_socket`)
