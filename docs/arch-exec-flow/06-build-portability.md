# Build, Portability, and Compatibility

This project is portable by design, but not "kernel-independent" in the absolute sense.

## 1. Build Behavior
`CMakeLists.txt` switches collector backend based on `libbpf` availability.

Outputs:
- binary: `etracegen`
- default BPF object path baked into compile definitions

## 2. Runtime BPF Object Resolution
Order:
1. environment variable `ETRACEGEN_BPF_OBJECT`
2. build-time default path from CMake

Why:
- supports custom deployment layouts
- avoids hard-coding runtime working directory assumptions

## 3. BPF Object Build Path (Linux)
Repository provides two equivalent paths:
1. script: `./scripts/build_bpf.sh`
2. CMake helper target: `cmake --build build --target bpf_object`

Build requirements:
- Linux host
- `clang`
- `bpftool`
- kernel BTF at `/sys/kernel/btf/vmlinux`

Outputs:
- generated CO-RE type header: `bpf/vmlinux.h`
- BPF object: `bpf/event_logger.bpf.o`

## 4. Compatibility Reality
Depends on:
- kernel version and features
- distro kernel config
- security controls (capabilities/lockdown)
- available BTF and hook support
- architecture-specific syscall numbering when using `filters.syscall_allowlist`

## 5. Degradation Strategy
Current strategy:
- compile-time fallback to stub if no libbpf
- runtime best-effort attach for each BPF program
- startup capability report with degraded reasons

## 6. Linux-Focused Development Notes
This repository can compile on non-Linux with stub mode, but full telemetry capture requires Linux kernel eBPF runtime.

Use host preflight before runtime tests:
```bash
./scripts/check_host_linux.sh
./scripts/check_host_linux.sh --strict
```
