# v1 Release Preflight

This document defines the pre-release gate for `eTraceGen` v1.

## 1. Entry Point
Use one command:
- `./scripts/linux.sh preflight`

## 2. What Preflight Checks
Repository and wiring:
- required source/config/docs files exist
- startup report path is wired
- raw syscall handler is present in kernel program

Artifacts:
- `build/etracegen` exists
- `bpf/event_logger.bpf.o` exists

Linux prerequisites:
- host OS is Linux
- `clang` available (BPF object build)
- `gcc`/`g++` available (userspace build)
- `bpftool` available
- kernel BTF present at `/sys/kernel/btf/vmlinux`

## 3. Intended Usage
Manual sequence:
- `./scripts/linux.sh all`
- `./scripts/linux.sh preflight`
- `./scripts/linux.sh smoke`
- `./scripts/linux.sh validate`

One-command sequence:
- `./scripts/linux.sh verify`

## 4. Scope
Structural and operational validation gate, not a full performance benchmark.
