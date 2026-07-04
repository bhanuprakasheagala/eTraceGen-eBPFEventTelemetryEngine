# Build, Portability, and Compatibility

This project is Linux-only, designed to work across many Linux distributions within eBPF compatibility bounds.

## 1. Build Behavior
`CMakeLists.txt` enforces Linux host build and requires `libbpf`.

Outputs:
- `build/etracegen`
- default BPF object path via compile definition

## 2. Runtime BPF Object Resolution
Order:
1. `ETRACEGEN_BPF_OBJECT`
2. build-time default path

## 3. Linux Build Path
Primary entrypoint:
- `./scripts/linux.sh`

Common commands:
- `./scripts/linux.sh build`
- `./scripts/linux.sh bpf`
- `./scripts/linux.sh all`

## 4. Compatibility Reality
Depends on:
- kernel version/features
- distro kernel config
- security controls (`cap_bpf`, lockdown, LSM)
- BTF availability

## 5. Runtime Controls
Current high-level controls are domain toggles:
- `domains.process`
- `domains.file`
- `domains.syscall`
- `domains.network_socket`

Current default mode is capture-first; allowlist/blocklist filtering is not active in primary flow.
