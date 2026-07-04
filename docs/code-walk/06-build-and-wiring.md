# Build and Wiring Walk

Source: `../../CMakeLists.txt`

## Build Graph
Executable target: `etracegen`.

Always-linked sources include pipeline stages plus `collector_libbpf.cpp`.

## Linux-Only Build Constraint
`CMakeLists.txt` fails configure on non-Linux hosts.
`libbpf` is required via `pkg-config`.

## BPF Object Default Path Injection
Compile definition:
- `EVENT_LOGGER_DEFAULT_BPF_OBJECT="${CMAKE_SOURCE_DIR}/bpf/event_logger.bpf.o"`

Why this helps:
- runtime does not depend on current working directory
- deterministic default for deployment and testing
- the object can be split across multiple domain modules without exposing that layout to userspace

## Runtime Override
Environment variable:
- `ETRACEGEN_BPF_OBJECT`

Why this exists:
- supports package-managed paths
- allows alternate BPF object testing without userspace rebuild

## Linux BPF Build Target
CMake helper target:
- `bpf_object`

Behavior:
- runs `scripts/linux.sh bpf`
- generates `bpf/vmlinux.h` from host BTF
- builds `bpf/event_logger.bpf.o` from the aggregator entrypoint that includes the domain-specific BPF files

## Operational Entry Point
Use one script for build/check/test/run:
- `./scripts/linux.sh`
