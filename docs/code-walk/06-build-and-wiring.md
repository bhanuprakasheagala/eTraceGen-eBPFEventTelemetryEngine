# Build and Wiring Walk

Source: `../../CMakeLists.txt`

## Build Graph
The executable is `etracegen`.
Core sources are always linked.
Collector backend is selected conditionally.

## Backend Selection
- detect `libbpf` with `pkg-config`
- if present: compile libbpf collector and define compile-time flags
- else: compile stub collector

Relevant blocks:
- option flag: `../../CMakeLists.txt`
- libbpf discovery branch
- libbpf target wiring branch
- stub fallback branch

## BPF Object Default Path Injection
Compile definition:
- `EVENT_LOGGER_DEFAULT_BPF_OBJECT="${CMAKE_SOURCE_DIR}/bpf/event_logger.bpf.o"`

Why this helps:
- runtime does not depend on process current directory
- provides deterministic default for deployments

## Runtime Override
Environment variable:
- `ETRACEGEN_BPF_OBJECT`

Why this exists:
- supports package-managed paths
- enables testing alternate BPF object builds without recompiling user space

## Linux BPF Build Target
CMake helper target:
- `bpf_object`

Behavior:
- runs `scripts/build_bpf.sh`
- generates `bpf/vmlinux.h` from host BTF
- builds `bpf/event_logger.bpf.o`

Why target is opt-in:
- avoids breaking non-Linux C++ development flows
- keeps Linux-specific build requirements explicit

## Practical Build Modes
1. Stub mode:
- build succeeds without libbpf
- useful for pipeline development

2. Full mode:
- requires Linux + libbpf + compiled BPF object
- enables real event capture
