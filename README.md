# eTraceGen: eBPF Event Telemetry Engine

`eTraceGen` is a Linux event telemetry engine built with eBPF (kernel space) and Modern C++ (user space).

It is designed to capture and stream high-value runtime telemetry for:
- Process lifecycle activity
- File operations
- System call activity
- Minimal network socket lifecycle metadata

Future (post-v1) domains:
- DNS events
- HTTP/HTTPS correlation
- deeper network telemetry (flow correlation, protocol context)

The project is intentionally organized as a portability-first pipeline:
- minimal and safe kernel-side work
- typed event contract shared with user space
- user-space decode/enrich/filter/sink stages
- graceful fallback when full eBPF runtime is unavailable

## Scope Guardrails
- **Current release target (v1):** Process + File + Syscall telemetry with minimal network socket lifecycle events.
- **Current network scope:** metadata-only `socket`/`connect`/`accept4`/`bind`/`listen`/`close`; no TLS inspection and no L7 parsing.
- **Design rule:** keep kernel path minimal, pair enter/exit accurately, and expand domains in controlled milestones.

## Who This Repo Is For
- Engineers building Linux observability/security telemetry systems
- Developers learning practical eBPF + libbpf integration with C++
- People who prefer understanding internals before adding features

## Documentation Map
- [Deep Dive Index](docs/README.md)
- [Architecture](docs/01-system-architecture.md)
- [Execution Story (step-by-step)](docs/02-execution-story.md)
- [Event Contract and ABI](docs/03-event-contract.md)
- [Kernel eBPF Side](docs/04-kernel-side.md)
- [User-Space Pipeline](docs/05-userspace-side.md)
- [Build, Portability, and Compatibility](docs/06-build-portability.md)
- [Roadmap and Extension Design](docs/07-roadmap-and-extension.md)
- [Code Walk (file-by-file)](docs/code-walk/README.md)
- [Linux Host Setup and Bring-up](docs/linux-setup.md)

## Quick Build
```bash
cmake -S . -B build
cmake --build build -j
```

## Build BPF Object (Linux)
Use the repo script:
```bash
./scripts/build_bpf.sh
```

Or via CMake helper target:
```bash
cmake --build build --target bpf_object
```

This produces:
- `bpf/vmlinux.h` (generated from `/sys/kernel/btf/vmlinux`)
- `bpf/event_logger.bpf.o`

## Quick Run
```bash
./build/etracegen
```

Optional runtime overrides:
```bash
ETRACEGEN_BPF_OBJECT=/absolute/path/to/event_logger.bpf.o ./build/etracegen
ETRACEGEN_CONFIG=/absolute/path/to/config.yaml ./build/etracegen
```

Enable selected syscall telemetry by setting syscall numbers in config:
```yaml
filters:
  syscall_allowlist: [0, 1, 2]
```

Note: syscall numbers are architecture-specific (`x86_64` vs `arm64`).

Enable kernel-side PID/UID filtering:
```yaml
filters:
  pid_allowlist: [1234]
  uid_allowlist: [1000]
```

Domain behavior:
- `domains.process: false` => process lifecycle events disabled
- `domains.file: false` => file events disabled
- `domains.syscall: false` => syscall events disabled (allowlist ignored)
- `domains.network_socket: false` => network socket events disabled

Filter behavior:
- `pid_allowlist: []` => PID filtering disabled
- `uid_allowlist: []` => UID filtering disabled
- `syscall_allowlist: []` => syscall telemetry disabled

## Current Status
- C++20 user-space pipeline is implemented.
- libbpf collector path can open/load/attach/poll events from BPF object.
- Stub collector fallback works when libbpf is unavailable.
- Process lifecycle telemetry includes exec/fork/exit plus clone/clone3/vfork outcome events with child-pid capture where available.
- File probes (`openat`, `unlinkat`, `renameat2`) are paired in-kernel across enter/exit and emitted with accurate syscall `ret` outcomes.
- Kernel-side PID/UID allowlist filters are enforced across process/file/syscall telemetry.
- Kernel BPF stats (`bpf_stats`) are reported periodically (every 30s) and at shutdown when libbpf backend is active.
- Startup capability report is emitted at process start (backend, program attach coverage, config load state, map availability, and degraded reason when applicable).
- Selected syscall telemetry is implemented via `raw_syscalls/sys_enter` + `raw_syscalls/sys_exit`, with allowlist-first control from config (`filters.syscall_allowlist`).
- Minimal network socket telemetry is active for `socket`, `connect`, `accept4`, `bind`, `listen`, and `close` with metadata-only payloads and no TLS inspection.

## Dependencies for Full Linux eBPF Mode
- clang/llvm
- libbpf
- bpftool
- kernel BTF (typically `/sys/kernel/btf/vmlinux`)

## Dev Command Wrapper
```bash
./scripts/dev.sh help
```

Common commands:
- `./scripts/dev.sh build`
- `./scripts/dev.sh bpf`
- `./scripts/dev.sh host-check`
- `./scripts/dev.sh check`
- `./scripts/dev.sh check --linux-strict --skip-build`

## One-Command Checks
```bash
./scripts/run_all_checks.sh
```

Linux strict mode (uses strict preflight):
```bash
./scripts/run_all_checks.sh --linux-strict
```

## Integration Smoke Test (Linux)
```bash
./scripts/integration_smoke.sh
```

This validates:
- process events are emitted
- file events are emitted
- file events include `ret` outcome field
- syscall events are emitted when `filters.syscall_allowlist` is enabled (asserted on x86_64 smoke path)

## V1 Validation Suite (Linux)
```bash
./scripts/validate_v1_linux.sh
```

This suite validates:
- baseline process/file/syscall emission
- PID allowlist block-all behavior
- UID allowlist block-all behavior
- UID allow-current behavior
- PID allow-self behavior (events constrained to expected PID)

## V1 Release Preflight
Cross-platform preflight:
```bash
./scripts/release_check_v1.sh
```

Linux release gate:
```bash
./scripts/release_check_v1.sh --linux-strict
```

Or run the full orchestrated checks:
```bash
./scripts/run_all_checks.sh
```
