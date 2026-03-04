# Event Contract and ABI

The most important long-term artifact in this project is the shared event contract.

## 1. Why a Shared Header Exists
`include/event_schema.h` is consumed by both:
- kernel eBPF C code
- user-space C++ code

This ensures binary compatibility for ring buffer payloads.

## 2. Event Envelope
All event types begin with `event_header`:
- timestamp (`ts_ns`)
- event type and payload size
- pid/tgid/ppid
- uid/gid
- `comm`

Why this shape:
- common fields are always available for indexing/filtering
- type-specific payload remains compact

## 3. Typed Payloads
- `process_event`
- `file_event`
- `syscall_event`
- `network_event` (Phase A contract)

Current implementation status:
- process lifecycle events (exec/fork/exit) are emitted in kernel, including ppid, child pid (fork), and exit code (exit) fields
- file events (`openat`, `unlinkat`, `renameat2`) are correlated in-kernel between syscall-enter and syscall-exit
- emitted file events include intent/path fields plus accurate syscall outcome (`ret`)
- syscall events are emitted through allowlist-first raw syscall telemetry
- network payload contract is active for minimal metadata-only socket telemetry (no payload inspection)

## 4. Decoder Contract
The decoder reads raw bytes and maps them to:
`std::variant<process_event, file_event, syscall_event, network_event>`

Safety checks:
- minimum header size required
- per-type payload size checks before memcpy

Why variant:
- compile-time type safety
- explicit handling in sink/policy/enricher

## 5. ABI Stability Rules (for future work)
1. Add fields by appending, not reordering existing fields.
2. Keep fixed-width integer types.
3. Version changes should be deliberate and documented.
4. Keep kernel payload minimal; enrich in user space.

Relevant files:
- `../include/event_schema.h`
- `../src/decoder/decoder.h`
- `../src/decoder/decoder.cpp`
