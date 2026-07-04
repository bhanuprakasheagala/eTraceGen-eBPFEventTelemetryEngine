# Event Contract and ABI

The most important long-term artifact in this project is the shared event contract.

## 1. Shared Header
`include/event_schema.h` is consumed by both:
- kernel eBPF code
- user-space C++ code

This keeps ring-buffer payload compatibility explicit.

## 2. Event Envelope
All payloads begin with `event_header`:
- `ts_ns`, `type`, `size`
- `pid`, `tgid`, `ppid`
- `uid`, `gid`
- `comm`

## 3. Typed Payloads
- `process_event`
- `file_event`
- `syscall_event`
- `network_event`

Current implementation status:
- process lifecycle telemetry: exec/fork/exit + clone-family outcomes
- file telemetry: openat/unlinkat/renameat2 with enter/exit pairing and final `ret`
- syscall telemetry: broad raw syscall capture (no allowlist gating in active flow)
- network telemetry: socket lifecycle and transport I/O hooks (`socket`, `connect`, `accept4`, `bind`, `listen`, `close`, `sendto`, `recvfrom`, `shutdown`) with metadata-only records; DNS/HTTP/HTTPS deferred

## 4. Decoder Contract
Decoder maps raw bytes to:
`std::variant<process_event, file_event, syscall_event, network_event>`

Checks:
- minimum header size
- per-type payload size before memcpy

## 5. ABI Stability Rules
1. Append fields; do not reorder published fields.
2. Keep fixed-width integer types.
3. Keep type ids stable.
4. Keep kernel payload compact; enrich in user space.

Relevant files:
- `../include/event_schema.h`
- `../src/decoder/decoder.h`
- `../src/decoder/decoder.cpp`
