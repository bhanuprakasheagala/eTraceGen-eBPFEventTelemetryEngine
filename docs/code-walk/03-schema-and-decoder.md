# Schema and Decoder Walk

Sources:
- `../../include/event_schema.h`
- `../../src/decoder/decoder.h`
- `../../src/decoder/decoder.cpp`

## Why This Pair Is Critical
This is the ABI seam between kernel eBPF producer and user space.

## Schema Structure
- `event_header`
- `process_event`
- `file_event`
- `syscall_event`
- `network_event`

## Decoder Behavior
`Decode(span)`:
1. validate minimum header size
2. read type and declared payload size
3. validate concrete struct size
4. memcpy into typed variant
5. return `nullopt` for invalid/unsupported payload

## ABI Invariants
1. Keep field order stable.
2. Use fixed-width types.
3. Add by appending fields.
4. Keep `type` values stable once published.

## Network Status
Current network event coverage includes:
- `socket`, `connect`, `accept4`, `bind`, `listen`, `close`, `sendto`, `recvfrom`, `shutdown`

Payload remains metadata-only for now (socket I/O hooks are present, but no payload/TLS inspection).
