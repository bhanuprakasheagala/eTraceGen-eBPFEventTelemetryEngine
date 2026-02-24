# Schema and Decoder Walk

Sources:
- `../../include/event_schema.h`
- `../../src/decoder/decoder.h`
- `../../src/decoder/decoder.cpp`

## Why This Pair Is Critical
This is the ABI seam between kernel eBPF and user space.
If this contract drifts, decoding breaks silently or corruptly.

## Schema Structure
- `event_header` (common envelope)
- `process_event`
- `file_event`
- `syscall_event`
- `network_event` (Phase A contract)

Header fields carry routing/indexing metadata:
- time, type, payload size
- pid/tgid/ppid
- uid/gid
- comm

## Decoder Behavior
`Decode(span)` logic:
1. ensure buffer >= header size
2. inspect `hdr->type`
3. ensure buffer >= expected concrete struct size
4. memcpy concrete struct into variant
5. return nullopt when unsupported or truncated

## Why memcpy and not pointer casting downstream
- yields owned event object independent of source buffer lifetime
- avoids aliasing/lifetime hazards
- prepares clean input for enrichment/policy/sink

## ABI Invariants
1. Keep field order stable.
2. Use fixed-width types only.
3. Append fields instead of reordering existing ones.
4. Keep `type` values stable once published.

## Extension Pattern
When adding a new event type:
1. add enum value in schema header
2. define payload struct
3. extend variant in `decoder.h`
4. extend decode branch in `decoder.cpp`
5. extend sink formatting
6. add producer in BPF side

Network status now:
- minimal `network_event` production is active in kernel for socket/connect/accept4/bind/listen/close
- decoder and sink paths are active for these events
