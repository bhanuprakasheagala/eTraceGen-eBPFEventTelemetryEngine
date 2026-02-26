# Pipeline Stages Walk

Sources:
- `../../src/enricher/enricher.cpp`
- `../../src/policy/policy.cpp`
- `../../src/sinks/json_sink.cpp`
- `../../src/metrics/metrics.h`

## Stage 1: Enricher
Current behavior: placeholder no-op.
Source: `../../src/enricher/enricher.cpp:5`

Intended role:
- resolve extra process context
- map cgroup/container identity
- attach host or deployment tags

Constraint:
- avoid unbounded latency in this stage.

## Stage 2: Policy Engine
Current behavior: always true.
Source: `../../src/policy/policy.cpp:5`

Intended role:
- filtering
- allow/deny rules
- sampling under pressure

Constraint:
- policy must be deterministic and cheap per event.

## Stage 3: Json Sink
Current behavior: emit JSON object per event.
Source: `../../src/sinks/json_sink.cpp:34`

Behavior details:
- common header written first (`WriteHeader`)
- `std::visit` dispatches per concrete event type
- event-specific fields appended

Potential caveat:
- string fields are not JSON-escaped yet.
- if comm/path includes quote/newline chars, output can be malformed.

## Metrics
Counters:
- received
- decoded
- dropped

Source: `../../src/metrics/metrics.h:8`

Current threading assumption:
- updated from callback thread in current design.
- if multi-threading is introduced later, counters should become atomic or synchronized.

