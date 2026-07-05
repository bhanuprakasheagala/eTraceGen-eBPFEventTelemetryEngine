# Implementation Plan: Signal-First Telemetry

This document turns the signal-first design into an implementation plan that is safe to execute incrementally. The goal is to improve signal quality without destabilizing the existing collector pipeline.

## 1. Implementation Goal

The project should evolve from a broad capture-first stream into a smaller set of high-value events that answer:

- what new process appeared,
- what meaningful file action occurred,
- what new network action occurred,
- and whether the event should be emitted or suppressed.

The first implementation should improve the default experience without requiring a full redesign of the existing eBPF and userspace architecture.

## 2. Guardrails for the First Iteration

The first implementation must preserve the following constraints:

1. Keep the kernel-side logic compact and bounded.
2. Keep the existing event contract as the low-level transport layer.
3. Move filtering, baseline handling, and semantic normalization into user space first.
4. Make the collector self-suppression reliable.
5. Make the default mode quieter and more useful than the current raw stream.

## 3. Proposed Delivery Order

### Phase 0 — Stabilize the current baseline

Objective:
- make the current system predictable before introducing richer policy logic.

Planned work:
- document the current low-level event families and their semantics.
- ensure collector self-suppression is explicit and tested.
- ensure startup configuration can select a policy profile cleanly.

Acceptance criteria:
- the collector does not emit its own events into the sink.
- the runtime can be switched between a verbose profile and a signal-first profile without changing the collector core.

### Phase 1 — Introduce policy-driven filtering in user space

Objective:
- move from permissive pass-through to explicit event filtering.

Planned work:
- use the existing policy stage as the control point for event emission.
- add a policy decision flow that evaluates:
  - self events,
  - startup baseline,
  - domain policy,
  - suppression rules,
  - and future deduplication state.

Acceptance criteria:
- events from the collector process are dropped before sink emission.
- events can be selectively suppressed based on policy without touching the main loop.
- the policy engine is deterministic and easy to extend.

### Phase 2 — Add startup baseline handling

Objective:
- stop treating already-running processes as fresh events.

Planned work:
- snapshot known process identities at startup.
- maintain a baseline registry of process identities in user space.
- treat processes that were already present at startup as known entities.
- surface only newly observed process activity as meaningful new events.

Acceptance criteria:
- a process that is already running when monitoring starts does not generate a startup flood.
- a process that appears after startup is recognized as newly observed.
- the baseline is explicit and can be inspected or tuned.

### Phase 3 — Introduce semantic file event normalization

Objective:
- replace low-meaning file open/close chatter with higher-value file actions.

Planned work:
- define a semantic mapping from existing file events to logical actions such as:
  - file_created,
  - file_modified,
  - file_deleted,
  - file_renamed.
- preserve the raw file event as a low-level source of truth if needed.
- enrich the semantic event with path, process identity, and outcome.

Acceptance criteria:
- file create/modify/delete/rename actions are represented as semantic events rather than just raw syscall-backed events.
- a path and process identity are present for each emitted file event.
- repeated file write bursts are reduced to a smaller number of meaningful records.

### Phase 4 — Introduce semantic process events

Objective:
- produce process-level events that are easier to reason about than raw lifecycle traces.

Planned work:
- emit semantic process events such as:
  - process_started,
  - process_execed,
  - process_exited.
- ensure that only meaningful new process activity is emitted in the default profile.
- keep parent/child correlation available for enrichment.

Acceptance criteria:
- new process starts after baseline are surfaced in a compact way.
- existing processes do not generate repeated startup-style events.
- process events include enough identity and ancestry information to be useful.

### Phase 5 — Add deduplication and debounce

Objective:
- reduce repeated low-value events caused by short bursts of activity.

Planned work:
- define a deduplication key based on:
  - event family,
  - action type,
  - subject identity,
  - object identity,
  - and a short time window.
- introduce configurable debounce windows for process and file events.

Acceptance criteria:
- repeated file writes in the same short interval are collapsed into a single logical event.
- repeated process events caused by short-lived bursts are suppressed by policy.
- deduplication is configurable and defaults to a conservative profile.

### Phase 6 — Add configuration profiles

Objective:
- make the behavior tunable without code changes.

Planned work:
- introduce YAML-driven policy profiles such as:
  - signal_first,
  - diagnostic,
  - strict.
- provide defaults for each profile.

Acceptance criteria:
- the operator can switch profiles without recompiling.
- the default profile is quieter and more useful than the current behavior.
- the verbose profile remains available for debugging.

## 4. Files Likely to Be Involved Later

The following files are the natural touchpoints for this phased implementation:

- [src/policy/policy.cpp](src/policy/policy.cpp)
- [src/policy/policy.h](src/policy/policy.h)
- [src/enricher/enricher.cpp](src/enricher/enricher.cpp)
- [src/enricher/enricher.h](src/enricher/enricher.h)
- [src/main.cpp](src/main.cpp)
- [src/sinks/json_sink.cpp](src/sinks/json_sink.cpp)
- [include/event_schema.h](include/event_schema.h)
- [config/default.yaml](config/default.yaml)

## 5. Suggested Scope for the First Implementation Slice

To keep risk low, the first implementation slice should be limited to:

1. collector self-suppression,
2. startup process baseline,
3. policy-driven emission control,
4. semantic process/file event shaping without changing the low-level kernel contract.

This is the smallest slice that meaningfully moves the project toward the new signal-first posture.

## 6. Validation Strategy

Each phase should be validated with a small set of focused checks:

- process startup scenario: verify new processes are surfaced only after startup baseline is established.
- file activity scenario: verify meaningful file changes are emitted and duplicate bursts are reduced.
- self-suppression scenario: verify collector activity does not appear in output.
- configuration scenario: verify policy profiles can change behavior without code changes.

## 7. Decision Point Before Coding

Before implementation begins, the team should confirm the following:

- whether the default profile should emit semantic events only, or both semantic and low-level events,
- whether file modification should be inferred from write-like behavior or from a larger semantic action model,
- and whether the first implementation should include process baseline persistence across restarts.

Once those decisions are made, implementation can begin phase by phase without overcommitting to the full design at once.
