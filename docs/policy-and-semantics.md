# Policy and Event Semantics Design

> **Scope note (read first):** this is a **design reference for the Semantic Engine + Policy layer**
> ([roadmap.md](roadmap.md) Milestone 3), where correlated knowledge becomes meaning. The
> subject/action/object/outcome model below is the target for that layer. The project goal is
> general system intelligence, not security detection — any security-flavored examples are
> illustrative.

This note complements [signal-first-design.md](signal-first-design.md) by defining the expected behavior of policy evaluation and the semantic event layer.

## 1. Intent

The system should eventually expose a small set of high-value events that describe what happened, who caused it, and what object was affected. This is more useful than a large number of low-level syscall callbacks.

## 2. Event Semantics

Each emitted event should ideally answer four questions:

1. Who did it?
2. What action happened?
3. What object was affected?
4. Was it successful or suppressed?

The conceptual model is:

- subject = process identity
- action = started, execed, created, modified, deleted, renamed, connected
- object = file path, process identity, or network endpoint
- outcome = success, failure, suppressed, or ignored

## 3. Policy Stages

### Stage A: Capture eligibility

The event is evaluated for whether it should be considered at all. This includes:

- collector self-suppression
- process allowlist or suppress list
- path allowlist or suppress list
- domain-profile gating

### Stage B: Baseline evaluation

The event is checked against the startup baseline.

Examples:

- an existing process performing a normal action should not create a fresh “process started” event
- an unknown new process should be surfaced as “newly observed”

### Stage C: Semantic normalization

The low-level event is translated into a logical event.

Examples:

- raw file syscalls become file_modified or file_created
- raw exec events become process_execed
- raw socket create/connect becomes connection_established

### Stage D: Deduplication and debounce

Repeated events within a short interval are collapsed to avoid noise.

## 4. Recommended Default Policy Profile

The default profile should be:

- self-suppression enabled
- startup baseline enabled
- new-process visibility enabled
- meaningful file change events enabled
- raw syscall verbosity disabled
- duplicate suppression enabled

## 5. Why This Is Better Than Raw Capture

A semantic event layer gives the system a better story for operators and downstream consumers:

- easier to reason about
- easier to query
- easier to alert on
- easier to store in structured logs
- less noisy than raw syscalls

## 6. Open Design Questions

Before implementation, the team should decide:

- whether the semantic layer should be emitted in addition to raw events or as a replacement in the default profile
- how much of the baseline should be persisted across runs
- whether deduplication should be per-process, per-object, or per-subject/object pair
- whether file modification should require write confirmation from the kernel path or simply be inferred from the current syscall pattern
