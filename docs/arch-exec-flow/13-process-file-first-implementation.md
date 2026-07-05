# Process and File First Implementation Plan

This document narrows the implementation plan to the process and file path only. Network handling remains intentionally out of scope for this milestone.

## 1. Scope for This Milestone

The first implementation slice will focus on:

- self-suppression for the collector process and its children,
- startup baseline handling for processes,
- policy-driven filtering for process and file events,
- semantic shaping of file events into create/modify/delete/rename actions,
- and a minimal amount of process enrichment to make the output more useful.

## 2. Design Principles for This Milestone

1. Keep the kernel-side contract unchanged unless the design clearly benefits from it.
2. Move all filtering and baseline decisions into user space first.
3. Emit fewer, more meaningful events than the current low-level stream.
4. Preserve the ability to fall back to the existing raw event model if needed for debugging.
5. Keep the implementation incremental and easy to reason about.

## 3. What Will Be Implemented First

### 3.1 Self-suppression

The collector must not emit its own events into the sink.

Implementation notes:

- use the existing collector PID/TID/TGID context already available in the event header,
- suppress events matching the collector’s identity and optionally its child process tree where practical.

### 3.2 Startup baseline for processes

At startup, the policy layer should create a baseline of known processes.

Implementation notes:

- capture the current set of processes visible at monitor startup,
- store a compact identity for each process,
- only emit new process activity after startup baseline is established,
- avoid repeated “already running” process churn.

### 3.3 Process event shaping

The first process semantics should be:

- process_new_seen
- process_execed
- process_exited

The default profile should prefer new process observation and exec activity over every lifecycle detail.

### 3.4 File event shaping

The first file semantics should be:

- file_created
- file_modified
- file_deleted
- file_renamed

The implementation should avoid turning every file open/close into a log event. It should instead infer a meaningful file action when the current event pattern supports it.

### 3.5 Shared policy and enrichment hooks

Both process and file handling will use the same shared path:

1. decode,
2. enrich,
3. policy evaluation,
4. sink emission.

This keeps the implementation consistent and avoids duplicating suppression logic.

## 4. Data Model Expectations

The existing event schema remains the low-level transport layer. A higher-level semantic event model can be introduced later, but the earliest implementation can use existing fields and a small amount of additional policy state.

For this milestone, the policy engine should maintain:

- a set of process identities seen at startup,
- a set of recently seen process/file actions for debounce,
- and a small amount of metadata for path and process context.

## 5. Expected Behavioral Changes

After this milestone:

- the collector process itself should disappear from the output,
- existing processes present at startup should not generate a flood of events,
- newly started processes should appear in a compact form,
- meaningful file create/modify/delete/rename actions should be surfaced instead of unstructured low-level noise.

## 6. Out of Scope for This Milestone

The following remain out of scope:

- network telemetry changes,
- deep content hashing,
- full forensic completeness of every file operation,
- complex allowlist management beyond the initial simple suppression logic.

## 7. Suggested Implementation Order

1. Add policy-side self-suppression.
2. Add startup process baseline tracking.
3. Add process new/exec filtering behavior.
4. Add semantic file action inference.
5. Add lightweight duplicate suppression for process/file bursts.

## 8. Acceptance Criteria

The milestone is complete when:

- the collector selbst does not appear in the sink,
- already-running processes are not emitted as new at startup,
- a newly appeared process produces a compact process event,
- file create/modify/delete/rename actions are represented as meaningful events,
- and event volume is visibly lower than the current raw stream.
