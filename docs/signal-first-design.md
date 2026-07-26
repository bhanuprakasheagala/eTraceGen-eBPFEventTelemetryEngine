# Signal-First Telemetry and Event Reduction Design

> **Scope note (read first):** the project's goal is *general system intelligence* — see
> [roadmap.md](roadmap.md). This document is a **design reference for the eventual Policy/output
> layer** (Milestone 3): how to shape and reduce output once the knowledge layers exist. Treat the
> Sysmon/Falco/auditd comparisons and security framing below as **illustrative**, not as the product
> direction. Noise reduction here is an *output concern* — the pipeline still ingests the whole fact
> stream as substrate.

This document defines an output-shaping design phase for eTraceGen. The objective is to move from a broad, low-level event stream to a focused, high-signal output — historically compared to logging products such as Sysmon, Falco, and auditd.

Status: documentation-only design reference; sequenced under [roadmap.md](roadmap.md) Milestone 3.

## 1. Problem Statement

The current telemetry stream is useful for visibility, but it is too noisy for practical operations. The main issues are:

- too many raw syscall events
- duplicate enter/exit patterns that are hard to interpret
- insufficient distinction between “new activity” and “already running activity”
- collector self-events and startup noise polluting the output
- file activity that is captured at a low level without semantic meaning such as create/modify/delete

The desired experience is:

- log new processes that appear after monitoring begins
- suppress already-running processes by default
- suppress the collector itself and its children
- capture meaningful file changes with path context and process identity
- reduce duplicates and repeated bursts into a smaller number of logical events

## 2. Design Goals

1. Reduce noise and improve signal quality in the default mode.
2. Favor semantic events over low-level kernel noise.
3. Treat monitoring as “observe delta from startup” rather than “record everything forever.”
4. Preserve a stable, extensible event contract for later implementation.
5. Keep the kernel side bounded and verifier-friendly while moving policy logic into user space.

## 3. Non-Goals for the Initial Design Phase

The first version of this strategy does not attempt to solve every possible telemetry need.

Non-goals include:

- full HTTP/DNS/TLS protocol parsing
- deep container identity inference
- exact byte-level content hashing for every file write
- perfect forensic completeness for all kernel events
- complete suppression of every benign system daemon without policy controls

## 4. Design Principles

### 4.1 Signal over volume

The system should emit fewer but more meaningful events. The default profile should emphasize:

- new process creation or exec
- file create/modify/delete/rename
- new network connection establishment
- process/file/network actions with clear subject/object semantics

### 4.2 Semantic events over raw syscalls

The implementation should produce logical events such as:

- process_started
- process_execed
- file_created
- file_modified
- file_deleted
- file_renamed
- network_connection_established

Raw syscalls should remain available only in diagnostic or debug modes, not in the default high-signal profile.

### 4.3 Baseline once, then report deltas

At startup, the monitor snapshots the current landscape and establishes a baseline. After baseline creation:

- already-running processes are treated as known entities
- newly observed processes are reported as new
- already-open or already-known objects are not treated as fresh events unless a meaningful action occurs

### 4.4 Self-suppression is a hard requirement

The collector process and its spawned children must not pollute the telemetry stream. This is a non-negotiable guardrail.

### 4.5 Policy and enrichment belong in user space

The kernel side should stay compact and deterministic. User space should own:

- stateful filtering
- baseline management
- deduplication
- enrichment such as path resolution, parent/child relationship, and process metadata

## 5. Runtime Model

The monitor should behave like a stateful observer rather than a raw event recorder.

### 5.1 Startup sequence

1. Initialize collector and load BPF object.
2. Create a startup baseline for process and file context.
3. Register the collector process identity for self-suppression.
4. Start the event pipeline.
5. Only emit events that occur after the baseline is established or that are identified as newly significant.

### 5.2 Event pipeline stages

The pipeline should be structured as follows:

1. Kernel capture
   - emit compact low-level event facts from tracepoints and syscalls
2. Early filters
   - drop self-events
   - drop events from suppressed processes or paths
   - ignore events that are clearly irrelevant in the current policy profile
3. Semantic normalization
   - translate low-level facts into logical actions such as process_exec or file_modified
4. Stateful policy evaluation
   - compare against startup baseline and recent history
   - decide whether to emit, suppress, or debounce
5. Enrichment
   - resolve paths, parent/child relationships, user/uid context, and process metadata
6. Sink emission
   - write normalized events to NDJSON or another backend

## 6. Policy Model

The system should support policy profiles rather than a single hard-coded policy.

### 6.1 Default profile: signal-first

This is the recommended default.

Behavior:

- suppress the collector process tree
- baseline existing processes at startup
- emit only new process activity after monitor start
- emit meaningful file create/modify/delete/rename operations
- suppress broad raw syscall volume
- debounce repeated events within a short window

### 6.2 Diagnostic profile: verbose

This profile is meant for debugging and investigation.

Behavior:

- enables broader syscall visibility
- disables baseline suppression for troubleshooting
- outputs more raw facts for developers

### 6.3 Strict profile: high-confidence security monitoring

This profile is meant for operational security use cases.

Behavior:

- stricter allow/deny rules
- suppress known-safe paths and background daemons
- emit only high-confidence actions

## 7. Process Tracking Strategy

### 7.1 Startup baseline for processes

At startup, the monitor should collect identities for processes that already exist. Examples of process identity include:

- tgid/pid
- parent/child relationship where available
- executable path when known
- command line when known
- start time or similar stable identity hint

These identities become the initial baseline. Processes present in the baseline are treated as already known and should not generate startup floods.

### 7.2 “New process” semantics

A process should be treated as new when it appears after startup and is not already in the process baseline. The first meaningful event for that process should be emitted with a clear indicator such as:

- observed_after_startup = true
- first_seen_ts
- first_seen_reason = exec|fork|clone|spawn

### 7.3 Suppress known processes by default

Once a process has been observed and is considered stable, subsequent normal activity should not necessarily create another “process started” event. Instead, later actions from that process should be represented under the relevant file/network/process semantics.

### 7.4 Collector suppression rules

The collector should always suppress:

- its own pid/tgid
- its own process tree where practical
- any process that is directly tracing or logging the collector environment if policy allows

## 8. File Activity Strategy

### 8.1 Intentional file semantics

The system should move away from raw open/close events and toward actions that matter operationally.

The initial semantic actions should be:

- file_created
- file_modified
- file_deleted
- file_renamed
- file_permission_changed

### 8.2 File path fidelity

For each file event, the system should strive to capture:

- full path when available
- parent directory
- basename
- process responsible
- operation type
- success or failure
- timestamp
- file identity hint such as inode or a hash-derived fingerprint when available

### 8.3 Content modification semantics

The project should avoid claiming that every file open is a content change. Instead, file modification should be inferred from meaningful patterns such as:

- a write-like syscall completed successfully
- a rename or replacement operation occurred
- a create followed by write on a new path
- a file was unlinked and replaced

This is a pragmatic model for the initial implementation and is similar to the way enterprise loggers model file-change events without requiring full content inspection.

### 8.4 File deduplication

Repeated write bursts on the same file should be collapsed into one logical event per short interval unless the policy is explicitly set to verbose mode.

## 9. Network Event Strategy

The network domain should remain intentionally narrow in the first signal-first phase.

Recommended behavior:

- emit meaningful network connections only
- suppress noisy socket metadata churn
- focus on connection initiation and state changes rather than every socket read/write syscall

This keeps the output useful while avoiding the volume profile that caused the current stream to feel too noisy.

## 10. Deduplication and Debounce Model

### 10.1 Why deduplication is needed

A high-volume stream will otherwise produce repeated events for the same action. This is especially common for:

- same process issuing repeated writes to the same file
- repeated open/close pairs during a short burst
- multiple enter/exit hooks that describe the same logical operation

### 10.2 Deduplication key

The system should deduplicate using a key such as:

- event family
- action type
- subject identity
- object identity
- outcome
- a short time window

Example:

- same process + same file path + file_modified + same short interval -> suppress duplicates

### 10.3 Debounce windows

Suggested defaults for the initial design:

- process events: 5–10 seconds
- file events: 2–5 seconds
- network events: 5 seconds

These values should be configurable and should be tuned after observing real workloads.

## 11. Event Schema Evolution

The existing payload model can evolve without breaking the entire system. The main design direction is to introduce a semantic event layer on top of the current low-level event types.

### 11.1 Existing event families remain valid

The current event families should continue to exist:

- process
- file
- syscall
- network

### 11.2 Semantic event semantics should be added

New semantic fields should describe:

- action
- subject
- object
- outcome
- reason
- is_new_observed
- suppressed_reason

This allows the pipeline to preserve the raw event while also emitting a richer logical event for downstream consumers.

## 12. Configuration Design

The policy should be configurable in YAML rather than hard-coded.

### 12.1 Example configuration structure

```yaml
policy:
  mode: signal_first
  self_suppression: true
  baseline_mode: startup_snapshot
  capture_existing_processes: false
  deduplication:
    enabled: true
    file_window_ms: 3000
    process_window_ms: 10000
    network_window_ms: 5000
  file_policy:
    meaningful_only: true
    include_create: true
    include_modify: true
    include_delete: true
    include_rename: true
  process_policy:
    emit_new_processes_only: true
    suppress_known_processes: true
  syscall_policy:
    emit_semantic_only: true
    debug_raw_syscalls: false
```

### 12.2 Configuration principles

- defaults should be safe and low-noise
- verbose or debug modes should remain available
- policy should be easy to reason about and easy to extend later

## 13. Operational Characteristics

The new policy should behave in a way that is predictable for operators:

- the first few seconds after startup may be quieter while the baseline is established
- later activity should appear as a small set of meaningful events
- users should be able to switch to verbose mode when investigating a specific issue

## 14. Implementation Phases

### Phase 1: Baseline and self-suppression

- add collector self-suppression
- add startup process baseline handling
- suppress already-running processes by default

### Phase 2: Semantic file events

- map raw file actions into create/modify/delete/rename semantics
- add path and process context
- reduce duplicate file bursts

### Phase 3: Semantic process events

- emit new process and exec events only when appropriate
- reduce duplicate process chatter
- keep parent/child correlation explicit

### Phase 4: Policy profiles and tuning

- add YAML profiles for signal-first, diagnostic, and strict modes
- tune debounce windows using real workloads
- refine suppression lists and allowlist behavior

### Phase 5: Advanced enrichment

- richer path resolution
- more complete process ancestry
- optional correlation to network and file activity

## 15. Open Questions

The design is intentionally scoped, but the following questions should be resolved before implementation:

1. Should the baseline include only processes, or also known files and network endpoints?
2. How should the system handle processes that existed before startup but later exec a new binary?
3. Should file modification semantics depend on inode identity, path identity, or both?
4. What is the right default debounce window for file and process events in real workloads?
5. Should the system support explicit allowlists for known-safe daemons or paths?
6. Should the default sink emit only semantic events, or should it keep a raw diagnostic channel as well?

## 16. Recommendation

The recommended target posture is a signal-first telemetry model:

- suppress the collector and startup churn
- baseline known processes at startup
- only emit new and meaningful process/file/network activity
- collapse repeated low-value events into a smaller set of logical records

This design is more aligned with enterprise telemetry expectations than the current capture-first approach and provides a stronger foundation for future security-oriented use cases.
