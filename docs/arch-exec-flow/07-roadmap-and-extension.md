# Roadmap and Extension Design

This document is now treated as a legacy planning note for the transition period. The primary design direction is captured in the signal-first telemetry and policy semantics documents, which supersede the older capture-first roadmap language.

## 1. Release Boundary
- Current scope: Process + File + Syscall + Network socket metadata telemetry.
- Deferred scope: DNS parsing, HTTP correlation, HTTPS/TLS strategies.

## 2. Near-Term
1. Harden process payload fidelity across distro/kernel matrix.
2. Harden file/syscall/network enter/exit correlation under pressure.
3. Validate expanded network syscall coverage (`sendto`, `recvfrom`, `shutdown`) across distros.
4. Improve startup diagnostics and domain-toggle observability.
5. Introduce a signal-first policy profile that suppresses collector self-events and startup noise.
6. Add startup baseline handling for existing processes so new-only behavior is the default.
7. Promote semantic file actions such as create/modify/delete/rename over raw open/close reporting.

## 3. Mid-Term
1. Extend machine-readable startup/report outputs for fleet diagnostics.
2. Add optional policy/filter stages in user space (opt-in, not default).
3. Add drop-accounting and backpressure controls.
4. Increase integration/regression coverage for schema and event correctness.
5. Add configurable debounce and deduplication windows for file and process events.
6. Introduce richer semantic event schema fields such as action/subject/object/outcome.

## 4. Later Domains
1. DNS telemetry.
2. HTTP metadata correlation.
3. HTTPS/TLS-aware strategies (non-intrusive by default).
4. Container/service identity enrichment.
5. Multi-sink outputs (files, streaming backends, SIEM).

## 5. Principles
- keep schema explicit and stable
- keep kernel payloads compact
- push expensive work to user space
- fail/degrade visibly via startup diagnostics
