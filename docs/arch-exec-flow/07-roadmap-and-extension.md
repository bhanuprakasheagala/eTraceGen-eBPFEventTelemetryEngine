# Roadmap and Extension Design

This roadmap explains growth path while preserving architecture quality.

## 1. Release Boundary
- Current scope: Process + File + Syscall + Network socket metadata telemetry.
- Deferred scope: DNS parsing, HTTP correlation, HTTPS/TLS strategies.

## 2. Near-Term
1. Harden process payload fidelity across distro/kernel matrix.
2. Harden file/syscall/network enter/exit correlation under pressure.
3. Validate expanded network syscall coverage (`sendto`, `recvfrom`, `shutdown`) across distros.
4. Improve startup diagnostics and domain-toggle observability.

## 3. Mid-Term
1. Extend machine-readable startup/report outputs for fleet diagnostics.
2. Add optional policy/filter stages in user space (opt-in, not default).
3. Add drop-accounting and backpressure controls.
4. Increase integration/regression coverage for schema and event correctness.

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
