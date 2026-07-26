# eTraceGen Documentation

A lean, forward-looking documentation set. Start with the roadmap for where the project is going,
then the architecture and event contract for how it works today.

**Goal in one line:** *From Kernel Observations to System Intelligence* — ingest the whole stream of
kernel facts and progressively transform it into reusable system knowledge and intelligence.

## Direction
- [roadmap.md](roadmap.md) — the current, sequenced plan (build the Knowledge Layer:
  Canonical Event Model + Entity Registry → Correlation → Semantic).
- [signal-first-design.md](signal-first-design.md) — design reference for the eventual Policy/output
  layer (noise reduction, event shaping).
- [policy-and-semantics.md](policy-and-semantics.md) — design reference for the Semantic + Policy
  layer (subject/action/object/outcome).

## How it works today
- [architecture.md](architecture.md) — kernel/user-space split, component graph, source map.
- [event-contract.md](event-contract.md) — the kernel↔userspace ABI (the stable transport layer).
- [network-design.md](network-design.md) — socket-first network design (implemented, not yet built in).

## Operating it
- [setup.md](setup.md) — Linux build, run, validate, troubleshoot.
- [verification-checklist.md](verification-checklist.md) — step-by-step build/run verification with
  expected outputs and pass/fail criteria (use after any change).

## Contributing
- [commenting-guidelines.md](commenting-guidelines.md) — Doxygen-first commenting strategy.

> **Current state in one line:** a working capture-first observation engine (process/file/syscall)
> that emits raw kernel facts. The next step is to build the knowledge layers that turn those facts
> into system intelligence. Network handlers exist but are not yet compiled in. See [roadmap.md](roadmap.md).
