# Code Walk: File-by-File Deep Dive

This section is the low-level companion to the architecture docs.

Reading order is the runtime order:
1. [main.cpp Walk](01-main.md)
2. [Collector Interface and Backends](02-collector.md)
3. [Schema and Decoder](03-schema-and-decoder.md)
4. [Pipeline Stages: Enricher, Policy, Sink, Metrics](04-pipeline-stages.md)
5. [Kernel eBPF Program Walk](05-kernel-bpf.md)
6. [Build and Wiring Walk](06-build-and-wiring.md)

## How to Use This Walk
- Read each file with the source open side-by-side.
- Focus on invariants and failure behavior first.
- Then read extension notes to see where to add the next feature safely.

