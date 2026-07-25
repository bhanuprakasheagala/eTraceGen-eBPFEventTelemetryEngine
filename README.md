<div align="center">

# eTraceGen [IN PROGRESS]

### From Kernel Facts to System Knowledge

*A modular Linux Activity Intelligence Platform built with **eBPF** and **Modern C++20**.*

[![Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)]()
[![eBPF](https://img.shields.io/badge/Kernel-eBPF-green.svg)]()
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)]()
[![libbpf](https://img.shields.io/badge/libbpf-supported-success.svg)]()
[![Status](https://img.shields.io/badge/Status-Phase%201-orange.svg)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)]()

</div>

---

## Overview

Modern Linux systems generate enormous volumes of runtime telemetry. While kernel events reveal **what happened**, deriving meaningful insights requires normalization, correlation, and contextual understanding.

**eTraceGen** is a modular Linux Activity Intelligence Platform that captures kernel activity using **eBPF** and incrementally transforms low-level observations into reusable system knowledge.

Instead of treating telemetry as isolated events, eTraceGen is designed around a layered architecture where each stage adds progressively richer meaning to the data.

```mermaid
flowchart LR

subgraph OBS["Observation Layer"]
    direction TB
    A[eBPF Programs]
    B[Kernel Events]
    A --> B
end

subgraph KNOW["Knowledge Layer"]
    direction TB
    C[Canonical Events]
    D[Entity Knowledge]
    C --> D
end

subgraph INTEL["Intelligence Layer"]
    direction TB
    E[Correlation]
    F[Semantics]
    G[Policy & Intelligence]
    E --> F --> G
end

B --> C
D --> E
```

The long-term vision is to evolve from **kernel event collection** into a reusable platform capable of understanding system activity, reconstructing relationships, and enabling higher-level behavioural analysis.

> **Current Focus**
>
> Phase 1 establishes a robust observation layer by collecting kernel events, normalizing them into canonical representations, and building the foundation for future correlation and semantic analysis.
