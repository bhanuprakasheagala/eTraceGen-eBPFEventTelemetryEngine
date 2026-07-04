# eTraceGen Deep Dive Index

This documentation is written as a story: from intent, to architecture, to runtime behavior, to extension patterns.

## Reading Order
1. [System Architecture](01-system-architecture.md)
2. [Execution Story](02-execution-story.md)
3. [Event Contract and ABI](03-event-contract.md)
4. [Kernel eBPF Side](04-kernel-side.md)
5. [User-Space Pipeline](05-userspace-side.md)
6. [Build, Portability, Compatibility](06-build-portability.md)
7. [Network Event Design (socket-first)](07-network-event-design.md)
8. [Roadmap and Extensions](07-roadmap-and-extension.md)
9. [v1 Validation Suite (Linux)](08-validation-v1.md)
10. [v1 Release Preflight](09-release-preflight-v1.md)
11. [Linux Host Setup and Bring-up](linux-setup.md)
12. [Code Walk: File-by-File Deep Dive](../code-walk/README.md)

## Philosophy Behind This Project
- Keep kernel programs small, bounded, and verifier-friendly.
- Keep policy and enrichment in user space where evolution is easier.
- Preserve schema stability as the project grows into network and higher-layer telemetry.
- Grow network capture in layers: socket control plane, socket data plane, protocol parsing, and userspace enrichment.
- Handle partial kernel feature availability with explicit startup diagnostics across Linux kernels and distro configurations.
