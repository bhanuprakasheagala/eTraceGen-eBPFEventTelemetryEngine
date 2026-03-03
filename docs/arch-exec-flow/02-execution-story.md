# Execution Story (Start to Stop)

This is the runtime story in the same order the code executes.

## 1. Build-Time Branching Chooses Collector Backend
`CMakeLists.txt` checks for `libbpf`.
- If found: compile `collector_libbpf.cpp`
- Else: compile `collector_stub.cpp`

Why this exists:
- development environments differ
- portability means "run with best available backend"

Relevant file: `../CMakeLists.txt`

## 2. Process Startup and Control Signals
`main()` installs signal handlers for `SIGINT` and `SIGTERM`.
- `g_running = true` initially
- on signal, handler flips `g_running = false`

Why this exists:
- deterministic shutdown without abrupt teardown

Relevant file: `../src/main.cpp`

## 3. Pipeline Construction
`main()` constructs all pipeline blocks:
- `Collector*` from `CreateCollector()`
- `Decoder`
- `Enricher`
- `PolicyEngine`
- `JsonSink`
- `Metrics`

Why objects are separate:
- each stage can evolve independently
- easier replacement and testing

## 4. Collector Start Registers Event Callback
`collector->Start(callback)` starts event ingestion.
The callback is the core data path.

Inside callback:
1. increment `received`
2. decode raw bytes
3. if decode fails -> increment `dropped`, return
4. increment `decoded`
5. enrich event
6. apply policy
7. write JSON

Why callback-driven design:
- collector only handles ingress mechanics
- business pipeline remains backend-agnostic

## 5. Poll Loop Runs Until Shutdown
`while (g_running) { collector->PollOnce(200); }`

Why polling:
- simple, explicit event loop
- easy to add periodic tasks later (stats flush, config reload)

## 6. Stop and Report
`collector->Stop()` releases resources.
Program prints metric counters.

Why this matters:
- transparent operational behavior
- easy sanity checks during development

