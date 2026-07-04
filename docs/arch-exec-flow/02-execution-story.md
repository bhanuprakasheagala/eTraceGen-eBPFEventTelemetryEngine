# Execution Story (Start to Stop)

This is the runtime story in the same order the code executes.

## 1. Build and Runtime Context
`eTraceGen` is Linux-only and builds with libbpf collector support.
`CMakeLists.txt` enforces Linux host build and required `libbpf` discovery.

Relevant file: `../CMakeLists.txt`

## 2. Process Startup and Signals
`main()` installs signal handlers for `SIGINT` and `SIGTERM`.
- `g_running = true` initially
- on signal, handler flips `g_running = false`

Relevant file: `../src/main.cpp`

## 3. Pipeline Construction
`main()` constructs:
- `Collector*` from `CreateCollector()`
- `Decoder`
- `Enricher`
- `PolicyEngine`
- `JsonSink`
- `Metrics`

## 4. Collector Start Registers Event Callback
`collector->Start(callback)` initializes libbpf object, applies runtime config maps, attaches programs, creates ring buffer, and starts ingestion.

Inside callback:
1. increment `received`
2. decode raw bytes
3. if decode fails -> increment `dropped`, return
4. increment `decoded`
5. enrich event
6. apply policy
7. write JSON

## 5. Poll Loop and Periodic Stats
Main loop:
`while (g_running) { collector->PollOnce(200); }`

Every 30 seconds, user space reads kernel BPF stats and prints a periodic line.

## 6. Stop and Shutdown Report
On shutdown:
1. read final kernel stats
2. stop collector and release libbpf resources
3. print pipeline counters (`received`, `decoded`, `dropped`)
4. print final kernel stats when available
