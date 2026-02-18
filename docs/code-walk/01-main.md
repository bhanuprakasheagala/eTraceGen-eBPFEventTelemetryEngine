# main.cpp Walk

Source: `../../src/main.cpp`

## Purpose
`main.cpp` is the orchestration layer. It does not know kernel internals; it only wires modules into a deterministic event loop.

## Execution Steps
1. Install signal handlers for shutdown control (`SIGINT`, `SIGTERM`).
2. Construct pipeline objects.
3. Start collector with callback.
4. Read and print collector startup capability report.
5. Poll until shutdown flag flips.
6. Stop collector and print metrics.

## Important Blocks and Why They Matter
- `g_running` atomic flag
  - invariant: loop termination is controlled by signals, not exceptions.
- Signal handler `OnSignal`
  - invariant: handler only flips flag, does no heavy work.
- `PrintStartupReport`
  - prints one-line capability summary so degraded startup is immediately visible.
- Callback registration in `collector->Start(...)`
  - callback is the event data path boundary.
- Decode failure accounting (`metrics.IncrementDropped()`)
  - dropped events are explicit and measurable.
- Poll loop (`collector->PollOnce(200)`)
  - pacing and responsiveness are controlled by poll timeout.
- Final metrics and kernel stats output
  - gives immediate operational sanity check.

## Dataflow Inside Callback
```text
raw bytes
  -> metrics.received++
  -> decoder.Decode(raw)
     -> fail: metrics.dropped++ and return
     -> ok: metrics.decoded++
            -> enricher.Enrich(event)
            -> policy.Allow(event)
               -> false: return
               -> true: sink.Write(event)
```

## Extension Guidance
- Add hot-reload config checks in the poll loop.
- Add periodic metrics flush in the same loop.
- Keep callback fast; move expensive work to bounded worker pipelines only when needed.
