# Collector Interface and Backend Walk

Sources:
- `../../src/collector/collector.h`
- `../../src/collector/collector_libbpf.cpp`

## Why Collector Exists
Collector isolates libbpf ingress mechanics from pipeline processing.

## Interface Contract
`Collector` methods:
- `Start(RawEventCallback cb)`
- `PollOnce(int timeout_ms)`
- `ReadKernelBpfStats(KernelBpfStats* out)`
- `ReadStartupReport(CollectorStartupReport* out)`
- `Stop()`

## Startup Path
- configure libbpf
- resolve object/config paths
- open/load BPF object
- discover map/program availability
- apply runtime domain/probe toggles (`process`, `file`, `syscall`, `network_socket`)
- attach programs best-effort
- create ring buffer reader
- publish startup report

## Poll Path
- ring buffer poll
- ignore `EINTR`, log unexpected poll errors

## Event Bridge
- convert `(void*, size)` to `std::span<const unsigned char>`
- forward to callback

## Stop Path
- free ring buffer
- destroy links
- close BPF object
- clear callback

## Failure Surface
- open/load failure: startup fails
- all attach failures: startup fails
- partial attach failure: continue + degraded startup report
- ring buffer creation failure: startup fails
