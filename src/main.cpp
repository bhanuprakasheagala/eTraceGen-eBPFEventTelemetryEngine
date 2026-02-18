/*
 * File Notes:
 * - Process entry point and pipeline orchestrator.
 * - Owns lifecycle: startup, event loop, shutdown, and coarse health counters.
 */

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>

#include "collector/collector.h"
#include "decoder/decoder.h"
#include "enricher/enricher.h"
#include "metrics/metrics.h"
#include "policy/policy.h"
#include "sinks/json_sink.h"

namespace {
std::atomic<bool> g_running{true};

/**
 * @brief Signal handler used to request graceful shutdown.
 *
 * @param sig Received signal number (unused).
 *
 * @note Handler intentionally performs only an atomic flag update.
 */
void OnSignal(int /*sig*/) { g_running = false; }

void PrintKernelStats(const event_logger::KernelBpfStats& s, const char* prefix) {
  std::cerr << prefix << " ringbuf_reserve_fail=" << s.ringbuf_reserve_fail
            << " file_state_save_fail=" << s.file_state_save_fail
            << " file_state_collision=" << s.file_state_collision
            << " file_state_miss=" << s.file_state_miss
            << " syscall_state_save_fail=" << s.syscall_state_save_fail
            << " syscall_state_collision=" << s.syscall_state_collision
            << " syscall_state_miss=" << s.syscall_state_miss
            << " network_state_save_fail=" << s.network_state_save_fail
            << " network_state_collision=" << s.network_state_collision
            << " network_state_miss=" << s.network_state_miss << "\n";
}

void PrintStartupReport(const event_logger::CollectorStartupReport& r) {
  std::cerr << "startup_report backend=" << r.backend_name
            << " bpf_object_path=" << (r.bpf_object_path.empty() ? "n/a" : r.bpf_object_path)
            << " config_path=" << (r.config_path.empty() ? "n/a" : r.config_path)
            << " programs_total=" << r.programs_total
            << " programs_attached=" << r.programs_attached
            << " programs_attach_failed=" << r.programs_attach_failed
            << " runtime_config_loaded=" << (r.runtime_config_loaded ? "true" : "false")
            << " map_events_found=" << (r.map_events_found ? "true" : "false")
            << " map_bpf_stats_found=" << (r.map_bpf_stats_found ? "true" : "false")
            << " map_file_probe_enabled_found=" << (r.map_file_probe_enabled_found ? "true" : "false")
            << " map_syscall_allowlist_found=" << (r.map_syscall_allowlist_found ? "true" : "false")
            << " map_pid_allowlist_found=" << (r.map_pid_allowlist_found ? "true" : "false")
            << " map_uid_allowlist_found=" << (r.map_uid_allowlist_found ? "true" : "false")
            << " map_network_probe_enabled_found="
            << (r.map_network_probe_enabled_found ? "true" : "false")
            << " map_network_port_allowlist_found="
            << (r.map_network_port_allowlist_found ? "true" : "false")
            << " map_network_port_filter_enabled_found="
            << (r.map_network_port_filter_enabled_found ? "true" : "false")
            << " file_probe_toggles_applied=" << (r.file_probe_toggles_applied ? "true" : "false")
            << " syscall_allowlist_applied_count=" << r.syscall_allowlist_applied_count
            << " pid_allowlist_applied_count=" << r.pid_allowlist_applied_count
            << " uid_allowlist_applied_count=" << r.uid_allowlist_applied_count
            << " network_probe_toggles_applied="
            << (r.network_probe_toggles_applied ? "true" : "false")
            << " network_port_allowlist_applied_count=" << r.network_port_allowlist_applied_count
            << " degraded=" << (r.degraded ? "true" : "false");

  if (!r.degrade_reason.empty()) {
    std::cerr << " degrade_reason=\"" << r.degrade_reason << "\"";
  }
  std::cerr << "\n";
}
}  // namespace

/**
 * @brief eTraceGen process entry point.
 *
 * Initializes pipeline components, starts collector ingestion, executes
 * the poll loop, and emits shutdown summaries.
 *
 * @return 0 on graceful completion.
 * @return 1 when collector startup fails.
 */
int main() {
  std::signal(SIGINT, OnSignal);
  std::signal(SIGTERM, OnSignal);

  auto* collector = event_logger::CreateCollector();
  event_logger::Decoder decoder;
  event_logger::Enricher enricher;
  event_logger::PolicyEngine policy;
  event_logger::JsonSink sink(std::cout);
  event_logger::Metrics metrics;

  const bool started = collector->Start([&](std::span<const unsigned char> raw) {
    metrics.IncrementReceived();

    auto decoded = decoder.Decode(raw);
    if (!decoded.has_value()) {
      metrics.IncrementDropped();
      return;
    }

    metrics.IncrementDecoded();
    auto event = *decoded;

    enricher.Enrich(event);
    if (!policy.Allow(event)) {
      return;
    }

    sink.Write(event);
  });

  event_logger::CollectorStartupReport startup_report{};
  if (collector->ReadStartupReport(&startup_report)) {
    PrintStartupReport(startup_report);
  }

  if (!started) {
    std::cerr << "failed to start collector\n";
    return 1;
  }

  using clock = std::chrono::steady_clock;
  auto next_stats_report = clock::now() + std::chrono::seconds(30);

  while (g_running) {
    collector->PollOnce(200);

    const auto now = clock::now();
    if (now >= next_stats_report) {
      event_logger::KernelBpfStats periodic_stats{};
      if (collector->ReadKernelBpfStats(&periodic_stats)) {
        PrintKernelStats(periodic_stats, "kernel_stats_periodic");
      }
      next_stats_report = now + std::chrono::seconds(30);
    }
  }

  event_logger::KernelBpfStats kernel_stats{};
  const bool has_kernel_stats = collector->ReadKernelBpfStats(&kernel_stats);

  collector->Stop();

  std::cerr << "received=" << metrics.received() << " decoded=" << metrics.decoded()
            << " dropped=" << metrics.dropped() << "\n";

  if (has_kernel_stats) {
    PrintKernelStats(kernel_stats, "kernel_stats_final");
  }

  return 0;
}
