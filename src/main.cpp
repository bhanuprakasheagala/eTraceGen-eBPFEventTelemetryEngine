/*
 * File Notes:
 * - Process entry point and pipeline orchestrator.
 * - Owns lifecycle: startup, event loop, shutdown, and coarse health counters.
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#include "collector/collector.h"
#include "decoder/decoder.h"
#include "enricher/enricher.h"
#include "metrics/metrics.h"
#include "policy/policy.h"
#include "sinks/json_sink.h"

namespace {
std::atomic<bool> g_running{true};

struct SinkRuntimeConfig {
  std::string path = "/var/log/etracegen/events.ndjson";
  uint64_t max_file_size_bytes = 100ULL * 1024ULL * 1024ULL;
};

void OnSignal(int /*sig*/) { g_running = false; }

std::string Trim(std::string s) {
  const auto not_space = [](unsigned char c) { return !std::isspace(c); };
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
  s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
  return s;
}

std::string DefaultConfigPath() {
  const char* env_path = std::getenv("ETRACEGEN_CONFIG");
  return env_path ? env_path : "config/default.yaml";
}

SinkRuntimeConfig LoadSinkRuntimeConfig() {
  SinkRuntimeConfig cfg;

  std::ifstream in(DefaultConfigPath());
  if (!in.is_open()) {
    return cfg;
  }

  bool in_sink = false;
  std::string line;
  while (std::getline(in, line)) {
    const auto hash_pos = line.find('#');
    if (hash_pos != std::string::npos) {
      line = line.substr(0, hash_pos);
    }

    const std::string trimmed = Trim(line);
    if (trimmed.empty()) {
      continue;
    }

    if (trimmed == "sink:") {
      in_sink = true;
      continue;
    }

    if (trimmed.back() == ':' && trimmed != "sink:") {
      in_sink = false;
      continue;
    }

    if (!in_sink) {
      continue;
    }

    const auto colon = trimmed.find(':');
    if (colon == std::string::npos) {
      continue;
    }

    const std::string key = Trim(trimmed.substr(0, colon));
    std::string value = Trim(trimmed.substr(colon + 1));

    if (value.size() >= 2 && ((value.front() == '"' && value.back() == '"') ||
                              (value.front() == '\'' && value.back() == '\''))) {
      value = value.substr(1, value.size() - 2);
    }

    if (key == "path") {
      cfg.path = value;
    } else if (key == "max_file_size_bytes") {
      try {
        cfg.max_file_size_bytes = std::stoull(value);
      } catch (...) {
        // Keep default when parse fails.
      }
    }
  }

  return cfg;
}

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
            << " map_file_probe_enabled_found="
            << (r.map_file_probe_enabled_found ? "true" : "false")
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

std::unique_ptr<event_logger::JsonSink> BuildSink() {
  const SinkRuntimeConfig cfg = LoadSinkRuntimeConfig();
  auto sink = std::make_unique<event_logger::JsonSink>(cfg.path, cfg.max_file_size_bytes);

  std::cerr << "[sink] file_json path=" << cfg.path
            << " max_file_size_bytes=" << cfg.max_file_size_bytes << "\n";

  return sink;
}
}  // namespace

int main() {
  std::signal(SIGINT, OnSignal);
  std::signal(SIGTERM, OnSignal);

  auto* collector = event_logger::CreateCollector();
  event_logger::Decoder decoder;
  event_logger::Enricher enricher;
  event_logger::PolicyEngine policy;
  auto sink = BuildSink();
  if (!sink || !sink->IsReady()) {
    std::cerr << "failed to initialize file sink; check sink.path permissions\n";
    return 1;
  }

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

    sink->Write(event);
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
