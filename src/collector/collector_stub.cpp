/*
 * File Notes:
 * - Development fallback collector used when libbpf is not available.
 * - Preserves pipeline lifecycle semantics without real kernel event ingress.
 */

#include "collector/collector.h"

#include <chrono>
#include <iostream>
#include <thread>

namespace event_logger {

class StubCollector final : public Collector {
 public:
  /**
   * @brief Initialize stub backend and retain callback.
   *
   * @param cb Raw event callback from pipeline.
   * @return Always true for stub mode.
   */
  bool Start(RawEventCallback cb) override {
    cb_ = std::move(cb);
    startup_report_ = {};
    startup_report_.backend_name = "stub";
    startup_report_.runtime_config_loaded = false;
    startup_report_.degraded = true;
    startup_report_.degrade_reason = "libbpf backend unavailable; running without kernel eBPF ingress";

    std::cerr << "[collector] stub backend active (libbpf unavailable)\n";
    return true;
  }

  /**
   * @brief Sleep to emulate blocking collector polling cadence.
   *
   * @param timeout_ms Sleep duration in milliseconds.
   */
  void PollOnce(int timeout_ms) override {
    std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));
  }

  /**
   * @brief Stub backend has no kernel stats source.
   *
   * @param out Unused.
   * @return false always.
   */
  bool ReadKernelBpfStats(KernelBpfStats* out) override {
    (void)out;
    return false;
  }

  /**
   * @brief Return stub startup report.
   */
  bool ReadStartupReport(CollectorStartupReport* out) override {
    if (!out) {
      return false;
    }
    *out = startup_report_;
    return true;
  }

  /**
   * @brief Release callback reference.
   */
  void Stop() override {
    cb_ = nullptr;
  }

 private:
  RawEventCallback cb_;
  CollectorStartupReport startup_report_;
};

Collector* CreateCollector() {
  static StubCollector collector;
  return &collector;
}

}  // namespace event_logger
