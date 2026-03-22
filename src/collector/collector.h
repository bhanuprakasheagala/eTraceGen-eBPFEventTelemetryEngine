#ifndef EVENT_LOGGER_COLLECTOR_H
#define EVENT_LOGGER_COLLECTOR_H

/*
 * File Notes:
 * - Defines the ingestion backend contract used by the rest of the pipeline.
 * - Collector hides libbpf ring-buffer source mechanics behind one interface.
 */

#include <functional>
#include <span>
#include <string>
#include <cstdint>

namespace event_logger {

/**
 * @brief Callback used by collector backends to forward raw event bytes.
 *
 * @param payload Read-only byte span containing one raw event payload.
 *
 * @note The collector owns source buffer lifetime only during callback execution.
 *       Downstream stages should copy data if they need to retain it.
 */
using RawEventCallback = std::function<void(std::span<const unsigned char> payload)>;

/**
 * @brief Kernel-side BPF statistics exported by eBPF maps.
 */
struct KernelBpfStats {
  uint64_t ringbuf_reserve_fail = 0;
  uint64_t file_state_save_fail = 0;
  uint64_t file_state_collision = 0;
  uint64_t file_state_miss = 0;
  uint64_t syscall_state_save_fail = 0;
  uint64_t syscall_state_collision = 0;
  uint64_t syscall_state_miss = 0;
  uint64_t network_state_save_fail = 0;
  uint64_t network_state_collision = 0;
  uint64_t network_state_miss = 0;
};

/**
 * @brief One-shot startup capability snapshot emitted by collector backend.
 */
struct CollectorStartupReport {
  std::string backend_name;
  std::string bpf_object_path;
  std::string config_path;

  uint32_t programs_total = 0;
  uint32_t programs_attached = 0;
  uint32_t programs_attach_failed = 0;

  bool runtime_config_loaded = false;
  bool map_events_found = false;
  bool map_bpf_stats_found = false;
  bool map_file_probe_enabled_found = false;
  bool map_syscall_allowlist_found = false;
  bool map_pid_allowlist_found = false;
  bool map_uid_allowlist_found = false;
  bool map_network_probe_enabled_found = false;
  bool map_network_port_allowlist_found = false;
  bool map_network_port_filter_enabled_found = false;

  bool file_probe_toggles_applied = false;
  uint32_t syscall_allowlist_applied_count = 0;
  uint32_t pid_allowlist_applied_count = 0;
  uint32_t uid_allowlist_applied_count = 0;
  bool network_probe_toggles_applied = false;
  uint32_t network_port_allowlist_applied_count = 0;

  bool degraded = false;
  std::string degrade_reason;
};

/**
 * @brief Abstract ingress backend for event retrieval.
 *
 * Implementations provide a common lifecycle regardless of the source
 * (libbpf ring buffer ingress).
 */
class Collector {
 public:
  virtual ~Collector() = default;

  /**
   * @brief Initialize backend resources and register the raw-event callback.
   *
   * @param cb Callback invoked for each received raw event payload.
   * @return true if backend initialization succeeded and polling can begin.
   * @return false if startup failed and no events will be produced.
   */
  virtual bool Start(RawEventCallback cb) = 0;

  /**
   * @brief Execute one bounded polling iteration.
   *
   * @param timeout_ms Maximum wait time for backend event polling.
   */
  virtual void PollOnce(int timeout_ms) = 0;

  /**
   * @brief Read kernel-side BPF stats if supported by backend.
   *
   * @param out Output stats structure.
   * @return true when stats were successfully read.
   * @return false when stats are unavailable or read failed.
   */
  virtual bool ReadKernelBpfStats(KernelBpfStats* out) = 0;

  /**
   * @brief Return startup capability snapshot when available.
   *
   * @param out Output startup report.
   * @return true when report is available.
   * @return false when backend has no startup report data.
   */
  virtual bool ReadStartupReport(CollectorStartupReport* out) = 0;

  /**
   * @brief Release backend resources and detach from event producers.
   */
  virtual void Stop() = 0;
};

/**
 * @brief Create the compile-time selected collector implementation.
 *
 * @return Pointer to process-wide collector instance.
 */
Collector* CreateCollector();

}  // namespace event_logger

#endif
