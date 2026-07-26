#ifndef EVENT_LOGGER_METRICS_H
#define EVENT_LOGGER_METRICS_H

/*
 * File Notes:
 * - Minimal pipeline health counters.
 * - Tracks ingress quality before full observability/telemetry stack is added.
 * - Accounting note: only decode failures increment `dropped`. Events removed by
 *   self-suppression or (future) policy are NOT counted, so `decoded` does not
 *   equal "records written". Dedicated suppression counters are future work.
 */

#include <cstdint>

namespace event_logger {

/**
 * @brief Lightweight in-process counters for pipeline visibility.
 */
class Metrics {
 public:
  /** @brief Increment total raw events received by callback path. */
  void IncrementReceived() { ++received_; }
  /** @brief Increment successfully decoded event count. */
  void IncrementDecoded() { ++decoded_; }
  /** @brief Increment events dropped due to decode or validation failures. */
  void IncrementDropped() { ++dropped_; }

  /** @brief Get received events count. */
  uint64_t received() const { return received_; }
  /** @brief Get decoded events count. */
  uint64_t decoded() const { return decoded_; }
  /** @brief Get dropped events count. */
  uint64_t dropped() const { return dropped_; }

 private:
  uint64_t received_ = 0;
  uint64_t decoded_ = 0;
  uint64_t dropped_ = 0;
};

}  // namespace event_logger

#endif
