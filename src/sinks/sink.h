#ifndef EVENT_LOGGER_SINK_H
#define EVENT_LOGGER_SINK_H

/*
 * File Notes:
 * - Declares output sink abstraction for typed events.
 * - Allows plugging stdout/file/network sinks without changing upstream stages.
 */

#include "model/canonical_event.h"

namespace event_logger {

/**
 * @brief Canonical event output contract.
 */
class Sink {
 public:
  virtual ~Sink() = default;

  /**
   * @brief Export one canonical event to the sink destination.
   *
   * @param event Canonical event to serialize/forward. Its `raw` pointer gives
   *              access to the underlying typed payload for full-fidelity output.
   */
  virtual void Write(const CanonicalEvent& event) = 0;
};

}  // namespace event_logger

#endif
