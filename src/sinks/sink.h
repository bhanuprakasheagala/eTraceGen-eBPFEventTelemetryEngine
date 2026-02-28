#ifndef EVENT_LOGGER_SINK_H
#define EVENT_LOGGER_SINK_H

/*
 * File Notes:
 * - Declares output sink abstraction for typed events.
 * - Allows plugging stdout/file/network sinks without changing upstream stages.
 */

#include "decoder/decoder.h"

namespace event_logger {

/**
 * @brief Typed event output contract.
 */
class Sink {
 public:
  virtual ~Sink() = default;

  /**
   * @brief Export one typed event to the sink destination.
   *
   * @param event Typed event payload to serialize/forward.
   */
  virtual void Write(const EventVariant& event) = 0;
};

}  // namespace event_logger

#endif
