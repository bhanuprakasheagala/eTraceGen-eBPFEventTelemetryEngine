#ifndef EVENT_LOGGER_JSON_SINK_H
#define EVENT_LOGGER_JSON_SINK_H

/*
 * File Notes:
 * - Concrete sink that renders events as line-delimited JSON objects.
 * - Used as default human-readable output during development.
 */

#include <ostream>

#include "sinks/sink.h"

namespace event_logger {

/**
 * @brief Sink that writes one JSON object per event line.
 */
class JsonSink final : public Sink {
 public:
  /**
   * @brief Construct JSON sink over caller-provided stream.
   *
   * @param out Destination stream for serialized events.
   */
  explicit JsonSink(std::ostream& out) : out_(out) {}

  /**
   * @brief Serialize and write one typed event as JSON.
   *
   * @param event Typed event payload.
   */
  void Write(const EventVariant& event) override;

 private:
  std::ostream& out_;
};

}  // namespace event_logger

#endif
