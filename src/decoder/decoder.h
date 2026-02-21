#ifndef EVENT_LOGGER_DECODER_H
#define EVENT_LOGGER_DECODER_H

/*
 * File Notes:
 * - Declares the raw-bytes to typed-event conversion boundary.
 * - Decoder is the first stage that interprets the shared ABI contract.
 */

#include <optional>
#include <span>
#include <variant>

#include "event_schema.h"

namespace event_logger {

/**
 * @brief Variant used to represent all currently supported typed event payloads.
 */
using EventVariant = std::variant<process_event, file_event, syscall_event, network_event>;

/**
 * @brief Converts raw payload bytes into typed event variants.
 */
class Decoder {
 public:
  /**
   * @brief Decode one raw event payload into a typed variant.
   *
   * @param data Raw event bytes received from collector backend.
   * @return Decoded typed event when type/size validation succeeds.
   * @return `std::nullopt` for unknown type or truncated payload.
   */
  std::optional<EventVariant> Decode(std::span<const unsigned char> data) const;
};

}  // namespace event_logger

#endif
