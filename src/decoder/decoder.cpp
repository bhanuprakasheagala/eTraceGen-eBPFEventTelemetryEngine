/*
 * File Notes:
 * - Implements strict size/type checks before copying raw payloads into typed structs.
 * - Prevents downstream stages from seeing malformed or partial events.
 */

#include "decoder/decoder.h"

#include <cstring>

namespace event_logger {

/**
 * @brief Decode raw event bytes into one of the supported event payload types.
 *
 * @param data Raw event bytes from collector callback.
 * @return Decoded event variant when payload type and size are valid.
 * @return `std::nullopt` when payload is too short or type is unsupported.
 */
std::optional<EventVariant> Decoder::Decode(std::span<const unsigned char> data) const {
  if (data.size() < sizeof(event_header)) {
    return std::nullopt;
  }

  const auto* hdr = reinterpret_cast<const event_header*>(data.data());
  const uint32_t wire_size = hdr->size;
  if (wire_size < sizeof(event_header) || wire_size > data.size()) {
    return std::nullopt;
  }

  if (hdr->type == EVENT_TYPE_PROCESS && wire_size == sizeof(process_event) &&
      data.size() >= sizeof(process_event)) {
    process_event ev{};
    std::memcpy(&ev, data.data(), sizeof(ev));
    return ev;
  }

  if (hdr->type == EVENT_TYPE_FILE && wire_size == sizeof(file_event) &&
      data.size() >= sizeof(file_event)) {
    file_event ev{};
    std::memcpy(&ev, data.data(), sizeof(ev));
    return ev;
  }

  if (hdr->type == EVENT_TYPE_SYSCALL && wire_size == sizeof(syscall_event) &&
      data.size() >= sizeof(syscall_event)) {
    syscall_event ev{};
    std::memcpy(&ev, data.data(), sizeof(ev));
    return ev;
  }

  if (hdr->type == EVENT_TYPE_NETWORK && wire_size == sizeof(network_event) &&
      data.size() >= sizeof(network_event)) {
    network_event ev{};
    std::memcpy(&ev, data.data(), sizeof(ev));
    return ev;
  }

  return std::nullopt;
}

}  // namespace event_logger
