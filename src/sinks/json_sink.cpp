/*
 * File Notes:
 * - Serializes typed events into compact JSON lines for inspection/ingestion.
 * - Relies on schema variant and shared header fields for consistent output shape.
 */

#include "sinks/json_sink.h"

#include <cstdio>
#include <string>

namespace event_logger {
namespace {

/**
 * @brief Convert wire-level event family id into stable textual label.
 *
 * @param type Numeric event family id.
 * @return String label used in JSON output.
 */
const char* EventTypeToString(uint32_t type) {
  switch (type) {
    case EVENT_TYPE_PROCESS:
      return "process";
    case EVENT_TYPE_FILE:
      return "file";
    case EVENT_TYPE_SYSCALL:
      return "syscall";
    case EVENT_TYPE_NETWORK:
      return "network";
    default:
      return "unknown";
  }
}

/**
 * @brief Escape C string for JSON string literal safety.
 *
 * @param s Input C string (may be null).
 * @return Escaped UTF-8/byte-preserving JSON-safe string.
 */
std::string JsonEscape(const char* s) {
  std::string out;
  if (!s) {
    return out;
  }

  for (const unsigned char* p = reinterpret_cast<const unsigned char*>(s); *p != '\0'; ++p) {
    const unsigned char c = *p;
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20) {
          char buf[7] = {};
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }

  return out;
}

/**
 * @brief Render fixed-size binary address bytes as lowercase hex string.
 */
std::string BytesToHex(const uint8_t* bytes, size_t size) {
  static const char kHex[] = "0123456789abcdef";
  if (!bytes || size == 0) {
    return {};
  }

  std::string out;
  out.reserve(size * 2);
  for (size_t i = 0; i < size; ++i) {
    const uint8_t b = bytes[i];
    out.push_back(kHex[(b >> 4) & 0x0F]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

/**
 * @brief Write common event envelope fields.
 *
 * @param out Output stream.
 * @param h Common event header.
 */
void WriteHeader(std::ostream& out, const event_header& h) {
  out << "\"ts_ns\":" << h.ts_ns << ","
      << "\"type\":\"" << EventTypeToString(h.type) << "\"," 
      << "\"pid\":" << h.pid << ","
      << "\"tgid\":" << h.tgid << ","
      << "\"ppid\":" << h.ppid << ","
      << "\"uid\":" << h.uid << ","
      << "\"gid\":" << h.gid << ","
      << "\"comm\":\"" << JsonEscape(h.comm) << "\"";
}

}  // namespace

/**
 * @brief Serialize one typed event into NDJSON-style output.
 *
 * @param event Typed event payload.
 */
void JsonSink::Write(const EventVariant& event) {
  out_ << "{";

  std::visit(
      [&](const auto& ev) {
        WriteHeader(out_, ev.hdr);

        using T = std::decay_t<decltype(ev)>;
        if constexpr (std::is_same_v<T, process_event>) {
          out_ << ",\"kind\":" << ev.kind
               << ",\"exit_code\":" << ev.exit_code
               << ",\"child_pid\":" << ev.child_pid
               << ",\"filename\":\"" << JsonEscape(ev.filename) << "\""
               << ",\"exec_path\":\"" << JsonEscape(ev.exec_path) << "\""
               << ",\"cmdline\":\"" << JsonEscape(ev.cmdline) << "\""
               << ",\"cwd\":\"" << JsonEscape(ev.cwd) << "\""
               << ",\"parent_comm\":\"" << JsonEscape(ev.parent_comm) << "\""
               << ",\"start_time_ticks\":" << ev.start_time_ticks;
        } else if constexpr (std::is_same_v<T, file_event>) {
          out_ << ",\"kind\":" << ev.kind
               << ",\"ret\":" << ev.ret
               << ",\"path_a\":\"" << JsonEscape(ev.path_a) << "\""
               << ",\"path_b\":\"" << JsonEscape(ev.path_b) << "\"";
        } else if constexpr (std::is_same_v<T, syscall_event>) {
          out_ << ",\"is_enter\":" << ev.is_enter
               << ",\"syscall_nr\":" << ev.syscall_nr
               << ",\"ret\":" << ev.ret;
        } else if constexpr (std::is_same_v<T, network_event>) {
          out_ << ",\"kind\":" << ev.kind
               << ",\"fd\":" << ev.fd
               << ",\"ret\":" << ev.ret
               << ",\"domain\":" << ev.domain
               << ",\"sock_type\":" << ev.sock_type
               << ",\"protocol\":" << ev.protocol
               << ",\"addr_family\":" << ev.addr_family
               << ",\"src_port\":" << ev.src_port
               << ",\"dst_port\":" << ev.dst_port
               << ",\"src_addr_hex\":\"" << BytesToHex(ev.src_addr, sizeof(ev.src_addr)) << "\""
               << ",\"dst_addr_hex\":\"" << BytesToHex(ev.dst_addr, sizeof(ev.dst_addr)) << "\"";
        }
      },
      event);

  out_ << "}\n";
}

}  // namespace event_logger
