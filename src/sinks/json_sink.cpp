/*
 * File Notes:
 * - Serializes typed events into compact JSON lines for ingestion.
 * - File-backed output with optional max-size rollover.
 */

#include "sinks/json_sink.h"

#include <cstdio>
#include <filesystem>
#include <sstream>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>

namespace event_logger {
namespace {

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

void WriteEventBody(std::ostream& out, const EventVariant& event) {
  std::visit(
      [&](const auto& ev) {
        WriteHeader(out, ev.hdr);

        using T = std::decay_t<decltype(ev)>;
        if constexpr (std::is_same_v<T, process_event>) {
          out << ",\"kind\":" << ev.kind
              << ",\"exit_code\":" << ev.exit_code
              << ",\"child_pid\":" << ev.child_pid
              << ",\"filename\":\"" << JsonEscape(ev.filename) << "\""
              << ",\"exec_path\":\"" << JsonEscape(ev.exec_path) << "\""
              << ",\"cmdline\":\"" << JsonEscape(ev.cmdline) << "\""
              << ",\"cwd\":\"" << JsonEscape(ev.cwd) << "\""
              << ",\"parent_comm\":\"" << JsonEscape(ev.parent_comm) << "\""
              << ",\"start_time_ticks\":" << ev.start_time_ticks;
        } else if constexpr (std::is_same_v<T, file_event>) {
          out << ",\"kind\":" << ev.kind
              << ",\"ret\":" << ev.ret
              << ",\"path_a\":\"" << JsonEscape(ev.path_a) << "\""
              << ",\"path_b\":\"" << JsonEscape(ev.path_b) << "\"";
        } else if constexpr (std::is_same_v<T, syscall_event>) {
          out << ",\"is_enter\":" << ev.is_enter
              << ",\"syscall_nr\":" << ev.syscall_nr
              << ",\"ret\":" << ev.ret;
        } else if constexpr (std::is_same_v<T, network_event>) {
          out << ",\"kind\":" << ev.kind
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
}

}  // namespace

JsonSink::JsonSink(std::string file_path, uint64_t max_file_size_bytes)
    : file_path_(std::move(file_path)), max_file_size_bytes_(max_file_size_bytes) {
  ready_ = OpenFileAppend();
}

bool JsonSink::OpenFileAppend() {
  std::error_code ec;

  const std::filesystem::path p(file_path_);
  const auto parent = p.parent_path();
  if (!parent.empty()) {
    std::filesystem::create_directories(parent, ec);
    ec.clear();
  }

  current_file_size_bytes_ = 0;
  if (std::filesystem::exists(p, ec)) {
    current_file_size_bytes_ = std::filesystem::file_size(p, ec);
    if (ec) {
      current_file_size_bytes_ = 0;
      ec.clear();
    }
  }

  file_out_.open(file_path_, std::ios::out | std::ios::app);
  return file_out_.is_open();
}

bool JsonSink::RotateIfNeeded(size_t next_record_bytes) {
  if (max_file_size_bytes_ == 0) {
    return true;
  }

  const uint64_t next_size = current_file_size_bytes_ + static_cast<uint64_t>(next_record_bytes);
  if (next_size <= max_file_size_bytes_) {
    return true;
  }

  file_out_.flush();
  file_out_.close();

  std::error_code ec;
  std::filesystem::remove(file_path_, ec);
  ec.clear();

  current_file_size_bytes_ = 0;
  file_out_.open(file_path_, std::ios::out | std::ios::trunc);
  if (!file_out_.is_open()) {
    return false;
  }
  file_out_.close();

  file_out_.open(file_path_, std::ios::out | std::ios::app);
  return file_out_.is_open();
}

void JsonSink::Write(const EventVariant& event) {
  if (!ready_) {
    return;
  }

  std::ostringstream line;
  line << "{";
  WriteEventBody(line, event);
  line << "}\n";

  const std::string serialized = line.str();

  if (!RotateIfNeeded(serialized.size())) {
    ready_ = false;
    return;
  }

  file_out_ << serialized;
  file_out_.flush();
  current_file_size_bytes_ += static_cast<uint64_t>(serialized.size());
}

}  // namespace event_logger
