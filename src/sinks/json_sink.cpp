/*
 * File Notes:
 * - Serializes typed events into compact JSON lines for ingestion.
 * - File-backed output with optional max-size rollover.
 * - Emits unified process_info for every event, sourced from the EntityRegistry.
 */

#include "sinks/json_sink.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>

#include "registry/entity_registry.h"

namespace event_logger {
namespace {

/**
 *  Return steady-clock timestamp in nanoseconds for flush scheduling.
 */
uint64_t NowMonoNs() {
  using clock = std::chrono::steady_clock;
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(clock::now().time_since_epoch()).count());
}

/**
 *  Convert numeric event family into stable JSON type label.
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

const char* NetworkEventKindToString(uint32_t kind) {
  switch (kind) {
    case NETWORK_SOCKET:
      return "socket";
    case NETWORK_CONNECT:
      return "connect";
    case NETWORK_ACCEPT:
      return "accept";
    case NETWORK_BIND:
      return "bind";
    case NETWORK_LISTEN:
      return "listen";
    case NETWORK_CLOSE:
      return "close";
    case NETWORK_SENDTO:
      return "sendto";
    case NETWORK_RECVFROM:
      return "recvfrom";
    case NETWORK_SHUTDOWN:
      return "shutdown";
    case NETWORK_SOCKETPAIR:
      return "socketpair";
    case NETWORK_ACCEPT4:
      return "accept4";
    case NETWORK_GETSOCKNAME:
      return "getsockname";
    case NETWORK_GETPEERNAME:
      return "getpeername";
    case NETWORK_SETSOCKOPT:
      return "setsockopt";
    case NETWORK_GETSOCKOPT:
      return "getsockopt";
    case NETWORK_SENDMSG:
      return "sendmsg";
    case NETWORK_RECVMSG:
      return "recvmsg";
    case NETWORK_READ:
      return "read";
    case NETWORK_WRITE:
      return "write";
    case NETWORK_READV:
      return "readv";
    case NETWORK_WRITEV:
      return "writev";
    case NETWORK_SENDMMSG:
      return "sendmmsg";
    case NETWORK_RECVMMSG:
      return "recvmmsg";
    default:
      return "unknown";
  }
}

const char* NetworkDirectionToString(uint32_t direction) {
  switch (direction) {
    case NETWORK_DIRECTION_INBOUND:
      return "inbound";
    case NETWORK_DIRECTION_OUTBOUND:
      return "outbound";
    default:
      return "unknown";
  }
}

const char* NetworkTransportToString(uint32_t transport) {
  switch (transport) {
    case NETWORK_TRANSPORT_TCP:
      return "tcp";
    case NETWORK_TRANSPORT_UDP:
      return "udp";
    case NETWORK_TRANSPORT_UNIX:
      return "unix";
    case NETWORK_TRANSPORT_RAW:
      return "raw";
    default:
      return "unknown";
  }
}

/**
 *  Escape raw text for safe JSON string embedding.
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

std::string JsonEscape(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (unsigned char c : s) {
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
 *  Render fixed-size binary address bytes as lowercase hex string.
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
 *  Serialize common event header fields into JSON key/value pairs.
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

/**
 *  Serialize normalized process_info block shared by every event type.
 */
void WriteProcessInfo(std::ostream& out, const event_header& h, const ProcessEntity* pe) {
  // Identity fields come from the event header (authoritative for this event);
  // rich fields come from the resolved registry entity (empty if unresolved).
  static const std::string kEmpty;
  out << ",\"process_info\":{"
      << "\"pid\":" << h.pid << ","
      << "\"tgid\":" << h.tgid << ","
      << "\"ppid\":" << h.ppid << ","
      << "\"uid\":" << h.uid << ","
      << "\"gid\":" << h.gid << ","
      << "\"comm\":\"" << JsonEscape(h.comm) << "\","
      << "\"exec_path\":\"" << JsonEscape(pe ? pe->exec_path : kEmpty) << "\","
      << "\"cmdline\":\"" << JsonEscape(pe ? pe->cmdline : kEmpty) << "\","
      << "\"cwd\":\"" << JsonEscape(pe ? pe->cwd : kEmpty) << "\","
      << "\"parent_comm\":\"" << JsonEscape(pe ? pe->parent_comm : kEmpty) << "\","
      << "\"start_time_ticks\":" << (pe ? pe->start_time_ticks : static_cast<uint64_t>(0))
      << "}";
}

/**
 *  Serialize a single network endpoint into JSON fields.
 */
void WriteNetworkEndpoint(std::ostream& out, const std::string& label, const network_endpoint& ep) {
  const size_t addr_len = std::min<size_t>(ep.addr_len, sizeof(ep.addr));
  out << ",\"" << label << "_family\":" << ep.family
      << ",\"" << label << "_port\":" << ep.port
      << ",\"" << label << "_addr_len\":" << ep.addr_len
      << ",\"" << label << "_addr\":\"" << BytesToHex(ep.addr, addr_len) << "\""
      << ",\"" << label << "_path\":\"" << JsonEscape(ep.path) << "\"";
}

/**
 *  Serialize typed payload into one JSON object body.
 *
 * Includes both raw event fields and normalized process_info context for
 * downstream consumers that join process identity across domains.
 */
void WriteEventBody(std::ostream& out, const CanonicalEvent& canonical) {
  const EventVariant& event = *canonical.raw;
  const ProcessEntity* pe = canonical.subject_process;

  std::visit(
      [&](const auto& ev) {
        WriteHeader(out, ev.hdr);
        WriteProcessInfo(out, ev.hdr, pe);

        // Stable knowledge-layer identity resolved by the EntityRegistry.
        out << ",\"entity_id\":" << canonical.subject.id;
        if (canonical.object_ref.id != 0) {
          out << ",\"object_entity_id\":" << canonical.object_ref.id;
        }

        using T = std::decay_t<decltype(ev)>;
        if constexpr (std::is_same_v<T, process_event>) {
          // Rich process context comes from the registry entity (single source of
          // truth); raw kind/exit_code/child_pid stay from the event payload.
          static const std::string kEmpty;
          out << ",\"kind\":" << ev.kind
              << ",\"exit_code\":" << ev.exit_code
              << ",\"child_pid\":" << ev.child_pid
              << ",\"filename\":\"" << JsonEscape(pe ? pe->exec_path : kEmpty) << "\""
              << ",\"exec_path\":\"" << JsonEscape(pe ? pe->exec_path : kEmpty) << "\""
              << ",\"cmdline\":\"" << JsonEscape(pe ? pe->cmdline : kEmpty) << "\""
              << ",\"cwd\":\"" << JsonEscape(pe ? pe->cwd : kEmpty) << "\""
              << ",\"parent_comm\":\"" << JsonEscape(pe ? pe->parent_comm : kEmpty) << "\""
              << ",\"start_time_ticks\":" << (pe ? pe->start_time_ticks : static_cast<uint64_t>(0));
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
          out << ",\"event_name\":\"" << NetworkEventKindToString(ev.kind) << "\""
              << ",\"kind\":" << ev.kind
              << ",\"fd\":" << ev.fd
              << ",\"peer_fd\":" << ev.peer_fd
              << ",\"ret\":" << ev.ret
              << ",\"domain\":" << ev.domain
              << ",\"sock_type\":" << ev.sock_type
              << ",\"protocol\":" << ev.protocol
              << ",\"flags\":" << ev.flags
              << ",\"backlog\":" << ev.backlog
              << ",\"how\":" << ev.how
              << ",\"opt_level\":" << ev.opt_level
              << ",\"opt_name\":" << ev.opt_name
              << ",\"opt_len\":" << ev.opt_len
              << ",\"optval_prefix\":\"" << JsonEscape(std::string(reinterpret_cast<const char*>(ev.optval_prefix), sizeof(ev.optval_prefix))) << "\""
              << ",\"flow_id\":" << ev.flow_id
              << ",\"socket_id\":" << ev.socket_id
              << ",\"direction\":\"" << NetworkDirectionToString(ev.direction) << "\""
              << ",\"transport\":\"" << NetworkTransportToString(ev.transport) << "\""
              << ",\"bytes_requested\":" << ev.bytes_requested
              << ",\"bytes_transferred\":" << ev.bytes_transferred
              << ",\"bytes_captured\":" << ev.bytes_captured
              << ",\"bytes_truncated\":" << ev.bytes_truncated;
          WriteNetworkEndpoint(out, "local", ev.local);
          WriteNetworkEndpoint(out, "remote", ev.remote);
        }
      },
      event);
}

}  // namespace

JsonSink::JsonSink(std::string file_path, uint64_t max_file_size_bytes)
    : file_path_(std::move(file_path)), max_file_size_bytes_(max_file_size_bytes) {
  last_flush_mono_ns_ = NowMonoNs();
  ready_ = OpenFileAppend();
}

JsonSink::~JsonSink() { ForceFlush(); }

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

  ForceFlush();
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

void JsonSink::MaybeFlush() {
  if (!file_out_.is_open()) {
    return;
  }

  static constexpr uint64_t kFlushEveryRecords = 256;
  static constexpr uint64_t kFlushIntervalNs = 250000000ULL;

  const uint64_t now_ns = NowMonoNs();
  if (pending_records_since_flush_ < kFlushEveryRecords &&
      (now_ns - last_flush_mono_ns_) < kFlushIntervalNs) {
    return;
  }

  file_out_.flush();
  pending_records_since_flush_ = 0;
  last_flush_mono_ns_ = now_ns;
}

void JsonSink::ForceFlush() {
  if (!file_out_.is_open()) {
    return;
  }

  file_out_.flush();
  pending_records_since_flush_ = 0;
  last_flush_mono_ns_ = NowMonoNs();
}

void JsonSink::Write(const CanonicalEvent& event) {
  if (!ready_) {
    return;
  }
  if (!event.raw) {
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
  current_file_size_bytes_ += static_cast<uint64_t>(serialized.size());
  ++pending_records_since_flush_;
  MaybeFlush();
}


}  // namespace event_logger
