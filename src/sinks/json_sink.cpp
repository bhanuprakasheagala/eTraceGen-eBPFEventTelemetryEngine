/*
 * File Notes:
 * - Serializes typed events into compact JSON lines for ingestion.
 * - File-backed output with optional max-size rollover.
 * - Emits unified process_info for every event using a bounded userspace cache.
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
#include <unordered_map>
#include <utility>
#include <unistd.h>

namespace event_logger {
namespace {

struct ProcessInfoSnapshot {
  uint32_t pid = 0;
  uint32_t tgid = 0;
  uint32_t ppid = 0;
  uint32_t uid = 0;
  uint32_t gid = 0;
  std::string comm;
  std::string exec_path;
  std::string cmdline;
  std::string cwd;
  std::string parent_comm;
  uint64_t start_time_ticks = 0;
};

class ProcessInfoCache {
 public:
  ProcessInfoSnapshot BuildForEvent(const EventVariant& event) {
    return std::visit(
        [&](const auto& ev) -> ProcessInfoSnapshot {
          ProcessInfoSnapshot snapshot = BuildFromHeader(ev.hdr);

          using T = std::decay_t<decltype(ev)>;
          if constexpr (std::is_same_v<T, process_event>) {
            const bool has_rich_fields = ev.exec_path[0] != '\0' || ev.cmdline[0] != '\0' ||
                                         ev.cwd[0] != '\0' || ev.parent_comm[0] != '\0' ||
                                         ev.start_time_ticks != 0;

            const uint32_t key = snapshot.tgid != 0 ? snapshot.tgid : snapshot.pid;
            if (key == 0) {
              return snapshot;
            }

            if (ev.exec_path[0] != '\0') {
              snapshot.exec_path = ev.exec_path;
            }
            if (ev.cmdline[0] != '\0') {
              snapshot.cmdline = ev.cmdline;
            }
            if (ev.cwd[0] != '\0') {
              snapshot.cwd = ev.cwd;
            }
            if (ev.parent_comm[0] != '\0') {
              snapshot.parent_comm = ev.parent_comm;
            }
            if (ev.start_time_ticks != 0) {
              snapshot.start_time_ticks = ev.start_time_ticks;
            }

            Entry* existing = FindAny(key);
            if (existing) {
              // Always track fast-moving identity fields from event headers.
              existing->snapshot.pid = snapshot.pid;
              existing->snapshot.tgid = snapshot.tgid;
              existing->snapshot.ppid = snapshot.ppid;
              existing->snapshot.uid = snapshot.uid;
              existing->snapshot.gid = snapshot.gid;
              existing->snapshot.comm = snapshot.comm;
              existing->last_used = std::chrono::steady_clock::now();

              // Avoid clobbering rich cached context with sparse process events.
              if (!has_rich_fields) {
                return existing->snapshot;
              }
            }

            if (has_rich_fields) {
              Upsert(key, snapshot);
              return snapshot;
            }

            // Sparse process event without prior cache state: best-effort refresh from /proc.
            ProcessInfoSnapshot refreshed = snapshot;
            RefreshFromProc(key, &refreshed);
            Upsert(key, refreshed);
            return refreshed;
          }

          const uint32_t key = snapshot.tgid != 0 ? snapshot.tgid : snapshot.pid;
          if (key == 0) {
            return snapshot;
          }

          Entry* entry = FindFresh(key);
          if (!entry) {
            ProcessInfoSnapshot refreshed = snapshot;
            RefreshFromProc(key, &refreshed);
            Upsert(key, refreshed);
            return refreshed;
          }

          // Keep fast-moving identity fields from the current event header.
          entry->snapshot.pid = snapshot.pid;
          entry->snapshot.tgid = snapshot.tgid;
          entry->snapshot.ppid = snapshot.ppid;
          entry->snapshot.uid = snapshot.uid;
          entry->snapshot.gid = snapshot.gid;
          entry->snapshot.comm = snapshot.comm;
          entry->last_used = std::chrono::steady_clock::now();
          return entry->snapshot;
        },
        event);
  }

 private:
  struct Entry {
    ProcessInfoSnapshot snapshot;
    std::chrono::steady_clock::time_point last_refresh;
    std::chrono::steady_clock::time_point last_identity_check;
    std::chrono::steady_clock::time_point last_used;
  };

  static constexpr size_t kMaxEntries = 8192;
  static constexpr auto kRefreshTtl = std::chrono::seconds(2);
  static constexpr auto kIdentityCheckInterval = std::chrono::milliseconds(500);

  static ProcessInfoSnapshot BuildFromHeader(const event_header& h) {
    ProcessInfoSnapshot s;
    s.pid = h.pid;
    s.tgid = h.tgid;
    s.ppid = h.ppid;
    s.uid = h.uid;
    s.gid = h.gid;
    s.comm = h.comm;
    return s;
  }

  static std::string ReadProcSymlink(const std::string& path) {
    char buf[EVENT_LOGGER_PATH_LEN] = {};
    const ssize_t n = ::readlink(path.c_str(), buf, sizeof(buf) - 1);
    if (n <= 0) {
      return {};
    }
    buf[n] = '\0';
    return std::string(buf);
  }

  static std::string ReadTextFile(const std::string& path, bool binary = false) {
    std::ifstream in(path, binary ? std::ios::binary : std::ios::in);
    if (!in.is_open()) {
      return {};
    }

    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
  }

  static std::string NormalizeCmdline(std::string raw) {
    if (raw.empty()) {
      return raw;
    }

    for (char& c : raw) {
      if (c == '\0') {
        c = ' ';
      }
    }

    while (!raw.empty() && raw.back() == ' ') {
      raw.pop_back();
    }
    return raw;
  }

  static void RStrip(std::string* s) {
    if (!s) {
      return;
    }

    while (!s->empty() && (s->back() == '\n' || s->back() == '\r' || s->back() == ' ')) {
      s->pop_back();
    }
  }

  static uint64_t ParseStartTimeTicks(const std::string& stat_line) {
    if (stat_line.empty()) {
      return 0;
    }

    const size_t close_paren = stat_line.rfind(") ");
    if (close_paren == std::string::npos || close_paren + 2 >= stat_line.size()) {
      return 0;
    }

    const std::string rest = stat_line.substr(close_paren + 2);
    std::istringstream iss(rest);
    std::string tok;
    for (int idx = 0; iss >> tok; ++idx) {
      if (idx == 19) {
        try {
          return static_cast<uint64_t>(std::stoull(tok));
        } catch (...) {
          return 0;
        }
      }
    }

    return 0;
  }

  static void RefreshFromProc(uint32_t tgid, ProcessInfoSnapshot* snapshot) {
    if (!snapshot || tgid == 0) {
      return;
    }

    const std::string pid_s = std::to_string(tgid);

    if (snapshot->exec_path.empty()) {
      snapshot->exec_path = ReadProcSymlink("/proc/" + pid_s + "/exe");
    }

    if (snapshot->cwd.empty()) {
      snapshot->cwd = ReadProcSymlink("/proc/" + pid_s + "/cwd");
    }

    if (snapshot->cmdline.empty()) {
      snapshot->cmdline = NormalizeCmdline(ReadTextFile("/proc/" + pid_s + "/cmdline", true));
    }

    if (snapshot->parent_comm.empty() && snapshot->ppid != 0) {
      snapshot->parent_comm = ReadTextFile("/proc/" + std::to_string(snapshot->ppid) + "/comm");
      RStrip(&snapshot->parent_comm);
    }

    if (snapshot->start_time_ticks == 0) {
      snapshot->start_time_ticks = ParseStartTimeTicks(ReadTextFile("/proc/" + pid_s + "/stat"));
    }
  }

  Entry* FindAny(uint32_t key) {
    auto it = entries_.find(key);
    if (it == entries_.end()) {
      return nullptr;
    }
    return &it->second;
  }

  Entry* FindFresh(uint32_t key) {
    auto it = entries_.find(key);
    if (it == entries_.end()) {
      return nullptr;
    }

    const auto now = std::chrono::steady_clock::now();
    if ((now - it->second.last_refresh) > kRefreshTtl) {
      return nullptr;
    }

    // Guard against PID/TGID reuse: periodically re-check process start time.
    if (it->second.snapshot.start_time_ticks != 0 &&
        (now - it->second.last_identity_check) > kIdentityCheckInterval) {
      const std::string stat_line = ReadTextFile("/proc/" + std::to_string(key) + "/stat");
      const uint64_t current_start = ParseStartTimeTicks(stat_line);
      it->second.last_identity_check = now;
      if (current_start == 0 || current_start != it->second.snapshot.start_time_ticks) {
        return nullptr;
      }
    }

    it->second.last_used = now;
    return &it->second;
  }

  void Upsert(uint32_t key, const ProcessInfoSnapshot& snapshot) {
    if (key == 0) {
      return;
    }

    const auto now = std::chrono::steady_clock::now();
    auto it = entries_.find(key);
    if (it == entries_.end()) {
      entries_.emplace(key, Entry{snapshot, now, now, now});
    } else {
      it->second.snapshot = snapshot;
      it->second.last_refresh = now;
      it->second.last_identity_check = now;
      it->second.last_used = now;
    }

    if (entries_.size() > kMaxEntries) {
      EvictLeastRecentlyUsed();
    }
  }

  void EvictLeastRecentlyUsed() {
    auto victim = entries_.end();
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
      if (victim == entries_.end() || it->second.last_used < victim->second.last_used) {
        victim = it;
      }
    }

    if (victim != entries_.end()) {
      entries_.erase(victim);
    }
  }

  std::unordered_map<uint32_t, Entry> entries_;
};

/**
 *  Return process-wide process-info cache instance.
 *
 * Keeps enrichment cache centralized so all sink writes share the same
 * freshness and reuse rules.
 */
ProcessInfoCache& GetProcessInfoCache() {
  static ProcessInfoCache cache;
  return cache;
}

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
void WriteProcessInfo(std::ostream& out, const ProcessInfoSnapshot& p) {
  out << ",\"process_info\":{"
      << "\"pid\":" << p.pid << ","
      << "\"tgid\":" << p.tgid << ","
      << "\"ppid\":" << p.ppid << ","
      << "\"uid\":" << p.uid << ","
      << "\"gid\":" << p.gid << ","
      << "\"comm\":\"" << JsonEscape(p.comm) << "\","
      << "\"exec_path\":\"" << JsonEscape(p.exec_path) << "\","
      << "\"cmdline\":\"" << JsonEscape(p.cmdline) << "\","
      << "\"cwd\":\"" << JsonEscape(p.cwd) << "\","
      << "\"parent_comm\":\"" << JsonEscape(p.parent_comm) << "\","
      << "\"start_time_ticks\":" << p.start_time_ticks
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
void WriteEventBody(std::ostream& out, const EventVariant& event) {
  const ProcessInfoSnapshot process_info = GetProcessInfoCache().BuildForEvent(event);

  std::visit(
      [&](const auto& ev) {
        WriteHeader(out, ev.hdr);
        WriteProcessInfo(out, process_info);

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
  current_file_size_bytes_ += static_cast<uint64_t>(serialized.size());
  ++pending_records_since_flush_;
  MaybeFlush();
}


}  // namespace event_logger
