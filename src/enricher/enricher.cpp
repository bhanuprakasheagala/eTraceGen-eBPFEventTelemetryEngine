/*
 * File Notes:
 * - Process-focused enrichment implementation.
 * - Populates additional process context from /proc when available.
 */

#include "enricher/enricher.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

namespace event_logger {
namespace {

/**
 * @brief Copy std::string into fixed-size event buffer with NUL termination.
 */
void CopyToFixed(char* dst, size_t dst_size, const std::string& src) {
  if (!dst || dst_size == 0) {
    return;
  }

  const size_t n = src.size() < (dst_size - 1) ? src.size() : (dst_size - 1);
  if (n > 0) {
    std::memcpy(dst, src.data(), n);
  }
  dst[n] = '\0';
}

/**
 * @brief Return true when fixed-size C string buffer is empty.
 */
bool IsEmpty(const char* s) {
  return !s || s[0] == '\0';
}

/**
 * @brief Read symbolic link target into string. Returns empty on failure.
 */
std::string ReadProcSymlink(const std::string& path) {
  char buf[EVENT_LOGGER_PATH_LEN] = {};
  const ssize_t n = ::readlink(path.c_str(), buf, sizeof(buf) - 1);
  if (n <= 0) {
    return {};
  }
  buf[n] = '\0';
  return std::string(buf);
}

/**
 * @brief Read entire small file into string. Returns empty on failure.
 */
std::string ReadTextFile(const std::string& path, bool binary = false) {
  std::ifstream in(path, binary ? std::ios::binary : std::ios::in);
  if (!in.is_open()) {
    return {};
  }

  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

/**
 * @brief Convert /proc/<pid>/cmdline NUL-separated payload to space-separated form.
 */
std::string NormalizeCmdline(std::string raw) {
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

/**
 * @brief Strip trailing newlines/spaces from proc text values.
 */
void RStrip(std::string* s) {
  if (!s) {
    return;
  }

  while (!s->empty() && (s->back() == '\n' || s->back() == '\r' || s->back() == ' ')) {
    s->pop_back();
  }
}

/**
 * @brief Parse process start time (clock ticks) from /proc/<pid>/stat.
 */
uint64_t ParseStartTimeTicks(const std::string& stat_line) {
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
    if (idx == 19) {  // field 22 in /proc/<pid>/stat (0-based from field 3).
      try {
        return static_cast<uint64_t>(std::stoull(tok));
      } catch (...) {
        return 0;
      }
    }
  }

  return 0;
}

/**
 * @brief Enrich process events with /proc-derived context.
 */
void EnrichProcessEvent(process_event* ev) {
  if (!ev) {
    return;
  }

  const uint32_t pid = ev->hdr.tgid != 0 ? ev->hdr.tgid : ev->hdr.pid;
  if (pid == 0) {
    return;
  }

  const std::string pid_s = std::to_string(pid);

  if (IsEmpty(ev->exec_path)) {
    const std::string exe = ReadProcSymlink("/proc/" + pid_s + "/exe");
    if (!exe.empty()) {
      CopyToFixed(ev->exec_path, sizeof(ev->exec_path), exe);
    }
  }

  // Keep legacy field populated for downstream consumers that still read `filename`.
  if (IsEmpty(ev->filename) && !IsEmpty(ev->exec_path)) {
    CopyToFixed(ev->filename, sizeof(ev->filename), std::string(ev->exec_path));
  }

  if (IsEmpty(ev->cwd)) {
    const std::string cwd = ReadProcSymlink("/proc/" + pid_s + "/cwd");
    if (!cwd.empty()) {
      CopyToFixed(ev->cwd, sizeof(ev->cwd), cwd);
    }
  }

  if (IsEmpty(ev->cmdline)) {
    std::string cmdline = ReadTextFile("/proc/" + pid_s + "/cmdline", true);
    cmdline = NormalizeCmdline(std::move(cmdline));
    if (!cmdline.empty()) {
      CopyToFixed(ev->cmdline, sizeof(ev->cmdline), cmdline);
    }
  }

  if (IsEmpty(ev->parent_comm) && ev->hdr.ppid != 0) {
    std::string pcomm = ReadTextFile("/proc/" + std::to_string(ev->hdr.ppid) + "/comm");
    RStrip(&pcomm);
    if (!pcomm.empty()) {
      CopyToFixed(ev->parent_comm, sizeof(ev->parent_comm), pcomm);
    }
  }

  if (ev->start_time_ticks == 0) {
    const std::string stat_line = ReadTextFile("/proc/" + pid_s + "/stat");
    ev->start_time_ticks = ParseStartTimeTicks(stat_line);
  }
}

}  // namespace

/**
 * @brief Enrich one decoded event with additional context.
 *
 * @param event Decoded event payload.
 */
void Enricher::Enrich(EventVariant& event) const {
  std::visit(
      [&](auto& ev) {
        using T = std::decay_t<decltype(ev)>;
        if constexpr (std::is_same_v<T, process_event>) {
          EnrichProcessEvent(&ev);
        }
      },
      event);
}

}  // namespace event_logger
