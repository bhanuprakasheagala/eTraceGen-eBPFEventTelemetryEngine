/*
 * File Notes:
 * - Implements the shared /proc-reading helpers declared in proc_util.h.
 */

#include "util/proc_util.h"

#include <fstream>
#include <sstream>
#include <unistd.h>

#include "event_schema.h"

namespace event_logger::proc_util {

std::string ReadProcSymlink(const std::string& path) {
  char buf[EVENT_LOGGER_PATH_LEN] = {};
  const ssize_t n = ::readlink(path.c_str(), buf, sizeof(buf) - 1);
  if (n <= 0) {
    return {};
  }
  buf[n] = '\0';
  return std::string(buf);
}

std::string ReadTextFile(const std::string& path, bool binary) {
  std::ifstream in(path, binary ? std::ios::binary : std::ios::in);
  if (!in.is_open()) {
    return {};
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

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

void RStrip(std::string* s) {
  if (!s) {
    return;
  }
  while (!s->empty() && (s->back() == '\n' || s->back() == '\r' || s->back() == ' ')) {
    s->pop_back();
  }
}

uint64_t ParseStartTimeTicks(const std::string& stat_line) {
  if (stat_line.empty()) {
    return 0;
  }
  // Skip past the (possibly space/paren-containing) comm field.
  const size_t close_paren = stat_line.rfind(") ");
  if (close_paren == std::string::npos || close_paren + 2 >= stat_line.size()) {
    return 0;
  }
  const std::string rest = stat_line.substr(close_paren + 2);
  std::istringstream iss(rest);
  std::string tok;
  for (int idx = 0; iss >> tok; ++idx) {
    if (idx == 19) {  // field 22 of stat (0-based from the field after comm).
      try {
        return static_cast<uint64_t>(std::stoull(tok));
      } catch (...) {
        return 0;
      }
    }
  }
  return 0;
}

}  // namespace event_logger::proc_util
