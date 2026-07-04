/*
 * File Notes:
 * - Real eBPF ingress backend using libbpf.
 * - Handles BPF object load/attach/ring-buffer polling and forwards raw event payloads upstream.
 *
 * Deep-dive intent:
 * - Keep startup failure reasons explicit so runtime compatibility problems are diagnosable.
 * - Prefer partial functionality (some probes attached) over total failure when safe.
 */

#include "collector/collector.h"
#include "event_schema.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
#include <sys/utsname.h>
#include <unistd.h>

namespace event_logger {
namespace {

enum bpf_stat_key {
  BPF_STAT_RINGBUF_RESERVE_FAIL = 0,
  BPF_STAT_FILE_STATE_SAVE_FAIL = 1,
  BPF_STAT_FILE_STATE_COLLISION = 2,
  BPF_STAT_FILE_STATE_MISS = 3,
  BPF_STAT_SYSCALL_STATE_SAVE_FAIL = 4,
  BPF_STAT_SYSCALL_STATE_COLLISION = 5,
  BPF_STAT_SYSCALL_STATE_MISS = 6,
  BPF_STAT_NETWORK_STATE_SAVE_FAIL = 7,
  BPF_STAT_NETWORK_STATE_COLLISION = 8,
  BPF_STAT_NETWORK_STATE_MISS = 9,
};

struct FileProbeConfig {
  bool openat = true;
  bool unlinkat = true;
  bool renameat2 = true;
};

struct DomainConfig {
  bool process = true;
  bool file = true;
  bool syscall = true;
  bool network_socket = false;
};

struct NetworkConfig {
  std::vector<uint32_t> port_allowlist;
};

struct RuntimeConfig {
  DomainConfig domains;
  FileProbeConfig file_probes;
  std::vector<uint32_t> pid_allowlist;
  std::vector<uint32_t> uid_allowlist;
  std::vector<int32_t> syscall_allowlist;
  NetworkConfig network;
};

/**
 *  Best-effort architecture string for startup diagnostics.
 *
 * Syscall numbers are architecture-specific, so logging machine architecture
 * helps explain why a numeric syscall allowlist may need adjustment per host.
 */
std::string DetectMachineArchitecture() {
  struct utsname uts = {};
  if (uname(&uts) != 0) {
    return "unknown";
  }
  return uts.machine;
}

/**
 *  Emit portability note when syscall allowlist is numeric and active.
 */
void LogSyscallAllowlistPortability(const RuntimeConfig& cfg) {
  if (cfg.syscall_allowlist.empty()) {
    return;
  }

  const std::string arch = DetectMachineArchitecture();
  std::cerr << "[collector] syscall_allowlist is numeric and arch-specific (arch=" << arch
            << "); verify values per architecture" << "\n";
}

/**
 * @brief Forward libbpf logs to stderr while suppressing debug-level noise.
 */
int LibbpfPrint(enum libbpf_print_level level, const char* fmt, va_list args) {
  if (level == LIBBPF_DEBUG) {
    return 0;
  }

  return std::vfprintf(stderr, fmt, args);
}

/**
 * @brief Return compile-time default BPF object path.
 */
const char* DefaultBpfObjectPath() {
#ifdef EVENT_LOGGER_DEFAULT_BPF_OBJECT
  return EVENT_LOGGER_DEFAULT_BPF_OBJECT;
#else
  return "bpf/event_logger.bpf.o";
#endif
}

/**
 * @brief Return config file path for runtime probe toggles.
 */
std::string DefaultConfigPath() {
  const char* env_path = std::getenv("ETRACEGEN_CONFIG");
  return env_path ? env_path : "config/default.yaml";
}

/**
 *  Trim leading/trailing whitespace for lightweight config parsing.
 */
std::string Trim(std::string s) {
  const auto not_space = [](unsigned char c) { return !std::isspace(c); };
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
  s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
  return s;
}

/**
 *  Parse strict `true`/`false` string into boolean output.
 */
bool ParseBool(std::string value, bool* out) {
  if (!out) {
    return false;
  }

  value = Trim(value);
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

  if (value == "true") {
    *out = true;
    return true;
  }
  if (value == "false") {
    *out = false;
    return true;
  }
  return false;
}

/**
 *  Parse inline integer list into int32 allowlist.
 */
void ParseInt32AllowlistInline(const std::string& value, std::vector<int32_t>* out) {
  if (!out) {
    return;
  }

  const auto l = value.find('[');
  const auto r = value.find(']');
  if (l == std::string::npos || r == std::string::npos || r <= l) {
    return;
  }

  const std::string body = value.substr(l + 1, r - l - 1);
  std::stringstream ss(body);
  std::string tok;
  while (std::getline(ss, tok, ',')) {
    tok = Trim(tok);
    if (tok.empty()) {
      continue;
    }

    try {
      const long parsed = std::stol(tok);
      out->push_back(static_cast<int32_t>(parsed));
    } catch (...) {
      // Ignore malformed entries to keep startup robust.
    }
  }
}

/**
 *  Parse inline integer list into uint32 allowlist.
 */
void ParseUint32AllowlistInline(const std::string& value, std::vector<uint32_t>* out) {
  if (!out) {
    return;
  }

  const auto l = value.find('[');
  const auto r = value.find(']');
  if (l == std::string::npos || r == std::string::npos || r <= l) {
    return;
  }

  const std::string body = value.substr(l + 1, r - l - 1);
  std::stringstream ss(body);
  std::string tok;
  while (std::getline(ss, tok, ',')) {
    tok = Trim(tok);
    if (tok.empty()) {
      continue;
    }

    try {
      const unsigned long parsed = std::stoul(tok);
      if (parsed <= std::numeric_limits<uint32_t>::max()) {
        out->push_back(static_cast<uint32_t>(parsed));
      }
    } catch (...) {
      // Ignore malformed entries to keep startup robust.
    }
  }
}

/**
 * @brief Load runtime config needed by BPF map initialization.
 *
 * Expected keys:
 * - `file_probes.openat|unlinkat|renameat2`
 * - `domains.process|file|syscall|network_socket`
 * - `filters.pid_allowlist|uid_allowlist|syscall_allowlist`
 * - `network_filters.port_allowlist`
 */
bool LoadRuntimeConfig(const std::string& path, RuntimeConfig* cfg) {
  if (!cfg) {
    return false;
  }

  std::ifstream in(path);
  if (!in.is_open()) {
    return false;
  }

  bool in_file_probes = false;
  bool in_domains = false;
  bool in_network_filters = false;

  std::string line;
  while (std::getline(in, line)) {
    const auto hash_pos = line.find('#');
    if (hash_pos != std::string::npos) {
      line = line.substr(0, hash_pos);
    }

    const std::string trimmed = Trim(line);
    if (trimmed.empty()) {
      continue;
    }

    if (trimmed == "file_probes:") {
      in_file_probes = true;
      in_domains = false;
      in_network_filters = false;
      continue;
    }

    if (trimmed == "domains:") {
      in_file_probes = false;
      in_domains = true;
      in_network_filters = false;
      continue;
    }

    if (trimmed == "network_filters:") {
      in_file_probes = false;
      in_domains = false;
      in_network_filters = true;
      continue;
    }

    if (trimmed.back() == ':' && trimmed != "file_probes:" && trimmed != "domains:" &&
        trimmed != "network_filters:") {
      in_file_probes = false;
      in_domains = false;
      in_network_filters = false;
      continue;
    }

    if (trimmed.rfind("pid_allowlist:", 0) == 0) {
      ParseUint32AllowlistInline(trimmed, &cfg->pid_allowlist);
      continue;
    }

    if (trimmed.rfind("uid_allowlist:", 0) == 0) {
      ParseUint32AllowlistInline(trimmed, &cfg->uid_allowlist);
      continue;
    }

    if (trimmed.rfind("syscall_allowlist:", 0) == 0) {
      ParseInt32AllowlistInline(trimmed, &cfg->syscall_allowlist);
      continue;
    }

    if (in_network_filters && trimmed.rfind("port_allowlist:", 0) == 0) {
      ParseUint32AllowlistInline(trimmed, &cfg->network.port_allowlist);
      continue;
    }

    const auto colon = trimmed.find(':');
    if (colon == std::string::npos) {
      continue;
    }

    const std::string key = Trim(trimmed.substr(0, colon));
    const std::string value = Trim(trimmed.substr(colon + 1));

    if (in_file_probes) {
      if (key == "openat") {
        ParseBool(value, &cfg->file_probes.openat);
      } else if (key == "unlinkat") {
        ParseBool(value, &cfg->file_probes.unlinkat);
      } else if (key == "renameat2") {
        ParseBool(value, &cfg->file_probes.renameat2);
      }
      continue;
    }

    if (in_domains) {
      if (key == "process") {
        ParseBool(value, &cfg->domains.process);
      } else if (key == "file") {
        ParseBool(value, &cfg->domains.file);
      } else if (key == "syscall") {
        ParseBool(value, &cfg->domains.syscall);
      } else if (key == "network_socket") {
        ParseBool(value, &cfg->domains.network_socket);
      }
      continue;
    }
  }

  return true;
}

/**
 *  Append a startup degrade reason while preserving prior context.
 */
void AppendDegradeReason(CollectorStartupReport* report, const std::string& message) {
  if (!report || message.empty()) {
    return;
  }

  if (!report->degrade_reason.empty()) {
    report->degrade_reason += "; ";
  }
  report->degrade_reason += message;
  report->degraded = true;
}

/**
 * @brief Push runtime file probe toggles into BPF map.
 */
bool ApplyFileProbeConfig(int map_fd, const FileProbeConfig& cfg) {
  if (map_fd < 0) {
    return false;
  }

  bool all_ok = true;
  const auto set_toggle = [&](uint32_t key, bool enabled) {
    uint8_t value = enabled ? 1U : 0U;
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
      std::cerr << "[collector] failed to set file probe toggle key=" << key << "\n";
      all_ok = false;
    }
  };

  set_toggle(FILE_OPENAT, cfg.openat);
  set_toggle(FILE_UNLINKAT, cfg.unlinkat);
  set_toggle(FILE_RENAMEAT2, cfg.renameat2);

  std::cerr << "[collector] file_probes openat=" << (cfg.openat ? "on" : "off")
            << " unlinkat=" << (cfg.unlinkat ? "on" : "off")
            << " renameat2=" << (cfg.renameat2 ? "on" : "off") << "\n";

  return all_ok;
}

/**
 * @brief Push runtime process domain toggles into BPF map.
 */
bool ApplyProcessProbeConfig(int map_fd, bool enabled) {
  if (map_fd < 0) {
    return false;
  }

  bool all_ok = true;
  const uint8_t value = enabled ? 1U : 0U;
  const uint32_t keys[] = {
      PROCESS_EXEC, PROCESS_FORK, PROCESS_EXIT, PROCESS_CLONE, PROCESS_CLONE3, PROCESS_VFORK,
  };
  for (int i = 0; i < 6; ++i) {
    uint32_t key = keys[i];
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
      std::cerr << "[collector] failed to set process probe toggle key=" << key << "\n";
      all_ok = false;
    }
  }

  std::cerr << "[collector] process_probes all=" << (enabled ? "on" : "off") << "\n";
  return all_ok;
}

/**
 * @brief Push runtime network domain probe toggles into BPF map.
 */
bool ApplyNetworkProbeConfig(int map_fd, bool enabled) {
  if (map_fd < 0) {
    return false;
  }

  bool all_ok = true;
  const uint8_t value = enabled ? 1U : 0U;

  const uint32_t keys[] = {
      NETWORK_SOCKET,     NETWORK_SOCKETPAIR, NETWORK_CONNECT,    NETWORK_BIND,
      NETWORK_LISTEN,     NETWORK_ACCEPT,     NETWORK_ACCEPT4,    NETWORK_GETSOCKNAME,
      NETWORK_GETPEERNAME, NETWORK_SETSOCKOPT, NETWORK_GETSOCKOPT, NETWORK_CLOSE,
      NETWORK_SENDTO,     NETWORK_RECVFROM,   NETWORK_SHUTDOWN,
      NETWORK_SENDMSG,    NETWORK_RECVMSG,    NETWORK_READ,       NETWORK_WRITE,
      NETWORK_READV,      NETWORK_WRITEV,     NETWORK_SENDMMSG,   NETWORK_RECVMMSG,
  };
  const size_t key_count = sizeof(keys) / sizeof(keys[0]);
  for (size_t i = 0; i < key_count; ++i) {
    uint32_t key = keys[i];
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
      std::cerr << "[collector] failed to set network probe toggle key=" << key << "\n";
      all_ok = false;
    }
  }

  std::cerr << "[collector] network_probes all=" << (enabled ? "on" : "off")
            << "\n";
  return all_ok;
}

/**
 * @brief Push uint32 allowlist entries into BPF hash map.
 */
uint32_t ApplyU32AllowlistConfig(int map_fd, const std::vector<uint32_t>& allowlist,
                                 const char* label) {
  if (map_fd < 0) {
    return 0;
  }

  uint32_t applied = 0;
  for (uint32_t key : allowlist) {
    uint8_t value = 1U;
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
      std::cerr << "[collector] failed to set " << label << " entry=" << key << "\n";
      continue;
    }
    ++applied;
  }

  std::cerr << "[collector] " << label << "_count=" << applied << "\n";
  return applied;
}

/**
 * @brief Push selected syscall allowlist into BPF map.
 */
uint32_t ApplySyscallAllowlistConfig(int map_fd, const std::vector<int32_t>& allowlist) {
  if (map_fd < 0) {
    return 0;
  }

  uint32_t applied = 0;
  for (int32_t nr : allowlist) {
    uint32_t key = static_cast<uint32_t>(nr);
    uint8_t value = 1U;
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
      std::cerr << "[collector] failed to set syscall allowlist entry nr=" << nr << "\n";
      continue;
    }
    ++applied;
  }

  std::cerr << "[collector] syscall_allowlist_count=" << applied << "\n";
  return applied;
}

/**
 * @brief Set allowlist-enabled flag in single-entry array map.
 */
bool SetAllowlistEnabled(int map_fd, bool enabled, const char* label) {
  if (map_fd < 0) {
    return false;
  }

  const uint32_t key = 0;
  const uint8_t value = enabled ? 1U : 0U;
  if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
    std::cerr << "[collector] failed to set " << label << " enabled=" << (enabled ? 1 : 0)
              << "\n";
    return false;
  }

  return true;
}

/**
 * @brief Read and aggregate one per-CPU counter from a per-CPU BPF map.
 */
bool ReadPerCpuCounter(int map_fd, uint32_t key, uint64_t* out) {
  if (!out) {
    return false;
  }

  const int cpu_count = libbpf_num_possible_cpus();
  if (cpu_count <= 0) {
    return false;
  }

  std::vector<uint64_t> values(static_cast<size_t>(cpu_count), 0);
  if (bpf_map_lookup_elem(map_fd, &key, values.data()) != 0) {
    return false;
  }

  uint64_t total = 0;
  for (uint64_t value : values) {
    total += value;
  }
  *out = total;
  return true;
}

}  // namespace

class LibbpfCollector final : public Collector {
 public:
  /**
   * @brief Initialize libbpf object, attach programs, and create ring buffer reader.
   */
  bool Start(RawEventCallback cb) override {
    cb_ = std::move(cb);
    startup_report_ = {};
    startup_report_.backend_name = "libbpf";
    startup_report_available_ = true;

    if (!cb_) {
      std::cerr << "[collector] callback is empty\n";
      AppendDegradeReason(&startup_report_, "missing callback");
      return false;
    }

    libbpf_set_print(LibbpfPrint);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    const char* env_path = std::getenv("ETRACEGEN_BPF_OBJECT");
    const std::string bpf_obj_path = env_path ? env_path : DefaultBpfObjectPath();
    startup_report_.bpf_object_path = bpf_obj_path;

    obj_ = bpf_object__open_file(bpf_obj_path.c_str(), nullptr);
    if (libbpf_get_error(obj_) != 0) {
      std::cerr << "[collector] failed to open BPF object: " << bpf_obj_path << "\n";
      obj_ = nullptr;
      AppendDegradeReason(&startup_report_, "failed to open BPF object");
      return false;
    }

    const int load_ret = bpf_object__load(obj_);
    if (load_ret != 0) {
      std::cerr << "[collector] failed to load BPF object: " << std::strerror(-load_ret) << "\n";
      AppendDegradeReason(&startup_report_, "failed to load BPF object");
      Stop();
      return false;
    }

    RuntimeConfig runtime_cfg;
    const std::string cfg_path = DefaultConfigPath();
    startup_report_.config_path = cfg_path;
    startup_report_.runtime_config_loaded = LoadRuntimeConfig(cfg_path, &runtime_cfg);
    if (!startup_report_.runtime_config_loaded) {
      std::cerr << "[collector] config not found, using defaults: " << cfg_path << "\n";
      AppendDegradeReason(&startup_report_, "runtime config not found; defaults used");
    }

    const int events_fd = bpf_object__find_map_fd_by_name(obj_, "events");
    const int stats_fd = bpf_object__find_map_fd_by_name(obj_, "bpf_stats");
    const int file_toggle_fd = bpf_object__find_map_fd_by_name(obj_, "file_probe_enabled");
    const int process_toggle_fd = bpf_object__find_map_fd_by_name(obj_, "process_probe_enabled");
    const int syscall_probe_enabled_fd =
        bpf_object__find_map_fd_by_name(obj_, "syscall_probe_enabled");
    const int syscall_allowlist_fd = bpf_object__find_map_fd_by_name(obj_, "syscall_allowlist");
    const int pid_allowlist_fd = bpf_object__find_map_fd_by_name(obj_, "pid_allowlist");
    const int uid_allowlist_fd = bpf_object__find_map_fd_by_name(obj_, "uid_allowlist");
    const int pid_filter_enabled_fd = bpf_object__find_map_fd_by_name(obj_, "pid_filter_enabled");
    const int uid_filter_enabled_fd = bpf_object__find_map_fd_by_name(obj_, "uid_filter_enabled");
    const int network_probe_enabled_fd =
        bpf_object__find_map_fd_by_name(obj_, "network_probe_enabled");
    const int network_port_allowlist_fd =
        bpf_object__find_map_fd_by_name(obj_, "network_port_allowlist");
    const int network_port_filter_enabled_fd =
        bpf_object__find_map_fd_by_name(obj_, "network_port_filter_enabled");
    const int suppress_tgid_fd = bpf_object__find_map_fd_by_name(obj_, "suppress_tgid");

    startup_report_.map_events_found = events_fd >= 0;
    startup_report_.map_bpf_stats_found = stats_fd >= 0;
    startup_report_.map_file_probe_enabled_found = file_toggle_fd >= 0;
    startup_report_.map_syscall_allowlist_found = syscall_allowlist_fd >= 0;
    startup_report_.map_pid_allowlist_found = pid_allowlist_fd >= 0;
    startup_report_.map_uid_allowlist_found = uid_allowlist_fd >= 0;
    startup_report_.map_network_probe_enabled_found = network_probe_enabled_fd >= 0;
    startup_report_.map_network_port_allowlist_found = network_port_allowlist_fd >= 0;
    startup_report_.map_network_port_filter_enabled_found = network_port_filter_enabled_fd >= 0;
    startup_report_.map_suppress_tgid_found = suppress_tgid_fd >= 0;

    if (!startup_report_.map_bpf_stats_found) {
      AppendDegradeReason(&startup_report_, "bpf_stats map missing; kernel diagnostics unavailable");
    }
    if (!startup_report_.map_file_probe_enabled_found) {
      AppendDegradeReason(&startup_report_,
                          "file_probe_enabled map missing; runtime file toggles disabled");
    }
    if (process_toggle_fd < 0) {
      AppendDegradeReason(&startup_report_,
                          "process_probe_enabled map missing; runtime process toggles disabled");
    }
    if (syscall_probe_enabled_fd < 0) {
      AppendDegradeReason(&startup_report_,
                          "syscall_probe_enabled map missing; runtime syscall domain toggle disabled");
    }
    if (!startup_report_.map_syscall_allowlist_found) {
      AppendDegradeReason(&startup_report_,
                          "syscall_allowlist map missing; runtime syscall gating disabled");
    }
    if (!startup_report_.map_pid_allowlist_found) {
      AppendDegradeReason(&startup_report_, "pid_allowlist map missing; runtime pid filtering disabled");
    }
    if (!startup_report_.map_uid_allowlist_found) {
      AppendDegradeReason(&startup_report_, "uid_allowlist map missing; runtime uid filtering disabled");
    }
    if (!startup_report_.map_network_probe_enabled_found) {
      AppendDegradeReason(&startup_report_,
                          "network_probe_enabled map missing; runtime network probe toggles disabled");
    }
    if (!startup_report_.map_network_port_allowlist_found) {
      AppendDegradeReason(&startup_report_,
                          "network_port_allowlist map missing; runtime network port filtering disabled");
    }
    if (!startup_report_.map_network_port_filter_enabled_found) {
      AppendDegradeReason(&startup_report_,
                          "network_port_filter_enabled map missing; network port filter activation unavailable");
    }
    if (pid_filter_enabled_fd < 0) {
      AppendDegradeReason(&startup_report_,
                          "pid_filter_enabled map missing; pid filtering activation unavailable");
    }
    if (uid_filter_enabled_fd < 0) {
      AppendDegradeReason(&startup_report_,
                          "uid_filter_enabled map missing; uid filtering activation unavailable");
    }

    if (suppress_tgid_fd < 0) {
      AppendDegradeReason(&startup_report_,
                          "suppress_tgid map missing; self-event suppression in-kernel disabled");
    }

    const bool process_domain_enabled = runtime_cfg.domains.process;
    const bool file_domain_enabled = runtime_cfg.domains.file;
    const bool syscall_domain_enabled = runtime_cfg.domains.syscall;
    const bool network_domain_enabled = runtime_cfg.domains.network_socket;

    if (!ApplyProcessProbeConfig(process_toggle_fd, process_domain_enabled)) {
      AppendDegradeReason(&startup_report_, "process probe toggle apply failed");
    }

    if (!SetAllowlistEnabled(syscall_probe_enabled_fd, syscall_domain_enabled, "syscall_probe")) {
      AppendDegradeReason(&startup_report_, "syscall probe toggle apply failed");
    }

    FileProbeConfig effective_file_probes = runtime_cfg.file_probes;
    if (!file_domain_enabled) {
      effective_file_probes.openat = false;
      effective_file_probes.unlinkat = false;
      effective_file_probes.renameat2 = false;
    }
    startup_report_.file_probe_toggles_applied =
        ApplyFileProbeConfig(file_toggle_fd, effective_file_probes);
    if (!startup_report_.file_probe_toggles_applied) {
      AppendDegradeReason(&startup_report_, "file probe toggle apply failed");
    }

    startup_report_.network_probe_toggles_applied =
        ApplyNetworkProbeConfig(network_probe_enabled_fd, network_domain_enabled);
    if (!startup_report_.network_probe_toggles_applied) {
      AppendDegradeReason(&startup_report_, "network probe toggle apply failed");
    }

    startup_report_.pid_allowlist_applied_count =
        ApplyU32AllowlistConfig(pid_allowlist_fd, runtime_cfg.pid_allowlist, "pid_allowlist");
    startup_report_.uid_allowlist_applied_count =
        ApplyU32AllowlistConfig(uid_allowlist_fd, runtime_cfg.uid_allowlist, "uid_allowlist");

    std::vector<int32_t> effective_syscall_allowlist = runtime_cfg.syscall_allowlist;
    if (!syscall_domain_enabled) {
      effective_syscall_allowlist.clear();
    }
    startup_report_.syscall_allowlist_applied_count =
        ApplySyscallAllowlistConfig(syscall_allowlist_fd, effective_syscall_allowlist);
    startup_report_.network_port_allowlist_applied_count = ApplyU32AllowlistConfig(
        network_port_allowlist_fd, runtime_cfg.network.port_allowlist, "network_port_allowlist");

    const bool pid_filter_should_enable = !runtime_cfg.pid_allowlist.empty();
    const bool uid_filter_should_enable = !runtime_cfg.uid_allowlist.empty();
    const bool network_port_filter_should_enable = !runtime_cfg.network.port_allowlist.empty();

    if (!SetAllowlistEnabled(pid_filter_enabled_fd, pid_filter_should_enable, "pid_filter")) {
      AppendDegradeReason(&startup_report_, "pid filter enable flag apply failed");
    }
    if (!SetAllowlistEnabled(uid_filter_enabled_fd, uid_filter_should_enable, "uid_filter")) {
      AppendDegradeReason(&startup_report_, "uid filter enable flag apply failed");
    }
    if (!SetAllowlistEnabled(network_port_filter_enabled_fd, network_port_filter_should_enable,
                             "network_port_filter")) {
      AppendDegradeReason(&startup_report_, "network port filter enable flag apply failed");
    }


    if (suppress_tgid_fd >= 0) {
      const uint32_t key = 0;
      const uint32_t value = static_cast<uint32_t>(::getpid());
      if (bpf_map_update_elem(suppress_tgid_fd, &key, &value, BPF_ANY) != 0) {
        std::cerr << "[collector] failed to set suppress_tgid=" << value << "\n";
        AppendDegradeReason(&startup_report_, "suppress_tgid apply failed");
      }
    }

    if (pid_filter_should_enable && startup_report_.pid_allowlist_applied_count == 0) {
      AppendDegradeReason(&startup_report_, "pid allowlist entries were not applied");
    }
    if (uid_filter_should_enable && startup_report_.uid_allowlist_applied_count == 0) {
      AppendDegradeReason(&startup_report_, "uid allowlist entries were not applied");
    }
    if (!effective_syscall_allowlist.empty() &&
        startup_report_.syscall_allowlist_applied_count == 0) {
      AppendDegradeReason(&startup_report_, "syscall allowlist entries were not applied");
    }
    if (network_port_filter_should_enable &&
        startup_report_.network_port_allowlist_applied_count == 0) {
      AppendDegradeReason(&startup_report_, "network port allowlist entries were not applied");
    }

    int attached_programs = 0;
    int total_programs = 0;
    std::vector<std::string> failed_programs;

    bpf_program* prog = nullptr;
    bpf_object__for_each_program(prog, obj_) {
      ++total_programs;

      bpf_link* link = bpf_program__attach(prog);
      if (libbpf_get_error(link) != 0) {
        link = nullptr;
        const char* name = bpf_program__name(prog);
        std::cerr << "[collector] attach failed for program '" << (name ? name : "<unknown>")
                  << "' (continuing)\n";
        failed_programs.emplace_back(name ? name : "<unknown>");
        continue;
      }

      links_.push_back(link);
      ++attached_programs;
    }

    startup_report_.programs_total = static_cast<uint32_t>(total_programs);
    startup_report_.programs_attached = static_cast<uint32_t>(attached_programs);
    startup_report_.programs_attach_failed = static_cast<uint32_t>(failed_programs.size());

    if (!failed_programs.empty()) {
      std::string joined;
      for (size_t i = 0; i < failed_programs.size(); ++i) {
        if (i != 0) {
          joined += ",";
        }
        joined += failed_programs[i];
      }
      AppendDegradeReason(&startup_report_, "attach failures=" + joined);
    }

    if (attached_programs == 0) {
      std::cerr << "[collector] no BPF programs attached\n";
      AppendDegradeReason(&startup_report_, "no BPF programs attached");
      Stop();
      return false;
    }

    if (!startup_report_.map_events_found) {
      std::cerr << "[collector] 'events' map not found\n";
      AppendDegradeReason(&startup_report_, "events map missing");
      Stop();
      return false;
    }

    rb_ = ring_buffer__new(events_fd, &LibbpfCollector::OnRingBufferEvent, this, nullptr);
    if (!rb_) {
      std::cerr << "[collector] failed to create ring buffer reader\n";
      AppendDegradeReason(&startup_report_, "failed to create ring buffer reader");
      Stop();
      return false;
    }

    started_ = true;
    std::cerr << "[collector] libbpf backend active, attached programs=" << attached_programs << "\n";
    return true;
  }

  void PollOnce(int timeout_ms) override {
    if (!started_ || !rb_) {
      return;
    }

    const int poll_ret = ring_buffer__poll(rb_, timeout_ms);
    if (poll_ret < 0 && poll_ret != -EINTR) {
      std::cerr << "[collector] ring buffer poll failed: " << std::strerror(-poll_ret) << "\n";
    }
  }

  /**
   * @brief Read aggregated kernel-side BPF stats from `bpf_stats` map.
   */
  bool ReadKernelBpfStats(KernelBpfStats* out) override {
    if (!out || !obj_) {
      return false;
    }

    const int stats_fd = bpf_object__find_map_fd_by_name(obj_, "bpf_stats");
    if (stats_fd < 0) {
      return false;
    }

    if (!ReadPerCpuCounter(stats_fd, BPF_STAT_RINGBUF_RESERVE_FAIL, &out->ringbuf_reserve_fail)) {
      return false;
    }
    if (!ReadPerCpuCounter(stats_fd, BPF_STAT_FILE_STATE_SAVE_FAIL, &out->file_state_save_fail)) {
      return false;
    }
    if (!ReadPerCpuCounter(stats_fd, BPF_STAT_FILE_STATE_COLLISION, &out->file_state_collision)) {
      return false;
    }
    if (!ReadPerCpuCounter(stats_fd, BPF_STAT_FILE_STATE_MISS, &out->file_state_miss)) {
      return false;
    }
    if (!ReadPerCpuCounter(stats_fd, BPF_STAT_SYSCALL_STATE_SAVE_FAIL,
                           &out->syscall_state_save_fail)) {
      return false;
    }
    if (!ReadPerCpuCounter(stats_fd, BPF_STAT_SYSCALL_STATE_COLLISION,
                           &out->syscall_state_collision)) {
      return false;
    }
    if (!ReadPerCpuCounter(stats_fd, BPF_STAT_SYSCALL_STATE_MISS, &out->syscall_state_miss)) {
      return false;
    }
    if (!ReadPerCpuCounter(stats_fd, BPF_STAT_NETWORK_STATE_SAVE_FAIL,
                           &out->network_state_save_fail)) {
      return false;
    }
    if (!ReadPerCpuCounter(stats_fd, BPF_STAT_NETWORK_STATE_COLLISION,
                           &out->network_state_collision)) {
      return false;
    }
    if (!ReadPerCpuCounter(stats_fd, BPF_STAT_NETWORK_STATE_MISS, &out->network_state_miss)) {
      return false;
    }

    return true;
  }

  /**
   * @brief Return startup capability report captured during Start().
   */
  bool ReadStartupReport(CollectorStartupReport* out) override {
    if (!out || !startup_report_available_) {
      return false;
    }
    *out = startup_report_;
    return true;
  }

  void Stop() override {
    started_ = false;

    if (rb_) {
      ring_buffer__free(rb_);
      rb_ = nullptr;
    }

    for (bpf_link* link : links_) {
      bpf_link__destroy(link);
    }
    links_.clear();

    if (obj_) {
      bpf_object__close(obj_);
      obj_ = nullptr;
    }

    cb_ = nullptr;
  }

 private:
  /**
   * @brief C callback bridge from libbpf ring buffer API to C++ callback contract.
   */
  static int OnRingBufferEvent(void* ctx, void* data, size_t size) {
    auto* self = static_cast<LibbpfCollector*>(ctx);
    if (!self || !self->cb_) {
      return 0;
    }

    const auto* begin = static_cast<const unsigned char*>(data);
    self->cb_(std::span<const unsigned char>(begin, size));
    return 0;
  }

  RawEventCallback cb_;
  bpf_object* obj_ = nullptr;
  ring_buffer* rb_ = nullptr;
  std::vector<bpf_link*> links_;
  bool started_ = false;

  CollectorStartupReport startup_report_;
  bool startup_report_available_ = false;
};

Collector* CreateCollector() {
  static LibbpfCollector collector;
  return &collector;
}

}  // namespace event_logger
