#ifndef EVENT_LOGGER_EVENT_SCHEMA_H
#define EVENT_LOGGER_EVENT_SCHEMA_H

/*
 * File Notes:
 * - Defines the binary event contract shared by kernel eBPF producer and C++ consumers.
 * - Field order and width are ABI-sensitive: changing them can break decode compatibility.
 */

#ifndef __BPF__
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Fixed process command-name length in event payloads. */
#define EVENT_LOGGER_COMM_LEN 16
/** @brief Fixed path buffer length used by process/file payload fields. */
#define EVENT_LOGGER_PATH_LEN 256
/** @brief Fixed pathname buffer length for UNIX domain socket endpoints. */
#define EVENT_LOGGER_UNIX_PATH_LEN 108

/**
 * @brief Top-level event family identifiers.
 */
enum event_type {
  EVENT_TYPE_PROCESS = 1,
  EVENT_TYPE_FILE = 2,
  EVENT_TYPE_SYSCALL = 3,
  EVENT_TYPE_NETWORK = 4,
};

/**
 * @brief Process lifecycle event subtypes.
 */
enum process_event_kind {
  PROCESS_EXEC = 1,
  PROCESS_FORK = 2,
  PROCESS_EXIT = 3,
  PROCESS_CLONE = 4,
  PROCESS_CLONE3 = 5,
  PROCESS_VFORK = 6,
};

/**
 * @brief File operation event subtypes.
 */
enum file_event_kind {
  FILE_OPENAT = 1,
  FILE_UNLINKAT = 2,
  FILE_RENAMEAT2 = 3,
};

/**
 * @brief Socket-centric network event subtypes.
 *
 * Control-plane kinds come first so kernel and userspace can evolve the socket
 * layer incrementally without renumbering earlier records.
 */
enum network_event_kind {
  NETWORK_SOCKET = 1,
  NETWORK_CONNECT = 2,
  NETWORK_ACCEPT = 3,
  NETWORK_BIND = 4,
  NETWORK_LISTEN = 5,
  NETWORK_CLOSE = 6,
  NETWORK_SENDTO = 7,
  NETWORK_RECVFROM = 8,
  NETWORK_SHUTDOWN = 9,
  NETWORK_SOCKETPAIR = 10,
  NETWORK_ACCEPT4 = 11,
  NETWORK_GETSOCKNAME = 12,
  NETWORK_GETPEERNAME = 13,
  NETWORK_SETSOCKOPT = 14,
  NETWORK_GETSOCKOPT = 15,
  NETWORK_SENDMSG = 16,
  NETWORK_RECVMSG = 17,
  NETWORK_READ = 18,
  NETWORK_WRITE = 19,
  NETWORK_READV = 20,
  NETWORK_WRITEV = 21,
  NETWORK_SENDMMSG = 22,
  NETWORK_RECVMMSG = 23,
};

enum network_event_direction {
  NETWORK_DIRECTION_UNKNOWN = 0,
  NETWORK_DIRECTION_INBOUND = 1,
  NETWORK_DIRECTION_OUTBOUND = 2,
};

enum network_transport {
  NETWORK_TRANSPORT_UNKNOWN = 0,
  NETWORK_TRANSPORT_TCP = 1,
  NETWORK_TRANSPORT_UDP = 2,
  NETWORK_TRANSPORT_UNIX = 3,
  NETWORK_TRANSPORT_RAW = 4,
};

/**
 * @brief Common event envelope present in every event payload.
 *
 * Contains identity/time metadata used by all downstream processing stages.
 */
struct event_header {
  uint64_t ts_ns;
  uint32_t type;
  uint32_t size;
  uint32_t pid;
  uint32_t tgid;
  uint32_t ppid;
  uint32_t uid;
  uint32_t gid;
  char comm[EVENT_LOGGER_COMM_LEN];
};

/**
 * @brief Process event payload.
 */
struct process_event {
  struct event_header hdr;
  uint32_t kind;
  uint32_t exit_code;
  uint32_t child_pid;
  char filename[EVENT_LOGGER_PATH_LEN];
  char exec_path[EVENT_LOGGER_PATH_LEN];
  char cmdline[EVENT_LOGGER_PATH_LEN];
  char cwd[EVENT_LOGGER_PATH_LEN];
  char parent_comm[EVENT_LOGGER_COMM_LEN];
  uint64_t start_time_ticks;
};

/**
 * @brief File event payload.
 *
 * @note `mode` carries syscall-specific context. In the current schema it is
 *       reused for `renameat2` newdfd context.
 */
struct file_event {
  struct event_header hdr;
  uint32_t kind;
  int32_t dfd;
  int32_t flags;
  int32_t mode;
  int32_t ret;
  char path_a[EVENT_LOGGER_PATH_LEN];
  char path_b[EVENT_LOGGER_PATH_LEN];
};

/**
 * @brief Syscall event payload.
 */
struct syscall_event {
  struct event_header hdr;
  uint32_t is_enter;
  int32_t syscall_nr;
  int64_t arg0;
  int64_t arg1;
  int64_t arg2;
  int64_t ret;
};

/**
 * @brief Socket endpoint snapshot shared by control-plane and future data-plane records.
 *
 * @note `addr` is used for IPv4/IPv6 raw bytes.
 * @note `path` is used for UNIX domain sockets, including abstract paths when present.
 */
struct network_endpoint {
  uint32_t family;
  uint32_t port;
  uint32_t addr_len;
  uint8_t addr[16];
  char path[EVENT_LOGGER_UNIX_PATH_LEN];
};

/**
 * @brief Network socket event payload.
 *
 * Socket events keep control-plane facts and bounded endpoint snapshots in one
 * record so userspace can correlate flow identity without kernel-side protocol
 * parsing. Future data-plane hooks will reuse the same envelope.
 */
struct network_event {
  struct event_header hdr;
  uint32_t kind;
  int32_t fd;
  int32_t peer_fd;
  int32_t ret;
  int32_t domain;
  int32_t sock_type;
  int32_t protocol;
  int32_t flags;
  int32_t backlog;
  int32_t how;
  int32_t opt_level;
  int32_t opt_name;
  int32_t opt_len;
  uint8_t optval_prefix[16];
  uint64_t flow_id;
  uint64_t socket_id;
  uint32_t direction;
  uint32_t transport;
  uint64_t bytes_requested;
  uint64_t bytes_transferred;
  uint32_t bytes_captured;
  uint32_t bytes_truncated;
  struct network_endpoint local;
  struct network_endpoint remote;
};

#ifdef __cplusplus
}
#endif

#endif
