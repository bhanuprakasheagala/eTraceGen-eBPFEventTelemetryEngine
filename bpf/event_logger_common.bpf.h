// SPDX-License-Identifier: GPL-2.0
#ifndef EVENT_LOGGER_COMMON_BPF_H
#define EVENT_LOGGER_COMMON_BPF_H

/*
 * File Notes:
 * - Kernel-side event producer for eTraceGen.
 * - Keeps logic intentionally compact to stay verifier-friendly and portable.
 *
 * Deep-dive intent:
 * - Demonstrate canonical ring-buffer emission for process, file, syscall, and minimal network events.
 * - Keep kernel payload construction deterministic so user-space decoding remains simple.
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Avoid name collisions with kernel-declared symbols from vmlinux.h during BPF compile.
#define event_header event_logger_event_header
#define process_event event_logger_process_event
#define file_event event_logger_file_event
#define syscall_event event_logger_syscall_event
#define network_event event_logger_network_event
#include "../include/event_schema.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef AF_UNIX
#define AF_UNIX 1
#endif

char LICENSE[] SEC("license") = "GPL";

/*
 * Map sizing constants:
 * - Keep these explicit so production sizing changes happen in one place.
 * - Larger enter/exit state maps improve pairing accuracy under syscall bursts.
 */
#define STATE_MAP_MAX_ENTRIES 16384U
#define MAX_IOVEC_ENTRIES 8
#define MAX_MMSGHDR_ENTRIES 8

/*
 * Ring buffer chosen over perf buffer for modern low-overhead streaming.
 * max_entries is total buffer capacity in bytes; sizing affects burst tolerance and memory use.
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

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
  BPF_STAT_MAX = 10,
};

/* Lightweight counters for kernel-side drop/correlation visibility. */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, BPF_STAT_MAX);
  __type(key, __u32);
  __type(value, __u64);
} bpf_stats SEC(".maps");

/*
 * Runtime file probe toggles keyed by file_event_kind.
 * Values: 0=disabled, non-zero=enabled.
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 4);
  __type(key, __u32);
  __type(value, __u8);
} file_probe_enabled SEC(".maps");

/*
 * Runtime process probe toggles keyed by process_event_kind.
 * Values: 0=disabled, non-zero=enabled.
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 8);
  __type(key, __u32);
  __type(value, __u8);
} process_probe_enabled SEC(".maps");

/* Runtime syscall domain toggle. Values: 0=disabled, non-zero=enabled. */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u8);
} syscall_probe_enabled SEC(".maps");

/*
 * Selected syscall allowlist keyed by syscall number.
 * Values: 0=disabled, non-zero=enabled.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, __u8);
} syscall_allowlist SEC(".maps");

/* Runtime process-ID allowlist keyed by pid/tgid value. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, __u8);
} pid_allowlist SEC(".maps");

/* Runtime user-ID allowlist keyed by uid value. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, __u8);
} uid_allowlist SEC(".maps");

/* Single-entry array toggles whether PID filter is active. */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u8);
} pid_filter_enabled SEC(".maps");

/* Single-entry array toggles whether UID filter is active. */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u8);
} uid_filter_enabled SEC(".maps");

/* Single-entry array stores collector TGID to suppress self-generated events. */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} suppress_tgid SEC(".maps");

/* Runtime network domain probe toggles keyed by network_event_kind. */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 32);
  __type(key, __u32);
  __type(value, __u8);
} network_probe_enabled SEC(".maps");

/* Runtime network port allowlist keyed by TCP/UDP port number. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 2048);
  __type(key, __u32);
  __type(value, __u8);
} network_port_allowlist SEC(".maps");

/* Single-entry array toggles whether network port allowlist is active. */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u8);
} network_port_filter_enabled SEC(".maps");

/* Correlation key for file enter/exit pairing in-kernel. */
struct file_state_key {
  __u64 pid_tgid;
  __u32 kind;
  __u32 pad;
};

/*
 * Stores file-enter payload until corresponding syscall-exit provides return code.
 * LRU map bounds memory usage under load.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, STATE_MAP_MAX_ENTRIES);
  __type(key, struct file_state_key);
  __type(value, struct file_event);
} file_enter_state SEC(".maps");

struct syscall_state_key {
  __u64 pid_tgid;
  __s32 syscall_nr;
  __u32 pad;
};

/* Stores selected syscall-enter payload until syscall-exit provides return code. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, STATE_MAP_MAX_ENTRIES);
  __type(key, struct syscall_state_key);
  __type(value, struct syscall_event);
} syscall_enter_state SEC(".maps");

struct network_state_key {
  __u64 pid_tgid;
  __u32 kind;
  __u32 pad;
};

struct network_state_value {
  struct network_event ev;
  __u64 sockaddr_ptr;
  __u64 sockaddr_len_ptr;
  __u64 sockaddr_len;
  __u64 peer_fd_ptr;
  __u64 optval_ptr;
  __u64 optlen_ptr;
  __u64 mmsg_ptr;
  __u64 mmsg_count;
};

struct socket_fd_key {
  __u32 tgid;
  __u32 fd;
  __u32 pad;
};

struct socket_fd_value {
  __u8 is_socket;
};

/* Stores network-enter payload until syscall-exit provides return code. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, STATE_MAP_MAX_ENTRIES);
  __type(key, struct network_state_key);
  __type(value, struct network_state_value);
} network_enter_state SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, STATE_MAP_MAX_ENTRIES);
  __type(key, struct socket_fd_key);
  __type(value, struct socket_fd_value);
} socket_fd_state SEC(".maps");

struct sockaddr_in_min {
  __u16 family;
  __be16 port;
  __be32 addr;
};

struct sockaddr_in6_min {
  __u16 family;
  __be16 port;
  __be32 flowinfo;
  __u8 addr[16];
  __be32 scope_id;
};

struct sockaddr_un_min {
  __u16 family;
  char path[EVENT_LOGGER_UNIX_PATH_LEN];
};

static __always_inline void stat_inc(__u32 key) {
  __u64* cnt = bpf_map_lookup_elem(&bpf_stats, &key);
  if (cnt) {
    (*cnt)++;
  }
}

/* Return true when probe is enabled by userspace-configured toggle map. */
static __always_inline bool is_file_probe_enabled(__u32 kind) {
  __u8* enabled = bpf_map_lookup_elem(&file_probe_enabled, &kind);
  if (!enabled) {
    return true;
  }

  return *enabled != 0;
}

/* Return true when process probe is enabled by userspace-configured toggle map. */
static __always_inline bool is_process_probe_enabled(__u32 kind) {
  __u8* enabled = bpf_map_lookup_elem(&process_probe_enabled, &kind);
  if (!enabled) {
    return true;
  }

  return *enabled != 0;
}

/* Return true when network probe is enabled by userspace-configured toggle map. */
static __always_inline bool is_network_probe_enabled(__u32 kind) {
  __u8* enabled = bpf_map_lookup_elem(&network_probe_enabled, &kind);
  return enabled && (*enabled != 0);
}

/* Return true when syscall domain capture is enabled by userspace toggle. */
static __always_inline bool is_syscall_probe_enabled(void) {
  __u32 key = 0;
  __u8* enabled = bpf_map_lookup_elem(&syscall_probe_enabled, &key);
  if (!enabled) {
    return true;
  }

  return *enabled != 0;
}

/* Return true when syscall is present in userspace-configured allowlist map. */
static __always_inline bool is_syscall_allowed(__s32 nr) {
  (void)nr;
  /* Capture-first mode: selected syscall allowlist is disabled for now. */
  return true;
}

/* Return true when network port allowlist enforcement toggle is active. */
static __always_inline bool is_network_port_filter_enabled(void) {
  __u32 key = 0;
  __u8* enabled = bpf_map_lookup_elem(&network_port_filter_enabled, &key);
  return enabled && (*enabled != 0);
}

/* Return true when specific network port exists in allowlist map. */
static __always_inline bool is_port_allowed(__u32 port) {
  __u8* allowed = bpf_map_lookup_elem(&network_port_allowlist, &port);
  return allowed && (*allowed != 0);
}

/* Return true when network event passes port allowlist policy. */
static __always_inline bool is_network_port_allowed(__u32 src_port, __u32 dst_port) {
  (void)src_port;
  (void)dst_port;
  /* Capture-first mode: network port allowlist filtering is disabled for now. */
  return true;
}

/* Return true when PID filtering is active and current task is allowlisted. */
static __always_inline bool is_current_pid_allowed(void) {
  /* Capture-first mode: PID allowlist filtering is disabled for now. */
  return true;
}

/* Return true when UID filtering is active and current uid is allowlisted. */
static __always_inline bool is_current_uid_allowed(void) {
  /* Capture-first mode: UID allowlist filtering is disabled for now. */
  return true;
}

/* Return true when current task is not the userspace collector itself. */
static __always_inline bool is_not_suppressed_self(void) {
  __u32 key = 0;
  __u32* suppressed = bpf_map_lookup_elem(&suppress_tgid, &key);
  if (!suppressed || *suppressed == 0) {
    return true;
  }

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  return tgid != *suppressed;
}

/* Unified per-event gate for v1 PID/UID kernel-side filtering plus self-suppression. */
static __always_inline bool is_event_allowed(void) {
  return is_not_suppressed_self() && is_current_pid_allowed() && is_current_uid_allowed();
}

/* Read parent TGID from current task for portable PPID derivation. */
static __always_inline __u32 get_current_ppid(void) {
  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  if (!task) {
    return 0;
  }

  return BPF_CORE_READ(task, real_parent, tgid);
}

/* Read exit code from current task on process-exit path. */
static __always_inline __u32 get_current_exit_code(void) {
  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  if (!task) {
    return 0;
  }

  return BPF_CORE_READ(task, exit_code);
}

/*
 * Best-effort user string copy.
 * On read failure we keep path empty rather than spending extra cycles on retries.
 */
static __always_inline void copy_user_path(char dst[EVENT_LOGGER_PATH_LEN], const char* user_ptr) {
  if (!user_ptr) {
    dst[0] = '\0';
    return;
  }

  long copied = bpf_probe_read_user_str(dst, EVENT_LOGGER_PATH_LEN, user_ptr);
  if (copied < 0) {
    dst[0] = '\0';
  }
}

/* Copy a bounded prefix from a userspace socket-option buffer into ring-buffer memory. */
static __always_inline void copy_optval_prefix(uint8_t dst[16], const void* user_ptr,
                                               __u32 len) {
  if (!dst || !user_ptr || len == 0) {
    return;
  }

  __u32 copy_len = len;
  if (copy_len > 16U) {
    copy_len = 16U;
  }

  /* Best-effort copy; zero-initialized callers keep the record deterministic on failure. */
  bpf_probe_read_user(dst, copy_len, user_ptr);
}

/* Reset a socket endpoint snapshot before populating it from userspace data. */
static __always_inline void reset_network_endpoint(struct network_endpoint* endpoint) {
  if (!endpoint) {
    return;
  }

  endpoint->family = 0;
  endpoint->port = 0;
  endpoint->addr_len = 0;
  endpoint->path[0] = '\0';
#pragma unroll
  for (int i = 0; i < 16; ++i) {
    endpoint->addr[i] = 0;
  }
}

static __always_inline uint32_t infer_network_transport(__s32 domain, __s32 type) {
  if (domain == AF_UNIX) {
    return NETWORK_TRANSPORT_UNIX;
  }
  if (type == SOCK_STREAM) {
    return NETWORK_TRANSPORT_TCP;
  }
  if (type == SOCK_DGRAM) {
    return NETWORK_TRANSPORT_UDP;
  }
  if (type == SOCK_RAW) {
    return NETWORK_TRANSPORT_RAW;
  }
  return NETWORK_TRANSPORT_UNKNOWN;
}

static __always_inline uint32_t infer_network_direction(__u32 kind) {
  switch (kind) {
    case NETWORK_CONNECT:
    case NETWORK_SENDTO:
    case NETWORK_SENDMSG:
    case NETWORK_WRITE:
    case NETWORK_WRITEV:
    case NETWORK_SENDMMSG:
      return NETWORK_DIRECTION_OUTBOUND;
    case NETWORK_ACCEPT:
    case NETWORK_ACCEPT4:
    case NETWORK_RECVFROM:
    case NETWORK_RECVMSG:
    case NETWORK_READ:
    case NETWORK_READV:
    case NETWORK_RECVMMSG:
      return NETWORK_DIRECTION_INBOUND;
    default:
      return NETWORK_DIRECTION_UNKNOWN;
  }
}

static __always_inline __u64 hash_fold64(__u64 x) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33;
  return x;
}

static __always_inline __u64 compute_network_flow_id(const struct network_event* ev) {
  __u64 id = bpf_get_current_pid_tgid();
  id ^= ((__u64)ev->kind << 48);
  id ^= ((__u64)(uint32_t)ev->fd << 32);
  id ^= ((__u64)(uint32_t)ev->peer_fd << 16);
  id ^= (__u64)ev->local.port;
  id ^= (__u64)ev->remote.port << 32;

  if (ev->local.addr_len >= 4) {
    __u32 v = 0;
    __builtin_memcpy(&v, ev->local.addr, 4);
    id ^= (__u64)v;
  }
  if (ev->remote.addr_len >= 4) {
    __u32 v = 0;
    __builtin_memcpy(&v, ev->remote.addr, 4);
    id ^= (__u64)v << 16;
  }

  return hash_fold64(id);
}

/* Copy the pathname or abstract name from a UNIX-domain sockaddr snapshot. */
static __always_inline void copy_unix_sockaddr_path(const struct sockaddr_un_min* un,
                                                    __u32 path_len,
                                                    struct network_endpoint* endpoint) {
  if (!un || !endpoint || path_len == 0) {
    return;
  }

  if (un->path[0] == '\0') {
    int has_name = 0;
#pragma unroll
    for (int i = 1; i < EVENT_LOGGER_UNIX_PATH_LEN; ++i) {
      if (i >= (__s32)path_len) {
        break;
      }
      if (un->path[i] != '\0') {
        has_name = 1;
        break;
      }
    }

    if (!has_name) {
      return;
    }

    endpoint->path[0] = '@';
    int out_idx = 1;
#pragma unroll
    for (int i = 1; i < EVENT_LOGGER_UNIX_PATH_LEN - 1; ++i) {
      if (i >= (__s32)path_len) {
        break;
      }
      const char c = un->path[i];
      if (c == '\0') {
        break;
      }
      endpoint->path[out_idx++] = c;
    }
    endpoint->path[out_idx] = '\0';
    return;
  }

#pragma unroll
  for (int i = 0; i < EVENT_LOGGER_UNIX_PATH_LEN - 1; ++i) {
    if (i >= (__s32)path_len) {
      break;
    }
    const char c = un->path[i];
    endpoint->path[i] = c;
    if (c == '\0') {
      break;
    }
  }

  if (path_len >= EVENT_LOGGER_UNIX_PATH_LEN - 1) {
    endpoint->path[EVENT_LOGGER_UNIX_PATH_LEN - 1] = '\0';
  } else {
    endpoint->path[path_len] = '\0';
  }
}

struct iovec_min {
  __u64 iov_base;
  __u64 iov_len;
};

struct msghdr_min {
  __u64 msg_name;
  __u32 msg_namelen;
  __u32 pad;
  __u64 msg_iov;
  __u64 msg_iovlen;
};

struct mmsghdr_min {
  struct msghdr_min msg_hdr;
  __u32 msg_len;
  __u32 pad;
};

static __always_inline __u64 sum_iovec_lengths(const struct iovec_min* iov, __u64 count) {
  __u64 total = 0;
  const __u8* base = (const __u8*)iov;
#pragma unroll
  for (int i = 0; i < MAX_IOVEC_ENTRIES; ++i) {
    if ((__u64)i >= count) {
      break;
    }

    struct iovec_min item = {};
    const void* item_ptr = (const void*)(base + i * sizeof(item));
    if (bpf_probe_read_user(&item, sizeof(item), item_ptr) == 0) {
      total += item.iov_len;
    }
  }
  return total;
}

static __always_inline __u64 sum_mmsghdr_lengths(const struct mmsghdr_min* msgs, __u32 count) {
  __u64 total = 0;
  const __u8* base = (const __u8*)msgs;
#pragma unroll
  for (int i = 0; i < MAX_MMSGHDR_ENTRIES; ++i) {
    if ((uint32_t)i >= count) {
      break;
    }

    struct mmsghdr_min item = {};
    const void* item_ptr = (const void*)(base + i * sizeof(item));
    if (bpf_probe_read_user(&item, sizeof(item), item_ptr) == 0) {
      total += sum_iovec_lengths((const struct iovec_min*)item.msg_hdr.msg_iov,
                                 item.msg_hdr.msg_iovlen);
    }
  }
  return total;
}

static __always_inline __u64 sum_mmsghdr_transfers(const struct mmsghdr_min* msgs, __u32 count) {
  __u64 total = 0;
  const __u8* base = (const __u8*)msgs;
#pragma unroll
  for (int i = 0; i < MAX_MMSGHDR_ENTRIES; ++i) {
    if ((uint32_t)i >= count) {
      break;
    }

    struct mmsghdr_min item = {};
    const void* item_ptr = (const void*)(base + i * sizeof(item));
    if (bpf_probe_read_user(&item, sizeof(item), item_ptr) == 0) {
      total += (__u64)item.msg_len;
    }
  }
  return total;
}

/* Parse sockaddr from userspace pointer into a bounded endpoint snapshot. */
static __always_inline void parse_sockaddr_user(const void* user_ptr, __u32 len,
                                                struct network_endpoint* endpoint) {
  if (!endpoint) {
    return;
  }

  reset_network_endpoint(endpoint);

  if (!user_ptr || len < sizeof(__u16)) {
    return;
  }

  __u16 fam = 0;
  /* User memory reads can fail due to invalid pointers or raced userspace writes. */
  if (bpf_probe_read_user(&fam, sizeof(fam), user_ptr) != 0) {
    return;
  }

  endpoint->family = fam;

  if (fam == AF_INET && len >= sizeof(struct sockaddr_in_min)) {
    struct sockaddr_in_min in4 = {};
    if (bpf_probe_read_user(&in4, sizeof(in4), user_ptr) == 0) {
      endpoint->port = bpf_ntohs(in4.port);
      endpoint->addr_len = 4;
      __builtin_memcpy(endpoint->addr, &in4.addr, 4);
    }
    return;
  }

  if (fam == AF_INET6 && len >= sizeof(struct sockaddr_in6_min)) {
    struct sockaddr_in6_min in6 = {};
    if (bpf_probe_read_user(&in6, sizeof(in6), user_ptr) == 0) {
      endpoint->port = bpf_ntohs(in6.port);
      endpoint->addr_len = 16;
      __builtin_memcpy(endpoint->addr, in6.addr, 16);
    }
    return;
  }

  if (fam == AF_UNIX) {
    struct sockaddr_un_min un = {};
    __u32 copy_len = len;
    if (copy_len > sizeof(un)) {
      copy_len = sizeof(un);
    }
    if (copy_len >= sizeof(__u16) && bpf_probe_read_user(&un, copy_len, user_ptr) == 0) {
      copy_unix_sockaddr_path(&un, copy_len - sizeof(__u16), endpoint);
    }
  }
}

/*
 * Fill event envelope fields consumed across all event families in user-space.
 * This function is intentionally narrow and side-effect free for verifier friendliness.
 */
static __always_inline void fill_header(struct event_header* hdr, __u32 type) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u64 uid_gid = bpf_get_current_uid_gid();

  hdr->ts_ns = bpf_ktime_get_ns();
  hdr->type = type;
  hdr->size = 0;

  /* bpf_get_current_pid_tgid uses low32=pid and high32=tgid. */
  hdr->pid = (__u32)pid_tgid;
  hdr->tgid = (__u32)(pid_tgid >> 32);
  hdr->uid = (__u32)uid_gid;
  hdr->gid = (__u32)(uid_gid >> 32);

  /* real_parent->tgid provides parent process identity for process lineage. */
  hdr->ppid = get_current_ppid();

  /* comm is short but consistently available at low cost. */
  bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

/*
 * Shared process event emitter used by multiple process lifecycle tracepoints.
 * Keeping emission logic centralized avoids drift in event shape across handlers.
 */
static __always_inline struct process_event* reserve_process_event(__u32 kind) {
  struct process_event* ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
  if (!ev) {
    stat_inc(BPF_STAT_RINGBUF_RESERVE_FAIL);
    return 0;
  }

  fill_header(&ev->hdr, EVENT_TYPE_PROCESS);
  ev->hdr.size = sizeof(*ev);
  ev->kind = kind;
  ev->exit_code = 0;
  ev->child_pid = 0;
  ev->filename[0] = '\0';
  ev->exec_path[0] = '\0';
  ev->cmdline[0] = '\0';
  ev->cwd[0] = '\0';
  ev->parent_comm[0] = '\0';
  ev->start_time_ticks = 0;

  return ev;
}

/* Shared file event allocator to keep all file handlers consistent and compact. */
static __always_inline struct file_event* reserve_file_event(__u32 kind) {
  struct file_event* ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
  if (!ev) {
    stat_inc(BPF_STAT_RINGBUF_RESERVE_FAIL);
    return 0;
  }

  fill_header(&ev->hdr, EVENT_TYPE_FILE);
  ev->hdr.size = sizeof(*ev);
  ev->kind = kind;
  ev->dfd = 0;
  ev->flags = 0;
  ev->mode = 0;
  ev->ret = 0;
  ev->path_a[0] = '\0';
  ev->path_b[0] = '\0';

  return ev;
}

/* Shared syscall event allocator to keep enter/exit handlers aligned. */
static __always_inline struct syscall_event* reserve_syscall_event(void) {
  struct syscall_event* ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
  if (!ev) {
    stat_inc(BPF_STAT_RINGBUF_RESERVE_FAIL);
    return 0;
  }

  fill_header(&ev->hdr, EVENT_TYPE_SYSCALL);
  ev->hdr.size = sizeof(*ev);
  ev->is_enter = 0;
  ev->syscall_nr = 0;
  ev->arg0 = 0;
  ev->arg1 = 0;
  ev->arg2 = 0;
  ev->ret = 0;

  return ev;
}

/* Shared network event allocator to keep enter/exit handlers aligned. */
static __always_inline struct network_event* reserve_network_event(__u32 kind) {
  struct network_event* ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
  if (!ev) {
    stat_inc(BPF_STAT_RINGBUF_RESERVE_FAIL);
    return 0;
  }

  fill_header(&ev->hdr, EVENT_TYPE_NETWORK);
  ev->hdr.size = sizeof(*ev);
  ev->kind = kind;
  ev->fd = 0;
  ev->peer_fd = 0;
  ev->ret = 0;
  ev->domain = 0;
  ev->sock_type = 0;
  ev->protocol = 0;
  ev->flags = 0;
  ev->backlog = 0;
  ev->how = 0;
  ev->opt_level = 0;
  ev->opt_name = 0;
  ev->opt_len = 0;
#pragma unroll
  for (int i = 0; i < 16; ++i) {
    ev->optval_prefix[i] = 0;
  }
  ev->flow_id = 0;
  ev->socket_id = 0;
  ev->direction = NETWORK_DIRECTION_UNKNOWN;
  ev->transport = NETWORK_TRANSPORT_UNKNOWN;
  ev->bytes_requested = 0;
  ev->bytes_transferred = 0;
  ev->bytes_captured = 0;
  ev->bytes_truncated = 0;
  reset_network_endpoint(&ev->local);
  reset_network_endpoint(&ev->remote);

  return ev;
}

/* Build stable correlation key for file enter/exit pairing by task and event kind. */
static __always_inline struct file_state_key make_file_key(__u32 kind) {
  struct file_state_key key = {};
  key.pid_tgid = bpf_get_current_pid_tgid();
  key.kind = kind;
  return key;
}

/* Build stable correlation key for syscall enter/exit pairing by task and syscall number. */
static __always_inline struct syscall_state_key make_syscall_key(__s32 nr) {
  struct syscall_state_key key = {};
  key.pid_tgid = bpf_get_current_pid_tgid();
  key.syscall_nr = nr;
  return key;
}

/* Build stable correlation key for network enter/exit pairing by task and network kind. */
static __always_inline struct network_state_key make_network_key(__u32 kind) {
  struct network_state_key key = {};
  key.pid_tgid = bpf_get_current_pid_tgid();
  key.kind = kind;
  return key;
}

/*
 * Stash file-enter payload into map and discard scratch ringbuf record.
 * Scratch record avoids stack allocation for large struct file_event.
 */
static __always_inline int save_file_enter_state(__u32 kind, struct file_event* ev) {
  struct file_state_key key = make_file_key(kind);

  struct file_event* existing = bpf_map_lookup_elem(&file_enter_state, &key);
  if (existing) {
    /* Prevent overwrite to avoid wrong enter/exit pairing under reentry. */
    stat_inc(BPF_STAT_FILE_STATE_COLLISION);
    bpf_ringbuf_discard(ev, 0);
    return -1;
  }

  int ret = bpf_map_update_elem(&file_enter_state, &key, ev, BPF_ANY);
  if (ret < 0) {
    stat_inc(BPF_STAT_FILE_STATE_SAVE_FAIL);
  }
  bpf_ringbuf_discard(ev, 0);
  return ret;
}

/* Save selected syscall-enter payload and discard scratch ringbuf record. */
static __always_inline int save_syscall_enter_state(__s32 nr, struct syscall_event* ev) {
  struct syscall_state_key key = make_syscall_key(nr);

  struct syscall_event* existing = bpf_map_lookup_elem(&syscall_enter_state, &key);
  if (existing) {
    stat_inc(BPF_STAT_SYSCALL_STATE_COLLISION);
    bpf_ringbuf_discard(ev, 0);
    return -1;
  }

  int ret = bpf_map_update_elem(&syscall_enter_state, &key, ev, BPF_ANY);
  if (ret < 0) {
    stat_inc(BPF_STAT_SYSCALL_STATE_SAVE_FAIL);
  }
  bpf_ringbuf_discard(ev, 0);
  return ret;
}

/* Save network-enter payload and discard scratch ringbuf record. */
static __always_inline int save_network_enter_state(__u32 kind, struct network_state_value* state,
                                                    struct network_event* scratch_ev) {
  struct network_state_key key = make_network_key(kind);

  struct network_state_value* existing = bpf_map_lookup_elem(&network_enter_state, &key);
  if (existing) {
    /*
     * Re-entrant syscall path for same pid_tgid+kind: dropping avoids mismatched exit correlation.
     */
    stat_inc(BPF_STAT_NETWORK_STATE_COLLISION);
    bpf_ringbuf_discard(scratch_ev, 0);
    return -1;
  }

  int ret = bpf_map_update_elem(&network_enter_state, &key, state, BPF_ANY);
  if (ret < 0) {
    stat_inc(BPF_STAT_NETWORK_STATE_SAVE_FAIL);
  }

  bpf_ringbuf_discard(scratch_ev, 0);
  return ret;
}

/*
 * Finalize correlated file event on syscall-exit by copying saved enter payload,
 * setting return code, and emitting one complete event.
 */
static __always_inline int emit_file_exit_event(__u32 kind, __s64 ret_code) {
  struct file_state_key key = make_file_key(kind);
  struct file_event* state = bpf_map_lookup_elem(&file_enter_state, &key);
  if (!state) {
    stat_inc(BPF_STAT_FILE_STATE_MISS);
    return 0;
  }

  struct file_event* out = reserve_file_event(kind);
  if (!out) {
    bpf_map_delete_elem(&file_enter_state, &key);
    return 0;
  }

  __builtin_memcpy(out, state, sizeof(*out));

  /* Use exit time for finalized file event and propagate authoritative syscall outcome. */
  out->hdr.ts_ns = bpf_ktime_get_ns();
  out->ret = (__s32)ret_code;

  bpf_ringbuf_submit(out, 0);
  bpf_map_delete_elem(&file_enter_state, &key);
  return 0;
}

/* Finalize selected syscall event at exit with authoritative return code. */
static __always_inline int emit_syscall_exit_event(__s32 nr, __s64 ret_code) {
  struct syscall_state_key key = make_syscall_key(nr);
  struct syscall_event* state = bpf_map_lookup_elem(&syscall_enter_state, &key);
  if (!state) {
    stat_inc(BPF_STAT_SYSCALL_STATE_MISS);
    return 0;
  }

  struct syscall_event* out = reserve_syscall_event();
  if (!out) {
    bpf_map_delete_elem(&syscall_enter_state, &key);
    return 0;
  }

  __builtin_memcpy(out, state, sizeof(*out));
  out->hdr.ts_ns = bpf_ktime_get_ns();
  out->is_enter = 0;
  out->ret = ret_code;

  bpf_ringbuf_submit(out, 0);
  bpf_map_delete_elem(&syscall_enter_state, &key);
  return 0;
}

static __always_inline int add_socket_fd(__s32 fd) {
  struct socket_fd_key key = {};
  key.tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  key.fd = (__u32)fd;

  struct socket_fd_value value = {};
  value.is_socket = 1;
  return bpf_map_update_elem(&socket_fd_state, &key, &value, BPF_ANY);
}

static __always_inline int delete_socket_fd(__s32 fd) {
  struct socket_fd_key key = {};
  key.tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  key.fd = (__u32)fd;
  return bpf_map_delete_elem(&socket_fd_state, &key);
}

static __always_inline bool is_socket_fd(__s32 fd) {
  struct socket_fd_key key = {};
  key.tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  key.fd = (__u32)fd;

  struct socket_fd_value* value = bpf_map_lookup_elem(&socket_fd_state, &key);
  return value != NULL && value->is_socket == 1;
}

/* Finalize network event at exit with authoritative return code. */
static __always_inline int emit_network_exit_event(__u32 kind, __s64 ret_code) {
  struct network_state_key key = make_network_key(kind);
  struct network_state_value* state = bpf_map_lookup_elem(&network_enter_state, &key);
  if (!state) {
    stat_inc(BPF_STAT_NETWORK_STATE_MISS);
    return 0;
  }

  struct network_event* out = reserve_network_event(kind);
  if (!out) {
    bpf_map_delete_elem(&network_enter_state, &key);
    return 0;
  }

  __builtin_memcpy(out, &state->ev, sizeof(*out));
  out->hdr.ts_ns = bpf_ktime_get_ns();
  out->ret = (__s32)ret_code;

  if (kind == NETWORK_SOCKET && ret_code >= 0) {
    out->fd = (__s32)ret_code;
    add_socket_fd(out->fd);
  }

  if (kind == NETWORK_SOCKETPAIR && ret_code >= 0 && state->peer_fd_ptr != 0) {
    __s32 fds[2] = {};
    if (bpf_probe_read_user(&fds, sizeof(fds), (const void*)state->peer_fd_ptr) == 0) {
      out->fd = fds[0];
      out->peer_fd = fds[1];
      add_socket_fd(out->fd);
      add_socket_fd(out->peer_fd);
    }
  }

  if (kind == NETWORK_ACCEPT && ret_code >= 0) {
    out->peer_fd = (__s32)ret_code;
    add_socket_fd(out->peer_fd);
  }

  if (kind == NETWORK_ACCEPT4 && ret_code >= 0) {
    out->peer_fd = (__s32)ret_code;
    add_socket_fd(out->peer_fd);
  }

  if (kind == NETWORK_CLOSE && ret_code >= 0) {
    delete_socket_fd(out->fd);
  }

  if ((kind == NETWORK_ACCEPT || kind == NETWORK_ACCEPT4 || kind == NETWORK_RECVFROM ||
       kind == NETWORK_GETPEERNAME) && ret_code >= 0 && state->sockaddr_ptr != 0) {
    __u32 len = 0;
    if (state->sockaddr_len_ptr != 0) {
      bpf_probe_read_user(&len, sizeof(len), (const void*)state->sockaddr_len_ptr);
    }
    parse_sockaddr_user((const void*)state->sockaddr_ptr, len, &out->remote);
  }

  if ((kind == NETWORK_SENDTO || kind == NETWORK_RECVFROM || kind == NETWORK_SENDMSG ||
       kind == NETWORK_RECVMSG || kind == NETWORK_READ || kind == NETWORK_WRITE ||
       kind == NETWORK_READV || kind == NETWORK_WRITEV) && ret_code >= 0) {
    out->bytes_transferred = (__u64)ret_code;
  }

  if ((kind == NETWORK_SENDMMSG || kind == NETWORK_RECVMMSG) && ret_code >= 0 &&
      state->mmsg_ptr != 0 && state->mmsg_count != 0) {
    out->bytes_transferred = sum_mmsghdr_transfers((const struct mmsghdr_min*)state->mmsg_ptr,
                                                   (__u32)state->mmsg_count);
  }

  if (out->flow_id == 0) {
    out->flow_id = compute_network_flow_id(out);
  }

  if ((kind == NETWORK_ACCEPT || kind == NETWORK_ACCEPT4) && ret_code >= 0) {
    out->peer_fd = (__s32)ret_code;
  }

  if ((kind == NETWORK_ACCEPT || kind == NETWORK_ACCEPT4 || kind == NETWORK_RECVFROM ||
       kind == NETWORK_GETPEERNAME) && ret_code >= 0 && state->sockaddr_ptr != 0) {
    __u32 len = 0;
    if (state->sockaddr_len_ptr != 0) {
      bpf_probe_read_user(&len, sizeof(len), (const void*)state->sockaddr_len_ptr);
    }
    parse_sockaddr_user((const void*)state->sockaddr_ptr, len, &out->remote);
  }

  if (kind == NETWORK_SENDTO || kind == NETWORK_RECVFROM) {
    if (ret_code >= 0) {
      out->bytes_transferred = (__u64)ret_code;
    }
  }

  if (kind == NETWORK_GETSOCKNAME && ret_code >= 0 && state->sockaddr_ptr != 0) {
    __u32 len = 0;
    if (state->sockaddr_len_ptr != 0) {
      bpf_probe_read_user(&len, sizeof(len), (const void*)state->sockaddr_len_ptr);
    }
    parse_sockaddr_user((const void*)state->sockaddr_ptr, len, &out->local);
  }

  if (kind == NETWORK_GETSOCKOPT && ret_code >= 0) {
    if (state->optlen_ptr != 0) {
      __u32 len = 0;
      if (bpf_probe_read_user(&len, sizeof(len), (const void*)state->optlen_ptr) == 0) {
        out->opt_len = (__s32)len;
      }
    }
    if (state->optval_ptr != 0 && out->opt_len > 0) {
      copy_optval_prefix(out->optval_prefix, (const void*)state->optval_ptr,
                         (__u32)out->opt_len);
    }
  }

  if (!is_network_port_allowed(out->local.port, out->remote.port)) {
    bpf_ringbuf_discard(out, 0);
    bpf_map_delete_elem(&network_enter_state, &key);
    return 0;
  }

  bpf_ringbuf_submit(out, 0);
  bpf_map_delete_elem(&network_enter_state, &key);
  return 0;
}



#endif /* EVENT_LOGGER_COMMON_BPF_H */
