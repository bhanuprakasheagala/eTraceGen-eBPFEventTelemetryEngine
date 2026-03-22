// SPDX-License-Identifier: GPL-2.0
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

char LICENSE[] SEC("license") = "GPL";

/*
 * Map sizing constants:
 * - Keep these explicit so production sizing changes happen in one place.
 * - Larger enter/exit state maps improve pairing accuracy under syscall bursts.
 */
#define STATE_MAP_MAX_ENTRIES 16384U

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

/* Runtime network domain probe toggles keyed by network_event_kind. */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 16);
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
};

/* Stores network-enter payload until syscall-exit provides return code. */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, STATE_MAP_MAX_ENTRIES);
  __type(key, struct network_state_key);
  __type(value, struct network_state_value);
} network_enter_state SEC(".maps");

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

static __always_inline bool is_network_port_filter_enabled(void) {
  __u32 key = 0;
  __u8* enabled = bpf_map_lookup_elem(&network_port_filter_enabled, &key);
  return enabled && (*enabled != 0);
}

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

/* Unified per-event gate for v1 PID/UID kernel-side filtering. */
static __always_inline bool is_event_allowed(void) {
  return is_current_pid_allowed() && is_current_uid_allowed();
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

/* Parse sockaddr from userspace pointer into fixed network_event fields. */
static __always_inline void parse_sockaddr_user(const void* user_ptr, __u32 len, __u32* family,
                                                __u32* port, __u8 addr[16]) {
  if (!family || !port || !addr) {
    return;
  }

  *family = 0;
  *port = 0;
  __builtin_memset(addr, 0, 16);

  if (!user_ptr || len < sizeof(__u16)) {
    return;
  }

  __u16 fam = 0;
  /* User memory reads can fail due to invalid pointers or raced userspace writes. */
  if (bpf_probe_read_user(&fam, sizeof(fam), user_ptr) != 0) {
    return;
  }

  *family = fam;

  if (fam == AF_INET && len >= sizeof(struct sockaddr_in_min)) {
    struct sockaddr_in_min in4 = {};
    if (bpf_probe_read_user(&in4, sizeof(in4), user_ptr) == 0) {
      *port = bpf_ntohs(in4.port);
      __builtin_memcpy(addr, &in4.addr, 4);
    }
    return;
  }

  if (fam == AF_INET6 && len >= sizeof(struct sockaddr_in6_min)) {
    struct sockaddr_in6_min in6 = {};
    if (bpf_probe_read_user(&in6, sizeof(in6), user_ptr) == 0) {
      *port = bpf_ntohs(in6.port);
      __builtin_memcpy(addr, in6.addr, 16);
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

  __builtin_memset(ev, 0, sizeof(*ev));
  fill_header(&ev->hdr, EVENT_TYPE_PROCESS);
  ev->hdr.size = sizeof(*ev);
  ev->kind = kind;

  return ev;
}

/* Shared file event allocator to keep all file handlers consistent and compact. */
static __always_inline struct file_event* reserve_file_event(__u32 kind) {
  struct file_event* ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
  if (!ev) {
    stat_inc(BPF_STAT_RINGBUF_RESERVE_FAIL);
    return 0;
  }

  __builtin_memset(ev, 0, sizeof(*ev));
  fill_header(&ev->hdr, EVENT_TYPE_FILE);
  ev->hdr.size = sizeof(*ev);
  ev->kind = kind;

  return ev;
}

/* Shared syscall event allocator to keep enter/exit handlers aligned. */
static __always_inline struct syscall_event* reserve_syscall_event(void) {
  struct syscall_event* ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
  if (!ev) {
    stat_inc(BPF_STAT_RINGBUF_RESERVE_FAIL);
    return 0;
  }

  __builtin_memset(ev, 0, sizeof(*ev));
  fill_header(&ev->hdr, EVENT_TYPE_SYSCALL);
  ev->hdr.size = sizeof(*ev);

  return ev;
}

/* Shared network event allocator to keep enter/exit handlers aligned. */
static __always_inline struct network_event* reserve_network_event(__u32 kind) {
  struct network_event* ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
  if (!ev) {
    stat_inc(BPF_STAT_RINGBUF_RESERVE_FAIL);
    return 0;
  }

  __builtin_memset(ev, 0, sizeof(*ev));
  fill_header(&ev->hdr, EVENT_TYPE_NETWORK);
  ev->hdr.size = sizeof(*ev);
  ev->kind = kind;

  return ev;
}

static __always_inline struct file_state_key make_file_key(__u32 kind) {
  struct file_state_key key = {};
  key.pid_tgid = bpf_get_current_pid_tgid();
  key.kind = kind;
  return key;
}

static __always_inline struct syscall_state_key make_syscall_key(__s32 nr) {
  struct syscall_state_key key = {};
  key.pid_tgid = bpf_get_current_pid_tgid();
  key.syscall_nr = nr;
  return key;
}

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

  if ((kind == NETWORK_ACCEPT || kind == NETWORK_RECVFROM) && ret_code >= 0 && state->sockaddr_ptr != 0) {
    __u32 len = 0;
    if (state->sockaddr_len_ptr != 0) {
      bpf_probe_read_user(&len, sizeof(len), (const void*)state->sockaddr_len_ptr);
    }
    parse_sockaddr_user((const void*)state->sockaddr_ptr, len, &out->addr_family, &out->dst_port,
                        out->dst_addr);
  }

  if (!is_network_port_allowed(out->src_port, out->dst_port)) {
    bpf_ringbuf_discard(out, 0);
    bpf_map_delete_elem(&network_enter_state, &key);
    return 0;
  }

  bpf_ringbuf_submit(out, 0);
  bpf_map_delete_elem(&network_enter_state, &key);
  return 0;
}

/* Exec tracepoint is a stable first hook for process lifecycle telemetry. */
SEC("tracepoint/sched/sched_process_exec")
int on_sched_exec(void* ctx) {
  (void)ctx;

  if (!is_event_allowed() || !is_process_probe_enabled(PROCESS_EXEC)) {
    return 0;
  }

  struct process_event* ev = reserve_process_event(PROCESS_EXEC);
  if (!ev) {
    return 0;
  }

  bpf_ringbuf_submit(ev, 0);
  return 0;
}

/*
 * Fork tracepoint emits the created child PID from tracepoint context so user-space
 * can correlate parent and child process lineage.
 */
SEC("tracepoint/sched/sched_process_fork")
int on_sched_fork(struct trace_event_raw_sched_process_fork* ctx) {
  if (!is_event_allowed() || !is_process_probe_enabled(PROCESS_FORK)) {
    return 0;
  }

  struct process_event* ev = reserve_process_event(PROCESS_FORK);
  if (!ev) {
    return 0;
  }

  ev->child_pid = (__u32)BPF_CORE_READ(ctx, child_pid);

  bpf_ringbuf_submit(ev, 0);
  return 0;
}

/*
 * Exit tracepoint emits exit code from current task_struct.
 * This keeps exit semantics visible without expensive additional lookups.
 */
SEC("tracepoint/sched/sched_process_exit")
int on_sched_exit(void* ctx) {
  (void)ctx;

  if (!is_event_allowed() || !is_process_probe_enabled(PROCESS_EXIT)) {
    return 0;
  }

  struct process_event* ev = reserve_process_event(PROCESS_EXIT);
  if (!ev) {
    return 0;
  }

  ev->exit_code = get_current_exit_code();

  bpf_ringbuf_submit(ev, 0);
  return 0;
}

/* clone exit: emit child pid returned by clone(2). */
SEC("tracepoint/syscalls/sys_exit_clone")
int on_sys_exit_clone(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_process_probe_enabled(PROCESS_CLONE)) {
    return 0;
  }

  struct process_event* ev = reserve_process_event(PROCESS_CLONE);
  if (!ev) {
    return 0;
  }

  if (ctx->ret > 0) {
    ev->child_pid = (__u32)ctx->ret;
  }

  bpf_ringbuf_submit(ev, 0);
  return 0;
}

/* clone3 exit: emit child pid returned by clone3(2). */
SEC("tracepoint/syscalls/sys_exit_clone3")
int on_sys_exit_clone3(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_process_probe_enabled(PROCESS_CLONE3)) {
    return 0;
  }

  struct process_event* ev = reserve_process_event(PROCESS_CLONE3);
  if (!ev) {
    return 0;
  }

  if (ctx->ret > 0) {
    ev->child_pid = (__u32)ctx->ret;
  }

  bpf_ringbuf_submit(ev, 0);
  return 0;
}

/* vfork exit: emit child pid returned by vfork(2). */
SEC("tracepoint/syscalls/sys_exit_vfork")
int on_sys_exit_vfork(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_process_probe_enabled(PROCESS_VFORK)) {
    return 0;
  }

  struct process_event* ev = reserve_process_event(PROCESS_VFORK);
  if (!ev) {
    return 0;
  }

  if (ctx->ret > 0) {
    ev->child_pid = (__u32)ctx->ret;
  }

  bpf_ringbuf_submit(ev, 0);
  return 0;
}

/* openat enter: capture full request context and stash until syscall-exit. */
SEC("tracepoint/syscalls/sys_enter_openat")
int on_sys_enter_openat(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_file_probe_enabled(FILE_OPENAT)) {
    return 0;
  }

  struct file_event* ev = reserve_file_event(FILE_OPENAT);
  if (!ev) {
    return 0;
  }

  ev->dfd = (__s32)ctx->args[0];
  ev->flags = (__s32)ctx->args[2];
  ev->mode = (__s32)ctx->args[3];
  copy_user_path(ev->path_a, (const char*)ctx->args[1]);

  save_file_enter_state(FILE_OPENAT, ev);
  return 0;
}

/* unlinkat enter: capture target path and unlink flags. */
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int on_sys_enter_unlinkat(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_file_probe_enabled(FILE_UNLINKAT)) {
    return 0;
  }

  struct file_event* ev = reserve_file_event(FILE_UNLINKAT);
  if (!ev) {
    return 0;
  }

  ev->dfd = (__s32)ctx->args[0];
  ev->flags = (__s32)ctx->args[2];
  copy_user_path(ev->path_a, (const char*)ctx->args[1]);

  save_file_enter_state(FILE_UNLINKAT, ev);
  return 0;
}

/* renameat2 enter: capture source/destination paths and rename flags. */
SEC("tracepoint/syscalls/sys_enter_renameat2")
int on_sys_enter_renameat2(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_file_probe_enabled(FILE_RENAMEAT2)) {
    return 0;
  }

  struct file_event* ev = reserve_file_event(FILE_RENAMEAT2);
  if (!ev) {
    return 0;
  }

  ev->dfd = (__s32)ctx->args[0];
  /* mode carries newdfd in current schema version for renameat2 context. */
  ev->mode = (__s32)ctx->args[2];
  ev->flags = (__s32)ctx->args[4];
  copy_user_path(ev->path_a, (const char*)ctx->args[1]);
  copy_user_path(ev->path_b, (const char*)ctx->args[3]);

  save_file_enter_state(FILE_RENAMEAT2, ev);
  return 0;
}

/* openat exit: emit paired event with accurate return code. */
SEC("tracepoint/syscalls/sys_exit_openat")
int on_sys_exit_openat(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_file_probe_enabled(FILE_OPENAT)) {
    return 0;
  }

  return emit_file_exit_event(FILE_OPENAT, ctx->ret);
}

/* unlinkat exit: emit paired event with accurate return code. */
SEC("tracepoint/syscalls/sys_exit_unlinkat")
int on_sys_exit_unlinkat(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_file_probe_enabled(FILE_UNLINKAT)) {
    return 0;
  }

  return emit_file_exit_event(FILE_UNLINKAT, ctx->ret);
}

/* renameat2 exit: emit paired event with accurate return code. */
SEC("tracepoint/syscalls/sys_exit_renameat2")
int on_sys_exit_renameat2(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_file_probe_enabled(FILE_RENAMEAT2)) {
    return 0;
  }

  return emit_file_exit_event(FILE_RENAMEAT2, ctx->ret);
}

/* Raw syscall enter handler for broad syscall telemetry capture. */
SEC("tracepoint/raw_syscalls/sys_enter")
int on_raw_sys_enter(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_syscall_probe_enabled()) {
    return 0;
  }

  __s32 nr = (__s32)BPF_CORE_READ(ctx, id);
  if (!is_syscall_allowed(nr)) {
    return 0;
  }

  struct syscall_event* ev = reserve_syscall_event();
  if (!ev) {
    return 0;
  }

  ev->is_enter = 1;
  ev->syscall_nr = nr;
  ev->arg0 = (__s64)ctx->args[0];
  ev->arg1 = (__s64)ctx->args[1];
  ev->arg2 = (__s64)ctx->args[2];

  save_syscall_enter_state(nr, ev);
  return 0;
}

/* Raw syscall exit handler emits paired syscall event with accurate return code. */
SEC("tracepoint/raw_syscalls/sys_exit")
int on_raw_sys_exit(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_syscall_probe_enabled()) {
    return 0;
  }

  __s32 nr = (__s32)BPF_CORE_READ(ctx, id);
  if (!is_syscall_allowed(nr)) {
    return 0;
  }

  return emit_syscall_exit_event(nr, ctx->ret);
}

/* socket enter: capture requested domain/type/protocol. */
SEC("tracepoint/syscalls/sys_enter_socket")
int on_sys_enter_socket(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SOCKET)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_SOCKET);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.domain = (__s32)ctx->args[0];
  state.ev.sock_type = (__s32)ctx->args[1];
  state.ev.protocol = (__s32)ctx->args[2];

  save_network_enter_state(NETWORK_SOCKET, &state, ev);
  return 0;
}

/* socket exit: emit finalized socket event with ret outcome. */
SEC("tracepoint/syscalls/sys_exit_socket")
int on_sys_exit_socket(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SOCKET)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_SOCKET, ctx->ret);
}

/* connect enter: capture fd and destination socket address. */
SEC("tracepoint/syscalls/sys_enter_connect")
int on_sys_enter_connect(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_CONNECT)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_CONNECT);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];

  const void* sockaddr_ptr = (const void*)ctx->args[1];
  __u32 sockaddr_len = (__u32)ctx->args[2];
  parse_sockaddr_user(sockaddr_ptr, sockaddr_len, &state.ev.addr_family, &state.ev.dst_port,
                      state.ev.dst_addr);

  save_network_enter_state(NETWORK_CONNECT, &state, ev);
  return 0;
}

/* connect exit: emit finalized connect event with ret outcome. */
SEC("tracepoint/syscalls/sys_exit_connect")
int on_sys_exit_connect(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_CONNECT)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_CONNECT, ctx->ret);
}

/* bind enter: capture fd and local socket address intent. */
SEC("tracepoint/syscalls/sys_enter_bind")
int on_sys_enter_bind(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_BIND)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_BIND);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];

  const void* sockaddr_ptr = (const void*)ctx->args[1];
  __u32 sockaddr_len = (__u32)ctx->args[2];
  parse_sockaddr_user(sockaddr_ptr, sockaddr_len, &state.ev.addr_family, &state.ev.src_port,
                      state.ev.src_addr);

  save_network_enter_state(NETWORK_BIND, &state, ev);
  return 0;
}

/* bind exit: emit finalized bind event with ret outcome. */
SEC("tracepoint/syscalls/sys_exit_bind")
int on_sys_exit_bind(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_BIND)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_BIND, ctx->ret);
}

/* accept4 enter: capture listening fd and peer sockaddr pointers for exit parsing. */
SEC("tracepoint/syscalls/sys_enter_accept4")
int on_sys_enter_accept4(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_ACCEPT)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_ACCEPT);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.sock_type = (__s32)ctx->args[3]; /* accept4 flags */
  state.sockaddr_ptr = (__u64)ctx->args[1];
  state.sockaddr_len_ptr = (__u64)ctx->args[2];

  save_network_enter_state(NETWORK_ACCEPT, &state, ev);
  return 0;
}

/* accept4 exit: emit finalized accept event with peer sockaddr and ret outcome. */
SEC("tracepoint/syscalls/sys_exit_accept4")
int on_sys_exit_accept4(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_ACCEPT)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_ACCEPT, ctx->ret);
}

/* listen enter: capture fd and backlog intent. */
SEC("tracepoint/syscalls/sys_enter_listen")
int on_sys_enter_listen(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_LISTEN)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_LISTEN);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.protocol = (__s32)ctx->args[1]; /* protocol reused for listen backlog */

  save_network_enter_state(NETWORK_LISTEN, &state, ev);
  return 0;
}

/* listen exit: emit finalized listen event with ret outcome. */
SEC("tracepoint/syscalls/sys_exit_listen")
int on_sys_exit_listen(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_LISTEN)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_LISTEN, ctx->ret);
}

/* sendto enter: capture fd/flags and destination socket address. */
SEC("tracepoint/syscalls/sys_enter_sendto")
int on_sys_enter_sendto(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SENDTO)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_SENDTO);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.sock_type = (__s32)ctx->args[3]; /* send flags */

  const void* sockaddr_ptr = (const void*)ctx->args[4];
  __u32 sockaddr_len = (__u32)ctx->args[5];
  parse_sockaddr_user(sockaddr_ptr, sockaddr_len, &state.ev.addr_family, &state.ev.dst_port,
                      state.ev.dst_addr);

  save_network_enter_state(NETWORK_SENDTO, &state, ev);
  return 0;
}

/* sendto exit: emit finalized sendto event with ret outcome. */
SEC("tracepoint/syscalls/sys_exit_sendto")
int on_sys_exit_sendto(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SENDTO)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_SENDTO, ctx->ret);
}

/* recvfrom enter: capture fd/flags and source sockaddr pointers for exit parsing. */
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int on_sys_enter_recvfrom(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_RECVFROM)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_RECVFROM);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.sock_type = (__s32)ctx->args[3]; /* recv flags */
  state.sockaddr_ptr = (__u64)ctx->args[4];
  state.sockaddr_len_ptr = (__u64)ctx->args[5];

  save_network_enter_state(NETWORK_RECVFROM, &state, ev);
  return 0;
}

/* recvfrom exit: emit finalized recvfrom event with source sockaddr and ret outcome. */
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int on_sys_exit_recvfrom(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_RECVFROM)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_RECVFROM, ctx->ret);
}

/* shutdown enter: capture fd and how value. */
SEC("tracepoint/syscalls/sys_enter_shutdown")
int on_sys_enter_shutdown(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SHUTDOWN)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_SHUTDOWN);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.protocol = (__s32)ctx->args[1]; /* protocol field reused for shutdown how */

  save_network_enter_state(NETWORK_SHUTDOWN, &state, ev);
  return 0;
}

/* shutdown exit: emit finalized shutdown event with ret outcome. */
SEC("tracepoint/syscalls/sys_exit_shutdown")
int on_sys_exit_shutdown(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SHUTDOWN)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_SHUTDOWN, ctx->ret);
}

/* close enter: capture fd intent before close outcome is known. */
SEC("tracepoint/syscalls/sys_enter_close")
int on_sys_enter_close(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_CLOSE)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_CLOSE);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];

  save_network_enter_state(NETWORK_CLOSE, &state, ev);
  return 0;
}

/* close exit: emit finalized close event with ret outcome. */
SEC("tracepoint/syscalls/sys_exit_close")
int on_sys_exit_close(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_CLOSE)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_CLOSE, ctx->ret);
}
