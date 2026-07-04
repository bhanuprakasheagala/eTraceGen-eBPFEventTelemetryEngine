// SPDX-License-Identifier: GPL-2.0
/*
 * File Notes:
 * - Process lifecycle handlers isolated from file, syscall, and network logic.
 * - Keeps process capture easy to scan and extend independently.
 */

#include "event_logger_common.bpf.h"

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
