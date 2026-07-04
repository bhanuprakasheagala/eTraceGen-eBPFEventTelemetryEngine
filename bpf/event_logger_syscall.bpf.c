// SPDX-License-Identifier: GPL-2.0
/*
 * File Notes:
 * - Broad syscall telemetry is split out so raw syscall logic remains focused.
 * - Raw enter/exit pairing stays independent from file and network handlers.
 */

#include "event_logger_common.bpf.h"

/*
 * Raw syscall enter handler for broad syscall telemetry capture.
 * Using raw_syscalls tracepoints minimizes per-syscall program count while
 * preserving syscall number plus first argument set for behavioral analysis.
 */
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

/*
 * Raw syscall exit handler emits paired syscall event with accurate return code.
 * Exit-side emission guarantees authoritative return value and avoids emitting
 * speculative enter-only records when pairing fails.
 */
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
