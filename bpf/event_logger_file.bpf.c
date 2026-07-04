// SPDX-License-Identifier: GPL-2.0
/*
 * File Notes:
 * - File syscall handlers live here so path pairing logic stays isolated.
 * - Keeps open/unlink/rename behavior separate from process and socket paths.
 */

#include "event_logger_common.bpf.h"

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
