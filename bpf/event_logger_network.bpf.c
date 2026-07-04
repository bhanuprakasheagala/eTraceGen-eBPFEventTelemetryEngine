// SPDX-License-Identifier: GPL-2.0
/*
 * File Notes:
 * - Socket-level network metadata handlers are isolated in their own module.
 * - Control-plane records come first so we can stabilize endpoint identity before protocol parsing.
 */

#include "event_logger_common.bpf.h"

/* socket enter: capture requested domain, type, and protocol. */
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
  state.ev.transport = infer_network_transport(state.ev.domain, state.ev.sock_type);
  state.ev.direction = infer_network_direction(NETWORK_SOCKET);

  save_network_enter_state(NETWORK_SOCKET, &state, ev);
  return 0;
}

/* socket exit: emit the created fd as the primary socket identity. */
SEC("tracepoint/syscalls/sys_exit_socket")
int on_sys_exit_socket(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SOCKET)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_SOCKET, ctx->ret);
}

/* socketpair enter: capture the family, socket type, protocol, and result array pointer. */
SEC("tracepoint/syscalls/sys_enter_socketpair")
int on_sys_enter_socketpair(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SOCKETPAIR)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_SOCKETPAIR);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.domain = (__s32)ctx->args[0];
  state.ev.sock_type = (__s32)ctx->args[1];
  state.ev.protocol = (__s32)ctx->args[2];
  state.peer_fd_ptr = (__u64)ctx->args[3];
  state.ev.transport = infer_network_transport(state.ev.domain, state.ev.sock_type);
  state.ev.direction = infer_network_direction(NETWORK_SOCKETPAIR);

  save_network_enter_state(NETWORK_SOCKETPAIR, &state, ev);
  return 0;
}

/* socketpair exit: read both returned descriptors from the caller-provided array. */
SEC("tracepoint/syscalls/sys_exit_socketpair")
int on_sys_exit_socketpair(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SOCKETPAIR)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_SOCKETPAIR, ctx->ret);
}

/* connect enter: capture fd and destination socket address intent. */
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
  state.ev.direction = infer_network_direction(NETWORK_CONNECT);

  const void* sockaddr_ptr = (const void*)ctx->args[1];
  __u32 sockaddr_len = (__u32)ctx->args[2];
  parse_sockaddr_user(sockaddr_ptr, sockaddr_len, &state.ev.remote);

  save_network_enter_state(NETWORK_CONNECT, &state, ev);
  return 0;
}

/* connect exit: keep the destination snapshot and attach the return code. */
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
  state.ev.direction = NETWORK_DIRECTION_UNKNOWN;

  const void* sockaddr_ptr = (const void*)ctx->args[1];
  __u32 sockaddr_len = (__u32)ctx->args[2];
  parse_sockaddr_user(sockaddr_ptr, sockaddr_len, &state.ev.local);

  save_network_enter_state(NETWORK_BIND, &state, ev);
  return 0;
}

/* bind exit: emit the local endpoint snapshot together with the return code. */
SEC("tracepoint/syscalls/sys_exit_bind")
int on_sys_exit_bind(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_BIND)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_BIND, ctx->ret);
}

/* accept enter: capture listening fd and peer sockaddr pointers for exit parsing. */
SEC("tracepoint/syscalls/sys_enter_accept")
int on_sys_enter_accept(struct trace_event_raw_sys_enter* ctx) {
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
  state.ev.direction = infer_network_direction(NETWORK_ACCEPT);
  state.sockaddr_ptr = (__u64)ctx->args[1];
  state.sockaddr_len_ptr = (__u64)ctx->args[2];

  save_network_enter_state(NETWORK_ACCEPT, &state, ev);
  return 0;
}

/* accept exit: finalize the inbound peer endpoint and the accepted fd. */
SEC("tracepoint/syscalls/sys_exit_accept")
int on_sys_exit_accept(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_ACCEPT)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_ACCEPT, ctx->ret);
}

/* accept4 enter: capture listening fd, peer sockaddr pointers, and accept flags. */
SEC("tracepoint/syscalls/sys_enter_accept4")
int on_sys_enter_accept4(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_ACCEPT4)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_ACCEPT4);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.flags = (__s32)ctx->args[3];
  state.ev.direction = infer_network_direction(NETWORK_ACCEPT4);
  state.sockaddr_ptr = (__u64)ctx->args[1];
  state.sockaddr_len_ptr = (__u64)ctx->args[2];

  save_network_enter_state(NETWORK_ACCEPT4, &state, ev);
  return 0;
}

/* accept4 exit: emit finalized accept4 event with peer sockaddr and ret outcome. */
SEC("tracepoint/syscalls/sys_exit_accept4")
int on_sys_exit_accept4(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_ACCEPT4)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_ACCEPT4, ctx->ret);
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
  state.ev.backlog = (__s32)ctx->args[1];

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

/* getsockname enter: capture fd and output buffer pointers for local endpoint recovery. */
SEC("tracepoint/syscalls/sys_enter_getsockname")
int on_sys_enter_getsockname(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_GETSOCKNAME)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_GETSOCKNAME);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.sockaddr_ptr = (__u64)ctx->args[1];
  state.sockaddr_len_ptr = (__u64)ctx->args[2];

  save_network_enter_state(NETWORK_GETSOCKNAME, &state, ev);
  return 0;
}

/* getsockname exit: read the kernel-written local endpoint from the caller buffer. */
SEC("tracepoint/syscalls/sys_exit_getsockname")
int on_sys_exit_getsockname(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_GETSOCKNAME)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_GETSOCKNAME, ctx->ret);
}

/* getpeername enter: capture fd and output buffer pointers for peer endpoint recovery. */
SEC("tracepoint/syscalls/sys_enter_getpeername")
int on_sys_enter_getpeername(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_GETPEERNAME)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_GETPEERNAME);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.sockaddr_ptr = (__u64)ctx->args[1];
  state.sockaddr_len_ptr = (__u64)ctx->args[2];

  save_network_enter_state(NETWORK_GETPEERNAME, &state, ev);
  return 0;
}

/* getpeername exit: read the kernel-written peer endpoint from the caller buffer. */
SEC("tracepoint/syscalls/sys_exit_getpeername")
int on_sys_exit_getpeername(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_GETPEERNAME)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_GETPEERNAME, ctx->ret);
}

/* setsockopt enter: capture fd and the option summary that will shape the socket behavior. */
SEC("tracepoint/syscalls/sys_enter_setsockopt")
int on_sys_enter_setsockopt(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SETSOCKOPT)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_SETSOCKOPT);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.opt_level = (__s32)ctx->args[1];
  state.ev.opt_name = (__s32)ctx->args[2];
  state.ev.opt_len = (__s32)ctx->args[4];
  state.optval_ptr = (__u64)ctx->args[3];
  copy_optval_prefix(state.ev.optval_prefix, (const void*)ctx->args[3], (__u32)ctx->args[4]);

  save_network_enter_state(NETWORK_SETSOCKOPT, &state, ev);
  return 0;
}

/* setsockopt exit: emit the option summary together with the syscall outcome. */
SEC("tracepoint/syscalls/sys_exit_setsockopt")
int on_sys_exit_setsockopt(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SETSOCKOPT)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_SETSOCKOPT, ctx->ret);
}

/* getsockopt enter: capture fd and the option buffer that will be filled on exit. */
SEC("tracepoint/syscalls/sys_enter_getsockopt")
int on_sys_enter_getsockopt(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_GETSOCKOPT)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_GETSOCKOPT);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.opt_level = (__s32)ctx->args[1];
  state.ev.opt_name = (__s32)ctx->args[2];
  state.optval_ptr = (__u64)ctx->args[3];
  state.optlen_ptr = (__u64)ctx->args[4];
  if (state.optlen_ptr != 0) {
    __u32 requested_len = 0;
    bpf_probe_read_user(&requested_len, sizeof(requested_len), (const void*)state.optlen_ptr);
    state.ev.opt_len = (__s32)requested_len;
  }

  save_network_enter_state(NETWORK_GETSOCKOPT, &state, ev);
  return 0;
}

/* getsockopt exit: refresh the option length and copy the returned value prefix. */
SEC("tracepoint/syscalls/sys_exit_getsockopt")
int on_sys_exit_getsockopt(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_GETSOCKOPT)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_GETSOCKOPT, ctx->ret);
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
  state.ev.flags = (__s32)ctx->args[3];
  state.ev.direction = infer_network_direction(NETWORK_SENDTO);
  state.ev.bytes_requested = (__u64)ctx->args[2];

  const void* sockaddr_ptr = (const void*)ctx->args[4];
  __u32 sockaddr_len = (__u32)ctx->args[5];
  parse_sockaddr_user(sockaddr_ptr, sockaddr_len, &state.ev.remote);

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

/* sendmsg enter: capture fd/flags, message vector lengths, and optional destination address. */
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int on_sys_enter_sendmsg(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SENDMSG)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_SENDMSG);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.flags = (__s32)ctx->args[2];
  state.ev.direction = infer_network_direction(NETWORK_SENDMSG);

  const struct msghdr_min* msg = (const struct msghdr_min*)ctx->args[1];
  if (msg) {
    struct msghdr_min hdr = {};
    if (bpf_probe_read_user(&hdr, sizeof(hdr), msg) == 0) {
      state.ev.bytes_requested = sum_iovec_lengths((const struct iovec_min*)hdr.msg_iov,
                                                  (__u64)hdr.msg_iovlen);
      if (hdr.msg_name && hdr.msg_namelen > 0) {
        parse_sockaddr_user((const void*)hdr.msg_name, hdr.msg_namelen, &state.ev.remote);
      }
    }
  }

  save_network_enter_state(NETWORK_SENDMSG, &state, ev);
  return 0;
}

/* sendmsg exit: emit finalized sendmsg event with ret outcome. */
SEC("tracepoint/syscalls/sys_exit_sendmsg")
int on_sys_exit_sendmsg(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SENDMSG)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_SENDMSG, ctx->ret);
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
  state.ev.flags = (__s32)ctx->args[3];
  state.ev.direction = infer_network_direction(NETWORK_RECVFROM);
  state.ev.bytes_requested = (__u64)ctx->args[2];
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

/* recvmsg enter: capture fd/flags, message vector lengths, and optional source address. */
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int on_sys_enter_recvmsg(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_RECVMSG)) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_RECVMSG);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.flags = (__s32)ctx->args[2];
  state.ev.direction = infer_network_direction(NETWORK_RECVMSG);

  const struct msghdr_min* msg = (const struct msghdr_min*)ctx->args[1];
  if (msg) {
    struct msghdr_min hdr = {};
    if (bpf_probe_read_user(&hdr, sizeof(hdr), msg) == 0) {
      state.ev.bytes_requested = sum_iovec_lengths((const struct iovec_min*)hdr.msg_iov,
                                                  (__u64)hdr.msg_iovlen);
      if (hdr.msg_name && hdr.msg_namelen > 0) {
        parse_sockaddr_user((const void*)hdr.msg_name, hdr.msg_namelen, &state.ev.remote);
      }
    }
  }

  save_network_enter_state(NETWORK_RECVMSG, &state, ev);
  return 0;
}

/* recvmsg exit: emit finalized recvmsg event with ret outcome. */
SEC("tracepoint/syscalls/sys_exit_recvmsg")
int on_sys_exit_recvmsg(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_RECVMSG)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_RECVMSG, ctx->ret);
}

/* read enter: capture fd and requested read size. */
SEC("tracepoint/syscalls/sys_enter_read")
int on_sys_enter_read(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_READ)) {
    return 0;
  }

  if (!is_socket_fd((__s32)ctx->args[0])) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_READ);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.direction = infer_network_direction(NETWORK_READ);
  state.ev.bytes_requested = (__u64)ctx->args[2];

  save_network_enter_state(NETWORK_READ, &state, ev);
  return 0;
}

/* read exit: emit finalized read event with transferred bytes. */
SEC("tracepoint/syscalls/sys_exit_read")
int on_sys_exit_read(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_READ)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_READ, ctx->ret);
}

/* write enter: capture fd and requested write size. */
SEC("tracepoint/syscalls/sys_enter_write")
int on_sys_enter_write(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_WRITE)) {
    return 0;
  }

  if (!is_socket_fd((__s32)ctx->args[0])) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_WRITE);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.direction = infer_network_direction(NETWORK_WRITE);
  state.ev.bytes_requested = (__u64)ctx->args[2];

  save_network_enter_state(NETWORK_WRITE, &state, ev);
  return 0;
}

/* write exit: emit finalized write event with transferred bytes. */
SEC("tracepoint/syscalls/sys_exit_write")
int on_sys_exit_write(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_WRITE)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_WRITE, ctx->ret);
}

/* readv enter: capture fd and requested iovec length. */
SEC("tracepoint/syscalls/sys_enter_readv")
int on_sys_enter_readv(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_READV)) {
    return 0;
  }

  if (!is_socket_fd((__s32)ctx->args[0])) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_READV);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.direction = infer_network_direction(NETWORK_READV);
  state.ev.bytes_requested = sum_iovec_lengths((const struct iovec_min*)ctx->args[1],
                                              (__u64)ctx->args[2]);

  save_network_enter_state(NETWORK_READV, &state, ev);
  return 0;
}

/* readv exit: emit finalized readv event with transferred bytes. */
SEC("tracepoint/syscalls/sys_exit_readv")
int on_sys_exit_readv(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_READV)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_READV, ctx->ret);
}

/* writev enter: capture fd and requested iovec length. */
SEC("tracepoint/syscalls/sys_enter_writev")
int on_sys_enter_writev(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_WRITEV)) {
    return 0;
  }

  if (!is_socket_fd((__s32)ctx->args[0])) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_WRITEV);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.direction = infer_network_direction(NETWORK_WRITEV);
  state.ev.bytes_requested = sum_iovec_lengths((const struct iovec_min*)ctx->args[1],
                                              (__u64)ctx->args[2]);

  save_network_enter_state(NETWORK_WRITEV, &state, ev);
  return 0;
}

/* writev exit: emit finalized writev event with transferred bytes. */
SEC("tracepoint/syscalls/sys_exit_writev")
int on_sys_exit_writev(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_WRITEV)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_WRITEV, ctx->ret);
}

/* sendmmsg enter: capture fd, message count, and requested vector lengths. */
SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int on_sys_enter_sendmmsg(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SENDMMSG)) {
    return 0;
  }

  if (!is_socket_fd((__s32)ctx->args[0])) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_SENDMMSG);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.flags = (__s32)ctx->args[3];
  state.ev.direction = infer_network_direction(NETWORK_SENDMMSG);
  state.mmsg_ptr = (__u64)ctx->args[1];
  state.mmsg_count = (__u64)ctx->args[2];
  state.ev.bytes_requested = sum_mmsghdr_lengths((const struct mmsghdr_min*)state.mmsg_ptr,
                                                 (__u32)state.mmsg_count);

  save_network_enter_state(NETWORK_SENDMMSG, &state, ev);
  return 0;
}

/* sendmmsg exit: emit finalized sendmmsg event with transferred bytes. */
SEC("tracepoint/syscalls/sys_exit_sendmmsg")
int on_sys_exit_sendmmsg(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_SENDMMSG)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_SENDMMSG, ctx->ret);
}

/* recvmmsg enter: capture fd, message count, and requested vector lengths. */
SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int on_sys_enter_recvmmsg(struct trace_event_raw_sys_enter* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_RECVMMSG)) {
    return 0;
  }

  if (!is_socket_fd((__s32)ctx->args[0])) {
    return 0;
  }

  struct network_event* ev = reserve_network_event(NETWORK_RECVMMSG);
  if (!ev) {
    return 0;
  }

  struct network_state_value state = {};
  state.ev = *ev;
  state.ev.fd = (__s32)ctx->args[0];
  state.ev.flags = (__s32)ctx->args[3];
  state.ev.direction = infer_network_direction(NETWORK_RECVMMSG);
  state.mmsg_ptr = (__u64)ctx->args[1];
  state.mmsg_count = (__u64)ctx->args[2];
  state.ev.bytes_requested = sum_mmsghdr_lengths((const struct mmsghdr_min*)state.mmsg_ptr,
                                                 (__u32)state.mmsg_count);

  save_network_enter_state(NETWORK_RECVMMSG, &state, ev);
  return 0;
}

/* recvmmsg exit: emit finalized recvmmsg event with transferred bytes. */
SEC("tracepoint/syscalls/sys_exit_recvmmsg")
int on_sys_exit_recvmmsg(struct trace_event_raw_sys_exit* ctx) {
  if (!is_event_allowed() || !is_network_probe_enabled(NETWORK_RECVMMSG)) {
    return 0;
  }

  return emit_network_exit_event(NETWORK_RECVMMSG, ctx->ret);
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
  state.ev.how = (__s32)ctx->args[1];

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
