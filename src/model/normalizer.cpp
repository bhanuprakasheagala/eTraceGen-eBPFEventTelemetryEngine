/*
 * File Notes:
 * - Implements structural raw-to-canonical mapping for each event family.
 * - Keeps the mapping centralized so the canonical vocabulary has exactly one
 *   authoritative translation from kernel event kinds.
 */

#include "model/normalizer.h"

#include <cstring>
#include <type_traits>

namespace event_logger {
namespace {

/** Copy the raw header identity into the normalized actor block. */
ActorIdentity MakeActor(const event_header& hdr) {
  ActorIdentity actor;
  actor.pid = hdr.pid;
  actor.tgid = hdr.tgid;
  actor.ppid = hdr.ppid;
  actor.uid = hdr.uid;
  actor.gid = hdr.gid;
  std::memcpy(actor.comm, hdr.comm, sizeof(actor.comm));
  actor.comm[sizeof(actor.comm) - 1] = '\0';
  return actor;
}

/** Map a process event kind onto its canonical action. */
CanonicalAction ProcessAction(uint32_t kind) {
  switch (kind) {
    case PROCESS_EXEC:
      return CanonicalAction::kProcessExeced;
    case PROCESS_EXIT:
      return CanonicalAction::kProcessExited;
    case PROCESS_FORK:
    case PROCESS_CLONE:
    case PROCESS_CLONE3:
    case PROCESS_VFORK:
      return CanonicalAction::kProcessStarted;
    default:
      return CanonicalAction::kUnknown;
  }
}

/** Map a file event kind onto its canonical action. */
CanonicalAction FileAction(uint32_t kind) {
  switch (kind) {
    case FILE_OPENAT:
      return CanonicalAction::kFileOpened;
    case FILE_UNLINKAT:
      return CanonicalAction::kFileDeleted;
    case FILE_RENAMEAT2:
      return CanonicalAction::kFileRenamed;
    default:
      return CanonicalAction::kUnknown;
  }
}

/** Map a network event kind onto its canonical action. */
CanonicalAction NetworkAction(uint32_t kind) {
  switch (kind) {
    case NETWORK_SOCKET:
    case NETWORK_SOCKETPAIR:
      return CanonicalAction::kSocketCreated;
    case NETWORK_CONNECT:
      return CanonicalAction::kSocketConnected;
    case NETWORK_ACCEPT:
    case NETWORK_ACCEPT4:
      return CanonicalAction::kSocketAccepted;
    case NETWORK_BIND:
      return CanonicalAction::kSocketBound;
    case NETWORK_LISTEN:
      return CanonicalAction::kSocketListened;
    case NETWORK_CLOSE:
      return CanonicalAction::kSocketClosed;
    case NETWORK_SENDTO:
    case NETWORK_SENDMSG:
    case NETWORK_WRITE:
    case NETWORK_WRITEV:
    case NETWORK_SENDMMSG:
      return CanonicalAction::kSocketSent;
    case NETWORK_RECVFROM:
    case NETWORK_RECVMSG:
    case NETWORK_READ:
    case NETWORK_READV:
    case NETWORK_RECVMMSG:
      return CanonicalAction::kSocketReceived;
    case NETWORK_SHUTDOWN:
      return CanonicalAction::kSocketShutdown;
    default:
      // getsockname/getpeername/setsockopt/getsockopt and others carry no
      // lifecycle meaning at this layer yet.
      return CanonicalAction::kUnknown;
  }
}

}  // namespace

CanonicalEvent Normalizer::Normalize(const EventVariant& raw) const {
  CanonicalEvent out;
  out.raw = &raw;

  std::visit(
      [&](const auto& ev) {
        using T = std::decay_t<decltype(ev)>;

        out.ts_ns = ev.hdr.ts_ns;
        out.actor = MakeActor(ev.hdr);
        out.subject.kind = EntityKind::kProcess;  // the actor is always a process

        if constexpr (std::is_same_v<T, process_event>) {
          out.domain = CanonicalDomain::kProcess;
          out.action = ProcessAction(ev.kind);
          // Kernel captures the exec path at the exec tracepoint; surface it so
          // the registry can use it when /proc enrichment is unavailable.
          if (ev.exec_path[0] != '\0') {
            out.exec_path_hint = ev.exec_path;
          }
          if (out.action == CanonicalAction::kProcessStarted) {
            out.object_ref.kind = EntityKind::kProcess;
            out.object.child_pid = ev.child_pid;
          } else if (out.action == CanonicalAction::kProcessExited) {
            out.outcome = static_cast<int64_t>(ev.exit_code);
          }
        } else if constexpr (std::is_same_v<T, file_event>) {
          out.domain = CanonicalDomain::kFile;
          out.action = FileAction(ev.kind);
          out.object_ref.kind = EntityKind::kFile;
          out.object.path = ev.path_a;
          if (ev.kind == FILE_RENAMEAT2) {
            out.object.path_to = ev.path_b;
          }
          out.outcome = static_cast<int64_t>(ev.ret);
          out.outcome_is_error = ev.ret < 0;
        } else if constexpr (std::is_same_v<T, syscall_event>) {
          out.domain = CanonicalDomain::kSyscall;
          out.action = CanonicalAction::kSyscallInvoked;
          out.outcome = static_cast<int64_t>(ev.ret);
          out.outcome_is_error = ev.ret < 0;
        } else if constexpr (std::is_same_v<T, network_event>) {
          out.domain = CanonicalDomain::kNetwork;
          out.action = NetworkAction(ev.kind);
          out.object_ref.kind = EntityKind::kSocket;
          out.object.fd = ev.fd;
          out.object.flow_id = ev.flow_id;
          out.outcome = static_cast<int64_t>(ev.ret);
          out.outcome_is_error = ev.ret < 0;
        }
      },
      raw);

  return out;
}

}  // namespace event_logger
