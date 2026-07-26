#ifndef EVENT_LOGGER_MODEL_CANONICAL_EVENT_H
#define EVENT_LOGGER_MODEL_CANONICAL_EVENT_H

/*
 * File Notes:
 * - Defines the kernel-agnostic canonical event model: the first "knowledge"
 *   representation the pipeline produces above the raw wire ABI.
 * - Downstream layers (registry, correlation, semantic) consume CanonicalEvent
 *   and never branch on raw kernel struct shapes. The raw event is retained by
 *   pointer so a diagnostic sink can still emit the full substrate.
 */

#include <cstdint>
#include <string>

#include "decoder/decoder.h"  // EventVariant, event_schema types

namespace event_logger {

// Defined in registry/entity_registry.h; referenced here only by pointer so the
// canonical model has no build dependency on the registry.
struct ProcessEntity;

/**
 * @brief Kernel-agnostic classification of the entity an event concerns.
 */
enum class EntityKind : uint8_t {
  kUnknown = 0,
  kProcess = 1,
  kFile = 2,
  kSocket = 3,
};

/**
 * @brief Stable reference to a system entity.
 *
 * @note `id` is assigned by the EntityRegistry. An id of 0 means the reference
 *       has not been resolved yet (the Normalizer leaves it unresolved).
 */
struct EntityRef {
  EntityKind kind = EntityKind::kUnknown;
  uint64_t id = 0;
};

/**
 * @brief High-level, kernel-agnostic domain of a canonical event.
 */
enum class CanonicalDomain : uint8_t {
  kProcess = 0,
  kFile = 1,
  kSyscall = 2,
  kNetwork = 3,
};

/**
 * @brief Normalized action vocabulary.
 *
 * Intentionally small at first; it grows as the semantic layer matures. Many
 * raw kernel event kinds collapse onto one stable action so downstream layers
 * never depend on kernel specifics.
 */
enum class CanonicalAction : uint16_t {
  kUnknown = 0,

  // Process lifecycle.
  kProcessStarted,  // fork / clone / clone3 / vfork (a new task appeared)
  kProcessExeced,   // exec (process image replaced)
  kProcessExited,   // exit

  // File operations (semantic create/modify inference is a later layer).
  kFileOpened,      // openat
  kFileDeleted,     // unlinkat
  kFileRenamed,     // renameat2

  // Generic syscall (kept coarse until the semantic layer refines it).
  kSyscallInvoked,

  // Socket lifecycle / IO (populated once network facts are enabled).
  kSocketCreated,
  kSocketConnected,
  kSocketAccepted,
  kSocketBound,
  kSocketListened,
  kSocketClosed,
  kSocketSent,
  kSocketReceived,
  kSocketShutdown,
};

/**
 * @brief Normalized actor identity carried on every canonical event.
 *
 * Sourced from the raw event header so downstream layers never read raw kernel
 * structs to learn who acted. Fixed-size `comm` avoids per-event allocation on
 * the hot path.
 */
struct ActorIdentity {
  uint32_t pid = 0;
  uint32_t tgid = 0;
  uint32_t ppid = 0;
  uint32_t uid = 0;
  uint32_t gid = 0;
  char comm[EVENT_LOGGER_COMM_LEN] = {};
};

/**
 * @brief Descriptor of the object an action affected, when applicable.
 *
 * Only the fields relevant to the resolved object kind are populated.
 */
struct ObjectDescriptor {
  // File object.
  std::string path;      // primary path (raw path_a)
  std::string path_to;   // rename destination (raw path_b)

  // Socket object.
  int32_t fd = -1;
  uint64_t flow_id = 0;

  // Process object (e.g. the child created by fork/clone).
  uint32_t child_pid = 0;
};

/**
 * @brief The normalized event consumed by the knowledge layers.
 */
struct CanonicalEvent {
  uint64_t ts_ns = 0;
  CanonicalDomain domain = CanonicalDomain::kProcess;
  CanonicalAction action = CanonicalAction::kUnknown;

  ActorIdentity actor;
  ObjectDescriptor object;

  EntityRef subject;     // the actor entity (resolved by the registry)
  EntityRef object_ref;  // the affected entity, if any (resolved by the registry)

  int64_t outcome = 0;         // syscall ret / exit code
  bool outcome_is_error = false;

  /**
   * @brief Kernel-provided exec path captured at the exec tracepoint.
   *
   * @note Empty for non-exec events. The registry uses it as an authoritative
   *       fallback for a process's exec path when /proc enrichment fails (e.g.
   *       short-lived processes gone before the ring buffer is drained).
   */
  std::string exec_path_hint;

  /**
   * @brief Non-owning pointer to the raw substrate event.
   *
   * @note Valid only for the duration of the pipeline callback. Retained so a
   *       raw/diagnostic sink can emit full fidelity; the knowledge layers must
   *       not store it beyond the current event.
   */
  const EventVariant* raw = nullptr;

  /**
   * @brief Resolved process entity for the actor, attached by the EntityRegistry.
   *
   * @note Non-owning; points into registry state and is valid only for the
   *       duration of the current pipeline callback (until the next Ingest).
   *       May be null if the actor could not be resolved. Downstream consumers
   *       (e.g. the sink) read process context from here — the registry is the
   *       single source of process truth.
   */
  const ProcessEntity* subject_process = nullptr;
};

}  // namespace event_logger

#endif
