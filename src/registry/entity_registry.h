#ifndef EVENT_LOGGER_REGISTRY_ENTITY_REGISTRY_H
#define EVENT_LOGGER_REGISTRY_ENTITY_REGISTRY_H

/*
 * File Notes:
 * - The stateful knowledge core: turns the flat canonical-event stream into
 *   persistent system entities with stable identity, lineage, and lifecycle.
 * - Stage 2 scope: process entities only. File and socket entities follow in a
 *   later stage; the API is shaped to accommodate them.
 * - Single-threaded: driven from the collector callback thread, like the rest of
 *   the pipeline. Not internally synchronized.
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "model/canonical_event.h"

namespace event_logger {

/**
 * @brief Persistent state for a single observed process instance.
 *
 * @note Identity is the pair (tgid, start_time_ticks): reusing a tgid after the
 *       original process exits produces a *new* entity with a new `id`.
 */
struct ProcessEntity {
  uint64_t id = 0;  // stable registry id (0 = none)

  uint32_t pid = 0;
  uint32_t tgid = 0;
  uint32_t ppid = 0;
  uint32_t uid = 0;
  uint32_t gid = 0;
  std::string comm;
  std::string exec_path;
  std::string cmdline;
  std::string cwd;
  std::string parent_comm;
  uint64_t start_time_ticks = 0;

  uint64_t parent_id = 0;      // resolved parent entity id (0 if unknown)
  uint64_t first_seen_ns = 0;  // event ts when first observed
  uint64_t last_seen_ns = 0;   // event ts of most recent activity

  bool exited = false;
  uint64_t exit_ns = 0;
  int64_t exit_code = 0;

  // Reserved for the M3 startup-baseline work; not meaningfully populated yet.
  bool observed_after_startup = false;

  // Internal: throttles /proc identity re-checks for reuse detection.
  uint64_t last_identity_check_ns = 0;
};

/**
 * @brief Registry of live/known system entities, updated from canonical events.
 */
class EntityRegistry {
 public:
  /**
   * @brief Resolve and update the entities referenced by a canonical event.
   *
   * Assigns stable ids to `ev.subject` (the acting process) and, where
   * applicable, `ev.object_ref` (currently only the child process on a
   * process-start event). Mutates registry state (creating, refreshing, or
   * retiring entities) as a side effect.
   *
   * @param ev Canonical event; its EntityRefs are filled in place.
   */
  void Ingest(CanonicalEvent& ev);

  /**
   * @brief Look up a process entity by stable id.
   * @return Pointer to the entity, or nullptr if unknown. Valid until the next
   *         mutating Ingest call.
   */
  const ProcessEntity* FindProcess(uint64_t id) const;

  /** @brief Number of process entities currently tracked (live + retained). */
  size_t ProcessCount() const { return processes_by_id_.size(); }

 private:
  uint64_t ResolveProcess(const ActorIdentity& actor, uint64_t now_ns, bool refresh_rich);
  uint64_t ResolveChild(uint32_t child_pid, uint64_t parent_id, const ActorIdentity& parent,
                        uint64_t now_ns);
  uint64_t CreateProcess(uint32_t key, const ActorIdentity& actor, uint64_t now_ns);
  void MarkExited(uint64_t id, uint64_t now_ns, int64_t exit_code);
  bool IsReused(ProcessEntity* entity, uint32_t key, uint64_t now_ns);
  void RetireIndex(uint32_t key, uint64_t id);
  void EvictIfNeeded();

  std::unordered_map<uint64_t, ProcessEntity> processes_by_id_;  // id -> entity
  std::unordered_map<uint32_t, uint64_t> tgid_index_;            // live tgid -> id
  uint64_t next_id_ = 1;
};

}  // namespace event_logger

#endif
