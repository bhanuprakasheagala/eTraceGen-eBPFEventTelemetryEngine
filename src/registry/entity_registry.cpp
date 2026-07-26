/*
 * File Notes:
 * - Implements process entity tracking: identity, lineage, lifecycle, reuse.
 * - Owns its own /proc enrichment so the registry is the single authority for
 *   process context (superseding the enricher and the sink's ProcessInfoCache,
 *   which are consolidated onto this registry in a later stage).
 */

#include "registry/entity_registry.h"

#include <string>

#include "util/proc_util.h"

namespace event_logger {
namespace {

// Cap on retained entities; least-recently-seen entities are evicted past this.
constexpr size_t kMaxEntries = 8192;
// Minimum spacing between /proc start-time re-checks used for reuse detection.
constexpr uint64_t kIdentityCheckNs = 500ULL * 1000ULL * 1000ULL;  // 500 ms

/** Read the current start-time ticks for a tgid; 0 if unavailable. */
uint64_t ReadStartTimeTicks(uint32_t key) {
  return proc_util::ParseStartTimeTicks(
      proc_util::ReadTextFile("/proc/" + std::to_string(key) + "/stat"));
}

/** Copy fast-moving header identity fields onto an entity. */
void UpdateFast(ProcessEntity* e, const ActorIdentity& a, uint64_t now_ns) {
  e->pid = a.pid;
  e->tgid = a.tgid;
  e->ppid = a.ppid;
  e->uid = a.uid;
  e->gid = a.gid;
  if (a.comm[0] != '\0') {
    e->comm = a.comm;
  }
  e->last_seen_ns = now_ns;
}

/** Fill/refresh the /proc-derived rich fields for an entity. */
void RefreshRich(ProcessEntity* e, uint32_t key) {
  if (key == 0) {
    return;
  }
  const std::string pid_s = std::to_string(key);

  const std::string exe = proc_util::ReadProcSymlink("/proc/" + pid_s + "/exe");
  if (!exe.empty()) {
    e->exec_path = exe;
  }
  const std::string cwd = proc_util::ReadProcSymlink("/proc/" + pid_s + "/cwd");
  if (!cwd.empty()) {
    e->cwd = cwd;
  }
  const std::string cmd =
      proc_util::NormalizeCmdline(proc_util::ReadTextFile("/proc/" + pid_s + "/cmdline", true));
  if (!cmd.empty()) {
    e->cmdline = cmd;
  }
  if (e->comm.empty()) {
    std::string c = proc_util::ReadTextFile("/proc/" + pid_s + "/comm");
    proc_util::RStrip(&c);
    if (!c.empty()) {
      e->comm = c;
    }
  }
  if (e->parent_comm.empty() && e->ppid != 0) {
    std::string pc = proc_util::ReadTextFile("/proc/" + std::to_string(e->ppid) + "/comm");
    proc_util::RStrip(&pc);
    if (!pc.empty()) {
      e->parent_comm = pc;
    }
  }
  if (e->start_time_ticks == 0) {
    e->start_time_ticks = ReadStartTimeTicks(key);
  }
}

}  // namespace

bool EntityRegistry::IsReused(ProcessEntity* entity, uint32_t key, uint64_t now_ns) {
  // Without a known start time we cannot distinguish reuse; assume same process.
  if (entity->start_time_ticks == 0) {
    return false;
  }
  // Throttle /proc reads on the hot path.
  if (now_ns - entity->last_identity_check_ns < kIdentityCheckNs) {
    return false;
  }
  entity->last_identity_check_ns = now_ns;

  const uint64_t current = ReadStartTimeTicks(key);
  if (current == 0) {
    // Process gone/unreadable: don't churn ids; an exit event will retire it.
    return false;
  }
  return current != entity->start_time_ticks;
}

uint64_t EntityRegistry::CreateProcess(uint32_t key, const ActorIdentity& actor, uint64_t now_ns) {
  ProcessEntity e;
  e.id = next_id_++;
  UpdateFast(&e, actor, now_ns);
  e.first_seen_ns = now_ns;
  e.last_identity_check_ns = now_ns;  // identity is fresh at creation
  RefreshRich(&e, key);

  const uint64_t id = e.id;
  processes_by_id_[id] = std::move(e);
  tgid_index_[key] = id;
  EvictIfNeeded();
  return id;
}

uint64_t EntityRegistry::ResolveProcess(const ActorIdentity& actor, uint64_t now_ns,
                                        bool refresh_rich) {
  const uint32_t key = actor.tgid != 0 ? actor.tgid : actor.pid;
  if (key == 0) {
    return 0;
  }

  auto it = tgid_index_.find(key);
  if (it != tgid_index_.end()) {
    const uint64_t id = it->second;
    auto ent = processes_by_id_.find(id);
    if (ent != processes_by_id_.end()) {
      ProcessEntity& e = ent->second;
      if (!IsReused(&e, key, now_ns)) {
        UpdateFast(&e, actor, now_ns);
        if (refresh_rich) {
          RefreshRich(&e, key);
        }
        return id;
      }
      // Reuse detected: retire the old instance (also clears its index entry).
      MarkExited(id, now_ns, 0);
    } else {
      tgid_index_.erase(it);  // dangling index entry
    }
  }

  return CreateProcess(key, actor, now_ns);
}

uint64_t EntityRegistry::ResolveChild(uint32_t child_pid, uint64_t parent_id,
                                      const ActorIdentity& parent, uint64_t now_ns) {
  if (child_pid == 0) {
    return 0;
  }

  ActorIdentity child{};
  child.pid = child_pid;
  child.tgid = child_pid;  // a new task is treated as its own thread-group leader
  child.ppid = parent.tgid != 0 ? parent.tgid : parent.pid;

  const uint64_t id = ResolveProcess(child, now_ns, /*refresh_rich=*/true);
  auto it = processes_by_id_.find(id);
  if (it != processes_by_id_.end() && it->second.parent_id == 0) {
    it->second.parent_id = parent_id;
  }
  return id;
}

void EntityRegistry::MarkExited(uint64_t id, uint64_t now_ns, int64_t exit_code) {
  auto it = processes_by_id_.find(id);
  if (it == processes_by_id_.end()) {
    return;
  }
  it->second.exited = true;
  it->second.exit_ns = now_ns;
  it->second.exit_code = exit_code;

  const uint32_t key = it->second.tgid != 0 ? it->second.tgid : it->second.pid;
  RetireIndex(key, id);
}

void EntityRegistry::RetireIndex(uint32_t key, uint64_t id) {
  auto it = tgid_index_.find(key);
  if (it != tgid_index_.end() && it->second == id) {
    tgid_index_.erase(it);
  }
}

void EntityRegistry::EvictIfNeeded() {
  if (processes_by_id_.size() <= kMaxEntries) {
    return;
  }

  // Evict the least-recently-seen entity (exited ones naturally fall here).
  auto victim = processes_by_id_.end();
  for (auto it = processes_by_id_.begin(); it != processes_by_id_.end(); ++it) {
    if (victim == processes_by_id_.end() ||
        it->second.last_seen_ns < victim->second.last_seen_ns) {
      victim = it;
    }
  }
  if (victim != processes_by_id_.end()) {
    const uint32_t key = victim->second.tgid != 0 ? victim->second.tgid : victim->second.pid;
    RetireIndex(key, victim->second.id);
    processes_by_id_.erase(victim);
  }
}

void EntityRegistry::Ingest(CanonicalEvent& ev) {
  const uint64_t now_ns = ev.ts_ns;
  const bool is_exec = ev.action == CanonicalAction::kProcessExeced;

  const uint64_t subject_id = ResolveProcess(ev.actor, now_ns, is_exec);
  ev.subject.kind = EntityKind::kProcess;
  ev.subject.id = subject_id;

  if (ev.action == CanonicalAction::kProcessExited) {
    MarkExited(subject_id, now_ns, ev.outcome);
  } else if (ev.action == CanonicalAction::kProcessStarted && ev.object.child_pid != 0) {
    const uint64_t child_id = ResolveChild(ev.object.child_pid, subject_id, ev.actor, now_ns);
    ev.object_ref.kind = EntityKind::kProcess;
    ev.object_ref.id = child_id;
  }

  // Use the kernel-captured exec path as an authoritative fallback when /proc
  // enrichment left the entity's exec path empty (e.g. short-lived processes).
  if (!ev.exec_path_hint.empty()) {
    auto it = processes_by_id_.find(subject_id);
    if (it != processes_by_id_.end() && it->second.exec_path.empty()) {
      it->second.exec_path = ev.exec_path_hint;
    }
  }

  // Attach the resolved actor entity for downstream consumers (the sink reads
  // process context from here). Looked up last so it reflects post-mutation
  // state; may be null if the subject was unresolved or evicted.
  ev.subject_process = FindProcess(subject_id);
}

const ProcessEntity* EntityRegistry::FindProcess(uint64_t id) const {
  auto it = processes_by_id_.find(id);
  return it == processes_by_id_.end() ? nullptr : &it->second;
}

}  // namespace event_logger
