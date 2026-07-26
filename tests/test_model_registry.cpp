/*
 * File Notes:
 * - Unit tests for the canonical Normalizer and the EntityRegistry.
 * - Covers the genuinely tricky stateful logic: identity stability, exit-based
 *   reuse, lineage, distinct entities, and bounded eviction.
 * - Tests avoid depending on /proc *content* (fake pids), so they are
 *   deterministic on any host; they exercise the state machine, not enrichment.
 */

#include <cstdio>

#include "decoder/decoder.h"
#include "model/canonical_event.h"
#include "model/normalizer.h"
#include "registry/entity_registry.h"

namespace {

int g_failures = 0;

void Check(bool condition, const char* name) {
  if (condition) {
    std::printf("[pass] %s\n", name);
  } else {
    std::printf("[FAIL] %s\n", name);
    ++g_failures;
  }
}

using namespace event_logger;

// ---- Normalizer tests -------------------------------------------------------

void TestNormalizeProcessExec() {
  process_event pe{};
  pe.hdr.type = EVENT_TYPE_PROCESS;
  pe.hdr.ts_ns = 42;
  pe.hdr.pid = 1000;
  pe.hdr.tgid = 1000;
  pe.kind = PROCESS_EXEC;

  const EventVariant ev = pe;
  const CanonicalEvent c = Normalizer{}.Normalize(ev);

  Check(c.domain == CanonicalDomain::kProcess, "exec -> domain process");
  Check(c.action == CanonicalAction::kProcessExeced, "exec -> action ProcessExeced");
  Check(c.actor.tgid == 1000, "exec -> actor tgid preserved");
  Check(c.ts_ns == 42, "exec -> timestamp preserved");
  Check(c.raw == &ev, "exec -> raw points at source");
  Check(c.subject.kind == EntityKind::kProcess, "exec -> subject is process");
}

void TestNormalizeProcessForkChild() {
  process_event pe{};
  pe.hdr.type = EVENT_TYPE_PROCESS;
  pe.hdr.tgid = 1000;
  pe.kind = PROCESS_FORK;
  pe.child_pid = 2000;

  const EventVariant ev = pe;
  const CanonicalEvent c = Normalizer{}.Normalize(ev);

  Check(c.action == CanonicalAction::kProcessStarted, "fork -> action ProcessStarted");
  Check(c.object.child_pid == 2000, "fork -> object child_pid captured");
  Check(c.object_ref.kind == EntityKind::kProcess, "fork -> object is process");
}

void TestNormalizeFileOpen() {
  file_event fe{};
  fe.hdr.type = EVENT_TYPE_FILE;
  fe.hdr.tgid = 1000;
  fe.kind = FILE_OPENAT;
  fe.ret = -2;  // e.g. -ENOENT
  std::snprintf(fe.path_a, sizeof(fe.path_a), "%s", "/etc/passwd");

  const EventVariant ev = fe;
  const CanonicalEvent c = Normalizer{}.Normalize(ev);

  Check(c.domain == CanonicalDomain::kFile, "open -> domain file");
  Check(c.action == CanonicalAction::kFileOpened, "open -> action FileOpened");
  Check(c.object.path == "/etc/passwd", "open -> object path captured");
  Check(c.outcome == -2, "open -> outcome carries ret");
  Check(c.outcome_is_error, "open -> negative ret flagged as error");
}

void TestNormalizeNetworkConnect() {
  network_event ne{};
  ne.hdr.type = EVENT_TYPE_NETWORK;
  ne.hdr.tgid = 1000;
  ne.kind = NETWORK_CONNECT;
  ne.fd = 7;
  ne.flow_id = 0xABCD;

  const EventVariant ev = ne;
  const CanonicalEvent c = Normalizer{}.Normalize(ev);

  Check(c.domain == CanonicalDomain::kNetwork, "connect -> domain network");
  Check(c.action == CanonicalAction::kSocketConnected, "connect -> action SocketConnected");
  Check(c.object.fd == 7, "connect -> object fd captured");
  Check(c.object.flow_id == 0xABCD, "connect -> object flow_id captured");
}

// ---- Registry helpers -------------------------------------------------------

CanonicalEvent MakeProcessEvent(uint32_t tgid, CanonicalAction action, uint64_t ts,
                                uint32_t child_pid = 0) {
  CanonicalEvent c;
  c.ts_ns = ts;
  c.domain = CanonicalDomain::kProcess;
  c.action = action;
  c.actor.pid = tgid;
  c.actor.tgid = tgid;
  c.subject.kind = EntityKind::kProcess;
  if (action == CanonicalAction::kProcessStarted) {
    c.object.child_pid = child_pid;
    c.object_ref.kind = EntityKind::kProcess;
  }
  return c;
}

// ---- Registry tests ---------------------------------------------------------

void TestRegistryStableIdentity() {
  EntityRegistry reg;
  CanonicalEvent a = MakeProcessEvent(100, CanonicalAction::kProcessExeced, 1);
  CanonicalEvent b = MakeProcessEvent(100, CanonicalAction::kUnknown, 2);
  reg.Ingest(a);
  reg.Ingest(b);
  Check(a.subject.id != 0, "registry assigns non-zero id");
  Check(a.subject.id == b.subject.id, "same tgid -> same entity id");
}

void TestRegistryDistinctTgids() {
  EntityRegistry reg;
  CanonicalEvent a = MakeProcessEvent(100, CanonicalAction::kProcessExeced, 1);
  CanonicalEvent b = MakeProcessEvent(101, CanonicalAction::kProcessExeced, 2);
  reg.Ingest(a);
  reg.Ingest(b);
  Check(a.subject.id != b.subject.id, "distinct tgids -> distinct ids");
}

void TestRegistryExitReuse() {
  EntityRegistry reg;
  CanonicalEvent first = MakeProcessEvent(100, CanonicalAction::kProcessExeced, 1);
  reg.Ingest(first);
  const uint64_t first_id = first.subject.id;

  CanonicalEvent exit = MakeProcessEvent(100, CanonicalAction::kProcessExited, 2);
  reg.Ingest(exit);

  // A new process reusing tgid 100 after exit must get a fresh entity id.
  CanonicalEvent reused = MakeProcessEvent(100, CanonicalAction::kProcessExeced, 3);
  reg.Ingest(reused);
  Check(reused.subject.id != first_id, "tgid reuse after exit -> new entity id");
}

void TestRegistryLineage() {
  EntityRegistry reg;
  CanonicalEvent fork = MakeProcessEvent(100, CanonicalAction::kProcessStarted, 1, /*child=*/200);
  reg.Ingest(fork);

  Check(fork.object_ref.id != 0, "fork -> child entity resolved");
  Check(fork.object_ref.id != fork.subject.id, "child id differs from parent id");

  const ProcessEntity* child = reg.FindProcess(fork.object_ref.id);
  Check(child != nullptr, "child entity exists in registry");
  Check(child != nullptr && child->parent_id == fork.subject.id, "child.parent_id links to parent");
}

void TestRegistryEvictionBounded() {
  EntityRegistry reg;
  // Exceed the internal cap (8192) and confirm the registry stays bounded.
  for (uint32_t i = 1; i <= 9000; ++i) {
    CanonicalEvent e = MakeProcessEvent(i, CanonicalAction::kProcessExeced, i);
    reg.Ingest(e);
  }
  Check(reg.ProcessCount() <= 8192, "registry evicts to stay within cap");
}

}  // namespace

int main() {
  TestNormalizeProcessExec();
  TestNormalizeProcessForkChild();
  TestNormalizeFileOpen();
  TestNormalizeNetworkConnect();

  TestRegistryStableIdentity();
  TestRegistryDistinctTgids();
  TestRegistryExitReuse();
  TestRegistryLineage();
  TestRegistryEvictionBounded();

  if (g_failures != 0) {
    std::printf("test_model_registry: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("test_model_registry: OK\n");
  return 0;
}
