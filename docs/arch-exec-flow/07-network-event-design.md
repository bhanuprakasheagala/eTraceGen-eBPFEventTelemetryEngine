# Network Event Design

This document defines the socket-first network phase for eTraceGen.
DNS, HTTP, and HTTPS remain later layers built on top of the socket foundation.

The target use case is a malware-analysis lab running controlled dynamic analysis.
We want strong attribution, enough socket detail to explain behavior, and bounded
capture that stays safe for Linux kernels and portable across distributions.

## 1. Why Socket First
Network telemetry becomes much easier to trust once the socket layer is stable.
Socket events give us:
- process attribution
- transport identity
- local and remote endpoint context
- lifecycle ordering
- a durable flow anchor for later DNS/HTTP/TLS parsing

That means the socket layer is the cheapest place to get high-value signal and the
best place to avoid rework later.

## 2. Phase 1 Scope
### In scope now
Socket control plane:
- `socket`
- `socketpair`
- `bind`
- `connect`
- `listen`
- `accept`
- `accept4`
- `getsockname`
- `getpeername`
- `setsockopt`
- `getsockopt`
- `shutdown`
- `close`

Socket data plane:
- `sendto`
- `recvfrom`
- `sendmsg`
- `recvmsg`
- `read`
- `write`
- `readv`
- `writev`
- `sendmmsg`
- `recvmmsg`

### Out of scope for this phase
- DNS request/response parsing
- HTTP request/response parsing
- HTTPS/TLS payload interpretation
- full TCP stream reassembly in kernel
- browser-specific metadata such as `webkitURL`

## 3. Socket-First Event Taxonomy
We do not need a top-level `type` field in the final network output.
The record is already known to be network telemetry.

Instead, every record should carry a network subtype such as:
- `socket_create`
- `socketpair`
- `bind`
- `connect`
- `listen`
- `accept`
- `accept4`
- `getsockname`
- `getpeername`
- `setsockopt`
- `getsockopt`
- `shutdown`
- `close`
- `sendto`
- `recvfrom`
- `sendmsg`
- `recvmsg`
- `read`
- `write`
- `readv`
- `writev`
- `sendmmsg`
- `recvmmsg`

These subtypes let us keep the output readable and let downstream tooling reason
about behavior without guessing from raw syscall names.

## 4. Layer Diagram
```text
+-------------------------+
| Process attribution     |
| pid/tgid/ppid/uid/gid   |
+------------+------------+
             |
             v
+-------------------------+
| Socket control plane    |
| socket, bind, connect,  |
| listen, accept, close   |
+------------+------------+
             |
             v
+-------------------------+
| Socket data plane       |
| send/recv/read/write    |
+------------+------------+
             |
             v
+-------------------------+
| Later protocol layers   |
| DNS, HTTP, HTTPS/TLS    |
+------------+------------+
             |
             v
+-------------------------+
| Userspace enrichment    |
| process_info, flow ID,  |
| normalization, JSON     |
+-------------------------+
```

## 5. Common Network Envelope
Every socket record should carry the same envelope before subtype-specific fields.

Suggested envelope fields:
- `pid`
- `tgid`
- `ppid`
- `uid`
- `gid`
- `comm`
- `timestamp`
- `event_name`
- `direction` (`inbound`, `outbound`, `unknown`)
- `transport` (`tcp`, `udp`, `unix`, `raw`, `unknown`)
- `family` (`ipv4`, `ipv6`, `unix`, `unknown`)
- `fd`
- `ret`
- `flow_id`
- `socket_id` when available
- `bytes_total`
- `bytes_captured`
- `bytes_truncated`
- `local endpoint`
- `remote endpoint`

The envelope should be compact, stable, and present on every socket record.

## 6. Flow Identity Strategy
`pid + fd` is useful, but not durable enough on its own.
We need an identity that survives repeated reads/writes, accept handoffs, and later
DNS/HTTP correlation.

### Preferred identity model
1. Use a stable kernel-visible socket identity when available.
2. If that is not available on a given kernel, synthesize a flow ID in userspace.
3. Keep `pid/tgid + fd` as supporting context, not the primary identity.

### Fallback flow ID inputs
A synthetic flow ID can be built from:
- process identity
- file descriptor
- socket family and transport
- local endpoint
- remote endpoint
- birth timestamp
- direction
- subtype

This keeps correlation stable even on kernels that do not expose a convenient socket cookie.

## 7. Socket Event Details

### 7.1 `socket_create`
Capture:
- family/domain
- socket type
- protocol number
- return code
- resulting file descriptor when available

Why it matters:
- shows the transport intent before any network I/O happens
- lets us distinguish TCP, UDP, UNIX, and raw socket creation

### 7.2 `socketpair`
Capture:
- family/domain
- socket type
- protocol number
- both returned file descriptors
- return code

Why it matters:
- common in local IPC and process handoff patterns

### 7.3 `bind`
Capture:
- local address family
- local IP or UNIX path
- local port
- bind flags when visible
- return code

Why it matters:
- tells us when a process starts listening or exposes a service

### 7.4 `connect`
Capture:
- remote address family
- remote IP or UNIX peer
- remote port
- return code
- retry/failure behavior when visible through repeated attempts

Why it matters:
- one of the highest-value outbound behavior signals for malware analysis

### 7.5 `listen`
Capture:
- listening file descriptor
- backlog
- return code

Why it matters:
- marks server-like behavior and inbound readiness

### 7.6 `accept` and `accept4`
Capture:
- listening fd
- accepted fd
- peer address
- accepted socket family and transport
- accept flags for `accept4`
- return code

Why it matters:
- shows inbound session establishment and peer attribution

### 7.7 `getsockname` and `getpeername`
Capture:
- resolved local or peer endpoint
- socket family
- return code

Why it matters:
- helps recover endpoint identity after the socket is already in use

### 7.8 `setsockopt` and `getsockopt`
Capture:
- option level
- option name
- option length
- option value summary or classification
- return code

Why it matters:
- explains keepalive, reuse, timeout, buffer, and proxy-like behavior

### 7.9 `shutdown`
Capture:
- shutdown mode
- fd
- return code

Why it matters:
- tells us whether the process stopped reading, writing, or both

### 7.10 `close`
Capture:
- fd
- return code
- whether this close ends the observed flow

Why it matters:
- marks end-of-life for socket correlation and flow summary

## 8. Socket Data-Plane Details
Data-plane events are not protocol events yet.
They are bounded transport records that tell us what bytes moved and how much.

Capture for each data-plane event:
- fd
- return code
- bytes requested
- bytes actually transferred
- bytes captured in prefix form
- truncation flag
- address family when available
- local endpoint when available
- remote endpoint when available
- flow identity
- process attribution

We should capture a small bounded prefix of the payload when that helps with
behavioral classification, but we should not try to rebuild the whole stream in kernel.

## 9. Socket State and Correlation
Socket event ordering matters.
We need a simple state machine so the output makes sense during replay.

### Client-style flow
```text
process -> socket_create -> connect -> send/recv -> shutdown -> close
```

### Server-style flow
```text
process -> socket_create -> bind -> listen -> accept -> send/recv -> shutdown -> close
```

### UNIX socket flow
```text
process -> socket_create -> bind/connect -> send/recv -> close
```

The state machine should support:
- connect-before-send client paths
- bind/listen/accept server paths
- fd reuse and close/reopen patterns
- partial visibility when some syscalls are missing

## 10. UNIX Socket Representation
For UNIX domain sockets, endpoint fields must support:
- pathname sockets
- abstract sockets
- unnamed sockets

This matters because local IPC is often how malware coordinates helper processes.

## 11. Kernel vs Userspace Split
### Kernel should do
- capture socket lifecycle facts
- record bounded transport metadata
- store only small state needed for pairing
- emit bounded ring-buffer records
- stay verifier-friendly

### Userspace should do
- normalize endpoint strings
- create or refine flow identity when needed
- keep process enrichment from `/proc`
- append `process_info`
- write NDJSON to the file sink
- later parse DNS/HTTP/TLS when those layers are added

This split keeps the kernel code small and keeps protocol evolution in user space.

## 12. Acceptance Criteria for Socket Phase
Socket phase is complete when:
- every socket record includes `pid` and `flow_id`
- control-plane events carry return codes and endpoint context where relevant
- data-plane events carry bounded payload-prefix or byte-count information
- UNIX socket representation works for pathname, abstract, and unnamed cases
- output remains file-backed NDJSON with no stdout event spam
- kernel stats still report reserve/correlation misses clearly
- DNS/HTTP/HTTPS remain deferred until the socket layer is stable

## 13. What Comes After Socket Phase
### DNS
Derived from UDP/TCP socket traffic and correlated through flow identity.
Should capture query/response structure, counts, flags, and answer summaries.

### HTTP
Derived from cleartext socket traffic.
Should capture requests and responses separately, with best-effort flow correlation.

### HTTPS/TLS
Metadata-first only unless we later add a separate trusted decryption path.
Should capture handshake and flow metadata, not pretend to expose decrypted payloads.

## 14. Recommended Next Implementation Order
1. Lock the socket event schema and field names.
2. Finalize flow identity rules.
3. Implement socket control-plane capture.
4. Implement socket data-plane capture with bounded prefixes.
5. Validate output shape and overhead.
6. Only then move to DNS.
7. Then HTTP.
8. Then HTTPS/TLS metadata.

## 15. Summary
The socket layer is the right first network milestone.
It gives us high-value behavior, stable attribution, and a foundation for later
protocol parsing without forcing us to redo the core design.
