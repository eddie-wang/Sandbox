# Sandbox

A small Rust controller/scheduler and Linux node worker for stateful tool execution.

**[Current architecture and implementation status](plans/container-architecture-eddie-wang-2026-11-12.md)**

**Status: experimental real-runtime implementation; the bounded native lifecycle
smoke passed on one approved Linux x86-64 host (runc 1.3.6, CRIU 4.3).** This includes
IPv4 TCP allowlists and the streaming app proxy (path and host forms, binary and
chunked bodies) inside a disposable outer test netns, restored listening
sockets/fresh connections, and the existing lifecycle cases: cold create, capture
without stopping the source, independent warm restore (including an established
loopback TCP connection) from a sealed EROFS layer and a once-per-node checkpoint
cache, chained capture of a restored child, deletion of a source whose dump was
stopped at its deadline, layer verification kept across worker restarts, a reaping PID 1, concurrent, streamed and killed commands whose bounds stop
only themselves, private writes/whiteouts, blocking inline results, cleanup after
client disconnect mid-exec and mid-create, waiting concurrent DELETEs, TTL/delete
and crash/restart cleanup. A real-image check (`python:3.12-slim`, including a
WebSocket echo through the proxy) passed too.
This is a targeted functional result, **not production isolation, general workload
readiness, cross-node portability or capacity qualification**. The validation host's
indirect system-library/shell trust was not established; see the operator recipe.
Compilation and the nonprivileged HTTP smoke (which also checks that simultaneous
creates spread over two stand-in workers) are separate checks.

## Safe default

Without an explicitly enabled `[native]` configuration, the worker creates no
sandboxes, mounts, cgroups or namespaces. Missing preflight requirements likewise
fail closed. Read-only preflight does not install packages, load modules, enable
controllers, modify sysctls or repair the host.

```sh
cargo build --locked
python3 scripts/smoke.py --binary target/debug/sandboxd
# Informational, read-only; nonzero when prerequisites/enablement are absent:
target/debug/sandboxd preflight --config config/worker.example.toml
```

Provision independent unpredictable `SANDBOX_CONTROLLER_TOKEN` and
`SANDBOX_WORKER_TOKEN` values in the environment (at least 32 printable ASCII
characters), then start:

```sh
target/debug/sandboxd worker --config config/worker.example.toml
target/debug/sandboxd controller --config config/controller.example.toml
```

Tokens never belong in CLI arguments or tracked configuration. Management routes
require authentication; `/healthz` is liveness only. Bind to loopback or a trusted
network with an operator-managed TLS/auth/ingress boundary. There is no tenancy,
RBAC, built-in TLS or Internet-facing connection defense.

## Real-runtime design

- Administrator-provisioned immutable EROFS base images plus EROFS layers sealed by
  captures, all content-addressed and mounted once per node as shared read-only
  lowers. The create job hashes a layer the first time this worker uses it (two
  creates of the same new layer hash it once; others never wait behind a hash) and
  saves the result with the image file's identity, so it is trusted again after a
  worker restart until the file changes; **ordinary private
  OverlayFS upper/work directories**, a fresh empty upper per sandbox, no
  per-container block devices or storage daemon. Only the shared EROFS mounts use
  loop devices.
- Native runc + CRIU, isolated PID/mount/network/IPC/UTS/cgroup namespaces, UID/GID
  65534, empty capabilities, `no_new_privs` and cgroup-v2 memory/swap/CPU/pids
  limits installed before launch. Seccomp follows the AgentENV container pattern:
  default-allow, blocking only io_uring (`ENOSYS`) and MPTCP sockets
  (`EPROTONOSUPPORT`), which CRIU cannot checkpoint. Isolation relies on the
  namespaces, absent capabilities, `no_new_privs`, cgroups and network policy.
  PID 1 is an operator-staged static `tini`, bind-mounted read-only, which runs the
  template's init as its child, forwards signals and reaps orphans; stdio is
  `/dev/null`.
- Fully isolated networking remains the default. Opt-in immutable templates can
  use **IPv4 TCP literal destination/port allowlists**, bounded by operator policy.
  A worker-owned routing namespace per sandbox enforces default-drop nftables
  rules and SNAT before launch/restore; every guest has the same private address.
  Routing namespaces are pre-created and pooled (AgentENV pattern): worker start
  builds one per admissible sandbox with its uplink and default-deny base table, a
  create only attaches the sandbox's guest namespace and installs the template's
  rules, and delete resets the slot (rules and connection tracking flushed) rather
  than deleting it. Restart rebuilds the pool; shutdown removes it.
  Isolated sandboxes also get a worker-owned guest namespace, with only loopback.
  The operator provisions a stable-MAC bridge, gateway and exclusive address pool.
  No global firewall, routing or sysctl repair; no DNS, UDP, IPv6 or host-network mode.
- One durable admission/state coordinator per worker, a fixed bounded pool for
  parallel create/capture/delete across sandboxes, per-sandbox exclusion of those
  jobs, separate restore slots and a shared-lower mailbox (no lock held over mount
  I/O). Durable atomic lifecycle records. **Blocking API:** each request returns its
  real outcome (create when running, exec results, kill after the command ended,
  capture after publication, delete after cleanup; concurrent DELETEs of one
  sandbox share that result) within a route-specific bounded deadline. A client
  disconnect or timeout does not orphan a sandbox (commands, capture and delete
  finish with normal cleanup; a create whose reply the worker could not deliver is
  deleted as `create_response_lost`), except when a later hop loses a reply the
  worker already handed over; the sandbox's TTL bounds that case. The controller chooses the
  worker (least projected load, counting its own in-flight and not-yet-polled
  creates, with round-robin between equal scores, so simultaneous creates spread)
  and generates an opaque sandbox ID that routes later calls; clients never
  name nodes. Worker admission is final; stale controller capacity cannot
  reserve memory or start a workload. CPU quota admission has an explicit bounded
  operator overcommit factor, rather than assuming each idle quota consumes a
  physical CPU.
- Capture follows the AgentENV container backend and does not stop the source:
  `runc pause`, `syncfs` and seal the upper into an EROFS layer (ownership, xattrs,
  whiteouts kept), `runc checkpoint --leave-running` with `--tcp-established
  --ext-unix-sk --file-locks`, `runc resume`; then archive the images and atomically
  publish the layer, manifest and digests. On failure the source is thawed and kept
  if it runs, except that a dump stopped at its deadline deletes the source (its
  state is uncertain). Children mount the sealed layer(s) above the base (captures
  of warm children chain up to 16 layers) and restore from CRIU images unpacked once
  per node per manifest digest, synced before they are trusted, and shared read-only. File
  identity and independent restore are explicit qualification gates, exercised by
  open upper/lower descriptors, mappings and a loopback TCP connection in the real
  fixture. That fixture passed; arbitrary open-file/application states and other
  host configurations are **not assumed compatible**.
- Local immutable template repository with bounded artifact verification and
  exact kernel/CPU/architecture/runc/CRIU/config compatibility. All published
  templates/layers are retained; automatic cache eviction/GC and S3 transfer are
  not implemented.
- `runc exec` with argv, bounded output/deadline, a blocking mode (one JSON result)
  and a streaming mode (server-sent stdout/stderr events, then an exit event).
  Several commands may run at once per sandbox, each on its own thread and in its
  own child cgroup; a timeout, output overflow or kill request stops **only that
  command's group** and reports `interrupted`, the sandbox keeps running. A normal
  end also cleans the command's leftover descendants. Capture and delete stay
  exclusive (capture is refused while commands run; delete stops them).
- App traffic uses an AgentENV-style reverse proxy instead of a management call:
  `<port>-<sandbox-id>.<proxy_domain>` hosts or `/v1/sandboxes/<id>/proxy/<port>/...`,
  authenticated by the controller, routed to the owner and from there over a new
  connection opened **inside the sandbox's routing namespace** to its fixed guest
  address, for template-approved service ports only. Real statuses, headers and
  streamed bodies both ways (large, binary, chunked, server-sent events) and
  WebSocket upgrades; the management Authorization header is never forwarded; open
  exchanges are bounded, end when the sender stays silent for the idle timeout
  (a client that stops reading is not timed out) or when the sandbox is deleted
  (also while still connecting); there is no total deadline, and controller
  shutdown waits for them only up to the longest management deadline.
- Deletion kills the owned cgroup, deletes runc state, unmounts only the private
  overlay and removes private files. Failed cleanup remains reserved and
  retryable. Restart terminates/reconciles prior workloads rather than adopting
  unverified running state. Shared layers outlive individual sandboxes.

See [network architecture](docs/network.md), [API](docs/api.md), [serialized contracts](docs/contracts.md) and the
[explicitly privileged qualification recipe](docs/runtime.md). The latter builds
an original tiny static C fixture locally; it downloads no rootfs and never runs
from the nonprivileged smoke. No unit tests are added. No license has been selected.

## Deferred qualification and features

No two-node, S3, broad application compatibility
or performance result is claimed. Fork and user-facing pause/resume remain out of
scope. An in-sandbox agent (AgentENV's envd: background processes, a file API) is
deferred; commands use `runc exec` and app traffic the reverse proxy. The worker root needs operator-controlled disk capacity/quota; sandbox disk
quotas and an automatic artifact retention policy are not implemented.

The planned capacity test uses **two nodes, about 10% active and 90% resident
idle, below 512 GB per node**. Use a 500,000,000,000-byte hard limit per node for
headroom and include the whole experiment's memory and charged file cache.
The acceptable latency regression has not yet been agreed. Report end-to-end
latency (including queueing and retries), throughput, memory, failures and cleanup.
Real application and cleanup checks come before load testing; example budgets
are not measured capacity claims.

Keep tracked examples, workloads and traces generic and public-safe.
