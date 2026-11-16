# Sandbox

A small Rust controller/scheduler and Linux node worker for stateful tool execution.

**[Current architecture and implementation status](plans/container-architecture-eddie-wang-2026-11-12.md)**

**Status: experimental real-runtime implementation; the bounded native lifecycle
smoke passed on one approved Linux x86-64 host (runc 1.3.6, conmon 2.1.10, CRIU 4.3).** This includes
IPv4 TCP allowlists and the streaming app proxy (path and host forms, binary and
chunked bodies) inside a disposable outer test netns, restored listening
sockets/fresh connections, and the existing lifecycle cases: cold create, capture
without stopping the source, independent warm restore (including an established
loopback TCP connection) from a cloned ext4 upper and a once-per-node checkpoint
cache, chained capture of a restored child, deletion of a source whose dump was
stopped at its deadline, layer verification kept across worker restarts, a reaping PID 1, concurrent, streamed and killed commands whose bounds stop
only themselves, private writes/whiteouts, blocking inline results, cleanup after
client disconnect mid-exec and mid-create, waiting concurrent DELETEs, TTL/delete
and crash/restart cleanup. A real-image check (`python:3.12-slim`, including a
WebSocket echo through the proxy) passed too, and so did a local concurrency stress
gate: 16 cold creates at once, 16 warm restores at once, then 16 of each together
(32 concurrent creates), each batch deleted concurrently, with zero errors.
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

- Administrator-provisioned immutable EROFS bases are content-addressed, verified
  once per node and mounted read-only. Their verified file identities survive
  worker restarts. File-backed EROFS bases remain loop-free on supported kernels;
  put `native.root` on node-local xfs/ext4; EROFS loop fallback requires `native.erofs_loop_fallback = true`.
- Every cold and restored sandbox has an **ext4 image containing OverlayFS upper/work**,
  on its own autoclearing direct-I/O loop device. The cold template's `writable_mib`
  defaults to 1024 MiB (1 GiB, including metadata), a per-sandbox capacity limit
  large enough for a 450 MiB upper. Cold images copy a once-formatted scratch image,
  following containerd blockfile. Allocation uses loop-control and private device
  nodes rather than requiring a large static `/dev/loopN` inventory. No storage
  daemon is added. Warm templates pack the frozen copy and process images together
  with GNU sparse tar: SHA-256 covers the whole archive, not logical image holes.
  A bounded hot-template pool (`native.upper_pool_size`, default 32, zero disables)
  refills mounted warm copies in the background, with synchronous fallback on misses.
  Idle copies count toward private storage; restart discards them before readiness.
  Disposable copies use ext4 no-log-flush shutdown before normal unmount on deletion.
  See [storage contracts](docs/contracts.md) for format, copying,
  durability, ownership and teardown details.
- Native runc + CRIU, isolated PID/mount/network/IPC/UTS/cgroup namespaces, UID/GID
  65534, empty capabilities, `no_new_privs` and cgroup-v2 memory/swap/CPU/pids
  limits installed before launch. Seccomp uses the generated Docker default
  allowlist (Moby v28.3.3), resolved for x86-64 with no capabilities: default EPERM,
  upstream architecture/argument restrictions, plus io_uring (`ENOSYS`) and MPTCP
  (`EPROTONOSUPPORT`) checkpoint guards. Other native architectures fail preflight;
  old seccomp-layout templates must be republished/recaptured. See
  [policy provenance and regeneration](docs/runtime.md#syscall-policy). This is
  defense in depth alongside namespaces, absent capabilities, `no_new_privs`,
  cgroups and network policy, not a general shared-kernel security qualification.
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
  than deleting it. Restart rebuilds free slots but retains unfinished teardown's
  slots for CNI DEL retries, never for new admission; shutdown removes the pool.
  Isolated sandboxes also get a worker-owned guest namespace, with only loopback.
  The operator provisions a stable-MAC bridge, gateway and exclusive address pool.
  In `[native.network]`, choose exactly one of `addresses` (explicit list) or `slots`
  (1–256), optionally with `first_address`. Slots expand in ascending order within
  `gateway/prefix`, starting after the gateway by default, skipping gateway/egress
  targets and excluding network/broadcast addresses; a range that runs out is rejected.
  Either pool must cover `capacity.max_sandboxes`; see [network configuration](docs/network.md).
  Guest veth/address/routes now use standalone **CNI ptp + static IPAM** inside the
  router slot, never the shared pod namespace. The default-drop boundary precedes
  ADD; cached config/results drive reverse DEL, including partial failures and
  vanished guests. Both link pairs have explicit MTU (`native.network.mtu`, default
  1500, no larger than the operator bridge); CNI checks and policy precede launch.
  Stage verified `ptp` and `static` from Canonical noble containernetworking-plugins
  alongside the other trusted tools. The versioned CNI/MTU layout rejects old templates.
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
  worker (room by polled usage; least projected load, also counting its own
  in-flight and not-yet-polled creates, with round-robin between equal scores, so
  simultaneous creates spread without a false `no_capacity`)
  and generates an opaque sandbox ID that routes later calls; clients never
  name nodes. Worker admission is final; stale controller capacity cannot
  reserve memory or start a workload. CPU quota admission has an explicit bounded
  operator overcommit factor, rather than assuming each idle quota consumes a
  physical CPU.
- Capture follows the AgentENV container backend and does not stop the source:
  `runc pause`, freeze the private ext4 filesystem, sparse/reflink-copy its image,
  thaw the filesystem, `runc checkpoint --leave-running` with `--tcp-established
  --ext-unix-sk --file-locks`, then `runc resume`. The image and process checkpoint
  are published atomically with their manifest. Children copy that image over the
  unchanged EROFS base; chained captures retain inode tables without adding lowers.
  CRIU and ext4 images are verified/cached once per manifest per node. Normal
  delete and killed-worker reconciliation unmount without lazy detach, release
  the owned loop and remove its image. Failed captures thaw before source recovery.
  The upper inode/hardlink and retained SQLite DELETE-connection gates are explicit.
  **Device numbers still differ**: SQLite lock sharing between retained and newly
  opened connections remains a tested limitation, not a fidelity pass. Arbitrary
  application state and other hosts are not assumed compatible.
- Local immutable template repository with bounded artifact verification and
  exact kernel/architecture/runc/CRIU/init/config compatibility. CPU compatibility
  is CRIU's own check, not a feature fingerprint (AgentENV has none): a capture
  saves `criu cpuinfo dump` output with the template, and before admitting a warm
  restore the worker runs `criu cpuinfo check` against it (once per template); a
  refusal is a pre-launch `template_unavailable`, so the controller tries another
  node. That check can pass in one direction between two hosts and fail in the
  other. All published
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
  shutdown waits for them only up to the longest management deadline. Both
  services set `TCP_NODELAY` on accepted connections, so a small answer is not
  held back about 40 ms waiting for the client's delayed acknowledgement.
- Host tools run with bounded output and deadlines; once a tool exits, its output is
  read without waiting for anything that still holds its pipes (a descendant, or a
  concurrently started tool), so fast tools under concurrent creates are not
  misreported as interrupted.
- Lifecycle phase logs and authenticated status histograms separate admission,
  storage, network, runc and cleanup time. CPU checks run on a bounded helper;
  transient CRIU failures are not cached. Create/final record sync runs on operation
  workers, already-mounted lowers bypass the mount queue, and helpers use an
  exec trampoline rather than copying the worker's address space. Network setup
  uses CNI for guest links and batches uplink ip commands without copying the mount namespace. A bounded connector
  pool makes proxy sockets; guest connections are still never reused.
- Startup actively probes ext4, loop direct I/O and the upper backing directory's
  directory-entry types, xattrs, copy-up/hardlinks and ordinary overlay mounts.
  Volatile overlays are disabled; ext4 freeze must capture all writes. Each upper
  has its own filesystem, so unmount does not sync unrelated host filesystems.
  Mount-data length remains bounded and failures do not select weaker options.
  Lazy-page restore is not enabled or supported.
- runc alone creates/configures sandbox cgroups from OCI memory/swap/CPU/pids and
  whole-group OOM limits, including restored copies; helpers, monitors and per-exec
  groups remain worker-owned. The driver is cgroupfs, not systemd.
- Conmon 2.1.10 supervises each init, using the complete startup/PID handshake:
  cold create then runc start, or conmon restore with CRIU options. Passthrough
  logging preserves `/dev/null` workload stdio. Exit codes and cgroup-v2 OOM evidence
  are retained under `monitors/<id>/`, not inferred from an empty workload group.
  Monitor loss fails closed. Exec remains the existing bounded `runc exec` path.
- Worker startup verifies pod-private mount propagation before threads start.
  Mount inventory decodes escaped paths and propagation fields; overlay/lower and
  netns-pin teardown retries only busy unmounts, never lazy-detaches as success.
- Deletion kills the workload, drains its separately owned monitor, saves exit/OOM
  evidence before runc removes the group, deletes runc state, unmounts only the private
  overlay and removes private files. Failed cleanup remains reserved and
  retryable. Restart terminates/reconciles prior workloads rather than adopting
  unverified running state, including monitors left by a worker crash. Shared layers
  outlive individual sandboxes. The conmon layout fingerprint rejects older templates;
  republish cold templates and recapture warm templates before upgrading.

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
