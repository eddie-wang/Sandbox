# Sandbox

A small Rust controller/scheduler and Linux node worker for stateful tool execution.

**Review checkpoint: networking and application HTTP are in progress and are NOT
privileged-runtime qualified.** This snapshot builds and passes the original
nonprivileged process smoke; it is published for code/design review, not deployment.

**[Latest architecture and implementation status](plans/container-architecture-eddie-wang-2026-11-12.md)**

The reviewed baseline `e34616b` passed a bounded isolated lifecycle smoke on one
approved Linux x86-64 host (runc 1.3.6, CRIU 4.3): cold create, capture/source recovery,
independent warm restore, concurrent operations, private writes, retries and cleanup.
That result does not qualify this draft's new network layout or manifest schema.
Neither version is a production-isolation, general-workload, cross-node or capacity
certification. The validation host's indirect system-library/shell trust was not
established; see the operator recipe.

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

- Administrator-provisioned immutable EROFS images; shared read-only lower mounts,
  **ordinary private OverlayFS upper/work directories**, no per-container block
  devices or storage daemon. Only the shared EROFS mount uses a loop device.
- Native runc + CRIU, isolated PID/mount/network/IPC/UTS/cgroup namespaces, UID/GID
  65534, empty capabilities, `no_new_privs`, a default-deny seccomp syscall profile
  and cgroup-v2 memory/swap/CPU/pids limits installed before launch.
- Fully isolated networking remains the default. **Draft, unqualified:** template
  IPv4/TCP destination+port allowlists bounded by operator policy, with fixed guest
  addressing behind worker-owned router-slot namespaces. The operator provisions
  the bridge/gateway/address pool; filtering and SNAT are slot-local. No worker
  changes to default-host routes/firewall/sysctls are intended. Ownership/restart
  review and real network/CRIU qualification are still pending.
- One durable admission/state coordinator per worker, a fixed bounded pool for
  parallel runtime I/O across sandboxes, per-sandbox exclusion, separate restore
  slots and a shared-lower mailbox (no lock held over mount I/O). Durable atomic records,
  caller-chosen idempotency IDs, short asynchronous HTTP acceptance and separate
  operation polling. Worker admission is final; stale controller capacity cannot
  reserve memory or start a workload. CPU quota admission has an explicit bounded
  operator overcommit factor, rather than assuming each idle quota consumes a
  physical CPU.
- Capture stops the source, archives the unchanged upper layout with ownership,
  xattrs and whiteouts, pairs it with CRIU images, recovers the source, then
  atomically publishes a manifest and digests. It never promotes upper files into
  a new lower. Directory-copy file identity and independent restore are explicit
  qualification gates, exercised by open upper/lower descriptors and mappings in
  the real fixture. That fixture passed; arbitrary open-file/application states
  and other host configurations are **not assumed compatible**.
- Local immutable template repository with bounded artifact verification and
  exact kernel/CPU/architecture/runc/CRIU/config compatibility. All published
  templates/layers are retained; automatic cache eviction/GC and S3 transfer are
  not implemented.
- `runc exec` with argv, bounded output/deadline and durable results. A bound
  violation conservatively terminates the **whole sandbox**, not just its runc
  client. Each exec uses an owned child cgroup and cleans descendants even after
  a successful parent exit. **Draft application HTTP** uses a tracked helper in the
  owned slot namespace, with a fixed guest target, authorized port and bounded
  UTF-8 request/response. No arbitrary upstream URL, redirects or credential
  forwarding. Real HTTP/network validation is still pending.
- Deletion kills the owned cgroup, deletes runc state, unmounts only the private
  overlay and removes private files. Failed cleanup remains reserved and
  retryable. Restart terminates/reconciles prior workloads rather than adopting
  unverified running state. Shared layers outlive individual sandboxes.

See [API](docs/api.md), [serialized contracts](docs/contracts.md) and the
[explicitly privileged qualification recipe](docs/runtime.md). The latter builds
an original tiny static C fixture locally; it downloads no rootfs and never runs
from the nonprivileged smoke. No unit tests are added. No license has been selected.

## Deferred qualification and features

Networking/application HTTP code in this branch is an unqualified draft; no
successful privileged network result is claimed. S3 is owner-deferred. Two-node,
broad application compatibility and performance qualification remain outstanding.
Fork and user-facing pause/resume remain out of scope. The worker root needs
operator-controlled disk capacity/quota; sandbox disk quotas and an automatic
artifact retention policy are not implemented.

Capacity qualification remains **two nodes, 10% active and 90% resident idle, under
a 512 GB budget**. Per-node versus total scope, exact byte count and acceptable
latency regression must be agreed before any run. Measure full-service memory
including page cache, p50/p95/p99 end-to-end latency, queueing, failures and teardown;
functional/isolation/leak gates come first. Example budgets are not capacity claims.

Keep tracked examples, workloads and traces generic and public-safe.
