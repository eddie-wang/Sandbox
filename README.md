# Sandbox

A small Rust controller/scheduler and Linux node worker for stateful tool execution.

**Status: experimental real-runtime implementation; the bounded native lifecycle
smoke passed on one approved Linux x86-64 host (runc 1.3.6, CRIU 4.3).** This includes
cold create, capture/source recovery, independent warm restore, overlapping commands,
private writes/whiteouts, idempotent retry, TTL/delete and crash/restart cleanup.
This is a targeted functional result, **not production isolation, general workload
readiness, cross-node portability or capacity qualification**. The validation host's
indirect system-library/shell trust was not established; see the operator recipe.
Compilation and the nonprivileged HTTP smoke are separate checks.

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
- Only **fully isolated, deny-all networking** is implemented: no veth, route,
  external interface, host networking or network socket syscall. No host firewall
  or sysctl changes. CRIU uses temporary nftables locks only in the owned netns.
  Destination/port egress allowlists are **not implemented**;
  requests cannot enable them. This is deliberately narrower than a general
  container application profile.
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
  a successful parent exit. Application HTTP is a distinct, **unimplemented** interface; there is
  no arbitrary upstream proxy.
- Deletion kills the owned cgroup, deletes runc state, unmounts only the private
  overlay and removes private files. Failed cleanup remains reserved and
  retryable. Restart terminates/reconciles prior workloads rather than adopting
  unverified running state. Shared layers outlive individual sandboxes.

See [API](docs/api.md), [serialized contracts](docs/contracts.md) and the
[explicitly privileged qualification recipe](docs/runtime.md). The latter builds
an original tiny static C fixture locally; it downloads no rootfs and never runs
from the nonprivileged smoke. No unit tests are added. No license has been selected.

## Deferred qualification and features

No two-node, S3, application HTTP, egress allowlist, broad application compatibility
or performance result is claimed. Fork and user-facing pause/resume remain out of
scope. The worker root needs operator-controlled disk capacity/quota; sandbox disk
quotas and an automatic artifact retention policy are not implemented.

Capacity qualification remains **two nodes, 10% active and 90% resident idle, under
a 512 GB budget**. Per-node versus total scope, exact byte count and acceptable
latency regression must be agreed before any run. Measure full-service memory
including page cache, p50/p95/p99 end-to-end latency, queueing, failures and teardown;
functional/isolation/leak gates come first. Example budgets are not capacity claims.

Keep tracked examples, workloads and traces generic and public-safe.
