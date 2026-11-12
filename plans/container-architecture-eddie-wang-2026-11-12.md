# Sandbox architecture — review draft

This document describes the design and the exact implementation checkpoint on `review/network-http-architecture`, based on reviewed lifecycle commit `e34616b`. It is not a production-readiness claim.

**Status:** the isolated runc/CRIU lifecycle passed a bounded, single-host functional smoke at the baseline. This branch adds networking and application HTTP code that builds and passes the original nonprivileged smoke, but **has not passed privileged networking, restored-listener, or cross-node qualification**. Do not transfer the baseline's qualification to the new network layout.

## Motivation/Goals

Build a small container-native service for stateful tool execution, without coupling process checkpoints to VM disk/snapshot abstractions.

- Restore independent sandboxes from a warmed filesystem/process template instead of repeating application initialization.
- Share immutable environment and seed files while isolating each sandbox's writes.
- Execute operations concurrently across independent sandboxes without losing admission, cancellation or cleanup ownership.
- Give applications a native `SandboxProvider` integration, command execution and bounded HTTP access, with explicitly restricted outbound access.
- Qualify sustainable capacity with two nodes, 10% actively executing and 90% resident idle, under a 512 GB budget and a specified latency bound. Budget scope and latency threshold are still open; no capacity result is claimed.

## Alternatives

- **Adapt a VM-shaped snapshot format — rejected.** A container snapshot should not need dummy memory disks or ignored VM configuration.
- **OverlayBD and per-container block filesystems — rejected for this implementation.** Shared filesystem mounts and private OverlayFS directories better match the chosen container model. This is not a general claim that block-level CoW is inferior.
- **Additional runtimes or gVisor comparison — rejected for current scope.** Only native Linux containers with runc + CRIU are selected.
- **One worker-wide blocking executor — rejected.** A slow command or restore must not serialize unrelated sandboxes. State ownership can be serialized; runtime I/O cannot.
- **Worker-managed global routing/NAT — rejected.** The operator supplies the worker's bridge/uplink/address pool; the worker manages its own slots and namespace-local filtering/NAT.
- **S3 transport — deferred by owner.** Current artifacts are node-local and explicitly staged by an administrator. No cloud client or storage-plugin framework is needed now.

## Constraints

- One Rust package and one `sandboxd` binary; controller and worker are separate modes. The scheduler stays inside the controller.
- No full E2B compatibility, separate scheduling daemon, global metadata database, runtime plugin framework, public fork API or user-facing pause/resume API in this version.
- Management APIs are authenticated. Workers require explicit administrator enablement and trusted executable/configuration paths. TLS, tenancy/RBAC and Internet-facing connection protection remain operator concerns.
- Untrusted workloads share the host kernel. Namespaces, capabilities, seccomp and cgroups are containment mechanisms, not a VM-equivalent or fully qualified hostile-code boundary.
- No workload runs before its filesystem, resource limits and network policy exist. API inputs cannot choose host paths, executable tools, arbitrary upstream URLs or broaden operator network authorization.
- Checkpoints and filesystem deltas must represent the same capture. Unknown/incompatible manifests fail closed; existing templates are not silently upgraded to a different layout.
- No unit tests by project preference. Use compilation/static checks and real process/runtime integration evidence. Keep all fixtures and published material generic.

## Architecture

### Components and ownership

```text
Application / SandboxProvider
             |
      native HTTP API
             |
  Rust controller + scheduler
    - configured worker origins
    - bounded status polling/freshness
    - advisory capacity/compatibility gate
    - owner-based routing
             |
       +-----+-------------------+
       |                         |
  Rust worker A             Rust worker B
    durable records           durable records
    admission coordinator     admission coordinator
    bounded operation pool    bounded operation pool
    EROFS/OverlayFS            EROFS/OverlayFS
    runc + CRIU                runc + CRIU
    owned networking           owned networking
       |                         |
   containers                 containers
```

**Controller.** It routes to static, administrator-configured workers and refreshes their status in a bounded background poller. In the current API, the client chooses an owner from status and supplies `<node_id>.<local_id>`; the controller checks that owner's advisory eligibility. It does not yet automatically allocate an owner or silently fail an ambiguous create over to another node. Embedding owner identity in IDs avoids a separate assignment database and preserves retry routing across controller restarts.

**Worker.** It is the final admission authority. A coordinator performs short durable state transitions and reservations, then sends runtime I/O to a fixed bounded operation pool. Only one mutation runs per sandbox; different sandboxes can run concurrently. Restore slots, live slots, memory reservations, retained outputs and CPU-overcommit budget are separate limits. A small mailbox owns shared-lower mount operations without a shared state lock spanning mount I/O.

**Operation ownership.** HTTP cancellation does not cancel accepted work or abandon its resources. Caller-chosen sandbox/operation IDs make retries observable and idempotent. A `202` means durable acceptance, not success; the caller polls the operation or sandbox state. No external resource is created before its durable owner exists.

These behaviors follow useful established orchestration patterns: per-sandbox exclusion, operation-owned work, conditional transitions, phase-aware cleanup and artifact protection. The implementation does not copy VM storage assumptions.

### Filesystem and template model

```text
Node-local immutable artifacts
  base.erofs  ----> one shared read-only mount per digest
                           |
                  +--------+--------+
                  |                 |
            OverlayFS A       OverlayFS B
            upper/ work/      upper/ work/
                  |                 |
             merged root       merged root
```

**Current implementation:** each template references one EROFS base image. It can contain runtime files and seed data together. Multiple independently composable EROFS base/seed/toolkit layers or a separate seed-volume API are not implemented. Unchanged files from the same mounted lower can share the host file cache; JVM/Python heaps and decoded buffers are still private.

Only the shared EROFS mount uses the standard loop-mount facility. Each sandbox's upper/work directories are ordinary host directories on a supported filesystem. There is no per-sandbox ext4 image, OverlayBD or block-device daemon.

A cold template contains the base digest and administrator-authored init/configuration. A warm template additionally contains:

- An archive of the private upper, preserving ownership, xattrs, ACLs and whiteouts.
- The matching CRIU image set.
- Resource and normalized OCI configuration requirements.
- Architecture, kernel, CPU-feature, runc/CRIU version and layout compatibility information.
- Artifact digests/sizes and an immutable manifest digest.

Capture stops/checkpoints the source, archives its upper in the same role, restores the source, then publishes the complete pair atomically. It is disruptive, not a zero-downtime fork. The upper is not promoted into a new lower, which would change file identity/layout assumptions. Compatible version checks are necessary but do not prove arbitrary application portability.

The repository is local and administrator-controlled. Shared artifacts are retained across source/child deletion and worker restart. Automatic GC, writable-disk quotas and idempotency-tombstone pruning are not implemented; the operator must bound and monitor the storage filesystem.

### Runtime and recovery

Create/restore proceeds as:

```text
durable admission/slot reservation
  -> verify immutable template
  -> acquire shared lower + prepare private upper/work
  -> install cgroups and network policy
  -> runc launch or CRIU restore
  -> publish running/result state
```

The baseline workload runs with an unprivileged UID/GID, empty capabilities, `no_new_privs`, restricted devices, a default-deny seccomp profile and private PID/mount/network/IPC/UTS/cgroup namespaces. The network draft narrowly adds the IPv4 TCP socket capability needed by its selected profile; it does not switch to an allow-all syscall profile.

Each command runs through `runc exec` with argv, bounded output/deadline and a private exec child cgroup. Descendants are drained even when the command exits successfully after closing its pipes. Timeout/output overflow conservatively terminates the sandbox. Host runtime/storage/helper processes have separate restart-discoverable helper cgroups and parent-death protection; restart drains helpers before reconciling their files/mounts.

Deletion and TTL kill owned workloads, remove private mounts/network state, delete private files and release admission. Cleanup failures stay reserved, observable and retryable. Worker restart currently terminates/reconciles prior live sandboxes and fails pending operations; it does not adopt arbitrary surviving state or automatically restore every sandbox.

### Networking draft: operator uplink, private router slots

```text
operator-provisioned bridge / gateway
                 |
          unique slot uplink IP
                 |
       worker-owned router namespace
       exact TCP allowlist + local SNAT
                 |
         private guest namespace
         fixed guest-visible IP
                 |
          container application
```

The operator configures an existing bridge, gateway/prefix, exclusive address pool, allowed external destination-IP/port pairs and allowed application service ports. The worker durably reserves a slot and owns its guest/router namespaces and veth endpoints. It applies default-drop rules before enabling the links or launching/restoring untrusted processes. Filtering and SNAT live in the router slot, not in the host's default firewall. The worker does not create global routes or enable global forwarding.

The fixed guest-side address keeps the application-visible network layout stable across independent restores while the external slot address varies. This **does not clone remote TCP peer or NAT state**. Restored listening sockets and fresh post-restore connections must be tested; transparent cloning of established external connections is not promised.

The draft supports literal IPv4/TCP pairs only: no implicit DNS, UDP or IPv6 opening. The fully isolated mode remains the default. Policies are currently immutable template fields and must be subsets of the worker's operator ceiling. Create-time endpoint overrides are **not implemented**, so a template tied to one service endpoint is not automatically reusable for another job's endpoint. That restriction is an explicit integration/review item.

Namespace ownership, partial-create cleanup and durable slot reconciliation are still under development/review in this checkpoint. An administrator must keep other workers or unrelated services out of the assigned address pool and namespace ownership domain.

### Application HTTP draft

`POST /v1/sandboxes/{id}/http` is an asynchronous, idempotent operation, not a general HTTP proxy. The worker authorizes a template service port, then invokes a bounded same-binary helper in the owned router namespace. The helper accesses only the fixed guest IP and permitted port. Namespace entry happens in a separate tracked process, never in a reusable Tokio/pool thread.

The draft accepts a relative path/query, limited methods, UTF-8 text body and only `accept`/`content-type` headers. It disables redirects and proxy inheritance, bounds request/response size and duration, and does not forward management bearer credentials. It returns status, optional content type and a UTF-8 body. Binary/streaming/WebSocket support is not implemented.

Controller routing currently carries both management and operation results through the controller. Direct worker data-plane access is a possible later performance change, **not an implemented separate path**.

### Source map

| Module | Responsibility |
| --- | --- |
| `src/main.rs`, `config.rs`, `http.rs` | Modes, administrator configuration, authentication and bounded HTTP handling |
| `src/controller.rs`, `scheduler.rs` | Worker polling, advisory eligibility and stable owner routing |
| `src/worker.rs`, `model.rs` | Native endpoints and typed request/status contracts |
| `src/engine.rs` | Durable ownership, admission, operation pool, state transitions and retries |
| `src/native.rs` | runc/CRIU, OCI config, cgroups, mounts and runtime preflight |
| `src/process.rs` | Bounded host subprocesses, verified PATH and helper-cgroup fencing |
| `src/storage.rs` | EROFS artifacts, OverlayFS deltas, manifests, integrity and publication |
| `src/network.rs` | Draft slot topology, policy, cleanup and application HTTP helper |
| `scripts/smoke.py` | Nonprivileged service integration checks |
| `scripts/runtime_smoke.py`, `scripts/fixture.c` | Explicitly privileged generic lifecycle fixture and assertions |

## Interfaces/signatures/headers

See [native API](../docs/api.md) and [storage contracts](../docs/contracts.md) for the reviewed lifecycle baseline. Those detailed documents have not yet been fully updated for this networking checkpoint; this section labels the draft additions.

- `sandboxd controller --config <file>`: trusted controller configuration and separate controller/worker credentials from environment/files.
- `sandboxd worker --config <file>`: explicit native enablement; no automatic package/module/network repair.
- `sandboxd preflight --config <file>`: read-only prerequisite checks, not a readiness certification.
- `POST /v1/sandboxes`: caller-owned sandbox ID, template ID, `runc_criu`, architecture, memory/vCPU quota and TTL. Durable acceptance followed by polling.
- `GET/DELETE /v1/sandboxes/{id}`: observed state or idempotent deletion request.
- `POST /v1/sandboxes/{id}/exec`: operation ID, argv, deadline and output bound.
- `POST /v1/sandboxes/{id}/capture`: operation ID and new immutable template ID.
- `GET /v1/sandboxes/{id}/operations/{operation_id}`: observable pending/completed/failed result.
- **Draft:** `POST /v1/sandboxes/{id}/http`: operation ID, permitted port, method, relative path, restricted headers/text body, timeout and response bound.
- **Draft:** `[native.network]` contains `bridge`, `gateway`, `prefix`, `addresses`, `egress` and `service_ports`; ordinary callers cannot set them.
- **Draft:** manifest schema v2 contains `network: {mode: isolated}` or `network: {mode: tcp_allowlist, egress, service_ports}`. The new layout fingerprint deliberately rejects old/incompatible manifests rather than silently converting them.

## Testing

| Gate | Reviewed baseline `e34616b` | This networking checkpoint |
| --- | --- | --- |
| Locked build/check | Passed | Passed before snapshot |
| Nonprivileged process smoke | Passed | Passed before snapshot |
| Static fixture / Python compilation | Passed | Passed before snapshot |
| Real isolated cold create/capture/independent restore | Passed with tiny fixture on one host | Must rerun after network/schema changes |
| Overlapping operations, admission, TTL/delete, restart/helper cleanup | Passed with bounded fixture | Network-specific regression still pending |
| Allowed/denied destination+port, sibling/host isolation | Deny-all only | Not yet run |
| Application HTTP bounds/auth behavior | Not implemented | Code present; privileged validation pending |
| CRIU external-netns/listener restore | Not implemented | Not yet run |
| Cross-node portability and real application trajectories | Not qualified | Not qualified |
| Two-node capacity/latency | Not run | Budget scope/threshold unresolved |

The original real smoke was limited to three 64 MiB / one-vCPU / 64-pid containers. It exercised process memory state, open files/mappings, private writes/whiteouts, concurrent operations/captures, lost-response retries, cleanup and restart. It was a functional gate on an explicitly approved development host, not a general security certification. Indirect system-shell/library trust was not established there.

Next networking validation must run inside a disposable outer namespace with local fixture services. Its bridge, addresses, routes and nftables changes stay inside that test topology; no default-host interfaces/routes/firewall/sysctls are changed. At this checkpoint, optional network assertions exist, but the disposable topology harness and its privileged run are still pending. Verify before/after resources and remove only test-owned state.

Capacity qualification is a separate gate: two nodes, 10% actually executing (not merely queued) and 90% alive/idle. Measure full-service memory including file cache, end-to-end p50/p95/p99 including queueing, throughput, actual concurrency, failures and teardown. Keep restore/first-call bursts separate from steady state. **512 GB per node versus combined, exact units, and acceptable latency regression are unresolved review decisions.** No number should be inferred from example configuration.
