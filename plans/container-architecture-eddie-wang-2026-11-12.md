# Sandbox architecture

This is the current architecture and qualification status, superseding the networking draft published at `27be407`. The isolated lifecycle baseline was reviewed at `e34616b`; networking/application HTTP subsequently passed independent review and targeted real integration checks, including a path-MTU fix and re-review.

**Status: experimental implementation with bounded single-host functional evidence, not production isolation, broad application compatibility, cross-node portability or capacity qualification.** Build/check, nonprivileged process smoke, isolated lifecycle, and disposable-topology network/HTTP lifecycle gates passed with runc 1.3.6 and CRIU 4.3. No JVM/Spark workload or two-node capacity result is claimed.

## Motivation/Goals

Build a small container-native service for stateful tool execution without coupling process checkpoints to VM disk/snapshot abstractions.

- Restore independent sandboxes from a warmed filesystem/process template instead of repeating initialization.
- Share immutable environment/seed files while isolating each sandbox's writes.
- Execute work concurrently across independent sandboxes without losing admission, cancellation or cleanup ownership.
- Expose a native `SandboxProvider` integration, bounded commands/application HTTP, and explicitly restricted outbound access.
- Qualify sustainable capacity on two nodes with 10% actively executing and 90% resident idle, under a 512 GB budget and a specified latency bound. Budget scope, exact units and latency threshold remain open.

## Alternatives

- **Adapt a VM-shaped snapshot format — rejected.** Container snapshots should not need dummy memory disks or ignored VM configuration.
- **OverlayBD and per-container block filesystems — rejected for this implementation.** Shared filesystem mounts and private OverlayFS directories match the selected model. This is not a general claim against block-level CoW.
- **Additional runtimes/gVisor comparison — rejected for current scope.** Only native Linux containers with runc + CRIU are selected.
- **One worker-wide blocking executor — rejected.** State ownership can be serialized, but a slow command/restore must not serialize unrelated sandboxes.
- **Worker-managed global routing/NAT — rejected.** Operators supply bridge/uplink/address pools; workers own their slots and namespace-local filtering/NAT.
- **S3 transport — deferred by owner.** Current artifacts are node-local and staged explicitly by an administrator. No cloud client or storage-plugin framework is needed now.

## Constraints

- One Rust package and one `sandboxd` binary with controller/worker modes. Scheduling stays inside the controller.
- No full E2B compatibility, separate scheduling daemon, assignment database, runtime plugin framework, public fork API or user-facing pause/resume API.
- Authenticated management and explicit administrator runtime enablement. TLS, tenancy/RBAC and Internet-facing connection defenses remain operator concerns.
- Workloads share the host kernel. Namespace/capability/seccomp/cgroup controls are not a VM-equivalent or fully qualified hostile-code boundary.
- Filesystem, resource and network policy setup precede untrusted execution. API callers cannot choose host paths, runtime tools, arbitrary upstream URLs or broader-than-operator network permissions.
- Checkpoint and filesystem delta must represent the same capture. Unknown/incompatible manifests fail closed; old artifacts are not silently upgraded.
- No unit tests by project preference. Use compile/static checks and real process/runtime integration evidence. All fixtures and public content remain generic.

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

**Controller.** Routes to static administrator-configured workers and refreshes their status in a bounded background poller. Currently the client chooses an owner from status and supplies `<node_id>.<local_id>`; the controller checks that owner's advisory eligibility. Automatic owner allocation is not wired into create. An ambiguous create is never silently retried on another worker. Owner-bearing IDs avoid a separate assignment database and preserve routing across controller restarts.

**Worker.** Final admission authority. A coordinator performs short durable transitions/reservations, then a fixed bounded pool runs runtime I/O. One mutation runs per sandbox; different sandboxes overlap. Restore slots, live slots, memory reservations, retained outputs and CPU-overcommit budgets are separate limits. A small mailbox owns shared-lower mount operations without a shared state lock spanning mount I/O.

**Operation ownership.** HTTP cancellation does not abandon accepted work/resources. Caller-chosen IDs make retries observable and idempotent. `202` means durable acceptance, not success; callers poll results/state. Resources are not created before their durable owner exists. These behaviors follow established per-sandbox exclusion, operation-owned work, conditional-transition, retryable-cleanup and artifact-protection patterns without inheriting VM storage assumptions.

### Filesystem and template model

```text
Node-local immutable artifacts
  base.erofs  ----> shared read-only mount per digest
                           |
                  +--------+--------+
                  |                 |
            OverlayFS A       OverlayFS B
            upper/ work/      upper/ work/
                  |                 |
             merged root       merged root
```

Each template currently references **one EROFS base** containing environment files and optionally seed data. Independently composable base/seed/toolkit layers and a separate seed-volume API are not implemented. Unchanged files from the same mounted lower can share host file-cache pages; process heaps/decoded buffers remain private.

Only the shared EROFS mount uses the standard loop-mount facility. Per-sandbox upper/work directories are ordinary directories on a supported local filesystem: no private ext4 image, OverlayBD or block-device daemon.

A cold template has the base digest and administrator-authored init/configuration. A warm template adds a private-upper archive preserving ownership/xattrs/ACLs/whiteouts, the matching CRIU image set, resource/normalized-OCI requirements, network policy, and architecture/kernel/CPU/runc/CRIU/layout compatibility. Artifact digests/sizes and a manifest digest bind publication.

Capture stops/checkpoints the source, archives its upper in the same role, restores the source, then publishes the complete pair atomically. It is disruptive, not a zero-downtime fork. The upper is not promoted into a new lower. Version matching and the passing open-file/mapping fixture do not prove arbitrary application portability.

Local artifacts are administrator-controlled and retained across source/child deletion/restart. Automatic GC, writable-disk quotas and tombstone pruning are not implemented; operators must bound and monitor storage. S3 is deferred, not an implicit dependency.

### Runtime and recovery

```text
durable admission/slot reservation
  -> verify template and acquire shared lower
  -> prepare private upper/work
  -> install cgroups and network policy
  -> runc launch or CRIU restore
  -> publish running/result state
```

Workloads use an unprivileged UID/GID, empty capabilities, `no_new_privs`, restricted devices, default-deny seccomp and private PID/mount/network/IPC/UTS/cgroup namespaces. The selected network profile narrowly permits the required IPv4 TCP socket operations; it does not enable all socket families or an allow-all syscall policy.

Commands run through `runc exec` with argv, deadlines/output limits and a private exec child cgroup. Descendants are drained even after successful parent exit; timeout/overflow conservatively terminates the sandbox. Host runtime/storage/HTTP helper processes have separate restart-discoverable helper cgroups and parent-death protection. Restart drains helpers before reconciling their files/mounts; it does not rely only on process groups or a dead worker's timeout loop.

Deletion/TTL kill owned workloads, remove private mounts/network state/files and release admission. Failures stay reserved, observable and retryable. Worker restart terminates/reconciles prior live workloads and fails pending operations rather than adopting arbitrary surviving state or automatically resuming every sandbox.

### Networking: operator uplink, private router slots

```text
operator-provisioned stable-MAC bridge / gateway
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

Operators configure an existing stable-MAC bridge, gateway/prefix, exclusive address pool, allowed literal IPv4 destination/port pairs and application service-port ceiling. Workers durably reserve slots and own guest/router namespaces and veth endpoints. Default-drop rules precede links/untrusted execution. Filtering/SNAT are slot-local; workers do not repair default-host routing, firewall or forwarding settings.

The fixed guest address preserves application-visible layout across independent restores while external slot addresses vary. It **does not clone external TCP peers or NAT/conntrack state**. Capture requires quiescent TCP: active/closing connections are rejected before stopping. Listening sockets and fresh allowed connections were exercised after source recovery and independent restore.

Allowed TCP traffic supports IPv4 path-MTU discovery. Only related fragmentation-needed errors matching the original guest source and an authorized TCP destination/port may return from a downstream router or the slot itself. There is no blanket ICMP/RELATED allowance and no extra workload raw-socket permission. The fix was validated with a DF-marked verified payload over reduced-MTU paths, including a restored child.

No DNS, UDP, IPv6 or domain/CIDR policy is implicit. Fully isolated mode remains default. Egress/service policies are currently **immutable template fields** bounded by operator configuration; create-time endpoint overrides are not implemented. Changing a job's service endpoint therefore requires another approved template. Operators own trusted bridge peers, pool exclusivity and routing beyond the bridge.

See [network details](../docs/network.md) for ordering, namespace ownership, cleanup/restart and capture restrictions.

### Application HTTP

`POST /v1/sandboxes/{id}/http` is a bounded asynchronous/idempotent operation, not a general proxy. After service-port authorization, a tracked same-binary helper enters only the owned router namespace and reaches the fixed guest address. Namespace entry never changes a reusable worker/Tokio thread.

The HTTP/1 client accepts a relative path/query, limited methods, UTF-8 text and only `accept`/`content-type` request headers. It disables redirects/proxies, bounds headers/body/result/deadline and does not forward management credentials. Results contain status, optional content type and UTF-8 body. Binary/streaming/WebSocket support is not implemented.

Controller routing currently carries management and operation results through the controller. Direct worker data-plane access is a possible later optimization, not an implemented path.

### Source map

| Module | Responsibility |
| --- | --- |
| `src/main.rs`, `config.rs`, `http.rs` | Modes, operator configuration, authentication, bounded HTTP handling |
| `src/controller.rs`, `scheduler.rs` | Polling, advisory eligibility and stable owner routing |
| `src/worker.rs`, `model.rs` | Native endpoints and typed contracts |
| `src/engine.rs` | Durable ownership, admission, operation pool, state transitions/retries |
| `src/native.rs` | runc/CRIU, OCI, cgroups, mounts and preflight |
| `src/process.rs` | Bounded subprocesses, verified PATH and helper-cgroup fencing |
| `src/storage.rs` | Artifacts, filesystem deltas, manifests, integrity/publication |
| `src/network.rs` | Slot topology, policy, cleanup and HTTP helper |
| `scripts/smoke.py` | Nonprivileged process integration |
| `scripts/runtime_smoke.py`, `scripts/fixture.c` | Bounded real lifecycle fixture |
| `scripts/network_smoke.py` | Disposable network/mount topology and network/HTTP qualification |

## Interfaces/signatures/headers

Exact fields/bounds are in [API](../docs/api.md), [storage contracts](../docs/contracts.md), [network](../docs/network.md) and [operator validation](../docs/runtime.md).

- `sandboxd controller --config <file>`: trusted configuration and separate controller/worker environment/file credentials.
- `sandboxd worker --config <file>`: explicit native enablement; no automatic package/module/network repair.
- `sandboxd preflight --config <file>`: read-only prerequisite checks, not certification.
- `POST /v1/sandboxes`: owner-bearing ID, template ID, `runc_criu`, architecture, memory/vCPU quota and TTL; durable acceptance then polling.
- `GET/DELETE /v1/sandboxes/{id}`: state or idempotent deletion request.
- `POST /v1/sandboxes/{id}/exec`: operation ID, argv, deadline/output limit.
- `POST /v1/sandboxes/{id}/capture`: operation ID and immutable template ID.
- `POST /v1/sandboxes/{id}/http`: operation ID, permitted port, method, relative path, restricted headers/text and timeout/response limit.
- `GET /v1/sandboxes/{id}/operations/{operation_id}`: pending/completed/failed result.
- `[native.network]`: administrator-only bridge, gateway, prefix, addresses, egress and service ports.
- Manifest schema v2 selects `isolated` or `tcp_allowlist`; exact layout includes `tcp-pmtu-v1`. Incompatible old schemas/layouts are rejected rather than converted implicitly.

## Testing

| Gate | Current evidence |
| --- | --- |
| Locked build/check, nonprivileged smoke, C/Python compilation | Passed on the final reviewed source |
| Isolated cold create, capture/source recovery, independent restore | Passed with tiny fixture on one host |
| Overlapping operations/captures, atomic admission, retries, TTL/delete, helper/restart cleanup | Passed within bounded fixture scope |
| Exact TCP destination/port positives and negatives; host/sibling isolation checks | Passed in disposable topology |
| Application HTTP auth, target/headers, text/bounds/timeouts/redirect handling | Passed in disposable topology |
| Restored listener/fresh egress, active-TCP capture rejection, retained namespace-FD cleanup retry | Passed in disposable topology |
| TCP path-MTU discovery, forwarded and slot-generated errors | Before-fix stall reproduced; final cold/restored cases passed with denied-traffic regression checks |
| Cross-node portability and real application trajectories | Not qualified |
| Two-node capacity/latency | Not run; budget scope/threshold unresolved |

Tests were limited to three containers, each 64 MiB / one-vCPU / 64-pids, using an original local static fixture. Network tests created a disposable outer network/mount namespace and local peers; bridge, routing, MTU and nftables changes stayed there. Default-host network inventory was unchanged. Owned processes/mounts/namespaces/loops/cgroups were cleaned; diagnostic artifacts were intentionally retained outside the repository.

This development-host evidence does not certify executable-ancestor/system-library trust, every failure/crash point, arbitrary kernel/CRIU states or hostile-workload containment. No unit tests or capacity claims are substituted for missing integration qualification.

Next gate: real application compatibility and explicit artifact staging between two approved nodes. Capacity is a separate test with 10% actually executing (not merely queued), measuring full-service memory including cache, p50/p95/p99 including queueing, throughput, failures and teardown. Keep restore/first-call bursts separate from steady state. **512 GB per node versus combined, exact units and acceptable latency regression remain unresolved.**
