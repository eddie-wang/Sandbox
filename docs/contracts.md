# Local runtime and storage contracts

These describe implemented code paths and serialized metadata. The bounded local
fixture passed on one approved host; this is **not general isolation or checkpoint
portability qualification**. Only native Linux runc + CRIU is supported.
No alternate runtime adapters, plugin framework, per-container disk images or
storage daemons are used.

## Ownership and filesystem layout

An explicitly configured, existing, administrator-owned root must have trusted
(non-symlink, UID 0, not group/other writable) ancestors. The worker holds an
exclusive advisory lock for its lifetime. The configured cgroup-v2 parent is
exclusive to that worker; operators must not share it between worker roots.

```text
<root>/
  worker.lock
  worker-status.json              durable shutdown cleanup error, if any
  records/<node>.<id>.json         atomic lifecycle/idempotency records
  private/<node>.<id>/
    upper/ work/ rootfs/           ordinary directories; rootfs is OverlayFS
    config.json exec.json         worker-authored OCI/process input
    criu.conf images/ criu-work/   protected runtime/checkpoint work
  layers/<sha256>.erofs            trusted immutable artifacts
  lowers/<sha256>/                 shared read-only EROFS mounts
  templates/<template-id>/
    manifest.json manifest.sha256
    upper.tar checkpoint.tar      present together only for warm templates
  staging/<sandbox-length>-<sandbox>-<operation>/
                                  unpublished capture; exclusively owned per job
  runc/                           private runc state root
```

The manifest sidecar is lowercase SHA-256 plus LF over the exact JSON bytes.
Artifact integrity is SHA-256 + byte count. Local provenance is administrator/worker
ownership and private directory permissions, **not a cryptographic publisher
signature or an unauthenticated download**. Administrators provision cold templates
and layers before use, or after stopping the worker; there is no live import/upload
API. Do not modify published artifacts, manifests or mounted images.

All HTTP identifiers are validated components, never host paths. Fixed filenames
and content hashes select artifacts. Ancestors are trusted, final artifact/record
opens reject symlinks, and metadata/sizes/digests are checked before runtime use.
User symlinks *inside* an archived upper are legitimate workload state and are
preserved by GNU tar, not followed as administrator paths. GNU tar's default
traversal/symlink extraction protections remain enabled. There is no user-supplied
archive or executable host path.

Lower mounts are shared by digest and are read-only, nodev/nosuid. Only these shared
EROFS images use the standard mount/loop facility. Each sandbox gets sibling
upper/work directories on the same supported local filesystem; OverlayFS uses
`index=off,metacopy=off,redirect_dir=off,xino=off,nodev,nosuid`. No lower layer is
writable, no upper is promoted to a new lower, and no private block device is added.

Deletion checks mountinfo before recursive private removal, never uses lazy unmount
or broad recursive mount deletion, and never deletes shared templates/images.
Shared lowers are unmounted only after all owned workloads have been cleaned during
shutdown/reconciliation; images/templates are retained indefinitely. Cache eviction,
artifact deletion API, S3 transfer and disk quotas are not implemented. Operators
must provision an appropriately bounded dedicated filesystem/quota and monitor free
space. A filesystem failure stops admission; old durable ownership still permits
termination/cleanup.

## Manifest v2

Strict JSON fields (unknown fields are rejected):

| Field | Meaning |
| --- | --- |
| `schema_version` | Exactly `2`; v1 is rejected, not silently migrated |
| `template_id`, `generation` | Validated immutable publication and capture-generation IDs |
| `runtime` | Exactly `runc_criu` |
| `compatibility` | Architecture, exact kernel release, SHA-256 of CPU feature string, exact runc and CRIU version output, fixed mount/network/seccomp layout version |
| `base` | `{ "sha256": "...", "bytes": ... }` for `layers/<digest>.erofs` |
| `upper`, `checkpoint` | Both null for cold, or descriptors for `upper.tar` and `checkpoint.tar` from one stopped generation |
| `init_argv` | Trusted absolute in-container executable + argv; not an OCI config/host executable |
| `memory_mib`, `vcpus` | Null cold; exact required resource settings warm |
| `pids_max` | Exact configured pids limit |
| `oci_config_sha256` | Null cold; warm SHA-256 of canonical worker-generated OCI JSON, with private cgroup, guest-netns and CRIU-config paths replaced by fixed reconstruction markers |
| `network` | Strict tagged `isolated` or `tcp_allowlist` policy; see API. Endpoints remain fixed across capture. |
| `uid`, `gid` | Exactly `65534`, `65534` |

`compatibility` is emitted by read-only `preflight` and has exactly:
`architecture`, `kernel`, `cpu_features_sha256`, `runc_version`, `criu_version`,
`layout`. The OCI network-policy digest annotation is preserved during normalization. `layout` is `erofs-overlay-upper-v2-fixed-slot-tcp-pmtu-v1-seccomp-v2`. The local fixture
script demonstrates complete cold publication; do not guess compatibility strings.
Exact matching deliberately rejects more hosts than might technically work. Version
matching is necessary, **not sufficient proof of CRIU portability**.

## Capture, file identity and recovery

The worker excludes overlapping mutations of the same sandbox; different sandboxes
run on a bounded operation pool. It uses a normal
stopping runc checkpoint (not `--leave-running`), then GNU tar with numeric ownership,
permissions, xattrs including OverlayFS metadata, ACLs, hardlinks, sparse files and
whiteouts. The process is no longer writing during the filesystem snapshot. The
same unchanged EROFS lower is referenced. Upper and checkpoint archives get their
own digests/sizes and a single generation/manifest. The source is restored from its
own original upper and images before publication. A failed dump can leave a live
PID with uncertain state, so checkpoint failure conservatively terminates/cleans
that source; it is not called recovered merely because runc reports a PID. Failure
after a completed dump attempts source recovery; recovery failure is terminal. Files/manifest are synced before atomic directory rename.
Failed/stale staging is removed without touching live mounts or published templates.

Children extract the upper into a **new upper**, create a fresh work directory and
mount the same lower layout. The worker writes a new OCI bundle/private cgroup and
asks runc to restore into the new container ID. CRIU runs from host authority, with
`mntns-compat-mode` and file-lock handling. Cgroup restoration uses runc's target
cgroup setup with CRIU manage mode `ignore`, not source-cgroup adoption. It does not
use TCP-established/external-Unix-socket/link-remap options to waive unsupported
application state. Unlinked open files and broader runtime state may be rejected. Networked guests
join a separately reconstructed, worker-pinned external netns with the same guest
IPv4 address. Listening TCP sockets may restore; active TCP connections must be
quiesced and are rejected by a precheck/CRIU. Peer and router conntrack state are
not checkpoint artifacts. Fresh post-restore connections get the child slot's
independent SNAT identity.

**Directory archives do not preserve host inode numbers.** The implementation keeps
upper/lower roles stable and relies on the supported runc/CRIU mount/file reopening
path, not on an assertion that inode changes are harmless. The real fixture holds
both lower and upper descriptors/mappings open and checks an in-memory random nonce
and counter across source recovery and independent restore. It also exercises
copy-up and whiteout isolation. That targeted gate **passed with the local static
fixture, runc 1.3.6 and CRIU 4.3**. It does not establish compatibility for arbitrary
open/unlinked files, other workloads or hosts. A failed gate must be investigated
as a real compatibility blocker; do not disable CRIU identity
checks, convert uppers into lower images, add a per-container block device or report
a passing restore without an approved architecture decision and actual evidence.
Cross-node reconstruction and different CPU/kernel combinations are unqualified.

## Admission, operations and cleanup

Worker admission is serialized with durable record creation before any resource
side effect. Memory, live slots, restore slots and a configured 1–16 CPU quota
oversubscription factor are checked against existing reservations, not controller
snapshots. The coordinator performs only durable state/admission transitions, not
blocking runtime tools. A fixed 1–64-thread pool bounds operation concurrency,
per-sandbox exclusion serializes each lifecycle, and separate restore slots bound
create/capture/restore. Shared lower mount creation has its own bounded mailbox;
there is no shared-state lock across mount/process I/O. Template names in capture
are reserved against concurrent publication. In-flight output budgets are reserved
before exec as well as retained afterward. The mailbox is bounded and short HTTP
deadlines do not cancel jobs owned by the coordinator.
Caller-chosen sandbox/operation IDs make ambiguous response retries idempotent.
Result bytes/counts and tombstones are bounded and retained; no automatic pruning
can silently reopen an ID for execution.

Network policy and cgroup limits precede runc launch and restore. A slot index is
reserved in the durable record before network side effects. Unique root/sandbox
namespace names, an exclusive private ownership marker and bounded helper cgroups
cover creation, cancellation and restart; unexplained namespace state fails closed.
Cleanup retains the reservation/marker on failures, including delayed kernel link
destruction, and retries without global flushes. See [network details](network.md). The workload has UID/GID
65534, empty capabilities, no_new_privs, minimal /dev, its own proc/PID/mount/net/IPC/
UTS/cgroup namespaces and an explicit default-errno seccomp allowlist. Namespace
creation via clone is filtered; clone3 returns ENOSYS for libc fallback; mount,
setns/unshare, ptrace, bpf, perf, io_uring are not allowed. Isolated templates still prohibit sockets; the opt-in
network profile permits only AF_INET/SOCK_STREAM with TCP or protocol zero, plus
stream operations. IPv6/UDP/raw/packet/netlink/Unix socket creation stays denied.
Host authority, not workload privilege, performs checkpoints. This profile is
intentionally narrow and unqualified for general applications.

TTL has a separate cgroup-kill watchdog so a long archive cannot keep an expired
workload running until a job completes. Deletion durably records cancellation and
signals active jobs; cleanup waits for the sandbox's in-flight job rather than
racing it. Exec uses a dedicated child cgroup and kills/removes descendants on
successful completion too, including children that close stdout/stderr. Exec clamps
its deadline to remaining TTL; output/deadline/persistent-pipe failure kills the
entire sandbox. Delete first
kills the owned cgroup (all descendants), force-deletes private runc state, checks
for no populated cgroup, unmounts the private overlay, then removes private state.
Reservation release follows successful cleanup exactly once. Failure remains
`cleanup_failed`, reserved, observable and retryable. Never recurse into a live mount.

On restart, records are loaded and ownership validated before admission. Previously
live/interrupted workloads are killed/cleaned, pending operations fail, and stopped
private resources are reconciled. Unexplained runc/private/cgroup entries fail startup
rather than being silently adopted/deleted. Published templates survive source and
child deletion. Abrupt worker death does not itself kill containers; an operator
must restart the worker with the same root/config promptly to reconcile them.

## Qualification

Read-only preflight checks tools/versions, UID/capabilities, advertised filesystems,
namespace/seccomp interfaces, supported upper filesystem family and an existing
empty delegated cgroup domain with cpu/memory/pids enabled. It does **not** write an
xattr probe, run `criu check`, create a mount/namespace, enable a controller or prove
runtime behavior. XFS ftype/xattr details, EROFS options, actual seccomp compatibility,
restore cgroup placement and lifecycle/isolation/cleanup claims require the
privileged gate. The static-fixture local gate passed, including independently
overlapping commands, final worker admission, rejected template compatibility/digest/
symlink inputs, command descendants, response-loss replay and pending-exec restart
cleanup. Host trust was not qualified: the approved validation host used
administrator-staged binaries but retained indirect system library/fixed-shell
dependencies. No performance, S3, general hostile-workload isolation or two-node
result is claimed.
