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
  verified-layers.json            layers this worker fully hashed: digest, size and the
                                  image file's identity at that time (root-owned 0600,
                                  replaced atomically; an unusable file means rehash)
  records/<sandbox-id>.json        atomic lifecycle records (schema 2; metadata only)
  private/<node>.<id>/
    upper/ work/ rootfs/           ordinary directories; rootfs is OverlayFS; upper
                                   starts empty for cold and warm sandboxes alike
    config.json exec-<n>.json     worker-authored OCI input and one process file per
                                   running command (removed when it ends)
    criu.conf criu-work/          protected runtime/checkpoint work
  layers/<sha256>.erofs            trusted immutable EROFS images: template bases and
                                   sealed capture layers, content-addressed
  lowers/<sha256>/                 shared read-only EROFS mounts of those layers
  checkpoints/<manifest-sha256>/   node cache: CRIU images unpacked once per warm
                                   template manifest, shared read-only by restores
  checkpoints/<sha256>.unpacking/  unpack in progress; removed on failure and at worker start
  templates/<template-id>/
    manifest.json manifest.sha256
    checkpoint.tar                present only for warm templates
  staging/<template-id>/          unpublished capture; exclusively created by the
                                  one in-flight capture reserving that template ID;
                                  a failed removal blocks that ID until restart
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
User symlinks *inside* a sealed upper layer are legitimate workload state: they are
stored as symlinks in the EROFS image and resolved only inside the sandbox's mount
namespace, never followed as administrator paths. The checkpoint archive is
worker-produced and extracted by GNU tar with its default traversal/symlink
protections. There is no user-supplied archive or executable host path.

Lower mounts are shared by digest and are read-only, nodev/nosuid. Only these shared
EROFS images use the standard mount/loop facility. Each sandbox gets sibling
upper/work directories on the same supported local filesystem; OverlayFS uses
`lowerdir=<sealed layers, newest first>:<base>` and
`index=off,metacopy=off,redirect_dir=off,xino=off,nodev,nosuid`. No lower layer is
writable and no private block device is added. A capture seals the source's upper
directory into a new immutable EROFS layer (see below); a child mounts it as a lower
with its own fresh empty upper, so nothing is copied per create.

**Verified once per node.** A create checks only the manifest digest sidecar and
fields at admission. The create job then fully hashes each layer image this worker
does not already trust, before handing the mounts to the shared-lower thread (which
never hashes and refuses an untrusted layer). Creates hash in parallel on their own
operation threads; a per-digest turn makes two creates of the same new layer hash
it once, and creates whose layers are trusted never wait behind a hash. A capture
marks the layer it publishes as verified. Each result is kept as digest, size and
the image file's identity when hashed (device, inode, size, modification and change
time, read from the hashed file before and after reading it), and saved atomically
to `verified-layers.json`. A layer is trusted, in memory or after a restart, only
while its image is still administrator-owned, not group/other writable and has that
exact identity; any write, truncation, replacement or permission change alters the
identity and means hashing again, and a mismatching hash fails the create and drops
the entry. The state file is used only if it is a root-owned regular file that
group/others cannot write, at most 16 MiB and well-formed; otherwise every layer is
hashed again. A known digest whose manifest size differs is rejected. Mount flags
and backing image are checked on every use.

A warm template's `checkpoint.tar` is fully hashed and unpacked once into
`checkpoints/<manifest-sha256>/` under a per-key turn: concurrent restores of the
same manifest wait for that unpack and later ones reuse the directory. GNU tar does
not sync what it writes, so the worker calls `syncfs` on the staging directory (one
filesystem) and syncs the directory itself before renaming
`<key>.unpacking` to `<key>` and syncing `checkpoints/`; a crash cannot leave
truncated images under the final name. A failed unpack removes its `.unpacking`
directory (after all helpers drained); start-up removes any left by a crash. The
renamed directory is the "verified" record and survives worker restarts. CRIU only
reads the images; the gate checks the cache is unchanged by restores. Published
artifacts must still never be modified in place: the cache directory is not
re-checked, and a layer changed in a way that keeps its identity (only possible by
resetting the clock or with raw device writes) is not re-detected.

Deletion checks mountinfo before recursive private removal, never uses lazy unmount
or broad recursive mount deletion, and never deletes shared templates/images.
Shared lowers are unmounted only after all owned workloads have been cleaned during
shutdown/reconciliation; images/templates/checkpoint caches are retained indefinitely. Cache eviction,
artifact deletion API, S3 transfer and disk quotas are not implemented. Operators
must provision an appropriately bounded dedicated filesystem/quota and monitor free
space. A filesystem failure stops admission; old durable ownership still permits
termination/cleanup.

## Manifest v3

Strict JSON fields (unknown fields are rejected):

| Field | Meaning |
| --- | --- |
| `schema_version` | Exactly `3`; v1/v2 (per-create `upper.tar`) templates are rejected, not silently migrated |
| `template_id`, `generation` | Validated immutable publication ID and worker-generated capture-generation ID |
| `runtime` | Exactly `runc_criu` |
| `compatibility` | Architecture, exact kernel release, SHA-256 of CPU feature string, exact runc and CRIU version output, fixed mount/network/seccomp layout version |
| `base` | `{ "sha256": "...", "bytes": ... }` for `layers/<digest>.erofs` |
| `layers` | Sealed capture layers above the base, newest first, each a descriptor for `layers/<digest>.erofs`; empty for cold, 1–16 for warm (a capture of a warm child adds one) |
| `checkpoint` | Null for cold, or the descriptor of `checkpoint.tar` (CRIU images) from the same frozen instant as `layers[0]` |
| `init_argv` | Trusted absolute in-container executable + argv; not an OCI config/host executable |
| `memory_mib`, `vcpus` | Cold: optional create defaults (1–1,048,576 MiB, 1–4,096); warm: required, exact captured resources |
| `pids_max` | Exact configured pids limit |
| `oci_config_sha256` | Null cold; warm SHA-256 of canonical worker-generated OCI JSON, with private cgroup, guest-netns and CRIU-config paths replaced by fixed reconstruction markers |
| `network` | Strict tagged `isolated` or `tcp_allowlist` policy; see API. Endpoints remain fixed across capture. |
| `uid`, `gid` | Exactly `65534`, `65534` |

`compatibility` is emitted by read-only `preflight` and has exactly:
`architecture`, `kernel`, `cpu_features_sha256`, `runc_version`, `criu_version`,
`init_sha256` (SHA-256 of the trusted static `tini` the worker bind-mounts as PID 1;
restored processes map it), `layout`. The OCI network-policy digest annotation is
preserved during normalization; the init's host path is normalized like the other
worker-local paths. `layout` is
`erofs-sealed-layers-v3-fixed-slot-tcp-established-pmtu-v1-seccomp-v4-agentenv-tini-v1`. The seccomp profile is the
default-allow AgentENV pattern described below; templates captured under earlier
layouts (deny-by-default seccomp, per-create upper archives, no reaping init) are rejected. Older layout
fingerprints are incompatible rather than silently reinterpreted. The local fixture
script demonstrates complete cold publication; do not guess compatibility strings.
Exact matching deliberately rejects more hosts than might technically work. Version
matching is necessary, **not sufficient proof of CRIU portability**.

## Capture, file identity and recovery

The worker excludes overlapping mutations of the same sandbox; different sandboxes
run on a bounded operation pool. Capture follows the AgentENV container backend and
**never stops the source**:

1. `runc pause` freezes the source's cgroup.
2. While frozen: read each task's `/proc/<pid>/maps` for a `[uprobes]` mapping (left
   by a host tracing/security agent), `syncfs` the overlay and build an EROFS image
   of the upper directory with `mkfs.erofs` (uncompressed; overlay whiteouts,
   opaque-directory xattrs, ownership, modes and other xattrs kept).
3. `runc checkpoint --leave-running --tcp-established --ext-unix-sk --file-locks`,
   with `network-lock nftables` and `skip-in-flight` (plus `allow-uprobes` when step
   2 found uprobes) in the per-container CRIU config.
4. `runc resume` thaws the source. The source is stopped from step 1 to step 4; the
   gates report the cgroup-freezer time inside it (CRIU briefly thaws the cgroup
   while the tasks stay ptrace-stopped, so freezer time slightly undercounts) and
   the longest gap a client or counter saw.
5. Outside the window: hash the sealed layer, archive the images into
   `checkpoint.tar` (GNU tar, numeric ownership/xattrs), write the manifest, publish
   the layer as `layers/<sha256>.erofs` without replacing an existing file (same
   digest = same content), then sync and atomically rename the staged template.

On an ordinary failure the worker thaws the source and keeps it if runc reports it
running; CRIU leaves dumped tasks alive, so a failed dump is not treated as
terminating the source (the gate forces a dump failure with an undumpable file and
checks the source keeps running). A source that stays frozen, or was
cancelled/expired, is deleted. So is a source whose `runc checkpoint` was stopped at
its command deadline or output limit (`checkpoint_interrupted`): a killed CRIU can
leave its network lock, sockets in repair mode or parasite code behind, so the state
is uncertain even if runc reports it running (the gate stops the checkpoint helper
and checks the source is deleted). A source template already at 16 sealed layers is
refused before the pause (`template_layer_limit`). A layer published before a later step failed stays in `layers/`
(content-addressed, retained like every layer). Failed/stale staging is removed
without touching live mounts or published templates.

`skip-in-flight`: clients that connect while the source is frozen wait unaccepted in
a listen backlog, which CRIU otherwise refuses to dump (observed in the image gate).
The running source still serves them after the thaw; children never had them.

Children mount the sealed layer(s) above the same base with a **new empty upper**
and a fresh work directory. The worker writes a new OCI bundle/private cgroup and
asks runc to restore into the new container ID from the node's shared checkpoint
cache, with `--tcp-established --ext-unix-sk --file-locks --manage-cgroups-mode
ignore` and restore-only `allow-uprobes`, `mntns-compat-mode` and `network-lock
nftables` (the AgentENV restore options plus the lock method). Cgroup restoration
uses runc's target cgroup setup, not source-cgroup adoption. Unlinked open files and
broader runtime state may be rejected.

**Established TCP.** Connections are dumped and restored in TCP repair mode. Every
sandbox, isolated or not, runs in a worker-created guest network namespace (runc
always checkpoints the network namespace as empty, so CRIU restores no links or
addresses itself), and every guest has the same fixed IPv4 address, so a captured
socket's local address exists in any child. Loopback connections inside the sandbox
continue in the child (both ends are restored). A connection to an external peer
is restored only on the child's side: its peer, the source slot's conntrack/NAT
state and its SNAT address are not cloned, so that connection fails in the child on
first use, while the source keeps it.

**Sealed layers do not preserve host inode numbers.** The implementation keeps
upper/lower roles stable and relies on the supported runc/CRIU mount/file reopening
path (files open in the source reopen from the sealed lower and copy up on write),
not on an assertion that inode changes are harmless. The real fixture holds lower
and upper descriptors/mappings open, an ESTABLISHED loopback connection, and checks
an in-memory random nonce and counter across capture and independent restore. It
also checks the sealed layer itself: a whiteout for a deleted base file, and the
modified base file with its owner, mode and a `user.` xattr. That targeted gate
**passed with the local static fixture, runc 1.3.6 and CRIU 4.3**. It does not
establish compatibility for arbitrary open/unlinked files, other workloads or
hosts. Cross-node reconstruction and different CPU/kernel combinations are
unqualified.

## Admission, operations and cleanup

Worker admission is serialized with durable record creation before any resource
side effect. Memory, live slots, restore slots and a configured 1–16 CPU quota
oversubscription factor are checked against existing reservations, not controller
snapshots. The coordinator performs only durable state/admission transitions, not
blocking runtime tools. A fixed 1–64-thread pool bounds create/capture/delete
concurrency, per-sandbox exclusion serializes each lifecycle, and separate restore
slots bound create/capture/restore. Commands are admitted by the same coordinator
(not while a create, capture or delete of that sandbox is in flight; a capture is
refused while any command runs) and run on their own threads, bounded per sandbox
(`max_execs_per_sandbox`) and per worker (`max_concurrent_execs`). Shared lower mount creation has its own bounded mailbox;
there is no shared-state lock across mount/process I/O. Template names in capture
are reserved against concurrent publication. The mailbox is bounded.
Create admission also reads the bounded template manifest on the coordinator thread
(never a Tokio thread) and resolves default resources before the record is written.
Each admitted job carries a one-shot reply: the waiting management request receives
the job's real outcome. Neither a client disconnect nor an expired wait cancels a job
owned by the coordinator; its result is simply discarded. The exception is a create
whose reply cannot be delivered: nobody can learn that generated ID, so the
coordinator requests deletion (`create_response_lost`). A capacity rejection writes
no record. Results are never stored,
so records hold only lifecycle metadata. Tombstones are bounded by `max_records` and
retained; no automatic pruning can silently reopen an ID.

Network policy and cgroup limits precede runc launch and restore. A slot index is
reserved in the durable record before network side effects. Router slots are
pre-created per worker root (`slots/<index>` ownership directories, default-deny
base rules) and reset, not deleted, when a sandbox is released; restart and shutdown
delete them, and restart builds a fresh pool. Unique root/sandbox guest namespace
names, root/index slot names, exclusive ownership markers and bounded helper cgroups
cover creation, cancellation and restart; unexplained namespace or slot state fails
closed. Cleanup retains the reservation/marker on failures and retries without
global flushes. See [network details](network.md).
PID 1 of every sandbox is the operator-staged static `tini` (a required trusted tool,
checked static by preflight), bind-mounted read-only at `/.sandbox-init`. It runs the
template's `init_argv` as its child, forwards signals and reaps orphaned processes
(for example killed exec descendants), and is checkpointed with the workload. Its
stdio, like the workload's, is `/dev/null`: detached runc runs/restores inherit
`/dev/null`, which CRIU can restore (a pipe hangs a detached run; a file is not
restorable), and runc's own log goes to `/dev/null`. The workload has UID/GID
65534, empty capabilities, no_new_privs, minimal /dev, its own proc/PID/mount/net/IPC/
UTS/cgroup namespaces and a seccomp profile matching the AgentENV container backend:
`SCMP_ACT_ALLOW` by default, with only two checkpointability guards that CRIU needs:
`io_uring_setup/enter/register` return ENOSYS and `socket(..., IPPROTO_MPTCP)` returns
EPROTONOSUPPORT, so libraries fall back. Seccomp is not an isolation layer here:
isolation relies on the namespaces, empty capabilities (so mount, namespace creation,
ptrace, raw/packet sockets and similar privileged operations fail), no_new_privs,
cgroups and network policy (a worker-created guest namespace with only loopback when
isolated; router-namespace nftables for `tcp_allowlist`). Workloads may create any unprivileged socket family; network
reachability is decided by the namespace and its rules, not by socket filtering.
Host authority, not workload privilege, performs checkpoints. This profile is
unqualified for general applications.

TTL has a separate cgroup-kill watchdog so a long archive cannot keep an expired
workload running until a job completes. Deletion durably records cancellation and
signals active jobs; cleanup waits for the sandbox's in-flight job rather than
racing it, and for its running commands, which it stops. Concurrent DELETE requests
of one sandbox all wait for that one cleanup and receive its result (AgentENV's
wait-for-transition; at most 64 waiters). Every exec runs on its own thread in its
own child cgroup `<sandbox cgroup>/exec-<n>` (`runc exec --cgroup`), several at once
per sandbox, and kills/removes its group when it ends, so descendants are cleaned
on successful completion too, including children that keep stdout/stderr open.
Exec clamps its deadline to remaining TTL; a deadline, output overflow, kill request
or sandbox deletion kills **only that command's group**, never the sandbox. A group
that cannot be emptied within five seconds deletes the sandbox (fail closed). Delete
first kills the owned cgroup (all descendants), removes leftover `exec-<n>` groups
(any other child group is unknown state and fails), force-deletes private runc
state, checks for no populated cgroup, unmounts the private overlay, then removes
private state.
Reservation release follows successful cleanup exactly once. Failure remains
`cleanup_failed`, reserved, observable and retryable. Never recurse into a live mount.

On restart, records are loaded and ownership validated before admission. Previously
live/interrupted workloads are killed/cleaned, in-flight requests lose their responses, and stopped
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
symlink inputs, command descendants, concurrent/streamed/killed/bounded commands that
keep the sandbox, client disconnect mid-exec and mid-create, in-flight exec/capture/
proxied-stream restart cleanup. Host trust was not qualified: the approved validation host used
administrator-staged binaries but retained indirect system library/fixed-shell
dependencies. No performance, S3, general hostile-workload isolation or two-node
result is claimed.
