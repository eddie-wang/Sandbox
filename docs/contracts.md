# Local runtime and storage contracts

These describe implemented code paths and serialized metadata. The bounded local
fixture passed on one approved host; this is **not general isolation or checkpoint
portability qualification**. Only native Linux runc + CRIU is supported.
No alternate runtime adapters, plugin framework or storage daemons are used.
Each sandbox has a private loop-mounted ext4 image for its OverlayFS upper/work.

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
    writable.ext4                 sparse private ext4 image (default logical size 1 GiB)
    loop                          private block-device node, mode 0600
    upperfs/upper/ upperfs/work/   inside the private ext4 mount at upperfs/
    rootfs/                       OverlayFS over the unchanged EROFS base
    config.json exec-<n>.json     worker-authored OCI input and one process file per
                                   running command (removed when it ends)
    criu.conf criu-work/          protected runtime/checkpoint work
  private/upper-pool/<slot>/     idle warm copy: writable.ext4, loop and mounted upperfs
  scratch/<mib>.ext4              immutable formatted cold image, one per capacity
  scratch/<mib>.creating/         interrupted formatting, discarded on restart
  layers/<sha256>.erofs            trusted immutable EROFS template bases, content-addressed
  lowers/<sha256>/                 shared read-only EROFS mounts of those layers
  checkpoints/<manifest-sha256>/   node cache: CRIU images and writable.ext4 verified once
                                   per warm manifest, never mounted or written in place
  checkpoints/<sha256>.unpacking/  unpack in progress; removed on failure and at worker start
  templates/<template-id>/
    manifest.json manifest.sha256
    checkpoint.tar                warm only: CRIU images + sparse writable.ext4 (GNU pax tar)
    cpuinfo.img                   warm templates on x86-64: CRIU's CPU description
  staging/<template-id>/          unpublished capture; exclusively created by the
                                  one in-flight capture reserving that template ID;
                                  a failed removal blocks that ID until restart
  runc/                           private runc state root
  monitors/<sandbox-id>/          retained conmon exit/OOM evidence, not a guest mount
    conmon.pid init.pid           diagnostic PIDs, never used alone to signal a process
    started.json                  successful runtime start/PID handshake
    exit oom                      conmon exit code and optional OOM-event marker
    result.json                   synced exit/OOM summary saved before group deletion
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
User symlinks *inside* an upper are legitimate workload state: they are
stored in the ext4 image and resolved only inside the sandbox's mount
namespace, never followed as administrator paths. The checkpoint archive is
worker-produced and extracted by GNU tar with its default traversal/symlink
protections. There is no user-supplied archive or executable host path.

Lower mounts are shared by digest and are read-only, nodev/nosuid. Only these shared
EROFS images prefer file-backed mounts, selected by a tiny startup probe under the
worker root lock. Unsupported kernels use the standard loop facility; a failed
individual image never triggers fallback. Both forms verify mount flags and the
image source before reuse or restart cleanup. EROFS file-backed base mounts remain loop-free.
Each sandbox gets its own ext4 image and private loop device, with `upper` and `work`
inside `upperfs`. OverlayFS uses `lowerdir=<base>` and
`index=off,metacopy=off,redirect_dir=off,xino=off,nodev,nosuid` (never `volatile`).
Cold create copies a cached formatted scratch image; restore copies the immutable captured image. The
unchanged base and cloned inode tables preserve upper-file inode numbers and hardlinks.

**Writable quota and format.** `writable_mib` in the cold template defaults to 1024
(1 GiB), range 64–65536 MiB; captures retain it. The image must also fit the
worker's `max_artifact_bytes`: operators using the 1 GiB default must set that limit
to at least 1073741824 (older example configurations use a smaller limit). This is a logical filesystem capacity,
including metadata, not reserved host space. It comfortably accommodates a 450 MiB
uncompressed upper; compression of an EROFS base is not a guide to upper capacity.
Sparse files can still exhaust host disk space, which operators must monitor.
Following containerd blockfile, each requested cold capacity is formatted once in
a staged scratch entry, synced and atomically published; concurrent creates wait
for that entry and later creates/restarts copy it. Scratch images are never mounted
or changed. Interrupted formatting is discarded before readiness.
The formatter is `mkfs.ext4 -q -F -b 4096 -m 0 -E lazy_itable_init=0,lazy_journal_init=0`:
4 KiB blocks, no root-reserved capacity, and completed inode/journal initialization.
Ext4 retains its normal journal; mounts use `nodev,nosuid,noatime,errors=remount-ro`.
GNU `cp --reflink=auto --sparse=always` clones whole filesystems without rebuilding inodes;
copies are synced before mounting or publication. Image file caches are discarded
with `POSIX_FADV_DONTNEED` after copying; `LOOP_CONFIGURE` requires and verifies
`AUTOCLEAR|DIRECT_IO`, so ordinary sandbox I/O does not double-cache the backing image.

**Ready-copy pool.** `native.upper_pool_size` defaults to 32 (range 0–32, zero disables).
One bounded background worker prepares copies of the most recently requested warm
manifest: verified cache image copied, direct-I/O loop attached, ext4 mounted. Ready
copies are tagged by manifest digest in memory. A create claims only an exact match;
an empty or mismatched pool uses the synchronous path without waiting for refill.
Requests for another template replace unused older entries; there is no unbounded
per-template multiplication. This adapts the existing ready-slot/synchronous-fallback
network pool, not a new service. It does not speed the very first empty-pool burst.

Each pool directory exists and its parent is synced before allocation. Handoff renames
that whole directory under the sandbox's already-durable record, syncing both parents;
a slot cannot refill until handoff finishes. Failed cleanup retains ownership and blocks
pool use. Restart discards every idle/interrupted pool entry before readiness. Shutdown
joins the refiller before normally releasing its mounts/loops. Pool files live beneath
`private/` so existing disk accounting includes idle copies; their logical capacity can
total `upper_pool_size × writable_mib`, with allocated space proportional to copied data.
Operator disk quotas must include these copies, scratch, templates and cache.

**Loop ownership.** Allocation uses `/dev/loop-control` and `LOOP_CTL_GET_FREE`,
retrying allocation races within the helper deadline. A worker-owned private 0600
block node (major 7, returned minor) avoids dependence on the host/pod's static
`/dev/loopN` inventory. No global device nodes are added or removed. The open loop
handle is retained through mounting. Cleanup verifies backing device/inode and mount
identity, thaws interrupted captures, unmounts without lazy detach, detaches only its
own association, waits for release, then removes the private image/node. A reused
loop is never detached. Durable sandbox records precede allocation and restart
reconciliation uses the same teardown. Preflight checks ext4 and loop-control;
startup actively mounts an ext4/loop/overlay probe and fails closed if unavailable.

Design references (fresh Rust integration, not copied third-party source):
- [GNU tar sparse formats](https://www.gnu.org/software/tar/manual/html_node/sparse.html):
  pax sparse format 1.0, hole maps and default SEEK_DATA/SEEK_HOLE detection. GNU
  [cp sparse copies](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)
  preserve holes, using reflinks where supported.
- Linux v6.12 `fs/ext4/ioctl.c:806–857` and `include/uapi/linux/ext4.h`:
  shutdown with NOLOGFLUSH aborts journal work; repeated shutdown is harmless.
  xfstests `src/godown.c` opens a mount and issues the same no-log-flush ioctl.
  The kernel's `Documentation/admin-guide/ext4.rst` describes the ext4 ioctl interface.
- AgentENV `src/sandbox/container/sandbox.rs:256–300,480–504`: private block-backed
  ext4 and pause/freeze/restack/thaw before CRIU leave-running.
- containerd v2.0.0 `plugins/snapshots/blockfile/blockfile.go:374–416,451–479`:
  copy a parent/scratch image and sync it; `core/mount/losetup_linux.go:48–60,89–116,170–193`:
  loop-control allocation, atomic configure, autoclear/direct-I/O and busy retries.
- Apptainer v1.4.2 `pkg/util/loop/loop.go:184–245,360–368,436–447`: create missing
  loop block nodes when a container has a static `/dev`. Sandbox confines nodes to
  its private directory, rather than modifying `/dev`.

**Verified once per node.** A create checks only the manifest digest sidecar and
fields at admission. The create job then fully hashes each layer image this worker
does not already trust, before handing the mounts to the shared-lower thread (which
never hashes and refuses an untrusted layer). Creates hash in parallel on their own
operation threads; a per-digest turn makes two creates of the same new layer hash
it once, and creates whose layers are trusted never wait behind a hash. Each result is kept as digest, size and
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

A warm template's joint `checkpoint.tar` is fully hashed once, including GNU tar's
sparse map and all stored image data. Holes are not stored or hashed as logical zero
bytes; integrity still covers every archive byte. The archive is sparsely unpacked into
`checkpoints/<manifest-sha256>/` under a per-key turn: concurrent restores of the
same manifest wait for that unpack and later ones reuse the directory. GNU tar does
not sync what it writes, so the worker starts write-back of each extracted file,
then syncs those files and directories (not the unrelated host filesystem) before renaming
`<key>.unpacking` to `<key>` and syncing `checkpoints/`; a crash cannot leave
truncated images under the final name. A failed unpack removes its `.unpacking`
directory (after all helpers drained); start-up removes any left by a crash. The
renamed directory is the "verified" record and survives worker restarts. CRIU only
reads its images; each restore copies the cached ext4 image to its own private image; the gate checks the cache is unchanged by restores. Published
artifacts must still never be modified in place: the cache directory is not
re-checked, and a layer changed in a way that keeps its identity (only possible by
resetting the clock or with raw device writes) is not re-detected.

After workload drain, deletion verifies the owned ext4 mount/loop identity and uses
`EXT4_IOC_SHUTDOWN` with `EXT4_GOING_FLAGS_NOLOGFLUSH` before unmounting overlay/ext4.
These private copies are disposable: dirty data and journal work are discarded, not
flushed. This is never used on the source during capture, on scratch or cached images.
Normal (not lazy) unmount, loop release and unlink must finish before reservations
are released; failures retain ownership for retry. Deletion checks mountinfo before
recursive private removal and never deletes shared templates/images.
Shared lowers are unmounted only after all owned workloads have been cleaned during
shutdown/reconciliation; images/templates/checkpoint caches are retained indefinitely. Cache eviction,
artifact deletion API and S3 transfer are not implemented. Per-sandbox writable
capacity is bounded by the ext4 image; shared artifact/cache disk quotas are not implemented. Operators
must provision an appropriately bounded dedicated filesystem/quota and monitor free
space. A filesystem failure stops admission; old durable ownership still permits
termination/cleanup.

## Manifest v5

Strict JSON fields (unknown fields are rejected):

| Field | Meaning |
| --- | --- |
| `schema_version` | Exactly `5`; all older templates (including raw-image and sealed-EROFS uppers) are rejected, not silently migrated |
| `template_id`, `generation` | Validated immutable publication ID and worker-generated capture-generation ID |
| `runtime` | Exactly `runc_criu` |
| `compatibility` | Architecture, exact kernel release, exact runc and CRIU version output, init digest, fixed mount/network/seccomp layout version (no CPU fingerprint; see `cpuinfo`) |
| `base` | `{ "sha256": "...", "bytes": ... }` for `layers/<digest>.erofs` |
| `layers` | Must be empty; warm snapshots no longer change the immutable lower stack |
| `writable_mib` | Ext4 image logical capacity, default 1024 MiB; must match the captured image length |
| `checkpoint` | Null for cold, or the SHA-256/byte-count descriptor of `checkpoint.tar`: CRIU images and sparse `writable.ext4` from the same frozen instant |
| `cpuinfo` | Null for cold; for warm templates on x86-64, the descriptor of `cpuinfo.img`, CRIU's description of the capturing host's CPU (`criu cpuinfo dump`, written just before the freeze). On other architectures CRIU writes none and the field is null |
| `init_argv` | Trusted absolute in-container executable + argv; not an OCI config/host executable |
| `memory_mib`, `vcpus` | Cold: optional create defaults (1–1,048,576 MiB, 1–4,096); warm: required, exact captured resources |
| `pids_max` | Exact configured pids limit |
| `oci_config_sha256` | Null cold; warm SHA-256 of canonical worker-generated OCI JSON, with private cgroup, guest-netns and CRIU-config paths replaced by fixed reconstruction markers |
| `network` | Strict tagged `isolated` or `tcp_allowlist` policy; see API. Endpoints remain fixed across capture. |
| `uid`, `gid` | Exactly `65534`, `65534` |

`compatibility` is emitted by read-only `preflight` and has exactly:
`architecture`, `kernel`, `runc_version`, `criu_version`,
`init_sha256` (SHA-256 of the trusted static `tini` the worker bind-mounts as PID 1;
restored processes map it), `layout`. The OCI network-policy digest annotation is
preserved during normalization; the init's host path is normalized like the other
worker-local paths. `layout` is
`erofs-ext4-upper-v5-sparse-tar-cni-ptp-static-v1-mtu<value>-tcp-established-pmtu-v1-seccomp-v5-moby-28.3.3-nocaps-tini-v1-conmon-null-v1`
where `<value>` is the configured MTU (1500 without network configuration).
Pre-CNI templates, templates with another MTU, and the former default-allow seccomp
layout are rejected. The current profile is the generated Docker deny-by-default
allowlist described below. Older layout fingerprints are incompatible rather than
silently reinterpreted; republish cold templates and recapture warm templates. The local fixture
script demonstrates complete cold publication; do not guess compatibility strings.
Exact matching deliberately rejects more hosts than might technically work. Version
matching is necessary, **not sufficient proof of CRIU portability**.

CPU compatibility of a warm template is CRIU's own decision, as AgentENV leaves it
(AgentENV fingerprints no CPU features): before a create of a warm template is
admitted, the worker verifies `cpuinfo.img` against its descriptor and runs
`criu cpuinfo check --images-dir templates/<id>` (default capability set) with a
5 s deadline. A failing check is a pre-launch `template_unavailable` (no ID, no
record), so the controller tries another node. The answer is remembered per
`cpuinfo.img` digest for the worker's lifetime (a check that could not finish is
not remembered); only success or explicit CRIU CPU-comparison refusals are cached,
not environment, image-read, helper or deadline failures. One bounded CPU-check
thread serves at most 16 queued descriptions and 64 waiting creates, outside the
admission coordinator; waiters reserve no sandbox resources. A capture remembers
its own host as compatible. The check can be
**one-directional**: CRIU may accept a template captured on host A when restoring
on host B, but refuse the reverse (for example when only A has `xsaves`). CRIU's
restore repeats its own check.

Templates published with the removed `compatibility.cpu_features_sha256` field
must be republished before upgrading; strict manifest parsing rejects them,
including cold templates. There is no silent migration.

## Capture, file identity and recovery

The worker excludes overlapping mutations of the same sandbox; different sandboxes
run on a bounded operation pool. Capture follows the AgentENV container backend and
**never stops the source**:

0. Before the freeze, `criu cpuinfo dump` writes the host's CPU description as
   `cpuinfo.img` into the staging directory (x86-64; see `cpuinfo` above).
1. `runc pause` freezes the source's cgroup.
2. While processes are frozen, inspect their maps for uprobes, freeze the private
   ext4 filesystem with `FIFREEZE`, sparse/reflink-copy `writable.ext4` to staging,
   sync the copy and thaw ext4 with `FITHAW`. No inode table is rebuilt. Copy errors
   still trigger thaw; restart cleanup also thaws a filesystem left frozen by a killed worker.
3. `runc checkpoint --leave-running --tcp-established --ext-unix-sk --file-locks`,
   with `network-lock nftables` and `skip-in-flight` (plus `allow-uprobes` when step
   2 found uprobes) in the per-container CRIU config.
4. `runc resume` thaws the source. The source is stopped from step 1 to step 4; the
   gates report the cgroup-freezer time inside it (CRIU briefly thaws the cgroup
   while the tasks stay ptrace-stopped, so freezer time slightly undercounts) and
   the longest gap a client or counter saw.
5. Outside the window: GNU `tar --format=pax --sparse` packs the immutable image
   copy together with the process images into `checkpoint.tar`; hash that archive,
   write the manifest, sync and atomically rename the staged template. No raw image
   hashing or live-image archiving occurs. Cross-node transfer includes the joint
   archive, `cpuinfo.img`, manifest/sidecar and referenced EROFS base.

On an ordinary failure the worker thaws the source and keeps it if runc reports it
running; CRIU leaves dumped tasks alive, so a failed dump is not treated as
terminating the source (the gate forces a dump-helper failure and
checks the source keeps running). A `runc checkpoint` stopped at its command
deadline or output limit gets the same AgentENV thaw-and-keep handling but its own
code, `checkpoint_interrupted`: a killed CRIU can leave its network lock, sockets in
repair mode or parasite code behind in a source that runc still reports running, so
the caller decides whether to delete it (the gate stops the checkpoint helper until
the deadline and checks the source keeps running). A source that stays frozen, is not
running after the thaw, or was cancelled/expired, is deleted (the gate kills a
source's processes during its dump and checks it is deleted). Failed/stale staging
is removed without touching live mounts or published templates. Chained captures
replace the saved writable image, not the base, and add no EROFS layers.

`skip-in-flight`: clients that connect while the source is frozen wait unaccepted in
a listen backlog, which CRIU otherwise refuses to dump (observed in the image gate).
The running source still serves them after the thaw; children never had them.

Children mount their own **copy of the captured ext4 image**, retaining the same
upper/work relative layout, over the unchanged base. The worker writes a new OCI bundle/private cgroup and
asks runc to restore into the new container ID from the node's shared checkpoint
cache, with `--tcp-established --ext-unix-sk --file-locks --manage-cgroups-mode
ignore` and restore-only `allow-uprobes`, `mntns-compat-mode` and `network-lock
nftables` (the AgentENV restore options plus the lock method). Cgroup restoration
uses runc's target cgroup setup, not source-cgroup adoption. Adding OCI whole-group
OOM configuration changes the normalized spec digest: warm templates captured before
that change must be recaptured; they are not silently restored with a different spec. Unlinked open files and
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

**Inodes are preserved; device numbers are not.** The block clone retains upper
inode numbers and hardlinks (including copied-up base files) without manufacturing
an EROFS upper. `runtime_smoke.py` checks source/two-copy inode equality, hardlink
writes and independent contents, chained capture and loop/image/mount cleanup on
delete and killed-worker restart. `image_e2e.py` keeps a stock SQLite DELETE-journal
connection open across capture and requires its next write in both copies to succeed
without `SQLITE_READONLY_DBMOVED`, with source/copy row isolation.

**Explicit tested limitation, not a fidelity pass:** SQLite's in-process lock sharing
between a retained pre-capture connection and a newly opened post-restore connection
is not preserved. SQLite keys that bookkeeping by both device and inode; each copy
has a different device number. The image gate performs two `BEGIN IMMEDIATE`
operations then rolls back without modifying pages: the source must reject the
second writer with `SQLITE_BUSY`, while restored copies currently admit it. This
limitation also existed before ext4 cloning. Inode preservation fixes DBMOVED, not
full SQLite transaction fidelity; affected multi-connection workloads remain
unqualified. No reconnect, WAL switch, application patch or error filtering is used.
Arbitrary open/unlinked files, other workloads, cross-node reconstruction and
different CPU/kernel combinations remain unqualified.

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

Network policy precedes runc launch and restore. The slot's default-drop boundary
also precedes CNI ptp/static ADD; per-attachment configs, ADD intents and results are
persisted in `private/<id>/cni.json`. Failed ADDs receive DEL; teardown walks attempted
plugins in reverse with the cached result and retries failed entries. Missing guest
pins use empty `CNI_NETNS`; static has no persistent allocation database. CNI host
operations run only in the routing slot, not the worker/pod shared network namespace.
The fixed guest `eth0`/`192.0.2.2` survives reconstruction, while MACs may differ.
Both CNI link MTUs and the full chain are checked before custom policy and launch. runc alone creates/configures each
sandbox cgroup from OCI memory/swap/CPU/pids/device limits and
`linux.resources.unified["memory.oom.group"] = "1"`, before workloads execute.
Equal OCI memory/swap limits disable swap; cgroupfs is used, never systemd. A slot index is
reserved in the durable record before network side effects. Router slots are
pre-created per worker root (`slots/<index>` ownership directories, default-deny
base rules) and reset, not deleted, when a sandbox is released. Restart rebuilds
unreserved slots but retains slots needed by unfinished cleanup outside the ready
pool, so failed CNI DEL can retry in its original routing namespace. Those retained
slots are destroyed after successful DEL, before reuse; shutdown deletes the pool
once cleanup is complete. Unique root/sandbox guest namespace
names, root/index slot names, exclusive ownership markers and bounded helper cgroups
cover creation, cancellation and restart; unexplained namespace or slot state fails
closed. Cleanup retains the reservation/marker on failures and retries without
global flushes. See [network details](network.md).
PID 1 of every sandbox is the operator-staged static `tini` (a required trusted tool,
checked static by preflight), bind-mounted read-only at `/.sandbox-init`. It runs the
template's `init_argv` as its child, forwards signals and reaps orphaned processes
(for example killed exec descendants), and is checkpointed with the workload. Its
stdio, like the workload's, is `/dev/null`: conmon's passthrough mode keeps the
runtime's inherited null descriptors (no logging pipes or attach API). Conmon is
outside the guest, subreaps init and persists exit/OOM files. Runc startup diagnostics
use the private `runc.log`, not workload stdio. The workload has UID/GID
65534, empty capabilities, no_new_privs, minimal /dev, its own proc/PID/mount/net/IPC/
UTS/cgroup namespaces and Docker's default seccomp allowlist (Moby v28.3.3), resolved
for native x86-64 with **no capabilities**, embedded as plain OCI `linux.seccomp`.
Other native architectures fail preflight. `defaultAction` is `SCMP_ACT_ERRNO` and
`defaultErrnoRet` is 1 (EPERM), exactly as in that upstream profile. Capability-only
allow rules are omitted; native-architecture, kernel and argument rules are preserved:
namespace-changing clone flags are denied, clone3 returns ENOSYS, personality is
argument-limited and AF_VSOCK sockets are denied. Mount, unshare, keyctl, bpf and
userfaultfd are denied. Upstream permits ptrace/process_vm_readv/process_vm_writev
on Linux >= 4.8 even without CAP_SYS_PTRACE; the normal kernel access checks still
apply. Do not describe ptrace as categorically blocked.

The two CRIU guards remain: `io_uring_setup/enter/register` return ENOSYS and
`socket(..., IPPROTO_MPTCP=262)` returns EPROTONOSUPPORT. The socket allow rule retains
upstream's family restriction as well as excluding MPTCP. Runc's upstream ENOSYS
fallback for syscall numbers beyond the profile's known maximum is retained, not
replaced with an allow rule or a hand-written syscall-number list. See
[syscall policy](runtime.md#syscall-policy) for generation, licensing and the distinction
from containers-common's ENOSYS-default variant.

This filter is defense in depth alongside namespaces, empty capabilities,
no_new_privs, cgroups and network policy (loopback only when isolated;
router-namespace nftables for `tcp_allowlist`). Ordinary UDP, IPv6 and Unix socket
creation is allowed; external reachability is decided by the namespace and its rules.
Host authority, not workload privilege, performs checkpoints. Local gates do not
qualify the shared-kernel boundary against hostile workloads or general applications.

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
first stops unfinished monitor startup, kills the workload group (all descendants),
removes leftover `exec-<n>` groups (other children fail closed), waits for conmon to
reap and persist exit/OOM evidence, then drains its separately owned monitor group.
Before runc can remove the workload group, cleanup saves `result.json` containing
`exit_code` (nullable), `oom` (an event/marker), `oom_kill` (nullable counter),
`monitor_lost` and `runtime_started`. A 137 exit alone is not classified as OOM.
Cleanup tries plain runc delete before force deletion, checks for no populated
group, unmounts the private overlay, then removes private state. Monitor evidence
stays with retained records and does not reserve capacity after successful cleanup.
Reservation release follows successful cleanup exactly once. Failure remains
`cleanup_failed`, reserved, observable and retryable. Never recurse into a live mount.

On restart, records are loaded and ownership validated before admission. Previously
live/interrupted workloads are killed/cleaned, in-flight requests lose their responses, and stopped
private resources and durable `.monitors-<root-digest>/<id>` groups are reconciled.
The monitor is never in a kill-on-return helper leaf. The watcher detects real init
exits from conmon's file and fails closed on monitor loss, not workload-group
emptiness. Unexplained runc/private/monitor/cgroup entries fail startup
rather than being silently adopted/deleted. Published templates survive source and
child deletion. Abrupt worker death does not itself kill containers; an operator
must restart the worker with the same root/config promptly to reconcile them.
The `-conmon-null-v1` layout requires republished cold and recaptured warm templates;
older templates are rejected even though the null-descriptor model is preserved.

## Qualification

Read-only preflight checks tools/versions, UID/capabilities, advertised filesystems,
namespace/seccomp interfaces, the private worker mount boundary and an existing
empty delegated cgroup domain with cpu/memory/pids enabled. It does **not** write an
xattr probe, run `criu check`, create a mount/namespace, enable a controller or prove
runtime behavior. Under the root lock, before request threads, worker startup probes
actual upper backing-directory d_type, user/trusted xattrs, ordinary overlay copy-up
and hardlinks, private ext4/loop direct I/O and mount-data size. It also mounts/reads a tiny
EROFS image to select file backing or loop fallback. Probes must clean up before
readiness; interrupted owned probes are cleaned on restart. The cached worker
preflight records `active_overlay_backing_features` and `overlay_volatile` (null in
read-only CLI preflight), plus EROFS mode. Actual seccomp compatibility,
restore cgroup placement and lifecycle/isolation/cleanup claims require the
privileged gate. The static-fixture local gate passed, including independently
overlapping commands, final worker admission, rejected template compatibility/digest/
symlink inputs, command descendants, concurrent/streamed/killed/bounded commands that
keep the sandbox, client disconnect mid-exec and mid-create, in-flight exec/capture/
proxied-stream restart cleanup. Host trust was not qualified: the approved validation host used
administrator-staged binaries but retained indirect system library/fixed-shell
dependencies. No performance, S3, general hostile-workload isolation or two-node
result is claimed.
