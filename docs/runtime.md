# Explicitly privileged real-runtime qualification

**Targeted functional gate passed on one explicitly approved Linux x86-64 host,
with runc 1.3.6, conmon 2.1.10 and CRIU 4.3.** The real script exercised shared EROFS/private OverlayFS,
capture without stopping the source (pause, sealed EROFS layer, `--leave-running`),
established loopback TCP and independent restored memory/file state, the node
checkpoint cache, the reaping PID 1, concurrent, streamed and killed commands,
waiting concurrent DELETEs, admission, per-command bounds that keep the sandbox,
TTL/delete and crash/restart cleanup. Compilation and the nonprivileged HTTP smoke
also passed, but are not substitutes for this gate. The network variant also passed
inside a disposable outer network/mount namespace, including policy, the app proxy
(path and host forms, streaming, binary, chunked, bounds), listening-socket restore
and helper cleanup.
General hostile-workload isolation, host trust, other kernels/applications,
cross-node portability and capacity remain unqualified.

## Prerequisites and authority

An operator must separately provision and approve:

- Root/host authority, including mount/namespaces, ptrace, cgroup, mknod, ownership,
  UID/GID/capability setup and resource-limit capabilities. A rootless/containerized
  shell with missing capabilities is not enough.
- EROFS and OverlayFS **already available** in the kernel. File-backed EROFS needs
  Linux 6.12+ with `CONFIG_EROFS_FS_BACKED_BY_FILE`; older kernels need available
  loop device nodes for the shared lowers. No module loading or package installation
  is done by the service/script.
- Trusted standard `runc`, **`conmon` 2.1.10**, `criu`, `mount`, `umount`, GNU `tar`, `mkfs.erofs`, `ip`,
  `nft`, `iptables`, `iptables-save`, `iptables-restore`, `ip6tables-save`,
  `ip6tables-restore`, `gzip`, **CNI `ptp` and `static`** (protocol 1.0.0), and a **statically linked `tini`** (preflight rejects a
  dynamic one: it is bind-mounted read-only into every sandbox as PID 1, so it must run
  in any image; its SHA-256 is part of the template compatibility fingerprint). Take
  `tini` from a trusted, verified package (for example the distribution's static tini
  or the tini-based `docker-init` of an installed, signature-verified Docker package)
  and stage it like the other tools; never download an unverified binary. CRIU uses
  namespace firewall-state helpers and gzip for tmpfs images; these are not workload
  egress support. GNU tar also invokes its
  fixed `/bin/sh`, and dynamic binaries depend on system libraries/loaders. Review
  administrator system CRIU configuration; request options do not replace host trust.
  For the smoke: Python 3, a C compiler with static libc, `nsenter`, sandboxd and
  `strace` with syscall fault injection (qualified with 6.8). The runtime gate uses
  path-filtered faults on its own worker threads, never on runtime children.
  No rootfs or tool downloads are performed by the smoke.
- A new dedicated administrator-owned root with actual OverlayFS d_type and
  user/trusted-xattr support; XFS needs ftype=1. Startup tests the backing directory,
  not a filesystem-family allowlist or kernel release. All ancestors must be owned by UID 0,
  not group/other writable and not symlinks. Give the root private permissions.
  Supply operator disk capacity/quota; the worker does not implement disk quotas.
- An operator-provided **pod-private mount namespace**: the covering mounts of the
  worker root and `/run` must be private (neither shared nor slave). Provide a trusted
  `/run/netns` directory inside this boundary. Startup never changes `/` or a host
  ancestor; it rejects unsafe propagation, locally privatizes existing netns anchors
  before threads, and lets `ip` share that anchor only inside the private parent.
- An **existing, exclusive cgroup-v2 domain parent**, not the cgroup filesystem root.
  It must have no processes in `cgroup.procs`; `cgroup.subtree_control` must already
  contain `cpu memory pids`, and cgroup.kill/swap accounting must be available.
  The worker service itself runs **outside** this parent. Its workload children and
  separately owned `.helpers-<root-digest>` host-command and `.monitors-<root-digest>`
  init-monitor subtrees belong inside it. Do not share the parent with another worker, root or service.
- Isolated validation-host access and trusted loopback ingress. Do not expose bearer
  HTTP on an untrusted network.

Neither `preflight` nor startup enables controllers, creates the parent, changes
host networking/firewall/sysctls, installs software, loads modules or invokes sudo.
Read-only preflight is deliberately not an active CRIU/xattr/kernel capability test.
Startup separately qualifies actual backing directories with bounded, tracked probes:
ordinary overlay, d_type, user/trusted xattrs, copy-up/hardlinks, volatile support and
mount-data length. Its cached preflight reports `active_overlay_backing_features`
and `overlay_volatile`; read-only CLI preflight leaves the latter null. Real process
checkpoint, restore, isolation and cleanup still require the gates below.

### Administrator-staged tools

By default the worker searches a fixed system path and verifies resolved executable
ownership/mode and trusted ancestors. An optional `[native].tools_dir` instead uses
**only that existing directory**, with the fixed basenames listed above. Its ancestors
and files must be UID 0-owned and not group/other writable; configured tool symlinks
are rejected. Missing tools fail closed with no system-PATH fallback. The worker
clears inherited environment (including loader variables) and gives runc/CRIU a
PATH assembled only from verified tool directories. Every required helper's first
executable resolution in that exact PATH must match the verified executable map;
shadowing (including a candidate rejected during discovery) fails preflight closed.
The same validated PATH is used for runtime and storage commands. Mount uses internal-only
mode rather than filesystem helpers. Unmount uses a tracked internal syscall helper,
with containerd-style EBUSY-only retry (50 attempts, 50 ms apart), the normal command
deadline and no lazy detach; errors retain backing files and reservations. API callers never select a host executable.
The service does not create/populate a tools directory or install dependencies.

If an administrator explicitly stages installed binaries, verify each source is a
regular root-owned non-writable file, copy into a unique trusted directory, preserve
source/destination SHA-256 inventory, and use `--tools-dir /var/lib/sandbox-tools`
with the smoke. Do not repair global directory permissions or silently relax checks.
The approved functional run needed such staging because the system binary ancestors
were not trusted by preflight. Fixed `/bin/sh` executable ownership was checked,
but shell ancestry and dynamic-library integrity were **not established**. Staging
is not a hardened-host qualification; production use needs a trusted system too.

### Cluster deployment boundary

Use the pod's private mount namespace, not the node's host mount namespace; do not
use bidirectional/host-to-container propagation for the worker root or `/run`.
Provision `/run/netns` in that pod namespace and retain the namespace across worker
process restarts so reconciliation can see old pins/mounts. If the inherited mounts
are shared, an operator entrypoint may make them private **inside the pod only**
before launching the worker. Startup validates this instead of changing node mounts.
The local gates use a disposable outer mount/network namespace for the same reason.

Delegate one empty cgroup-v2 parent to the worker; run the worker outside it. runc's
cgroupfs driver alone creates/configures sandbox children, including CRIU restore
with manage-cgroups ignore. The worker retains helper and exec children, whole-tree
kill and orphan cleanup. No in-pod systemd service is required. Stage **conmon 2.1.10**
from Canonical's noble `conmon` package (`2.1.10+ds1-1build2` in the local qualification)
with `apt-get download`, verify the archive signature/index and package SHA-256, then
extract with `dpkg-deb -x` and copy its executable root-owned into the trusted tools
directory. Do not install a system service or run `apt install` on the node. Include
conmon and its system-library dependencies in the worker image/tool inventory; the
worker verifies conmon ownership and its protocol version during preflight.
Also stage **`ptp` and `static`** from Canonical noble `containernetworking-plugins`
(`1.1.1+ds1-3ubuntu0.24.04.3` in the local qualification), using the same signed-index,
`apt-get download`, hash-check and `dpkg-deb -x` procedure. Copy the executables
from the extracted `usr/lib/cni` into the trusted tools directory with fixed basenames;
no CNI daemon, kubelet integration, host-local database or tuning plugin is needed.
Preflight checks both verified executables and their CNI 1.0.0 protocol support.
CNI runs with the router slot as its host namespace, never the node or pod shared
network namespace. Its guest target is the worker-owned pin. Configure
`[native.network].mtu` (default 1500, range 1280–9000) for the actual pod underlay;
it cannot exceed the existing stable-MAC bridge MTU. Ptp and both uplink ends use
this value; the worker verifies both CNI link MTUs and CNI CHECK before launching.
Keep the operator's bridge/outer routing and worker-owned nft allowlist/SNAT model.
Preserve the root and delegated monitor subtree across worker process restarts so
reconciliation can drain old monitors and replay persisted CNI DEL. The private
cluster harness must stage conmon and CNI, select its MTU, and republish templates:
pre-CNI layouts and layouts with a different MTU are rejected. No cluster run is
implied by the local qualification.

## Bounded command plan

Run the nonprivileged checks first:

```sh
cargo build --locked
python3 scripts/smoke.py --binary target/debug/sandboxd
python3 -m py_compile scripts/runtime_smoke.py scripts/image_e2e.py scripts/stress_smoke.py
cc -static -O2 -Wall -Wextra -Werror scripts/fixture.c -o target/smoke-fixture
```

Then, **only after explicit approval**, as the authorized administrator on the
prepared host (paths below are generic examples, not directories created by a
setup script):

```sh
python3 scripts/runtime_smoke.py \
  --allow-privileged-runtime \
  --binary target/debug/sandboxd \
  --root /var/lib/sandbox-validation \
  --cgroup-parent /sys/fs/cgroup/sandbox-validation
```

Any build works; the recorded gate runs use `cargo build --release --locked` and
`--binary target/release/sandboxd` (layer hashing in a debug build is several times
slower, which mainly shows in the first cold create of a large base).

The script refuses without both opt-in and UID 0. It creates a unique owned session
root under the already trusted directory and writes temporary configurations with
random environment-only credentials. It checks mount-inventory decoding and shared-boundary rejection with a small owned
temporary mount, then runs read-only preflight before workload launch; missing
prerequisites abort. It builds an original static C fixture,
creates a small EROFS image locally, publishes a digest-bound cold manifest, and
starts real worker/controller processes on ephemeral loopback ports.

Run this gate in an operator-prepared disposable outer mount/network namespace
with private propagation and a namespace-local `/run/netns`; do not make `/` private
in the host namespace to satisfy preflight. The network and image wrappers create
their own disposable outer namespace.

Hard validation budgets are **at most three simultaneously admitted containers,
64 MiB, one vCPU quota and 64 pids each**; worker aggregate reservation cap 192 MiB,
CPU-overcommit factor 3, two active restores, four fixed operation threads, 64 MiB per
artifact and 30-second host tool deadlines. No capacity/load benchmark, cluster job, package installation,
host veth/route/firewall/sysctl change, module loading or external network traffic
is part of the isolated command. The worker does create one owned, loopback-only
network namespace pin per sandbox under the existing `/run/netns` and removes it on
cleanup. `nsenter ... ip ... link show` only inspects an owned netns. Other workload
namespaces are created by runc/CRIU; there is no host-network mode.

## CNI qualification boundary

The fixed standalone chain follows libcni's config/result chaining and reverse-order
DEL semantics. Per-attachment config, intent and successful results live in
`private/<id>/cni.json`; an unsuccessful ADD still receives DEL, failed deletion
retains its ownership for retry, and a vanished guest supplies an empty `CNI_NETNS`.
The slot's default-drop filter is installed **before ADD**, because ptp raises links.
The exact custom policy is applied only after the full chain and validation succeed;
no workload can launch/restore earlier. CNI's own masquerading is off.

`network_smoke.py` checks the actual ptp-generated routes, fixed guest IP/eth0,
random link identities, 1500-byte MTU, cached configs/results, failed ADD rollback,
post-ADD cache failure under default drop, missing-namespace/repeated deletion,
slot reset/restart, allowlist/SNAT, PMTU and restore with `--tcp-established`.
A blocked startup DEL input write must retain its original slot across two worker
restarts, exclude it from new admission, then automatically finish cleanup after
the fault is removed, without manual namespace deletion. The retained slot must be
destroyed before its index is rebuilt for a new sandbox.
CRIU uses an external/empty supplied netns: no saved MAC or host-interface name is
replayed. Established loopback and listening sockets must continue in cold, warm
and chained copies even though MACs differ. External peers and NAT state are still
not cloned. See [network details](network.md) for the route composition.

## Gate assertions

The script fails rather than substituting a fake runtime/result. It exercises:

1. Actual EROFS/shared-lower and private OverlayFS blocking cold creates through the
   controller, which assigns the returned ID (template-default and explicit resources);
   direct worker same-ID replay/conflict handling and inline argv exec results.
   Two commands in one sandbox and one in another must have overlapping
   in-container monotonic execution intervals, each in its own `exec-<n>` group; a
   capture during them gets an immediate `409 sandbox_busy`; a fourth concurrent
   command (limit 3 in the gate) gets `409 exec_limit`. Kill stops each of three
   running commands (`exec_killed`, sandbox still running) and an unknown ID is
   `404 exec_not_found`. Streaming mode delivers `start`, output events spread over
   the command's run (base64, stdout and stderr), then `exit`; a streamed timeout ends
   with `exec_timeout`. A fourth reservation is rejected by the worker without writing
   a record, and the controller reports `no_capacity`. Incompatible, symlinked,
   unknown-field, schema-2 (old per-create upper archive) and (network) unauthorized
   templates are rejected before any record; a digest-mismatched artifact is a failed
   create naming its ID. PID 1 is `/.sandbox-init` (tini), and an orphaned exec child
   leaves no zombie. A client that disconnects mid-exec leaves the command to finish
   (or, on a bound violation, to be stopped at its deadline while the sandbox keeps
   running) with full cleanup; a
   client that disconnects mid-create (host helpers frozen) gets its unlearnable
   sandbox deleted with `create_response_lost`; DELETE cancels an in-flight exec
   (`sandbox_cancelled_or_expired`) and, with networking, ends an open proxied
   stream;
   with cleanup frozen, a second DELETE waits and both return `deleted`; and a DELETE
   whose root unmount is blocked by a test-owned open file reports `cleanup_failed`,
   keeps the reservation and ownership marker, and is retried to `deleted` once the
   file is closed. A test-owned guest namespace FD likewise keeps its pin mounted
   and cleanup reserved until closed; veth removal and slot reset happen first.
2. Private write/copy-up and lower whiteout isolation between two cold sandboxes.
3. Distinct PID/mount/network namespaces from each other and the host, only loopback
   in the sandbox, UID/GID 65534, empty effective caps, no_new_privs and an active
   seccomp filter. Inside the sandbox `io_uring_setup` returns ENOSYS, an MPTCP
   socket returns EPROTONOSUPPORT, a packet socket returns EPERM (no capability)
   and IPv6 (and, when isolated, external IPv4) connects are unreachable. Host
   cgroup memory/swap/CPU/pids settings are inspected.
4. A CRIU checkpoint with **open upper and lower descriptors/mappings**, an in-memory
   counter and random nonce, and an **ESTABLISHED loopback TCP connection** that the
   init uses every 100 ms. The source must keep running: its counter advances during
   the capture except while it is stopped (the cgroup-freezer time and the longest
   unchanged interval are recorded), and its loopback connection keeps working. A new container restores the same memory
   nonce, continues the loopback connection, sees the filesystem delta/whiteout, and
   writes independently of the source. The published template has a sealed EROFS layer
   and `checkpoint.tar` but no upper archive, plus the capturing host's `cpuinfo.img`
   (its digest in the manifest); a copy whose `cpuinfo.img` requires a CPU feature no
   host has (extended-state bit 50) is refused by `criu cpuinfo check` as a pre-launch
   `422 template_unavailable` with no ID, record or runtime state; the mounted layer holds a whiteout for
   the deleted base file and the modified base file with its owner, mode and `user.`
   xattr, and the child's upper starts empty. The child's restore unpacks the node
   checkpoint cache once; it is unchanged by that restore and reused unchanged by a
   later restore after a worker restart. A checkpoint that fails after the freeze
   (the fixture holds an undumpable userfaultfd) leaves the source running and
   publishes nothing; a `runc checkpoint` stopped by the test (SIGSTOP) until the
   worker kills it at the 30 s command deadline is `500 checkpoint_interrupted`, and
   that source is thawed and keeps running (its counter advances). A source whose
   processes the test kills while its `runc checkpoint` is stopped fails with `500
   checkpoint_failed` and is deleted. A **chained capture** of the warm child (two
   sealed layers) restores a grandchild with the same nonce, the child's file change, the source's
   whiteout and a working loopback connection. Restored host PIDs must be in their
   own cgroups. This is a
   targeted file-identity check, not blanket CRIU compatibility for all
   filesystem/syscall/application states. Two captures run concurrently into
   distinct, exclusively created staging leaves and restore independently. A
   preexisting unacquired leaf must remain untouched by a failed capture, and a warm
   create with mismatching explicit resources is rejected.
5. TTL cleanup, explicit deletion, successful exec descendant cleanup (including a
   child that closes its stdio), and a deadline or output overflow (stdout only and
   both streams) that stops only that command, with bounded output reported inline,
   while the sandbox keeps running.
6. Layer verification: two simultaneous first creates of a new 16 MiB base make the
   worker read (`rchar`) between one and one and a half times its size (hashed once,
   in the create jobs); `verified-layers.json` is root-owned 0600 and records each
   used layer's digest, size and current file identity. After the restart below, a
   create of that base reads less than half its size (trusted, not rehashed), a
   permission change makes the next create hash it again, and a same-size in-place
   corruption of an unmounted layer is `500 artifact_digest_mismatch`.
7. One worker SIGKILL with a live owned source and an actually running blocking exec,
   then restart using the same root: records, exec child cgroup, processes and private
   mounts must reconcile. Retained warm artifacts
   must still restore after source cleanup/restart. A second crash occurs with a
   host checkpoint helper paused in its owned cgroup before exec. A trusted sleeping fixture
   holding a staging FD is explicitly placed in that leaf to stand in for a surviving
   helper descendant outside the worker's parent-death signal/process group. Restart
   must kill/drain it and discard interrupted staging before becoming ready.
8. Final graceful shutdown: no owned mounts, cgroups or private sandbox directories;
   management tokens absent from service logs. Shared **artifacts**, records and
   fixture build inputs are intentionally retained for inspection, not mistaken for
   live-container leaks. `validation.json` retains actual overlap, namespace and
   warm-state observations. Records hold lifecycle metadata only; results are inline.

The script does not prove hostile-workload containment, full memory-pressure/pids
exhaustion behavior, system-wide host cleanup under every crash point, arbitrary
application compatibility, S3 transfer or two-node portability. Extend approved
integration qualification after this first gate; no unit-test substitute is used.

## Local concurrency stress gate

`scripts/stress_smoke.py` uses a disposable outer network/mount namespace, never
changes default-host networking, and runs a real controller and worker. With the
tiny fixture (64 MiB, one vCPU, 64 pids), isolated batches are **16 cold, 16 warm,
then 16 of each together**; approved-port batches are **32 cold and 32 warm**.
One capture source plus the batch means at most 33 live fixture containers. Each
batch is deleted concurrently. Optional `--oci-layout` adds a Python image at
128 MiB: `--image-concurrency` defaults to 2 plus its source (at most three live
images); larger image batches need separate approval. The approved local bound is
an owned cgroup with 4 GiB and 4096 pids. `--fixture-concurrency 2` instead runs one-wide
cold/warm and two-wide mixed/network/distinct-lower batches, with at most three live
containers including the source. Use this bounded variant when approval is limited
to three containers; it is not evidence for the default 32-wide gate. Every create/delete must succeed first try,
with no host-tool failure and no leftovers. The gate checks histogram bounds and
authentication, profiles per-phase times and measures 16-byte/1-MiB replies directly
in the routing slot, through the worker and through the controller. These are
informational release-build measurements on one host, not a capacity qualification.
A final batch creates 32 sandboxes from distinct tiny EROFS images to exercise
first-use lower mounts at full concurrency; it checks mountinfo sources and
`/sys/block/loop*/loop/backing_file` before/after. File-backed mode must add zero
loop associations for this worker; forced fallback must use loop sources. The
normal runtime gate also retains 32 distinct lowers while deleting each sandbox,
without exceeding its three-container bound. These do not exhaust global host
loop devices or change their allocation limits.

Host tools are run with their output on nonblocking pipes. Once a tool has exited,
everything it wrote is already in its pipes, so the worker reads what is there and
stops at the first empty read: a pipe still held open by a descendant, or briefly by
another tool that is being started at that moment (a forked child holds copies of
the worker's descriptors until it executes its program), is neither waited for nor
an interruption. Before this, such a pipe made a fast tool look interrupted
(`tool_deadline_or_output_limit`, and as `guest_namespace_create_failed` or
`cleanup_failed` through their callers); concurrent creates hit it routinely. The
output limit and deadline are unchanged. A failing host tool is written to the
worker's error output with its name, static error, exit code and at most the last
512 input bytes of stderr, escaped onto one line. This includes storage tar,
runc's direct/checked paths (conmon startup diagnostics come from runc's log), and CRIU's
CPU check. Guest command output is delivered to its caller, not copied to worker
logs. Logs can contain workload paths or tool diagnostics; protect them.

### EROFS mount selection

Worker startup, after acquiring its root lock and draining old helpers, builds a
tiny plain EROFS image under `erofs-probe`, mounts and reads it once, then removes
it. This active probe is separate from the read-only CLI `preflight`. The cached
worker preflight and status expose its result (`erofs` in [api.md](api.md)).
Direct backing uses `mount(2)` with the image path, type `erofs`, and
`ro,nodev,nosuid` in a tracked, deadline-bound helper. Some util-linux versions
silently allocate a loop even without `-o loop`; the direct call avoids that.
Like [composefs's EROFS mount path](https://github.com/containers/composefs/blob/main/libcomposefs/lcfs-mount.c),
only `ENOTBLK` from this known valid probe selects loop fallback;
permission, I/O, helper or cleanup errors fail startup. Later image-mount failures
never switch modes. `SANDBOX_EROFS_FORCE_LOOP=1` explicitly selects the old loop
path for validation; it does not claim the kernel lacks file backing.

Both forms verify the EROFS type, mount flags and expected image before reuse or
unmount: direct mountinfo source is the image path, while loop mounts resolve the
backing file from the mount's device number. Restart cleans interrupted probe state
and old lowers using the same checks, regardless of the new selected mode. There
is no change to artifact compatibility, private overlays or capture semantics.
Loop fallback reports free existing visible block nodes, unknown nodes and scan
truncation in status; counts are advisory, not reservations. No free nodes yields
`erofs_loop_devices_exhausted`, including a mount failure whose post-failure scan
confirms exhaustion. Other mount failures keep their original static error.

A failed EROFS lower mount also emits `lower_mount_diagnostic`: image checksum,
actual superblock compatibility/incompatibility bits and block-size shift, current
kernel and its advertised EROFS features, loop-control open errno, counts of
existing loop devices/backing associations/device nodes (scan bounded at 4096),
and the local `mkfs.erofs --version`. Optional trusted `losetup`, discovered under
the same tool-directory policy, supplies a bounded read-only device list and its
stderr/exit status. Missing losetup does not change readiness. Diagnostics never
allocate/detach a device, infer the image's build tool, or replace the original
failure (loop exhaustion is classified separately by the mount path). Existing
free-device counts are not a proof of available loop capacity.

DELETE cancellation is checked for both buffered and streamed exec results. Their
end events now pass through the engine after it publishes deletion state, avoiding
a command-thread/snapshot race that could return `running` for a cancelled exec.

Every admitted lifecycle job or exec emits one `sandboxd: phases {…}` line with
operation, sandbox ID, result, total milliseconds and completed phase durations.
Create/restore separates admission wait, manifest, layer verification, lower and
overlay mounts, guest/slot network, OCI spec, runc (including cgroup setup) and running verification.
`first_ready` is elapsed time to the running result, not application readiness;
uncompleted steps are recorded as `failed_step` before recovery or cleanup, not
charged to `kill`. Capture records thaw/running checks as `recovery`. Capture and
delete similarly expose sealing/checkpoint/publication and cleanup steps. Status
carries the bounded cumulative histograms described in [api.md](api.md).

CPU checks run off the admission coordinator, with bounded queues and definitive
answers cached; transient failures are retried. Older manifests containing
`compatibility.cpu_features_sha256` must be republished (strict parsing rejects
them). Runtime overlays use the startup-probed `volatile` mode; only EINVAL or
EOPNOTSUPP from that tiny probe selects ordinary overlays, after an ordinary mount
already succeeded. Permission/I/O/helper errors fail startup; later failed mounts
never change mode or reuse a volatile work directory. Capture still freezes and seals matching files/processes and syncs
the published layer. Lazy pages are not shipped: small-image experiments are not
proof of reliable page-server ownership and restore under sustained load.

### Init supervision and retained exit evidence

Conmon 2.1.10 is a required binary, not another runtime service. Its start gate is
released only after the fresh helper joins a durable per-sandbox monitor group;
the worker waits for the launcher and bounded JSON PID reply. Cold creation then
calls `runc start`; warm creation uses conmon `--restore` and `--runtime-opt` for
TCP-established, external Unix sockets, file locks, cgroup-ignore and private CRIU
work paths. The worker-authored `org.criu.config` annotation still supplies restore
compatibility/network-lock options. Conmon's passthrough mode inherits null standard
streams, keeping the checkpoint descriptor model unchanged. No logging/attach/TTY
API is added; commands still use the existing `runc exec` implementation.

Conmon lives in `.monitors-<root-digest>/<sandbox-id>`, **never** a kill-on-return
helper leaf. It subreaps init, persists its exit status and observes cgroup-v2 OOM.
The watcher uses those files, not workload `cgroup.events`, to detect init exit;
a missing/dead monitor without an exit file fails closed as `monitor_lost`. It
rechecks exit evidence after observing an empty monitor group, because conmon can
publish its exit between the watcher's initial file check and group check.
`runtime_start_failed` means the create/start handshake failed, while an already
started workload ending is `workload_exited` (or `workload_oom` with an actual OOM
kill counter). An early exit may fail create, but never masquerades as runtime
startup failure. Restore startup failures keep the existing `restore_failed` error.

Deletion and restart kill the workload, allow conmon five seconds to reap and
write its files, then drain any stuck monitor before reclaiming resources. An
unfinished create/restore is stopped first so it cannot race workload cleanup.
The worker reads conmon's OOM marker and `memory.events` **before runc delete**,
and atomically saves `monitors/<id>/result.json`. Cleanup retries republish the
existing summary and complete both file and directory sync before removing groups:
a visible result file alone does not prove its prior directory sync succeeded.
Raw `exit`, `oom`, PID files and
the summary stay with retained records after private-state deletion. Exit 137
alone is not OOM evidence. A lost monitor has no known exit code. Unknown monitor
ownership blocks restart; restart still kills/cleans rather than adopting tasks.
There is no new retention/GC policy: monitor evidence shares record retention.

The layout now ends in `-conmon-null-v1`: older cold templates must be republished
and warm templates recaptured. Conmon is outside the guest and is not checkpointed;
the layout change deliberately requires requalification rather than assuming old
images are compatible. Preflight requires the qualified 2.1.10 protocol version.

Behavioral references: conmon v2.1.10 `src/conmon.c`, `runtime_args.c`,
`ctr_logging.c`, `cgroup.c`; Podman v4.9.0 `libpod/oci_conmon_common.go`
`createOCIContainer`, `readConmonPipeData`, `StartContainer`. These are fresh small
protocol integrations; no third-party source was copied into this repository.

The runtime gate checks cold/restored null descriptors and monitor parentage,
runtime-start failure versus immediate and natural workload exits, a real 64 MiB
whole-group OOM with marker/counter, monitor loss, and worker-crash reconciliation
of both running monitors and incomplete startup. Deterministic syscall-fault cases
exercise an exit published between watcher observations and repeated post-rename
directory-sync failures; teardown must wait for a successful retry that preserves
the original summary. It retains the exit evidence and fault traces for inspection. See the qualification scope above;
this is not cluster, arbitrary-application or hostile-workload qualification.

### Mount and filesystem qualification

Mountinfo paths are decoded as bytes, including octal escapes and non-UTF-8 names;
optional propagation fields are parsed separately. EROFS reuse checks source and
flags; namespace-pin removal checks nsfs ownership and unmounts without ip's lazy
DELETE. Busy teardown retains reservation until a real unmount succeeds. The local
runtime gate includes escaped mount paths, transient and persistent busy holders,
all OCI limits on cold/restored groups, and sealed hardlink identity. With `index=off`,
a lower hardlink pair may split on copy-up; with `xino=off`, inode/device numbers are
not generally stable. The gate records this behavior rather than changing options
or promising arbitrary file-identity compatibility.

Behavioral references: runc v1.3.6 `specconv/CreateCgroupConfig`, `criuApplyCgroups`
and `rootfsParentMountPrivate`; containerd v2.2.0 `core/mount/mount_unix.go` and overlay
`NewSnapshotter`; Moby mountinfo v0.7.2; containers/storage v1.57.0 `checkSupportVolatile`.
These small integrations do not import a runtime service or third-party source tree.

## Failure and cleanup procedure

On a failure, preserve the session root and error code. Never `rm -rf` a worker root
or recursively delete/unmount through potentially live mounts. The script attempts
API deletes and graceful shutdown; if shutdown times out it reports retained state
that needs reconciliation. A failed root may still own live workloads/resources.

With the same binary/config and separately re-provisioned worker token matching
that config's environment source, restart **only that worker**:

```sh
target/debug/sandboxd worker --config /var/lib/sandbox-validation/SESSION/worker.toml
```

`SESSION` is the actual generated directory, not literal input. After acquiring the
root lock, startup kills and drains the root-specific host-helper cgroup tree before
inspecting or reconciling workload resources or staging. Every mutating host command
joins an exclusive helper leaf before exec; forked/daemonized helpers inherit it.
Command completion/deadline kills and drains the leaf before returning; a drain
failure fences further cleanup until restart. Parent-death SIGKILL additionally
terminates direct children. Read-only preflight version queries use parent-death
signaling but do not create cgroups or touch runtime/storage state. Startup then loads
records and kills/cleans prior workloads before admission. Inspect authenticated
sandbox/status responses and `worker-status.json` for `cleanup_failed`/shutdown
errors; retries retain reservations. A mismatched node identity, unexplained state,
missing capability or damaged record fails closed and requires operator inspection,
not guessing ownership or broad cleanup. Gracefully stop the reconciled worker.

Verify no mountinfo entry lies under the session root, no recorded sandbox's cgroup
or private directory remains, and no runc instance remains under its private runc
root. Only after those checks and after all artifact references are intentionally
retired may an operator delete that **specific session's** retained files. Do not
remove another worker's cgroups, loop devices, mounts or shared images. Published
layers/templates are never automatically evicted while referenced (there is currently
no automatic eviction at all).

## Explicit remaining boundaries

- Literal IPv4 TCP allowlists and the app proxy to approved service ports are implemented;
  DNS, UDP, IPv6, domain/CIDR policy, per-create endpoint overrides and arbitrary
  established external TCP connection cloning remain unsupported.
- Seccomp follows the AgentENV container pattern: default-allow, with only io_uring
  (ENOSYS) and MPTCP sockets (EPROTONOSUPPORT) blocked because CRIU cannot dump them.
  Isolation relies on namespaces, empty capabilities, no_new_privs, cgroups and
  network policy. CRIU runs with `--tcp-established --ext-unix-sk --file-locks`
  (AgentENV's options): established and loopback TCP are captured and restored; a
  child's copy of a connection to an external peer fails on first use. Other
  unsupported state (for example a userfaultfd) fails the capture while the source
  keeps running.
- No S3 client, remote template transport, signed publisher provenance or two-node
  qualification. The local digest-bound layout is the serialized transfer boundary.
- No per-sandbox writable-disk quota, automatic artifact GC or tombstone pruning.
- The local privileged functional result does not establish production readiness,
  broad isolation, general workload suitability, performance or capacity. Independent
  review and per-deployment qualification are still required. The future two-node/512 GB
  budget scope and latency threshold remain unresolved.


## Disposable network qualification

Opt-in networking additionally requires an operator-provisioned bridge with a
**stable, explicitly assigned MAC**, its configured IPv4 gateway address/prefix,
and an exclusive pool of unused addresses sufficient for worker sandbox capacity.
The worker preflight inspects bridge kind and address/prefix, validates pool/policy
bounds, and never provisions or repairs host networking. Operator routing beyond
that bridge and address allocation exclusivity are deployment prerequisites, not
inferred from a successful preflight. Without a fixed bridge MAC, bridge port
churn can change the gateway MAC and strand cached neighbor entries. Use a trusted
bridge dedicated to worker uplinks; do not attach untrusted host peers.

After the same explicit privilege approval and cgroup/tool preparation, use:

```sh
python3 scripts/network_smoke.py --allow-privileged-runtime \
  --binary target/debug/sandboxd \
  --root /var/lib/sandbox-validation \
  --cgroup-parent /sys/fs/cgroup/sandbox-validation \
  --tools-dir /var/lib/sandbox-tools
```

This harness enters a disposable **outer network and mount namespace** before
creating the bridge, gateway/fixture addresses, local HTTP fixture servers or any
worker. `/run/netns` is a private tmpfs inside that mount namespace. No public
network, downloads or actual default-namespace interfaces/routes/rules/sysctls are
changed; before/after default namespace topology/stateless-rules/forwarding
inventories are compared. Existing `/run/netns` is required. Only three containers,
64 MiB/one vCPU/64 pids each, remain the limit. No additional installed helper is
needed; the existing verified `ip` enters namespaces for same-binary helpers.

The network variant retains relevant previous lifecycle cases and adds positive
exact destination/port, denied other destination/port/sibling, no IPv6/UDP/raw
socket creation, capture of a sandbox holding an established external TCP
connection and restore of a child from it, source and child restored listening
sockets/fresh egress, the pre-created slot pool (built at start, reset rather than
deleted on release even while a test-owned FD holds the guest namespace; the pin's
real unmount waits for that FD; rebuilt on restart and removed at shutdown), cleanup retry after a held root mount is released,
and the app proxy through the controller and worker: path and host forms, the
management token absent from the forwarded request, Host and X-Forwarded-Host,
authentication, an unapproved port (`403`), a returned redirect, a 20,000-byte
response header, chunked parts arriving as sent, two concurrent 32 MiB binary
downloads, an 8 MiB binary upload counted by the guest, 40 small calls on one
kept-alive client connection through the controller and the worker with a median
under 10 ms (no Nagle wait; see the API's app proxy section), the worker idle timeout
(`504 upstream_timeout`, gate value 3 s), the worker connection limit (`503 busy`
with four connections ESTABLISHED inside the slot and none in the worker's
namespace), a stream ended by DELETE, and a worker crash during an open stream.
The gate configures small proxy bounds (worker four connections, 3 s idle;
controller 6 s idle) and `proxy_domain = "sandbox.test"`. Namespace rules, addresses,
identities and observations are retained under the test-owned root. Fixtures
are original local code, not downloaded images. Test harness helpers are drained
before pins/staging are discarded. Functional qualification on a development host
does not establish hardened-host isolation or a production network deployment.


The network gate also routes bounded 64 KiB TCP payloads through a 1280-byte hop
inside the disposable outer topology. The guest and fixture peer start at MTU 1500,
DF is required, and guest TCP black-hole probing must be disabled. A second case
lowers only the owned slot uplink to 1280 to exercise slot-generated errors. The
fixture validates every payload byte and acknowledges completion; socket PMTU and
narrow-rule counters prove that both forwarded and locally generated IPv4
fragmentation-needed messages reached the guest. The gate repeats payloads after
capture on the source and after independent child restore and retains denied destinations and
ports. No MTU, route or forwarding sysctl on the actual host/default namespace is
changed. This is targeted PMTU transport qualification, not a general routed-network
or performance result.

## Real-image end-to-end check

`scripts/image_e2e.py` runs the owner workflow with a real OCI image instead of
the static fixture: build a cold template from the image, create a container,
call the HTTP server inside it through the app proxy, run streamed, concurrent,
killed and bounded commands, capture a warm CRIU template, restore an independent
child from it and call the child. Everything goes through the controller's API. It needs the same explicit approval, root, trusted
root directory, delegated cgroup parent and tools as the network gate, and it
runs in its own disposable outer network/mount namespace in the same way.

The image comes from an OCI image layout directory (`--oci-layout`) or a tar of
one (`--oci-tar`). `--image REF --oci-layout DIR --fetch-only` fetches one platform
into a new layout with an already installed `regctl`, `skopeo` or `crane`
(`--fetch-tool`). It runs without privilege and in the host network namespace, and
your proxy environment applies. If you have no registry access, use an existing
local layout instead. Example with a generic public image:

```sh
python3 scripts/image_e2e.py --fetch-only --image python:3.12-slim --oci-layout /tmp/python-oci
python3 scripts/image_e2e.py --allow-privileged-runtime \
  --oci-layout /tmp/python-oci \
  --binary target/debug/sandboxd \
  --root /var/lib/sandbox-validation \
  --cgroup-parent /sys/fs/cgroup/sandbox-validation \
  --tools-dir /var/lib/sandbox-tools
```

What the script does:

- **Image to template.**
  - It verifies the manifest, config and layer digests and the uncompressed
    `diff_ids`.
  - It applies the layers in order: `.wh.` whiteouts and `.wh..wh..opq` opaque
    directories, modes including setuid, numeric ownership, symlinks, hardlinks,
    devices and FIFOs. Paths are resolved as if chrooted, and `..` member names
    are rejected. xattrs are not copied. zstd layers need the installed `zstd` tool.
  - It makes `/workspace` owned by 65534. It replaces the image's
    `/etc/resolv.conf` with a loopback-only one and adds a localhost `/etc/hosts`
    if the image has none. This follows the AgentENV fresh-rootfs pattern; turn it
    off with `--keep-image-resolver`. Sandboxes have no DNS, so a build-time
    resolver would make lookups wait on blocked egress. For example, Python's
    `http.server` took about 20 s to start listening.
  - It builds an uncompressed EROFS base with `mkfs.erofs` and writes a cold
    manifest with `runtime_smoke.py`'s helpers.
  - The image `Env` is passed to the workload through the image's `env(1)`
    (`--no-image-env` turns this off). The image `User` and `WorkingDir` are not
    applied: the worker always uses UID/GID 65534 and `/workspace`.
- **Default workload.** `python3 -m http.server 8000 --bind 0.0.0.0`. Change it with
  `--init-argv` (a JSON list), `--port`, `--http-path` and `--expect-body`. The
  template network is `tcp_allowlist` with that service port and the next one (for
  the WebSocket check) and no egress. The controller uses
  `proxy_domain = "sandbox.test"`.
- **Lifecycle.** The script runs these steps in order:
  0. Before any create, the worker has pre-created three clean routing slots
     (loopback and uplink only, no rules in the filter chains).
  1. Cold create (the worker reads at least the base's size: the first use hashes
     it), then retry a GET through the app proxy (path form) until the
     server answers 200 with the expected body. Check the init process's UID,
     capabilities and no_new_privs.
  2. Check that PID 1 is the reaping init and that a killed background exec child
     leaves no zombie. Run an exec (`--exec-argv`/`--exec-expect`) and write a random
     marker file with the image's shell (`--shell`). Then: the host form reaches the
     same server; a streamed Python command's output arrives over 2.5 s before its
     `exit` event; two commands overlap in one sandbox, each in its own exec group;
     a WebSocket echo server run by a streaming command on the second port echoes a
     text and a 70,000-byte binary message through the proxy in both forms, and the
     kill endpoint stops it (`exec_killed`) while the HTTP server keeps answering; a
     timeout (`sleep 30`, 500 ms) and an output overflow (`yes`, 4,096 bytes) stop
     only their commands. Per-call overhead is measured (informational): 30 proxied
     GETs, 30 GETs made inside the sandbox by one command, and 10 `true` commands.
  3. Capture a warm template while a probe in the sandbox's routing namespace
     requests the service port every 20 ms. The source must answer during the
     capture except while it is stopped; a host-side watch of its cgroup freezer
     measures the freezer time, and the longest client-visible gap (slightly longer,
     since CRIU thaws and refreezes the cgroup) is recorded too. It must still
     be running and answering afterward. The template has one sealed layer and no
     upper archive.
  4. Create a child from the warm template (the first restore on the node unpacks
     the checkpoint cache) and call its HTTP server on a fresh connection. The marker
     must be present in the child. A second child restores from the unchanged cache,
     answers and is deleted.
  5. Write a file in the child that must not appear in the source, and check
     that the pid/mnt/net namespaces are distinct.
  6. Delete both. No runc state, private state, cgroups or guest namespaces may
     remain; the three pooled slots remain and are clean again (reset, not deleted).
  7. Stop the worker gracefully (exit 0) and start it again. `verified-layers.json`
     lists the base; the next cold create trusts it (the worker reads less than half
     the base's size), answers HTTP and is deleted.
  8. After shutdown, no owned mounts, cgroups, namespace pins or veths may remain
     and service logs must not contain the tokens.
- **Defaults.** 256 MiB, one vCPU and 128 pids per container, at most three
  containers. PASS lines print informational timings (cold create, first HTTP
  ready, streamed output, WebSocket handshakes, per-call overhead, capture and its
  freezer time, first and cached warm restore, first call after restore, cold create
  after a restart). These
  are not
  benchmarks. The session root keeps `prepared.json`, `image-e2e.json` and the
  service logs for inspection.

This is a targeted compatibility check for one image and workload on one host. It
is not general application compatibility, isolation or performance qualification.
