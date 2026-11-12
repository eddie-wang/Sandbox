# Explicitly privileged real-runtime qualification

**Targeted functional gate passed on one explicitly approved Linux x86-64 host,
with runc 1.3.6 and CRIU 4.3.** The real script exercised shared EROFS/private OverlayFS,
capture/source recovery, independent restored memory/file state, overlapping exec,
admission, bounded commands, TTL/delete and crash/restart cleanup. Compilation and
the nonprivileged HTTP smoke also passed, but are not substitutes for this gate.
General hostile-workload isolation, host trust, other kernels/applications,
cross-node portability and capacity remain unqualified.

## Prerequisites and authority

An operator must separately provision and approve:

- Root/host authority, including mount/namespaces, ptrace, cgroup, mknod, ownership,
  UID/GID/capability setup and resource-limit capabilities. A rootless/containerized
  shell with missing capabilities is not enough.
- EROFS and OverlayFS **already available** in the kernel; loop control already
  available. No module loading or package installation is done by the service/script.
- Trusted standard `runc`, `criu`, `mount`, `umount`, GNU `tar`, `mkfs.erofs`, `ip`,
  `nft`, `iptables`, `iptables-save`, `iptables-restore`, `ip6tables-save`,
  `ip6tables-restore` and `gzip`. CRIU uses namespace firewall-state helpers and gzip
  for tmpfs images; these are not workload egress support. GNU tar also invokes its
  fixed `/bin/sh`, and dynamic binaries depend on system libraries/loaders. Review
  administrator system CRIU configuration; request options do not replace host trust.
  For the smoke: Python 3, a C compiler with static libc, `nsenter`, and sandboxd.
  No rootfs or tool downloads are performed by the smoke.
- A new dedicated administrator-owned root on ext4/XFS/Btrfs with correct OverlayFS
  d_type/xattr semantics; XFS needs ftype=1. All ancestors must be owned by UID 0,
  not group/other writable and not symlinks. Give the root private permissions.
  Supply operator disk capacity/quota; the worker does not implement disk quotas.
- An **existing, exclusive cgroup-v2 domain parent**, not the cgroup filesystem root.
  It must have no processes in `cgroup.procs`; `cgroup.subtree_control` must already
  contain `cpu memory pids`, and cgroup.kill/swap accounting must be available.
  The worker service itself runs **outside** this parent. Its workload children and
  a separately owned `.helpers-<root-digest>` subtree for host commands belong inside it. Do not share the parent with another worker, root or service.
- Isolated validation-host access and trusted loopback ingress. Do not expose bearer
  HTTP on an untrusted network.

Neither `preflight` nor startup enables controllers, creates the parent, changes
host networking/firewall/sysctls, installs software, loads modules or invokes sudo.
Read-only preflight is deliberately not an active CRIU/xattr/kernel capability test.
Its filesystem-family and interface checks need this real gate afterward.

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
The same validated PATH is used for runtime and storage commands. Mount/umount use internal-only
mode rather than filesystem helpers. API callers never select a host executable.
The service does not create/populate a tools directory or install dependencies.

If an administrator explicitly stages installed binaries, verify each source is a
regular root-owned non-writable file, copy into a unique trusted directory, preserve
source/destination SHA-256 inventory, and use `--tools-dir /var/lib/sandbox-tools`
with the smoke. Do not repair global directory permissions or silently relax checks.
The approved functional run needed such staging because the system binary ancestors
were not trusted by preflight. Fixed `/bin/sh` executable ownership was checked,
but shell ancestry and dynamic-library integrity were **not established**. Staging
is not a hardened-host qualification; production use needs a trusted system too.

## Bounded command plan

Run the nonprivileged checks first:

```sh
cargo build --locked
python3 scripts/smoke.py --binary target/debug/sandboxd
python3 -m py_compile scripts/runtime_smoke.py
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

The script refuses without both opt-in and UID 0. It creates a unique owned session
root under the already trusted directory and writes temporary configurations with
random environment-only credentials. It runs read-only preflight before any runtime
mutation; missing prerequisites abort. It builds an original static C fixture,
creates a small EROFS image locally, publishes a digest-bound cold manifest, and
starts real worker/controller processes on ephemeral loopback ports.

Hard validation budgets are **at most three simultaneously admitted containers,
64 MiB, one vCPU quota and 64 pids each**; worker aggregate reservation cap 192 MiB,
CPU-overcommit factor 3, two active restores, four fixed operation threads, 64 MiB per
artifact and 30-second host tool deadlines. No capacity/load benchmark, cluster job, package installation,
host veth/route/firewall/sysctl change, module loading or external network traffic
is part of the command. `nsenter ... ip ... link show` only inspects an owned netns.
Workload namespaces are created by runc/CRIU; there is no host-network mode.

## Gate assertions

The script fails rather than substituting a fake runtime/result. It exercises:

1. Actual EROFS/shared-lower and private OverlayFS cold creates through the controller;
   worker create replay/conflict handling and real argv exec. Independent commands
   must have overlapping in-container monotonic execution intervals; same-sandbox
   mutation is excluded. A fourth reservation is rejected by the worker. Incompatible,
   digest-mismatched and symlinked template metadata fail before launch. A disconnected
   command response can be retried without repeating its write.
2. Private write/copy-up and lower whiteout isolation between two cold sandboxes.
3. Distinct PID/mount/network namespaces from each other and the host, only loopback
   in the sandbox, UID/GID 65534, empty effective caps, no_new_privs, seccomp and
   denied socket creation. Host cgroup memory/swap/CPU/pids settings are inspected.
4. A CRIU checkpoint with **open upper and lower descriptors/mappings**, an in-memory
   counter and random nonce. Source recovery must preserve the nonce/state; a new
   container restores the same memory nonce, filesystem delta/whiteout and private
   network namespace, and writes independently of the source. Restored host PIDs
   must be in their own cgroups. This is a targeted file-identity check, not blanket
   CRIU compatibility for all filesystem/syscall/application states. Two captures with
   formerly ambiguous hyphen-paired IDs run concurrently into distinct, exclusively
   created staging leaves and restore independently. A preexisting unacquired leaf
   must remain untouched by a failed capture.
5. TTL cleanup, explicit deletion, successful exec descendant cleanup (including a
   child that closes its stdio), deadline-triggered whole-sandbox termination and
   output-overflow termination with bounded output.
6. One worker SIGKILL with a live owned source and a durably accepted, actually
   running exec, then restart using the same root: records, pending operation,
   exec child cgroup, processes and private mounts must reconcile. Retained warm artifacts
   must still restore after source cleanup/restart. A second crash occurs with a
   host checkpoint helper paused in its owned cgroup before exec. A trusted sleeping fixture
   holding a staging FD is explicitly placed in that leaf to stand in for a surviving
   helper descendant outside the worker's parent-death signal/process group. Restart
   must kill/drain it and discard interrupted staging before becoming ready.
7. Final graceful shutdown: no owned mounts, cgroups or private sandbox directories;
   management tokens absent from service logs. Shared **artifacts**, records and
   fixture build inputs are intentionally retained for inspection, not mistaken for
   live-container leaks. `validation.json` retains actual overlap, namespace and
   warm-state observations; records retain bounded operation results.

The script does not prove hostile-workload containment, full memory-pressure/pids
exhaustion behavior, system-wide host cleanup under every crash point, arbitrary
application compatibility, S3 transfer or two-node portability. Extend approved
integration qualification after this first gate; no unit-test substitute is used.

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

- No destination IP/port egress allowlist, DNS, usable network sockets or application
  HTTP. Unsupported input is rejected; deny-all is not advertised as allowlist support.
- No S3 client, remote template transport, signed publisher provenance or two-node
  qualification. The local digest-bound layout is the serialized transfer boundary.
- No per-sandbox writable-disk quota, automatic artifact GC or tombstone pruning.
- The local privileged functional result does not establish production readiness,
  broad isolation, general workload suitability, performance or capacity. Independent
  review and per-deployment qualification are still required. The future two-node/512 GB
  budget scope and latency threshold remain unresolved.
