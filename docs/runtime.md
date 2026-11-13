# Explicitly privileged real-runtime qualification

**Targeted functional gate passed on one explicitly approved Linux x86-64 host,
with runc 1.3.6 and CRIU 4.3.** The real script exercised shared EROFS/private OverlayFS,
capture/source recovery, independent restored memory/file state, overlapping exec,
admission, bounded commands, TTL/delete and crash/restart cleanup. Compilation and
the nonprivileged HTTP smoke also passed, but are not substitutes for this gate.
The network variant also passed inside a disposable outer network/mount namespace,
including policy, application HTTP, listening-socket restore and helper cleanup.
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
python3 -m py_compile scripts/runtime_smoke.py scripts/image_e2e.py
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
is part of the isolated command. `nsenter ... ip ... link show` only inspects an owned netns.
Workload namespaces are created by runc/CRIU; there is no host-network mode.

## Gate assertions

The script fails rather than substituting a fake runtime/result. It exercises:

1. Actual EROFS/shared-lower and private OverlayFS blocking cold creates through the
   controller, which assigns the returned ID (template-default and explicit resources);
   direct worker same-ID replay/conflict handling and inline argv exec results.
   Independent commands must have overlapping in-container monotonic execution
   intervals; a conflicting same-sandbox exec/capture gets an immediate
   `409 sandbox_busy`. A fourth reservation is rejected by the worker without writing
   a record, and the controller reports `no_capacity`. Incompatible, symlinked,
   unknown-field and (network) unauthorized/old-schema templates are rejected before
   any record; a digest-mismatched artifact is a failed create naming its ID. A client
   that disconnects mid-exec leaves the command to finish (or, on a bound violation,
   the sandbox to be terminated) with full cleanup; a client that disconnects
   mid-create (host helpers frozen) gets its unlearnable sandbox deleted with
   `create_response_lost`; DELETE cancels an in-flight exec.
2. Private write/copy-up and lower whiteout isolation between two cold sandboxes.
3. Distinct PID/mount/network namespaces from each other and the host, only loopback
   in the sandbox, UID/GID 65534, empty effective caps, no_new_privs and an active
   seccomp filter. Inside the sandbox `io_uring_setup` returns ENOSYS, an MPTCP
   socket returns EPROTONOSUPPORT, a packet socket returns EPERM (no capability)
   and IPv6 (and, when isolated, external IPv4) connects are unreachable. Host
   cgroup memory/swap/CPU/pids settings are inspected.
4. A CRIU checkpoint with **open upper and lower descriptors/mappings**, an in-memory
   counter and random nonce. Source recovery must preserve the nonce/state; a new
   container restores the same memory nonce, filesystem delta/whiteout and private
   network namespace, and writes independently of the source. Restored host PIDs
   must be in their own cgroups. This is a targeted file-identity check, not blanket
   CRIU compatibility for all filesystem/syscall/application states. Capture returns
   only after publication and source recovery. Two captures run concurrently into
   distinct, exclusively created staging leaves and restore independently. A
   preexisting unacquired leaf must remain untouched by a failed capture, and a warm
   create with mismatching explicit resources is rejected.
5. TTL cleanup, explicit deletion, successful exec descendant cleanup (including a
   child that closes its stdio), deadline-triggered whole-sandbox termination and
   output-overflow termination with bounded output, reported inline.
6. One worker SIGKILL with a live owned source and an actually running blocking exec,
   then restart using the same root: records, exec child cgroup, processes and private
   mounts must reconcile. Retained warm artifacts
   must still restore after source cleanup/restart. A second crash occurs with a
   host checkpoint helper paused in its owned cgroup before exec. A trusted sleeping fixture
   holding a staging FD is explicitly placed in that leaf to stand in for a surviving
   helper descendant outside the worker's parent-death signal/process group. Restart
   must kill/drain it and discard interrupted staging before becoming ready.
7. Final graceful shutdown: no owned mounts, cgroups or private sandbox directories;
   management tokens absent from service logs. Shared **artifacts**, records and
   fixture build inputs are intentionally retained for inspection, not mistaken for
   live-container leaks. `validation.json` retains actual overlap, namespace and
   warm-state observations. Records hold lifecycle metadata only; results are inline.

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

- Literal IPv4 TCP allowlists and bounded text application HTTP are implemented;
  DNS, UDP, IPv6, domain/CIDR policy, per-create endpoint overrides and arbitrary
  established external TCP connection cloning remain unsupported.
- Seccomp follows the AgentENV container pattern: default-allow, with only io_uring
  (ENOSYS) and MPTCP sockets (EPROTONOSUPPORT) blocked because CRIU cannot dump them.
  Isolation relies on namespaces, empty capabilities, no_new_privs, cgroups and
  network policy. CRIU runs without `--ext-unix-sk` or `--tcp-established`: Unix
  sockets connected outside the dumped tree and established TCP (including loopback
  connections in isolated sandboxes, which have no TCP precheck) fail capture closed.
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
socket creation, HTTP authentication/header stripping/path validation, text body,
redirect refusal, timeout/output bounds, quiescent capture rejection of established
TCP, source and child restored listening sockets/fresh egress, delayed namespace
FD cleanup retry and HTTP-helper crash/restart cleanup. Adding `--http-limits`
also exercises the opt-in large ceilings: an 8 MiB inline response, two concurrent
worst-case JSON-escaped 8 MiB results, a 16 KiB escaped body, a 31-second application
deadline beyond `request_timeout_ms`, and TTL clamping. Namespace rules, addresses,
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
source recovery and independent child restore and retains denied destinations and
ports. No MTU, route or forwarding sysctl on the actual host/default namespace is
changed. This is targeted PMTU transport qualification, not a general routed-network
or performance result.

## Real-image end-to-end check

`scripts/image_e2e.py` runs the owner workflow with a real OCI image instead of
the static fixture: build a cold template from the image, create a container,
call the HTTP server inside it, capture a warm CRIU template, restore an
independent child from it and call the child. Everything goes through the
controller's blocking API. It needs the same explicit approval, root, trusted
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
  template network is `tcp_allowlist` with only that service port and no egress.
- **Lifecycle.** The script runs these steps in order:
  1. Cold create, then retry the application HTTP operation until the server
     answers 200 with the expected body. Check the init process's UID,
     capabilities and no_new_privs.
  2. Run an exec (`--exec-argv`/`--exec-expect`) and write a random marker file
     with the image's shell (`--shell`).
  3. Capture a warm template. The source must still be running and answering
     afterward.
  4. Create a child from the warm template and call its HTTP server on a fresh
     connection. The marker must be present in the child.
  5. Write a file in the child that must not appear in the source, and check
     that the pid/mnt/net namespaces are distinct.
  6. Delete both. No runc state, private state, cgroups, network namespaces or
     veths may remain.
  7. After shutdown, no owned mounts or cgroups may remain and service logs must
     not contain the tokens.
- **Defaults.** 256 MiB, one vCPU and 128 pids per container, at most three
  containers. PASS lines print informational timings (cold create, first HTTP
  ready, capture, warm restore, first call after restore). These are not
  benchmarks. The session root keeps `prepared.json`, `image-e2e.json` and the
  service logs for inspection.

This is a targeted compatibility check for one image and workload on one host. It
is not general application compatibility, isolation or performance qualification.
