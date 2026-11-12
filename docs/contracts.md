# Runtime, storage and admission contracts (not implemented)

These are required future contracts, **not** serialized manifests accepted by the
current API, runtime adapters, validated capabilities or successful stub methods.
The executable runtime enum has only `runc_criu` and `runsc_native`; no plugin
framework or interchangeable checkpoint format is intended.

## Checkpoint manifest boundary

A future versioned, immutable manifest must bind the following as a single
publication unit. Exact serialization/version negotiation still requires the
runtime implementation and portability validation.

| Common field group | Required information |
| --- | --- |
| Identity | Manifest schema version, template ID/version, runtime enum, capture generation |
| Compatibility | CPU architecture/features, host kernel constraints, resource/cgroup mode, network reconstruction requirements |
| Immutable filesystem | Ordered EROFS lower artifact digests and sizes, format/options, mount layout |
| Writable filesystem | Frozen private OverlayFS upper artifact digest/size and format, whiteout/xattr/ownership semantics, matching capture generation |
| Process state | Backend-specific artifact digests/sizes, same capture generation and matching filesystem snapshot |
| Integrity/provenance | Digests for every referenced artifact and manifest, trusted publisher identity and verified publication provenance |

Backend-specific process records must be **distinct discriminated variants**:

- **`runtime: runc_criu`**: runc version, CRIU version and image-format/feature
  requirements, OCI configuration digest, kernel/CPU requirements, and the CRIU
  image-set artifact descriptor. Restore only through the runc/CRIU path.
- **`runtime: runsc_native`**: runsc version/build and selected platform,
  native checkpoint-format requirements, OCI configuration digest, applicable
  host/platform compatibility constraints, and native checkpoint artifact
  descriptors. Restore only through the runsc native path; never feed these
  artifacts to CRIU or reinterpret them as CRIU images.

No runtime fallback or format conversion is implicit. Version/kernel/CPU matching
is necessary but not sufficient evidence of portability; incompatible or unknown
fields must fail closed. Runtime selection must eventually derive from a verified
manifest rather than trust a caller's runtime/architecture assertion. Current
create inputs are syntactic contracts only; no manifest is fetched or validated.

## EROFS + OverlayFS and publication

- Shared immutable EROFS seed/lower mounts are read-only and reusable. They are
  never writable sandbox state. Each sandbox owns a private OverlayFS upper and
  work directory, with required same-filesystem and xattr/whiteout semantics.
- Capture must quiesce execution and bind filesystem and process snapshots from
  the same point in time. A failure must not publish a partial or mismatched pair.
- Publish complete verified artifacts before atomically exposing their manifest.
  Keep artifacts/mounts while referenced by templates, live sandboxes or restores;
  reconcile references after restart before reclaiming. Cache eviction must not
  remove referenced state. Shared mounts must not be torn down with one sandbox.
- Template repository/cache, artifact digests, atomic publication, retention,
  mount handling and crash cleanup are all planned, not implemented here.

## Worker is the final admission authority

Controller snapshots and scheduler choice are advisory. Future restore admission
must atomically check node compatibility, verified template, memory/CPU/sandbox
budgets and restore slots on the worker, with idempotency and bounded reservation
expiry. Never hold shared locks across network, storage or subprocess I/O. Bound
subprocess lifetime and output; move blocking filesystem work off async threads.
A slot must not be reported as a running sandbox before the runtime actually starts.

Before any untrusted process runs, install default-deny host-enforced network
policy with explicit destination/port allowances and resource containment. Apply
it again before a restored process can run. Application HTTP forwarding needs a
separate authenticated, bounded routing design; no arbitrary upstream URL API.

TTL/delete/failure handling must terminate processes, remove private mounts and
network rules, release admission exactly once, retain referenced artifacts, and
reconcile leaks after restart. Expiry and failure must not strand a reservation.
These requirements need durable lifecycle state and integration validation; this
milestone intentionally creates **no** mock reservations or sandbox lifecycle state.

## Validation and qualification gates

Before advertising any runtime as ready, separately validate lifecycle correctness,
checkpoint/filesystem consistency, compatibility rejection, network isolation,
resource enforcement, deletion/expiry, restart cleanup and artifact retention on
approved hosts. Do not infer these from compilation or the nonprivileged smoke.

Capacity qualification remains two nodes, 10% actively executing and 90% idle,
under a 512 GB budget. The budget scope (per node or whole cluster), exact byte
count and latency-regression acceptance threshold are unresolved. Do not pick them
from example configuration or claim a capacity result from request concurrency.
No capacity, isolation or privileged runtime qualification has been run here.
