# Sandbox

A minimal, container-native sandbox service for stateful tool execution.

**Status: initial development. No runtime, isolation, capacity, or checkpoint portability claim is qualified yet.**

## Direction

- Rust controller with an integrated scheduler, plus one Rust worker per compute node.
- A small native HTTP API suitable for a `SandboxProvider` adapter; no E2B compatibility requirement.
- Shared immutable EROFS filesystem layers with private OverlayFS writable uppers. No OverlayBD or per-sandbox block-device daemon.
- Two runtime candidates: runc with CRIU, and gVisor/runsc with its native checkpoint/restore. Their checkpoint formats are not interchangeable.
- Warmed template capture/publication, restore on compatible workers, command execution/application HTTP access, expiration, and explicit deletion.
- Default-deny network policy enforced outside the sandbox, with explicit destination/port allowances.
- Local artifact caching backed by an S3-compatible template repository.

```text
SandboxProvider
      |
controller + scheduler
      |
per-node worker
      +-- shared EROFS mounts / private OverlayFS uppers
      +-- runc + CRIU OR runsc + native checkpoint
      +-- network isolation / resource admission / cleanup
```

Fork and user-facing pause/resume APIs are deferred. Kernel modules, cluster jobs, and host configuration changes require separate operator approval.

## Performance contract

Rust is an implementation choice, not evidence of capacity. Bound request concurrency, memory-intensive restores, subprocess output, and admission on each worker. Avoid blocking the async executor and do not hold shared state locks over network or process I/O.

Qualification uses two nodes with 10% of live sandboxes actively executing tools and 90% resident but idle. Find the maximum sustainable population under a 512 GB memory budget and an agreed latency-regression limit. The budget scope (per node or whole cluster), exact byte count, and latency acceptance threshold must be specified before a run; none is assumed yet.

Measure end-to-end latency including queueing, p50/p95/p99, actual active concurrency, throughput, full service memory including file cache, failures, and teardown. Compare both runtime candidates on equivalent environments and varied trajectories. Report restore/first-call performance separately from steady state. Functional correctness, network isolation, resource containment, and leak-free cleanup are prerequisite gates.

Do not put private workloads, deployment recipes, credentials, organization endpoints, or benchmark traces in this repository.
