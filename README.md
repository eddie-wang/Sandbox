# Sandbox

A minimal, container-native sandbox service for stateful tool execution.

**Status: first foundation milestone. Async controller/worker HTTP services run; no sandbox runtime is implemented. No isolation, capacity, or checkpoint portability claim is qualified.**

## Run the nonprivileged foundation

Requires a Rust toolchain compatible with the lockfile and Python 3 for the smoke.
No runtime binaries, containers, mounts, host networking changes or root access are
needed for this milestone.

```sh
cargo build --locked
python3 scripts/smoke.py --binary target/debug/sandboxd
```

For manual startup, securely provision `SANDBOX_CONTROLLER_TOKEN` and
`SANDBOX_WORKER_TOKEN` in the environment (independent unpredictable values of at
least 32 ASCII characters), then in separate terminals:

```sh
target/debug/sandboxd worker --config config/worker.example.toml
target/debug/sandboxd controller --config config/controller.example.toml
```

Do not put token values in CLI arguments or tracked configuration. A configured
secret file is also supported; see the [native API](docs/api.md) for limits and
trust boundaries. Example binds are loopback. Supply TLS and network restrictions
before use beyond a trusted host/network; this is not production-ready ingress.

Implemented: liveness, authenticated status and strict management input validation;
bounded parsed requests/bodies/deadlines; static worker polling with a pooled HTTP
client, bounded fanout and stale-node exclusion; advisory capacity/load/runtime
selection. All worker runtime capabilities remain **not ready**. Create/exec/capture
fail closed without creating state or executing a process. Configured budgets are
not measurements or enforcement.

The process-level smoke starts real local worker/controller processes with ephemeral
credentials, exercises authentication, invalid configuration/input, request bounds,
status freshness, concurrent health/control traffic and unavailable operations.
It creates no sandboxes and is not a capacity or security qualification. There are
no unit tests, network-fetching CI jobs, or workload images.

Planned lifecycle/storage/network boundaries and CRIU checkpoint manifest
requirements are in [contracts](docs/contracts.md). No license has been selected yet.

## Direction

- Rust controller with an integrated scheduler, plus one Rust worker per compute node.
- A small native HTTP API suitable for a `SandboxProvider` adapter; no E2B compatibility requirement.
- Shared immutable EROFS filesystem layers with private OverlayFS writable uppers. No OverlayBD or per-sandbox block-device daemon.
- Native Linux containers only: runc for execution and CRIU for warmed process capture/restore. No alternate runtime or runtime-comparison work.
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
      +-- runc + CRIU
      +-- network isolation / resource admission / cleanup
```

Fork and user-facing pause/resume APIs are deferred. Kernel modules, cluster jobs, and host configuration changes require separate operator approval.

## Performance contract

Rust is an implementation choice, not evidence of capacity. Bound request concurrency, memory-intensive restores, subprocess output, and admission on each worker. Avoid blocking the async executor and do not hold shared state locks over network or process I/O.

Qualification uses two nodes with 10% of live sandboxes actively executing tools and 90% resident but idle. Find the maximum sustainable population under a 512 GB memory budget and an agreed latency-regression limit. The budget scope (per node or whole cluster), exact byte count, and latency acceptance threshold must be specified before a run; none is assumed yet.

Measure end-to-end latency including queueing, p50/p95/p99, actual active concurrency, throughput, full service memory including file cache, failures, and teardown. Exercise varied trajectories and compare loaded performance against a low-contention baseline for the same environment. Report restore/first-call performance separately from steady state. Functional correctness, network isolation, resource containment, and leak-free cleanup are prerequisite gates.

Do not put private workloads, deployment recipes, credentials, organization endpoints, or benchmark traces in this repository.
