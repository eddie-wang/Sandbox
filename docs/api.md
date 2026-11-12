# Native API: foundation milestone

One `sandboxd` binary runs as `controller` or `worker`. This is a small native API,
not an E2B-compatible implementation. There is no sandbox lifecycle yet.

## Transport and authentication

- Default binds: controller `127.0.0.1:8080`, worker `127.0.0.1:8081`.
- Only `GET /healthz` is public. Every other request, including unknown routes,
  requires `Authorization: Bearer <token>`. Duplicate authorization headers fail.
- Controller management and worker management use separately configured tokens.
  The controller's `worker_auth` must match each configured worker's `auth`.
  Workers are infrastructure endpoints, not intended for direct tenant access.
- A credential source specifies exactly one `env` variable name or `file` path.
  Tokens are 32–1024 printable ASCII bytes without whitespace. A secret file may
  end in one LF or CRLF. Generate unpredictable tokens, protect files/environment,
  and restart to rotate. Tokens are never CLI values, response fields or logs.
- No built-in TLS, tenancy, RBAC, per-user quotas or audit trail. HTTP listeners
  belong on loopback or a trusted network behind an operator-managed TLS/auth
  boundary. Outbound HTTPS validates certificates using public roots; custom
  trust roots and mTLS are not configured in this slice. Never expose plain HTTP
  bearer tokens to an untrusted network.
- Worker origins come only from administrator-owned startup configuration.
  HTTP(S) origins with credentials, paths, queries or fragments are rejected.
  No registration API or user-supplied destination is accepted. The pooled HTTP
  client ignores proxy environment variables and does not follow redirects.
  Configuration and DNS remain trusted; this is not an arbitrary-URL SSRF proxy.

## Implemented endpoints

| Method and path | Role | Behavior |
| --- | --- | --- |
| `GET /healthz` | Both | `200 {"service":"controller" or "worker","live":true}`; process liveness only |
| `GET /v1/status` | Controller | Cached node status, freshness, poll failure codes; `lifecycle_implemented:false` |
| `GET /v1/status` | Worker | Configured budgets, host OS/architecture, `usage:null`, `admission_ready:false`, all runtime `ready:false` |
| `POST /v1/sandboxes` | Controller | Validate input; `503 no_ready_runtime`; no reservation/dispatch |
| `POST /v1/sandboxes` | Worker | Validate input; `503 runtime_unavailable`; final admission fails closed |
| `POST /v1/sandboxes/{id}/exec` | Both | Validate input; `501 lifecycle_not_implemented` |
| `POST /v1/sandboxes/{id}/capture` | Both | Validate input; `501 lifecycle_not_implemented` |

No successful create/exec/capture response, fake ID, fake reservation, backend
probe or resource measurement exists. A foreign worker reporting ready admission
can pass advisory selection, but the controller still returns `501`; it cannot
activate an unimplemented lifecycle. Unknown sandbox existence is not checked by
exec/capture because there is no lifecycle state store.

### Create input

```json
{
  "template_id": "example-template",
  "runtime": "runc_criu",
  "architecture": "x86_64",
  "memory_mib": 256,
  "vcpus": 1,
  "ttl_seconds": 300
}
```

All fields are required, and unknown fields are rejected. Runtime is exactly
`runc_criu`; architecture is `x86_64` or `aarch64`. Identifiers
are 1–64 ASCII alphanumeric, hyphen or underscore characters. Syntactic limits:
memory 1–1,048,576 MiB; vCPUs 1–4,096; TTL 1–86,400 seconds. These are API bounds,
not resource guarantees; there is no TTL enforcement until lifecycle exists.

### Exec input

```json
{"argv":["echo","hello"],"timeout_ms":1000,"max_output_bytes":4096}
```

`argv`: 1–64 arguments, each at most 4,096 bytes, no NUL, nonempty first argument.
Timeout: 1–60,000 ms. Output limit: 1–1,048,576 bytes. No subprocess is started;
these are input contracts, not implemented execution/output limits.

### Capture input

```json
{"template_id":"example-template","runtime":"runc_criu"}
```

Both fields required. No template is captured or published. Future CRIU
manifest requirements are in [contracts.md](contracts.md).

### Status semantics and advisory scheduler

Worker status schema version is `1`. `capacity` contains operator-configured
`memory_mib`, `vcpus`, `max_sandboxes`, and `max_concurrent_restores`. They are not
available memory measurements or enforcement. `usage:null` means unknown, not
zero. `runtimes` contains exactly one entry with `runtime:"runc_criu"`,
`ready:false`, and `reason:"not_implemented"`. Worker configuration likewise requires
`runtimes = ["runc_criu"]`; other runtimes, empty lists, and duplicates are rejected.
Installing runtime binaries cannot make the backend ready in this milestone.

Controller `nodes` entries include `node_id`, `fresh`, `reachable`, `age_ms`,
`error`, and `status`. Age uses the controller's monotonic time since the last
successful validated observation. Initial status is null with `not_polled`.
A failed poll retains the last successful status but sets `reachable:false` and
`fresh:false`; stale data is never eligible for selection. `reachable` only means
the most recent poll succeeded, not a current network guarantee. Clients must
check `fresh`; a successful but aged observation can have `reachable:true`.

Polling runs in the background, not within status/create HTTP requests. One sweep
at a time, up to configured `fanout` concurrent calls, each with a total deadline
and 64 KiB response limit. Node identity/schema and bounded capacity/status fields
are checked. A slow sweep can exceed freshness; polling never extends the
freshness deadline to make a node eligible. No shared-state lock crosses I/O.

Advisory choice requires fresh status, Linux, matching architecture/runtime, ready
admission, known usage, and space for requested memory/vCPUs, one sandbox and one
restore. It minimizes maximum projected memory/CPU/sandbox/restore utilization,
then sorts by node ID. It is **not** reservation or full checkpoint compatibility.
Actual workers in this milestone cannot be selected.

### Errors and request bounds

API errors use a static, non-sensitive envelope:

```json
{"error":{"code":"no_ready_runtime","message":"No fresh compatible worker has ready runtime admission and capacity"}}
```

| Status | Code / meaning |
| --- | --- |
| 400 | `invalid_input`: invalid JSON, content type, field/value or identifier |
| 401 | `unauthorized`: missing/invalid bearer credential |
| 404 | `not_found`: unknown route |
| 405 | Unsupported method (framework response) |
| 408 | `request_timeout`: parsed request/body/handler deadline exceeded |
| 413 | `body_too_large`: declared/streamed body limit, or body read failure |
| 501 | `lifecycle_not_implemented` |
| 503 | `no_ready_runtime`, `runtime_unavailable`, or `busy` |

Default bounds: 64 active admitted requests, 16 KiB body, 5-second request deadline.
There is no waiting admission queue; a full semaphore returns `503 busy`.
Authentication precedes body buffering. Limits include health requests; health can
also return busy under saturation. Buffers and response objects are bounded, but
this is **not a complete hostile-network DoS defense**: the application semaphore
starts after HTTP headers are parsed, and the handler deadline does not cover
accepted idle connections, slow headers, response transmission or graceful drain.
An ingress proxy must enforce connection/header limits, TLS, idle/write deadlines,
rate limits and bounded shutdown; direct Internet deployment is unsupported.

Configuration is strict (unknown fields fail startup). Server ranges:
`max_in_flight` 1–1,024; `request_timeout_ms` 100–30,000; `max_body_bytes` 256–65,536.
Poll ranges: `interval_ms` 100–30,000; `timeout_ms` 100–10,000;
`freshness_ms` 500–60,000 and at least interval; `fanout` 1–16; at most 128 workers.
Capacity ranges match the memory/CPU input bounds, with 1–1,000,000 sandbox slots
and 1–1,024 restore slots (restore slots cannot exceed sandbox slots).
Configuration files are at most 64 KiB. Startup file reads precede the async runtime.

## Not implemented

Warmed capture/publication, template repository/cache, compatible-node restore,
atomic worker reservation/admission, command/app HTTP, TTL expiration, deletion,
restart reconciliation, network/resource enforcement and artifact retention.
Fork and user-facing pause/resume APIs remain deferred. No readiness endpoint,
capacity benchmark, workload image or privileged setup script is supplied.
