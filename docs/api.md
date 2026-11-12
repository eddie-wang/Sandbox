# Native API

> Review-branch note: this reference describes the reviewed lifecycle baseline.
> Draft networking and `/http` additions are described in the
> [latest architecture](../plans/container-architecture-eddie-wang-2026-11-12.md).
> The detailed API reference has not yet been fully updated or network-qualified.

One `sandboxd` runs as controller or worker. This is an early native API, not an
E2B-compatible interface. Runtime execution is experimental; the bounded local
functional smoke has passed, but general isolation/workload readiness is unqualified;
[operator prerequisites and validation](runtime.md) are mandatory before relying
on it. The default worker has no enabled runtime and fails closed.

## Authentication and transport

Only `GET /healthz` is public. Every other route, including unknown routes and
preflight, requires exactly one `Authorization: Bearer <token>` header. Controller
and worker tokens are separate; the controller's configured `worker_auth` matches
its workers. Each credential source has exactly one `env` name or `file` path.
Tokens are 32–1024 printable ASCII bytes without whitespace; secret files may end
in one LF/CRLF. Restart to rotate. Never put credentials in CLI arguments or logs.

There is no built-in TLS, tenancy, RBAC, audit trail or per-user quota. Put listeners
behind a trusted TLS/auth/ingress boundary. Ingress must bound connections, slow
headers, response writes, rates and drain. The application semaphore begins after
header parsing, not on TCP accept. Direct Internet deployment is unsupported.

Worker origins are strict administrator-configured HTTP(S) origins without
credentials, path, query or fragment. The pooled client ignores proxy environment
variables, validates HTTPS certificates and never follows redirects. There is no
registration, download URL or arbitrary-upstream proxy API. DNS and configuration
are trusted infrastructure.

## Ownership and asynchronous operations

Sandbox IDs are caller-chosen **`<node_id>.<local_id>`**. Each component is 1–64
ASCII alphanumeric, hyphen or underscore characters. Template and operation IDs
use one component. The controller validates/routes only configured owners; changing
node membership or restarting the controller cannot move an existing ID. Clients
choose a node from authenticated status. Scheduling is deliberately conservative:
create checks that owner's fresh compatible status and advisory capacity; it does
not silently fail over an ambiguous create to another worker. The worker atomically
checks memory, live slots, restore slots and `vcpus * cpu_overcommit` quota budget.

Mutations return `202` **only after durable worker acceptance**. Accepted is not
running or successful. Poll sandbox state or the operation result. The worker has
a bounded 32-entry mailbox and serializes short admission/durable state transitions
off Tokio. A fixed `max_concurrent_operations` thread pool (default 16, range 1–64)
runs blocking work concurrently across different sandboxes; one job per sandbox and
separate restore slots prevent conflicting mutations. Same-sandbox contention or a
full operation/restore pool returns `503 busy` without accepting a new operation. A short
HTTP deadline can expire before the actor acknowledges or after acceptance. On
**any transport error, 408 or 503, first read state or retry the identical ID and
payload**. Never invent another ID merely because a response was lost. Work that
was queued but not durably accepted can disappear on worker crash; retry is safe.
No external resource is created before its owning durable record exists.

Create is idempotent for the complete original payload. Exec/capture require
`operation_id`; the same ID/kind/payload replays the existing operation, while
changed input returns `409 idempotency_conflict`. Delete is idempotent. Deleted and
failed records are retained as tombstones; IDs cannot be reused. Retention limits
return `503 retention_limit`, rather than silently dropping idempotency records.
An admission rejection is a durable `failed` create record; use a new ID after
correcting the request/capacity. A retry through the controller can fail its advisory
capacity gate even for an existing ID; GET still routes to the owner.

## Endpoints

| Method/path | Behavior |
| --- | --- |
| `GET /healthz` | `200 {"service":"worker" or "controller","live":true}`; not readiness |
| `GET /v1/status` | Worker: configured budgets, reserved usage, CPU overcommit, admission/runtime status and `qualification:"unvalidated"`. Controller: cached validated nodes and freshness; `lifecycle_implemented:true` describes dispatch code, not runtime qualification. |
| `GET /v1/preflight` | Worker only: cached read-only startup checks, versions/compatibility fingerprint; authenticated |
| `POST /v1/sandboxes` | Durable create/restore acceptance; no arbitrary rootfs/config/path fields |
| `GET /v1/sandboxes/{id}` | State, static error code, absolute Unix `expires_at`, operation summaries |
| `DELETE /v1/sandboxes/{id}` | Durable deletion request; poll until `deleted` |
| `POST /v1/sandboxes/{id}/exec` | Durable bounded command operation |
| `POST /v1/sandboxes/{id}/capture` | Durable warmed-template capture operation |
| `GET /v1/sandboxes/{id}/operations/{operation_id}` | Pending/complete/failed operation, static error, result/template ID |

Example acceptance: `{"sandbox_id":"node-a.example","operation_id":null}`.
Create progresses `creating -> running` or `failed/cleanup_failed`. Capture uses
`capturing`, then returns the source to `running` only after actual recovery, or
makes it terminal through deletion. Delete/TTL/restart uses `deleting -> deleted`
or `cleanup_failed`. Cleanup failures keep memory/live admission reserved and
retry on the lifecycle thread. GET of an unknown sandbox/operation is 404.

Worker restart deliberately terminates previous live workloads and fails pending
operations with `worker_restarted`; it does not resume them from arbitrary in-memory
state. Completed operation outputs and template publications survive restart.

### Create

```json
{
  "sandbox_id": "node-a.example",
  "template_id": "example-template",
  "runtime": "runc_criu",
  "architecture": "x86_64",
  "memory_mib": 64,
  "vcpus": 1,
  "ttl_seconds": 120
}
```

All fields required; unknown fields rejected. Runtime is exactly `runc_criu`;
architecture is `x86_64` or `aarch64` and must match the worker/template. Memory:
1–1,048,576 MiB; vCPUs: 1–4,096; TTL: 1–86,400 seconds. Operator budgets further
restrict these. Cold init argv comes only from the trusted template, never from a
create request. Warm restore requires exactly the captured memory/vCPU/pids/config
and host compatibility. Filesystem/digest/compatibility failures become failed
records, not running IDs. TTL starts at durable acceptance. A dedicated expiry
watchdog kills the cgroup at expiration independently of long artifact work;
private cleanup follows on the lifecycle thread. Timer/scheduling granularity is
not a hard real-time guarantee.

### Exec

```json
{"operation_id":"command-1","argv":["/fixture","counter"],"timeout_ms":1000,"max_output_bytes":4096}
```

Argv is executed **inside the container by runc**, with no shell interpolation or
host executable selection. No inherited management environment; UID/GID 65534,
fixed PATH/HOME/LANG and cwd `/workspace`. Argv: 1–64 arguments, each at most 4096
bytes, no NUL and a nonempty first argument. Timeout: 1–60,000 ms, additionally
clamped to remaining TTL. Combined raw stdout/stderr limit: 1–1,048,576 bytes;
invalid UTF-8 is replaced for JSON, so JSON encoding may be larger. Results contain
`exit_code`, `stdout`, `stderr`, `interrupted`. A nonzero program exit is a completed
operation, not necessarily a service error. Timeout, output overflow or surviving
output-pipe descendants terminate the whole sandbox and fail the operation. This
conservative behavior prevents killing only a detached runc client and leaking its
workload. Every exec joins its own worker-created child cgroup; successful completion
also kills remaining descendants and removes that group. Closing inherited output
pipes does not permit a background child to escape command cleanup. Background jobs
are not a supported exec contract.

Results are retained and authenticated. Worker retained-output budget defaults to
16 MiB; one sandbox's encoded outputs are capped below 8 MiB. Operation count and
record count are separately bounded. Commands are not logged; the worker-authored
process JSON is temporarily stored under the protected private directory. Checkpoint
artifacts and exec outputs can contain workload secrets: protect the entire root.

### Capture

```json
{"operation_id":"capture-1","template_id":"warmed-example","runtime":"runc_criu"}
```

Template IDs are immutable; existing publication names are rejected. Capture stops
and checkpoints the source, archives its upper (not a merged rootfs or promoted
lower), recovers the source from its own images, then publishes matching digests.
Failure publishes no incomplete pair. A failed checkpoint with uncertain process
state, or failed source recovery, terminates/cleans the source rather than treating
PID liveness as recovery. Failure before checkpoint leaves the source running;
after a complete checkpoint the worker attempts source recovery. Capture is
 disruptive, not zero-downtime. The fixture's independent child restore and open-file/
mapping consistency gate passed; other applications/hosts remain unqualified. There is no per-step pause, fork, S3 or application HTTP operation.

### Networking

The only supported policy is `isolated`, authored by the worker/template. There is
no API network-policy field: egress/destination/port/host-network requests are
rejected as unknown input. Workloads get their own netns with no external link or
route, no network capabilities and no socket syscalls. No host firewall rules,
interfaces, routes or sysctls are changed. CRIU's temporary nftables network locks
and firewall-state helpers operate inside the owned workload namespace. This does **not** implement a usable egress allowlist or app
HTTP service, and is not presented as tested isolation without the real gate.

## Status and bounds

Worker status schema is `1`. `usage` counts reservations, not measured utilization;
null means disabled/failed preflight, not zero. `vcpus` in usage sums quotas, compared
with configured physical/admission `capacity.vcpus * cpu_overcommit` (factor 1–16).
The fixed operation pool bounds total parallel mutations. `max_concurrent_restores`
bounds create/restore/capture jobs independently and cannot exceed that pool. Deletes
cancel active work, then perform per-sandbox serialized cleanup; another sandbox's
long command/restore does not block admission or an available operation slot.
`ready:true` means explicit experimental enablement, read-only preflight and
reconciliation passed. The API's **qualification remains unvalidated** because it
does not attest an installation from a separately run smoke.

Controller polls at bounded fanout, with 64 KiB responses, total per-call deadlines
and identity/schema checks. Failed polls retain last status but mark it unreachable
and not fresh; aged successful observations are also excluded. No state lock spans
network/filesystem/subprocess I/O. Ownership routes require a fresh validated owner;
worker rejection is authoritative even if controller usage is stale.

Default HTTP bounds: 64 active requests, 16 KiB body, 5-second body/handler deadline,
no waiting HTTP admission queue. Full request or lifecycle queues return `503 busy`.
Worker forwarding responses are capped at 8 MiB; subprocess output/deadlines and
artifact sizes are independently bounded. Configuration files are capped at 64 KiB.
Startup fields are strict; credentials/error bodies are not parser diagnostics.

Static errors use `{"error":{"code":"invalid_input","message":"..."}}`.
Common statuses: 400 invalid fields/IDs, 401 unauthorized, 404 missing route/resource,
408 HTTP deadline, 409 idempotency conflict, 413 body limit, 503 disabled/preflight,
owner unavailability, busy, retention or durability failures. An enabled worker can
return a 202 acceptance followed by a failed resource operation; always poll results.

Server bounds: concurrency 1–1024, request timeout 100–30,000 ms, body 256–65,536 bytes.
Poll: interval 100–30,000 ms, timeout 100–10,000 ms, freshness 500–60,000 ms and at least
interval, fanout 1–16, workers at most 128. Capacity: memory/CPU as above, sandbox
slots 1–1,000,000, restore slots 1–1024 and at most sandbox slots. Native bounds are
listed in the [example configuration](../config/worker.native.example.toml).
