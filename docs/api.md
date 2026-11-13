# Native API

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

## Placement, IDs and blocking operations

Clients talk only to the controller and never choose or need to know nodes. For
create, the controller ranks every fresh, ready worker by advisory reserved load
(least projected memory/vCPU/slot load, then fewer active restores, then node ID),
generates the sandbox ID and forwards the create. The controller does not read
templates: a worker without a valid, compatible template answers before creating
anything. IDs are currently `<node_id>.<32 hex>`; treat them as **opaque**. The owner
prefix lets later calls and controller restarts route without an assignment table.
A worker rejects an ID whose prefix is not its own node. Direct worker create
remains behind the worker credential only (controller and operator use).

**Every management request is blocking** and returns its real outcome, like an
ordinary RPC: create returns `201` after the container is running or restored (or
an error after failure cleanup); exec returns exit code and bounded output; HTTP
returns the application's status/content-type/body; capture returns after template
publication with the source running; delete returns after cleanup. There is no
operation ID, operation endpoint or stored result. Different sandboxes run
concurrently on the worker's fixed operation pool (`max_concurrent_operations`,
default 16, range 1–64); `max_concurrent_restores` bounds create/restore/capture.

At most one create/exec/HTTP/capture runs per sandbox. A conflicting request for a
sandbox with work in flight gets an immediate `409 sandbox_busy`; it is never queued.
Concurrent exec/HTTP in one sandbox is deliberately not supported: a bound-violating
exec terminates the whole sandbox, which would race a parallel command's cleanup.
`DELETE` is the exception: it cancels in-flight work of that sandbox (whose request
then returns its failed or interrupted outcome) and returns after cleanup. A second
concurrent DELETE of the same sandbox waits for the same cleanup and returns its
result (up to 64 waiting DELETEs per sandbox; more get `503 busy`). A full operation pool
or restore budget returns `503 busy` before anything starts.

**Deadlines cover the operation.** Each route's worker waits for at most:

| Route | Outcome wait |
| --- | --- |
| create | `[server.operation_deadlines] create_ms` (default 120,000) |
| capture | `capture_ms` (default 300,000) |
| delete | `delete_ms` (default 120,000) |
| exec / HTTP | the request's `timeout_ms` + `margin_ms` (default 30,000; covers teardown and bound-kill cleanup) |
| status, GET, preflight | `request_timeout_ms` (default 5,000) |

The request body is always read within `request_timeout_ms`. A service's route
deadline is the route's longest valid wait plus one `request_timeout_ms` per
forwarding hop, and the controller's per-request forward timeout is the owner's
wait plus one `request_timeout_ms`, so the innermost layer reports first. Configure
`[server.operation_deadlines]` (and `[server.application_http]`) identically on the
controller and workers. Ranges: create/delete 1,000–1,800,000 ms, capture
1,000–3,600,000 ms, margin 1,000–300,000 ms. If a wait expires the worker returns
`504 operation_timeout`; the controller returns `504 owner_response_timeout`, or
`503 owner_response_unavailable` when the owner's answer is lost.

**Client disconnect or timeout never orphans work.** The worker's admission thread,
not the HTTP handler, owns every job. An exec, HTTP, capture or delete job runs to a
terminal state with normal cleanup, TTL and bound enforcement; only its result is
discarded, so read the sandbox with GET afterward. A create is different: the client
cannot learn a controller-generated ID whose reply was lost, so when the worker
finds the create reply undeliverable (client disconnect, any layer's expired wait)
it deletes the new sandbox, recording `error:"create_response_lost"`. Only in the
small window where the worker delivered the reply but a later hop failed to write it
can a sandbox remain unknown to its client; its TTL bounds it.

**Lost responses are not exactly-once.** Retrying a create after a lost response
may create a second sandbox, as with other gateway-assigned sandbox APIs. The first
is normally deleted as above (otherwise TTL bounds it), and an ambiguous create error
names its generated `sandbox_id` so the caller can GET or DELETE it. A direct worker create with an existing ID is idempotent
(`200` with current state; `409 sandbox_busy` while that create is in flight;
`409 idempotency_conflict` for different input). An exec or HTTP request runs at most
once, but a client retry runs it again: a lost response may hide a command or
application side effect that already happened. A capture retry for a published
template ID returns `409 template_already_exists`. Delete is safe to repeat, also
concurrently (a second DELETE waits for the first and gets its result).

Create failover is limited to **definitive pre-launch rejections**, where the worker
answered before creating any resource: `busy`, `admission_exhausted`,
`record_limit`, `runtime_unavailable`, `worker_unavailable` or `template_unavailable`.
The controller then tries the next candidate with a new ID, at most three attempts.
A capacity rejection writes no record, so failover cannot consume `max_records`. All
attempts share one budget (`create_ms` + one `request_timeout_ms`) that ends before
the controller's route deadline; a later attempt gets only the remaining budget, and
none starts with less than `request_timeout_ms` left. It never fails over on
transport errors (including refused connections), timeouts or a failure after launch;
those errors include the generated `sandbox_id`. No candidates or capacity rejections
give `503 no_capacity`; only template rejections give `422 template_unavailable`.
Records are retained as tombstones; IDs are never reused.

## Endpoints

| Method/path | Behavior |
| --- | --- |
| `GET /healthz` | `200 {"service":"worker" or "controller","live":true}`; not readiness |
| `GET /v1/status` | Worker: configured budgets, reserved usage, CPU overcommit, admission/runtime status and `qualification:"unvalidated"`. Controller: cached validated nodes and freshness; `lifecycle_implemented:true` describes dispatch code, not runtime qualification. |
| `GET /v1/preflight` | Worker only: cached read-only startup checks, versions/compatibility fingerprint; authenticated |
| `POST /v1/sandboxes` | Blocking create/restore; `201` with the sandbox view once running. No caller ID, rootfs/config/path fields |
| `GET /v1/sandboxes/{id}` | `200` view: `sandbox_id`, `template_id`, `state`, static `error`, absolute Unix `expires_at` |
| `DELETE /v1/sandboxes/{id}` | Blocking; `200` view after cleanup (`deleted`, or `failed` for a never-launched ID); `500 cleanup_failed` otherwise |
| `POST /v1/sandboxes/{id}/exec` | Blocking bounded command; `200` result |
| `POST /v1/sandboxes/{id}/http` | Blocking bounded application HTTP (not a management proxy); `200` result |
| `POST /v1/sandboxes/{id}/capture` | Blocking warmed-template capture; `200` after publication, with the source running (it is only briefly frozen) |

Create example: `201 {"sandbox_id":"node-a.3f0c…","template_id":"example-template",
"state":"running","error":null,"expires_at":1700000000}`. States are `creating`,
`running`, `capturing`, `deleting`, `deleted`, `failed` and `cleanup_failed`. Capture
returns the source to `running` once runc reports it running after the thaw, or makes
it terminal through deletion. Delete/TTL/restart uses `deleting -> deleted` or `cleanup_failed`.
Cleanup failures keep memory/live admission reserved and retry in the background.
GET of an unknown sandbox is 404.

Worker restart deliberately terminates previous live workloads; it does not resume
them from arbitrary in-memory state. Requests in flight lose their responses.
Template publications survive restart.

### Create

```json
{"template_id": "example-template", "ttl_seconds": 120}
```

`template_id` and `ttl_seconds` (1–86,400) are required; optional `memory_mib`
(1–1,048,576) and `vcpus` (1–4,096) default to the template's values. Unknown fields
are rejected, including the former `sandbox_id`, `runtime` and `architecture`: only
`runc_criu` exists, and the owner's template fixes the architecture. Operator budgets
further restrict resources. A warm template rejects explicit values that differ from
its captured resources (`422 template_resource_mismatch`); a cold template that
declares no defaults needs both values (`422 resources_required`). Cold init argv
comes only from the trusted template, never from a create request. Warm restore
requires the captured memory/vCPU/pids/config and host compatibility.

During admission the worker checks the template manifest (digest sidecar, strict
fields, exact host compatibility including architecture, network policy and pids);
failure is a pre-launch `422 template_unavailable`. The create job hashes each layer
image the first time this worker mounts it and a warm template's checkpoint archive
the first time it is unpacked into the node cache, so a damaged artifact is a failed
create with a tombstone and static error, never a running ID; later creates reuse
the verified mounts and cache. TTL starts at admission. A dedicated expiry watchdog kills the
cgroup at expiration independently of long artifact work; private cleanup follows.
Timer/scheduling granularity is not a hard real-time guarantee.

### Exec

```json
{"argv":["/fixture","counter"],"timeout_ms":1000,"max_output_bytes":4096}
```

Argv is executed **inside the container by runc**, with no shell interpolation or
host executable selection. No inherited management environment; UID/GID 65534,
fixed PATH/HOME/LANG and cwd `/workspace`. Argv: 1–64 arguments, each at most 4096
bytes, no NUL and a nonempty first argument. Timeout: 1–60,000 ms, additionally
clamped to remaining TTL. Combined raw stdout/stderr limit: 1–1,048,576 bytes;
invalid UTF-8 is replaced for JSON, so JSON encoding may be larger. The `200` result
contains `exit_code`, `stdout`, `stderr`, `interrupted`, `error` and `sandbox_state`.
A nonzero program exit is a normal result. Timeout, output overflow or surviving
output-pipe descendants terminate the whole sandbox: the result then has
`interrupted:true`, `error:"exec_deadline_or_output_limit"`, the bounded output and
`sandbox_state:"deleted"` (or `cleanup_failed`). Other exec failures return a static
error and also terminate the sandbox. This
conservative behavior prevents killing only a detached runc client and leaking its
workload. Every exec joins its own worker-created child cgroup; successful completion
also kills remaining descendants and removes that group. Closing inherited output
pipes does not permit a background child to escape command cleanup. Background jobs
are not a supported exec contract.

Results are returned once and never stored. Commands are not logged; the
worker-authored process JSON is temporarily stored under the protected private
directory. Checkpoint artifacts can contain workload secrets: protect the entire root.

### Capture

```json
{"template_id":"warmed-example","runtime":"runc_criu"}
```

Success is `200 {"sandbox_id":"...","template_id":"warmed-example","generation":"<32 hex>",
"state":"running"}`; the worker generates the capture generation. Template IDs are
immutable; existing publication names are rejected (`409 template_already_exists`),
and a concurrent capture to the same name gets `409 template_busy`. Unpublished work
is staged in `staging/<template-id>`; if removing a failed stage itself fails, the
capture reports that error and the template ID stays unusable (capture returns
`directory_create_failed`) until the worker restarts and reconciles staging.

Capture **does not stop the source** (AgentENV pattern): the worker freezes it with
`runc pause`, seals its upper directory into a content-addressed EROFS layer, takes a
CRIU checkpoint with `--leave-running` (established TCP, external Unix sockets and
file locks included) and thaws it, then archives the images and publishes the
manifest. The source is unavailable only during that frozen window (the real-image
gate measures it; it grows with the upper's size and the process memory); clients
connecting meanwhile wait and are served after the thaw. On any failure the source
is thawed and stays running if runc reports it running; only a source that stays
frozen or was cancelled/expired is deleted. Failure publishes no template.
Established connections, including outbound ones, do not block capture. Loopback
connections continue in children; a child's copy of a connection to an external
peer fails on first use because the peer and the source slot's conntrack/NAT state
are never cloned. The fixture's independent child restore, open-file/mapping and
loopback-TCP gate passed; other applications/hosts remain unqualified. There is no
user-facing pause, fork or S3 operation.

### Networking

Create has no caller-authored network field: callers select an immutable template.
Manifest v3 specifies either `{"mode":"isolated"}` (loopback only, no external links) or:

```json
{"mode":"tcp_allowlist","egress":[{"ip":"198.51.100.20","port":8443}],"service_ports":[8080]}
```

The worker rejects any destination/port or service port outside `[native.network]`
operator bounds, including on warm restore. At most 64 literal IPv4 TCP entries
and 16 service ports; no domains, CIDRs, protocols, DNS, UDP, IPv6 or host-network
policy types. Unsupported/unknown input fails explicitly. The fixed internal
`192.0.2.0/30`, loopback, link-local, multicast and pool destinations cannot be
operator egress entries. Other destinations (including host endpoints) require
explicit operator approval of that exact IP and port. There is no implicit access
to the host, siblings or their service ports. Necessary IPv4 fragmentation-needed
control replies are accepted only toward the guest and only when conntrack relates
them to an authorized TCP destination/port; this does not add an ICMP policy type
or permit workload ICMP/raw socket creation.

**Current restriction:** policy endpoints are fixed in the immutable template and
in captured children. Per-create policy subsets are not implemented; publish a
separate approved template for a different tool-service destination. Selection
cannot broaden the operator ceiling. See [network architecture](network.md) for
operator bridge/pool prerequisites and the fixed-address restore boundary.

### Application HTTP

```json
{"port":8080,"method":"POST","path":"/tool?mode=small","headers":{"content-type":"application/json"},"body":"{\"input\":\"example\"}","timeout_ms":2000,"max_response_bytes":4096}
```

`POST /v1/sandboxes/{id}/http` has the same authentication, blocking outcome and
per-sandbox exclusion as exec/capture. It runs on the worker's bounded operation pool. Only the selected sandbox's
fixed guest IP and an explicitly template/operator-approved service port are
reachable. GET/POST/PUT/DELETE/HEAD, relative absolute-path-form paths up to 2048
ASCII bytes (optional query), no URL/authority, `//`, backslash or fragment. The
only request headers are lowercase `accept` and `content-type`, each at most 256
printable ASCII bytes. No caller/management Authorization, Host or hop-by-hop header
is forwarded. The client ignores proxy environment and does not follow redirects.

By default, body is a UTF-8 JSON string up to 8192 bytes (text/JSON, **not a binary
contract**), deadline is 1–30,000 ms, and response body limit is 1–65,536 bytes.
The controller and worker can each explicitly configure `[server.application_http]`
with `max_body_bytes` up to 16,384, `max_response_bytes` up to 8,388,608, and
`max_timeout_ms` up to 600,000. Both services enforce their configured ceilings;
configure them consistently. These are opt-in ceilings, not new defaults.

Every operation deadline remains clamped to remaining TTL; an owned helper is
killed/drained within a further one-second startup/exit allowance. The route
deadline follows `max_timeout_ms` plus `margin_ms` (see above), so a long
application deadline is waited for in full. Responses remain UTF-8 only; headers are checked against
16 KiB and only content-type (at most 256 bytes) is returned. Client parsing has its
own bounded HTTP/1 buffers.
The normal management body limit still applies. A 16 KiB text body
can expand toward 96 KiB inside its JSON request envelope; opt-in body configuration
requires sufficient `server.max_body_bytes` (128 KiB covers all supported fields).
The helper's private request file is bounded at 128 KiB. Results are carried inline
and never stored: a result's worst-case JSON size is `6 * max_response_bytes + 8192`
(an 8 MiB raw response can be about 48 MiB when JSON-escaped). Helper output,
controller forwarding and memory are bounded by that per-request size; in-flight
result memory is bounded by the operation pool size times the configured ceiling.

Non-UTF-8, oversized, invalid or timed-out responses fail with a static error, never
an upstream error body. No response is truncated into a successful result. Unlike exec bounds, an HTTP bound failure does not terminate the sandbox.

Success is `200 {"status":200,"content_type":"text/plain","body":"..."}`; non-2xx
and redirects are returned as application statuses, not followed. A port outside
the template's approved service ports is `403 service_port_not_authorized`; an
application failure, timeout or bound is `502 application_http_failed_or_bounded`.
A client retry sends the application request again. On a lost response or worker
crash, application side effects may already have occurred: there are no
exactly-once remote application semantics.

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
network/filesystem/subprocess I/O. Routing requires a fresh validated owner;
worker rejection is authoritative even if controller usage is stale.

Default HTTP bounds: 64 active requests, 16 KiB body, 5-second body deadline,
route-specific handler deadlines (above), no waiting HTTP admission queue. Blocked
requests hold their permit while they wait, so size the controller's `max_in_flight`
above the sum of its workers' operation pools. Full request or lifecycle queues
return `503 busy`. Controller forwarding accepts at most the request's largest valid
result (64 KiB for sandbox views; `6 * max_*_bytes + 8192` for exec/HTTP).
Subprocess output/deadlines and artifact sizes are independently bounded. Configuration files are capped at 64 KiB.
Startup fields are strict; credentials/error bodies are not parser diagnostics.

Static errors use `{"error":{"code":"invalid_input","message":"..."}}`.
Common statuses: 200 result, 201 created, 400 invalid fields/IDs, 401 unauthorized,
403 unapproved service port, 404 missing route/sandbox, 408 request/body deadline,
409 `sandbox_busy`/`sandbox_not_running`/template conflicts, 413 body limit, 422
template unavailable or resource rules, 500 failed operation or `cleanup_failed`,
502 application HTTP failure, 503 disabled/preflight, owner unavailability, busy or
capacity, 504 outcome wait expired. Failed operations name a static code; read the
sandbox state afterward, because a failed exec, or a capture that leaves the source
frozen, can terminate the sandbox.

Server bounds: concurrency 1–1024, request timeout 100–30,000 ms, body 256–131,072 bytes.
Durable records hold lifecycle metadata only (bounded at 64 KiB each, `max_records`
including tombstones); there are no output-retention budgets. Records written by
the earlier polling API (schema 1) fail startup closed; reconcile such a root with
the binary that wrote it before upgrading.
Poll: interval 100–30,000 ms, timeout 100–10,000 ms, freshness 500–60,000 ms and at least
interval, fanout 1–16, workers at most 128. Capacity: memory/CPU as above, sandbox
slots 1–1,000,000, restore slots 1–1024 and at most sandbox slots. Native bounds are
listed in the [example configuration](../config/worker.native.example.toml).
