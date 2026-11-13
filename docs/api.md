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
credentials, path, query or fragment. The pooled clients ignore proxy environment
variables, validate HTTPS certificates and never follow redirects. There is no
registration, download URL or arbitrary-upstream proxy API: the app proxy reaches
only a sandbox's own approved service ports. DNS and configuration are trusted
infrastructure.

## Placement, IDs and blocking operations

Clients talk only to the controller and never choose or need to know nodes. For
create, the controller offers every fresh, ready worker whose last polled usage
leaves room for the request, ranked by advisory projected load (least projected
memory/vCPU/slot load, then fewer active restores, then round-robin between equal
scores, as AgentENV's scheduler takes turns), generates the sandbox ID and forwards
the create. The projected load adds the controller's own creates that are still in
flight or were answered after the worker's last polled status (their requested
memory, vCPUs and one slot each); an entry is dropped once a poll sent after the
answer counts it, when the node refused before reserving anything, or after the
freshness window. Creates sent at the same moment therefore spread over equal
workers instead of all landing on the first one. These entries only order the
workers: the room check uses polled usage alone, because a poll taken while a create
is in flight already counts it, so a worker with one free slot is still offered
(no false `no_capacity`). The table holds at most 4,096 entries; worker admission
stays final. The controller does not read
templates: a worker without a valid, compatible template answers before creating
anything. IDs are currently `<node_id>.<32 hex>`; treat them as **opaque**. The owner
prefix lets later calls and controller restarts route without an assignment table.
A worker rejects an ID whose prefix is not its own node. Direct worker create
remains behind the worker credential only (controller and operator use).

**Every management request is blocking** and returns its real outcome, like an
ordinary RPC: create returns `201` after the container is running or restored (or
an error after failure cleanup); exec returns exit code and bounded output (or, in
streaming mode, sends the output as it arrives and ends with the exit); kill returns
after the command has ended; capture returns after template publication with the
source running; delete returns after cleanup. There is no operation ID, operation
endpoint or stored result. App traffic is not a management operation: it goes
through the [app proxy](#app-proxy). Create, capture and delete of different
sandboxes run concurrently on the worker's fixed operation pool
(`max_concurrent_operations`, default 16, range 1–64); `max_concurrent_restores`
bounds create/restore/capture.

At most one create, capture or delete runs per sandbox, and commands may not
overlap a create or capture of the same sandbox: such a conflicting request gets an
immediate `409 sandbox_busy`; it is never queued. Several commands may run at once
in one sandbox (`max_execs_per_sandbox`, default 8, range 1–64; `409 exec_limit`
beyond it; `max_concurrent_execs`, default 64, range 1–1024, per worker; `503 busy`
beyond it). Each runs on its own thread and in its own resource group, so a bound
violation stops only that command. A capture is refused while any command runs (a
checkpoint cannot include their host pipes). `DELETE` is the exception: it cancels
in-flight work and running commands of that sandbox (whose requests then return
their failed or interrupted outcome) and returns after cleanup. A second concurrent
DELETE of the same sandbox waits for the same cleanup and returns its result (up to
64 waiting DELETEs per sandbox; more get `503 busy`). A full operation pool or
restore budget returns `503 busy` before anything starts.

**Deadlines cover the operation.** Each route's worker waits for at most:

| Route | Outcome wait |
| --- | --- |
| create | `[server.operation_deadlines] create_ms` (default 120,000) |
| capture | `capture_ms` (default 300,000) |
| delete | `delete_ms` (default 120,000) |
| exec (blocking mode) | the request's `timeout_ms` + `margin_ms` (default 30,000; covers teardown and bound-kill cleanup) |
| exec kill | `margin_ms` |
| status, GET, preflight | `request_timeout_ms` (default 5,000) |
| exec (streaming mode), app proxy | none: headers come at once; then only `[server.proxy] idle_timeout_ms` applies (see [app proxy](#app-proxy)) |

The request body is always read within `request_timeout_ms`. A service's route
deadline is the route's longest valid wait plus one `request_timeout_ms` per
forwarding hop, and the controller's per-request forward timeout is the owner's
wait plus one `request_timeout_ms`, so the innermost layer reports first. Configure
`[server.operation_deadlines]` identically on the controller and workers, and give
the controller a larger `[server.proxy] idle_timeout_ms` than its workers. Ranges: create/delete 1,000–1,800,000 ms, capture
1,000–3,600,000 ms, margin 1,000–300,000 ms. If a wait expires the worker returns
`504 operation_timeout`; the controller returns `504 owner_response_timeout`, or
`503 owner_response_unavailable` when the owner's answer is lost.

**Client disconnect or timeout never orphans work.** The worker's admission thread,
not the HTTP handler, owns every job and command. A command, capture or delete runs
to a terminal state with normal cleanup, TTL and bound enforcement (a disconnected
streaming client does not stop its command either); only its result is discarded,
so read the sandbox with GET afterward. A create is different: the client
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
`409 idempotency_conflict` for different input). An exec or proxied request runs at
most once, but a client retry runs it again: a lost response may hide a command or
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
| `POST /v1/sandboxes/{id}/exec` | Bounded command: blocking `200` JSON result, or `stream:true` for `200` server-sent events |
| `POST /v1/sandboxes/{id}/exec/{exec_id}/kill` | Blocking; stops one running command, `200 {"sandbox_id","exec_id","state":"exited"}` after it ended; `404 exec_not_found` if it is not running |
| any method `/v1/sandboxes/{id}/proxy/{port}/{path}` | [App proxy](#app-proxy), path form: streams the request to the sandbox's approved service port and returns the application's answer |
| any method, any path, Host `{port}-{id}.{proxy_domain}` | App proxy, host form (controller only, when `proxy_domain` is configured) |
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
fields, exact host compatibility including architecture, network policy and pids)
and, for a warm template, CRIU's own CPU check of its saved `cpuinfo.img` on this
host (`criu cpuinfo check`, once per template per worker; see contracts.md);
failure is a pre-launch `422 template_unavailable`, so the controller tries another
node. CPU compatibility can be one-directional between two hosts. The create job itself hashes
each layer image this worker does not yet trust (creates hash in parallel; two
creates of the same new layer hash it once; creates whose layers are trusted never
wait behind a hash) and a warm template's checkpoint archive the first time it is
unpacked into the node cache, so a damaged artifact is a failed create with a
tombstone and static error, never a running ID. A hashed layer stays trusted, also
across worker restarts, while its image file keeps the same identity (device, inode,
size, modification and change time); any change means hashing it again. Later
creates reuse the verified mounts and cache. TTL starts at admission. A dedicated expiry watchdog kills the
cgroup at expiration independently of long artifact work; private cleanup follows.
Timer/scheduling granularity is not a hard real-time guarantee.

### Exec

```json
{"argv":["/fixture","counter"],"timeout_ms":1000,"max_output_bytes":4096}
```

Argv is executed **inside the container by runc** (`runc exec`), with no shell
interpolation or host executable selection. No inherited management environment;
UID/GID 65534, fixed PATH/HOME/LANG and cwd `/workspace`. Argv: 1–64 arguments, each
at most 4096 bytes, no NUL and a nonempty first argument. Timeout: 1–60,000 ms,
additionally clamped to remaining TTL. Combined raw stdout/stderr limit:
1–1,048,576 bytes. Optional `"stream": true` selects streaming mode.

Every command gets a worker-generated `exec_id`, its own thread and its own child
resource group `exec-<exec_id>` of the sandbox, and several may run at once (see
above). **A timeout, output overflow, kill request or the sandbox's deletion/expiry
stops only that command:** the worker kills its resource group (the command and
everything it started) and the result reports `interrupted:true`, `exit_code:null`
and `error` `exec_timeout`, `exec_output_limit`, `exec_killed` or
`sandbox_cancelled_or_expired`, with the output delivered up to the limit. The
sandbox keeps running. A normal end also kills what the command left behind (for
example background children that kept its output open) and removes its group, so
background jobs are not a supported exec contract. A nonzero program exit is a
normal result. A start failure (for example runc refusing the command) is a result
with a static `error` and no exit code; only a command whose group cannot be emptied
within five seconds also deletes the sandbox (`exec_cleanup_failed`), because it
may have left unknown processes.

**Blocking mode** returns `200 {"exec_id":7,"exit_code":0,"stdout":"…","stderr":"…",
"interrupted":false,"error":null,"sandbox_state":"running"}` after the command ended;
invalid UTF-8 is replaced for JSON, so the JSON may be larger than the raw output.

**Streaming mode** returns `200` with `Content-Type: text/event-stream` at once and
sends server-sent events as the command produces output:

```text
event: start
data: {"exec_id":7}

event: stdout
data: {"data":"<base64 bytes>"}

event: stderr
data: {"data":"<base64 bytes>"}

event: exit
data: {"exit_code":0,"interrupted":false,"error":null,"sandbox_state":"running"}
```

Output events carry raw bytes in base64 (any binary output survives) in arrival
order; exactly one `exit` event ends the stream. A refused command (busy, not
running, limit) is an ordinary JSON error instead of a stream. The controller passes
the events through as they arrive, under its `[server.proxy]` bounds.

`POST /v1/sandboxes/{id}/exec/{exec_id}/kill` stops one running command (the ID from
the `start` event or a previous result) and returns `200` once it has ended and its
group is gone; that command's own result then reports `exec_killed`. Kill also works
on an unhealthy worker.

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
manifest. The source is unavailable only from the pause to the resume (the real-image
gate reports the cgroup-freezer time and the longest gap a client saw, which is
somewhat longer because CRIU briefly thaws the cgroup while the tasks stay stopped;
both grow with the upper's size and the process memory); clients connecting
meanwhile wait and are served after the thaw. On a failure the source is thawed and
stays running if runc reports it running, as in AgentENV (`500 checkpoint_failed`).
A `runc checkpoint` stopped at its command deadline or 64 KiB output limit is
handled the same way but answers `500 checkpoint_interrupted`, so callers can tell:
a dump killed midway may leave CRIU's network lock, repaired sockets or parasite code
in a source that still runs, and a caller may delete it. A source that stays frozen,
is not running after the thaw, or was cancelled/expired is deleted. A source
template that already has 16
sealed layers is refused before the pause (`409 template_layer_limit`; the source
keeps running). Failure publishes no template.
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

### App proxy

App traffic to a sandbox's own service (HTTP, streaming, WebSocket) uses a reverse
proxy after AgentENV's gateway and node proxy, instead of a management operation.
Two request forms reach the same place:

- **Host form** (controller, when the controller config sets
  `proxy_domain = "sandbox.example"`): any method and path with
  `Host: <port>-<sandbox-id>.sandbox.example`, for example
  `8000-node-a.3f0c….sandbox.example`. The sandbox ID is used verbatim, so it spans
  two DNS labels; host routing needs DNS-safe (lowercase) node IDs and a wildcard DNS
  name covering them. A host that is the domain itself, is not below it or has no
  hyphen in its first label is ordinary management traffic; a malformed port or ID
  below the domain is `400 invalid_input`.
- **Path form** (controller and worker), for clients without wildcard DNS:
  `/v1/sandboxes/<id>/proxy/<port>/<path>?<query>`; `/proxy/<port>` alone means `/`.

Both require the same single `Authorization: Bearer <token>` as management calls; the
controller checks it first, then routes by the ID's owner prefix to a fresh owner,
which checks that the sandbox is running (or capturing) and that the port is one of
its template's `service_ports` (`403 service_port_not_authorized` otherwise,
including isolated templates; `404`/`409 sandbox_not_running` for missing or
stopping sandboxes). The worker then opens a new connection to the sandbox's fixed
guest address from inside its router namespace (see the
[network architecture](network.md#app-proxy-boundary)).

The exchange is forwarded as HTTP/1.1: the method, raw path and query, the
application's status, headers and body, in both directions and streaming (large,
binary and chunked bodies, server-sent events), with hop-by-hop headers removed.
The **management Authorization header never reaches the sandbox** (so an
application cannot receive an `Authorization` header through the proxy), Host
becomes `192.0.2.2:<port>`, and `X-Forwarded-Host` (the client's host) and
`X-Forwarded-Proto: http` replace any client-supplied forwarding headers. A request
asking to upgrade (`Connection: upgrade`, `Upgrade: websocket`) gets the
application's `101` and then a byte tunnel both ways. Redirects are returned, not
followed. CONNECT is refused. A request without an `Accept` header reaches the
application with `Accept: */*`, added by the controller's HTTP client. Both services
turn off Nagle's algorithm (`TCP_NODELAY`) on every accepted connection, and the
hops to the worker and to the guest set it too, so the last piece of a small answer
is sent at once instead of waiting for the client's delayed acknowledgement (before
this, every small call on a kept-alive connection took about 40 ms).

Bounds (`[server.proxy]` on each service): `max_connections` open exchanges
(default 256; `503 busy` beyond it, held until the response or tunnel ends) and
`idle_timeout_ms` (default 600,000): the proxy waits at most that long for the sending
side to move a byte — the response head, the next frame of either body, and a
tunnel's reads and blocked writes. A receiver that stops reading (its TCP window
closes) is not timed out: that exchange and its permit stay held until the client
reads again or disconnects. There is no total deadline: the client decides how long
to wait. On shutdown the controller stops accepting and waits for open requests at
most the longest management route wait plus two `request_timeout_ms`, then cuts any
exchange still open. Errors are JSON envelopes: `502 upstream_unavailable` (the service refused,
reset or answered nothing valid), `504 upstream_timeout` (worker idle timeout),
`504 owner_response_timeout` and `503 owner_response_unavailable` (controller to
worker). Deleting or expiring the sandbox ends its open exchanges, including ones
still connecting or waiting for the response head (`502 upstream_unavailable`), so a
pooled routing slot never carries a pending exchange to its next sandbox; a body
whose receiver has stopped reading sees the close at its next read. A retry sends
the request again; there are no exactly-once application semantics.

## Status and bounds

Worker status schema is `1`. `usage` counts reservations, not measured utilization;
null means disabled/failed preflight, not zero. `vcpus` in usage sums quotas, compared
with configured physical/admission `capacity.vcpus * cpu_overcommit` (factor 1–16).
The fixed operation pool bounds parallel create/capture/delete jobs.
`max_concurrent_restores` bounds create/restore/capture jobs independently and
cannot exceed that pool. Commands run outside the pool, bounded per sandbox and per
worker. Deletes cancel active work and commands, then perform per-sandbox serialized
cleanup; another sandbox's long command/restore does not block admission or an
available operation slot.
`ready:true` means explicit experimental enablement, read-only preflight and
reconciliation passed. The API's **qualification remains unvalidated** because it
does not attest an installation from a separately run smoke.

Controller polls at bounded fanout, with 64 KiB responses, total per-call deadlines
and identity/schema checks. Failed polls retain last status but mark it unreachable
and not fresh; aged successful observations are also excluded. No state lock spans
network/filesystem/subprocess I/O. Routing requires a fresh validated owner;
worker rejection is authoritative even if controller usage is stale.

Default management bounds: 64 active requests, 16 KiB body, 5-second body deadline,
route-specific handler deadlines (above), no waiting HTTP admission queue. Blocked
requests hold their permit while they wait, so size the controller's `max_in_flight`
above the sum of its workers' operation pools and blocking commands. Full request or
lifecycle queues return `503 busy`. Controller forwarding accepts at most the
request's largest valid result (64 KiB for sandbox views; `6 * max_output_bytes +
8192` for a blocking exec). App-proxy exchanges and streaming exec forwards are not
management requests: they bypass the management permit, body limit and route
deadline and are bounded by `[server.proxy]` instead.
Subprocess output/deadlines and artifact sizes are independently bounded. Configuration files are capped at 64 KiB.
Startup fields are strict; credentials/error bodies are not parser diagnostics.

Static errors use `{"error":{"code":"invalid_input","message":"..."}}`.
Common statuses: 200 result, 201 created, 400 invalid fields/IDs, 401 unauthorized,
403 unapproved service port, 404 missing route/sandbox, 408 request/body deadline,
409 `sandbox_busy`/`exec_limit`/`sandbox_not_running`/template conflicts, 413 body
limit, 422 template unavailable or resource rules, 500 failed operation or
`cleanup_failed`, 502 proxied service unavailable, 503 disabled/preflight, owner
unavailability, busy or capacity, 504 outcome wait or proxy idle timeout expired.
Proxied applications return their own statuses, which pass through unchanged.
Failed operations name a static code; read the sandbox state afterward, because a
capture that leaves the source frozen or not running, or a command whose resource
group cannot be emptied, terminates the sandbox. A 65th concurrent
DELETE of one sandbox (or kill of one command) gets `503 busy` with a message saying
too many requests already wait for it.

Server bounds: concurrency 1–1024, request timeout 100–30,000 ms, body 256–131,072 bytes,
`[server.proxy]` `max_connections` 1–65,536 and `idle_timeout_ms` 1,000–3,600,000.
The removed `[server.application_http]` table is rejected at startup.
Durable records hold lifecycle metadata only (bounded at 64 KiB each, `max_records`
including tombstones); there are no output-retention budgets. Records written by
the earlier polling API (schema 1) fail startup closed; reconcile such a root with
the binary that wrote it before upgrading.
Poll: interval 100–30,000 ms, timeout 100–10,000 ms, freshness 500–60,000 ms and at least
interval, fanout 1–16, workers at most 128. Capacity: memory/CPU as above, sandbox
slots 1–1,000,000, restore slots 1–1024 and at most sandbox slots. Native bounds are
listed in the [example configuration](../config/worker.native.example.toml).
