# Sandbox architecture, in plain English

Sandbox runs tools in Linux containers that can keep their files and running programs between calls. It can also save an initialized container as a template and start independent containers from that saved state.

This document explains the current code, not a future design. **Small, real-container tests have passed on one host. Real application compatibility, two-node operation and capacity are not yet qualified.** It is an experimental service, not a production security guarantee.

## Motivation/Goals

An application may need many separate environments for running tools. Starting the application and loading its data from scratch for every environment can be expensive. Keeping a separate copy of every unchanged file is wasteful too.

Sandbox aims to:

- Start new environments from an already initialized application.
- Share unchanged files while keeping each environment's writes private.
- Run work in several environments at once, without letting a slow one block all the others.
- Put limits on resource use and reliably clean up when work ends or fails.

A **sandbox** is one container and the resources assigned to it. A **template** is the saved material needed to create one. A template can contain just files and startup instructions, or also a saved running application.

## Alternatives

These choices keep the first version small:

| Choice | Decision and reason |
| --- | --- |
| Reuse a VM snapshot format | **Rejected.** A container should not need pretend VM disks or unused VM settings. |
| Give each sandbox its own disk image | **Rejected for this version.** Ordinary private directories are sufficient for its changed files. |
| Support several container runtimes | **Rejected for this version.** Use runc and CRIU first; no gVisor or runtime-plugin system. |
| Run all worker operations one at a time | **Rejected.** A slow command in one sandbox should not stop an unrelated sandbox. |
| Let the worker repair host networking | **Rejected.** An operator prepares the surrounding network; the worker manages only its own sandbox connections. |
| Run an agent inside each sandbox for commands and files (AgentENV's envd) | **Deferred.** Commands keep using `runc exec`, now with streaming output and several at once; app traffic uses a reverse proxy instead. |

S3 transfer is **deferred**, not a prerequisite. An administrator currently places the required template files on each node before they are used.

## Constraints

- Management requests require authentication. The service does not provide built-in TLS, user accounts or per-user permissions; an operator must supply the appropriate access boundary.
- A container shares the host's Linux kernel. Its isolation is not the same as a separate virtual machine, and hostile-workload security has not been fully qualified.
- Isolation relies on Linux namespaces, an unprivileged user with no capabilities, `no_new_privs`, resource groups and network policy. The system-call filter follows the AgentENV container pattern: everything is allowed except io_uring and MPTCP sockets, which the checkpoint tool cannot save.
- Resource limits, private files and network restrictions must be in place before application code starts.
- A saved process and its saved file changes must come from the same capture. The worker rejects missing, damaged or incompatible template files instead of trying to guess how to use them.
- Every created resource must belong to a saved sandbox record, so the worker can find and clean it up after a restart.
- API callers cannot supply arbitrary host paths, select host executables or expand the operator's network permissions.

## Architecture

There is one executable, `sandboxd`, which can run in two roles. The **controller** receives client requests, chooses a node for each new sandbox and forwards later requests to that node. Each node has a **worker** that owns its containers, checks its resource budget and performs the requested work. Clients talk only to the controller.

```text
Application / client
        |
        | HTTP requests
        v
Controller
  knows the configured workers
  checks their recent status
  picks a node for each create
  forwards to the sandbox's owner
        |
        +-------------------------+
        |                         |
        v                         v
Worker on node A            Worker on node B
  saved records               saved records
  resource budget             resource budget
  background work             background work
        |                         |
        v                         v
Containers                  Containers
```

The controller does not launch containers itself. The worker uses existing Linux tools:

| Piece | What it does |
| --- | --- |
| **runc** | Starts a container or runs another command inside it. |
| **CRIU** | Saves and restores running processes, including their memory. The worker asks runc to perform these operations. |
| **EROFS** | Stores the shared, read-only base filesystem in an image. |
| **OverlayFS** | Makes the shared base and one sandbox's private changes appear as one filesystem. |
| **Linux resource controls** | Enforce limits on memory, CPU time and the number of processes. These controls are called cgroups. |

### 1. Creating a sandbox

Suppose a client wants a sandbox from template `example-template`. It sends only the template name, a lifetime and, optionally, memory and CPU. Omitted values come from the template.

1. **The controller validates the request.** It checks authentication and the request fields.
2. **The controller chooses a node.** It considers every worker with a recent, healthy status and orders them by how full their promised budgets are, least full first. Whether a worker has room is decided from its last status alone. That status can be a moment old, so for the order the controller also counts the creates it has itself just sent there (still running, or answered but not yet in a newer status), and equally full workers take turns, as AgentENV's scheduler does. Creates that arrive together therefore spread over the workers instead of all going to the same one. These counts never turn a worker away: a status taken while a create is still running already includes it, so counting it again would refuse a worker that still has a free slot. The client never names a node.
3. **The controller creates the sandbox ID.** The ID starts with the chosen node's name followed by a random part, for example `node-a.3f0c…`. Clients treat it as an opaque name. Because the owner is part of the ID, later requests reach the right worker without a lookup table, even after the controller restarts.
4. **The controller forwards the request to that worker.** Worker addresses come from administrator configuration, not the caller. The controller uses its separate worker credential.
5. **The worker makes the final decision.** The controller's information may already be out of date. The worker checks that it has a valid, compatible copy of the template, then its own reservations, container count and background-work slots. It saves a record before creating anything outside that record. If capacity has run out, it says so without saving anything.
6. **If the worker said no before starting anything, the controller tries another node.** Examples are "no capacity", "busy" and "I don't have a usable copy of this template". It makes at most three attempts, each with a new ID. If the outcome is uncertain — the connection broke, the wait ran out, or the worker failed after it started — the controller does **not** try elsewhere. It reports the error together with the ID, so the client can look at or delete that sandbox.
7. **Background work checks the template files.** The create's own background job verifies each layer's checksum the first time the node uses it (two creates needing the same new layer check it once; creates whose layers are already checked never wait for someone else's check). The result is saved with the file's identity, so a worker restart does not check an unchanged layer again; a changed file is checked again. Then the template's shared read-only layers are mounted (its base and, for a warm template, the layers sealed by captures); later creates reuse the verified mount. For a warm template it also takes the node's copy of the saved processes, unpacked and verified once per template, written safely to disk before it is used, and shared by every later restore.
8. **The worker prepares this sandbox's private environment.** It creates the writable directories, mounts OverlayFS, installs resource limits and any permitted networking, and writes the container's configuration file.
9. **The worker starts or restores the application.** For a files-only template it invokes `runc run --detach --bundle <private-directory> <sandbox-id>`. For a template with saved processes it invokes `runc restore` instead. These are descriptions of worker-generated commands, not standalone setup instructions. The first process in every container is a tiny standard init program, `tini`, which starts the template's application, passes signals on to it and cleans up finished child processes ("zombies"), much like Docker's `--init`.
10. **The worker verifies the container is running, and only then does the client get its answer.** The response (`201 Created`) contains the new ID and `running`. If creation failed, the worker first cleans up and the client receives the reason.

The status budget counts **resources already promised to sandboxes**, not a live measurement of free host RAM. The controller's check is an early filter; it cannot reserve resources on a worker. For example, two requests can pass the same cached check, but the worker must still prevent them from reserving the same remaining capacity.

### 2. Sharing files without sharing private changes

```text
One shared EROFS image and read-only mount on the node
                         |
              +----------+----------+
              |                     |
         OverlayFS A           OverlayFS B
         private changes A     private changes B
              |                     |
         Sandbox A             Sandbox B
```

Each sandbox reads unchanged files from the shared base. Its own new files and changes go into its private directory. Modifying a base file can cause OverlayFS to copy that file into the private directory. Deleting a base file records a private deletion; it does not remove the file for other sandboxes.

The private directory that stores changes is called `upper`. OverlayFS also needs a private working directory, called `work`. These are ordinary directories, not a disk image per sandbox. The shared EROFS image is mounted through Linux's standard loop-device mechanism.

A template references **one base image** plus, for a warm template, the layers its captures sealed (newest first). Each layer is stored once per node under its checksum and shared by every template and sandbox that uses it. Separate, independently selectable application/data/toolkit layers are not implemented.

**What EROFS adds:** a read-only image format, optional on-disk compression and convenient image-based staging. The main sharing benefit is not unique to EROFS: OverlayFS over a shared ext4/XFS directory could also share base files and cached file pages. That alternative is not implemented here. Compression does not mean an application's working data stays compressed in RAM.

**What is not shared:** private application memory, such as a JVM heap or a Python object's contents. Two containers restored from the same template still have independent process memory.

### 3. Running a command or calling a tool service

There are two different ways in:

- **Run a command:** the client submits an argument list such as `["/fixture", "counter"]`. The worker runs it inside the container with `runc exec`. It does not pass the arguments through a host shell. Each exec starts a new command process; state that must survive calls belongs in files or an application already running in the sandbox. The client chooses between waiting for the whole result (exit code and bounded output) and **streaming**: output arrives as it is produced, as a series of events, followed by a final event with the exit code.
- **Talk to the application in the sandbox:** app traffic goes through a **reverse proxy**, as in AgentENV. A client sends an ordinary HTTP request to the controller, either to a host name `<port>-<sandbox-id>.<proxy domain>` or to the path `/v1/sandboxes/<id>/proxy/<port>/...`. After checking the credential, the controller passes it to the sandbox's node, which opens a new connection from inside that sandbox's private routing environment to the application's port. Only ports the template approves are reachable. The request and the answer pass through as they are: real status and headers, large or binary bodies streamed in both directions, and WebSocket connections. The management credential is removed before the request reaches the application.

Requests wait for their real result, like an ordinary function call; nothing is saved for later retrieval. **Several commands can run in one sandbox at the same time**, each in its own resource group, up to a per-sandbox limit. Creating, capturing and deleting a sandbox remain one at a time per sandbox: a conflicting request is refused immediately rather than queued, and a capture is refused while commands are running. Work in different sandboxes runs at the same time.

The worker limits how many create, capture and delete jobs and how many commands can run at once. Creating/restoring containers and capturing templates have an additional concurrency limit. Slow mounts, commands and file copies run separately from the short checks that reserve resources and update records. The proxy limits how many exchanges are open and ends one whose sender stays silent for too long; a client that simply stops reading is not cut off by this limit. Otherwise the client decides how long to wait. When the controller shuts down, it waits for open requests at most as long as the longest management request may take, then cuts any streams still open.

A command's time limit or output limit stops **only that command** (and everything it started); the result says it was interrupted, and the sandbox keeps running. A command can also be stopped on request by its ID. Even a successful command has its leftover child processes cleaned up; detached background jobs are not supported by this API.

### 4. Saving an initialized application and starting a copy

A **cold template** contains the base files and startup instructions. A **warm template** also contains saved process state and the original sandbox's file changes, sealed into a read-only layer.

Capture follows the AgentENV container design and **does not stop the source**:

1. Check that the requested template name is unused and that the sandbox can be captured.
2. Briefly freeze the source's processes (`runc pause`).
3. While it is frozen, flush its private file changes to disk and seal them into a new read-only EROFS layer. The layer keeps file permissions, owners, extended attributes and records of deleted base files.
4. Still frozen, ask runc/CRIU to save the processes and let them keep running afterwards. Open network connections are saved too, including connections inside the sandbox.
5. Unfreeze the source. It was unavailable only between steps 2 and 5; requests that arrive meanwhile wait and are answered afterwards. (The tests report the time the source's resource group was frozen and the longest gap a client saw; the gap is slightly longer because the checkpoint tool briefly unfreezes the group while it still holds the processes.)
6. Archive the saved processes, then publish the layer and the complete template: the matching process checkpoint, the sealed layer, the base reference, the required configuration and checksums.

If any step fails, the worker unfreezes the source and keeps it if it is still running, as AgentENV does; it never kills a running source. A source that stays frozen or is not running afterwards is deleted. A checkpoint that had to be stopped at its time or output limit is handled the same way but reported with its own error (`checkpoint_interrupted`): the checkpoint tool may have left the running source half-changed, so the client can decide to delete it.

A warm child can itself be captured. Its own changes become one more sealed layer on top, so templates can chain (up to 16 layers); the tests restore a copy from such a two-layer template.

To create a child, the client makes another create request naming the warm template; it gets a new sandbox ID, and the controller places it on a node holding a compatible copy of that template. The worker mounts the sealed layer on top of the base with a new, empty private directory for the child's changes, reconstructs the limits and network, and invokes `runc restore`. Nothing is copied per child. Source and child then continue independently. Connections inside the sandbox keep working in the child; a connection to an outside service keeps working only in the source, because the outside service and the source's network state are not copied.

The worker checks the architecture, kernel, CPU features, runtime versions and required configuration. Successful tests on one machine do not prove a template can be restored on every other machine. A target node must already have the required artifacts; the service does not fetch them from S3.

### 5. Waiting, lost answers and cleaning up

Each kind of request has a time limit long enough for that operation: a command's own time limit plus a margin for cleanup, or configured limits for creating, capturing and deleting. If the limit passes, the client gets a timeout error. Proxied app traffic and streamed command output have no overall time limit, only the idle limit described above.

**A dropped connection or timeout does not stop or abandon work.** The worker, not the client's connection, owns the work. A command, capture or delete finishes or fails normally, including cleanup and lifetime limits, and its result is discarded. The client can read the sandbox's state afterward. A create is the exception: if its answer cannot be delivered, nobody knows the new ID, so the worker deletes that sandbox.

Without operation IDs, retries are not deduplicated. If a create's answer is lost and the client asks again, it may get a second sandbox. The first is normally deleted as described above; in the rare case where the answer was lost after the worker handed it over, it ends when its lifetime expires, or the client can delete it using the ID in the error. A repeated command or proxied request runs again; an application may already have acted on the first one. Delete is safe to repeat. Deleted and failed IDs are kept and never reused.

Cleanup happens when the client deletes a sandbox, its lifetime expires, or the worker restarts:

- Stop its processes and the worker's associated helper processes.
- Remove its runtime state, private mounts, network connections and private files.
- Release its reserved capacity only after cleanup succeeds.

A delete request waits for cleanup to finish; if commands are running in that sandbox, delete stops them first, and it ends the sandbox's open proxied connections, including ones still connecting or waiting for the application's first answer. If a second delete request for the same sandbox arrives meanwhile, it waits for the same cleanup and gets the same answer. If cleanup fails, the delete request reports it, the record stays in `cleanup_failed`, its capacity remains reserved, and the worker retries. Shared base files and saved templates are retained; deleting a sandbox does not delete them.

A separate lifetime monitor can stop an expired sandbox even while a long background operation is running. The requested lifetime starts when the worker accepts the create, not when application startup finishes.

**Worker restart does not resume or adopt old containers.** It reads the saved records, stops leftover work and cleans up. Requests that were waiting lose their answers. Host-side helper programs are tracked separately so that a dead worker does not leave an unowned mount or runtime command behind.

### 6. Network access is off unless explicitly allowed

By default, a sandbox has no external network access: it still gets its own private network environment, created by the worker, but with only the internal loopback connection. An approved template can allow specific **IPv4 addresses and TCP ports**, plus ports on which its own application may receive tool requests.

An operator supplies a bridge, gateway and an address pool reserved for this worker. Each networked sandbox has its own isolated network and a private routing environment that checks traffic before forwarding it. The worker installs the rules before starting the application. It does not repair the host's existing firewall, routes or forwarding settings.

The routing environments are **built ahead of time and reused**, as AgentENV does. When the worker starts, it builds one per sandbox it can hold, each connected to the bridge with its own outside address and a "block everything" rule set. Creating a sandbox then only connects the sandbox's own network to a free routing environment and adds that template's allowed endpoints. Deleting a sandbox disconnects it, removes those rules and forgets all remembered connections, and returns the routing environment for the next sandbox instead of tearing it down. If one cannot be reset, it is removed and rebuilt later. A restarted worker never reuses old ones: it removes them all and builds fresh ones. A worker that shuts down removes them.

All guests see the same private address inside their separate environments. The address used outside each sandbox is different. Keeping the guest-side address stable lets saved connections restore in any child; it does not copy the outside end of external connections or the router's connection state.

There is no implicit DNS, UDP, IPv6 or access to the host or sibling sandboxes. The allowed endpoints are fixed in the template and checked against the operator's limits. A create request cannot override them.

The app proxy reaches only that sandbox's approved service ports, over a connection made from inside its routing environment; nothing is exposed on the host network. It does not forward management credentials, follow redirects or accept arbitrary upstream URLs.

Low-level packet rules and the tested fix for paths with smaller packet-size limits are documented in [network details](../docs/network.md).

### Where to look in the code

| File | Plain-English responsibility |
| --- | --- |
| [`main.rs`](../src/main.rs) | Chooses controller, worker or read-only preflight mode. |
| [`config.rs`](../src/config.rs) | Loads and checks administrator settings and credential sources. |
| [`http.rs`](../src/http.rs) | Checks management authentication and request size/time limits, and hands app traffic (proxy paths and proxy host names) to the proxy. |
| [`proxy.rs`](../src/proxy.rs) | The reverse proxy: reads proxy host names and paths, streams requests and answers between hops, tunnels WebSockets, and opens the node's connection inside the sandbox's routing environment. |
| [`controller.rs`](../src/controller.rs) | Polls workers, places new sandboxes, generates their IDs and forwards requests to the owner. |
| [`scheduler.rs`](../src/scheduler.rs) | Keeps ready nodes whose last status has room and orders them by how full their promised budgets are (including creates just sent there), taking turns between equally full nodes, for create placement. |
| [`worker.rs`](../src/worker.rs) | Receives node-local API requests, waits for each result (or streams command output) and returns it; checks proxied traffic against the sandbox's approved ports. |
| [`model.rs`](../src/model.rs) | Defines request/status fields and checks valid values. |
| [`engine.rs`](../src/engine.rs) | Owns saved sandbox records, reservations, background work and its results, running commands, expiry and restart cleanup. |
| [`native.rs`](../src/native.rs) | Prepares mounts, resource limits and container configuration; calls runc/CRIU; runs each command in its own resource group. |
| [`process.rs`](../src/process.rs) | Runs and tracks host helper programs, bounds their output/time (passing command output on as it arrives), and safely writes saved JSON records. |
| [`storage.rs`](../src/storage.rs) | Checks template files, handles file archives and publishes complete templates. |
| [`network.rs`](../src/network.rs) | Keeps the pool of pre-built routing environments, connects each sandbox's private network to one, applies and resets its traffic rules. |
| [`lifecycle.rs`](../src/lifecycle.rs) | Defines the small liveness response. Despite its name, the lifecycle logic is in `engine.rs`. |

## Interfaces/signatures/headers

The same executable starts either service:

```text
sandboxd controller --config <controller-config>
sandboxd worker --config <worker-config>
sandboxd preflight --config <worker-config>
```

Preflight only checks prerequisites. It does not install packages, load kernel modules or change host networking. A worker without explicit runtime enablement, or with failed checks, cannot create containers.

The main API operations are:

| Request | Purpose |
| --- | --- |
| `GET /v1/status` | Inspect worker budgets/readiness, or the controller's recent observations. |
| `POST /v1/sandboxes` | Create a sandbox from a cold or warm template; returns its ID once running. |
| `GET /v1/sandboxes/{id}` | Read its state and expiry time. |
| `POST /v1/sandboxes/{id}/exec` | Run a command inside it; returns exit code and output, or streams the output. |
| `POST /v1/sandboxes/{id}/exec/{exec_id}/kill` | Stop one running command; returns once it has ended. |
| any request to `/v1/sandboxes/{id}/proxy/{port}/...` or host `{port}-{id}.{proxy domain}` | App traffic to an approved port of the sandbox's application, passed through as it is. |
| `POST /v1/sandboxes/{id}/capture` | Save its initialized state as a new template without stopping it; returns once the template is published and the source is running. |
| `DELETE /v1/sandboxes/{id}` | Clean it up; returns when cleanup is complete. |

Only `/healthz` is public, and it reports that the service is alive—not that it can run workloads. See the [API reference](../docs/api.md) for exact fields, limits, response states and retry rules.

There is no full E2B-compatible API, public fork/pause/resume API, automatic template cleanup, writable-disk quota or deletion of old request records. Operators must monitor disk usage and retained artifacts. The [storage reference](../docs/contracts.md) describes the exact saved-file format.

## Testing

### What has passed

Real tests used runc 1.3.6, CRIU 4.3 and a tiny application on one approved Linux host, with at most three containers, each limited to 64 MiB, one vCPU and 64 processes. They checked:

- Cold startup, private file changes, capture without stopping the source (and a failed capture that leaves it running, a checkpoint stopped at its time limit that is reported as interrupted and leaves the source running, and a failed capture whose source died that deletes it), independent restore, a capture of a restored copy and a restore from that two-layer template, and reuse of the node's saved-process copy.
- Layer checking in the create job (once for two simultaneous creates), trusted again after a worker restart, checked again after the file changes, and a damaged layer rejected; with the real image, a cold create after a restart that does not check the base again.
- Saved open files, memory mappings and an open connection inside the sandbox in that fixture; deleted and modified base files in the sealed layer.
- A first process that cleans up finished child processes, and a second delete that waits for the first.
- The same workflow with a real public Python image, including a measurement of how long the source is frozen during capture.
- Waiting requests that return real results, concurrent operations in different sandboxes, several commands at once in one sandbox, streamed command output, stopping a command by its ID, time and output limits that stop only the command, immediate refusal of a conflicting capture, cleanup after a client disconnects mid-command or mid-create, lifetime expiry, deletion and worker-restart cleanup.
- Allowed and denied TCP connections, the app proxy (both request forms, large binary bodies in both directions, chunked streaming, a WebSocket echo with the real image, connection and idle limits, unapproved ports), restored listeners and new connections after restore.
- Cleanup of test-owned processes, mounts, namespaces, loop devices and resource groups.

Networking tests ran inside a disposable private network environment; they did not change the default host network. The real-container tests used an optimized (release) build. Build checks and a separate nonprivileged API smoke also passed; the smoke includes eight simultaneous creates against two stand-in workers, which split four and four. Detailed instructions and limits are in [runtime validation](../docs/runtime.md).

These results do not prove arbitrary application compatibility, all possible crash cases, hostile-workload containment, complete host/library trust or cross-node restore. No unit tests are used by project preference; small fixture results are not a substitute for real workload testing.

### What the next qualification must establish

First, run a representative real application through startup, tool calls, capture (source keeps running) and independent restore on both nodes. Only then measure pressure:

- **Two nodes; below 512 GB per node**, not 512 GB combined. Use a 500,000,000,000-byte hard limit per node for headroom, covering the whole experiment and its charged file cache. Report any memory outside that accounting boundary.
- **16, 32 and 64 live sandboxes across the job**, with the per-node split reported. Keep about 10% actually executing and 90% resident but idle; queued requests do not count as active execution.
- Compare against a low-contention baseline. Report median, 95th- and 99th-percentile end-to-end latency, including queueing and retries, plus throughput, memory, CPU, errors and cleanup.
- Measure startup/restore and synchronized tool-call bursts separately from normal steady-state operation.

The acceptable latency regression has not yet been agreed. There is no completed two-node capacity result to report, and no basis yet to declare a particular population supported.
