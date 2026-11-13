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
2. **The controller chooses a node.** It considers every worker with a recent, healthy status and orders them by how full their promised budgets are, least full first. The client never names a node.
3. **The controller creates the sandbox ID.** The ID starts with the chosen node's name followed by a random part, for example `node-a.3f0c…`. Clients treat it as an opaque name. Because the owner is part of the ID, later requests reach the right worker without a lookup table, even after the controller restarts.
4. **The controller forwards the request to that worker.** Worker addresses come from administrator configuration, not the caller. The controller uses its separate worker credential.
5. **The worker makes the final decision.** The controller's information may already be out of date. The worker checks that it has a valid, compatible copy of the template, then its own reservations, container count and background-work slots. It saves a record before creating anything outside that record. If capacity has run out, it says so without saving anything.
6. **If the worker said no before starting anything, the controller tries another node.** Examples are "no capacity", "busy" and "I don't have a usable copy of this template". It makes at most three attempts, each with a new ID. If the outcome is uncertain — the connection broke, the wait ran out, or the worker failed after it started — the controller does **not** try elsewhere. It reports the error together with the ID, so the client can look at or delete that sandbox.
7. **Background work checks the template files.** It verifies their checksums and acquires the shared read-only base mount.
8. **The worker prepares this sandbox's private environment.** It creates the writable directories, mounts OverlayFS, installs resource limits and any permitted networking, and writes the container's configuration file.
9. **The worker starts or restores the application.** For a files-only template it invokes `runc run --detach --bundle <private-directory> <sandbox-id>`. For a template with saved processes it invokes `runc restore` instead. These are descriptions of worker-generated commands, not standalone setup instructions.
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

The current template format references **one base image**. Separate, independently selectable application/data/toolkit layers are not implemented.

**What EROFS adds:** a read-only image format, optional on-disk compression and convenient image-based staging. The main sharing benefit is not unique to EROFS: OverlayFS over a shared ext4/XFS directory could also share base files and cached file pages. That alternative is not implemented here. Compression does not mean an application's working data stays compressed in RAM.

**What is not shared:** private application memory, such as a JVM heap or a Python object's contents. Two containers restored from the same template still have independent process memory.

### 3. Running a command or calling a tool service

There are two different operations:

- **Run a command:** the client submits an argument list such as `["/fixture", "counter"]`. The worker runs it inside the container with `runc exec`. It does not pass the arguments through a host shell. Each exec starts a new command process; state that must survive calls belongs in files or an application already running in the sandbox. The response contains the exit code and bounded output.
- **Make an application HTTP request:** the client submits an approved service port, a method, a relative path and an optional text body. A worker-controlled helper connects to that sandbox's application. The response contains the application's HTTP status and text body. This does not run `runc exec`, and it is not an arbitrary-URL proxy.

Every request waits for its real result, like an ordinary function call; nothing is saved for later retrieval. Only one such operation runs in a sandbox at a time. A second request for a busy sandbox is refused immediately rather than queued. Operations in different sandboxes run at the same time.

The worker limits how many operations can run at once. Creating/restoring containers and capturing templates have an additional concurrency limit. Slow mounts, commands and file copies run separately from the short checks that reserve resources and update records.

Command timeouts or excessive output cause the **whole sandbox** to be terminated, not just the host-side runc command. Even a successful command has its leftover child processes cleaned up; detached background jobs are not supported by this API. An application HTTP timeout or response-size failure ends that HTTP operation without automatically terminating the sandbox.

### 4. Saving an initialized application and starting a copy

A **cold template** contains the base files and startup instructions. A **warm template** also contains saved process state and the original sandbox's file changes.

Capture works as follows:

1. Check that the requested template name is unused and that the sandbox can be captured.
2. Reject active or closing TCP connections. Listening sockets are supported, but connections to external services cannot simply be copied.
3. Ask runc/CRIU to checkpoint the application. **This stops the source application.**
4. Archive the source's private file changes, including file permissions and records of deleted base files.
5. Restore the source application from the checkpoint. Do not call it running until recovery succeeds.
6. Publish the complete template only after source recovery succeeds. It contains the matching process checkpoint, private-file archive, base reference, required configuration and checksums.

Capture therefore interrupts the source briefly; it is not a zero-downtime fork. The saved private changes remain private changes: they are not turned into a replacement base layer.

To create a child, the client makes another create request naming the warm template; it gets a new sandbox ID, and the controller places it on a node holding a compatible copy of that template. The worker creates new private directories, reconstructs the filesystem and limits, and invokes `runc restore`. Source and child then continue independently.

The worker checks the architecture, kernel, CPU features, runtime versions and required configuration. Successful tests on one machine do not prove a template can be restored on every other machine. A target node must already have the required artifacts; the service does not fetch them from S3.

### 5. Waiting, lost answers and cleaning up

Each kind of request has a time limit long enough for that operation: a command's own time limit plus a margin for cleanup, or configured limits for creating, capturing and deleting. If the limit passes, the client gets a timeout error.

**A dropped connection or timeout does not stop or abandon work.** The worker, not the client's connection, owns the work. A command, HTTP call, capture or delete finishes or fails normally, including cleanup and lifetime limits, and its result is discarded. The client can read the sandbox's state afterward. A create is the exception: if its answer cannot be delivered, nobody knows the new ID, so the worker deletes that sandbox.

Without operation IDs, retries are not deduplicated. If a create's answer is lost and the client asks again, it may get a second sandbox. The first is normally deleted as described above; in the rare case where the answer was lost after the worker handed it over, it ends when its lifetime expires, or the client can delete it using the ID in the error. A repeated command or HTTP request runs again; an application may already have acted on the first one. Delete is safe to repeat. Deleted and failed IDs are kept and never reused.

Cleanup happens when the client deletes a sandbox, its lifetime expires, or the worker restarts:

- Stop its processes and the worker's associated helper processes.
- Remove its runtime state, private mounts, network connections and private files.
- Release its reserved capacity only after cleanup succeeds.

A delete request waits for cleanup to finish; if a command is running in that sandbox, delete stops it first. If cleanup fails, the delete request reports it, the record stays in `cleanup_failed`, its capacity remains reserved, and the worker retries. Shared base files and saved templates are retained; deleting a sandbox does not delete them.

A separate lifetime monitor can stop an expired sandbox even while a long background operation is running. The requested lifetime starts when the worker accepts the create, not when application startup finishes.

**Worker restart does not resume or adopt old containers.** It reads the saved records, stops leftover work and cleans up. Requests that were waiting lose their answers. Host-side helper programs are tracked separately so that a dead worker does not leave an unowned mount or runtime command behind.

### 6. Network access is off unless explicitly allowed

By default, a sandbox has no external network access. An approved template can allow specific **IPv4 addresses and TCP ports**, plus ports on which its own application may receive tool requests.

An operator supplies a bridge, gateway and an address pool reserved for this worker. Each networked sandbox has its own isolated network and a private routing environment that checks traffic before forwarding it. The worker installs the rules before starting the application. It does not repair the host's existing firewall, routes or forwarding settings.

All guests see the same private address inside their separate environments. The address used outside each sandbox is different. Keeping the guest-side address stable helps restore saved applications; it does not copy external connections or the router's connection state.

There is no implicit DNS, UDP, IPv6 or access to the host or sibling sandboxes. The allowed endpoints are fixed in the template and checked against the operator's limits. A create request cannot override them.

Application HTTP is restricted to that sandbox's approved service ports. It does not forward management credentials, follow redirects or accept arbitrary upstream URLs. Its request and result bodies are bounded UTF-8 text; binary responses, streaming and WebSockets are not supported.

Low-level packet rules and the tested fix for paths with smaller packet-size limits are documented in [network details](../docs/network.md).

### Where to look in the code

| File | Plain-English responsibility |
| --- | --- |
| [`main.rs`](../src/main.rs) | Chooses controller, worker or read-only preflight mode. |
| [`config.rs`](../src/config.rs) | Loads and checks administrator settings and credential sources. |
| [`http.rs`](../src/http.rs) | Checks management authentication and request size/time limits. |
| [`controller.rs`](../src/controller.rs) | Polls workers, places new sandboxes, generates their IDs and forwards requests to the owner. |
| [`scheduler.rs`](../src/scheduler.rs) | Orders ready nodes by how full their promised budgets are, for create placement. |
| [`worker.rs`](../src/worker.rs) | Receives node-local API requests, waits for each result and returns it. |
| [`model.rs`](../src/model.rs) | Defines request/status fields and checks valid values. |
| [`engine.rs`](../src/engine.rs) | Owns saved sandbox records, reservations, background work and its results, expiry and restart cleanup. |
| [`native.rs`](../src/native.rs) | Prepares mounts, resource limits and container configuration; calls runc/CRIU. |
| [`process.rs`](../src/process.rs) | Runs and tracks host helper programs, bounds their output/time, and safely writes saved JSON records. |
| [`storage.rs`](../src/storage.rs) | Checks template files, handles file archives and publishes complete templates. |
| [`network.rs`](../src/network.rs) | Creates private sandbox networking, applies traffic rules and runs the application HTTP helper. |
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
| `POST /v1/sandboxes/{id}/exec` | Run a command inside it; returns exit code and output. |
| `POST /v1/sandboxes/{id}/http` | Call its application over HTTP; returns status and body. |
| `POST /v1/sandboxes/{id}/capture` | Save its initialized state as a new template; returns after the source is running again. |
| `DELETE /v1/sandboxes/{id}` | Clean it up; returns when cleanup is complete. |

Only `/healthz` is public, and it reports that the service is alive—not that it can run workloads. See the [API reference](../docs/api.md) for exact fields, limits, response states and retry rules.

There is no full E2B-compatible API, public fork/pause/resume API, automatic template cleanup, writable-disk quota or deletion of old request records. Operators must monitor disk usage and retained artifacts. The [storage reference](../docs/contracts.md) describes the exact saved-file format.

## Testing

### What has passed

Real tests used runc 1.3.6, CRIU 4.3 and a tiny application on one approved Linux host, with at most three containers, each limited to 64 MiB, one vCPU and 64 processes. They checked:

- Cold startup, private file changes, capture, source recovery and independent restore.
- Saved open files and memory mappings in that fixture.
- Waiting requests that return real results, concurrent operations in different sandboxes, immediate refusal of a conflicting request, cleanup after a client disconnects mid-command or mid-create, lifetime expiry, deletion and worker-restart cleanup.
- Allowed and denied TCP connections, application HTTP limits, restored listeners and new connections after restore.
- Cleanup of test-owned processes, mounts, namespaces, loop devices and resource groups.

Networking tests ran inside a disposable private network environment; they did not change the default host network. Build checks and a separate nonprivileged API smoke also passed. Detailed instructions and limits are in [runtime validation](../docs/runtime.md).

These results do not prove arbitrary application compatibility, all possible crash cases, hostile-workload containment, complete host/library trust or cross-node restore. No unit tests are used by project preference; small fixture results are not a substitute for real workload testing.

### What the next qualification must establish

First, run a representative real application through startup, tool calls, capture, source recovery and independent restore on both nodes. Only then measure pressure:

- **Two nodes; below 512 GB per node**, not 512 GB combined. Use a 500,000,000,000-byte hard limit per node for headroom, covering the whole experiment and its charged file cache. Report any memory outside that accounting boundary.
- **16, 32 and 64 live sandboxes across the job**, with the per-node split reported. Keep about 10% actually executing and 90% resident but idle; queued requests do not count as active execution.
- Compare against a low-contention baseline. Report median, 95th- and 99th-percentile end-to-end latency, including queueing and retries, plus throughput, memory, CPU, errors and cleanup.
- Measure startup/restore and synchronized tool-call bursts separately from normal steady-state operation.

The acceptable latency regression has not yet been agreed. There is no completed two-node capacity result to report, and no basis yet to declare a particular population supported.
