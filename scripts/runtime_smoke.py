#!/usr/bin/env python3
"""Explicitly privileged, real lifecycle gate. Never runs from the foundation smoke.

Every management call is blocking: create/exec/kill/capture/delete responses carry
the real outcome (streaming exec sends its output as it arrives). App traffic goes
through the controller's reverse proxy. The controller chooses the owner and returns
the sandbox ID.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import tempfile
import time

import socket
import stat
import threading

from smoke import eventually, exchange, exec_events, expect, port, request as smoke_request


# Runs the worker's read-only preflight for this config and returns the host
# compatibility fingerprint a manifest must carry. Fails if any check fails.
def preflight_compatibility(binary, worker_config):
    # Version checks and preflight do not install/load/configure anything.
    report = subprocess.run([binary, "preflight", "--config", str(worker_config)], capture_output=True, timeout=15)
    if report.returncode:
        print(report.stdout.decode(errors="replace"))
        raise RuntimeError("preflight failed; no runtime mutation attempted")
    return json.loads(report.stdout)["compatibility"]


# Moves a built EROFS image into the worker's digest-named layer store and
# returns its manifest descriptor (sha256 and size).
def publish_layer(root, image):
    digest = hashlib.sha256()
    with image.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    (root / "layers").mkdir(mode=0o700, exist_ok=True)
    target = root / "layers" / (digest.hexdigest() + ".erofs")
    image.rename(target)
    return dict(sha256=digest.hexdigest(), bytes=target.stat().st_size)


# Returns a cold (no checkpoint, no sealed layers) schema-3 template manifest the
# worker accepts: fixed UID/GID 65534, the given base layer, init argv, network
# policy and defaults.
def cold_manifest(template_id, compatibility, base, init_argv, network, memory_mib, vcpus, pids_max):
    return dict(schema_version=3, template_id=template_id, generation="cold-v1", runtime="runc_criu", compatibility=compatibility,
                base=base, layers=[], checkpoint=None, init_argv=init_argv, memory_mib=memory_mib, vcpus=vcpus, pids_max=pids_max,
                oci_config_sha256=None, network=network, uid=65534, gid=65534)


# Returns the shared checkpoint-cache directory of a warm template (keyed by its
# manifest digest) and a listing of (relative path, size, mtime_ns, inode) that
# changes if anything re-extracts or writes into it.
def checkpoint_cache(root, template_id):
    key = (root / "templates" / template_id / "manifest.sha256").read_text().strip()
    cache = root / "checkpoints" / key
    listing = sorted((str(p.relative_to(cache)), p.lstat().st_size, p.lstat().st_mtime_ns, p.lstat().st_ino) for p in cache.rglob("*"))
    return cache, (cache.stat().st_ino, listing)


# Polls a sandbox cgroup's cgroup.events every 5 ms until stop is set. Returns the
# number of freezer periods ("frozen 1") seen and their total and longest length.
# This is cgroup-freezer time only: CRIU thaws the cgroup while its tasks stay
# ptrace-stopped and refreezes it, so the source is stopped somewhat longer.
def watch_frozen(events, stop):
    periods, since, frozen = [], None, False
    while not stop.is_set():
        try:
            frozen = "frozen 1" in events.read_text()
        except OSError:
            frozen = False
        now = time.monotonic()
        if frozen and since is None:
            since = now
        elif not frozen and since is not None:
            periods.append(now - since)
            since = None
        time.sleep(0.005)
    if since is not None:
        periods.append(time.monotonic() - since)
    return dict(freeze_periods=len(periods), frozen_s=round(sum(periods), 3), longest_frozen_s=round(max(periods, default=0), 3))


# Polls a source's counter file (as the host sees it in the upper directory)
# until stop is set. Returns the samples, the longest interval without a change
# (the time the source was stopped plus one 100 ms tick at most) and whether it advanced.
def watch_counter(path, stop):
    samples = []
    while not stop.is_set():
        try:
            samples.append((time.monotonic(), path.read_text()))
        except OSError:
            pass
        time.sleep(0.01)
    changes = [t for (t, value), (_, previous) in zip(samples[1:], samples) if value != previous]
    edges = [samples[0][0], *changes, samples[-1][0]] if samples else []
    return dict(samples=len(samples), changes=len(changes), longest_unchanged_s=round(max((b - a for a, b in zip(edges, edges[1:])), default=0), 3))


# Writes manifest.json and its digest sidecar into a new template directory.
def write_template(root, manifest):
    (root / "templates").mkdir(mode=0o700, exist_ok=True)
    template = root / "templates" / manifest["template_id"]
    template.mkdir(mode=0o700)
    (template / "manifest.json").write_text(json.dumps(manifest))
    (template / "manifest.sha256").write_text(hashlib.sha256((template / "manifest.json").read_bytes()).hexdigest() + "\n")
    return template


# Run the privileged gate on fixture templates through a real worker and controller: creates, execs
# and bounds, rejections, disconnects, DELETE waits, captures (failed, interrupted, chained), warm
# restores, layer verification across restarts, TTL and crash cleanup; --network adds policy
# networking and the app proxy. Retain the root and observations; require no owned state to remain.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-privileged-runtime", action="store_true")
    parser.add_argument("--network", action="store_true", help="Only inside network_smoke.py disposable outer namespace")
    parser.add_argument("--binary", default="target/debug/sandboxd")
    parser.add_argument("--root", required=True, help="Existing trusted directory on ext4/XFS/Btrfs; retained for inspection")
    parser.add_argument("--cgroup-parent", required=True, help="Existing empty delegated domain; cpu memory pids already enabled")
    parser.add_argument("--tools-dir", help="Optional existing administrator-staged trusted tool directory")
    args = parser.parse_args()
    # Send a management request with a long default client deadline.
    def request(*call, timeout=None, **named):
        # Blocking calls wait for real outcomes; the client deadline exceeds the
        # services' route deadlines so their own timeout errors are observable.
        return smoke_request(*call, timeout=timeout or 200, **named)
    if not args.allow_privileged_runtime or os.geteuid() != 0:
        parser.error("requires explicit opt-in and administrator execution on an approved host")
    if args.network and os.environ.get("SANDBOX_TEST_OUTER_NETNS") != os.readlink("/proc/self/ns/net"):
        parser.error("network tests require the disposable outer namespace harness")
    binary = str(Path(args.binary).resolve())
    parent = Path(args.root).resolve(strict=True)
    cgroup = Path(args.cgroup_parent).resolve(strict=True)
    if not str(cgroup).startswith("/sys/fs/cgroup/"):
        parser.error("cgroup parent must be below /sys/fs/cgroup")
    root = Path(tempfile.mkdtemp(prefix="lifecycle-", dir=parent))
    root.chmod(0o700)
    # Worker-owned namespace names start with this root-derived prefix; routing slots add "s-<index>"
    # and their host links are "sb" + 10 root-digest hex digits + the index in 3 hex digits.
    owned_prefix = "sb-" + hashlib.sha256(str(root).encode()).hexdigest()[:16] + "-"
    slot_link_prefix = "sb" + hashlib.sha256(str(root).encode()).hexdigest()[:10]
    helpers = cgroup / (".helpers-" + hashlib.sha256(str(root).encode()).hexdigest())
    worker_port, controller_port = port(), port()
    assert worker_port != controller_port
    token = secrets.token_urlsafe(48)
    worker_token = secrets.token_urlsafe(48)
    env = dict(os.environ, SANDBOX_CONTROLLER_TOKEN=token, SANDBOX_WORKER_TOKEN=worker_token)
    worker_config = root / "worker.toml"
    worker_config.write_text(f'''node_id = "node-smoke"
runtimes = ["runc_criu"]
[server]
listen = "127.0.0.1:{worker_port}"
request_timeout_ms = 5000
[server.proxy]
max_connections = 4
idle_timeout_ms = 3000
[auth]
env = "SANDBOX_WORKER_TOKEN"
[capacity]
memory_mib = 192
vcpus = 1
max_sandboxes = 3
max_concurrent_restores = 2
[native]
enabled = true
root = {json.dumps(str(root))}
cgroup_parent = {json.dumps(str(cgroup))}
{('tools_dir = ' + json.dumps(str(Path(args.tools_dir).resolve(strict=True)))) if args.tools_dir else ''}
cpu_overcommit = 3
pids_max = 64
max_records = 48
max_concurrent_operations = 4
max_execs_per_sandbox = 3
max_artifact_bytes = 67108864
command_timeout_seconds = 30
''')
    if args.network:
        with worker_config.open("a") as f:
            f.write('''
[native.network]
bridge = "sb-test-br"
gateway = "198.18.0.1"
prefix = 24
addresses = ["198.18.0.10", "198.18.0.11", "198.18.0.12"]
egress = [{ip="198.18.0.1", port=18080}, {ip="198.19.0.2", port=18080}, {ip="198.19.0.3", port=18080}]
service_ports = [8080]
''')
    controller_config = root / "controller.toml"
    controller_config.write_text(f'''proxy_domain = "sandbox.test"
[server]
listen = "127.0.0.1:{controller_port}"
request_timeout_ms = 5000
[server.proxy]
max_connections = 16
idle_timeout_ms = 6000
[auth]
env = "SANDBOX_CONTROLLER_TOKEN"
[worker_auth]
env = "SANDBOX_WORKER_TOKEN"
[poll]
interval_ms = 100
timeout_ms = 4000
freshness_ms = 5000
fanout = 1
[[workers]]
node_id = "node-smoke"
url = "http://127.0.0.1:{worker_port}"
''')
    compatibility = preflight_compatibility(binary, worker_config)
    rootfs = root / "fixture-rootfs"
    rootfs.mkdir(mode=0o755)
    for name in ("dev", "proc", "workspace"):
        (rootfs / name).mkdir(mode=0o755)
    (rootfs / "workspace").chmod(0o777)
    for name in ("copied", "removed"):
        (rootfs / "workspace" / name).write_text("immutable-base")
        (rootfs / "workspace" / name).chmod(0o666)
    # Copy-up and the sealed capture layer must keep this extended attribute.
    os.setxattr(rootfs / "workspace" / "copied", "user.sandbox-test", b"base-xattr")
    (rootfs / "seed").write_bytes(b"seed\n" + bytes(4091))
    subprocess.run(["cc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", str(Path(__file__).with_name("fixture.c")), "-o", str(rootfs / "fixture")], check=True, timeout=60)
    layer = root / "fixture.erofs"
    subprocess.run(["mkfs.erofs", str(layer), str(rootfs)], check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    manifest = cold_manifest("fixture", compatibility, publish_layer(root, layer), ["/fixture", "init-network" if args.network else "init"],
                             ({"mode":"tcp_allowlist", "egress":[{"ip":"198.18.0.1","port":18080}, {"ip":"198.19.0.2","port":18080}, {"ip":"198.19.0.3","port":18080}], "service_ports":[8080]} if args.network else {"mode": "isolated"}),
                             memory_mib=64, vcpus=1, pids_max=64)
    write_template(root, manifest)
    # Two more cold bases for the layer-verification checks: "probe" adds 16 MiB of ballast (so
    # hashing it shows in the worker's read counter) and "probe-small" only a marker file.
    probe_bases = {}
    for name, ballast in (("probe", os.urandom(16 << 20)), ("probe-small", b"marker\n")):
        probe_rootfs = root / f"{name}-rootfs"
        shutil.copytree(rootfs, probe_rootfs, symlinks=True)
        (probe_rootfs / "ballast").write_bytes(ballast)
        probe_image = root / f"{name}.erofs"
        subprocess.run(["mkfs.erofs", str(probe_image), str(probe_rootfs)], check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        probe_bases[name] = publish_layer(root, probe_image)
        write_template(root, dict(manifest, template_id=name, base=probe_bases[name]))
    for name in ("incompatible", "tampered", "symlinked", "unknown-metadata", "no-defaults", "old-schema") + (("policy-not-authorized", "unsupported-policy") if args.network else ()):
        directory = root / "templates" / name
        directory.mkdir(mode=0o700)
        invalid = json.loads(json.dumps(manifest))
        invalid["template_id"] = name
        if name == "incompatible":
            invalid["compatibility"]["kernel"] = "incompatible-kernel"
        if name == "tampered":
            invalid["base"]["bytes"] += 1
        if name == "unknown-metadata":
            invalid["unsupported_field"] = True
        if name == "policy-not-authorized":
            invalid["network"]["egress"][0]["port"] = 18081
        if name == "unsupported-policy":
            invalid["network"]["egress"][0]["protocol"] = "udp"
        if name == "old-schema":
            # A schema-2 template (per-create upper.tar) is rejected, not migrated.
            invalid["schema_version"] = 2
            del invalid["layers"]
            invalid["upper"] = None
        if name == "no-defaults":
            invalid["memory_mib"] = invalid["vcpus"] = None
        if name == "symlinked":
            (directory / "manifest.json").symlink_to("../fixture/manifest.json")
        else:
            (directory / "manifest.json").write_text(json.dumps(invalid))
        (directory / "manifest.sha256").write_text(hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest() + "\n")
    processes = []
    worker = None
    controller = None
    ids = []
    observations = {"maximum_live_sandboxes": 3, "memory_mib_per_sandbox": 64, "vcpus_per_sandbox": 1, "pids_per_sandbox": 64}

    # Launch the requested service, retain its log and process, and wait for its health endpoint.
    def start(role, config):
        log = root / f"{role}-{len(processes)}.log"
        with log.open("wb") as output:
            proc = subprocess.Popen([binary, role, "--config", str(config)], env=env, stdout=output, stderr=subprocess.STDOUT)
        processes.append(proc)
        eventually(lambda: request(worker_port if role == "worker" else controller_port, "/healthz", timeout=4)[0] == 200, timeout=15)
        return proc

    # Wait until the controller reports a fresh observation of the worker.
    def fresh():
        eventually(lambda: expect(request(controller_port, "/v1/status", token, timeout=4), 200)["nodes"][0]["fresh"], timeout=15)

    # Return the controller's current view of a sandbox.
    def get(sandbox):
        return expect(request(controller_port, f"/v1/sandboxes/{sandbox}", token, timeout=4), 200)

    # Require that the sandbox's private directory, cgroup and runc state are all gone.
    def gone(sandbox):
        assert not (root / "private" / sandbox).exists() and not (cgroup / sandbox).exists() and not (root / "runc" / sandbox).exists()

    # Send one create through the controller, remember any returned sandbox ID for cleanup and return
    # the status and body.
    def create_call(body):
        # Only definitive "no capacity" (advisory usage lag) is retried. A transport
        # error is never retried: it could create a second sandbox.
        deadline = time.monotonic() + 30
        while True:
            code, payload = request(controller_port, "/v1/sandboxes", token, body, "POST")
            if code == 503 and payload.get("error", {}).get("code") == "no_capacity" and time.monotonic() < deadline:
                time.sleep(0.2)
                continue
            if "sandbox_id" in payload:
                ids.append(payload["sandbox_id"])
            return code, payload

    # Create a running sandbox through the controller and record its create time. Check that a direct
    # worker retry with the same ID is idempotent and a changed reuse is rejected; return the ID.
    def create(template_id="fixture", ttl=120, **resources):
        body = dict(template_id=template_id, ttl_seconds=ttl, **resources)
        started = time.monotonic()
        result = expect(create_call(body), 201)
        sandbox = result["sandbox_id"]
        assert result["state"] == "running" and sandbox.startswith("node-smoke.") and get(sandbox)["state"] == "running"
        observations.setdefault("create_seconds", []).append([template_id, round(time.monotonic() - started, 3)])
        # Direct worker retry with the same ID is idempotent; conflicting reuse is rejected.
        replay = expect(request(worker_port, "/v1/sandboxes", worker_token, dict(body, sandbox_id=sandbox), "POST"), 200)
        assert replay["state"] == "running"
        expect(request(worker_port, "/v1/sandboxes", worker_token, dict(body, sandbox_id=sandbox, ttl_seconds=ttl + 1), "POST"), 409, "idempotency_conflict")
        return sandbox

    # Run a command through the controller and return the raw status and result.
    def exec_call(sandbox, argv, timeout_ms=3000, max_output_bytes=8192):
        return request(controller_port, f"/v1/sandboxes/{sandbox}/exec", token, dict(argv=argv, timeout_ms=timeout_ms, max_output_bytes=max_output_bytes), "POST")

    # Run a bounded fixture command inside the sandbox and return its successful standard output.
    def execute(sandbox, *argv):
        result = expect(exec_call(sandbox, ["/fixture", *argv]), 200)
        assert result["exit_code"] == 0 and not result["interrupted"] and result["error"] is None and result["sandbox_state"] == "running", result
        return result["stdout"]

    # Send one app request to a sandbox port through the controller's proxy (path form, or the host form
    # `<port>-<id>.sandbox.test`) and return the status, headers and body bytes.
    def proxy_call(sandbox, method, path, body=None, headers=None, port_number=8080, host_form=False, authorized=True, timeout=60):
        headers = dict(headers or {})
        if authorized:
            headers["Authorization"] = "Bearer " + token
        if host_form:
            headers["Host"] = f"{port_number}-{sandbox}.sandbox.test"
        target = path if host_form else f"/v1/sandboxes/{sandbox}/proxy/{port_number}{path}"
        return exchange(controller_port, method, target, headers, body, timeout)

    # Require a proxied call to fail with the given status and error code.
    def proxy_error(result, status, code):
        assert result[0] == status and json.loads(result[2])["error"]["code"] == code, result

    # Kill a running command through the controller and return the raw status and result.
    def kill_call(sandbox, exec_id):
        return request(controller_port, f"/v1/sandboxes/{sandbox}/exec/{exec_id}/kill", token, method="POST")

    # Ask the controller to capture a sandbox as a template and return the raw status and result.
    def capture(sandbox, template_id):
        return request(controller_port, f"/v1/sandboxes/{sandbox}/capture", token, dict(template_id=template_id, runtime="runc_criu"), "POST")

    # Copy the first 64 KiB of each CRIU log of a sandbox into a private diagnostics directory.
    def diagnostics(sandbox, label):
        # The known generic fixture has no workload credentials. Retain bounded,
        # private CRIU diagnostics before cleanup removes them.
        target_dir = root / "diagnostics"
        target_dir.mkdir(mode=0o700, exist_ok=True)
        for logfile in (root / "private" / sandbox / "criu-work").glob("*.log"):
            with logfile.open("rb") as source_log:
                data = source_log.read(65536)
            target = target_dir / (label + "-" + logfile.name)
            target.write_bytes(data)
            target.chmod(0o600)

    # Capture a sandbox, saving CRIU logs on failure, and require success with the source still running
    # and the template published.
    def captured(sandbox, template_id):
        code, result = capture(sandbox, template_id)
        if code != 200:
            diagnostics(sandbox, template_id)
        assert code == 200 and result["state"] == "running" and result["template_id"] == template_id, result
        assert len(result["generation"]) == 32 and (root / "templates" / template_id / "manifest.json").exists()
        return result

    # Delete through the controller, require the blocking reply to report deleted and verify private
    # files, runc state and the sandbox resource group are gone.
    def remove(sandbox):
        result = expect(request(controller_port, f"/v1/sandboxes/{sandbox}", token, method="DELETE"), 200)
        assert result["state"] == "deleted"
        gone(sandbox)

    # Start a call on a background thread and return the thread and a box that receives its result.
    def in_background(call):
        box = {}
        thread = threading.Thread(target=lambda: box.setdefault("result", call()), daemon=True)
        thread.start()
        return thread, box

    # Return the per-command resource groups (`exec-<id>`) that currently exist in a sandbox.
    def exec_groups(sandbox):
        return sorted(p.name for p in (cgroup / sandbox).glob("exec-*") if p.is_dir()) if (cgroup / sandbox).exists() else []

    # Report whether a command is currently running in one of the sandbox's exec groups.
    def exec_cgroup_populated(sandbox):
        return any("populated 1" in (cgroup / sandbox / name / "cgroup.events").read_text() for name in exec_groups(sandbox))

    # Send a raw exec request to the controller and close the connection once the command is running.
    def disconnect_mid_exec(sandbox, body):
        # Send a complete request, wait until the command is really running, then
        # close the client connection without reading the response.
        data = json.dumps(body).encode()
        with socket.create_connection(("127.0.0.1", controller_port), timeout=4) as raw:
            raw.sendall((f"POST /v1/sandboxes/{sandbox}/exec HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n"
                         f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data)
            eventually(lambda: exec_cgroup_populated(sandbox), timeout=10)

    # Returns the name of the pooled routing slot namespace recorded for a sandbox.
    def slot_of(sandbox):
        return f"{owned_prefix}s-{json.loads((root / 'records' / f'{sandbox}.json').read_text())['network_slot']}"

    # Returns each pooled slot's identity: its ownership directory's change time and its host link's
    # interface index. A slot that was rebuilt gets new values; a slot that was reset keeps them.
    def slot_identities():
        links = {link["ifname"]: link["ifindex"] for link in json.loads(subprocess.check_output(["ip", "-j", "link"], timeout=5))}
        return {i: ((root / "slots" / str(i)).stat().st_ctime_ns, links[f"{slot_link_prefix}{i:03x}"]) for i in range(3)}

    # Returns the number of connection-tracking entries in a routing slot.
    def tracked_connections(name):
        return int(subprocess.check_output(["ip", "netns", "exec", name, "cat", "/proc/sys/net/netfilter/nf_conntrack_count"], text=True, timeout=5))

    # Requires a pooled slot to be in its clean pool state: only loopback and the uplink, no rule in
    # its filter chains and no tracked connection.
    def slot_reset(name):
        links = sorted(link["ifname"] for link in json.loads(subprocess.check_output(["ip", "-n", name, "-j", "link"], timeout=5)))
        assert links == ["lo", "uplink"], (name, links)
        table = json.loads(subprocess.check_output(["ip", "netns", "exec", name, "nft", "-j", "list", "table", "inet", "sandbox"], timeout=5))
        assert not any("rule" in entry for entry in table["nftables"]), (name, table)
        assert tracked_connections(name) == 0, name

    # Return how many bytes the worker process has read so far (rchar in /proc/<pid>/io). Hashing a
    # layer reads its whole image; reads through a loop-mounted layer are not counted.
    def worker_read_bytes():
        return int(next(line for line in Path(f"/proc/{worker.pid}/io").read_text().splitlines() if line.startswith("rchar:")).split()[1])

    # Return the identity the worker records for a layer image: device, inode, size, and modification
    # and change times in seconds and nanoseconds.
    def file_identity(path):
        info = path.stat()
        return dict(dev=info.st_dev, ino=info.st_ino, size=info.st_size, mtime=info.st_mtime_ns // 10**9, mtime_nsec=info.st_mtime_ns % 10**9,
                    ctime=info.st_ctime_ns // 10**9, ctime_nsec=info.st_ctime_ns % 10**9)

    # Kill the worker abruptly, start a new one on the same root and wait for a fresh observation.
    def kill_and_restart_worker():
        nonlocal worker
        worker.kill()
        worker.wait(timeout=5)
        worker = start("worker", worker_config)
        fresh()

    try:
        worker = start("worker", worker_config)
        controller = start("controller", controller_config)
        fresh()
        if args.network:
            # The worker pre-creates one clean routing slot per sandbox it can admit, before any create.
            assert sorted(p.name for p in Path("/run/netns").iterdir() if p.name.startswith(owned_prefix)) == [f"{owned_prefix}s-{i}" for i in range(3)]
            for i in range(3):
                slot_reset(f"{owned_prefix}s-{i}")
            pool_identities = slot_identities()
        # Omitted resources come from the cold template defaults (64 MiB, 1 vCPU).
        source = create()
        assert (cgroup / source / "memory.max").read_text().strip() == "67108864"
        assert int(execute(source, "process-group")) >= 0
        observations["read_only_process_group_query"] = True
        # PID 1 is the bind-mounted reaping init; the fixture init does not reap.
        assert execute(source, "init-name") == "/.sandbox-init\n"
        execute(source, "orphan-exit")
        time.sleep(1)
        assert execute(source, "zombies") == "0\n", "orphaned child was not reaped by PID 1"
        observations["pid1_reaping_init"] = True
        isolated = create(memory_mib=64, vcpus=1)
        observations["create_explicit_and_template_default_resources"] = True
        # Several commands run at once in one sandbox (and in another), each in its own exec group.
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            commands = [pool.submit(execute, source, "delay"), pool.submit(execute, source, "delay"), pool.submit(execute, isolated, "delay")]
            eventually(lambda: len(exec_groups(source)) == 2, timeout=10)
            groups_seen = exec_groups(source)
            started = time.monotonic()
            # A third command in the same sandbox still runs (limit 3); capture is refused while commands run.
            assert execute(source, "counter")
            expect(capture(source, "busy-capture"), 409, "sandbox_busy")
            assert time.monotonic() - started < 2, "a conflicting capture waited instead of failing fast"
            spans = [tuple(map(int, command.result(timeout=15).split())) for command in commands]
        assert max(begin for begin, _ in spans) < min(end for _, end in spans), "concurrent commands were serialized"
        assert not (root / "templates" / "busy-capture").exists() and exec_groups(source) == []
        observations["concurrent_exec_monotonic_ns"] = spans
        observations["concurrent_exec_groups"] = groups_seen
        # The per-sandbox command limit (3 here) refuses a fourth running command at once.
        hangs = [in_background(lambda: exec_call(source, ["/fixture", "hang"], timeout_ms=20000)) for _ in range(3)]
        eventually(lambda: len(exec_groups(source)) == 3 and exec_cgroup_populated(source), timeout=10)
        expect(exec_call(source, ["/fixture", "counter"]), 409, "exec_limit")
        # Kill stops one command by its ID and answers after it ended; the command reports exec_killed and
        # the sandbox keeps running.
        for name in exec_groups(source):
            killed = expect(kill_call(source, int(name.split("-")[1])), 200)
            assert killed["state"] == "exited" and killed["exec_id"] == int(name.split("-")[1]), killed
            assert name not in exec_groups(source)
        for thread, box in hangs:
            thread.join(timeout=15)
            code, result = box["result"]
            assert code == 200 and result["interrupted"] and result["error"] == "exec_killed" and result["exit_code"] is None and result["sandbox_state"] == "running", result
        expect(kill_call(source, 999999), 404, "exec_not_found")
        observations["exec_limit_and_kill"] = True
        # Streaming mode: output events arrive while the command runs, then the exit event.
        status, events = exec_events(controller_port, f"/v1/sandboxes/{source}/exec", token, dict(argv=["/fixture", "ticks"], timeout_ms=5000, max_output_bytes=4096))
        assert status == 200 and events[0][1] == "start" and events[-1][1] == "exit", events
        assert b"".join(base64.b64decode(data["data"]) for _, name, data in events if name == "stdout") == b"".join(f"tick {i}\n".encode() for i in range(5))
        arrivals = [at for at, name, _ in events if name == "stdout"]
        assert arrivals[-1] - arrivals[0] >= 0.6, "streamed output arrived only at the end"
        assert events[-1][2] == {"exit_code": 0, "interrupted": False, "error": None, "sandbox_state": "running"}, events[-1]
        status, events = exec_events(controller_port, f"/v1/sandboxes/{source}/exec", token, dict(argv=["/fixture", "dual-output"], timeout_ms=5000, max_output_bytes=262144))
        streams = {name: b"".join(base64.b64decode(data["data"]) for _, kind, data in events if kind == name) for name in ("stdout", "stderr")}
        assert status == 200 and streams == {"stdout": b"o" * 131072, "stderr": b"e" * 131072} and events[-1][2]["exit_code"] == 0
        status, events = exec_events(controller_port, f"/v1/sandboxes/{source}/exec", token, dict(argv=["/fixture", "hang"], timeout_ms=300, max_output_bytes=1024))
        assert status == 200 and events[-1][2] == {"exit_code": None, "interrupted": True, "error": "exec_timeout", "sandbox_state": "running"}, events
        observations["streaming_exec_spread_s"] = round(arrivals[-1] - arrivals[0], 3)
        execute(source, "orphan")
        assert exec_groups(source) == [], "exec descendants/cgroup survived successful command"
        print("PASS blocking cold create, concurrent commands in one sandbox (own groups), command limit, kill, streamed output and immediate capture 409")

        before_dirs = {name: sorted(p.name for p in (root / name).iterdir()) for name in ("private", "runc")}
        rejected_templates = ["incompatible", "symlinked", "unknown-metadata", "old-schema"] + (["policy-not-authorized", "unsupported-policy"] if args.network else [])
        for invalid_template in rejected_templates:
            rejected = expect(create_call(dict(template_id=invalid_template, ttl_seconds=60)), 422, "template_unavailable")
            assert "sandbox_id" not in rejected, "a pre-launch template rejection must not name an ID"
        rejected = expect(create_call(dict(template_id="no-defaults", ttl_seconds=60)), 422, "resources_required")
        assert "sandbox_id" not in rejected
        tampered = expect(create_call(dict(template_id="tampered", ttl_seconds=60)), 500, "artifact_digest_mismatch")
        record = get(tampered["sandbox_id"])
        assert record["state"] == "failed" and record["error"] == "artifact_digest_mismatch"
        gone(tampered["sandbox_id"])
        assert before_dirs == {name: sorted(p.name for p in (root / name).iterdir()) for name in ("private", "runc")}
        observations["template_rejections"] = {"pre_launch_422": rejected_templates, "failed_record_with_id": "tampered"}
        third = create("no-defaults", memory_mib=64, vcpus=1)
        over_budget = dict(sandbox_id="node-smoke.over-budget", template_id="fixture", ttl_seconds=120)
        expect(request(worker_port, "/v1/sandboxes", worker_token, over_budget, "POST"), 503, "admission_exhausted")
        # A capacity rejection consumes no durable record (failover cannot exhaust max_records).
        expect(request(worker_port, f"/v1/sandboxes/{over_budget['sandbox_id']}", worker_token), 404, "sandbox_not_found")
        assert not (root / "records" / (over_budget["sandbox_id"] + ".json")).exists() and not (cgroup / over_budget["sandbox_id"]).exists()
        fresh()
        eventually(lambda: expect(request(controller_port, "/v1/status", token, timeout=4), 200)["nodes"][0]["status"]["usage"]["sandboxes"] == 3)
        expect(request(controller_port, "/v1/sandboxes", token, dict(template_id="fixture", ttl_seconds=60), "POST"), 503, "no_capacity")
        observations["final_worker_admission_without_record_and_controller_no_capacity"] = True
        guest = Path(json.loads((root / "private" / third / "config.json").read_text())["linux"]["namespaces"][2]["path"])
        # A test-owned open file in the sandbox root keeps its mount busy, so the blocking DELETE reports
        # cleanup_failed; the reservation and ownership marker survive and cleanup is retried once the
        # file is closed. A test-owned guest namespace FD does not delay the network release: deleting
        # the slot's end of the veth pair removes the guest's end at once.
        with open(guest, "rb") as held_guest, open(root / "private" / third / "rootfs" / "fixture", "rb"):
            expect(request(controller_port, f"/v1/sandboxes/{third}", token, method="DELETE"), 500, "cleanup_failed")
            assert get(third)["state"] == "cleanup_failed" and (root / "private" / third / "network-owned").exists()
            assert not guest.exists()
            held_links = json.loads(subprocess.check_output(["nsenter", f"--net=/proc/{os.getpid()}/fd/{held_guest.fileno()}", "ip", "-j", "link"], timeout=5))
            assert [link["ifname"] for link in held_links] == ["lo"], held_links
            if args.network:
                third_slot = slot_of(third)
                slot_reset(third_slot)
        eventually(lambda: get(third)["state"] == "deleted", timeout=15)
        remove(third)
        observations["cleanup_retry_after_root_holder_release"] = True
        if args.network:
            # Released slots are reset, not deleted: the same slot namespace and host link remain.
            assert slot_identities() == pool_identities
            slot_reset(third_slot)
            observations["network_slot_reset_not_deleted_with_guest_namespace_held"] = third_slot
        print("PASS template rejection without IDs, failed-launch tombstone, final worker admission without a record and inline delete")

        # A client that disconnects mid-exec leaves no orphan: the command still runs
        # to completion with normal exec-cgroup cleanup, then the sandbox is free again.
        disconnect_mid_exec(source, dict(argv=["/fixture", "delay"], timeout_ms=5000, max_output_bytes=1024))
        eventually(lambda: exec_groups(source) == [], timeout=15)
        expect(exec_call(source, ["/fixture", "counter"]), 200)
        # A disconnected bound-violating command is still stopped at its deadline; only its group goes.
        doomed = create()
        disconnect_mid_exec(doomed, dict(argv=["/fixture", "hang"], timeout_ms=1500, max_output_bytes=1024))
        eventually(lambda: exec_groups(doomed) == [], timeout=15)
        assert get(doomed)["state"] == "running" and execute(doomed, "counter")
        remove(doomed)
        observations["client_disconnect_mid_exec_no_orphan"] = True
        # A client that disconnects mid-create can never learn the generated ID, so
        # the worker deletes the sandbox when its create reply is undeliverable.
        known = {p.name for p in (root / "records").glob("*.json")}
        # The raw request is not retried, so let the advisory snapshot catch up first.
        live = expect(request(worker_port, "/v1/status", worker_token, timeout=4), 200)["usage"]["sandboxes"]
        eventually(lambda: expect(request(controller_port, "/v1/status", token, timeout=4), 200)["nodes"][0]["status"]["usage"]["sandboxes"] == live)
        (helpers / "cgroup.freeze").write_text("1")
        try:
            data = json.dumps(dict(template_id="fixture", ttl_seconds=600)).encode()
            with socket.create_connection(("127.0.0.1", controller_port), timeout=4) as raw:
                raw.sendall((f"POST /v1/sandboxes HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n"
                             f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data)
                try:
                    created_record = eventually(lambda: [p for p in (root / "records").glob("*.json") if p.name not in known], timeout=10)
                except AssertionError:
                    raw.settimeout(2)
                    raise AssertionError("create never reached admission; controller answered: " + raw.recv(4096).decode(errors="replace"))
                eventually(lambda: any("populated 1" in p.read_text() for p in helpers.glob("command-*/cgroup.events")), timeout=10)
            time.sleep(1)
        finally:
            (helpers / "cgroup.freeze").write_text("0")
        lost = created_record[0].name[:-len(".json")]
        ids.append(lost)
        eventually(lambda: get(lost)["state"] == "deleted", timeout=30)
        assert get(lost)["error"] == "create_response_lost"
        gone(lost)
        observations["client_disconnect_mid_create_deleted"] = lost
        # DELETE cancels an in-flight exec (and, with networking, an open proxied stream) of the same
        # sandbox and returns after cleanup.
        cancelled = create()
        thread, box = in_background(lambda: exec_call(cancelled, ["/fixture", "hang"], timeout_ms=30000))
        eventually(lambda: exec_cgroup_populated(cancelled), timeout=10)
        if args.network:
            stream = http.client.HTTPConnection("127.0.0.1", controller_port, timeout=30)
            stream.request("GET", f"/v1/sandboxes/{cancelled}/proxy/8080/chunked/60/200", headers={"Authorization": "Bearer " + token})
            streamed = stream.getresponse()
            assert streamed.status == 200 and streamed.readline() == b"part-0\n"
        started = time.monotonic()
        remove(cancelled)
        assert time.monotonic() - started < 20
        thread.join(timeout=30)
        code, result = box["result"]
        assert code == 200 and result["interrupted"] and result["error"] == "sandbox_cancelled_or_expired" and result["sandbox_state"] != "running", result
        observations["delete_cancels_inflight_exec"] = {"delete_seconds": round(time.monotonic() - started, 3), "exec_status": code}
        if args.network:
            try:
                rest = streamed.read()
                ended = "complete" if rest.endswith(b"part-59\n") else "truncated"
            except (http.client.HTTPException, OSError):
                ended = "reset"
            stream.close()
            assert ended != "complete" and time.monotonic() - started < 12, ended
            observations["delete_ends_open_proxy_stream"] = ended
        # A second concurrent DELETE waits for the first cleanup and gets its result.
        waited = create()
        delete_call = lambda: request(controller_port, f"/v1/sandboxes/{waited}", token, method="DELETE")
        (helpers / "cgroup.freeze").write_text("1")
        try:
            first_delete, first_box = in_background(delete_call)
            eventually(lambda: any("populated 1" in p.read_text() for p in helpers.glob("command-*/cgroup.events")), timeout=10)
            second_delete, second_box = in_background(delete_call)
            time.sleep(1)
            assert first_delete.is_alive() and second_delete.is_alive(), "a DELETE returned while cleanup was frozen"
        finally:
            (helpers / "cgroup.freeze").write_text("0")
        first_delete.join(timeout=30)
        second_delete.join(timeout=30)
        for box in (first_box, second_box):
            code, result = box["result"]
            assert code == 200 and result["state"] == "deleted", (code, result)
        gone(waited)
        observations["second_delete_waits_for_first"] = True
        print("PASS client disconnect mid-exec (completion and bound-kill) and mid-create, DELETE cancellation and a waiting second DELETE leave no orphan")

        # Loopback round trips over one ESTABLISHED connection inside the sandbox.
        # Return the round-trip count after checking both ends are established and no error occurred.
        def loopback(sandbox):
            fields = dict(item.split("=") for item in execute(sandbox, "loopback").split())
            assert fields["error"] == "0" and fields["established"] == "2", fields
            return int(fields["roundtrips"])
        execute(source, "write", "copied", "source-private")
        execute(source, "unlink", "removed")
        assert execute(isolated, "read", "copied") == "immutable-base"
        assert execute(isolated, "read", "removed") == "immutable-base"
        status = execute(source, "network-isolation" if args.network else "isolation")
        assert status.startswith("seccomp_guards io_uring=ENOSYS mptcp=EPROTONOSUPPORT\n") and "CapEff:\t0000000000000000" in status and "NoNewPrivs:\t1" in status and "Seccomp:\t2" in status
        assert (cgroup / source / "memory.max").read_text().strip() == "67108864"
        assert (cgroup / source / "memory.swap.max").read_text().strip() == "0"
        assert (cgroup / source / "cpu.max").read_text().strip() == "100000 100000"
        assert (cgroup / source / "pids.max").read_text().strip() == "64"
        # Namespace identities are independently owned, not a shared warm netns.
        # Query runc for the sandbox's host process ID with a short deadline and controlled tool environment.
        def host_pid(sandbox):
            runc = str(Path(args.tools_dir) / "runc") if args.tools_dir else "runc"
            data = subprocess.run([runc, "--root", str(root / "runc"), "state", sandbox], check=True, capture_output=True, timeout=5, env={"PATH": args.tools_dir or "/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
            return json.loads(data.stdout)["pid"]
        a, b = host_pid(source), host_pid(isolated)
        observations["namespace_identities"] = {}
        for namespace in ("pid", "mnt", "net", "ipc", "uts", "cgroup"):
            identities = [os.readlink(f"/proc/{pid}/ns/{namespace}") for pid in (a, b, os.getpid())]
            assert len(set(identities)) == 3
            observations["namespace_identities"][namespace] = identities
        # Examine links only inside owned netns; never change interfaces/rules.
        links = subprocess.run(["nsenter", "-t", str(a), "-n", "ip", "-j", "link", "show"], check=True, capture_output=True, timeout=5)
        assert sorted(link["ifname"] for link in json.loads(links.stdout)) == (["eth0", "lo"] if args.network else ["lo"])
        if not args.network:
            # An isolated template approves no service port, so the proxy refuses it.
            proxy_error(proxy_call(source, "GET", "/"), 403, "service_port_not_authorized")
            # The worker-created isolated guest namespace has loopback only: no routes either.
            routes = subprocess.run(["nsenter", "-t", str(a), "-n", "ip", "-j", "route", "show", "table", "main"], check=True, capture_output=True, timeout=5)
            assert json.loads(routes.stdout or b"[]") == []
            assert Path(json.loads((root / "private" / source / "config.json").read_text())["linux"]["namespaces"][2]["path"]).exists()
        # Record owned network state and exercise allowed/denied TCP, path-MTU discovery and the app proxy
        # (path and host forms). With full, also check authentication, an unapproved port, real
        # statuses and headers, binary and chunked streaming in both directions, the idle timeout and
        # the connection limit, with the connections opened inside the routing slot only, while
        # requiring the sandbox to remain running. Return True.
        def network_gate(sandbox, full=False):
            config_json = json.loads((root / "private" / sandbox / "config.json").read_text())
            guest = Path(config_json["linux"]["namespaces"][2]["path"]).name
            slot = slot_of(sandbox)
            observations.setdefault("network_rules", {})[sandbox] = {name: subprocess.check_output(["ip", "netns", "exec", name, "nft", "list", "ruleset"], text=True, timeout=5) for name in [guest, slot]}
            observations.setdefault("network_links", {})[sandbox] = {name: {what: subprocess.check_output(["ip", "-n", name, "-j", what], text=True, timeout=5) for what in ["address", "route", "neigh"]} for name in [guest, slot]}
            observations.setdefault("guest_netns_match", {})[sandbox] = [os.readlink(f"/proc/{host_pid(sandbox)}/ns/net"), os.stat("/run/netns/" + guest).st_ino]
            assert "connected=1" in execute(sandbox, "connect", "198.18.0.1", "18080", "1")
            for ip, port_number in [("198.18.0.1", "18081"), ("198.18.0.2", "18080"), ("198.18.0.11", "8080")]:
                assert "connected=0" in execute(sandbox, "connect", ip, port_number, "0")
            # Black-hole probing must not mask the actual fragmentation-needed path.
            assert subprocess.check_output(["ip", "netns", "exec", guest, "cat", "/proc/sys/net/ipv4/tcp_mtu_probing"], text=True).strip() == "0"
            # Sum packet counters in the selected routing-namespace firewall chain to observe path-MTU error
            # traffic.
            def pmtu_count(chain):
                data = json.loads(subprocess.check_output(["ip", "netns", "exec", slot, "nft", "-j", "list", "chain", "inet", "sandbox", chain], text=True))
                return sum(expr["counter"]["packets"] for entry in data["nftables"] for expr in entry.get("rule", {}).get("expr", []) if "counter" in expr)
            for destination, chain, mtu in [("198.19.0.2", "forward", 1500), ("198.19.0.3", "output", 1280)]:
                before_packets = pmtu_count(chain)
                subprocess.run(["ip", "-n", slot, "link", "set", "uplink", "mtu", str(mtu)], check=True, timeout=5)
                try:
                    transfer = execute(sandbox, "transfer", destination).strip()
                finally:
                    subprocess.run(["ip", "-n", slot, "link", "set", "uplink", "mtu", "1500"], check=True, timeout=5)
                after_packets = pmtu_count(chain)
                assert "bytes=65536" in transfer and "mtu_after=1280" in transfer
                if full:
                    assert "mtu_before=1500" in transfer, "test must start without a cached reduced PMTU"
                if "mtu_before=1500" in transfer:
                    assert after_packets > before_packets, "necessary ICMP did not traverse the narrow PMTU rule"
                observations.setdefault("pmtu_transfers", []).append(dict(sandbox=sandbox, destination=destination, chain=chain,
                    result=transfer, counter_before=before_packets, counter_after=after_packets, blackhole_probing=0))
            for destination, port_number in [("198.19.0.2", "18081"), ("198.19.0.4", "18080")]:
                assert "connected=0" in execute(sandbox, "connect", destination, port_number, "0")
            # The app proxy reaches the approved service port through the controller and the worker.
            status, headers, body = proxy_call(sandbox, "POST", "/headers?test=1", b"request-text", {"Content-Type": "text/plain"})
            assert status == 200 and body.startswith(b"POST /headers?test=1 HTTP/1.1\r\n") and body.endswith(b"request-text"), body[:300]
            lowered = body.lower()
            assert b"\r\nauthorization:" not in lowered and token.encode() not in body and worker_token.encode() not in body
            assert b"\r\nhost: 192.0.2.2:8080\r\n" in lowered and f"\r\nx-forwarded-host: 127.0.0.1:{controller_port}\r\n".encode() in lowered, body[:600]
            status, _, body = proxy_call(sandbox, "GET", "/via-host?x=1", host_form=True)
            assert status == 200 and body.startswith(b"GET /via-host?x=1 HTTP/1.1\r\n") and f"\r\nx-forwarded-host: 8080-{sandbox}.sandbox.test\r\n".encode() in body.lower()
            if full:
                proxy_error(proxy_call(sandbox, "GET", "/", authorized=False), 401, "unauthorized")
                proxy_error(proxy_call(sandbox, "GET", "/", port_number=8081), 403, "service_port_not_authorized")
                status, headers, _ = proxy_call(sandbox, "GET", "/redirect")
                assert status == 302 and headers["location"] == "http://198.18.0.2:18080/", "redirects are returned, not followed"
                status, headers, _ = proxy_call(sandbox, "GET", "/headers-large")
                assert status == 200 and headers["x-large"] == "a" * 20000
                assert proxy_call(sandbox, "GET", "/binary")[2] == b"\xff"
                # Chunked parts reach the client as the guest sends them.
                connection = http.client.HTTPConnection("127.0.0.1", controller_port, timeout=10)
                started = time.monotonic()
                connection.request("GET", f"/v1/sandboxes/{sandbox}/proxy/8080/chunked/5/300", headers={"Authorization": "Bearer " + token})
                response = connection.getresponse()
                arrivals = []
                for _ in range(5):
                    line = response.readline()
                    arrivals.append((round(time.monotonic() - started, 3), line))
                assert response.read() == b"" and [line for _, line in arrivals] == [f"part-{i}\n".encode() for i in range(5)]
                assert arrivals[-1][0] - arrivals[0][0] >= 1.0 and response.getheader("Transfer-Encoding") == "chunked", arrivals
                connection.close()
                # Two concurrent 32 MiB binary downloads and an 8 MiB binary upload stream through unchanged.
                size = 32 << 20
                expected = (bytes(range(251)) * (size // 251 + 1))[:size]
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    downloads = list(pool.map(lambda _: proxy_call(sandbox, "GET", f"/pattern/{size}"), range(2)))
                assert all(d[0] == 200 and d[1]["content-length"] == str(size) and d[2] == expected for d in downloads)
                upload = os.urandom(8 << 20)
                fnv = 1469598103934665603
                for byte in upload:
                    fnv = ((fnv ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
                status, _, body = proxy_call(sandbox, "POST", "/count", upload, {"Content-Type": "application/octet-stream"})
                assert status == 200 and body == f"bytes={len(upload)} fnv={fnv:016x}".encode(), body
                # Every proxied connection was opened inside the routing slot: none in this namespace.
                assert not any(row.split()[2] == "020200C0:1F90" for row in Path("/proc/net/tcp").read_text().splitlines()[1:]), "guest connection in the worker namespace"
                # Nothing for longer than the worker idle timeout (3 s) is a 504; the sandbox keeps running.
                proxy_error(proxy_call(sandbox, "GET", "/delay/4000"), 504, "upstream_timeout")
                eventually(lambda: proxy_call(sandbox, "GET", "/")[0] == 200, timeout=30)
                # The worker allows four open exchanges; a fifth is refused at once.
                held = [in_background(lambda: proxy_call(sandbox, "GET", "/delay/2500")) for _ in range(4)]
                # The open exchanges are ESTABLISHED connections to the guest port inside the slot.
                def guest_connections():
                    rows = subprocess.check_output(["ip", "netns", "exec", slot, "cat", "/proc/net/tcp"], text=True, timeout=5).splitlines()[1:]
                    return sum(1 for row in rows if row.split()[2] == "020200C0:1F90" and row.split()[3] == "01")
                eventually(lambda: guest_connections() >= 4, timeout=10)
                started = time.monotonic()
                proxy_error(proxy_call(sandbox, "GET", "/"), 503, "busy")
                assert time.monotonic() - started < 2
                for thread, _ in held:
                    thread.join(timeout=30)
                assert {box["result"][0] for _, box in held} <= {200, 504}
                eventually(lambda: proxy_call(sandbox, "GET", "/")[0] == 200, timeout=40)
                observations.setdefault("proxy_full", {})[sandbox] = dict(chunk_arrivals_s=[at for at, _ in arrivals], download_bytes=size, upload_bytes=len(upload),
                    held_results=sorted(box["result"][0] for _, box in held))
                assert get(sandbox)["state"] == "running"
            return True
        if args.network:
            observations["network_and_proxy_before_capture"] = network_gate(source, True)
            # An ESTABLISHED external connection no longer blocks capture
            # (--tcp-established). The source keeps it; a child restores its socket
            # with the same fixed guest IP (the remote peer is not cloned).
            held = create()
            execute(held, "write", "hold-external", "1")
            time.sleep(0.3)
            assert execute(held, "read", "holding") == "ready"
            captured(held, "held-warm")
            assert get(held)["state"] == "running" and loopback(held) > 0
            remove(held)
            held_child = create("held-warm")
            time.sleep(0.3)
            first_trips = loopback(held_child)
            time.sleep(0.5)
            assert loopback(held_child) > first_trips and get(held_child)["state"] == "running"
            remove(held_child)
            observations["established_external_connection_captured_and_restored"] = True
        before, nonce = map(int, execute(source, "counter").split())
        source_trips = loopback(source)
        expect(capture(source, "fixture"), 409, "template_already_exists")
        assert get(source)["state"] == "running"
        # A capture must neither adopt nor clean an existing unacquired staging leaf.
        conflict = root / "staging" / "not-published"
        conflict.mkdir(mode=0o700)
        (conflict / "sentinel").write_text("owned-by-test")
        expect(capture(source, "not-published"), 500, "directory_create_failed")
        assert (conflict / "sentinel").read_text() == "owned-by-test" and get(source)["state"] == "running"
        (conflict / "sentinel").unlink()
        conflict.rmdir()
        observations["unacquired_staging_preserved"] = True
        # A checkpoint that fails after the source was frozen (CRIU cannot dump a userfaultfd) thaws
        # the source and keeps it: it stays running, its counter and loopback connection advance, and
        # nothing is published.
        # Read the init's userfaultfd status; empty until the init first writes it.
        def uffd_status():
            result = expect(exec_call(source, ["/fixture", "read", "uffd-status"]), 200)
            return result["stdout"] if result["exit_code"] == 0 else ""
        execute(source, "write", "hold-uffd", "1")
        eventually(lambda: uffd_status() == "held\n", timeout=10)
        frozen_counter = int(execute(source, "counter").split()[0])
        failed_trips = loopback(source)
        code, failed = capture(source, "uffd-fails")
        assert code == 500 and failed["error"]["code"] == "checkpoint_failed", (code, failed)
        assert get(source)["state"] == "running" and not (root / "templates" / "uffd-fails").exists() and not (root / "staging" / "uffd-fails").exists()
        time.sleep(0.3)
        assert int(execute(source, "counter").split()[0]) > frozen_counter and loopback(source) > failed_trips
        execute(source, "unlink", "hold-uffd")
        eventually(lambda: uffd_status().startswith("released"), timeout=10)
        observations["failed_checkpoint_keeps_source_running"] = True
        # A dump stopped at its deadline leaves the source in an uncertain state, so it is deleted rather
        # than kept. The test stops the `runc checkpoint` helper (SIGSTOP) as soon as it appears; the
        # worker kills it at the 30 s command deadline.
        doomed = create()
        stopped = {}
        # Find this sandbox's runc checkpoint process among the worker's helpers and stop it.
        def stop_checkpoint():
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                for procs in helpers.glob("command-*/cgroup.procs"):
                    try:
                        pids = procs.read_text().split()
                    except OSError:
                        continue
                    for pid in pids:
                        try:
                            argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
                        except OSError:
                            continue
                        if b"checkpoint" in argv and doomed.encode() in argv:
                            os.kill(int(pid), signal.SIGSTOP)
                            stopped["pid"] = int(pid)
                            return
                time.sleep(0.001)
        stopper = threading.Thread(target=stop_checkpoint, daemon=True)
        stopper.start()
        started = time.monotonic()
        code, interrupted = capture(doomed, "interrupted-dump")
        interrupted_seconds = time.monotonic() - started
        stopper.join(timeout=5)
        assert stopped and code == 500 and interrupted["error"]["code"] == "checkpoint_interrupted", (stopped, code, interrupted)
        assert interrupted_seconds >= 29, interrupted_seconds
        assert get(doomed)["state"] == "deleted" and get(doomed)["error"] == "checkpoint_interrupted", get(doomed)
        gone(doomed)
        assert not (root / "templates" / "interrupted-dump").exists() and not (root / "staging" / "interrupted-dump").exists()
        assert get(source)["state"] == "running" and get(isolated)["state"] == "running"
        observations["interrupted_checkpoint_deletes_source"] = dict(stopped_pid=stopped["pid"], capture_s=round(interrupted_seconds, 3))
        isolated_nonce = int(execute(isolated, "counter").split()[1])
        # The source keeps running during capture except while frozen (pause to resume).
        stop_watch = threading.Event()
        watchers = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        watcher = watchers.submit(watch_counter, root / "private" / source / "upper" / "workspace" / "counter", stop_watch)
        freezer = watchers.submit(watch_frozen, cgroup / source / "cgroup.events", stop_watch)
        capture_started = time.monotonic()
        # Freeze only the owned helper subtree to make concurrent staging observable.
        (helpers / "cgroup.freeze").write_text("1")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(captured, source, "warm")
            second = pool.submit(captured, isolated, "isolated-warm")
            try:
                stages = [root / "staging" / "warm", root / "staging" / "isolated-warm"]
                eventually(lambda: all(p.is_dir() for p in stages) and sum("populated 1" in p.read_text() for p in helpers.glob("command-*/cgroup.events")) == 2, timeout=10)
                observations["concurrent_capture_staging"] = [p.name for p in stages]
            finally:
                (helpers / "cgroup.freeze").write_text("0")
            observations["capture_results"] = [first.result(timeout=200), second.result(timeout=200)]
        capture_seconds = time.monotonic() - capture_started
        stop_watch.set()
        watched = dict(watcher.result(timeout=10), **freezer.result(timeout=10))
        assert watched["changes"] > 0 and watched["longest_unchanged_s"] < capture_seconds, watched
        assert watched["freeze_periods"] >= 1 and 0 < watched["frozen_s"] < capture_seconds, watched
        observations["source_during_capture"] = dict(watched, capture_s=round(capture_seconds, 3))
        assert not any(p.exists() for p in stages)
        current, source_nonce = map(int, execute(source, "counter").split())
        assert source_nonce == nonce and current >= before
        # The source's loopback connection kept working across its own checkpoint.
        assert loopback(source) > source_trips
        # The capture sealed the upper into a content-addressed EROFS layer; no upper archive.
        warm_manifest = json.loads((root / "templates" / "warm" / "manifest.json").read_text())
        layer = warm_manifest["layers"][0]["sha256"]
        assert warm_manifest["schema_version"] == 3 and len(warm_manifest["layers"]) == 1 and (root / "layers" / f"{layer}.erofs").is_file()
        assert sorted(p.name for p in (root / "templates" / "warm").iterdir()) == ["checkpoint.tar", "manifest.json", "manifest.sha256"]
        remove(isolated)
        expect(create_call(dict(template_id="warm", ttl_seconds=60, memory_mib=128)), 422, "template_resource_mismatch")
        child = create("warm")
        time.sleep(0.3)
        restored, child_nonce = map(int, execute(child, "counter").split())
        assert child_nonce == nonce and restored >= before
        observations["warm_state"] = {"before_counter":before,"source_counter":current,"child_counter":restored,"source_nonce":source_nonce,"child_nonce":child_nonce}
        # The restored child continues the captured ESTABLISHED loopback connection.
        child_trips = loopback(child)
        time.sleep(0.5)
        assert loopback(child) > child_trips
        observations["established_loopback_restored"] = {"child_roundtrips": [child_trips, loopback(child)]}
        assert execute(child, "read", "copied") == "source-private"
        missing = expect(exec_call(child, ["/fixture", "read", "removed"], timeout_ms=2000, max_output_bytes=1024), 200)
        assert missing["exit_code"] != 0 and not missing["interrupted"] and missing["sandbox_state"] == "running"
        # Sealed layer, as mounted read-only on the host: a whiteout for the deleted base file and the
        # modified base file with its ownership, mode and extended attribute.
        sealed = root / "lowers" / layer / "workspace"
        whiteout = sealed.joinpath("removed").lstat()
        assert stat.S_ISCHR(whiteout.st_mode) and whiteout.st_rdev == 0
        modified = sealed.joinpath("copied").lstat()
        assert sealed.joinpath("copied").read_text() == "source-private" and (modified.st_uid, modified.st_gid, stat.S_IMODE(modified.st_mode)) == (0, 0, 0o666)
        assert os.getxattr(sealed / "copied", "user.sandbox-test") == b"base-xattr"
        assert os.getxattr(root / "private" / child / "rootfs" / "workspace" / "copied", "user.sandbox-test") == b"base-xattr"
        assert not (root / "private" / child / "upper" / "workspace" / "copied").exists(), "child upper must start empty"
        observations["sealed_layer"] = {"sha256": layer, "whiteout": True, "modified_owner_mode_xattr": True}
        warm_cache, warm_cache_state = checkpoint_cache(root, "warm")
        assert not any(p.name.endswith(".unpacking") for p in (root / "checkpoints").iterdir())
        execute(child, "write", "copied", "child-private")
        assert execute(source, "read", "copied") == "source-private"
        observations["restored_namespace_identities"] = {}
        for namespace in ("pid", "mnt", "net", "ipc", "uts", "cgroup"):
            identities = [os.readlink(f"/proc/{pid}/ns/{namespace}") for pid in (host_pid(source), host_pid(child), os.getpid())]
            assert len(set(identities)) == 3
            observations["restored_namespace_identities"][namespace] = identities
        for sandbox in (source, child):
            assert str(host_pid(sandbox)) in (cgroup / sandbox / "cgroup.procs").read_text().split()
            assert (cgroup / sandbox / "memory.max").read_text().strip() == "67108864"
        if args.network:
            observations["restored_listening_socket_and_fresh_egress"] = network_gate(child)
            observations["source_listening_socket_and_fresh_egress"] = network_gate(source)
        # CRIU only read the shared images while restoring the child.
        assert checkpoint_cache(root, "warm")[1] == warm_cache_state
        print("PASS capture without stopping the source (stopped only while frozen and dumped), sealed EROFS layer with whiteout/xattr, "
              "warm restore with established loopback TCP, independent child")
        # Chained capture: capturing the warm child seals its own changes as a second layer above the
        # source's; a grandchild restores from that two-layer template.
        captured(child, "chained")
        chained_manifest = json.loads((root / "templates" / "chained" / "manifest.json").read_text())
        assert len(chained_manifest["layers"]) == 2 and chained_manifest["layers"][1]["sha256"] == layer, chained_manifest["layers"]
        assert chained_manifest["base"] == warm_manifest["base"]
        assert get(child)["state"] == "running" and execute(child, "read", "copied") == "child-private"
        grandchild = create("chained")
        time.sleep(0.3)
        assert int(execute(grandchild, "counter").split()[1]) == nonce
        assert execute(grandchild, "read", "copied") == "child-private"
        missing = expect(exec_call(grandchild, ["/fixture", "read", "removed"], timeout_ms=2000, max_output_bytes=1024), 200)
        assert missing["exit_code"] != 0 and not missing["interrupted"]
        grandchild_trips = loopback(grandchild)
        time.sleep(0.5)
        assert loopback(grandchild) > grandchild_trips
        execute(grandchild, "write", "copied", "grandchild-private")
        assert execute(child, "read", "copied") == "child-private"
        remove(grandchild)
        observations["chained_capture"] = dict(layers=[l["sha256"] for l in chained_manifest["layers"]], grandchild_roundtrips=grandchild_trips)
        print("PASS chained capture of a warm child and restore from the two-layer template (counter, files, whiteout, loopback TCP)")
        if args.network:
            child_slot = slot_of(child)
            assert tracked_connections(child_slot) > 0
        remove(child)
        if args.network:
            # The release flushed the child's rules and connection tracking from its slot.
            slot_reset(child_slot)
            observations["released_slot_connection_tracking_flushed"] = child_slot
        other_child = create("isolated-warm", memory_mib=64, vcpus=1)
        assert int(execute(other_child, "counter").split()[1]) == isolated_nonce
        assert execute(other_child, "read", "copied") == "immutable-base"
        remove(other_child)
        observations["independent_concurrent_capture_restores"] = True
        expiring = create(ttl=3)
        eventually(lambda: get(expiring)["state"] == "deleted", timeout=15)
        gone(expiring)
        bounded = create()
        dual = expect(exec_call(bounded, ["/fixture", "dual-output"], timeout_ms=2000, max_output_bytes=262144), 200)
        assert dual["stdout"] == "o"*131072 and dual["stderr"] == "e"*131072
        observations["exec_both_streams_drained"] = True
        # A timeout or output overflow stops only that command group; the sandbox keeps running.
        result = expect(exec_call(bounded, ["/fixture", "hang"], timeout_ms=100, max_output_bytes=1024), 200)
        assert result["interrupted"] and result["error"] == "exec_timeout" and result["exit_code"] is None and result["sandbox_state"] == "running", result
        for command in ("flood", "flood-both"):
            result = expect(exec_call(bounded, ["/fixture", command], timeout_ms=1000, max_output_bytes=128), 200)
            assert result["interrupted"] and result["error"] == "exec_output_limit" and result["sandbox_state"] == "running", result
            assert len(result["stdout"].encode()) + len(result["stderr"].encode()) <= 128
        assert get(bounded)["state"] == "running" and exec_groups(bounded) == [] and execute(bounded, "counter")
        remove(bounded)
        observations["exec_bound_violation_keeps_sandbox"] = True
        print("PASS configured cgroup limits, namespace separation, seccomp checkpoint guards, TTL and per-command bounds that keep the sandbox")

        # Layer verification runs in the create job: two simultaneous first creates of a new base hash it
        # once. The result is saved with the image's identity in a root-owned 0600 state file.
        probe_bytes = probe_bases["probe"]["bytes"]
        read_before = worker_read_bytes()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            pair = [f.result(timeout=200) for f in [pool.submit(create, "probe"), pool.submit(create, "probe")]]
        first_use_read = worker_read_bytes() - read_before
        assert probe_bytes <= first_use_read < probe_bytes * 3 // 2, (first_use_read, probe_bytes)
        for sandbox in pair:
            remove(sandbox)
        small = create("probe-small")
        remove(small)
        state_file = root / "verified-layers.json"
        state_info = state_file.lstat()
        assert stat.S_ISREG(state_info.st_mode) and state_info.st_uid == 0 and stat.S_IMODE(state_info.st_mode) == 0o600
        saved = {entry["sha256"]: entry for entry in json.loads(state_file.read_text())["layers"]}
        for descriptor in (probe_bases["probe"], probe_bases["probe-small"], manifest["base"], warm_manifest["layers"][0]):
            image = root / "layers" / f"{descriptor['sha256']}.erofs"
            assert saved[descriptor["sha256"]]["bytes"] == descriptor["bytes"] and saved[descriptor["sha256"]]["file"] == file_identity(image), descriptor
        observations["layer_verification"] = dict(first_use_two_creates_read_bytes=first_use_read, probe_bytes=probe_bytes, saved_layers=len(saved))
        pending_thread, _ = in_background(lambda: exec_call(source, ["/fixture", "hang"], timeout_ms=60000, max_output_bytes=1024))
        eventually(lambda: exec_cgroup_populated(source), timeout=10)
        kill_and_restart_worker()
        pending_thread.join(timeout=10)
        assert get(source)["state"] == "deleted"
        gone(source)
        observations["restart_inflight_exec_reconciled"] = True
        if args.network:
            # Restart never adopts old slots: every pooled slot was removed and built fresh.
            rebuilt = slot_identities()
            assert all(rebuilt[i][0] != pool_identities[i][0] and rebuilt[i][1] != pool_identities[i][1] for i in range(3)), (pool_identities, rebuilt)
            for i in range(3):
                slot_reset(f"{owned_prefix}s-{i}")
            observations["restart_rebuilt_slot_pool"] = True
        # After the restart the saved state is trusted while the image keeps its identity (no rehash);
        # a changed identity (here only the change time) means hashing again, and same-size corrupted
        # content is then rejected.
        probe_image = root / "layers" / f"{probe_bases['probe']['sha256']}.erofs"
        read_before = worker_read_bytes()
        trusted = create("probe")
        trusted_read = worker_read_bytes() - read_before
        assert trusted_read < probe_bytes // 2, (trusted_read, probe_bytes)
        remove(trusted)
        probe_image.chmod(0o600)
        read_before = worker_read_bytes()
        rehashed = create("probe")
        rehash_read = worker_read_bytes() - read_before
        assert rehash_read >= probe_bytes, (rehash_read, probe_bytes)
        remove(rehashed)
        # probe-small is not mounted since the restart, so its image can be changed in place safely.
        small_image = root / "layers" / f"{probe_bases['probe-small']['sha256']}.erofs"
        assert not any(line.split()[4] == str(root / "lowers" / probe_bases["probe-small"]["sha256"]) for line in Path("/proc/self/mountinfo").read_text().splitlines())
        with small_image.open("r+b") as image_file:
            image_file.seek(small_image.stat().st_size // 2)
            original = image_file.read(1)
            image_file.seek(-1, os.SEEK_CUR)
            image_file.write(bytes([original[0] ^ 0xFF]))
        code, corrupted = create_call(dict(template_id="probe-small", ttl_seconds=60))
        assert code == 500 and corrupted["error"]["code"] == "artifact_digest_mismatch", (code, corrupted)
        assert get(corrupted["sandbox_id"])["state"] == "failed"
        gone(corrupted["sandbox_id"])
        assert probe_bases["probe-small"]["sha256"] not in {entry["sha256"] for entry in json.loads(state_file.read_text())["layers"]}
        observations["layer_verification"].update(trusted_after_restart_read_bytes=trusted_read, rehash_after_identity_change_read_bytes=rehash_read,
                                                  corrupted_same_size_rejected=True)
        print("PASS layer hashing in the create job (once for two simultaneous creates), saved verified state trusted after restart, "
              "rehash on identity change, corrupted image rejected")
        # Publication survives source/restart cleanup and is still independently restorable.
        retained = create("warm")
        time.sleep(0.3)
        assert int(execute(retained, "counter").split()[1]) == nonce
        # A later restore of this manifest digest, after a worker restart: the node cache is
        # reused, not re-extracted.
        assert checkpoint_cache(root, "warm") == (warm_cache, warm_cache_state)
        observations["checkpoint_cache_reused_after_restart"] = str(warm_cache.name)
        # Crash during a host checkpoint command, not just workload exec.
        (helpers / "cgroup.freeze").write_text("1")
        capture_thread, _ = in_background(lambda: capture(retained, "interrupted-warm"))
        leaves = eventually(lambda: [p for p in helpers.glob("command-*") if "populated 1" in (p / "cgroup.events").read_text()], timeout=10)
        assert len(leaves) == 1
        stage = root / "staging" / "interrupted-warm"
        assert stage.is_dir()
        # A trusted, sleeping stand-in holds a staging FD in the same helper leaf,
        # independently of the worker's parent-death signal/process group. This
        # explicitly tests restart drain of surviving helper descendants/holders.
        held_file = (stage / "held-by-probe").open("wb")
        probe = subprocess.Popen([str(rootfs / "fixture"), "hang"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, pass_fds=(held_file.fileno(),), start_new_session=True, env={})
        processes.append(probe)
        held_file.close()
        (leaves[0] / "cgroup.procs").write_text(str(probe.pid))
        worker.kill()
        worker.wait(timeout=5)
        assert probe.poll() is None
        observations["restart_host_helper"] = {"leaf": leaves[0].name, "surviving_probe_pid": probe.pid, "staging": stage.name}
        worker = start("worker", worker_config)
        assert probe.wait(timeout=5) == -9
        fresh()
        capture_thread.join(timeout=10)
        assert get(retained)["state"] == "deleted"
        gone(retained)
        assert not stage.exists() and not (root / "templates" / "interrupted-warm").exists()
        assert not any(helpers.glob("command-*"))
        observations["restart_host_helper"]["drained_before_ready"] = True
        if args.network:
            # A worker crash during an open proxied exchange: the client gets an error, and the restarted
            # worker deletes the sandbox before it is ready.
            proxy_restart = create("warm")
            # Return the streamed answer, or the transport error that ends it when the worker dies.
            def interrupted_stream():
                try:
                    return proxy_call(proxy_restart, "GET", "/chunked/40/200", timeout=30)
                except (http.client.HTTPException, OSError) as error:
                    return (None, {}, type(error).__name__.encode())
            proxy_thread, proxy_box = in_background(interrupted_stream)
            eventually(lambda: tracked_connections(slot_of(proxy_restart)) > 0, timeout=10)
            time.sleep(0.5)
            kill_and_restart_worker()
            proxy_thread.join(timeout=15)
            assert proxy_box["result"][0] != 200 or not proxy_box["result"][2].endswith(b"part-39\n"), proxy_box
            observations["restart_inflight_proxy_client_saw"] = proxy_box["result"][0] or proxy_box["result"][2].decode()
            assert get(proxy_restart)["state"] == "deleted" and not any(helpers.glob("command-*"))
            gone(proxy_restart)
            observations["restart_inflight_proxy_reconciled"] = True
        print("PASS worker crash during exec/capture/proxy: host-helper drain and cleanup before ready; retained-template restore")
    finally:
        if helpers.exists():
            (helpers / "cgroup.freeze").write_text("0")
        # All cleanup goes through the owner. Never recurse through potentially
        # live mounts, remove shared images, or indiscriminately delete cgroups.
        if worker is not None and worker.poll() is None:
            for sandbox in ids:
                try:
                    request(worker_port, f"/v1/sandboxes/{sandbox}", worker_token, method="DELETE", timeout=150)
                except (OSError, TimeoutError, http.client.HTTPException):
                    pass
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=180)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    raise RuntimeError("shutdown did not finish; retained root requires reconciliation")
        observations["sandbox_ids"] = ids
        (root / "validation.json").write_text(json.dumps(observations, indent=2))
        (root / "validation.json").chmod(0o600)
        print("Retained owned artifacts/records for inspection:", root)
    mountinfo = Path("/proc/self/mountinfo").read_text()
    assert not any(str(root) in line.split()[4] for line in mountinfo.splitlines()), "owned mounts remain"
    assert not any(path.is_dir() for path in cgroup.iterdir()), "owned workload/helper cgroups remain"
    assert all(not (root / "private" / sandbox).exists() for sandbox in ids), "private state remains"
    # Isolated and networked sandboxes alike leave no worker-owned namespace pin; shutdown removes the
    # slot pool.
    assert not any(p.name.startswith(owned_prefix) for p in Path("/run/netns").iterdir()), "owned netns remain"
    if args.network:
        assert not any(p.name.startswith("sb-") and p.name != "sb-test-peer" for p in Path("/run/netns").iterdir()), "owned netns remain"
        assert not any(link["ifname"].startswith("sb") and link["ifname"] not in ("sb-test-br", "sb-pmtu-out") for link in json.loads(subprocess.check_output(["ip", "-j", "link"]))), "owned veth remain"
    for log in root.glob("*.log"):
        assert token.encode() not in log.read_bytes() and worker_token.encode() not in log.read_bytes()
    print("REAL LIFECYCLE SMOKE PASSED on this host only; not a capacity or two-node qualification")


if __name__ == "__main__":
    main()
