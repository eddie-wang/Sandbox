#!/usr/bin/env python3
"""Explicitly privileged, real lifecycle gate. Never runs from the foundation smoke.

Every management call is blocking: create/exec/HTTP/capture/delete responses carry
the real outcome. The controller chooses the owner and returns the sandbox ID.
"""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

import socket
import threading

from smoke import eventually, expect, port, request as smoke_request


# Require explicit privileged opt-in, prepare a tiny local template and launch worker/controller
# services. Exercise cold runs, captures, restores, limits, restart cleanup and optional networking,
# retaining observations. Route cleanup through owners and verify no owned runtime resources or leaked
# tokens remain.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-privileged-runtime", action="store_true")
    parser.add_argument("--network", action="store_true", help="Only inside network_smoke.py disposable outer namespace")
    parser.add_argument("--http-limits", action="store_true", help="Also exercise opt-in large inline text HTTP results")
    parser.add_argument("--binary", default="target/debug/sandboxd")
    parser.add_argument("--root", required=True, help="Existing trusted directory on ext4/XFS/Btrfs; retained for inspection")
    parser.add_argument("--cgroup-parent", required=True, help="Existing empty delegated domain; cpu memory pids already enabled")
    parser.add_argument("--tools-dir", help="Optional existing administrator-staged trusted tool directory")
    args = parser.parse_args()
    def request(*call, timeout=None, **named):
        # Blocking calls wait for real outcomes; the client deadline exceeds the
        # services' route deadlines so their own timeout errors are observable.
        return smoke_request(*call, timeout=timeout or 200, **named)
    if not args.allow_privileged_runtime or os.geteuid() != 0:
        parser.error("requires explicit opt-in and administrator execution on an approved host")
    if args.network and os.environ.get("SANDBOX_TEST_OUTER_NETNS") != os.readlink("/proc/self/ns/net"):
        parser.error("network tests require the disposable outer namespace harness")
    if args.http_limits and not args.network:
        parser.error("large HTTP qualification requires the disposable network harness")
    server_limits = ('''request_timeout_ms = 5000
max_body_bytes = 131072
[server.application_http]
max_body_bytes = 16384
max_response_bytes = 8388608
max_timeout_ms = 600000''' if args.http_limits else 'request_timeout_ms = 5000')
    binary = str(Path(args.binary).resolve())
    parent = Path(args.root).resolve(strict=True)
    cgroup = Path(args.cgroup_parent).resolve(strict=True)
    if not str(cgroup).startswith("/sys/fs/cgroup/"):
        parser.error("cgroup parent must be below /sys/fs/cgroup")
    root = Path(tempfile.mkdtemp(prefix="lifecycle-", dir=parent))
    root.chmod(0o700)
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
{server_limits}
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
    controller_config.write_text(f'''[server]
listen = "127.0.0.1:{controller_port}"
{server_limits}
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
    # Version checks and preflight do not install/load/configure anything.
    report = subprocess.run([binary, "preflight", "--config", str(worker_config)], capture_output=True, timeout=15)
    if report.returncode:
        print(report.stdout.decode(errors="replace"))
        raise RuntimeError("preflight failed; no runtime mutation attempted")
    compatibility = json.loads(report.stdout)["compatibility"]
    rootfs = root / "fixture-rootfs"
    rootfs.mkdir(mode=0o755)
    for name in ("dev", "proc", "workspace"):
        (rootfs / name).mkdir(mode=0o755)
    (rootfs / "workspace").chmod(0o777)
    for name in ("copied", "removed"):
        (rootfs / "workspace" / name).write_text("immutable-base")
        (rootfs / "workspace" / name).chmod(0o666)
    (rootfs / "seed").write_bytes(b"seed\n" + bytes(4091))
    subprocess.run(["cc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", str(Path(__file__).with_name("fixture.c")), "-o", str(rootfs / "fixture")], check=True, timeout=60)
    layer = root / "fixture.erofs"
    subprocess.run(["mkfs.erofs", str(layer), str(rootfs)], check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    digest = hashlib.sha256(layer.read_bytes()).hexdigest()
    (root / "layers").mkdir(mode=0o700)
    layer.rename(root / "layers" / (digest + ".erofs"))
    (root / "templates").mkdir(mode=0o700)
    template = root / "templates" / "fixture"
    template.mkdir(mode=0o700)
    manifest = dict(schema_version=2, template_id="fixture", generation="cold-v1", runtime="runc_criu", compatibility=compatibility,
                    base=dict(sha256=digest, bytes=(root / "layers" / (digest + ".erofs")).stat().st_size), upper=None, checkpoint=None,
                    init_argv=["/fixture", "init-network" if args.network else "init"], memory_mib=64, vcpus=1, pids_max=64, oci_config_sha256=None,
                    network=({"mode":"tcp_allowlist", "egress":[{"ip":"198.18.0.1","port":18080}, {"ip":"198.19.0.2","port":18080}, {"ip":"198.19.0.3","port":18080}], "service_ports":[8080]} if args.network else {"mode": "isolated"}), uid=65534, gid=65534)
    (template / "manifest.json").write_text(json.dumps(manifest))
    (template / "manifest.sha256").write_text(hashlib.sha256((template / "manifest.json").read_bytes()).hexdigest() + "\n")
    for name in ("incompatible", "tampered", "symlinked", "unknown-metadata", "no-defaults") + (("policy-not-authorized", "unsupported-policy", "old-schema") if args.network else ()):
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
            invalid["schema_version"] = 1
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

    def fresh():
        eventually(lambda: expect(request(controller_port, "/v1/status", token, timeout=4), 200)["nodes"][0]["fresh"], timeout=15)

    def get(sandbox):
        return expect(request(controller_port, f"/v1/sandboxes/{sandbox}", token, timeout=4), 200)

    def gone(sandbox):
        assert not (root / "private" / sandbox).exists() and not (cgroup / sandbox).exists() and not (root / "runc" / sandbox).exists()

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

    def exec_call(sandbox, argv, timeout_ms=3000, max_output_bytes=8192):
        return request(controller_port, f"/v1/sandboxes/{sandbox}/exec", token, dict(argv=argv, timeout_ms=timeout_ms, max_output_bytes=max_output_bytes), "POST")

    # Run a bounded fixture command inside the sandbox and return its successful standard output.
    def execute(sandbox, *argv):
        result = expect(exec_call(sandbox, ["/fixture", *argv]), 200)
        assert result["exit_code"] == 0 and not result["interrupted"] and result["error"] is None and result["sandbox_state"] == "running", result
        return result["stdout"]

    def http_call(sandbox, body):
        return request(controller_port, f"/v1/sandboxes/{sandbox}/http", token, body, "POST")

    def capture(sandbox, template_id):
        return request(controller_port, f"/v1/sandboxes/{sandbox}/capture", token, dict(template_id=template_id, runtime="runc_criu"), "POST")

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

    def captured(sandbox, template_id):
        code, result = capture(sandbox, template_id)
        if code != 200:
            diagnostics(sandbox, template_id)
        assert code == 200 and result["state"] == "running" and result["template_id"] == template_id, result
        assert len(result["generation"]) == 32 and (root / "templates" / template_id / "manifest.json").exists()
        return result

    # Request deletion, wait for the deleted state and verify private files and the sandbox resource group
    # are gone.
    def remove(sandbox):
        result = expect(request(controller_port, f"/v1/sandboxes/{sandbox}", token, method="DELETE"), 200)
        assert result["state"] == "deleted"
        gone(sandbox)

    def in_background(call):
        box = {}
        thread = threading.Thread(target=lambda: box.setdefault("result", call()), daemon=True)
        thread.start()
        return thread, box

    def exec_cgroup_populated(sandbox):
        events = cgroup / sandbox / "exec" / "cgroup.events"
        return events.exists() and "populated 1" in events.read_text()

    def disconnect_mid_exec(sandbox, body):
        # Send a complete request, wait until the command is really running, then
        # close the client connection without reading the response.
        data = json.dumps(body).encode()
        with socket.create_connection(("127.0.0.1", controller_port), timeout=4) as raw:
            raw.sendall((f"POST /v1/sandboxes/{sandbox}/exec HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n"
                         f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data)
            eventually(lambda: exec_cgroup_populated(sandbox), timeout=10)

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
        # Omitted resources come from the cold template defaults (64 MiB, 1 vCPU).
        source = create()
        assert (cgroup / source / "memory.max").read_text().strip() == "67108864"
        assert int(execute(source, "process-group")) >= 0
        observations["read_only_process_group_query"] = True
        isolated = create(memory_mib=64, vcpus=1)
        observations["create_explicit_and_template_default_resources"] = True
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(execute, source, "delay")
            second = pool.submit(execute, isolated, "delay")
            eventually(lambda: exec_cgroup_populated(source), timeout=10)
            started = time.monotonic()
            expect(exec_call(source, ["/fixture", "counter"]), 409, "sandbox_busy")
            expect(capture(source, "busy-capture"), 409, "sandbox_busy")
            assert time.monotonic() - started < 2, "conflicting same-sandbox request waited instead of failing fast"
            begin_a, end_a = map(int, first.result(timeout=15).split())
            begin_b, end_b = map(int, second.result(timeout=15).split())
        assert max(begin_a, begin_b) < min(end_a, end_b), "independent workloads were serialized"
        assert not (root / "templates" / "busy-capture").exists()
        observations["overlapping_exec_monotonic_ns"] = [[begin_a, end_a], [begin_b, end_b]]
        observations["same_sandbox_conflict_rejected_immediately"] = True
        execute(source, "orphan")
        assert not any(path.is_dir() for path in (cgroup / source).iterdir()), "exec descendants/cgroup survived successful command"
        print("PASS blocking cold create, inline exec results, overlapping independent commands and immediate same-sandbox 409")

        before_dirs = {name: sorted(p.name for p in (root / name).iterdir()) for name in ("private", "runc")}
        rejected_templates = ["incompatible", "symlinked", "unknown-metadata"] + (["policy-not-authorized", "unsupported-policy", "old-schema"] if args.network else [])
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
        if args.network:
            guest = Path(json.loads((root / "private" / third / "config.json").read_text())["linux"]["namespaces"][2]["path"])
            # A test-owned namespace FD deliberately delays kernel link destruction.
            # The blocking DELETE reports cleanup_failed; reservations survive and retry.
            with open(guest.with_name(guest.name.replace("-g-", "-s-")), "rb"):
                expect(request(controller_port, f"/v1/sandboxes/{third}", token, method="DELETE"), 500, "cleanup_failed")
                assert get(third)["state"] == "cleanup_failed" and (root / "private" / third / "network-owned").exists()
            eventually(lambda: get(third)["state"] == "deleted", timeout=15)
            remove(third)
            observations["network_cleanup_retry_after_namespace_fd_release"] = True
        else:
            remove(third)
        print("PASS template rejection without IDs, failed-launch tombstone, final worker admission without a record and inline delete")

        # A client that disconnects mid-exec leaves no orphan: the command still runs
        # to completion with normal exec-cgroup cleanup, then the sandbox is free again.
        disconnect_mid_exec(source, dict(argv=["/fixture", "delay"], timeout_ms=5000, max_output_bytes=1024))
        eventually(lambda: not (cgroup / source / "exec").exists(), timeout=15)
        # The finished job releases the sandbox shortly after its exec cgroup is gone.
        eventually(lambda: exec_call(source, ["/fixture", "counter"])[0] == 200, timeout=10)
        # A disconnected bound-violating exec still terminates and cleans its sandbox.
        doomed = create()
        disconnect_mid_exec(doomed, dict(argv=["/fixture", "hang"], timeout_ms=1500, max_output_bytes=1024))
        eventually(lambda: get(doomed)["state"] == "deleted", timeout=30)
        gone(doomed)
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
        # DELETE cancels an in-flight exec of the same sandbox and returns after cleanup.
        cancelled = create()
        thread, box = in_background(lambda: exec_call(cancelled, ["/fixture", "hang"], timeout_ms=30000))
        eventually(lambda: exec_cgroup_populated(cancelled), timeout=10)
        started = time.monotonic()
        remove(cancelled)
        assert time.monotonic() - started < 20
        thread.join(timeout=30)
        code, result = box["result"]
        assert code != 200 or result["sandbox_state"] != "running", result
        observations["delete_cancels_inflight_exec"] = {"delete_seconds": round(time.monotonic() - started, 3), "exec_status": code}
        print("PASS client disconnect mid-exec (completion and bound-kill) and mid-create, and DELETE cancellation, leave no orphan")

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
        # Inspect owned network state and exercise allowed/denied TCP, path-MTU discovery and application
        # HTTP. Optionally check malformed and bounded HTTP failures while requiring the sandbox to remain
        # running.
        def network_gate(sandbox, full=False):
            config_json = json.loads((root / "private" / sandbox / "config.json").read_text())
            guest = Path(config_json["linux"]["namespaces"][2]["path"]).name
            slot = guest.replace("-g-", "-s-")
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
            body = dict(port=8080, method="POST", path="/headers?test=1", headers={"content-type":"text/plain"}, body="request-text", timeout_ms=2000, max_response_bytes=4096)
            result = expect(http_call(sandbox, body), 200)
            assert result["status"] == 200 and "request-text" in result["body"]
            assert "authorization:" not in result["body"].lower() and token not in result["body"] and worker_token not in result["body"]
            if full:
                expect(request(controller_port, f"/v1/sandboxes/{sandbox}/http", body=body, method="POST"), 401, "unauthorized")
                for changes in [dict(path="http://198.18.0.1/"), dict(path="//198.18.0.1/"), dict(headers={"authorization":"secret"}), dict(body="x"*(16385 if args.http_limits else 8193)), dict(max_response_bytes=8388609 if args.http_limits else 65537), dict(operation_id="removed")]:
                    expect(http_call(sandbox, dict(body, **changes)), 400, "invalid_input")
                expect(http_call(sandbox, dict(body, port=8081)), 403, "service_port_not_authorized")
                assert expect(http_call(sandbox, dict(body, path="/redirect")), 200)["status"] == 302
                for changes in [dict(path="/slow", timeout_ms=50), dict(path="/large", max_response_bytes=128), dict(path="/binary"), dict(path="/headers-large")]:
                    expect(http_call(sandbox, dict(body, **changes)), 502, "application_http_failed_or_bounded")
                assert get(sandbox)["state"] == "running"
            return True
        if args.network:
            observations["network_and_http_before_capture"] = network_gate(source, True)
            held = create()
            execute(held, "write", "hold-external", "1")
            time.sleep(0.3)
            assert execute(held, "read", "holding") == "ready"
            expect(capture(held, "held-invalid"), 409, "capture_requires_quiescent_tcp")
            assert get(held)["state"] == "running"
            observations["established_connection_capture_rejected"] = True
            remove(held)
            # Close fixture connections before capture; remote TCP state is not cloned.
            time.sleep(1)
        before, nonce = map(int, execute(source, "counter").split())
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
        isolated_nonce = int(execute(isolated, "counter").split()[1])
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
        assert not any(p.exists() for p in stages)
        current, source_nonce = map(int, execute(source, "counter").split())
        assert source_nonce == nonce and current >= before
        remove(isolated)
        expect(create_call(dict(template_id="warm", ttl_seconds=60, memory_mib=128)), 422, "template_resource_mismatch")
        child = create("warm")
        time.sleep(0.3)
        restored, child_nonce = map(int, execute(child, "counter").split())
        assert child_nonce == nonce and restored >= before
        observations["warm_state"] = {"before_counter":before,"source_counter":current,"child_counter":restored,"source_nonce":source_nonce,"child_nonce":child_nonce}
        assert execute(child, "read", "copied") == "source-private"
        missing = expect(exec_call(child, ["/fixture", "read", "removed"], timeout_ms=2000, max_output_bytes=1024), 200)
        assert missing["exit_code"] != 0 and not missing["interrupted"] and missing["sandbox_state"] == "running"
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
        print("PASS inline capture after publication and source recovery, warm restore with template resources, independent child")
        remove(child)
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
        result = expect(exec_call(bounded, ["/fixture", "hang"], timeout_ms=100, max_output_bytes=1024), 200)
        assert result["interrupted"] and result["error"] == "exec_deadline_or_output_limit" and result["sandbox_state"] == "deleted"
        assert get(bounded)["state"] == "deleted"
        gone(bounded)
        for command in ("flood", "flood-both"):
            flooding = create()
            result = expect(exec_call(flooding, ["/fixture", command], timeout_ms=1000, max_output_bytes=128), 200)
            assert result["interrupted"] and result["error"] == "exec_deadline_or_output_limit" and result["sandbox_state"] == "deleted"
            assert len(result["stdout"].encode()) + len(result["stderr"].encode()) <= 128
            gone(flooding)
        print("PASS configured cgroup limits, namespace separation, seccomp checkpoint guards, TTL and inline bounded exec teardown")

        pending_thread, _ = in_background(lambda: exec_call(source, ["/fixture", "hang"], timeout_ms=60000, max_output_bytes=1024))
        eventually(lambda: exec_cgroup_populated(source), timeout=10)
        kill_and_restart_worker()
        pending_thread.join(timeout=10)
        assert get(source)["state"] == "deleted"
        gone(source)
        observations["restart_inflight_exec_reconciled"] = True
        # Publication survives source/restart cleanup and is still independently restorable.
        retained = create("warm")
        time.sleep(0.3)
        assert int(execute(retained, "counter").split()[1]) == nonce
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
            http_restart = create("warm")
            (helpers / "cgroup.freeze").write_text("1")
            http_thread, _ = in_background(lambda: http_call(http_restart, dict(port=8080, method="GET", path="/", timeout_ms=30000, max_response_bytes=4096)))
            eventually(lambda: any("populated 1" in p.read_text() for p in helpers.glob("command-*/cgroup.events")), timeout=10)
            kill_and_restart_worker()
            http_thread.join(timeout=10)
            assert get(http_restart)["state"] == "deleted" and not any(helpers.glob("command-*"))
            gone(http_restart)
            observations["restart_http_helper_reconciled"] = True
        print("PASS worker crash during exec/capture/HTTP: host-helper drain and cleanup before ready; retained-template restore")
        if args.http_limits:
            plain = create(ttl=180)
            escaped = create(ttl=180)
            large = dict(port=8080, method="GET", path="/sized/8388608/120", timeout_ms=10000, max_response_bytes=8388608)
            assert expect(http_call(plain, large), 200)["body"] == "x"*8388608
            result = expect(http_call(plain, dict(large, method="POST", path="/body-size", body="\u0000"*16384, max_response_bytes=128)), 200)
            assert result["body"] == "body_bytes=16384", "escaped request envelope or body was truncated"
            expect(http_call(plain, dict(large, path="/sized/8388609/120")), 502, "application_http_failed_or_bounded")
            expect(http_call(plain, dict(large, timeout_ms=600001)), 400, "invalid_input")
            # Two worst-case escaped results in different sandboxes are carried inline concurrently.
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda sandbox: expect(http_call(sandbox, dict(large, path="/sized/8388608/0")), 200), (plain, escaped)))
            assert all(r["body"] == "\u0000"*8388608 for r in results)
            # A deadline beyond request_timeout_ms (5 s) is covered by the route deadline.
            started = time.monotonic()
            long_call = expect(http_call(plain, dict(large, path="/delay/31000", timeout_ms=35000, max_response_bytes=4096)), 200)
            assert long_call["status"] == 200 and time.monotonic() - started >= 31
            remove(plain)
            remove(escaped)
            expiring_http = create(ttl=3)
            started = time.monotonic()
            code, _ = http_call(expiring_http, dict(large, path="/delay/31000", timeout_ms=600000, max_response_bytes=128))
            assert code in (500, 502) and time.monotonic() - started < 10, "HTTP deadline was not clamped to TTL"
            observations["opt_in_http_limits"] = {"raw_response_bytes": 8388608, "escaped_inline_concurrent": True,
                                                   "request_body_bytes": 16384, "long_deadline_seconds": 31, "ttl_clamped": True}
            print("PASS opt-in inline HTTP raw/escaped bounds, concurrent worst-case results, long deadline and TTL clamp")
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
    if args.network:
        assert not any(p.name.startswith("sb-") and p.name != "sb-test-peer" for p in Path("/run/netns").iterdir()), "owned netns remain"
        assert not any(link["ifname"].startswith("sb") and link["ifname"] not in ("sb-test-br", "sb-pmtu-out") for link in json.loads(subprocess.check_output(["ip", "-j", "link"]))), "owned veth remain"
    for log in root.glob("*.log"):
        assert token.encode() not in log.read_bytes() and worker_token.encode() not in log.read_bytes()
    print("REAL LIFECYCLE SMOKE PASSED on this host only; not a capacity or two-node qualification")


if __name__ == "__main__":
    main()
