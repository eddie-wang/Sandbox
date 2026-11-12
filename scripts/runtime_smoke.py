#!/usr/bin/env python3
"""Explicitly privileged, real lifecycle gate. Never runs from the foundation smoke."""
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

from smoke import eventually, expect, port, request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-privileged-runtime", action="store_true")
    parser.add_argument("--network", action="store_true", help="Only inside network_smoke.py disposable outer namespace")
    parser.add_argument("--binary", default="target/debug/sandboxd")
    parser.add_argument("--root", required=True, help="Existing trusted directory on ext4/XFS/Btrfs; retained for inspection")
    parser.add_argument("--cgroup-parent", required=True, help="Existing empty delegated domain; cpu memory pids already enabled")
    parser.add_argument("--tools-dir", help="Optional existing administrator-staged trusted tool directory")
    args = parser.parse_args()
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
max_records = 32
max_operations_per_sandbox = 64
max_concurrent_operations = 4
max_retained_output_bytes = 16777216
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
egress = [{ip="198.18.0.1", port=18080}]
service_ports = [8080]
''')
    controller_config = root / "controller.toml"
    controller_config.write_text(f'''[server]
listen = "127.0.0.1:{controller_port}"
request_timeout_ms = 5000
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
                    init_argv=["/fixture", "init-network" if args.network else "init"], memory_mib=None, vcpus=None, pids_max=64, oci_config_sha256=None,
                    network=({"mode":"tcp_allowlist", "egress":[{"ip":"198.18.0.1","port":18080}], "service_ports":[8080]} if args.network else {"mode": "isolated"}), uid=65534, gid=65534)
    (template / "manifest.json").write_text(json.dumps(manifest))
    (template / "manifest.sha256").write_text(hashlib.sha256((template / "manifest.json").read_bytes()).hexdigest() + "\n")
    for name in ("incompatible", "tampered", "symlinked", "unknown-metadata"):
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

    def start(role, config):
        log = root / f"{role}-{len(processes)}.log"
        with log.open("wb") as output:
            proc = subprocess.Popen([binary, role, "--config", str(config)], env=env, stdout=output, stderr=subprocess.STDOUT)
        processes.append(proc)
        eventually(lambda: request(worker_port if role == "worker" else controller_port, "/healthz")[0] == 200, timeout=15)
        return proc

    def get(sandbox):
        return expect(request(controller_port, f"/v1/sandboxes/{sandbox}", token), 200)

    def state(sandbox, expected, timeout=120):
        def check():
            result = get(sandbox)
            if result["state"] in ("failed", "cleanup_failed"):
                raise RuntimeError("lifecycle failure: " + str(result["error"]))
            return result if result["state"] == expected else None
        return eventually(check, timeout=timeout)

    def create(name, template_id="fixture", ttl=120):
        sandbox = "node-smoke." + name
        ids.append(sandbox)
        body = dict(sandbox_id=sandbox, template_id=template_id, runtime="runc_criu", architecture=compatibility["architecture"], memory_mib=64, vcpus=1, ttl_seconds=ttl)
        def accepted():
            code, payload = request(controller_port, "/v1/sandboxes", token, body, "POST")
            if code in (408, 503):
                # Capacity/restore observations can lag; an earlier response may
                # also have been lost. Preserve the caller-selected owner/id.
                existing, _ = request(controller_port, f"/v1/sandboxes/{sandbox}", token)
                return existing == 200
            expect((code, payload), 202)
            return True
        eventually(accepted, timeout=30)
        state(sandbox, "running")
        # Identical create is idempotent; conflicting reuse must not create again.
        expect(request(worker_port, "/v1/sandboxes", worker_token, body, "POST"), 202)
        expect(request(worker_port, "/v1/sandboxes", worker_token, dict(body, ttl_seconds=ttl + 1), "POST"), 409, "idempotency_conflict")
        return sandbox

    def op(sandbox, kind, body, allow_failure=False, operation=None):
        operation = operation or secrets.token_hex(8)
        body = dict(body, operation_id=operation)
        # A transport timeout may have already accepted the known ID. Retry the
        # identical request only; never generate a new operation ID on retry.
        def accepted():
            code, payload = request(controller_port, f"/v1/sandboxes/{sandbox}/{kind}", token, body, "POST")
            if code in (408, 503):
                return False
            expect((code, payload), 202)
            return True
        eventually(accepted, timeout=120)
        def complete():
            code, result = request(controller_port, f"/v1/sandboxes/{sandbox}/operations/{operation}", token)
            if code in (404, 503):
                return None
            expect((code, result), 200)
            return result if result["state"] != "pending" else None
        result = eventually(complete, timeout=180)
        if not allow_failure:
            if kind == "capture" and result["state"] != "complete":
                # The known generic fixture has no workload credentials. Retain
                # bounded, private CRIU diagnostics before finally cleans it up.
                diagnostics = root / "diagnostics"
                diagnostics.mkdir(mode=0o700, exist_ok=True)
                for logfile in (root / "private" / sandbox / "criu-work").glob("*.log"):
                    with logfile.open("rb") as source:
                        data = source.read(65536)
                    target = diagnostics / (operation + "-" + logfile.name)
                    target.write_bytes(data)
                    target.chmod(0o600)
            assert result["state"] == "complete", "operation failed: " + str(result["error"])
            if kind == "exec":
                assert result["output"]["exit_code"] == 0 and not result["output"]["interrupted"]
        # Completed operation replays, rather than re-executing.
        expect(request(worker_port, f"/v1/sandboxes/{sandbox}/{kind}", worker_token, body, "POST"), 202)
        return result

    def execute(sandbox, *argv):
        return op(sandbox, "exec", dict(argv=["/fixture", *argv], timeout_ms=2000, max_output_bytes=8192))["output"]["stdout"]

    def remove(sandbox):
        expect(request(controller_port, f"/v1/sandboxes/{sandbox}", token, method="DELETE"), 202)
        state(sandbox, "deleted")
        assert not (root / "private" / sandbox).exists()
        assert not (cgroup / sandbox).exists()

    try:
        worker = start("worker", worker_config)
        controller = start("controller", controller_config)
        eventually(lambda: expect(request(controller_port, "/v1/status", token), 200)["nodes"][0]["fresh"], timeout=15)
        source = create("source")
        isolated = create("source-part")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(execute, source, "delay")
            second = pool.submit(execute, isolated, "delay")
            eventually(lambda: any(o["state"] == "pending" for o in get(source)["operations"]))
            busy = dict(operation_id="same-sandbox-busy", argv=["/fixture", "counter"], timeout_ms=1000, max_output_bytes=1024)
            expect(request(worker_port, f"/v1/sandboxes/{source}/exec", worker_token, busy, "POST"), 503, "busy")
            begin_a, end_a = map(int, first.result(timeout=15).split())
            begin_b, end_b = map(int, second.result(timeout=15).split())
        assert max(begin_a, begin_b) < min(end_a, end_b), "independent workloads were serialized"
        observations["overlapping_exec_monotonic_ns"] = [[begin_a, end_a], [begin_b, end_b]]
        observations["same_sandbox_exclusion"] = True
        execute(source, "orphan")
        assert not any(path.is_dir() for path in (cgroup / source).iterdir()), "exec descendants/cgroup survived successful command"
        for invalid_template, error in (("incompatible", "incompatible_template"), ("tampered", "artifact_digest_mismatch"), ("symlinked", "artifact_unavailable"), ("unknown-metadata", "invalid_record")):
            invalid_id = "node-smoke." + invalid_template
            ids.append(invalid_id)
            invalid_request = dict(sandbox_id=invalid_id, template_id=invalid_template, runtime="runc_criu", architecture=compatibility["architecture"], memory_mib=64, vcpus=1, ttl_seconds=120)
            expect(request(worker_port, "/v1/sandboxes", worker_token, invalid_request, "POST"), 202)
            invalid = eventually(lambda: get(invalid_id) if get(invalid_id)["state"] == "failed" else None)
            assert invalid["error"] == error and not (cgroup / invalid_id).exists() and not (root / "private" / invalid_id).exists()
        observations["template_compatibility_digest_symlink_rejection"] = True
        third = create("slot-three")
        rejected = "node-smoke.over-budget"
        ids.append(rejected)
        body = dict(sandbox_id=rejected, template_id="fixture", runtime="runc_criu", architecture=compatibility["architecture"], memory_mib=64, vcpus=1, ttl_seconds=120)
        expect(request(worker_port, "/v1/sandboxes", worker_token, body, "POST"), 202)
        denied = eventually(lambda: get(rejected) if get(rejected)["state"] == "failed" else None)
        assert denied["error"] == "admission_exhausted" and not (cgroup / rejected).exists()
        remove(third)
        disconnected = dict(operation_id="disconnected-response", argv=["/fixture", "write", "marker", "once"], timeout_ms=2000, max_output_bytes=1024)
        connection = http.client.HTTPConnection("127.0.0.1", worker_port, timeout=4)
        connection.request("POST", f"/v1/sandboxes/{source}/exec", body=json.dumps(disconnected), headers={"Authorization":"Bearer " + worker_token,"Content-Type":"application/json"})
        connection.close()
        def disconnected_completed():
            code, result = request(worker_port, f"/v1/sandboxes/{source}/operations/disconnected-response", worker_token)
            if code == 404:
                expect(request(worker_port, f"/v1/sandboxes/{source}/exec", worker_token, disconnected, "POST"), 202)
                return False
            return result.get("state") == "complete"
        eventually(disconnected_completed)
        execute(source, "write", "marker", "changed")
        expect(request(worker_port, f"/v1/sandboxes/{source}/exec", worker_token, disconnected, "POST"), 202)
        assert execute(source, "read", "marker") == "changed", "ambiguous-response retry executed twice"
        observations["disconnected_response_idempotent"] = True
        observations["successful_exec_descendants_cleaned"] = True
        print("PASS overlapping independent commands, per-sandbox exclusion, exec descendant cleanup, disconnected-response replay and final worker admission")
        execute(source, "write", "copied", "source-private")
        execute(source, "unlink", "removed")
        assert execute(isolated, "read", "copied") == "immutable-base"
        assert execute(isolated, "read", "removed") == "immutable-base"
        status = execute(source, "network-isolation" if args.network else "isolation")
        assert "CapEff:\t0000000000000000" in status and "NoNewPrivs:\t1" in status and "Seccomp:\t2" in status
        assert (cgroup / source / "memory.max").read_text().strip() == "67108864"
        assert (cgroup / source / "memory.swap.max").read_text().strip() == "0"
        assert (cgroup / source / "cpu.max").read_text().strip() == "100000 100000"
        assert (cgroup / source / "pids.max").read_text().strip() == "64"
        # Namespace identities are independently owned, not a shared warm netns.
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
        def network_gate(sandbox, full=False):
            assert "connected=1" in execute(sandbox, "connect", "198.18.0.1", "18080", "1")
            for ip, port_number in [("198.18.0.1", "18081"), ("198.18.0.2", "18080"), ("198.18.0.11", "8080")]:
                assert "connected=0" in execute(sandbox, "connect", ip, port_number, "0")
            body = dict(port=8080, method="POST", path="/headers?test=1", headers={"content-type":"text/plain"}, body="request-text", timeout_ms=2000, max_response_bytes=4096)
            result = op(sandbox, "http", body)["http_output"]
            assert result["status"] == 200 and "request-text" in result["body"]
            assert "authorization:" not in result["body"].lower() and token not in result["body"] and worker_token not in result["body"]
            if full:
                expect(request(controller_port, f"/v1/sandboxes/{sandbox}/http", body=dict(body, operation_id="unauth"), method="POST"), 401, "unauthorized")
                for changes in [dict(path="http://198.18.0.1/"), dict(path="//198.18.0.1/"), dict(headers={"authorization":"secret"}), dict(body="x"*8193), dict(max_response_bytes=65537)]:
                    expect(request(controller_port, f"/v1/sandboxes/{sandbox}/http", token, dict(body, operation_id="invalid", **changes), "POST"), 400, "invalid_input")
                assert op(sandbox, "http", dict(body, port=8081), allow_failure=True)["error"] == "service_port_not_authorized"
                assert op(sandbox, "http", dict(body, path="/redirect"))["http_output"]["status"] == 302
                for changes in [dict(path="/slow", timeout_ms=50), dict(path="/large", max_response_bytes=128)]:
                    assert op(sandbox, "http", dict(body, **changes), allow_failure=True)["state"] == "failed"
                assert get(sandbox)["state"] == "running"
            return True
        if args.network:
            observations["network_and_http_before_capture"] = network_gate(source, True)
            # Close fixture connections before capture; remote TCP state is not cloned.
            time.sleep(1)
        before, nonce = map(int, execute(source, "counter").split())
        rejected_capture = op(source, "capture", dict(template_id="fixture", runtime="runc_criu"), allow_failure=True)
        assert rejected_capture["error"] == "template_already_exists" and get(source)["state"] == "running"
        # A capture must neither adopt nor clean an existing unacquired staging leaf.
        conflict = root / "staging" / f"{len(source)}-{source}-existing"
        conflict.mkdir(mode=0o700)
        (conflict / "sentinel").write_text("owned-by-test")
        failed = op(source, "capture", dict(template_id="not-published", runtime="runc_criu"), allow_failure=True, operation="existing")
        assert failed["error"] == "directory_create_failed"
        assert (conflict / "sentinel").read_text() == "owned-by-test" and get(source)["state"] == "running"
        (conflict / "sentinel").unlink()
        conflict.rmdir()
        observations["unacquired_staging_preserved"] = True
        isolated_nonce = int(execute(isolated, "counter").split()[1])
        # These two valid pairs formerly had the same hyphen-concatenated basename.
        # Freeze only the owned helper subtree to make concurrent staging observable.
        (helpers / "cgroup.freeze").write_text("1")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(op, source, "capture", dict(template_id="warm", runtime="runc_criu"), operation="part-snapshot")
            second = pool.submit(op, isolated, "capture", dict(template_id="isolated-warm", runtime="runc_criu"), operation="snapshot")
            try:
                stages = [root / "staging" / f"{len(source)}-{source}-part-snapshot", root / "staging" / f"{len(isolated)}-{isolated}-snapshot"]
                eventually(lambda: all(p.is_dir() for p in stages) and sum("populated 1" in p.read_text() for p in helpers.glob("command-*/cgroup.events")) == 2, timeout=10)
                assert len(set(stages)) == 2
                observations["concurrent_capture_staging"] = [p.name for p in stages]
            finally:
                (helpers / "cgroup.freeze").write_text("0")
            first.result(timeout=120)
            second.result(timeout=120)
        assert not any(p.exists() for p in stages)
        current, source_nonce = map(int, execute(source, "counter").split())
        assert source_nonce == nonce and current >= before
        remove(isolated)
        child = create("child", "warm")
        time.sleep(0.3)
        restored, child_nonce = map(int, execute(child, "counter").split())
        assert child_nonce == nonce and restored >= before
        observations["warm_state"] = {"before_counter":before,"source_counter":current,"child_counter":restored,"source_nonce":source_nonce,"child_nonce":child_nonce}
        assert execute(child, "read", "copied") == "source-private"
        missing = op(child, "exec", dict(argv=["/fixture", "read", "removed"], timeout_ms=2000, max_output_bytes=1024), allow_failure=True)
        assert missing["output"]["exit_code"] != 0
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
        print("PASS cold create, private writes/whiteouts, retained open files/mappings, warm memory nonce, independent restore and source recovery")
        remove(child)
        other_child = create("other-child", "isolated-warm")
        assert int(execute(other_child, "counter").split()[1]) == isolated_nonce
        assert execute(other_child, "read", "copied") == "immutable-base"
        remove(other_child)
        observations["independent_concurrent_capture_restores"] = True
        expiring = create("expiring", ttl=2)
        state(expiring, "deleted", timeout=15)
        assert not (cgroup / expiring).exists()
        bounded = create("bounded")
        result = op(bounded, "exec", dict(argv=["/fixture", "hang"], timeout_ms=100, max_output_bytes=1024), allow_failure=True)
        assert result["error"] == "exec_deadline_or_output_limit"
        state(bounded, "deleted")
        flooding = create("flooding")
        result = op(flooding, "exec", dict(argv=["/fixture", "flood"], timeout_ms=1000, max_output_bytes=128), allow_failure=True)
        assert result["error"] == "exec_deadline_or_output_limit"
        assert len(result["output"]["stdout"].encode()) + len(result["output"]["stderr"].encode()) <= 128
        state(flooding, "deleted")
        print("PASS configured cgroup limits, namespace separation, deny-all profile, TTL and bounded exec teardown")
        pending = dict(operation_id="restart-pending", argv=["/fixture", "hang"], timeout_ms=60000, max_output_bytes=1024)
        expect(request(worker_port, f"/v1/sandboxes/{source}/exec", worker_token, pending, "POST"), 202)
        pending_group = cgroup / source / "exec-restart-pending" / "cgroup.events"
        eventually(lambda: pending_group.exists() and "populated 1" in pending_group.read_text(), timeout=10)
        worker.kill()
        worker.wait(timeout=5)
        worker = start("worker", worker_config)
        eventually(lambda: expect(request(controller_port, "/v1/status", token), 200)["nodes"][0]["fresh"], timeout=15)
        state(source, "deleted")
        interrupted = expect(request(controller_port, f"/v1/sandboxes/{source}/operations/restart-pending", token), 200)
        assert interrupted["state"] == "failed" and interrupted["error"] == "worker_restarted"
        observations["restart_pending_exec_reconciled"] = True
        assert not (root / "private" / source).exists() and not (cgroup / source).exists()
        # Publication survives source/restart cleanup and is still independently restorable.
        retained = create("retained", "warm")
        time.sleep(0.3)
        assert int(execute(retained, "counter").split()[1]) == nonce
        # Crash during an accepted host checkpoint command, not just workload exec.
        (helpers / "cgroup.freeze").write_text("1")
        capture = dict(operation_id="restart-capture", template_id="interrupted-warm", runtime="runc_criu")
        expect(request(worker_port, f"/v1/sandboxes/{retained}/capture", worker_token, capture, "POST"), 202)
        leaves = eventually(lambda: [p for p in helpers.glob("command-*") if "populated 1" in (p / "cgroup.events").read_text()], timeout=10)
        assert len(leaves) == 1
        stage = root / "staging" / f"{len(retained)}-{retained}-restart-capture"
        assert stage.is_dir()
        # A trusted, sleeping stand-in holds a staging FD in the same helper leaf,
        # independently of the worker's parent-death signal/process group. This
        # explicitly tests restart drain of surviving helper descendants/holders.
        held = (stage / "held-by-probe").open("wb")
        probe = subprocess.Popen([str(rootfs / "fixture"), "hang"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, pass_fds=(held.fileno(),), start_new_session=True, env={})
        processes.append(probe)
        held.close()
        (leaves[0] / "cgroup.procs").write_text(str(probe.pid))
        worker.kill()
        worker.wait(timeout=5)
        assert probe.poll() is None
        observations["restart_host_helper"] = {"leaf": leaves[0].name, "surviving_probe_pid": probe.pid, "staging": stage.name}
        worker = start("worker", worker_config)
        assert probe.wait(timeout=5) == -9
        eventually(lambda: expect(request(controller_port, "/v1/status", token), 200)["nodes"][0]["fresh"], timeout=15)
        state(retained, "deleted")
        interrupted = expect(request(worker_port, f"/v1/sandboxes/{retained}/operations/restart-capture", worker_token), 200)
        assert interrupted["state"] == "failed" and interrupted["error"] == "worker_restarted"
        assert not stage.exists() and not (root / "templates" / "interrupted-warm").exists()
        assert not any(helpers.glob("command-*"))
        observations["restart_host_helper"]["drained_before_ready"] = True
        print("PASS concurrent capture ownership, worker crash/host-helper drain and retained-template restore")
    finally:
        if helpers.exists():
            (helpers / "cgroup.freeze").write_text("0")
        # All cleanup goes through the owner. Never recurse through potentially
        # live mounts, remove shared images, or indiscriminately delete cgroups.
        if worker is not None and worker.poll() is None:
            for sandbox in ids:
                try:
                    request(worker_port, f"/v1/sandboxes/{sandbox}", worker_token, method="DELETE")
                except (OSError, TimeoutError):
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
        assert not any(p.name.startswith(("sb-g-", "sb-s-")) for p in Path("/run/netns").iterdir()), "owned netns remain"
        assert not any(p.name.startswith("sb") and p.name != "sb-test-br" for p in Path("/sys/class/net").iterdir()), "owned veth remain"
    for log in root.glob("*.log"):
        assert token.encode() not in log.read_bytes() and worker_token.encode() not in log.read_bytes()
    print("REAL LIFECYCLE SMOKE PASSED on this host only; not a capacity or two-node qualification")


if __name__ == "__main__":
    main()
