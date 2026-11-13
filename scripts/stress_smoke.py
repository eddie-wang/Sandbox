#!/usr/bin/env python3
"""Explicitly privileged local concurrency stress gate. Never runs from the foundation smoke.

Through a real controller and worker, with the tiny fixture (isolated network policy, 64 MiB and
one vCPU per sandbox): 16 concurrent cold creates, one capture, 16 concurrent warm restores, then 16
cold creates and 16 warm restores at the same time (32 concurrent creates, so 32 guest network
namespaces are made at once); every batch ends with concurrent deletes. Every create and delete
must succeed on its first attempt, with no error. This is a local burst check on one host, not a
capacity, performance or two-node qualification.
"""
import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import secrets
import statistics
import subprocess
import tempfile
import time

from runtime_smoke import cold_manifest, preflight_compatibility, publish_layer, write_template
from smoke import eventually, expect, port, request as smoke_request

BATCH = 16
# The capture source plus the largest batch (16 cold and 16 warm at once) fit with room to spare.
MAX_SANDBOXES = 2 * BATCH + 4
MEMORY_MIB = 64


# Set up a fresh root, worker and controller, run the create/restore/delete bursts, and require zero
# errors, no owned mounts, cgroups or namespace pins afterwards and no credentials in the logs.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-privileged-runtime", action="store_true")
    parser.add_argument("--binary", default="target/release/sandboxd")
    parser.add_argument("--root", required=True, help="Existing trusted directory on ext4/XFS/Btrfs; retained for inspection")
    parser.add_argument("--cgroup-parent", required=True, help="Existing empty delegated domain; cpu memory pids already enabled")
    parser.add_argument("--tools-dir", help="Optional existing administrator-staged trusted tool directory")
    args = parser.parse_args()
    if not args.allow_privileged_runtime or os.geteuid() != 0:
        parser.error("requires explicit opt-in and administrator execution on an approved host")

    # Send a management request with a client deadline above the services' own route deadlines.
    def request(*call, timeout=None, **named):
        return smoke_request(*call, timeout=timeout or 200, **named)

    binary = str(Path(args.binary).resolve())
    parent = Path(args.root).resolve(strict=True)
    cgroup = Path(args.cgroup_parent).resolve(strict=True)
    if not str(cgroup).startswith("/sys/fs/cgroup/"):
        parser.error("cgroup parent must be below /sys/fs/cgroup")
    root = Path(tempfile.mkdtemp(prefix="stress-", dir=parent))
    root.chmod(0o700)
    owned_prefix = "sb-" + hashlib.sha256(str(root).encode()).hexdigest()[:16] + "-"
    worker_port, controller_port = port(), port()
    assert worker_port != controller_port
    token, worker_token = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
    env = dict(os.environ, SANDBOX_CONTROLLER_TOKEN=token, SANDBOX_WORKER_TOKEN=worker_token)
    worker_config = root / "worker.toml"
    worker_config.write_text(f'''node_id = "node-stress"
runtimes = ["runc_criu"]
[server]
listen = "127.0.0.1:{worker_port}"
max_in_flight = 256
request_timeout_ms = 5000
[auth]
env = "SANDBOX_WORKER_TOKEN"
[capacity]
memory_mib = {MAX_SANDBOXES * MEMORY_MIB}
vcpus = 4
max_sandboxes = {MAX_SANDBOXES}
max_concurrent_restores = {MAX_SANDBOXES}
[native]
enabled = true
root = {json.dumps(str(root))}
cgroup_parent = {json.dumps(str(cgroup))}
{('tools_dir = ' + json.dumps(str(Path(args.tools_dir).resolve(strict=True)))) if args.tools_dir else ''}
cpu_overcommit = 16
pids_max = 64
max_records = 512
max_concurrent_operations = {MAX_SANDBOXES}
max_artifact_bytes = 67108864
command_timeout_seconds = 60
''')
    controller_config = root / "controller.toml"
    controller_config.write_text(f'''[server]
listen = "127.0.0.1:{controller_port}"
max_in_flight = 256
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
node_id = "node-stress"
url = "http://127.0.0.1:{worker_port}"
''')
    compatibility = preflight_compatibility(binary, worker_config)
    rootfs = root / "fixture-rootfs"
    rootfs.mkdir(mode=0o755)
    for name in ("dev", "proc", "workspace"):
        (rootfs / name).mkdir(mode=0o755)
    (rootfs / "workspace").chmod(0o777)
    (rootfs / "seed").write_bytes(b"seed\n" + bytes(4091))
    subprocess.run(["cc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", str(Path(__file__).with_name("fixture.c")), "-o", str(rootfs / "fixture")], check=True, timeout=60)
    layer = root / "fixture.erofs"
    subprocess.run(["mkfs.erofs", str(layer), str(rootfs)], check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    write_template(root, cold_manifest("fixture", compatibility, publish_layer(root, layer), ["/fixture", "init"], {"mode": "isolated"},
                                       memory_mib=MEMORY_MIB, vcpus=1, pids_max=64))
    processes, ids, observations = [], [], {"batch": BATCH, "memory_mib_per_sandbox": MEMORY_MIB, "batches": []}

    # Launch a service, keep its log and process, and wait for its health endpoint.
    def start(role, config):
        log = root / f"{role}-{len(processes)}.log"
        with log.open("wb") as output:
            processes.append(subprocess.Popen([binary, role, "--config", str(config)], env=env, stdout=output, stderr=subprocess.STDOUT))
        eventually(lambda: request(worker_port if role == "worker" else controller_port, "/healthz", timeout=4)[0] == 200, timeout=15)

    # Create one sandbox through the controller exactly once (no retry of any kind) and return the
    # template, status, error code and seconds taken.
    def create_once(template_id):
        started = time.monotonic()
        code, body = request(controller_port, "/v1/sandboxes", token, dict(template_id=template_id, ttl_seconds=600), "POST")
        if "sandbox_id" in body:
            ids.append(body["sandbox_id"])
        error = None if code == 201 and body.get("state") == "running" else (body.get("error") or {}).get("code", f"http_{code}")
        return dict(template=template_id, sandbox=body.get("sandbox_id"), status=code, error=error, seconds=time.monotonic() - started)

    # Delete one sandbox through the controller exactly once and return its status and error code.
    def delete_once(sandbox):
        started = time.monotonic()
        code, body = request(controller_port, f"/v1/sandboxes/{sandbox}", token, method="DELETE")
        error = None if code == 200 and body.get("state") == "deleted" else (body.get("error") or {}).get("code", f"http_{code}")
        return dict(status=code, error=error, seconds=time.monotonic() - started)

    # Start every create of a batch at the same moment, then delete them all at once. Record error
    # counts and timings and return whether the batch was clean; every batch runs even after a
    # failed one, so the gate reports all of them.
    def burst(name, templates):
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(templates)) as pool:
            created = list(pool.map(create_once, templates))
        running = [c["sandbox"] for c in created if c["error"] is None]
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(running))) as pool:
            deleted = list(pool.map(delete_once, running))
        errors = collections.Counter(c["error"] for c in created + deleted if c["error"] is not None)
        summary = dict(name=name, creates=len(created), deletes=len(deleted), errors=dict(errors),
                       create_p50_s=round(statistics.median(c["seconds"] for c in created), 3), create_max_s=round(max(c["seconds"] for c in created), 3),
                       delete_max_s=round(max((d["seconds"] for d in deleted), default=0), 3))
        for kind in sorted({c["template"] for c in created}):
            seconds = [c["seconds"] for c in created if c["template"] == kind]
            summary[f"{kind}_create_p50_s"], summary[f"{kind}_create_max_s"] = round(statistics.median(seconds), 3), round(max(seconds), 3)
        observations["batches"].append(summary)
        print("BATCH " + json.dumps(summary), flush=True)
        clean = not errors and len(running) == len(templates)
        for sandbox in running:
            clean &= not (root / "private" / sandbox).exists() and not (cgroup / sandbox).exists() and not (root / "runc" / sandbox).exists()
        return clean

    try:
        start("worker", worker_config)
        start("controller", controller_config)
        eventually(lambda: expect(request(controller_port, "/v1/status", token, timeout=4), 200)["nodes"][0]["fresh"], timeout=15)
        clean = {"cold": burst("cold", ["fixture"] * BATCH)}
        source = create_once("fixture")
        assert source["error"] is None, source
        code, captured = request(controller_port, f"/v1/sandboxes/{source['sandbox']}/capture", token, dict(template_id="warm", runtime="runc_criu"), "POST")
        assert code == 200 and captured["state"] == "running", captured
        clean["warm"] = burst("warm", ["warm"] * BATCH)
        clean["mixed"] = burst("mixed", ["fixture", "warm"] * BATCH)
        assert delete_once(source["sandbox"])["error"] is None
        assert all(clean.values()), f"batches with errors: {[name for name, ok in clean.items() if not ok]}"
        print(f"PASS {BATCH} concurrent cold creates, {BATCH} concurrent warm restores, then both at once (32 concurrent creates and "
              "guest namespaces), each with concurrent deletes: zero errors", flush=True)
        for log in root.glob("worker-*.log"):
            failures = [line for line in log.read_text(errors="replace").splitlines() if "host tool" in line]
            assert not failures, failures[:5]
    finally:
        # All cleanup goes through the owner; never recurse through live mounts.
        if processes and processes[0].poll() is None:
            for sandbox in ids:
                try:
                    request(worker_port, f"/v1/sandboxes/{sandbox}", worker_token, method="DELETE", timeout=150)
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
        observations["sandbox_ids"] = len(ids)
        (root / "validation.json").write_text(json.dumps(observations, indent=2))
        (root / "validation.json").chmod(0o600)
        print("Retained owned artifacts/records for inspection:", root)
    mountinfo = Path("/proc/self/mountinfo").read_text()
    assert not any(str(root) in line.split()[4] for line in mountinfo.splitlines()), "owned mounts remain"
    assert not any(path.is_dir() for path in cgroup.iterdir()), "owned workload/helper cgroups remain"
    assert not any(p.name.startswith(owned_prefix) for p in Path("/run/netns").iterdir()), "owned netns remain"
    for log in root.glob("*.log"):
        assert token.encode() not in log.read_bytes() and worker_token.encode() not in log.read_bytes()
    print("STRESS SMOKE PASSED on this host only; not a capacity, performance or two-node qualification")


if __name__ == "__main__":
    main()
