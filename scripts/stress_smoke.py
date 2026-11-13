#!/usr/bin/env python3
"""Explicitly privileged local concurrency stress gate. Never runs from the foundation smoke.

Through a real controller and worker, inside a disposable network/mount namespace (as in
network_smoke.py), with the tiny fixture at 64 MiB and one vCPU per sandbox:
- isolated policy: 16 concurrent cold creates, one capture, 16 concurrent warm restores, then 16
  cold creates and 16 warm restores at the same time (32 concurrent creates and guest namespaces);
- approved-port policy (pooled routing slots, firewall rules, veth pairs): one capture, then 32
  concurrent cold creates and 32 concurrent warm restores;
- with --oci-layout, a real image (python3 -m http.server, 128 MiB): one capture once
  its server answers, then --image-concurrency cold creates and warm restores (default 2,
  plus one source; larger batches require separate host approval).
Every batch ends with concurrent deletes. Every create and delete must succeed on its first attempt,
with no error and no failed host tool in the worker log. Each batch prints the median and largest
duration of every create, restore and delete step from the worker's phase log. Afterwards one
approved-port sandbox measures proxied call times per hop (inside its routing namespace, through
the worker, through the controller) for small and 1 MiB answers. This is a local burst check and
an informational profile on one host, not a capacity, performance or two-node qualification.
A final batch starts 32 distinct tiny EROFS bases at once to exercise first-use lower mounts.
"""
import argparse
import collections
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import statistics
import subprocess
import sys
import tempfile
import time
import types

from network_smoke import inventory, run
from runtime_smoke import cold_manifest, preflight_compatibility, publish_layer, write_template
from smoke import eventually, exchange, expect, port, request as smoke_request

BATCH = 16
WIDE = 32
# The capture sources plus the largest batch fit with room to spare.
MAX_SANDBOXES = WIDE + 4
MEMORY_MIB = 64
IMAGE_MEMORY_MIB = 128
FIXTURE_PORT = 8080
IMAGE_PORT = 8000
BRIDGE = "sb-test-br"
# Time one request in the routing namespace: a fresh connection per call, as the worker's proxy uses.
HOP_CLIENT = """import http.client, json, sys, time
host, port, path, count = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
times = []
for _ in range(count):
    started = time.perf_counter()
    connection = http.client.HTTPConnection(host, port, timeout=10)
    connection.request("GET", path)
    response = connection.getresponse()
    body = response.read()
    connection.close()
    assert response.status == 200, response.status
    times.append(time.perf_counter() - started)
print(json.dumps(dict(times=times, bytes=len(body))))
"""


# Parse the gate's options and require explicit privileged opt-in.
def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--allow-privileged-runtime", action="store_true")
    parser.add_argument("--binary", default="target/release/sandboxd")
    parser.add_argument("--root", required=True, help="Existing trusted directory on ext4/XFS/Btrfs; retained for inspection")
    parser.add_argument("--cgroup-parent", required=True, help="Existing empty delegated domain; cpu memory pids already enabled")
    parser.add_argument("--tools-dir", help="Optional existing administrator-staged trusted tool directory")
    parser.add_argument("--oci-layout", help="Optional OCI image layout of a Python image (for example python:3.12-slim) for the real-image batches")
    parser.add_argument("--image-concurrency", type=int, choices=range(1, 33), default=2,
                        help="Real-image batch width, plus one source; default 2 keeps at most three live images")
    parser.add_argument("--platform", default="linux/" + {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine, os.uname().machine))
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--session", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.allow_privileged_runtime or os.geteuid() != 0:
        parser.error("requires explicit opt-in and administrator execution on an approved host")
    if not str(Path(args.cgroup_parent).resolve()).startswith("/sys/fs/cgroup/"):
        parser.error("cgroup parent must be below /sys/fs/cgroup")
    return args


# Outer phase: build the fixture (and image) layers in the host namespace, run the batches in a
# disposable network/mount namespace and require the default namespace inventory to be unchanged.
# Also build 32 distinct small bases for the lower-mount regression batch.
def outer(args):
    session = Path(tempfile.mkdtemp(prefix="stress-", dir=Path(args.root).resolve(strict=True)))
    session.chmod(0o700)
    rootfs = session / "fixture-rootfs"
    rootfs.mkdir(mode=0o755)
    for name in ("dev", "proc", "workspace"):
        (rootfs / name).mkdir(mode=0o755)
    (rootfs / "workspace").chmod(0o777)
    (rootfs / "seed").write_bytes(b"seed\n" + bytes(4091))
    subprocess.run(["cc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", str(Path(__file__).with_name("fixture.c")), "-o", str(rootfs / "fixture")], check=True, timeout=60)
    layer = session / "fixture.erofs"
    subprocess.run(["mkfs.erofs", str(layer), str(rootfs)], check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    prepared = dict(fixture=publish_layer(session, layer), distinct=[])
    for index in range(WIDE):
        (rootfs / "layer-id").write_text(str(index))
        subprocess.run(["mkfs.erofs", str(layer), str(rootfs)], check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        prepared["distinct"].append(publish_layer(session, layer))
    if args.oci_layout:
        from image_e2e import prepare_image
        image = prepare_image(types.SimpleNamespace(oci_tar=None, oci_layout=args.oci_layout, platform=args.platform, init_argv=None, port=IMAGE_PORT,
                                                    keep_image_resolver=False, no_image_env=False, tools_dir=args.tools_dir), session)
        prepared["image"] = dict(base=image["base"], init_argv=image["init_argv"])
    (session / "stress-prepared.json").write_text(json.dumps(prepared))
    # Flush the preparation's write-back, so it does not slow the first timed batch's syncs.
    os.sync()
    before = inventory()
    env = dict(os.environ, SANDBOX_TEST_PARENT_NETNS=os.readlink("/proc/self/ns/net"))
    result = subprocess.run(["unshare", "--mount", "--net", "--fork", sys.executable, os.path.abspath(__file__), *sys.argv[1:],
                             "--inside", "--session", str(session)], env=env, timeout=1500)
    after = inventory()
    if before != after:
        print("INVENTORY BEFORE", json.dumps(before), "INVENTORY AFTER", json.dumps(after))
        raise AssertionError("default namespace inventory changed; inspect before any cleanup")
    print("PASS default namespace network inventory unchanged")
    print("Retained session root for inspection:", session)
    return result.returncode


# Inner phase: inside the disposable namespace, create only a namespace-local bridge and private
# /run/netns, run the batches, then verify teardown.
def inner(args):
    assert os.readlink("/proc/self/ns/net") != os.environ["SANDBOX_TEST_PARENT_NETNS"]
    assert len(json.loads(run("ip", "-j", "link"))) == 1
    run("mount", "--make-rprivate", "/")
    if not Path("/run/netns").is_dir():
        raise SystemExit("operator must provide existing /run/netns directory")
    run("mount", "-t", "tmpfs", "-o", "mode=700", "tmpfs", "/run/netns")
    run("ip", "link", "set", "lo", "up")
    run("ip", "link", "add", BRIDGE, "address", "02:00:00:00:00:01", "type", "bridge")
    run("ip", "addr", "add", "198.18.0.1/24", "dev", BRIDGE)
    run("ip", "link", "set", BRIDGE, "up")
    try:
        lifecycle(args, Path(args.session))
    finally:
        # Never discard namespace pins while an owned workload/helper may be live.
        assert not list(Path("/run/netns").iterdir()), "owned namespace pins remain"
        run("ip", "link", "delete", BRIDGE)
        assert [link["ifname"] for link in json.loads(run("ip", "-j", "link"))] == ["lo"]
        assert not run("nft", "list", "ruleset").strip()
        run("umount", "/run/netns")
    print("PASS outer namespace bridge/pins cleaned")
    print("STRESS SMOKE PASSED on this host only; not a capacity, performance or two-node qualification")
    return 0


# Return the median and the largest value of a list, rounded to milliseconds or seconds as given.
def summary(values, digits=3):
    return dict(p50=round(statistics.median(values), digits), max=round(max(values), digits)) if values else None


# Set up a worker and controller in the session root, run the create/restore/delete bursts and the
# hop measurement, and require zero errors, no failed host tool, phase histograms in worker status,
# no owned mounts or cgroups afterwards and no credentials in the logs.
def lifecycle(args, root):
    prepared = json.loads((root / "stress-prepared.json").read_text())

    # Send a management request with a client deadline above the services' own route deadlines.
    def request(*call, timeout=None, **named):
        return smoke_request(*call, timeout=timeout or 200, **named)

    binary = str(Path(args.binary).resolve())
    cgroup = Path(args.cgroup_parent).resolve(strict=True)
    owned_prefix = "sb-" + hashlib.sha256(str(root).encode()).hexdigest()[:16] + "-"
    worker_port, controller_port = port(), port()
    assert worker_port != controller_port
    token, worker_token = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
    env = dict(os.environ, SANDBOX_CONTROLLER_TOKEN=token, SANDBOX_WORKER_TOKEN=worker_token)
    addresses = ", ".join(f'"198.18.0.{10 + i}"' for i in range(MAX_SANDBOXES))
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
memory_mib = {MAX_SANDBOXES * IMAGE_MEMORY_MIB}
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
max_records = 1024
max_concurrent_operations = {MAX_SANDBOXES}
max_artifact_bytes = 4294967296
command_timeout_seconds = 60
[native.network]
bridge = "{BRIDGE}"
gateway = "198.18.0.1"
prefix = 24
addresses = [{addresses}]
egress = []
service_ports = [{FIXTURE_PORT}, {IMAGE_PORT}]
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
    fixture_net = {"mode": "tcp_allowlist", "egress": [], "service_ports": [FIXTURE_PORT]}
    write_template(root, cold_manifest("fixture", compatibility, prepared["fixture"], ["/fixture", "init"], {"mode": "isolated"},
                                       memory_mib=MEMORY_MIB, vcpus=1, pids_max=64))
    write_template(root, cold_manifest("fixture-net", compatibility, prepared["fixture"], ["/fixture", "init-network"], fixture_net,
                                       memory_mib=MEMORY_MIB, vcpus=1, pids_max=64))
    for index, base in enumerate(prepared["distinct"]):
        write_template(root, cold_manifest(f"distinct-{index}", compatibility, base, ["/fixture", "init"], {"mode": "isolated"},
                                           memory_mib=MEMORY_MIB, vcpus=1, pids_max=64))
    if "image" in prepared:
        image_net = {"mode": "tcp_allowlist", "egress": [], "service_ports": [IMAGE_PORT]}
        write_template(root, cold_manifest("image", compatibility, prepared["image"]["base"], prepared["image"]["init_argv"], image_net,
                                           memory_mib=IMAGE_MEMORY_MIB, vcpus=1, pids_max=64))
    processes, ids, observations = [], [], {"batch": BATCH, "wide": WIDE, "batches": []}

    # Launch a service, keep its log and process, and wait for its health endpoint.
    def start(role, config):
        log = root / f"{role}-{len(processes)}.log"
        with log.open("wb") as output:
            processes.append(subprocess.Popen([binary, role, "--config", str(config)], env=env, stdout=output, stderr=subprocess.STDOUT))
        eventually(lambda: request(worker_port if role == "worker" else controller_port, "/healthz", timeout=4)[0] == 200, timeout=60)

    # Create one sandbox through the controller exactly once (no retry of any kind) and return the
    # template, status, error code and seconds taken.
    def create_once(template_id):
        started = time.monotonic()
        code, body = request(controller_port, "/v1/sandboxes", token, dict(template_id=template_id, ttl_seconds=900), "POST")
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

    # Read the worker's phase log lines (one JSON object per finished operation).
    def phase_lines():
        lines = []
        for log in sorted(root.glob("worker-*.log")):
            for line in log.read_text(errors="replace").splitlines():
                if line.startswith("sandboxd: phases "):
                    lines.append(json.loads(line[len("sandboxd: phases "):]))
        return lines

    # Summarize the median and largest milliseconds of each step of the given sandboxes' operations,
    # per operation kind.
    def phase_profile(sandboxes):
        wanted, profile = set(sandboxes), {}
        for kind in ("create", "restore", "delete"):
            entries = [l for l in phase_lines() if l["op"] == kind and l["sandbox_id"] in wanted and l["result"] == "ok"]
            if not entries:
                continue
            steps = collections.defaultdict(list)
            for entry in entries:
                steps["total"].append(entry["total_ms"])
                for name, ms in entry["phases"].items():
                    steps[name].append(ms)
            profile[kind] = {name: summary(values, 2) for name, values in steps.items()}
        return profile

    # Start every create of a batch at the same moment, then delete them all at once. Record error
    # counts, timings and the step profile and return whether the batch was clean; every batch runs
    # even after a failed one, so the gate reports all of them.
    def burst(name, templates):
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(templates)) as pool:
            created = list(pool.map(create_once, templates))
        running = [c["sandbox"] for c in created if c["error"] is None]
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(running))) as pool:
            deleted = list(pool.map(delete_once, running))
        errors = collections.Counter(c["error"] for c in created + deleted if c["error"] is not None)
        result = dict(name=name, creates=len(created), deletes=len(deleted), errors=dict(errors),
                      create_s=summary([c["seconds"] for c in created]), delete_s=summary([d["seconds"] for d in deleted]))
        for kind in sorted({c["template"] for c in created}):
            result[f"{kind}_create_s"] = summary([c["seconds"] for c in created if c["template"] == kind])
        result["phases_ms"] = phase_profile(running)
        observations["batches"].append(result)
        print("BATCH " + json.dumps({k: v for k, v in result.items() if k != "phases_ms"}), flush=True)
        for kind, steps in result["phases_ms"].items():
            print(f"PHASES {name} {kind} " + " ".join(f"{step}={value['p50']}/{value['max']}" for step, value in sorted(steps.items(), key=lambda s: -s[1]["p50"])), flush=True)
        clean = not errors and len(running) == len(templates)
        for sandbox in running:
            clean &= not (root / "private" / sandbox).exists() and not (cgroup / sandbox).exists() and not (root / "runc" / sandbox).exists()
        return clean

    # GET an app path of a sandbox through the controller's path-form proxy.
    def proxy_get(sandbox, service_port, path, timeout=10):
        return exchange(controller_port, "GET", f"/v1/sandboxes/{sandbox}/proxy/{service_port}{path}", {"Authorization": "Bearer " + token}, timeout=timeout)

    # Create a source sandbox, wait until its service answers (if it has one) and capture it as a
    # warm template.
    def capture(template_id, warm_id, service_port=None, path="/"):
        source = create_once(template_id)
        assert source["error"] is None, source
        if service_port:
            eventually(lambda: proxy_get(source["sandbox"], service_port, path)[0] == 200, timeout=60)
        started = time.monotonic()
        code, captured = request(controller_port, f"/v1/sandboxes/{source['sandbox']}/capture", token, dict(template_id=warm_id, runtime="runc_criu"), "POST")
        assert code == 200 and captured["state"] == "running", captured
        print(f"PASS captured {warm_id} from {template_id} in {time.monotonic() - started:.3f}s", flush=True)
        return source["sandbox"]

    # Time `count` GETs of `path` per hop: a fresh connection to the guest from inside its routing
    # namespace (what the worker's proxy does), the worker's path-form proxy and the controller's,
    # each over one kept-alive client connection. Return per-hop median and 90th percentile ms.
    def hops(sandbox, slot, path, count):
        inside = json.loads(subprocess.run(["ip", "netns", "exec", f"{owned_prefix}s-{slot}", sys.executable, "-c", HOP_CLIENT, "192.0.2.2", str(FIXTURE_PORT), path, str(count)],
                                           check=True, capture_output=True, timeout=120).stdout)
        result = {"slot_netns": inside["times"]}
        for hop, port_number, credential in (("worker", worker_port, worker_token), ("controller", controller_port, token)):
            connection = http.client.HTTPConnection("127.0.0.1", port_number, timeout=30)
            times = []
            try:
                for _ in range(count):
                    started = time.perf_counter()
                    connection.request("GET", f"/v1/sandboxes/{sandbox}/proxy/{FIXTURE_PORT}{path}", headers={"Authorization": "Bearer " + credential})
                    response = connection.getresponse()
                    body = response.read()
                    times.append(time.perf_counter() - started)
                    assert response.status == 200 and len(body) == inside["bytes"], (response.status, len(body))
            finally:
                connection.close()
            result[hop] = times
        return {hop: dict(p50_ms=round(statistics.median(t) * 1000, 3), p90_ms=round(sorted(t)[int(len(t) * 0.9)] * 1000, 3)) for hop, t in result.items()}

    try:
        start("worker", worker_config)
        start("controller", controller_config)
        eventually(lambda: expect(request(controller_port, "/v1/status", token, timeout=4), 200)["nodes"][0]["fresh"], timeout=15)
        clean = {"cold": burst("cold", ["fixture"] * BATCH)}
        source = capture("fixture", "warm")
        clean["warm"] = burst("warm", ["warm"] * BATCH)
        clean["mixed"] = burst("mixed", ["fixture", "warm"] * BATCH)
        assert delete_once(source)["error"] is None
        source = capture("fixture-net", "warm-net", FIXTURE_PORT, "/sized/16/97")
        clean["cold-net-32"] = burst("cold-net-32", ["fixture-net"] * WIDE)
        clean["warm-net-32"] = burst("warm-net-32", ["warm-net"] * WIDE)
        assert delete_once(source)["error"] is None
        if "image" in prepared:
            source = capture("image", "image-warm", IMAGE_PORT)
            for width in (args.image_concurrency,):
                clean[f"image-cold-{width}"] = burst(f"image-cold-{width}", ["image"] * width)
                clean[f"image-warm-{width}"] = burst(f"image-warm-{width}", ["image-warm"] * width)
            assert delete_once(source)["error"] is None
        assert all(clean.values()), f"batches with errors: {[name for name, ok in clean.items() if not ok]}"
        print(f"PASS isolated: {BATCH} cold, {BATCH} warm, then {BATCH}+{BATCH} at once; approved-port: {WIDE} cold and {WIDE} warm"
              + (f"; image: {args.image_concurrency} cold and warm" if "image" in prepared else "") + "; each with concurrent deletes: zero errors", flush=True)
        # Per-hop proxied call times (informational): small and 1 MiB answers.
        bench = create_once("fixture-net")
        assert bench["error"] is None, bench
        eventually(lambda: proxy_get(bench["sandbox"], FIXTURE_PORT, "/sized/16/97")[0] == 200, timeout=30)
        slot = json.loads((root / "records" / f"{bench['sandbox']}.json").read_text())["network_slot"]
        observations["hops"] = {"small_16_bytes": hops(bench["sandbox"], slot, "/sized/16/97", 200), "large_1_mib": hops(bench["sandbox"], slot, "/sized/1048576/97", 40)}
        print("HOPS " + json.dumps(observations["hops"]), flush=True)
        assert delete_once(bench["sandbox"])["error"] is None
        assert burst("distinct-lowers-32", [f"distinct-{index}" for index in range(WIDE)]), "distinct EROFS lower mounts failed"
        print("PASS 32 distinct EROFS bases mounted for simultaneous first-use creates", flush=True)
        status = expect(request(worker_port, "/v1/status", worker_token, timeout=4), 200)
        assert all(status["phases"].get(f"{op}.total", {}).get("count", 0) > 0 for op in ("create", "restore", "delete", "capture")), sorted(status["phases"])
        assert 0 < len(status["phases"]) <= 160
        for histogram in status["phases"].values():
            assert len(histogram["buckets"]) == 15 and sum(histogram["buckets"]) == histogram["count"], histogram
        for operation in ("create", "restore"):
            assert status["phases"][f"{operation}.first_ready"]["count"] == status["phases"][f"{operation}.total"]["count"]
        assert request(worker_port, "/v1/status", timeout=4)[0] == 401
        observations["status_histograms"] = len(status["phases"])
        print(f"PASS worker status carries {len(status['phases'])} phase histograms", flush=True)
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


# Run the outer phase, or the inner phase when re-executed inside the disposable namespace.
def main():
    args = parse_args()
    sys.exit(inner(args) if args.inside else outer(args))


if __name__ == "__main__":
    main()
