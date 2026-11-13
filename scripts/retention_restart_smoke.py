#!/usr/bin/env python3
"""Privileged metadata-only restart regression; real worker, no containers or mounts.

Uses trusted synthetic history (including populated exec/HTTP results), never a
runtime substitute. Requires normal native preflight and an isolated, bounded
administrator-owned root/cgroup. Does not install tools or load kernel modules.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import tempfile
import time

from smoke import eventually, expect, port, request


MIB = 1048576
PER_SANDBOX = MIB + 16384
GLOBAL = MIB + 20480
RETAINED = MIB + 8192


# Encode fixture data as compact UTF-8 JSON so retained-byte calculations include escaping.
def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


# Build a synthetic operation record with no output, fingerprinting the supplied request or an empty
# one.
def operation(kind, state, payload=None):
    return dict(fingerprint=hashlib.sha256(encoded(payload or {})).hexdigest(),
                kind=kind, state=state, error="fixture_failure" if state == "failed" else None,
                output=None, http_output=None, template_id=None)


# Build a synthetic sandbox history record with bounded resources and a short expiry.
def record(name, state="deleted"):
    return dict(schema_version=1, request=dict(sandbox_id="node-history." + name,
                template_id="history", runtime="runc_criu", architecture=platform.machine(),
                memory_mib=64, vcpus=1, ttl_seconds=60), state=state, error=None,
                expires_at=int(time.time()) + 60, delete_requested=False,
                network_slot=None, network_policy=None, operations={})


# Build trusted synthetic history near the retained-output limit, mixing bounded result data with
# output-free metadata. Include interrupted operations and assert that populated results fit the
# original reservation budgets.
def history():
    # Each populated output fits a conservative reservation at its position in
    # this history under the original budgets; do not rely on impossible output
    # sizes to manufacture the boundary. The values are fixtures, not native runs.
    result = record("results")
    retained = 0
    while retained < RETAINED:
        index = len(result["operations"])
        kind = "exec" if index % 2 == 0 else "http"
        overhead = 4096 if kind == "exec" else 8192
        maximum = min(65536, (PER_SANDBOX - retained - overhead) // 6)
        op_id = f"result-{index}"
        op = operation(kind, "complete")
        # Include JSON-escaped bytes as well as ordinary text in both result kinds.
        text = "\x00\n\\\""
        if kind == "exec":
            op["output"] = dict(exit_code=0, stdout=text, stderr="fixture-stderr\n", interrupted=False)
            field, body = "output", "stdout"
        else:
            op["http_output"] = dict(status=200, content_type="text/plain", body=text)
            field, body = "http_output", "body"
        base = len(encoded([op["output"], op["http_output"]]))
        stderr_bytes = len(op["output"]["stderr"]) if kind == "exec" else 0
        fill = min(maximum - len(text) - stderr_bytes, RETAINED - retained - base)
        if 0 < RETAINED - retained - base - fill < 128:
            fill -= 128
        assert fill >= 0
        op[field][body] += "x" * fill
        raw = len(op[field][body].encode()) + (len(op["output"]["stderr"]) if kind == "exec" else 0)
        reservation = raw * 6 + overhead
        size = len(encoded([op["output"], op["http_output"]]))
        assert size <= reservation and retained + reservation <= PER_SANDBOX
        assert retained + reservation <= GLOBAL
        result["operations"][op_id] = op
        retained += size
    assert retained == RETAINED and len(result["operations"]) < 60
    records = {result["request"]["sandbox_id"]: result}
    # Only disk fixtures: no API flood or capture loop. Metadata remains below
    # the configured record/operation limits while its old null charge exceeds
    # the remaining global result budget.
    for index in range(20):
        r = record(f"empty-{index}", "failed" if index % 2 else "deleted")
        for number in range(60):
            kind = ("capture", "exec", "http")[number % 3]
            state = "complete" if kind == "capture" and number % 2 == 0 else "failed"
            op = operation(kind, state)
            if state == "complete":
                op["template_id"] = "historical-template"
            r["operations"][f"empty-{number}"] = op
        records[r["request"]["sandbox_id"]] = r
    pending = record("interrupted", "capturing")
    for kind in ("capture", "exec", "http"):
        pending["operations"][f"pending-{kind}"] = operation(kind, "pending")
    records[pending["request"]["sandbox_id"]] = pending
    absent = sum(op["output"] is None and op["http_output"] is None
                 for r in records.values() for op in r["operations"].values())
    assert RETAINED + absent * 11 > GLOBAL
    assert len(records) <= 24 and all(len(r["operations"]) <= 64 for r in records.values())
    return records, absent


# Require explicit administrator opt-in and successful native preflight before installing synthetic
# history. Check restart preservation, interrupted-operation cleanup and independent retention gates
# without creating containers. Retain evidence and stop workers, then verify owned runtime directories
# are empty.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-privileged-runtime", action="store_true")
    parser.add_argument("--binary", default="target/debug/sandboxd")
    parser.add_argument("--root", required=True, help="Existing trusted disposable parent; evidence retained")
    parser.add_argument("--cgroup-parent", required=True, help="Existing empty, bounded delegated domain")
    parser.add_argument("--tools-dir", required=True, help="Existing trusted administrator-staged tools")
    args = parser.parse_args()
    if not args.allow_privileged_runtime or os.geteuid() != 0:
        parser.error("requires explicit opt-in and administrator execution on an approved host")
    binary = str(Path(args.binary).resolve(strict=True))
    root = Path(tempfile.mkdtemp(prefix="retention-restart-", dir=Path(args.root).resolve(strict=True)))
    cgroup = Path(args.cgroup_parent).resolve(strict=True)
    tools = Path(args.tools_dir).resolve(strict=True)
    config = root / "worker.toml"
    token = secrets.token_urlsafe(48)
    env = dict(os.environ, SANDBOX_WORKER_TOKEN=token)
    worker_port = port()
    processes = []
    observations = dict(maximum_live_containers=0, fixture_records=22, retained_output_bytes=RETAINED,
                        per_sandbox_budget=PER_SANDBOX, global_budget=GLOBAL,
                        rejected_per_sandbox_budget=RETAINED - 1, rejected_global_budget=RETAINED - 1,
                        per_sandbox_admission_global_budget=2 * GLOBAL, checks=[])

    # Write the isolated worker configuration with the requested per-sandbox and global retention budgets.
    def configure(per=PER_SANDBOX, total=GLOBAL):
        config.write_text(f'''node_id = "node-history"
runtimes = ["runc_criu"]
[server]
listen = "127.0.0.1:{worker_port}"
[auth]
env = "SANDBOX_WORKER_TOKEN"
[capacity]
memory_mib = 64
vcpus = 1
max_sandboxes = 1
max_concurrent_restores = 1
[native]
enabled = true
root = {json.dumps(str(root))}
cgroup_parent = {json.dumps(str(cgroup))}
tools_dir = {json.dumps(str(tools))}
cpu_overcommit = 1
pids_max = 64
max_records = 24
max_operations_per_sandbox = 64
max_concurrent_operations = 1
max_retained_output_bytes = {total}
max_retained_output_per_sandbox_bytes = {per}
max_artifact_bytes = 1048576
command_timeout_seconds = 10
''')

    # Launch a worker and require either ready admission or the expected retention-limit startup
    # rejection. Save successful preflight evidence and record the check name.
    def start(name, rejected=False):
        log = root / f"{name}.log"
        with log.open("wb") as output:
            proc = subprocess.Popen([binary, "worker", "--config", str(config)], env=env,
                                    stdout=output, stderr=subprocess.STDOUT)
        processes.append(proc)
        if rejected:
            assert proc.wait(timeout=20) != 0
            assert "retained_output_limit" in log.read_text()
        else:
            # Require the launched worker to remain alive and report both admission and runtime readiness.
            def ready():
                assert proc.poll() is None, f"worker exited; inspect {log.name}"
                status = expect(request(worker_port, "/v1/status", token), 200)
                assert status["admission_ready"] and status["runtimes"][0]["ready"], "preflight/reconcile failed"
                return True
            eventually(ready, timeout=20)
            preflight = expect(request(worker_port, "/v1/preflight", token), 200)
            assert preflight["ready"] and all(c["ok"] for c in preflight["checks"])
            (root / f"{name}-preflight.json").write_text(json.dumps(preflight, indent=2) + "\n")
        observations["checks"].append(name)
        return proc

    # Stop the worker cleanly and require its saved cleanup status to report no error.
    def stop(proc):
        proc.terminate()
        assert proc.wait(timeout=20) == 0
        assert json.loads((root / "worker-status.json").read_text())["cleanup_error"] is None

    # Hash every saved sandbox record to detect history changes across restarts.
    def files():
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (root / "records").glob("*.json")}

    # Compare all saved records and sandbox summaries to expected history, then verify selected full
    # operation results through HTTP.
    def verify(expected):
        assert len(files()) == len(expected)
        for sandbox, r in expected.items():
            disk = json.loads((root / "records" / f"{sandbox}.json").read_text())
            assert disk == r, f"history changed: {sandbox}"
            actual = expect(request(worker_port, f"/v1/sandboxes/{sandbox}", token), 200)
            assert actual["state"] == r["state"]
            assert {op["operation_id"] for op in actual["operations"]} == set(r["operations"])
        # All populated results, plus representative no-output states, through
        # the actual management API. No new production endpoint is involved.
        selected = {"node-history.results": expected["node-history.results"]["operations"],
                    "node-history.interrupted": expected["node-history.interrupted"]["operations"],
                    "node-history.empty-0": {key: expected["node-history.empty-0"]["operations"][key]
                                             for key in ("empty-0", "empty-1", "empty-2")}}
        for sandbox, operations in selected.items():
            for op_id, op in operations.items():
                assert expect(request(worker_port, f"/v1/sandboxes/{sandbox}/operations/{op_id}", token), 200) == op

    # Submit a bounded operation and check acceptance or retention rejection. For accepted work on
    # terminal sandboxes, verify the saved output-free failure and update expected history.
    def submit(sandbox, kind, op_id, size, accepted=False):
        body = dict(operation_id=op_id)
        if kind == "capture":
            body.update(template_id="new-history", runtime="runc_criu")
        elif kind == "exec":
            body.update(argv=["/fixture", "unused"], timeout_ms=100, max_output_bytes=size)
        else:
            body.update(port=8080, method="GET", path="/", timeout_ms=100, max_response_bytes=size)
        response = request(worker_port, f"/v1/sandboxes/{sandbox}/{kind}", token, body, "POST")
        expect(response, 202 if accepted else 503, None if accepted else "retention_limit")
        if accepted:
            op = expect(request(worker_port, f"/v1/sandboxes/{sandbox}/operations/{op_id}", token), 200)
            assert op["state"] == "failed" and op["error"] == "sandbox_not_running"
            assert op["output"] is None and op["http_output"] is None
            expected[sandbox]["operations"][op_id] = op
        else:
            expect(request(worker_port, f"/v1/sandboxes/{sandbox}/operations/{op_id}", token), 404, "operation_not_found")

    try:
        configure()
        preflight = subprocess.run([binary, "preflight", "--config", str(config)],
                                   capture_output=True, timeout=20, env=env)
        (root / "preflight.json").write_bytes(preflight.stdout)
        assert preflight.returncode == 0, "native preflight failed; no history installed"
        expected, absent = history()
        observations["initial_absent_output_operations"] = absent
        observations["old_null_tuple_charge_bytes"] = absent * 11
        outputs = expected["node-history.results"]["operations"].values()
        observations["populated_output_operations"] = len(expected["node-history.results"]["operations"])
        raw_bytes = sum(len((op["output"]["stdout"] + op["output"]["stderr"]).encode()) if op["output"]
                        else len(op["http_output"]["body"].encode()) for op in outputs)
        observations["raw_output_bytes"] = raw_bytes
        assert raw_bytes < RETAINED - 1
        (root / "records").mkdir(mode=0o700)
        for sandbox, r in expected.items():
            (root / "records" / f"{sandbox}.json").write_bytes(encoded(r))
        (root / "initial-record-hashes.json").write_text(json.dumps(files(), indent=2) + "\n")
        pending = expected["node-history.interrupted"]
        pending.update(state="deleted", delete_requested=True)
        for op in pending["operations"].values():
            op.update(state="failed", error="worker_restarted")
        proc = start("initial-history-reconciliation")
        verify(expected)
        # Successful admissions of absent-output failures must remain free; actual
        # execution is deliberately impossible on these terminal records.
        submit("node-history.results", "capture", "new-capture", 0, True)
        submit("node-history.results", "exec", "new-exec", 1, True)
        submit("node-history.empty-0", "http", "new-http", 1, True)
        # Empty record isolates the global admission budget from the per-record one.
        for kind in ("exec", "http"):
            submit("node-history.empty-1", kind, f"global-{kind}", 4096)
        verify(expected)
        stable = files()
        stop(proc)
        proc = start("unchanged-budget-restart")
        verify(expected)
        assert files() == stable
        stop(proc)
        # One byte below the encoded output total: even if raw payloads fit,
        # serialization overhead must still be charged for present outputs.
        configure(per=RETAINED - 1)
        start("lowered-per-sandbox-rejected", rejected=True)
        assert files() == stable
        configure(total=RETAINED - 1)
        start("lowered-global-only-rejected", rejected=True)
        assert files() == stable
        # Raise only the global budget to independently exercise per-sandbox
        # admission rejection, not to make the unchanged-budget regression pass.
        configure(total=2 * GLOBAL)
        proc = start("per-sandbox-admission")
        for kind in ("exec", "http"):
            submit("node-history.results", kind, f"per-{kind}", 4096)
        assert files() == stable
        stop(proc)
        configure()
        proc = start("restored-original-budgets")
        verify(expected)
        assert files() == stable
        stop(proc)
        observations["final_record_hashes"] = stable
        observations["result"] = "passed"
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
        observations["workers_exited"] = all(proc.poll() is not None for proc in processes)
        observations["cgroup_directories_remaining"] = [p.name for p in cgroup.iterdir() if p.is_dir()]
        observations["runtime_directories_empty"] = all(not any((root / name).iterdir())
                                                        for name in ("private", "runc", "lowers", "staging")
                                                        if (root / name).exists())
        (root / "validation.json").write_text(json.dumps(observations, indent=2) + "\n")
        print(root)
    assert not observations["cgroup_directories_remaining"] and observations["runtime_directories_empty"]
    print("retention/restart metadata regression passed (zero containers)")


if __name__ == "__main__":
    main()
