#!/usr/bin/env python3
"""Nonprivileged process smoke: real HTTP services, no containers or mock runtime."""

import argparse
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port_number, path, token=None, body=None, method="GET", chunked=False):
    headers = {}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
        if isinstance(body, dict):
            body = json.dumps(body).encode()
    connection = http.client.HTTPConnection("127.0.0.1", port_number, timeout=4)
    try:
        connection.request(method, path, body=body, headers=headers, encode_chunked=chunked)
        response = connection.getresponse()
        payload = response.read()
        return response.status, json.loads(payload)
    finally:
        connection.close()


def expect(result, status, code=None):
    actual, payload = result
    assert actual == status, f"expected HTTP {status}, got {actual}"
    if code:
        assert payload.get("error", {}).get("code") == code, "unexpected error code"
    return payload


def eventually(check, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.025)
    raise AssertionError("condition did not become true within smoke deadline")


def worker_config(port_number, node="node-a", limit=32, timeout=800):
    return f'''node_id = "{node}"
runtimes = ["runc_criu"]
[server]
listen = "127.0.0.1:{port_number}"
max_in_flight = {limit}
request_timeout_ms = {timeout}
max_body_bytes = 2048
[auth]
env = "SANDBOX_WORKER_TOKEN"
[capacity]
memory_mib = 8192
vcpus = 4
max_sandboxes = 32
max_concurrent_restores = 2
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/sandboxd")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    assert Path(binary).is_file(), "build sandboxd before running the smoke"
    target = Path(__file__).resolve().parent.parent / "target"
    target.mkdir(exist_ok=True)
    worker_token = secrets.token_urlsafe(48)
    controller_token = secrets.token_urlsafe(48)
    environment = dict(os.environ, SANDBOX_WORKER_TOKEN=worker_token)
    processes = []
    logs = []
    with tempfile.TemporaryDirectory(prefix="smoke-", dir=target) as directory:
        root = Path(directory)
        secret = root / "controller-token"
        secret.write_text(controller_token + "\n")
        secret.chmod(0o600)
        worker_port, second_port, controller_port = port(), port(), port()
        assert len({worker_port, second_port, controller_port}) == 3, "ephemeral port collision; retry"
        controller_text = f'''[server]
listen = "127.0.0.1:{controller_port}"
max_in_flight = 32
request_timeout_ms = 800
max_body_bytes = 2048
[auth]
file = {json.dumps(str(secret))}
[worker_auth]
env = "SANDBOX_WORKER_TOKEN"
[poll]
interval_ms = 100
timeout_ms = 200
freshness_ms = 500
fanout = 2
[[workers]]
node_id = "node-a"
url = "http://127.0.0.1:{worker_port}"
[[workers]]
node_id = "node-b"
url = "http://127.0.0.1:{second_port}"
'''

        def start(role, text):
            index = len(processes)
            config = root / f"{role}-{index}.toml"
            config.write_text(text)
            log = root / f"{role}-{index}.log"
            with log.open("wb") as output:
                process = subprocess.Popen(
                    [binary, role, "--config", str(config)], env=environment,
                    stdout=output, stderr=subprocess.STDOUT,
                )
            processes.append(process)
            logs.append(log)
            return process

        def stop(process):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                    raise AssertionError("service failed to terminate within smoke deadline")
            assert process.returncode == 0, "service exited unsuccessfully"

        def invalid_config(role, text, env=None):
            config = root / "invalid.toml"
            config.write_text(text)
            result = subprocess.run(
                [binary, role, "--config", str(config)], env=env or environment,
                capture_output=True, timeout=3,
            )
            assert result.returncode != 0, "invalid configuration was accepted"
            for token in (worker_token, controller_token):
                assert token.encode() not in result.stdout + result.stderr, "credential leaked in diagnostics"

        create = {
            "sandbox_id": "node-a.example", "template_id": "example-template", "runtime": "runc_criu",
            "architecture": "x86_64", "memory_mib": 256, "vcpus": 1, "ttl_seconds": 300,
        }
        try:
            # Strict startup validation and safe diagnostics, including accidentally embedded secrets.
            invalid_config("worker", worker_config(worker_port).replace("memory_mib = 8192", "memory_mib = 0"))
            invalid_config("worker", worker_config(worker_port).replace('"runc_criu"', '"unknown_runtime"'))
            invalid_config("worker", worker_config(worker_port).replace('["runc_criu"]', '[]'))
            invalid_config("worker", worker_config(worker_port).replace('["runc_criu"]', '["runc_criu", "runc_criu"]'))
            invalid_config("worker", 'unknown = ' + json.dumps(worker_token) + "\n" + worker_config(worker_port))
            invalid_config("worker", worker_config(worker_port), dict(environment, SANDBOX_WORKER_TOKEN="short"))
            missing = dict(environment)
            missing.pop("SANDBOX_WORKER_TOKEN")
            invalid_config("worker", worker_config(worker_port), missing)
            invalid_config("controller", controller_text.replace('node_id = "node-b"', 'node_id = "node-a"'))
            invalid_config("controller", controller_text.replace(f"http://127.0.0.1:{worker_port}", "http://user:password@127.0.0.1/"))
            invalid_config("controller", controller_text.replace("fanout = 2", "fanout = 0"))
            invalid_config("controller", controller_text.replace("[worker_auth]", 'env = "SANDBOX_WORKER_TOKEN"\n[worker_auth]'))
            print("PASS strict configuration and credential-source validation")

            worker = start("worker", worker_config(worker_port))
            second = start("worker", worker_config(second_port, "node-b"))
            controller = start("controller", controller_text)
            for number, role in ((worker_port, "worker"), (second_port, "worker"), (controller_port, "controller")):
                health = eventually(lambda: request(number, "/healthz"))[1]
                assert health == {"service": role, "live": True}
            for number, token in ((worker_port, worker_token), (controller_port, controller_token)):
                expect(request(number, "/v1/status"), 401, "unauthorized")
                expect(request(number, "/v1/status", "incorrect"), 401, "unauthorized")
                expect(request(number, "/v1/sandboxes", body=create, method="POST"), 401, "unauthorized")
                expect(request(number, "/missing"), 401, "unauthorized")
                expect(request(number, "/missing", token), 404, "not_found")
                expect(request(number, "/v1/status", token), 200)
            expect(request(controller_port, "/v1/status", worker_token), 401, "unauthorized")
            print("PASS real process health and management authentication (environment and file)")

            worker_status = expect(request(worker_port, "/v1/status", worker_token), 200)
            assert worker_status["usage"] is None and not worker_status["admission_ready"]
            assert worker_status["runtimes"] == [
                {"runtime": "runc_criu", "ready": False, "reason": "runtime_disabled"},
            ]

            def nodes():
                status = expect(request(controller_port, "/v1/status", controller_token), 200)
                assert status["lifecycle_implemented"]
                return {node["node_id"]: node for node in status["nodes"]}

            eventually(lambda: len(nodes()) == 2 and all(node["fresh"] for node in nodes().values()))
            for number, token, code in ((worker_port, worker_token, "runtime_unavailable"), (controller_port, controller_token, "no_ready_runtime")):
                expect(request(number, "/v1/sandboxes", token, create, "POST"), 503, code)
                for change in ({"memory_mib": 0}, {"ttl_seconds": 0}, {"runtime": "other"}, {"unexpected": True}, {"vcpus": -1}, {"sandbox_id": "../escape"}, {"template_id": "../escape"}, {"egress": []}, {"rootfs": "/tmp/untrusted"}):
                    expect(request(number, "/v1/sandboxes", token, dict(create, **change), "POST"), 400, "invalid_input")
                expect(request(number, "/v1/sandboxes", token, b"{", "POST"), 400, "invalid_input")
                expect(request(number, "/v1/sandboxes", token, b"x" * 2049, "POST"), 413, "body_too_large")
                expect(request(number, "/v1/sandboxes", token, iter([b"x" * 1024] * 3), "POST", True), 413, "body_too_large")
                execution = {"operation_id": "exec-1", "argv": ["echo", "hello"], "timeout_ms": 1000, "max_output_bytes": 1024}
                expect(request(number, "/v1/sandboxes/node-a.example/exec", token, execution, "POST"), 503, "runtime_unavailable")
                expect(request(number, "/v1/sandboxes/node-a.example/exec", token, dict(execution, argv=[]), "POST"), 400, "invalid_input")
                app_http = {"operation_id":"http-1", "port":8080, "method":"GET", "path":"/", "timeout_ms":1000, "max_response_bytes":4096}
                expect(request(number, "/v1/sandboxes/node-a.example/http", token, app_http, "POST"), 503, "runtime_unavailable")
                for changes in [dict(path="http://example.invalid/"), dict(path="//example.invalid/"), dict(headers={"authorization":"not-forwarded"}), dict(port=0), dict(method="CONNECT")]:
                    expect(request(number, "/v1/sandboxes/node-a.example/http", token, dict(app_http, **changes), "POST"), 400, "invalid_input")
                expect(request(number, "/v1/sandboxes/node-a.example/http", token, dict(app_http, body="x"*8193), "POST"), 413, "body_too_large")
                capture = {"operation_id": "capture-1", "template_id": "example", "runtime": "runc_criu"}
                expect(request(number, "/v1/sandboxes/node-a.example/capture", token, capture, "POST"), 503, "runtime_unavailable")
                expect(request(number, "/v1/sandboxes/node-a.example/capture", token, dict(capture, runtime="other"), "POST"), 400, "invalid_input")
                for identifier in ("%FF", "bad%2Fid"):
                    expect(request(number, f"/v1/sandboxes/{identifier}/exec", token, execution, "POST"), 400, "invalid_input")
                    expect(request(number, f"/v1/sandboxes/{identifier}/capture", token, capture, "POST"), 400, "invalid_input")
            print("PASS strict inputs/identifiers, fixed/chunked body bounds and fail-closed create/exec/capture/HTTP")

            def concurrent_check(index):
                number, token = (worker_port, worker_token) if index % 2 else (controller_port, controller_token)
                if index % 3 == 0:
                    expect(request(number, "/healthz"), 200)
                elif index % 3 == 1:
                    expect(request(number, "/v1/status", token), 200)
                else:
                    code = "runtime_unavailable" if number == worker_port else "no_ready_runtime"
                    expect(request(number, "/v1/sandboxes", token, create, "POST"), 503, code)

            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                list(pool.map(concurrent_check, range(96)))
            print("PASS 96 mixed health/status/create requests with 16 concurrent clients (not a benchmark)")

            stop(worker)
            eventually(lambda: not nodes()["node-a"]["fresh"])
            stale = nodes()["node-a"]
            assert not stale["reachable"] and stale["status"] is not None and stale["error"]
            eventually(lambda: nodes()["node-a"]["age_ms"] > 500)
            assert nodes()["node-b"]["fresh"]
            expect(request(controller_port, "/v1/sandboxes", controller_token, create, "POST"), 503, "no_ready_runtime")
            wrong = start("worker", worker_config(worker_port, "wrong-node"))
            eventually(lambda: nodes()["node-a"]["error"] == "invalid_status")
            assert not nodes()["node-a"]["fresh"]
            stop(wrong)
            worker = start("worker", worker_config(worker_port))
            eventually(lambda: nodes()["node-a"]["fresh"])
            print("PASS stale exclusion, node identity validation and worker restart recovery")

            # Explicit runtime enablement cannot bypass missing privilege/capability checks.
            native_root = root / "native-runtime"
            native_root.mkdir()
            blocked_port = port()
            native_text = worker_config(blocked_port, "blocked") + f'''[native]
enabled = true
root = {json.dumps(str(native_root))}
cgroup_parent = "/sys/fs/cgroup/sandbox-smoke-unavailable"
cpu_overcommit = 2
pids_max = 64
max_records = 8
max_operations_per_sandbox = 4
max_artifact_bytes = 1048576
command_timeout_seconds = 10
'''
            invalid_config("worker", native_text.replace("cpu_overcommit = 2", "cpu_overcommit = 17"))
            invalid_config("worker", native_text.replace("cpu_overcommit = 2", "cpu_overcommit = 0"))
            blocked = start("worker", native_text)
            eventually(lambda: request(blocked_port, "/healthz")[0] == 200)
            blocked_status = expect(request(blocked_port, "/v1/status", worker_token), 200)
            assert not blocked_status["admission_ready"] and blocked_status["usage"] is None
            assert blocked_status["runtimes"][0]["reason"] == "preflight_failed"
            preflight = expect(request(blocked_port, "/v1/preflight", worker_token), 200)
            assert not preflight["ready"] and preflight["qualification"] == "unvalidated"
            expect(request(blocked_port, "/v1/preflight"), 401, "unauthorized")
            expect(request(blocked_port, "/v1/sandboxes", worker_token, dict(create, sandbox_id="blocked.example"), "POST"), 503, "runtime_unavailable")
            assert not list(native_root.iterdir()), "preflight mutated the runtime root"
            stop(blocked)
            print("PASS explicit-enable fail-closed preflight, CPU overcommit bounds, no runtime-root mutation")

            # Isolated one-permit server makes saturation deterministic without loading the host.
            limited_port = port()
            limited = start("worker", worker_config(limited_port, "limited", limit=1, timeout=1500))
            eventually(lambda: request(limited_port, "/healthz")[0] == 200)
            with socket.create_connection(("127.0.0.1", limited_port), timeout=4) as slow:
                slow.sendall((
                    "POST /v1/sandboxes HTTP/1.1\r\nHost: localhost\r\n"
                    f"Authorization: Bearer {worker_token}\r\n"
                    "Content-Type: application/json\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{"
                ).encode())
                eventually(lambda: request(limited_port, "/healthz")[0] == 503, timeout=1)
                expect(request(limited_port, "/v1/status", worker_token), 503, "busy")
                # Other processes continue serving while one server waits for a partial body.
                expect(request(controller_port, "/healthz"), 200)
                expect(request(worker_port, "/v1/status", worker_token), 200)
                response = http.client.HTTPResponse(slow)
                response.begin()
                expect((response.status, json.loads(response.read())), 408, "request_timeout")
            eventually(lambda: request(limited_port, "/healthz")[0] == 200)
            stop(limited)
            print("PASS admission overload, partial-body deadline and recovery")
            stop(controller)
            stop(worker)
            stop(second)
            for log in logs:
                content = log.read_bytes()
                assert worker_token.encode() not in content and controller_token.encode() not in content, "credential leaked in service logs"
            print("PASS graceful termination and token-redaction checks")
            print("SMOKE PASSED: no containers, mounts, network policy changes or capacity qualification")
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)


if __name__ == "__main__":
    main()
