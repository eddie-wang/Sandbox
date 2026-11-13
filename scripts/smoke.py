#!/usr/bin/env python3
"""Nonprivileged process smoke: real HTTP services, no containers or runtime substitute.

Controller placement is exercised against small worker-protocol routing doubles
(RoutingDouble). They answer only status/create/get/exec/delete routing calls and
never claim to run a container; real lifecycle checks are in runtime_smoke.py.
"""

import argparse
import concurrent.futures
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import select
import socket
import subprocess
import tempfile
import threading
import time


# Ask the local system for an unused loopback port, releasing it before returning the number.
def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# Send a loopback management request with optional authentication and JSON body. Read the JSON
# response and always close the connection.
def request(port_number, path, token=None, body=None, method="GET", chunked=False, timeout=4):
    headers = {}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
        if isinstance(body, dict):
            body = json.dumps(body).encode()
    connection = http.client.HTTPConnection("127.0.0.1", port_number, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers, encode_chunked=chunked)
        response = connection.getresponse()
        payload = response.read()
        return response.status, json.loads(payload)
    finally:
        connection.close()


# Assert the expected HTTP status and optional error code, then return the response data.
def expect(result, status, code=None):
    actual, payload = result
    assert actual == status, f"expected HTTP {status}, got {actual}"
    if code:
        assert payload.get("error", {}).get("code") == code, "unexpected error code"
    return payload


# Poll until a check returns a truthy result, tolerating temporary connection errors until the
# deadline.
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


class RoutingDouble:
    """Worker-protocol double for controller placement/routing only. Not a runtime."""

    def __init__(self, node_id, token):
        self.node_id, self.token = node_id, token
        self.mode, self.ready, self.peer_closed = "accept", True, False
        self.create_attempts, self.records, self.calls = [], {}, []
        self.lock = threading.Lock()
        double = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, body):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def handle_any(self, method):
                if self.headers.get("Authorization") != "Bearer " + double.token:
                    return self.reply(401, {"error": {"code": "unauthorized", "message": "test double"}})
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                if method == "POST" and self.path == "/v1/sandboxes" and double.mode == "hang":
                    # Outside the lock: observe whether the controller abandons this
                    # forward when its own client disconnects.
                    with double.lock:
                        double.create_attempts.append(body["sandbox_id"])
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        readable, _, _ = select.select([self.connection], [], [], 0.05)
                        if readable and not self.connection.recv(1, socket.MSG_PEEK):
                            double.peer_closed = True
                            break
                    self.close_connection = True
                    return None
                with double.lock:
                    double.calls.append((method, self.path))
                    if method == "GET" and self.path == "/v1/status":
                        count = sum(r["state"] == "running" for r in double.records.values())
                        return self.reply(200, dict(schema_version=1, node_id=double.node_id, architecture="x86_64", os="linux",
                            capacity=dict(memory_mib=1024, vcpus=4, max_sandboxes=8, max_concurrent_restores=2),
                            usage=dict(memory_mib=64 * count, vcpus=count, sandboxes=count, restores=0),
                            admission_ready=double.ready, runtimes=[dict(runtime="runc_criu", ready=double.ready, reason="routing_test_double")],
                            cpu_overcommit=1, qualification="unvalidated"))
                    if method == "POST" and self.path == "/v1/sandboxes":
                        assert body["sandbox_id"].startswith(double.node_id + "."), "controller sent a foreign owner prefix"
                        double.create_attempts.append(body["sandbox_id"])
                        if double.mode == "busy":
                            return self.reply(503, {"error": {"code": "busy", "message": "test double rejection"}})
                        if double.mode == "drop":
                            self.close_connection = True
                            return None
                        if double.mode == "template":
                            return self.reply(422, {"error": {"code": "template_unavailable", "message": "test double rejection"}})
                        if double.mode == "fail":
                            return self.reply(500, {"error": {"code": "incompatible_template", "message": "test double failure"}})
                        view = dict(sandbox_id=body["sandbox_id"], template_id=body["template_id"], state="running", error=None, expires_at=0)
                        double.records[body["sandbox_id"]] = view
                        return self.reply(201, view)
                    parts = self.path.split("/")
                    record = double.records.get(parts[3]) if len(parts) > 3 else None
                    if record is None:
                        return self.reply(404, {"error": {"code": "sandbox_not_found", "message": "test double"}})
                    if method == "GET" and len(parts) == 4:
                        return self.reply(200, record)
                    if method == "DELETE" and len(parts) == 4:
                        record["state"] = "deleted"
                        return self.reply(200, record)
                    if method == "POST" and parts[4:] == ["exec"]:
                        return self.reply(200, dict(exit_code=0, stdout=double.node_id, stderr="", interrupted=False, error=None, sandbox_state="running"))
                    return self.reply(404, {"error": {"code": "not_found", "message": "test double"}})

            def do_GET(self):
                self.handle_any("GET")

            def do_POST(self):
                self.handle_any("POST")

            def do_DELETE(self):
                self.handle_any("DELETE")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


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


# Launch local services and check authentication, input bounds, fail-closed readiness and stale-owner
# routing. Exercise overload and shutdown without containers; clean up processes and check logs for
# leaked tokens.
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

        # Write a service configuration, launch it with private test credentials and retain its process and
        # log for cleanup.
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

        # Terminate a service within a deadline and require a clean exit, killing it if graceful shutdown
        # stalls.
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

        # Require startup to reject the supplied configuration without printing either test credential.
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

        # Clients send only the spec; the controller picks the owner and generates the ID.
        # Runtime and architecture come from the owner's template; resources may be omitted.
        spec = {"template_id": "example-template", "memory_mib": 256, "vcpus": 1, "ttl_seconds": 300}
        # Controller-to-worker create carries the generated owner-prefixed ID.
        create = dict(spec, sandbox_id="node-a.example")
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
            for setting in ("max_body_bytes = 16385", "max_response_bytes = 8388609", "max_timeout_ms = 600001", "max_body_bytes = 16384"):
                # The final case has a valid opt-in body ceiling but insufficient
                # outer JSON envelope capacity and must also fail at startup.
                invalid_config("worker", worker_config(worker_port).replace("[auth]", "[server.application_http]\n" + setting + "\n[auth]"))
            for setting in ("create_ms = 999", "capture_ms = 3600001", "delete_ms = 0", "margin_ms = 300001", "unknown_ms = 1000"):
                invalid_config("worker", worker_config(worker_port).replace("[auth]", "[server.operation_deadlines]\n" + setting + "\n[auth]"))
                invalid_config("controller", controller_text.replace("[auth]", "[server.operation_deadlines]\n" + setting + "\n[auth]"))
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

            # Read controller status and return its worker observations indexed by node ID.
            def nodes():
                status = expect(request(controller_port, "/v1/status", controller_token), 200)
                assert status["lifecycle_implemented"]
                return {node["node_id"]: node for node in status["nodes"]}

            eventually(lambda: len(nodes()) == 2 and all(node["fresh"] for node in nodes().values()))
            for number, token, code, body in ((worker_port, worker_token, "runtime_unavailable", create), (controller_port, controller_token, "no_capacity", spec)):
                expect(request(number, "/v1/sandboxes", token, body, "POST"), 503, code)
                for change in ({"memory_mib": 0}, {"ttl_seconds": 0}, {"runtime": "runc_criu"}, {"architecture": "x86_64"}, {"memory_mib": "64"}, {"unexpected": True}, {"vcpus": -1}, {"sandbox_id": "../escape"}, {"template_id": "../escape"}, {"egress": []}, {"rootfs": "/tmp/untrusted"}):
                    expect(request(number, "/v1/sandboxes", token, dict(body, **change), "POST"), 400, "invalid_input")
                expect(request(number, "/v1/sandboxes", token, b"{", "POST"), 400, "invalid_input")
                expect(request(number, "/v1/sandboxes", token, b"x" * 2049, "POST"), 413, "body_too_large")
                expect(request(number, "/v1/sandboxes", token, iter([b"x" * 1024] * 3), "POST", True), 413, "body_too_large")
                execution = {"argv": ["echo", "hello"], "timeout_ms": 1000, "max_output_bytes": 1024}
                expect(request(number, "/v1/sandboxes/node-a.example/exec", token, execution, "POST"), 503, "runtime_unavailable")
                expect(request(number, "/v1/sandboxes/node-a.example/exec", token, dict(execution, argv=[]), "POST"), 400, "invalid_input")
                expect(request(number, "/v1/sandboxes/node-a.example/exec", token, dict(execution, timeout_ms=60001), "POST"), 400, "invalid_input")
                # The polling-era operation identifier is no longer an accepted field.
                expect(request(number, "/v1/sandboxes/node-a.example/exec", token, dict(execution, operation_id="exec-1"), "POST"), 400, "invalid_input")
                app_http = {"port":8080, "method":"GET", "path":"/", "timeout_ms":1000, "max_response_bytes":4096}
                expect(request(number, "/v1/sandboxes/node-a.example/http", token, app_http, "POST"), 503, "runtime_unavailable")
                for changes in [dict(path="http://example.invalid/"), dict(path="//example.invalid/"), dict(headers={"authorization":"not-forwarded"}), dict(port=0), dict(method="CONNECT")]:
                    expect(request(number, "/v1/sandboxes/node-a.example/http", token, dict(app_http, **changes), "POST"), 400, "invalid_input")
                expect(request(number, "/v1/sandboxes/node-a.example/http", token, dict(app_http, body="x"*8193), "POST"), 413, "body_too_large")
                capture = {"template_id": "example", "runtime": "runc_criu"}
                expect(request(number, "/v1/sandboxes/node-a.example/capture", token, capture, "POST"), 503, "runtime_unavailable")
                expect(request(number, "/v1/sandboxes/node-a.example/capture", token, dict(capture, runtime="other"), "POST"), 400, "invalid_input")
                expect(request(number, "/v1/sandboxes/node-a.example/operations/op-1", token), 404, "not_found")
                for identifier in ("%FF", "bad%2Fid"):
                    expect(request(number, f"/v1/sandboxes/{identifier}/exec", token, execution, "POST"), 400, "invalid_input")
                    expect(request(number, f"/v1/sandboxes/{identifier}/capture", token, capture, "POST"), 400, "invalid_input")
            print("PASS strict inputs/identifiers, no caller sandbox_id/operation_id, body bounds and fail-closed create/exec/capture/HTTP")

            # Send one mixed health, status or fail-closed create check to the selected service.
            def concurrent_check(index):
                number, token = (worker_port, worker_token) if index % 2 else (controller_port, controller_token)
                if index % 3 == 0:
                    expect(request(number, "/healthz"), 200)
                elif index % 3 == 1:
                    expect(request(number, "/v1/status", token), 200)
                else:
                    code, body = ("runtime_unavailable", create) if number == worker_port else ("no_capacity", spec)
                    expect(request(number, "/v1/sandboxes", token, body, "POST"), 503, code)

            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                list(pool.map(concurrent_check, range(96)))
            print("PASS 96 mixed health/status/create requests with 16 concurrent clients (not a benchmark)")

            stop(worker)
            eventually(lambda: not nodes()["node-a"]["fresh"])
            stale = nodes()["node-a"]
            assert not stale["reachable"] and stale["status"] is not None and stale["error"]
            eventually(lambda: nodes()["node-a"]["age_ms"] > 500)
            assert nodes()["node-b"]["fresh"]
            expect(request(controller_port, "/v1/sandboxes", controller_token, spec, "POST"), 503, "no_capacity")
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
max_artifact_bytes = 1048576
command_timeout_seconds = 10
'''
            invalid_config("worker", native_text.replace("cpu_overcommit = 2", "cpu_overcommit = 17"))
            invalid_config("worker", native_text.replace("cpu_overcommit = 2", "cpu_overcommit = 0"))
            # Removed polling-era retention settings are rejected, not silently ignored.
            for removed in ("max_operations_per_sandbox = 4", "max_retained_output_bytes = 16777216", "max_retained_output_per_sandbox_bytes = 8388608"):
                invalid_config("worker", native_text.replace("max_records = 8", "max_records = 8\n" + removed))
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

            # Controller placement over two workers, using routing doubles (not runtimes).
            doubles = [RoutingDouble("stub-a", worker_token), RoutingDouble("stub-b", worker_token)]
            try:
                placing_port = port()
                placing_text = controller_text.replace(f"127.0.0.1:{controller_port}", f"127.0.0.1:{placing_port}")
                placing_text = placing_text.replace('node_id = "node-a"', 'node_id = "stub-a"').replace(f"http://127.0.0.1:{worker_port}", f"http://127.0.0.1:{doubles[0].port}")
                placing_text = placing_text.replace('node_id = "node-b"', 'node_id = "stub-b"').replace(f"http://127.0.0.1:{second_port}", f"http://127.0.0.1:{doubles[1].port}")
                placing = start("controller", placing_text)
                eventually(lambda: request(placing_port, "/healthz")[0] == 200)

                def placed_nodes():
                    status = expect(request(placing_port, "/v1/status", controller_token), 200)
                    return {n["node_id"]: n for n in status["nodes"]}

                def settle(expected):
                    eventually(lambda: all(n["fresh"] and n["status"]["usage"]["sandboxes"] == expected[k] and n["status"]["admission_ready"] == doubles[i].ready
                                           for i, (k, n) in enumerate(sorted(placed_nodes().items()))), timeout=5)

                def place(code=201):
                    status, body = request(placing_port, "/v1/sandboxes", controller_token, spec, "POST")
                    assert status == code, f"expected HTTP {code}, got {status}: {body}"
                    return body

                settle({"stub-a": 0, "stub-b": 0})
                first = place()["sandbox_id"]
                assert first.startswith("stub-a.") and first in doubles[0].records
                settle({"stub-a": 1, "stub-b": 0})
                second_id = place()["sandbox_id"]
                assert second_id.startswith("stub-b.") and second_id in doubles[1].records
                assert len(first.split(".")[1]) == 32 and first.split(".")[1] != second_id.split(".")[1]
                print("PASS controller-chosen placement across both workers with generated IDs")

                for sandbox_id, double in ((first, doubles[0]), (second_id, doubles[1])):
                    result = expect(request(placing_port, f"/v1/sandboxes/{sandbox_id}/exec", controller_token, execution, "POST"), 200)
                    assert result["stdout"] == double.node_id
                    assert expect(request(placing_port, f"/v1/sandboxes/{sandbox_id}", controller_token), 200)["sandbox_id"] == sandbox_id
                    assert ("POST", f"/v1/sandboxes/{sandbox_id}/exec") in double.calls
                print("PASS later exec/GET routed to the owner by the returned ID")

                settle({"stub-a": 1, "stub-b": 1})
                doubles[0].mode = "busy"
                attempts_a = len(doubles[0].create_attempts)
                failed_over = place()["sandbox_id"]
                assert failed_over.startswith("stub-b.") and len(doubles[0].create_attempts) == attempts_a + 1
                assert doubles[0].create_attempts[-1] != failed_over, "failover must use a new ID on the next owner"
                print("PASS failover to the next candidate after a definitive pre-launch rejection")

                settle({"stub-a": 1, "stub-b": 2})
                for mode, status_code, code in (("drop", 503, "owner_response_unavailable"), ("fail", 500, "incompatible_template")):
                    doubles[0].mode = mode
                    attempts_b = len(doubles[1].create_attempts)
                    ambiguous = place(status_code)
                    assert ambiguous["error"]["code"] == code
                    assert ambiguous["sandbox_id"] == doubles[0].create_attempts[-1] and ambiguous["sandbox_id"].startswith("stub-a.")
                    assert len(doubles[1].create_attempts) == attempts_b, "ambiguous create outcome was retried on another node"
                print("PASS no failover after a lost response or post-acceptance failure; error names the generated ID")

                # A client that disconnects mid-create makes the controller drop its
                # forward, so the owner sees the lost reply (and deletes the sandbox).
                doubles[0].mode = "hang"
                attempts_a = len(doubles[0].create_attempts)
                data = json.dumps(spec).encode()
                with socket.create_connection(("127.0.0.1", placing_port), timeout=4) as raw:
                    raw.sendall((f"POST /v1/sandboxes HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {controller_token}\r\n"
                                 f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data)
                    eventually(lambda: len(doubles[0].create_attempts) == attempts_a + 1)
                eventually(lambda: doubles[0].peer_closed, timeout=5)
                print("PASS client disconnect mid-create cancels the controller's forward to the owner")

                doubles[0].mode = "template"
                minimal = {"template_id": "example-template", "ttl_seconds": 60}
                status, body = request(placing_port, "/v1/sandboxes", controller_token, minimal, "POST")
                assert status == 201 and body["sandbox_id"].startswith("stub-b."), f"template failover failed: {status} {body}"
                settle({"stub-a": 1, "stub-b": 3})
                doubles[1].mode = "template"
                rejected = expect(request(placing_port, "/v1/sandboxes", controller_token, minimal, "POST"), 422, "template_unavailable")
                assert "sandbox_id" not in rejected
                doubles[1].mode = "accept"
                print("PASS template rejection fails over; all-template rejection is 422 without an ID")

                doubles[0].mode = "accept"
                expect(request(placing_port, f"/v1/sandboxes/{first}", controller_token, method="DELETE"), 200)
                assert doubles[0].records[first]["state"] == "deleted"
                for double in doubles:
                    double.ready = False
                settle({"stub-a": 0, "stub-b": 3})
                expect(request(placing_port, "/v1/sandboxes", controller_token, spec, "POST"), 503, "no_capacity")
                print("PASS DELETE routing and no_capacity without fresh ready candidates")
                stop(placing)
            finally:
                for double in doubles:
                    double.close()
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
