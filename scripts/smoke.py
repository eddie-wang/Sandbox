#!/usr/bin/env python3
"""Nonprivileged process smoke: real HTTP services, no containers or runtime substitute.

Controller placement is exercised against small worker-protocol routing doubles
(RoutingDouble). They answer only status/create/get/exec/delete routing calls, plus
app-proxy and streaming-exec forwards that check the controller hop (streaming,
headers, binary bodies, upgrades, bounds), and never claim to run a container; real
lifecycle checks are in runtime_smoke.py.
"""
import hashlib

import argparse
import base64
import concurrent.futures
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import select
import socket
import statistics
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


# Send one raw HTTP request (any method, headers and bytes body; an iterable body is sent chunked) and
# return the status, the response headers (lowercase names) and the whole body.
def exchange(port_number, method, path, headers=None, body=None, timeout=10):
    connection = http.client.HTTPConnection("127.0.0.1", port_number, timeout=timeout)
    try:
        chunked = body is not None and not isinstance(body, (bytes, str))
        connection.request(method, path, body=body, headers=headers or {}, encode_chunked=chunked)
        response = connection.getresponse()
        return response.status, {name.lower(): value for name, value in response.getheaders()}, response.read()
    finally:
        connection.close()


# Time `count` small proxied POSTs sent one after another over one kept-alive connection and return
# each round trip in seconds. A reply held back by Nagle's algorithm until the client's delayed
# acknowledgement shows up as about 40 ms per call.
def small_call_latencies(port_number, path, headers, count=60):
    connection = http.client.HTTPConnection("127.0.0.1", port_number, timeout=10)
    seconds = []
    try:
        for _ in range(count):
            started = time.perf_counter()
            connection.request("POST", path, body=b"ping", headers=headers)
            response = connection.getresponse()
            assert response.status == 200 and response.read() == b"ping", response.status
            seconds.append(time.perf_counter() - started)
    finally:
        connection.close()
    return seconds


# Run a streaming exec (server-sent events) and return the HTTP status with either the error body or
# the events as (seconds since the request, event name, decoded JSON data) in arrival order.
def exec_events(port_number, path, token, body, timeout=60):
    connection = http.client.HTTPConnection("127.0.0.1", port_number, timeout=timeout)
    try:
        started = time.monotonic()
        connection.request("POST", path, body=json.dumps(dict(body, stream=True)).encode(),
                           headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        response = connection.getresponse()
        if response.status != 200:
            return response.status, json.loads(response.read())
        assert response.getheader("Content-Type") == "text/event-stream"
        events, name = [], None
        while True:
            line = response.readline()
            if not line:
                return response.status, events
            line = line.decode().rstrip("\n")
            if line.startswith("event: "):
                name = line[len("event: "):]
            elif line.startswith("data: "):
                events.append((time.monotonic() - started, name, json.loads(line[len("data: "):])))
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

    # Start a loopback HTTP server that answers worker status, create, get, exec (blocking and
    # streaming), delete and app-proxy calls for one node ID. The mode selects accept, busy, drop,
    # template, fail or hang behavior for creates; an accepted create can be answered after a delay
    # (its record counts in the status at once, as a real worker's reservation does). The status
    # reports `vcpus` vCPUs and `max_sandboxes` slots (4 and 8 unless a test changes them); each
    # record uses one vCPU and 64 MiB.
    def __init__(self, node_id, token):
        self.node_id, self.token = node_id, token
        self.mode, self.ready, self.peer_closed, self.create_delay = "accept", True, False, 0
        self.vcpus, self.max_sandboxes = 4, 8
        self.create_attempts, self.records, self.calls = [], {}, []
        self.lock = threading.Lock()
        double = self

        class Handler(BaseHTTPRequestHandler):
            # Suppress routine request logging from the routing double.
            def log_message(self, *args):
                pass

            # Send a JSON response with the given status.
            def reply(self, status, body):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            # Read the request body: Content-Length bytes, or chunked transfer coding.
            def body_bytes(self):
                if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                    data = bytearray()
                    while True:
                        size = int(self.rfile.readline().split(b";")[0], 16)
                        if size == 0:
                            self.rfile.readline()
                            return bytes(data)
                        data += self.rfile.read(size)
                        self.rfile.readline()
                return self.rfile.read(int(self.headers.get("Content-Length") or 0))

            # Answer a proxied app request forwarded by the controller (no runtime): echo the request
            # (at once, or chunked with its end sent apart), return a chosen status with hop-by-hop
            # headers, stream chunks or a trickle, send a binary pattern, wait before answering, or
            # switch to a raw echo tunnel on upgrade.
            def proxy(self):
                app = self.path.split("/proxy/", 1)[1].split("/", 1)[1] if "/" in self.path.split("/proxy/", 1)[1] else ""
                route = "/" + app
                if route.startswith("/echo"):
                    data = self.body_bytes()
                    auth = self.headers.get("Authorization")
                    self.send_response(200)
                    for name, value in (("Content-Type", "application/octet-stream"), ("X-Echo-Path", route),
                                        ("X-Echo-Auth", "worker" if auth == "Bearer " + double.token else ("none" if auth is None else "other")),
                                        ("X-Echo-Forwarded-Host", self.headers.get("X-Forwarded-Host") or ""), ("X-Echo-Chunked", "yes" if self.headers.get("Transfer-Encoding") else "no"),
                                        ("X-Echo-Sha256", hashlib.sha256(data).hexdigest()), ("Content-Length", str(len(data)))):
                        self.send_header(name, value)
                    self.end_headers()
                    self.wfile.write(data)
                elif route == "/split":
                    # Echo the body chunked, sending the head with the data and then the final chunk a
                    # moment later (no Nagle delay on this side), as an application server may do.
                    data = self.body_bytes()
                    self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    self.protocol_version = "HTTP/1.1"
                    self.send_response(200)
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
                    time.sleep(0.002)
                    self.wfile.write(b"0\r\n\r\n")
                    self.close_connection = True
                elif route.startswith("/status/"):
                    self.send_response(int(route.split("/")[2]))
                    for name, value in (("X-Custom", "kept"), ("Connection", "X-Hop"), ("X-Hop", "dropped"), ("Content-Length", "6")):
                        self.send_header(name, value)
                    self.end_headers()
                    self.wfile.write(b"teapot")
                elif route in ("/chunks", "/trickle"):
                    self.protocol_version = "HTTP/1.1"
                    self.send_response(200)
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    count, gap = (3, 0.4) if route == "/chunks" else (6, 0.5)
                    for index in range(count):
                        part = f"part-{index}\n".encode()
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
                        self.wfile.flush()
                        time.sleep(gap)
                    self.wfile.write(b"0\r\n\r\n")
                    self.close_connection = True
                elif route.startswith("/binary/"):
                    size = int(route.split("/")[2])
                    self.send_response(200)
                    self.send_header("Content-Length", str(size))
                    self.end_headers()
                    pattern = bytes(range(256)) * 4096
                    for offset in range(0, size, len(pattern)):
                        self.wfile.write(pattern[:min(len(pattern), size - offset)])
                elif route == "/slow":
                    time.sleep(1.5)
                    self.reply(200, {"slow": True})
                elif route == "/upgrade" and (self.headers.get("Upgrade") or "").lower() == "echo":
                    self.protocol_version = "HTTP/1.1"
                    self.send_response(101)
                    self.send_header("Upgrade", "echo")
                    self.send_header("Connection", "Upgrade")
                    self.end_headers()
                    self.wfile.flush()
                    while data := self.connection.recv(65536):
                        self.connection.sendall(data)
                    self.close_connection = True
                else:
                    self.reply(404, {"error": {"code": "not_found", "message": "test double"}})

            # Stream a fake command's output as server-sent events with gaps between them.
            def exec_stream(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                frames = [("start", {"exec_id": 1})] + [("stdout", {"data": base64.b64encode(f"tick {i}\n".encode()).decode()}) for i in range(3)] \
                    + [("exit", {"exit_code": 0, "interrupted": False, "error": None, "sandbox_state": "running"})]
                for name, data in frames:
                    self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
                    self.wfile.flush()
                    time.sleep(0.3)
                self.close_connection = True

            # Check the worker token and answer one routing or proxied call from the double's records and
            # mode. In hang mode, hold a create open until the controller closes its connection; with a
            # create delay, answer an accepted create only after it.
            def handle_any(self, method):
                if self.headers.get("Authorization") != "Bearer " + double.token:
                    return self.reply(401, {"error": {"code": "unauthorized", "message": "test double"}})
                if "/proxy/" in self.path:
                    with double.lock:
                        double.calls.append((method, self.path))
                    return self.proxy()
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
                            capacity=dict(memory_mib=1024, vcpus=double.vcpus, max_sandboxes=double.max_sandboxes, max_concurrent_restores=2),
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
                        if not double.create_delay:
                            return self.reply(201, view)
                        delayed = view
                    else:
                        parts = self.path.split("/")
                        record = double.records.get(parts[3]) if len(parts) > 3 else None
                        if record is None:
                            return self.reply(404, {"error": {"code": "sandbox_not_found", "message": "test double"}})
                        if method == "GET" and len(parts) == 4:
                            return self.reply(200, record)
                        if method == "DELETE" and len(parts) == 4:
                            record["state"] = "deleted"
                            return self.reply(200, record)
                        streamed = method == "POST" and parts[4:] == ["exec"] and body.get("stream")
                        if method == "POST" and parts[4:] == ["exec"] and not streamed:
                            return self.reply(200, dict(exec_id=1, exit_code=0, stdout=double.node_id, stderr="", interrupted=False, error=None, sandbox_state="running"))
                        if not streamed:
                            return self.reply(404, {"error": {"code": "not_found", "message": "test double"}})
                # Outside the lock: a delayed create answer and the stream take a while.
                if method == "POST" and self.path == "/v1/sandboxes":
                    time.sleep(double.create_delay)
                    return self.reply(201, delayed)
                return self.exec_stream()

            # Handle a GET request.
            def do_GET(self):
                self.handle_any("GET")

            # Handle a POST request.
            def do_POST(self):
                self.handle_any("POST")

            # Handle a DELETE request.
            def do_DELETE(self):
                self.handle_any("DELETE")

            # Handle a PUT request (proxied app traffic only).
            def do_PUT(self):
                self.handle_any("PUT")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    # Stop the double's HTTP server and release its port.
    def close(self):
        self.server.shutdown()
        self.server.server_close()


# Return a worker configuration with no native runtime for the given port, node ID, concurrency limit
# and request deadline.
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


# Check pool expansion through read-only preflight, including exact ordering and validation failures.
# Native execution stays disabled and the nonexistent tool directory prevents host tool discovery.
def network_config_gate(binary, root, environment):
    base = worker_config(0).replace("max_sandboxes = 32", "max_sandboxes = 3") + '''[native]
enabled = false
root = "/sandbox-smoke-unavailable"
cgroup_parent = "/sys/fs/cgroup/sandbox-smoke-unavailable"
tools_dir = "/sandbox-smoke-unavailable/tools"
cpu_overcommit = 1
pids_max = 64
max_records = 8
max_artifact_bytes = 67108864
command_timeout_seconds = 30
[native.network]
bridge = "sandbox0"
gateway = "198.18.0.1"
prefix = 24
egress = []
service_ports = [8080]
'''
    config = root / "network-config.toml"

    # Run the real parser and validator; a valid disabled configuration still reports non-readiness.
    # Never accept a failed validation as a preflight report or expose a test token in diagnostics.
    def check(pool, expected=None, error=None, replacements=()):
        text = base + pool + "\n"
        for old, new in replacements:
            text = text.replace(old, new)
        config.write_text(text)
        result = subprocess.run([binary, "preflight", "--config", str(config)], env=environment,
                                capture_output=True, timeout=3)
        assert result.returncode != 0, "disabled native runtime must not be ready"
        assert environment["SANDBOX_WORKER_TOKEN"].encode() not in result.stdout + result.stderr
        if error is not None:
            assert not result.stdout and error.encode() in result.stderr, (pool, result.stdout, result.stderr)
        else:
            assert result.stdout, (pool, result.stderr)
            report = json.loads(result.stdout)
            assert not report["ready"] and report["network_addresses"] == expected, report
            assert not next(c["ok"] for c in report["checks"] if c["name"] == "explicitly_enabled")

    check("slots = 3", ["198.18.0.2", "198.18.0.3", "198.18.0.4"])
    check('slots = 3\nfirst_address = "198.18.0.10"', ["198.18.0.10", "198.18.0.11", "198.18.0.12"])
    check('slots = 3\nfirst_address = "198.18.0.1"', ["198.18.0.2", "198.18.0.3", "198.18.0.4"])
    check('slots = 3\nfirst_address = "198.18.0.10"', ["198.18.0.10", "198.18.0.12", "198.18.0.13"],
          replacements=[('gateway = "198.18.0.1"', 'gateway = "198.18.0.11"')])
    check("slots = 3", ["198.18.0.2", "198.18.0.4", "198.18.0.5"],
          replacements=[("egress = []", 'egress = [{ip="198.18.0.3", port=443}]')])
    check('slots = 3\nfirst_address = "198.18.0.254"', ["198.18.0.254", "198.18.0.255", "198.18.1.0"],
          replacements=[("prefix = 24", "prefix = 23")])
    check("slots = 1", ["198.18.0.2"], replacements=[("max_sandboxes = 3", "max_sandboxes = 1"),
                                                     ("max_concurrent_restores = 2", "max_concurrent_restores = 1")])
    check("slots = 256", [f"198.18.0.{i}" for i in range(2, 256)] + ["198.18.1.0", "198.18.1.1"],
          replacements=[("prefix = 24", "prefix = 23")])
    explicit = 'addresses = ["198.18.0.12", "198.18.0.10", "198.18.0.11"]'
    check(explicit, ["198.18.0.12", "198.18.0.10", "198.18.0.11"])
    choice_error = "configure exactly one of native.network.addresses or native.network.slots"
    for pool in ("", explicit + "\nslots = 3", "addresses = []\nslots = 3", 'first_address = "198.18.0.10"'):
        check(pool, error=choice_error)
    check(explicit + '\nfirst_address = "198.18.0.10"', error="first_address requires slots")
    for slots in (0, 257):
        check(f"slots = {slots}", error="slots must be between 1 and 256")
    check("slots = 2", error="network slots must cover sandbox capacity")
    check("slots = 3", error="slot address range exhausted", replacements=[("prefix = 24", "prefix = 30")])
    check('slots = 3\nfirst_address = "198.18.0.253"', error="slot address range exhausted")
    check("slots = 3", error="slot address range exhausted",
          replacements=[('gateway = "198.18.0.1"', 'gateway = "198.18.0.254"')])
    check('slots = 3\nfirst_address = "198.18.0.252"', error="slot address range exhausted",
          replacements=[("egress = []", 'egress = [{ip="198.18.0.253", port=443}]')])
    for first in ("198.18.0.0", "198.18.0.255", "198.18.1.10", "0.0.0.0", "255.255.255.255"):
        check(f'slots = 3\nfirst_address = "{first}"', error="first address must be inside the gateway subnet")
    for prefix in (0, 7, 31, 32, 255):
        check("slots = 3", error="invalid native network policy or address pool",
              replacements=[("prefix = 24", f"prefix = {prefix}")])
    for gateway in ("198.18.0.0", "224.0.0.1"):
        check("slots = 3", error="invalid native network policy or address pool",
              replacements=[('gateway = "198.18.0.1"', f'gateway = "{gateway}"')])
    for pool in ('addresses = []', 'addresses = ["198.18.0.2", "198.18.0.2", "198.18.0.3"]',
                 'addresses = ["198.18.0.1", "198.18.0.2", "198.18.0.3"]',
                 'addresses = ["198.18.0.0", "198.18.0.255", "198.18.1.1"]'):
        check(pool, error="invalid native network policy or address pool")
    check(explicit, error="invalid native network policy or address pool",
          replacements=[("egress = []", 'egress = [{ip="198.18.0.10", port=443}]')])
    for pool in ('slots = "3"', "slots = -1", "slots = 3\nunknown = 1",
                 'slots = 3\nfirst_address = ' + json.dumps(environment["SANDBOX_WORKER_TOKEN"])):
        check(pool, error="invalid configuration: check fields and types")
    print("PASS network slots: exact expansion, gateway/egress skip, subnet bounds, explicit-list compatibility and config errors")


# Launch services and check network pool configuration, authentication, input bounds and proxy routing.
# Check fail-closed readiness, stale-owner routing, controller placement, ID routing, failover and the
# controller's proxy and streaming-exec hop against routing doubles, and overload and shutdown, all
# without containers; clean up processes and check logs for leaked tokens.
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
        controller_text = f'''proxy_domain = "sandbox.test"
[server]
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
            # The removed JSON application HTTP operation's limits are rejected, not silently ignored.
            invalid_config("worker", worker_config(worker_port).replace("[auth]", "[server.application_http]\nmax_body_bytes = 8192\n[auth]"))
            invalid_config("controller", controller_text.replace("[auth]", "[server.application_http]\nmax_body_bytes = 8192\n[auth]"))
            for setting in ("max_connections = 0", "max_connections = 65537", "idle_timeout_ms = 999", "idle_timeout_ms = 3600001", "unknown = 1"):
                invalid_config("worker", worker_config(worker_port).replace("[auth]", "[server.proxy]\n" + setting + "\n[auth]"))
            for domain in ("Sandbox.Test", "sandbox_test", "-sandbox.test", "sandbox..test", ""):
                invalid_config("controller", controller_text.replace('proxy_domain = "sandbox.test"', f'proxy_domain = "{domain}"'))
            for setting in ("create_ms = 999", "capture_ms = 3600001", "delete_ms = 0", "margin_ms = 300001", "unknown_ms = 1000"):
                invalid_config("worker", worker_config(worker_port).replace("[auth]", "[server.operation_deadlines]\n" + setting + "\n[auth]"))
                invalid_config("controller", controller_text.replace("[auth]", "[server.operation_deadlines]\n" + setting + "\n[auth]"))
            network_config_gate(binary, root, environment)
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
                # The JSON application HTTP operation is removed; app traffic uses the proxy.
                expect(request(number, "/v1/sandboxes/node-a.example/http", token, {"port": 8080}, "POST"), 404, "not_found")
                expect(request(number, "/v1/sandboxes/node-a.example/exec", token, dict(execution, stream=True), "POST"), 503, "runtime_unavailable")
                expect(request(number, "/v1/sandboxes/node-a.example/exec", token, dict(execution, stream="yes"), "POST"), 400, "invalid_input")
                expect(request(number, "/v1/sandboxes/node-a.example/exec/1/kill", token, method="POST"), 503, "runtime_unavailable")
                expect(request(number, "/v1/sandboxes/node-a.example/exec/one/kill", token, method="POST"), 400, "invalid_input")
                for method in ("GET", "POST", "PUT", "DELETE"):
                    expect(request(number, "/v1/sandboxes/node-a.example/proxy/8080/app?x=1", method=method), 401, "unauthorized")
                    expect(request(number, "/v1/sandboxes/node-a.example/proxy/8080/app?x=1", token, method=method), 503, "runtime_unavailable")
                expect(request(number, "/v1/sandboxes/node-a.example/proxy/8080", token), 503, "runtime_unavailable")
                for invalid in ("/v1/sandboxes/node-a.example/proxy/0/", "/v1/sandboxes/node-a.example/proxy/080/", "/v1/sandboxes/node-a.example/proxy/65536/", "/v1/sandboxes/node-a.example/proxy/web/", "/v1/sandboxes/bad%2Fid/proxy/8080/"):
                    expect(request(number, invalid, token), 400, "invalid_input")
                capture = {"template_id": "example", "runtime": "runc_criu"}
                expect(request(number, "/v1/sandboxes/node-a.example/capture", token, capture, "POST"), 503, "runtime_unavailable")
                expect(request(number, "/v1/sandboxes/node-a.example/capture", token, dict(capture, runtime="other"), "POST"), 400, "invalid_input")
                expect(request(number, "/v1/sandboxes/node-a.example/operations/op-1", token), 404, "not_found")
                for identifier in ("%FF", "bad%2Fid"):
                    expect(request(number, f"/v1/sandboxes/{identifier}/exec", token, execution, "POST"), 400, "invalid_input")
                    expect(request(number, f"/v1/sandboxes/{identifier}/capture", token, capture, "POST"), 400, "invalid_input")
            # Host routing (AgentENV `<port>-<sandbox-id>.<domain>`) is a controller feature; the
            # controller authenticates first, then routes by the ID's owner prefix.
            routed = {"Host": "8080-node-a.example.sandbox.test:443"}
            assert exchange(controller_port, "GET", "/healthz", routed)[0] == 401, "host-routed /healthz is app traffic and needs authentication"
            authorized = dict(routed, Authorization="Bearer " + controller_token)
            for path in ("/", "/healthz", "/v1/status", "/any/app/path?q=1"):
                status, _, body = exchange(controller_port, "GET", path, authorized)
                assert status == 503 and json.loads(body)["error"]["code"] == "runtime_unavailable", (path, status, body)
            for host in ("x-node-a.example.sandbox.test", "0-node-a.example.sandbox.test", "8080-bad id.sandbox.test", "8080-noprefix.sandbox.test"):
                status, _, body = exchange(controller_port, "GET", "/", {"Host": host, "Authorization": "Bearer " + controller_token})
                assert status == 400 and json.loads(body)["error"]["code"] == "invalid_input", (host, status)
            status, _, body = exchange(controller_port, "GET", "/", {"Host": "8080-unknown-node.example.sandbox.test", "Authorization": "Bearer " + controller_token})
            assert status == 400, (status, body)
            for host in ("sandbox.test", "nohyphen.sandbox.test", "8080-node-a.example.other.test"):
                answer = exchange(controller_port, "GET", "/v1/status", {"Host": host, "Authorization": "Bearer " + controller_token})
                assert answer[0] == 200, (host, answer)
            # Workers have no proxy domain: the Host header never routes there.
            assert exchange(worker_port, "GET", "/v1/status", dict(routed, Authorization="Bearer " + worker_token))[0] == 200
            print("PASS strict inputs/identifiers, no caller sandbox_id/operation_id, body bounds and fail-closed create/exec/kill/capture/proxy")
            print("PASS proxy path form, host routing below the configured domain only, authentication before routing")

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
                placing_text = placing_text.replace("[auth]", "[server.proxy]\nmax_connections = 4\nidle_timeout_ms = 1000\n[auth]")
                placing = start("controller", placing_text)
                eventually(lambda: request(placing_port, "/healthz")[0] == 200)

                # Return the placement controller's worker observations indexed by node ID.
                def placed_nodes():
                    status = expect(request(placing_port, "/v1/status", controller_token), 200)
                    return {n["node_id"]: n for n in status["nodes"]}

                # Wait until both doubles are fresh with the expected sandbox counts and readiness.
                def settle(expected):
                    eventually(lambda: all(n["fresh"] and n["status"]["usage"]["sandboxes"] == expected[k] and n["status"]["admission_ready"] == doubles[i].ready
                                           for i, (k, n) in enumerate(sorted(placed_nodes().items()))), timeout=5)

                # Create through the placement controller, require the given status and return the body.
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

                # The controller hop of the app proxy, against the routing double standing in for the
                # owner (the worker hop and real sandboxes are covered by the privileged gates).
                bearer = {"Authorization": "Bearer " + controller_token}
                prefix = f"/v1/sandboxes/{first}/proxy/9000"
                status, headers, body = exchange(placing_port, "GET", prefix + "/echo/a%2Fb?x=1&y=%20", dict(bearer, **{"X-Forwarded-Host": "spoofed.example"}))
                assert status == 200 and headers["x-echo-path"] == "/echo/a%2Fb?x=1&y=%20", headers
                assert headers["x-echo-auth"] == "worker" and headers["x-echo-forwarded-host"] == f"127.0.0.1:{placing_port}", headers
                assert ("GET", prefix + "/echo/a%2Fb?x=1&y=%20") in doubles[0].calls and not any("/proxy/" in path for _, path in doubles[1].calls)
                upload = os.urandom(4 << 20)
                status, headers, body = exchange(placing_port, "POST", prefix + "/echo", dict(bearer, **{"Content-Type": "application/x-test"}), upload, timeout=30)
                assert status == 200 and body == upload and headers["x-echo-sha256"] == hashlib.sha256(upload).hexdigest() and headers["x-echo-chunked"] == "no"
                status, headers, body = exchange(placing_port, "PUT", prefix + "/echo", bearer, iter([upload[:1 << 20], upload[1 << 20:]]), timeout=30)
                assert status == 200 and body == upload and headers["x-echo-chunked"] == "yes"
                status, headers, body = exchange(placing_port, "GET", prefix + "/status/418", bearer)
                assert status == 418 and body == b"teapot" and headers["x-custom"] == "kept" and "x-hop" not in headers, headers
                status, headers, body = exchange(placing_port, "GET", prefix + "/binary/8388608", bearer, timeout=30)
                assert status == 200 and headers["content-length"] == "8388608" and body == (bytes(range(256)) * 32768)
                # Chunked parts arrive as they are sent, not after the whole response.
                connection = http.client.HTTPConnection("127.0.0.1", placing_port, timeout=10)
                started = time.monotonic()
                connection.request("GET", prefix + "/chunks", headers=bearer)
                response = connection.getresponse()
                arrivals = []
                for _ in range(3):
                    line = response.readline()
                    arrivals.append((time.monotonic() - started, line))
                assert response.read() == b"" and [line for _, line in arrivals] == [b"part-0\n", b"part-1\n", b"part-2\n"]
                assert arrivals[2][0] - arrivals[0][0] >= 0.6 and response.getheader("Transfer-Encoding") == "chunked", arrivals
                connection.close()
                # Host form reaches the same owner and application path.
                status, headers, _ = exchange(placing_port, "GET", "/echo?h=1", dict(bearer, Host=f"9000-{first}.sandbox.test"))
                assert status == 200 and headers["x-echo-path"] == "/echo?h=1" and headers["x-echo-forwarded-host"] == f"9000-{first}.sandbox.test"
                # An upgrade answered with 101 becomes a byte tunnel through the controller.
                with socket.create_connection(("127.0.0.1", placing_port), timeout=5) as tunnel:
                    tunnel.sendall((f"GET {prefix}/upgrade HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {controller_token}\r\n"
                                    "Connection: Upgrade\r\nUpgrade: echo\r\n\r\n").encode())
                    head = b""
                    while b"\r\n\r\n" not in head:
                        head += tunnel.recv(4096)
                    assert head.startswith(b"HTTP/1.1 101") and b"upgrade: echo" in head.lower(), head
                    for message in (b"ping", os.urandom(100000)):
                        tunnel.sendall(message)
                        echoed = b""
                        while len(echoed) < len(message):
                            echoed += tunnel.recv(65536)
                        assert echoed == message
                # Small calls on one kept-alive connection are not held back by Nagle's algorithm.
                latencies = small_call_latencies(placing_port, prefix + "/split", bearer)
                small_call_p50 = statistics.median(latencies)
                assert small_call_p50 < 0.010, f"small proxied call p50 {small_call_p50 * 1000:.1f} ms"
                print(f"INFO small proxied call through the controller: p50 {small_call_p50 * 1000:.2f} ms, max {max(latencies) * 1000:.2f} ms over {len(latencies)} calls")
                # A streaming exec's events pass through as the owner sends them.
                status, events = exec_events(placing_port, f"/v1/sandboxes/{first}/exec", controller_token, execution)
                assert status == 200 and [name for _, name, _ in events] == ["start", "stdout", "stdout", "stdout", "exit"], events
                assert events[-1][0] - events[0][0] >= 1.0 and base64.b64decode(events[1][2]["data"]) == b"tick 0\n"
                # Bounds: the owner must send something within the idle timeout, and open exchanges are
                # limited (four here); a released permit is reusable.
                status, _, body = exchange(placing_port, "GET", prefix + "/slow", bearer)
                assert status == 504 and json.loads(body)["error"]["code"] == "owner_response_timeout"
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    held = [pool.submit(exchange, placing_port, "GET", prefix + "/trickle", bearer) for _ in range(4)]
                    eventually(lambda: sum(path == prefix + "/trickle" for _, path in doubles[0].calls) == 4)
                    status, _, body = exchange(placing_port, "GET", prefix + "/echo", bearer)
                    assert status == 503 and json.loads(body)["error"]["code"] == "busy"
                    assert all(f.result(timeout=10)[2] == b"".join(f"part-{i}\n".encode() for i in range(6)) for f in held)
                assert exchange(placing_port, "GET", prefix + "/echo", bearer)[0] == 200
                expect(request(placing_port, prefix + "/echo"), 401, "unauthorized")
                print("PASS controller proxy hop: owner routing, worker credential, forwarded host, raw paths, 4 MiB uploads (length and chunked), "
                      "real status/headers, 8 MiB binary, streamed chunks, host form, upgrade tunnel, small-call p50 under 10 ms, streaming exec, idle and connection bounds")

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
                # The controller counts those ambiguous creates against stub-a until a poll sent after
                # their answers; wait for one so stub-a ranks first again.
                time.sleep(0.4)
                settle({"stub-a": 1, "stub-b": 2})

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

                # Creates sent at the same moment spread over equal workers: the controller counts its
                # own in-flight and not-yet-polled creates, and equal scores take turns. Each double
                # answers creates only after 0.5 s, so every create ranks before any answer.
                spreading = [RoutingDouble("spread-a", worker_token), RoutingDouble("spread-b", worker_token)]
                doubles.extend(spreading)
                spread_port = port()
                spread_text = placing_text.replace(f"127.0.0.1:{placing_port}", f"127.0.0.1:{spread_port}")
                spread_text = spread_text.replace('node_id = "stub-a"', 'node_id = "spread-a"').replace(f"http://127.0.0.1:{doubles[0].port}", f"http://127.0.0.1:{spreading[0].port}")
                spread_text = spread_text.replace('node_id = "stub-b"', 'node_id = "spread-b"').replace(f"http://127.0.0.1:{doubles[1].port}", f"http://127.0.0.1:{spreading[1].port}")
                spread = start("controller", spread_text)
                eventually(lambda: request(spread_port, "/healthz")[0] == 200)
                eventually(lambda: all(n["fresh"] for n in expect(request(spread_port, "/v1/status", controller_token), 200)["nodes"]))
                for double in spreading:
                    double.create_delay = 0.5
                light = {"template_id": "example-template", "memory_mib": 64, "ttl_seconds": 300}
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    placed = [f.result(timeout=30) for f in [pool.submit(request, spread_port, "/v1/sandboxes", controller_token, light, "POST", timeout=10) for _ in range(8)]]
                assert all(code == 201 for code, _ in placed), placed
                split = {double.node_id: len(double.records) for double in spreading}
                print("spread of 8 simultaneous creates:", split)
                assert all(3 <= count <= 5 for count in split.values()), f"simultaneous creates were not spread: {split}"
                print("PASS 8 simultaneous creates split across two equal workers (in-flight placements counted, round-robin ties)")

                # Return the spreading controller's view of one node's status.
                def spread_status(node_id):
                    nodes = expect(request(spread_port, "/v1/status", controller_token), 200)["nodes"]
                    return next(n for n in nodes if n["node_id"] == node_id)["status"]

                # A node with exactly one free slot while one create is still in flight is still
                # offered: its polled usage already counts that create, so the controller's own entry
                # for it only orders nodes and must not cause a false no_capacity.
                tight = spreading[0]
                spreading[1].ready = False
                tight.max_sandboxes = tight.vcpus = len(tight.records) + 2
                tight.create_delay = 1.5
                eventually(lambda: not spread_status("spread-b")["admission_ready"] and spread_status("spread-a")["capacity"]["max_sandboxes"] == tight.max_sandboxes)
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    in_flight = pool.submit(request, spread_port, "/v1/sandboxes", controller_token, light, "POST", timeout=10)
                    eventually(lambda: spread_status("spread-a")["usage"]["sandboxes"] == tight.max_sandboxes - 1, timeout=1)
                    assert not in_flight.done(), "the in-flight create was answered before the next one was placed"
                    code, body = request(spread_port, "/v1/sandboxes", controller_token, light, "POST", timeout=10)
                    assert code == 201 and body["sandbox_id"].startswith("spread-a."), f"last free slot was not offered: {code} {body}"
                    assert in_flight.result(timeout=10)[0] == 201
                assert len(tight.records) == tight.max_sandboxes
                stop(spread)
                print("PASS a node with one free slot and one in-flight create is still offered (no false no_capacity)")
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
