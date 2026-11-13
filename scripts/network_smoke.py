#!/usr/bin/env python3
"""Bounded local network qualification, entirely in a disposable outer netns.

No public targets, host network changes, packages, modules, or cgroup provisioning.
The caller must supply the same explicit runtime authority/prepared roots as the
lifecycle smoke. The harness adds only a namespace-local bridge and local fixtures.
"""
import json
import os
import select
import socket
from pathlib import Path
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=10).stdout.decode()


def inventory():
    return {"links": json.loads(run("ip", "-j", "link")),
            "routes": json.loads(run("ip", "-j", "route", "show", "table", "all")),
            "rules": run("nft", "-s", "list", "ruleset"),
            "forwarding": Path("/proc/sys/net/ipv4/ip_forward").read_text()}


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"local-approved-fixture")

    def log_message(self, *args):
        pass


def pmtu_peer():
    assert os.geteuid() == 0 and os.readlink("/proc/self/ns/net") != os.environ["SANDBOX_TEST_PARENT_NETNS"]
    listeners = []
    for port in (18080, 18081):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen(4)
        listeners.append(listener)
    expected = bytes(i % 251 for i in range(65536))
    print("READY", flush=True)
    while True:
        ready, _, _ = select.select(listeners, [], [], 5)
        for listener in ready:
            client, _ = listener.accept()
            with client:
                client.settimeout(4)
                try:
                    data = bytearray()
                    while len(data) < len(expected):
                        chunk = client.recv(min(4096, len(expected) - len(data)))
                        if not chunk:
                            break
                        data.extend(chunk)
                    if data == expected:
                        client.sendall(b"OK65536\n")
                except OSError:
                    pass


def main():
    if sys.argv[1:] == ["--pmtu-peer"]:
        return pmtu_peer()
    if os.geteuid() != 0 or "--allow-privileged-runtime" not in sys.argv:
        raise SystemExit("requires administrator and explicit --allow-privileged-runtime")
    args = sys.argv[1:]
    if "--inside" not in args:
        before = inventory()
        env = dict(os.environ, SANDBOX_TEST_PARENT_NETNS=os.readlink("/proc/self/ns/net"))
        result = subprocess.run(["unshare", "--mount", "--net", "--fork", sys.executable, __file__, "--inside", *args], env=env, timeout=900)
        after = inventory()
        # Link counters may change, but topology/address/rules/forwarding must not.
        if before != after:
            print("INVENTORY BEFORE", json.dumps(before), "INVENTORY AFTER", json.dumps(after))
            raise AssertionError("default namespace inventory changed; inspect before any cleanup")
        print("PASS default namespace network inventory unchanged")
        raise SystemExit(result.returncode)
    args.remove("--inside")
    assert os.readlink("/proc/self/ns/net") != os.environ["SANDBOX_TEST_PARENT_NETNS"]
    assert len(json.loads(run("ip", "-j", "link"))) == 1
    # Namespace bind mounts are private to the outer mount namespace, too.
    run("mount", "--make-rprivate", "/")
    if not Path("/run/netns").is_dir():
        raise SystemExit("operator must provide existing /run/netns directory")
    run("mount", "-t", "tmpfs", "-o", "mode=700", "tmpfs", "/run/netns")
    run("ip", "link", "set", "lo", "up")
    run("ip", "link", "add", "sb-test-br", "address", "02:00:00:00:00:01", "type", "bridge")
    run("ip", "addr", "add", "198.18.0.1/24", "dev", "sb-test-br")
    run("ip", "addr", "add", "198.18.0.2/24", "dev", "sb-test-br")
    run("ip", "link", "set", "sb-test-br", "up")
    # Only the downstream router end is reduced: peer TCP MSS still advertises
    # 1500-byte MTU, so a successful payload really requires ICMP PMTU discovery.
    run("ip", "netns", "add", "sb-test-peer")
    run("ip", "link", "add", "sb-pmtu-out", "type", "veth", "peer", "name", "eth0", "netns", "sb-test-peer")
    run("ip", "addr", "add", "198.19.0.1/24", "dev", "sb-pmtu-out")
    run("ip", "link", "set", "sb-pmtu-out", "mtu", "1280", "up")
    for address in ("198.19.0.2", "198.19.0.3", "198.19.0.4"):
        run("ip", "-n", "sb-test-peer", "addr", "add", address + "/24", "dev", "eth0")
    run("ip", "-n", "sb-test-peer", "link", "set", "eth0", "mtu", "1500", "up")
    run("ip", "-n", "sb-test-peer", "link", "set", "lo", "up")
    run("ip", "-n", "sb-test-peer", "route", "add", "default", "via", "198.19.0.1")
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
    peer = None
    servers = [HTTPServer(address, Fixture) for address in [("198.18.0.1", 18080), ("198.18.0.1", 18081), ("198.18.0.2", 18080)]]
    threads = [threading.Thread(target=server.serve_forever) for server in servers]
    for thread in threads:
        thread.start()
    try:
        peer = subprocess.Popen(["ip", "netns", "exec", "sb-test-peer", sys.executable, __file__, "--pmtu-peer"],
                                env={"PATH":os.environ["PATH"], "SANDBOX_TEST_PARENT_NETNS":os.environ["SANDBOX_TEST_PARENT_NETNS"]},
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert select.select([peer.stdout], [], [], 5)[0] and peer.stdout.readline() == b"READY\n", "PMTU peer did not start"
        env = dict(os.environ, SANDBOX_TEST_OUTER_NETNS=os.readlink("/proc/self/ns/net"))
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("runtime_smoke.py")), "--network", *args], env=env, timeout=800)
    finally:
        if peer is not None:
            peer.terminate()
            try:
                peer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                peer.kill()
                peer.wait(timeout=5)
            peer.stdout.close()
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
        assert not run("ip", "netns", "pids", "sb-test-peer").strip(), "PMTU peer processes remain"
        run("ip", "link", "delete", "sb-pmtu-out")
        run("ip", "netns", "delete", "sb-test-peer")
        # Never discard namespace pins while an owned workload/helper is live.
        assert not list(Path("/run/netns").iterdir()), "owned namespace pins remain"
        run("ip", "link", "delete", "sb-test-br")
        assert [link["ifname"] for link in json.loads(run("ip", "-j", "link"))] == ["lo"]
        assert not run("nft", "list", "ruleset").strip()
        run("umount", "/run/netns")
    print("PASS outer namespace fixture/links/routes/rules/pins cleaned")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
