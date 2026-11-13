#!/usr/bin/env python3
"""Minimal real-image end-to-end gate. Explicitly privileged; never run by smoke.py.

Builds a cold template from an OCI image (layout directory or layout tar, optionally
fetched first with regctl, skopeo or crane), then drives the controller's API: cold
create, wait for the in-container HTTP server through the app proxy (path and host
forms), exec, reaping PID 1, marker write, a streamed long-running command, two
concurrent commands, a WebSocket echo server run by a streaming command and reached
through the proxy, kill, bounded commands that stop without stopping the sandbox,
per-call overhead (proxy call, direct call inside the sandbox, exec round trip),
warm capture (the worker freezes the source, seals its upper into an EROFS layer,
checkpoints it leaving it running and thaws it; a probe shows the source answering
except while it is stopped), two independent child restores (the second reuses
the node's checkpoint cache), HTTP and marker checks in the children, source/child
isolation, delete and cleanup checks, then a graceful worker restart and a cold
create that trusts the saved verified-layer state instead of rehashing the base.
Printed timings are informational, not benchmarks.

Networking runs entirely inside a disposable outer network/mount namespace, as in
network_smoke.py. The template allows only the service port and the next port (for
the WebSocket server); no egress.
"""
import argparse
import base64
import concurrent.futures
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform as host_platform
import queue
import re
import secrets
import shutil
import socket
import stat
import statistics
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

from network_smoke import inventory, run
from runtime_smoke import checkpoint_cache, watch_frozen, cold_manifest, preflight_compatibility, publish_layer, write_template
from smoke import eventually, exchange, expect, port, request as smoke_request

INDEX_TYPES = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
MARKER = "/workspace/sandbox-e2e-marker"
CHILD_ONLY = "/workspace/sandbox-e2e-child-only"
BRIDGE = "sb-test-br"

# A minimal WebSocket echo server (RFC 6455 handshake, unfragmented frames) for the proxy check; it
# runs inside the sandbox as a streaming command, with the port as its argument.
WS_SERVER = """import base64, hashlib, socket, struct, sys
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", int(sys.argv[1])))
listener.listen(4)
print("listening", flush=True)
while True:
    client, _ = listener.accept()
    with client:
        head = b""
        while b"\\r\\n\\r\\n" not in head:
            head += client.recv(4096)
        key = [line.split(b":", 1)[1].strip() for line in head.split(b"\\r\\n") if line.lower().startswith(b"sec-websocket-key:")][0]
        accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        client.sendall(b"HTTP/1.1 101 Switching Protocols\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Accept: " + accept + b"\\r\\n\\r\\n")
        stream = client.makefile("rb")
        while len(first := stream.read(2)) == 2:
            opcode, size = first[0] & 15, first[1] & 127
            if size == 126:
                size = struct.unpack(">H", stream.read(2))[0]
            elif size == 127:
                size = struct.unpack(">Q", stream.read(8))[0]
            mask = stream.read(4)
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(stream.read(size)))
            if opcode == 8:
                client.sendall(bytes([0x88, 0]))
                break
            length = bytes([len(payload)]) if len(payload) < 126 else (bytes([126]) + struct.pack(">H", len(payload)) if len(payload) < 65536 else bytes([127]) + struct.pack(">Q", len(payload)))
            client.sendall(bytes([0x80 | opcode]) + length + payload)
"""


class UnpackError(Exception):
    pass


# Parses arguments shared by the outer (host namespace) and inner (disposable
# namespace) phases. The inner phase receives the same arguments plus --inside.
def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--allow-privileged-runtime", action="store_true")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--oci-layout", help="OCI image layout directory (the fetch target when --image is given)")
    source.add_argument("--oci-tar", help="Tar archive of an OCI image layout")
    parser.add_argument("--image", help="Image reference to fetch into --oci-layout (must not exist yet)")
    parser.add_argument("--fetch-tool", help="regctl, skopeo or crane executable; default: first one found on PATH")
    parser.add_argument("--fetch-only", action="store_true", help="Fetch --image into --oci-layout and stop (no privilege needed)")
    parser.add_argument("--platform", default="linux/" + {"x86_64": "amd64", "aarch64": "arm64"}.get(host_platform.machine(), host_platform.machine()))
    parser.add_argument("--port", type=int, default=8000, help="Service port of the in-container HTTP server (the next port serves the WebSocket check)")
    parser.add_argument("--init-argv", help="JSON argv of the workload; default: python3 -m http.server PORT --bind 0.0.0.0")
    parser.add_argument("--no-image-env", action="store_true", help="Do not pass the image config Env to the workload via env(1)")
    parser.add_argument("--keep-image-resolver", action="store_true", help="Keep the image's /etc/resolv.conf and /etc/hosts as shipped")
    parser.add_argument("--http-path", default="/")
    parser.add_argument("--expect-body", default="Directory listing", help="Substring the first HTTP response body must contain")
    parser.add_argument("--exec-argv", help="JSON argv of the exec check; default prints the UID and working directory with python3")
    parser.add_argument("--exec-expect", default="exec-ok 65534 /workspace")
    parser.add_argument("--shell", default="sh", help="Shell inside the image used for marker writes/checks")
    parser.add_argument("--memory-mib", type=int, default=256)
    parser.add_argument("--vcpus", type=int, default=1)
    parser.add_argument("--pids-max", type=int, default=128)
    parser.add_argument("--ready-timeout", type=float, default=60)
    parser.add_argument("--binary", default="target/debug/sandboxd")
    parser.add_argument("--root", help="Existing trusted directory on ext4/XFS/Btrfs; a session root is retained under it")
    parser.add_argument("--cgroup-parent", help="Existing empty delegated domain; cpu memory pids already enabled")
    parser.add_argument("--tools-dir", help="Optional existing administrator-staged trusted tool directory")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--session", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.image and not args.oci_layout:
        parser.error("--image needs --oci-layout as the fetch target")
    if args.fetch_only:
        if not args.image:
            parser.error("--fetch-only needs --image")
        return args
    if not (args.oci_layout or args.oci_tar):
        parser.error("give --oci-layout or --oci-tar")
    if not args.allow_privileged_runtime or os.geteuid() != 0:
        parser.error("requires explicit opt-in and administrator execution on an approved host")
    if not args.root or not args.cgroup_parent:
        parser.error("--root and --cgroup-parent are required")
    if not str(Path(args.cgroup_parent).resolve()).startswith("/sys/fs/cgroup/"):
        parser.error("cgroup parent must be below /sys/fs/cgroup")
    if not 0 < args.port < 65535:
        parser.error("invalid --port")
    return args


# Fetches one platform of an image reference into a new OCI layout directory with
# an already installed tool. The caller's environment (including proxies) is kept.
def fetch_image(ref, layout, tool, platform):
    if layout.exists():
        raise SystemExit(f"fetch target already exists: {layout}")
    tool = tool or next((found for name in ("regctl", "skopeo", "crane") if (found := shutil.which(name))), None)
    if not tool:
        raise SystemExit("no regctl, skopeo or crane available; supply a local --oci-layout or --oci-tar instead")
    os_name, arch = platform.split("/", 1)
    name = Path(tool).name
    if name == "regctl":
        command = [tool, "image", "copy", "--platform", platform, ref, f"ocidir://{layout}:image"]
    elif name == "skopeo":
        command = [tool, "copy", "--override-os", os_name, "--override-arch", arch, f"docker://{ref}", f"oci:{layout}:image"]
    elif name == "crane":
        command = [tool, "pull", "--format=oci", "--platform", platform, ref, str(layout)]
    else:
        raise SystemExit("--fetch-tool must be regctl, skopeo or crane")
    started = time.monotonic()
    result = subprocess.run(command, timeout=900, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(f"image fetch failed (registry access?): {result.stderr.strip()[-2000:]}")
    print(f"PASS fetched {ref} for {platform} with {name} into {layout} in {time.monotonic() - started:.1f}s")


# Returns the path of a content-addressed blob after checking its size and sha256.
def blob(layout, descriptor):
    algorithm, value = descriptor["digest"].split(":", 1)
    if algorithm != "sha256" or not re.fullmatch("[0-9a-f]{64}", value):
        raise UnpackError("unsupported blob digest " + descriptor["digest"])
    path = layout / "blobs" / "sha256" / value
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    if digest.hexdigest() != value or ("size" in descriptor and size != descriptor["size"]):
        raise UnpackError("blob digest or size mismatch " + descriptor["digest"])
    return path


# Reads a verified JSON blob (manifest, index or image config), bounded to 4 MiB.
def json_blob(layout, descriptor):
    path = blob(layout, descriptor)
    if path.stat().st_size > 4 << 20:
        raise UnpackError("metadata blob too large")
    return json.loads(path.read_bytes())


# Chooses the image manifest for the requested platform, descending through
# nested indexes. Returns the manifest descriptor and the parsed manifest.
def select_manifest(layout, platform):
    os_name, arch = platform.split("/", 1)
    candidates = json.loads((layout / "index.json").read_text())["manifests"]
    for _ in range(4):
        matching = [d for d in candidates if "platform" not in d
                    or (d["platform"].get("os") == os_name and d["platform"].get("architecture") == arch)]
        if len(matching) != 1:
            raise UnpackError(f"expected exactly one manifest for {platform}, found {len(matching)}")
        descriptor = matching[0]
        document = json_blob(layout, descriptor)
        media = descriptor.get("mediaType") or document.get("mediaType")
        if media in MANIFEST_TYPES:
            return descriptor, document
        if media not in INDEX_TYPES:
            raise UnpackError(f"unsupported manifest media type {media}")
        candidates = document["manifests"]
    raise UnpackError("image index nesting too deep")


class HashingReader:
    """Read-only stream wrapper that hashes the uncompressed layer tar (diff_id)."""

    # Wraps a decompressed layer stream.
    def __init__(self, stream):
        self.stream, self.digest = stream, hashlib.sha256()

    # Reads and hashes the next chunk.
    def read(self, size=-1):
        data = self.stream.read(size)
        self.digest.update(data)
        return data

    # Hashes the remaining bytes (tar end padding) and returns the sha256 digest.
    def finish(self):
        while self.read(1 << 20):
            pass
        return "sha256:" + self.digest.hexdigest()


# Opens a decompressed stream for a layer blob by media type. zstd uses the
# installed zstd tool; the returned process (or None) must be waited for.
def open_layer(path, media):
    if media.endswith("+gzip") or media.endswith(".tar.gzip"):
        return gzip.open(path, "rb"), None
    if media.endswith("+zstd"):
        process = subprocess.Popen(["zstd", "-dc", str(path)], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL)
        return process.stdout, process
    if media.endswith(".tar") or media.endswith(".tar.v1") or media.endswith("layer.v1.tar"):
        return path.open("rb"), None
    raise UnpackError(f"unsupported layer media type {media}")


# Splits an archive member name into clean components. Rejects ".." and empty
# names; a leading "/" or "./" is treated as relative to the image root.
def clean_parts(name):
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise UnpackError("path traversal in layer member " + repr(name))
    return parts


# Removes a file, symlink or whole directory tree without following symlinks.
def remove_any(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    elif os.path.lexists(path):
        os.unlink(path)


class Rootfs:
    """Applies OCI layers to a host directory, never writing outside it."""

    # Starts from an existing empty root directory.
    def __init__(self, root):
        self.root = os.path.realpath(root)
        self.whiteouts = self.opaque = 0

    # Returns the host path of a directory inside the image, following image
    # symlinks as if chrooted (absolute targets restart at the image root and ".."
    # stops at it). Missing directories are created when create is true.
    def directory(self, parts, create=True):
        current, pending, hops = [], list(parts), 0
        while pending:
            part = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                if current:
                    current.pop()
                continue
            host = os.path.join(self.root, *current, part)
            try:
                mode = os.lstat(host).st_mode
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(host, 0o755)
                current.append(part)
                continue
            if stat.S_ISLNK(mode):
                hops += 1
                if hops > 40:
                    raise UnpackError("too many symlinks resolving " + "/".join(parts))
                target = os.readlink(host)
                if target.startswith("/"):
                    current = []
                pending = target.split("/") + pending
            elif stat.S_ISDIR(mode):
                current.append(part)
            else:
                raise UnpackError("layer path crosses a non-directory: " + "/".join(parts))
        return os.path.join(self.root, *current)

    # Returns the absolute in-image path of the first PATH directory that has an
    # entry named program, or None.
    def which(self, program, search_path):
        for directory in search_path.split(":"):
            if not directory.startswith("/"):
                continue
            try:
                host = self.directory(clean_parts(directory), create=False)
            except (FileNotFoundError, UnpackError):
                continue
            if os.path.lexists(os.path.join(host, program)):
                return directory.rstrip("/") + "/" + program
        return None

    # Removes everything below a directory that the current layer did not create
    # (opaque whiteout). Entries of the current layer are kept.
    def purge_lower(self, directory, created):
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if path not in created:
                remove_any(path)
            elif os.path.isdir(path) and not os.path.islink(path):
                self.purge_lower(path, created)

    # Applies ownership, permission bits (including setuid/setgid/sticky) and mtime.
    @staticmethod
    def metadata(path, member):
        os.lchown(path, member.uid, member.gid)
        if not member.issym():
            os.chmod(path, member.mode & 0o7777)
        os.utime(path, (member.mtime, member.mtime), follow_symlinks=False)

    # Applies one layer tar stream in order, handling .wh. whiteouts and opaque
    # directories, regular files, directories, symlinks, hardlinks, devices and FIFOs.
    def apply(self, stream):
        created, directories = set(), {}
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                parts = clean_parts(member.name)
                if not parts:
                    continue  # the layer's own "./" entry; the root stays root-owned 0755
                parent = self.directory(parts[:-1])
                name = parts[-1]
                if name == ".wh..wh..opq":
                    self.purge_lower(parent, created)
                    self.opaque += 1
                    continue
                if name.startswith(".wh."):
                    if name[4:] in ("", ".", ".."):
                        raise UnpackError("invalid whiteout " + repr(member.name))
                    hidden = os.path.join(parent, name[4:])
                    # Whiteouts hide lower-layer entries only, never this layer's.
                    if hidden not in created:
                        remove_any(hidden)
                        self.whiteouts += 1
                    continue
                path = os.path.join(parent, name)
                if member.isdir():
                    if not (os.path.isdir(path) and not os.path.islink(path)):
                        remove_any(path)
                        os.mkdir(path, 0o700)
                    directories.pop(path, None)  # a recreated directory keeps its last entry's metadata
                    directories[path] = member
                else:
                    remove_any(path)
                    if member.isreg():
                        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                        with os.fdopen(descriptor, "wb") as output:
                            shutil.copyfileobj(archive.extractfile(member), output, 1 << 20)
                    elif member.issym():
                        os.symlink(member.linkname, path)
                    elif member.islnk():
                        target = clean_parts(member.linkname)
                        if not target:
                            raise UnpackError("hardlink to the image root")
                        source = os.path.join(self.directory(target[:-1], create=False), target[-1])
                        if stat.S_ISDIR(os.lstat(source).st_mode):
                            raise UnpackError("hardlink to a directory")
                        os.link(source, path, follow_symlinks=False)
                    elif member.ischr() or member.isblk():
                        kind = stat.S_IFCHR if member.ischr() else stat.S_IFBLK
                        os.mknod(path, kind | 0o600, os.makedev(member.devmajor, member.devminor))
                    elif member.isfifo():
                        os.mkfifo(path, 0o600)
                    else:
                        raise UnpackError(f"unsupported layer member type for {member.name!r}")
                    if not member.islnk():
                        self.metadata(path, member)
                created.add(path)
        # Directory metadata last, deepest first, so later entries do not change
        # the times. A later entry may have replaced the directory or a parent with
        # a symlink: skip any path that is no longer a real directory reached
        # without symlinks (self.root is already resolved), so metadata can never
        # follow a link out of the rootfs.
        for path, member in reversed(directories.items()):
            try:
                real_directory = os.path.realpath(path) == path and stat.S_ISDIR(os.lstat(path).st_mode)
            except OSError:
                real_directory = False  # removed, or a parent became a non-directory
            if real_directory:
                self.metadata(path, member)


# Replaces the image's resolv.conf (often a build-time file or symlink) with a
# loopback-only one and adds a localhost /etc/hosts when it is missing, empty or a
# symlink, as AgentENV's fresh-rootfs preparation does. Sandboxes have no DNS, so
# lookups fail fast at loopback instead of waiting on blocked egress.
def prepare_resolver(rootfs):
    etc = rootfs.directory(["etc"])
    resolv = os.path.join(etc, "resolv.conf")
    remove_any(resolv)
    Path(resolv).write_text("# No DNS resolver is provided in this sandbox.\nnameserver 127.0.0.1\n")
    os.chmod(resolv, 0o644)
    hosts = os.path.join(etc, "hosts")
    if os.path.islink(hosts) or not os.path.isfile(hosts) or os.path.getsize(hosts) == 0:
        remove_any(hosts)
        Path(hosts).write_text("127.0.0.1 localhost\n::1 localhost\n")
        os.chmod(hosts, 0o644)


# Unpacks the selected image into a new rootfs, builds an uncompressed EROFS base
# with mkfs.erofs and publishes it. Returns a description saved for the inner phase.
def prepare_image(args, session):
    if args.oci_tar:
        layout = session / "oci-layout"
        layout.mkdir(mode=0o700)
        with tarfile.open(args.oci_tar) as archive:
            archive.extractall(layout, filter="data")
    else:
        layout = Path(args.oci_layout).resolve(strict=True)
    started = time.monotonic()
    descriptor, manifest = select_manifest(layout, args.platform)
    config = json_blob(layout, manifest["config"])
    diff_ids = config.get("rootfs", {}).get("diff_ids", [])
    if len(diff_ids) != len(manifest["layers"]):
        raise UnpackError("image config diff_ids do not match manifest layers")
    rootfs_dir = session / "image-rootfs"
    rootfs_dir.mkdir(mode=0o755)
    rootfs = Rootfs(rootfs_dir)
    for layer, diff_id in zip(manifest["layers"], diff_ids):
        stream, process = open_layer(blob(layout, layer), layer["mediaType"])
        reader = HashingReader(stream)
        with stream:
            rootfs.apply(reader)
            actual = reader.finish()
        if process is not None and process.wait(timeout=60):
            raise UnpackError("zstd decompression failed")
        if actual != diff_id:
            raise UnpackError(f"layer diff_id mismatch for {layer['digest']}")
    unpack_seconds = time.monotonic() - started
    # Mount points for the runtime and the workload's fixed working directory.
    # The worker always runs processes as 65534 in /workspace.
    for name in ("proc", "dev"):
        if not os.path.lexists(rootfs_dir / name):
            (rootfs_dir / name).mkdir(mode=0o755)
    workspace = rootfs_dir / "workspace"
    if workspace.is_symlink() or (workspace.exists() and not workspace.is_dir()):
        raise UnpackError("/workspace in the image is not a directory")
    workspace.mkdir(mode=0o755, exist_ok=True)
    os.chown(workspace, 65534, 65534)
    workspace.chmod(0o755)
    if not args.keep_image_resolver:
        prepare_resolver(rootfs)
    image_config = config.get("config") or {}
    env = [e for e in image_config.get("Env") or [] if "=" in e and not e.startswith("-")]
    search_path = next((e.split("=", 1)[1] for e in env if e.startswith("PATH=")), "/usr/local/bin:/usr/bin:/bin")
    argv = json.loads(args.init_argv) if args.init_argv else ["python3", "-m", "http.server", str(args.port), "--bind", "0.0.0.0"]
    program = argv[0] if argv[0].startswith("/") else rootfs.which(argv[0], search_path)
    if not program:
        raise UnpackError(f"{argv[0]} not found on the image PATH")
    init_argv = [program, *argv[1:]]
    env_tool = rootfs.which("env", search_path) if env and not args.no_image_env else None
    if env_tool:
        init_argv = [env_tool, *env, *init_argv]
    if len(init_argv) > 64 or any(len(a) > 4096 or "\0" in a for a in init_argv):
        raise UnpackError("init argv exceeds the manifest bounds (64 arguments of 4096 bytes); try --no-image-env")
    notes = [] if args.keep_image_resolver else ["image /etc/resolv.conf replaced with loopback-only (no DNS in sandboxes); localhost /etc/hosts added if absent"]
    if image_config.get("WorkingDir") not in (None, "", "/workspace"):
        notes.append(f"image WorkingDir {image_config['WorkingDir']!r} not applied: the worker always uses /workspace")
    if image_config.get("User"):
        notes.append(f"image User {image_config['User']!r} not applied: the worker always uses UID/GID 65534")
    if env and not env_tool:
        notes.append("image Env not applied: disabled or env(1) not found in the image")
    mkfs = str(Path(args.tools_dir) / "mkfs.erofs") if args.tools_dir else "mkfs.erofs"
    started = time.monotonic()
    image_file = session / "base.erofs"
    subprocess.run([mkfs, str(image_file), str(rootfs_dir)], check=True, timeout=900, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    erofs_seconds = time.monotonic() - started
    base = publish_layer(session, image_file)
    shutil.rmtree(rootfs_dir)  # plain unpacked files; never a mount
    prepared = dict(manifest_digest=descriptor["digest"], config_digest=manifest["config"]["digest"], platform=args.platform,
                    layers=[layer["digest"] for layer in manifest["layers"]], base=base, init_argv=init_argv, notes=notes,
                    unpack_seconds=round(unpack_seconds, 3), erofs_seconds=round(erofs_seconds, 3))
    (session / "prepared.json").write_text(json.dumps(prepared, indent=2))
    print(f"PASS unpacked {len(manifest['layers'])} layers (manifest {descriptor['digest']}) in {unpack_seconds:.1f}s; "
          f"EROFS base {base['bytes']} bytes in {erofs_seconds:.1f}s; {rootfs.whiteouts} whiteouts, {rootfs.opaque} opaque directories applied")
    for note in notes:
        print("NOTE", note)
    return prepared


# Outer phase: prepares the image in the host namespace (registry access stays
# there), then runs the lifecycle in a disposable network/mount namespace and
# checks that the default namespace inventory did not change.
def outer(args):
    if args.image:
        fetch_image(args.image, Path(args.oci_layout).resolve(), args.fetch_tool, args.platform)
    parent = Path(args.root).resolve(strict=True)
    session = Path(tempfile.mkdtemp(prefix="image-e2e-", dir=parent))
    session.chmod(0o700)
    prepare_image(args, session)
    before = inventory()
    env = dict(os.environ, SANDBOX_TEST_PARENT_NETNS=os.readlink("/proc/self/ns/net"))
    result = subprocess.run(["unshare", "--mount", "--net", "--fork", sys.executable, os.path.abspath(__file__), *sys.argv[1:],
                             "--inside", "--session", str(session)], env=env, timeout=1800)
    after = inventory()
    if before != after:
        print("INVENTORY BEFORE", json.dumps(before), "INVENTORY AFTER", json.dumps(after))
        raise AssertionError("default namespace inventory changed; inspect before any cleanup")
    print("PASS default namespace network inventory unchanged")
    print("Retained session root for inspection:", session)
    return result.returncode


# Inner phase: inside the disposable namespace, creates only a namespace-local
# bridge and private /run/netns, runs the lifecycle, then verifies teardown.
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
    return 0


# Runs the real worker and controller and drives the image workflow through the
# controller API. Prints PASS lines with informational timings.
def lifecycle(args, session):
    prepared = json.loads((session / "prepared.json").read_text())
    binary = str(Path(args.binary).resolve())
    cgroup = Path(args.cgroup_parent).resolve(strict=True)
    worker_port, controller_port = port(), port()
    assert worker_port != controller_port
    token, worker_token = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
    env = dict(os.environ, SANDBOX_CONTROLLER_TOKEN=token, SANDBOX_WORKER_TOKEN=worker_token)
    tools = ("tools_dir = " + json.dumps(str(Path(args.tools_dir).resolve(strict=True)))) if args.tools_dir else ""
    worker_config = session / "worker.toml"
    worker_config.write_text(f'''node_id = "node-image"
runtimes = ["runc_criu"]
[server]
listen = "127.0.0.1:{worker_port}"
request_timeout_ms = 5000
[auth]
env = "SANDBOX_WORKER_TOKEN"
[capacity]
memory_mib = {3 * args.memory_mib}
vcpus = {args.vcpus}
max_sandboxes = 3
max_concurrent_restores = 2
[native]
enabled = true
root = {json.dumps(str(session))}
cgroup_parent = {json.dumps(str(cgroup))}
{tools}
cpu_overcommit = 3
pids_max = {args.pids_max}
max_records = 16
max_concurrent_operations = 4
max_artifact_bytes = 4294967296
command_timeout_seconds = 120
[native.network]
bridge = "{BRIDGE}"
gateway = "198.18.0.1"
prefix = 24
addresses = ["198.18.0.10", "198.18.0.11", "198.18.0.12"]
egress = []
service_ports = [{args.port}, {args.port + 1}]
''')
    controller_config = session / "controller.toml"
    controller_config.write_text(f'''proxy_domain = "sandbox.test"
[server]
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
node_id = "node-image"
url = "http://127.0.0.1:{worker_port}"
''')
    compatibility = preflight_compatibility(binary, worker_config)
    network = {"mode": "tcp_allowlist", "egress": [], "service_ports": [args.port, args.port + 1]}
    write_template(session, cold_manifest("image-cold", compatibility, prepared["base"], prepared["init_argv"], network,
                                          memory_mib=args.memory_mib, vcpus=args.vcpus, pids_max=args.pids_max))
    processes, ids, timings, observations = [], [], {}, {"prepared": prepared}
    # Worker-owned namespace names start with this root-derived prefix; routing slots add "s-<index>".
    owned_prefix = "sb-" + hashlib.sha256(str(session).encode()).hexdigest()[:16] + "-"
    worker = None

    # Blocking calls wait for real outcomes; the client deadline exceeds the
    # services' route deadlines so their own timeout errors are observable.
    def request(*call, timeout=None, **named):
        return smoke_request(*call, timeout=timeout or 400, **named)

    # Starts a service process with its own log in the session root and waits for /healthz.
    def start(role, config):
        log = session / f"{role}-{len(processes)}.log"
        with log.open("wb") as output:
            process = subprocess.Popen([binary, role, "--config", str(config)], env=env, stdout=output, stderr=subprocess.STDOUT)
        processes.append(process)
        eventually(lambda: request(worker_port if role == "worker" else controller_port, "/healthz", timeout=4)[0] == 200, timeout=15)
        return process

    # Returns how many bytes the worker process has read so far (rchar in /proc/<pid>/io). Hashing a
    # layer reads its whole image; reads through a loop-mounted layer are not counted.
    def worker_read_bytes():
        return int(next(line for line in Path(f"/proc/{worker.pid}/io").read_text().splitlines() if line.startswith("rchar:")).split()[1])

    # Returns the controller's view of a sandbox.
    def get(sandbox):
        return expect(request(controller_port, f"/v1/sandboxes/{sandbox}", token, timeout=4), 200)

    # Blocking create through the controller. Only a definitive no_capacity
    # (advisory usage lag) is retried; a transport error never is. Returns the
    # running sandbox ID and the elapsed seconds.
    def create(template_id):
        deadline = time.monotonic() + 30
        started = time.monotonic()
        while True:
            code, payload = request(controller_port, "/v1/sandboxes", token, dict(template_id=template_id, ttl_seconds=900), "POST")
            if code == 503 and payload.get("error", {}).get("code") == "no_capacity" and time.monotonic() < deadline:
                time.sleep(0.2)
                continue
            break
        if "sandbox_id" in payload:
            ids.append(payload["sandbox_id"])
        assert code == 201 and payload["state"] == "running", (code, payload)
        return payload["sandbox_id"], time.monotonic() - started

    # One application request through the controller's app proxy, in path form or host form
    # (`<port>-<id>.sandbox.test`). Returns the status, headers and body bytes.
    def proxy_call(sandbox, path=None, port_number=None, host_form=False, timeout=30):
        port_number, path = port_number or args.port, path or args.http_path
        headers = {"Authorization": "Bearer " + token}
        if host_form:
            headers["Host"] = f"{port_number}-{sandbox}.sandbox.test"
        return exchange(controller_port, "GET", path if host_form else f"/v1/sandboxes/{sandbox}/proxy/{port_number}{path}", headers, timeout=timeout)

    # One GET of --http-path through the proxy, returned as the proxy status and {status, body text}.
    def http_call(sandbox, host_form=False):
        status, _, body = proxy_call(sandbox, host_form=host_form)
        return status, {"status": status, "body": body.decode(errors="replace")}

    # Retries a proxied GET until the in-container server answers 200 or the
    # deadline passes. Returns the response, elapsed seconds and attempt count.
    def wait_http(sandbox, timeout):
        started, attempts, last = time.monotonic(), 0, None
        while time.monotonic() - started < timeout:
            attempts += 1
            code, payload = http_call(sandbox)
            if code == 200 and payload["status"] == 200:
                return payload, time.monotonic() - started, attempts
            last = (code, payload)
            assert get(sandbox)["state"] == "running", "sandbox stopped while waiting for its HTTP server"
            time.sleep(0.1)
        raise AssertionError(f"HTTP server did not answer within {timeout}s: {last}")

    # Runs one blocking command through the controller and returns its raw status and result.
    def exec_call(sandbox, argv, timeout_ms=20000, max_output_bytes=65536):
        return request(controller_port, f"/v1/sandboxes/{sandbox}/exec", token, dict(argv=argv, timeout_ms=timeout_ms, max_output_bytes=max_output_bytes), "POST")

    # Runs one command through the controller and requires a clean exit.
    def execute(sandbox, argv, expect_exit=0):
        result = expect(exec_call(sandbox, argv), 200)
        assert result["exit_code"] == expect_exit and not result["interrupted"] and result["sandbox_state"] == "running", result
        return result["stdout"]

    # Starts a streaming command and returns its exec ID and a queue that a background thread fills
    # with (arrival time, event name, data) events, then None when the stream ends.
    def start_stream(sandbox, argv, timeout_ms):
        connection = http.client.HTTPConnection("127.0.0.1", controller_port, timeout=timeout_ms / 1000 + 60)
        connection.request("POST", f"/v1/sandboxes/{sandbox}/exec", json.dumps(dict(argv=argv, timeout_ms=timeout_ms, max_output_bytes=65536, stream=True)),
                           {"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        response = connection.getresponse()
        assert response.status == 200 and response.getheader("Content-Type") == "text/event-stream", response.status
        events = queue.Queue()
        # Parse server-sent events into the queue until the stream ends.
        def pump():
            name = None
            try:
                while line := response.readline():
                    line = line.decode().rstrip("\n")
                    if line.startswith("event: "):
                        name = line[len("event: "):]
                    elif line.startswith("data: "):
                        events.put((time.monotonic(), name, json.loads(line[len("data: "):])))
            finally:
                events.put(None)
                connection.close()
        threading.Thread(target=pump, daemon=True).start()
        _, name, data = events.get(timeout=10)
        assert name == "start", name
        return data["exec_id"], events

    # Drains a stream's queue to its end; returns the events and the decoded stdout.
    def finish_stream(events, timeout=90):
        collected = []
        while (item := events.get(timeout=timeout)) is not None:
            collected.append(item)
        return collected, b"".join(base64.b64decode(data["data"]) for _, name, data in collected if name == "stdout")

    # Opens a WebSocket through the controller's proxy (path or host form), checks the handshake, echoes
    # a text and a 70000-byte binary message, closes it and returns the handshake time in seconds.
    def websocket_echo(sandbox, ws_port, host_form=False):
        key = base64.b64encode(os.urandom(16)).decode()
        target = "/ws" if host_form else f"/v1/sandboxes/{sandbox}/proxy/{ws_port}/ws"
        host = f"{ws_port}-{sandbox}.sandbox.test" if host_form else f"127.0.0.1:{controller_port}"
        started = time.monotonic()
        with socket.create_connection(("127.0.0.1", controller_port), timeout=10) as ws:
            ws.sendall((f"GET {target} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                        f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n").encode())
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = ws.recv(4096)
                assert chunk, data
                data += chunk
            head, rest = data.split(b"\r\n\r\n", 1)
            handshake = time.monotonic() - started
            fields = {line.split(b":", 1)[0].strip().lower(): line.split(b":", 1)[1].strip() for line in head.split(b"\r\n")[1:] if b":" in line}
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
            assert head.startswith(b"HTTP/1.1 101") and fields.get(b"sec-websocket-accept") == accept and fields.get(b"upgrade", b"").lower() == b"websocket", head
            buffer = bytearray(rest)
            # Reads exactly n bytes, starting with what arrived together with the handshake.
            def read(n):
                while len(buffer) < n:
                    chunk = ws.recv(65536)
                    assert chunk, "WebSocket closed early"
                    buffer.extend(chunk)
                out = bytes(buffer[:n])
                del buffer[:n]
                return out
            for opcode, payload in ((1, b"hello-ws"), (2, os.urandom(70000))):
                mask = os.urandom(4)
                length = bytes([0x80 | len(payload)]) if len(payload) < 126 else (bytes([0x80 | 126]) + len(payload).to_bytes(2, "big") if len(payload) < 65536 else bytes([0x80 | 127]) + len(payload).to_bytes(8, "big"))
                ws.sendall(bytes([0x80 | opcode]) + length + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
                first, size = read(2)
                size &= 127
                if size == 126:
                    size = int.from_bytes(read(2), "big")
                elif size == 127:
                    size = int.from_bytes(read(8), "big")
                assert first == 0x80 | opcode and read(size) == payload
            ws.sendall(bytes([0x88, 0x80]) + os.urandom(4))
            assert read(2)[0] == 0x88
        return handshake

    # Returns the host PID of a sandbox's init process from runc state.
    def host_pid(sandbox):
        runc = str(Path(args.tools_dir) / "runc") if args.tools_dir else "runc"
        data = subprocess.run([runc, "--root", str(session / "runc"), "state", sandbox], check=True, capture_output=True, timeout=5,
                              env={"PATH": args.tools_dir or "/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
        return json.loads(data.stdout)["pid"]

    # Copies bounded CRIU logs of a sandbox (if still present) for diagnosis.
    def diagnostics(sandbox, label):
        target = session / "diagnostics"
        target.mkdir(mode=0o700, exist_ok=True)
        for log in (session / "private" / sandbox / "criu-work").glob("*.log"):
            with log.open("rb") as source:
                (target / f"{label}-{log.name}").write_bytes(source.read(262144))

    # Returns the name of the pooled routing slot namespace recorded for a sandbox.
    def slot_of(sandbox):
        index = json.loads((session / "records" / f"{sandbox}.json").read_text())["network_slot"]
        return f"{owned_prefix}s-{index}"

    # Requires every pooled routing slot to exist in its clean pool state: only loopback and the
    # uplink, no rule in its filter chains and no tracked connection (both flushed on release).
    def slots_reset():
        for pin in sorted(Path("/run/netns").iterdir()):
            assert pin.name.startswith(owned_prefix + "s-"), f"unexpected namespace pin {pin.name}"
            links = sorted(link["ifname"] for link in json.loads(run("ip", "-n", pin.name, "-j", "link")))
            assert links == ["lo", "uplink"], (pin.name, links)
            table = json.loads(run("ip", "netns", "exec", pin.name, "nft", "-j", "list", "table", "inet", "sandbox"))
            assert not any("rule" in entry for entry in table["nftables"]), (pin.name, table)
            assert run("ip", "netns", "exec", pin.name, "cat", "/proc/sys/net/netfilter/nf_conntrack_count").strip() == "0", pin.name

    # Starts a client in the sandbox's routing namespace that requests the service
    # port every 20 ms (2 s timeout) and prints "start end ok" monotonic times,
    # until the stop file exists. Returns the process and its output file.
    def availability_probe(sandbox, label):
        script = ("import socket, sys, time, os\n"
                  "while not os.path.exists(sys.argv[3]):\n"
                  "    t = time.monotonic(); ok = 0\n"
                  "    try:\n"
                  "        with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2) as c:\n"
                  "            c.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n'); ok = c.recv(12).startswith(b'HTTP/1.0 200')\n"
                  "    except OSError:\n"
                  "        pass\n"
                  "    print(t, time.monotonic(), int(ok), flush=True); time.sleep(0.02)\n")
        output = (session / f"probe-{label}.txt").open("w")
        stop = session / f"probe-{label}.stop"
        process = subprocess.Popen(["ip", "netns", "exec", slot_of(sandbox), sys.executable, "-c", script, "192.0.2.2", str(args.port), str(stop)],
                                   stdout=output, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        return process, output, stop

    # Stops a probe and summarizes its answers inside [started, finished]: successes,
    # the longest interval without a completed successful answer and the slowest answer.
    def probe_summary(probe, started, finished):
        process, output, stop = probe
        stop.touch()
        process.wait(timeout=10)
        output.close()
        rows = [tuple(map(float, line.split())) for line in Path(output.name).read_text().splitlines()]
        done = [end for start, end, ok in rows if ok and started <= end <= finished]
        edges = [started, *done, finished]
        return dict(probes=len(rows), successes_during_capture=len(done),
                    longest_without_answer_s=round(max(b - a for a, b in zip(edges, edges[1:])), 3),
                    slowest_answer_s=round(max((end - start for start, end, ok in rows if ok and started <= end <= finished), default=0), 3),
                    failures=sum(1 for _, end, ok in rows if not ok and started <= end <= finished))

    # Requires that no per-sandbox runc state, private directory or cgroup remains.
    def gone(sandbox):
        assert not (session / "private" / sandbox).exists(), "private state remains"
        assert not (session / "runc" / sandbox).exists(), "runc state remains"
        assert not (cgroup / sandbox).exists(), "cgroup remains"

    try:
        worker = start("worker", worker_config)
        start("controller", controller_config)
        eventually(lambda: expect(request(controller_port, "/v1/status", token, timeout=4), 200)["nodes"][0]["fresh"], timeout=15)
        # The worker pre-creates one routing slot per sandbox it can admit, before any create.
        assert sorted(p.name for p in Path("/run/netns").iterdir()) == [f"{owned_prefix}s-{i}" for i in range(3)]
        slots_reset()

        read_before = worker_read_bytes()
        source, timings["cold_create_s"] = create("image-cold")
        # The first use of the base on this node hashes it fully in the create job.
        timings["cold_create_read_bytes"] = worker_read_bytes() - read_before
        assert timings["cold_create_read_bytes"] >= prepared["base"]["bytes"], timings
        first, ready_after_create, attempts = wait_http(source, args.ready_timeout)
        timings["first_http_ready_after_create_s"] = ready_after_create
        timings["first_http_ready_total_s"] = timings["cold_create_s"] + ready_after_create
        assert args.expect_body in first["body"], first
        pid = host_pid(source)
        status = Path(f"/proc/{pid}/status").read_text()
        uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
        assert uid_line.split()[1:] == ["65534"] * 4 and "NoNewPrivs:\t1" in status and "CapEff:\t0000000000000000" in status, status
        observations["source_init"] = dict(cmdline=Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[0].decode(), uid=uid_line)
        print(f"PASS cold create {timings['cold_create_s']:.2f}s; HTTP {first['status']} after {ready_after_create:.2f}s more "
              f"({attempts} attempts) as UID 65534, no capabilities, no_new_privs")

        exec_argv = json.loads(args.exec_argv) if args.exec_argv else ["python3", "-c", "import os; print('exec-ok', os.getuid(), os.getcwd())"]
        output = execute(source, exec_argv)
        assert args.exec_expect in output, output
        # PID 1 is the read-only reaping init (the image server is its child). A
        # background child killed with its exec is reparented to PID 1 and reaped.
        assert Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[0] == b"/.sandbox-init"
        execute(source, [args.shell, "-c", "sleep 30 </dev/null >/dev/null 2>&1 & exit 0"])
        time.sleep(1)
        zombies = execute(source, ["python3", "-c", "import os; print(sum(open(f'/proc/{p}/stat').read().rsplit(')', 1)[1].split()[0] == 'Z' for p in os.listdir('/proc') if p.isdigit()))"])
        assert zombies.strip() == "0", f"zombies remain under PID 1: {zombies}"
        print("PASS PID 1 is the reaping init; an orphaned, killed exec child left no zombie")
        nonce = secrets.token_hex(8)
        execute(source, [args.shell, "-c", 'printf %s "$1" > "$2"', "sh", nonce, MARKER])
        assert execute(source, ["cat", MARKER]) == nonce
        print(f"PASS exec ({output.strip()!r}) and marker write")

        # The host form (`<port>-<id>.<proxy_domain>`) reaches the same server as the path form.
        status, hosted = http_call(source, host_form=True)
        assert status == 200 and args.expect_body in hosted["body"], hosted
        print("PASS app proxy: path form and host form reach the in-container server")

        # A long-running command streams its output while it runs.
        ticker = "import time\nfor i in range(6):\n    print('tick', i, flush=True)\n    time.sleep(0.5)\n"
        started = time.monotonic()
        _, events = start_stream(source, ["python3", "-u", "-c", ticker], 20000)
        streamed, output = finish_stream(events)
        arrivals = [at - started for at, name, _ in streamed if name == "stdout"]
        assert output == b"".join(f"tick {i}\n".encode() for i in range(6)), output
        assert streamed[-1][1] == "exit" and streamed[-1][2] == {"exit_code": 0, "interrupted": False, "error": None, "sandbox_state": "running"}, streamed[-1]
        assert arrivals[-1] - arrivals[0] >= 2.0, f"output did not stream: {arrivals}"
        timings["stream_first_output_s"], timings["stream_last_output_s"] = arrivals[0], arrivals[-1]
        print(f"PASS streamed command: first output after {arrivals[0]:.2f}s, last after {arrivals[-1]:.2f}s, then the exit event")

        # Two commands run at once in one sandbox, each in its own resource group.
        span = "import time; a = time.monotonic(); time.sleep(1.5); print(a, time.monotonic())"
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            running = [pool.submit(execute, source, ["python3", "-c", span]) for _ in range(2)]
            eventually(lambda: len([p for p in (cgroup / source).glob("exec-*") if p.is_dir()]) == 2, timeout=10)
            spans = [tuple(map(float, command.result(timeout=30).split())) for command in running]
        assert max(begin for begin, _ in spans) < min(end for _, end in spans), f"commands were serialized: {spans}"
        assert not list((cgroup / source).glob("exec-*"))
        observations["concurrent_exec_spans"] = spans
        print("PASS two concurrent commands in one sandbox, each in its own exec group")

        # A WebSocket echo server, run by a streaming command on the second approved port, is reached
        # through the proxy in both forms while the HTTP server keeps answering; then it is killed.
        ws_port = args.port + 1
        server_id, server_events = start_stream(source, ["python3", "-u", "-c", WS_SERVER, str(ws_port)], 60000)
        banner = b""
        while b"listening" not in banner:
            item = server_events.get(timeout=30)
            assert item is not None and item[1] in ("stdout", "stderr"), item
            banner += base64.b64decode(item[2]["data"])
        timings["websocket_handshake_path_s"] = websocket_echo(source, ws_port)
        timings["websocket_handshake_host_s"] = websocket_echo(source, ws_port, host_form=True)
        status, _ = http_call(source)
        assert status == 200
        killed = expect(request(controller_port, f"/v1/sandboxes/{source}/exec/{server_id}/kill", token, method="POST"), 200)
        assert killed == {"sandbox_id": source, "exec_id": server_id, "state": "exited"}, killed
        rest, _ = finish_stream(server_events)
        assert rest[-1][1] == "exit" and rest[-1][2] == {"exit_code": None, "interrupted": True, "error": "exec_killed", "sandbox_state": "running"}, rest[-1]
        assert not list((cgroup / source).glob("exec-*"))
        print("PASS WebSocket echo (text and 70000-byte binary) through the proxy, path and host forms; kill stopped the server command only")

        # A deadline or output overflow stops only that command; the sandbox and its server keep running.
        result = expect(exec_call(source, ["sleep", "30"], timeout_ms=500), 200)
        assert result["interrupted"] and result["error"] == "exec_timeout" and result["sandbox_state"] == "running", result
        result = expect(exec_call(source, ["yes"], timeout_ms=10000, max_output_bytes=4096), 200)
        assert result["interrupted"] and result["error"] == "exec_output_limit" and len(result["stdout"]) <= 4096 and result["sandbox_state"] == "running", result
        assert get(source)["state"] == "running" and wait_http(source, 10)[0]["status"] == 200
        print("PASS bounded commands (timeout, output limit) stopped only themselves; the sandbox still serves")

        # Per-call overhead (informational): the same GET through the controller and worker proxy, and
        # directly from inside the sandbox; plus a trivial command's round trip.
        proxy_times = []
        for _ in range(30):
            started = time.monotonic()
            assert http_call(source)[0] == 200
            proxy_times.append(time.monotonic() - started)
        direct = ("import json, time, urllib.request\nts = []\nfor _ in range(30):\n    t = time.monotonic()\n"
                  f"    urllib.request.urlopen('http://127.0.0.1:{args.port}{args.http_path}').read()\n    ts.append(time.monotonic() - t)\nprint(json.dumps(ts))")
        direct_times = json.loads(execute(source, ["python3", "-c", direct]))
        exec_times = []
        for _ in range(10):
            started = time.monotonic()
            execute(source, ["true"])
            exec_times.append(time.monotonic() - started)
        overhead = dict(proxy_call_median_s=statistics.median(proxy_times), proxy_call_p90_s=sorted(proxy_times)[26],
                        direct_call_median_s=statistics.median(direct_times), direct_call_p90_s=sorted(direct_times)[26],
                        exec_true_median_s=statistics.median(exec_times))
        timings.update(overhead)
        observations["per_call_overhead_samples_s"] = dict(proxy=proxy_times, direct=direct_times, exec_true=exec_times)
        print("PER-CALL OVERHEAD (informational): " + ", ".join(f"{k} {v * 1000:.2f} ms" for k, v in overhead.items()))

        # Live traffic during capture: the source answers except while frozen.
        probe = availability_probe(source, "capture")
        stop_freezer = threading.Event()
        freezer = concurrent.futures.ThreadPoolExecutor(max_workers=1).submit(watch_frozen, cgroup / source / "cgroup.events", stop_freezer)
        time.sleep(1)
        started = time.monotonic()
        code, captured = request(controller_port, f"/v1/sandboxes/{source}/capture", token, dict(template_id="image-warm", runtime="runc_criu"), "POST")
        finished = time.monotonic()
        time.sleep(2)
        stop_freezer.set()
        availability = dict(probe_summary(probe, started, finished), **freezer.result(timeout=10), capture_started=round(started, 3), capture_finished=round(finished, 3))
        timings["capture_s"] = finished - started
        if code != 200:
            diagnostics(source, "capture")
        assert code == 200 and captured["state"] == "running" and captured["template_id"] == "image-warm", (code, captured, availability)
        assert get(source)["state"] == "running"
        observations["source_during_capture"] = availability
        # Freezer time only; the longest gap without an answer is the client-visible stop.
        timings["capture_freezer_s"] = availability["frozen_s"]
        timings["capture_longest_without_answer_s"] = availability["longest_without_answer_s"]
        assert availability["freeze_periods"] >= 1 and 0 < availability["frozen_s"] < timings["capture_s"], availability
        assert availability["successes_during_capture"] > 0 and availability["longest_without_answer_s"] < timings["capture_s"], availability
        warm = session / "templates" / "image-warm"
        warm_manifest = json.loads((warm / "manifest.json").read_text())
        assert warm_manifest["schema_version"] == 3 and len(warm_manifest["layers"]) == 1 and not (warm / "upper.tar").exists()
        observations["warm_artifacts"] = {"checkpoint.tar": (warm / "checkpoint.tar").stat().st_size, "sealed_layer": warm_manifest["layers"][0]}
        source_after, timings["source_http_after_capture_s"], _ = wait_http(source, 10)
        print(f"PASS capture {timings['capture_s']:.2f}s without stopping the source: freezer {availability['frozen_s']:.3f}s; "
              f"{availability['successes_during_capture']} probe answers during it, longest client-visible gap {availability['longest_without_answer_s']:.3f}s, "
              f"slowest answer {availability['slowest_answer_s']:.3f}s; "
              f"checkpoint {observations['warm_artifacts']['checkpoint.tar']} bytes, sealed layer {warm_manifest['layers'][0]['bytes']} bytes")

        child, timings["warm_restore_s"] = create("image-warm")
        cache, cache_state = checkpoint_cache(session, "image-warm")
        started = time.monotonic()
        code, child_first = http_call(child)
        timings["first_call_after_restore_s"] = time.monotonic() - started
        if not (code == 200 and child_first["status"] == 200):
            child_first, waited, attempts = wait_http(child, 10)
            observations["child_first_call_retried"] = attempts
            timings["first_call_after_restore_s"] += waited
        assert args.expect_body in child_first["body"]
        assert execute(child, ["cat", MARKER]) == nonce
        if args.http_path == "/" and args.expect_body == "Directory listing":
            assert Path(MARKER).name in child_first["body"], "child HTTP listing lacks the captured marker file"
        print(f"PASS warm restore {timings['warm_restore_s']:.2f}s (first on this node: unpacks the checkpoint cache); "
              f"first child HTTP call {timings['first_call_after_restore_s']:.3f}s; captured marker present in child")
        second, timings["warm_restore_cached_s"] = create("image-warm")
        assert checkpoint_cache(session, "image-warm") == (cache, cache_state), "checkpoint cache was re-extracted or written"
        second_first, _, _ = wait_http(second, 10)
        assert args.expect_body in second_first["body"] and execute(second, ["cat", MARKER]) == nonce
        result = expect(request(controller_port, f"/v1/sandboxes/{second}", token, method="DELETE"), 200)
        assert result["state"] == "deleted"
        gone(second)
        print(f"PASS second warm restore {timings['warm_restore_cached_s']:.2f}s reused the node checkpoint cache unchanged")

        execute(child, [args.shell, "-c", 'printf child > "$1"', "sh", CHILD_ONLY])
        execute(source, [args.shell, "-c", 'test ! -e "$1"', "sh", CHILD_ONLY])
        assert execute(source, ["cat", MARKER]) == nonce
        source_again, _, _ = wait_http(source, 10)
        assert Path(CHILD_ONLY).name not in source_again["body"]
        for namespace in ("pid", "mnt", "net"):
            identities = {os.readlink(f"/proc/{p}/ns/{namespace}") for p in (host_pid(source), host_pid(child), os.getpid())}
            assert len(identities) == 3, namespace
        print("PASS source still answers; child writes are not visible in the source; distinct pid/mnt/net namespaces")

        # The probe and HTTP calls left tracked connections in the source's slot.
        assert int(run("ip", "netns", "exec", slot_of(source), "cat", "/proc/sys/net/netfilter/nf_conntrack_count")) > 0
        for sandbox in (child, source):
            started = time.monotonic()
            result = expect(request(controller_port, f"/v1/sandboxes/{sandbox}", token, method="DELETE"), 200)
            assert result["state"] == "deleted"
            timings.setdefault("delete_s", []).append(round(time.monotonic() - started, 3))
            gone(sandbox)
        # Guest namespaces are gone; the pooled slots stay, reset rather than deleted.
        assert sorted(p.name for p in Path("/run/netns").iterdir()) == [f"{owned_prefix}s-{i}" for i in range(3)], "guest netns remain after delete"
        slots_reset()
        print("PASS delete of source and child: no runc state, private state, cgroups or guest namespaces remain; pooled slots reset")

        # A graceful worker restart (it unmounts the shared layers and removes the slot pool) keeps the
        # saved verified-layer state, so the next cold create trusts the unchanged base instead of
        # hashing it again: the worker reads (rchar) far less than the base's size.
        worker.terminate()
        assert worker.wait(timeout=180) == 0
        saved = {entry["sha256"]: entry for entry in json.loads((session / "verified-layers.json").read_text())["layers"]}
        assert saved[prepared["base"]["sha256"]]["bytes"] == prepared["base"]["bytes"]
        worker = start("worker", worker_config)
        eventually(lambda: (lambda node: node["fresh"] and node["status"]["admission_ready"])(
            expect(request(controller_port, "/v1/status", token, timeout=4), 200)["nodes"][0]), timeout=30)
        read_before = worker_read_bytes()
        again, timings["cold_create_after_restart_s"] = create("image-cold")
        timings["cold_create_after_restart_read_bytes"] = worker_read_bytes() - read_before
        assert timings["cold_create_after_restart_read_bytes"] < prepared["base"]["bytes"] // 2, timings
        wait_http(again, args.ready_timeout)
        assert expect(request(controller_port, f"/v1/sandboxes/{again}", token, method="DELETE"), 200)["state"] == "deleted"
        gone(again)
        print(f"PASS cold create after a worker restart {timings['cold_create_after_restart_s']:.2f}s without rehashing the base "
              f"(worker read {timings['cold_create_after_restart_read_bytes']} bytes; base {prepared['base']['bytes']} bytes)")
    finally:
        # All cleanup goes through the owner; never recurse through live mounts.
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
        observations["sandbox_ids"], observations["timings_s"] = ids, {k: (v if isinstance(v, list) else round(v, 3)) for k, v in timings.items()}
        (session / "image-e2e.json").write_text(json.dumps(observations, indent=2))
        (session / "image-e2e.json").chmod(0o600)
    mountinfo = Path("/proc/self/mountinfo").read_text()
    assert not any(str(session) in line.split()[4] for line in mountinfo.splitlines()), "owned mounts remain"
    assert not any(path.is_dir() for path in cgroup.iterdir()), "owned workload/helper cgroups remain"
    for log in session.glob("*.log"):
        assert token.encode() not in log.read_bytes() and worker_token.encode() not in log.read_bytes()
    print("PASS shutdown: no owned mounts or cgroups; tokens absent from service logs")
    print("TIMINGS (informational, not benchmarks): " + json.dumps(observations["timings_s"]))
    print("IMAGE E2E PASSED on this host only; not a capacity, isolation or performance qualification")


# Dispatches to fetch-only mode, the outer phase or the inner phase.
def main():
    args = parse_args()
    if args.fetch_only:
        fetch_image(args.image, Path(args.oci_layout).resolve(), args.fetch_tool, args.platform)
        return 0
    return inner(args) if args.inside else outer(args)


if __name__ == "__main__":
    sys.exit(main())
