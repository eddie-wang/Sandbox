#!/usr/bin/env python3
"""Minimal real-image end-to-end gate. Explicitly privileged; never run by smoke.py.

Builds a cold template from an OCI image (layout directory or layout tar, optionally
fetched first with regctl, skopeo or crane), then drives the controller's blocking
API: cold create, wait for the in-container HTTP server, application HTTP call,
exec, marker write, warm capture (the worker checkpoints the source and restores
it; the source must be running and answering afterward), independent child
restore, HTTP and marker checks in the child, source/child isolation, delete and
cleanup checks. Printed timings are informational, not benchmarks.

Networking runs entirely inside a disposable outer network/mount namespace, as in
network_smoke.py. The template allows only the service port; no egress.
"""
import argparse
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform as host_platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

from network_smoke import inventory, run
from runtime_smoke import cold_manifest, preflight_compatibility, publish_layer, write_template
from smoke import eventually, expect, port, request as smoke_request

INDEX_TYPES = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
MARKER = "/workspace/sandbox-e2e-marker"
CHILD_ONLY = "/workspace/sandbox-e2e-child-only"
BRIDGE = "sb-test-br"


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
    parser.add_argument("--port", type=int, default=8000, help="Service port of the in-container HTTP server")
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
    if not 0 < args.port < 65536:
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


# Same as AgentENV's fresh-rootfs preparation (resolv.conf replaced, a localhost
# /etc/hosts when the image has none). Images often ship a build-time resolv.conf
# (or a symlink into a runtime directory) and no /etc/hosts. Sandboxes have no DNS
# resolver, so lookups go to loopback and fail fast instead of waiting on blocked
# egress; localhost resolves from files.
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
service_ports = [{args.port}]
''')
    controller_config = session / "controller.toml"
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
node_id = "node-image"
url = "http://127.0.0.1:{worker_port}"
''')
    compatibility = preflight_compatibility(binary, worker_config)
    network = {"mode": "tcp_allowlist", "egress": [], "service_ports": [args.port]}
    write_template(session, cold_manifest("image-cold", compatibility, prepared["base"], prepared["init_argv"], network,
                                          memory_mib=args.memory_mib, vcpus=args.vcpus, pids_max=args.pids_max))
    processes, ids, timings, observations = [], [], {}, {"prepared": prepared}
    worker = None

    # Blocking calls wait for real outcomes; the client deadline exceeds the
    # services' route deadlines so their own timeout errors are observable.
    def request(*call, timeout=None, **named):
        return smoke_request(*call, timeout=timeout or 400, **named)

    # Starts a service process with its log in the session root and waits for /healthz.
    def start(role, config):
        log = session / f"{role}.log"
        with log.open("wb") as output:
            process = subprocess.Popen([binary, role, "--config", str(config)], env=env, stdout=output, stderr=subprocess.STDOUT)
        processes.append(process)
        eventually(lambda: request(worker_port if role == "worker" else controller_port, "/healthz", timeout=4)[0] == 200, timeout=15)
        return process

    # Returns the controller's view of a sandbox.
    def get(sandbox):
        return expect(request(controller_port, f"/v1/sandboxes/{sandbox}", token, timeout=4), 200)

    # Blocking create through the controller. Only a definitive no_capacity
    # (advisory usage lag) is retried; a transport error never is.
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

    # One application HTTP call through the controller's HTTP operation.
    def http_call(sandbox, timeout_ms=3000):
        body = dict(port=args.port, method="GET", path=args.http_path, timeout_ms=timeout_ms, max_response_bytes=65536)
        return request(controller_port, f"/v1/sandboxes/{sandbox}/http", token, body, "POST")

    # Retries the HTTP operation until the in-container server answers 200 or the
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

    # Runs one command through the controller and requires a clean exit.
    def execute(sandbox, argv, expect_exit=0):
        result = expect(request(controller_port, f"/v1/sandboxes/{sandbox}/exec", token,
                                dict(argv=argv, timeout_ms=20000, max_output_bytes=65536), "POST"), 200)
        assert result["exit_code"] == expect_exit and not result["interrupted"] and result["sandbox_state"] == "running", result
        return result["stdout"]

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

    # Requires that no per-sandbox runc state, private directory or cgroup remains.
    def gone(sandbox):
        assert not (session / "private" / sandbox).exists(), "private state remains"
        assert not (session / "runc" / sandbox).exists(), "runc state remains"
        assert not (cgroup / sandbox).exists(), "cgroup remains"

    try:
        worker = start("worker", worker_config)
        start("controller", controller_config)
        eventually(lambda: expect(request(controller_port, "/v1/status", token, timeout=4), 200)["nodes"][0]["fresh"], timeout=15)

        source, timings["cold_create_s"] = create("image-cold")
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
        nonce = secrets.token_hex(8)
        execute(source, [args.shell, "-c", 'printf %s "$1" > "$2"', "sh", nonce, MARKER])
        assert execute(source, ["cat", MARKER]) == nonce
        print(f"PASS exec ({output.strip()!r}) and marker write")

        started = time.monotonic()
        for _ in range(40):
            code, captured = request(controller_port, f"/v1/sandboxes/{source}/capture", token, dict(template_id="image-warm", runtime="runc_criu"), "POST")
            if code == 409 and captured.get("error", {}).get("code") == "capture_requires_quiescent_tcp":
                time.sleep(0.25)  # a closed HTTP connection is still finishing its TCP close
                continue
            break
        timings["capture_s"] = time.monotonic() - started
        if code != 200:
            diagnostics(source, "capture")
        assert code == 200 and captured["state"] == "running" and captured["template_id"] == "image-warm", (code, captured)
        assert get(source)["state"] == "running"
        warm = session / "templates" / "image-warm"
        observations["warm_artifacts"] = {name: (warm / name).stat().st_size for name in ("upper.tar", "checkpoint.tar")}
        source_after, timings["source_http_after_capture_s"], _ = wait_http(source, 10)
        print(f"PASS capture {timings['capture_s']:.2f}s (checkpoint {observations['warm_artifacts']['checkpoint.tar']} bytes, "
              f"upper {observations['warm_artifacts']['upper.tar']} bytes); source running and answering")

        child, timings["warm_restore_s"] = create("image-warm")
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
        print(f"PASS warm restore {timings['warm_restore_s']:.2f}s; first child HTTP call {timings['first_call_after_restore_s']:.3f}s; "
              "captured marker present in child")

        execute(child, [args.shell, "-c", 'printf child > "$1"', "sh", CHILD_ONLY])
        execute(source, [args.shell, "-c", 'test ! -e "$1"', "sh", CHILD_ONLY])
        assert execute(source, ["cat", MARKER]) == nonce
        source_again, _, _ = wait_http(source, 10)
        assert Path(CHILD_ONLY).name not in source_again["body"]
        for namespace in ("pid", "mnt", "net"):
            identities = {os.readlink(f"/proc/{p}/ns/{namespace}") for p in (host_pid(source), host_pid(child), os.getpid())}
            assert len(identities) == 3, namespace
        print("PASS source still answers; child writes are not visible in the source; distinct pid/mnt/net namespaces")

        for sandbox in (child, source):
            started = time.monotonic()
            result = expect(request(controller_port, f"/v1/sandboxes/{sandbox}", token, method="DELETE"), 200)
            assert result["state"] == "deleted"
            timings.setdefault("delete_s", []).append(round(time.monotonic() - started, 3))
            gone(sandbox)
        assert not list(Path("/run/netns").iterdir()), "owned netns remain after delete"
        assert not any(link["ifname"].startswith("sb") and link["ifname"] != BRIDGE for link in json.loads(run("ip", "-j", "link"))), "owned veth remain"
        print("PASS delete of source and child: no runc state, private state, cgroups or network namespaces remain")
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


# Dispatches to the outer or inner phase.
def main():
    args = parse_args()
    if args.fetch_only:
        fetch_image(args.image, Path(args.oci_layout).resolve(), args.fetch_tool, args.platform)
        return 0
    return inner(args) if args.inside else outer(args)


if __name__ == "__main__":
    sys.exit(main())
