//! Local immutable publication layout. Artifact names are fixed, never supplied
//! by HTTP clients. Templates and layers are retained; there is no automatic GC.
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt}, path::{Path, PathBuf}};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::{model::valid_id, process::{self, Result}};

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    pub architecture: String,
    pub kernel: String,
    pub runc_version: String,
    pub criu_version: String,
    pub init_sha256: String,
    pub layout: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact { pub sha256: String, pub bytes: u64 }

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub template_id: String,
    pub generation: String,
    pub runtime: String,
    pub compatibility: Compatibility,
    pub base: Artifact,
    pub layers: Vec<Artifact>,
    pub checkpoint: Option<Artifact>,
    // A warm template's CPU description written by `criu cpuinfo dump` on the capturing host
    // (cpuinfo.img, x86-64 only); each worker checks it with `criu cpuinfo check` before restoring.
    pub cpuinfo: Option<Artifact>,
    pub init_argv: Vec<String>,
    pub memory_mib: Option<u64>,
    pub vcpus: Option<u32>,
    pub pids_max: u32,
    pub oci_config_sha256: Option<String>,
    pub network: crate::model::NetworkPolicy,
    pub uid: u32,
    pub gid: u32,
}

// Manifest format this worker reads and writes: sealed EROFS capture layers listed in `layers`.
// Other versions (such as schema 2 with a per-create upper archive) are rejected, not migrated.
pub const MANIFEST_SCHEMA: u32 = 3;
// Sealed capture layers a template may stack above its base (chained captures add one each).
pub const MAX_LAYERS: usize = 16;
// Whether warm templates carry CRIU's CPU description (cpuinfo.img). CRIU writes one for x86-64 only.
pub const CPUINFO_SAVED: bool = cfg!(target_arch = "x86_64");

// Return the SHA-256 fingerprint of the supplied bytes.
pub fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
// Recognize a SHA-256 fingerprint written as exactly 64 lowercase hexadecimal digits.
pub fn hex_digest(value: &str) -> bool { value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }

// Require every directory in the path to be administrator-owned, not a symlink and not writable by
// others.
pub fn trusted_directory(path: &Path) -> Result<()> {
    // Administrator-owned ancestors exclude symlink swaps by untrusted users.
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part);
        let meta = fs::symlink_metadata(&current).map_err(|_| "directory_unavailable")?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 { return Err("untrusted_directory"); }
    }
    Ok(())
}

// Create a directory if absent, require administrator ownership and restrict its permissions to the
// owner.
pub fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() { fs::create_dir(path).map_err(|_| "directory_create_failed")?; }
    let meta = fs::symlink_metadata(path).map_err(|_| "directory_unavailable")?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        if !meta.is_dir() || meta.uid() != 0 { return Err("untrusted_directory"); }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| "directory_permissions_failed")?;
    }
    Ok(())
}

// Create an owner-only directory exclusively, failing rather than adopting an existing path.
pub fn exclusive_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path).map_err(|_| "directory_create_failed")
}

// Read bounded JSON only from a regular, administrator-owned file that others cannot write. Reject a
// final symlink, oversized content or invalid data.
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path, limit: u64) -> Result<T> {
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path).map_err(|_| "record_unavailable")?;
    let metadata = file.metadata().map_err(|_| "record_unavailable")?;
    if !metadata.is_file() || metadata.len() > limit || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 { return Err("invalid_record"); }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(limit + 1).read_to_end(&mut bytes).map_err(|_| "record_read_failed")?;
    if bytes.len() as u64 > limit { return Err("invalid_record"); }
    serde_json::from_slice(&bytes).map_err(|_| "invalid_record")
}

// Where a file is and when it last changed: device, inode, size, and modification and change times.
// Writing, truncating, replacing or re-permissioning the file changes at least one of them.
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity { pub dev: u64, pub ino: u64, pub size: u64, pub mtime: i64, pub mtime_nsec: i64, pub ctime: i64, pub ctime_nsec: i64 }
impl FileIdentity {
    // Read the identity fields from file metadata.
    fn of(meta: &fs::Metadata) -> Self {
        Self { dev: meta.dev(), ino: meta.ino(), size: meta.size(), mtime: meta.mtime(), mtime_nsec: meta.mtime_nsec(), ctime: meta.ctime(), ctime_nsec: meta.ctime_nsec() }
    }
}

// Open a trusted artifact without following a final symlink. Reject anything but a nonempty regular
// file within `max` bytes that is administrator-owned and not writable by group or others.
fn open_artifact(path: &Path, max: u64) -> Result<(File, fs::Metadata)> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path).map_err(|_| "artifact_unavailable")?;
    let meta = file.metadata().map_err(|_| "artifact_unavailable")?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > max || meta.uid() != 0 || meta.mode() & 0o022 != 0 { return Err("invalid_artifact"); }
    Ok((file, meta))
}

// Return the identity of a trusted artifact file without reading its contents (same checks as
// `artifact`).
pub fn artifact_identity(path: &Path, max: u64) -> Result<FileIdentity> {
    open_artifact(path, max).map(|(_, meta)| FileIdentity::of(&meta))
}

// Read the entire trusted artifact to compute its SHA-256 and byte count. Reject symlinks, empty or
// oversized files, untrusted ownership and reads exceeding the deadline.
pub fn artifact(path: &Path, max: u64) -> Result<Artifact> {
    let (file, _) = open_artifact(path, max)?;
    hash_file(file, max)
}

// Hash an open artifact from its start within the five-minute deadline and return its digest and size.
fn hash_file(mut file: File, max: u64) -> Result<Artifact> {
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut bytes = 0u64;
    let started = std::time::Instant::now();
    loop {
        if started.elapsed() > std::time::Duration::from_secs(300) { return Err("artifact_verification_deadline"); }
        let n = file.read(&mut buf).map_err(|_| "artifact_read_failed")?;
        if n == 0 { break; }
        bytes += n as u64;
        if bytes > max { return Err("artifact_too_large"); }
        hash.update(&buf[..n]);
    }
    Ok(Artifact { sha256: format!("{:x}", hash.finalize()), bytes })
}

// Validate the expected descriptor, then fully hash the artifact and compare both digest and size.
pub fn verify(path: &Path, expected: &Artifact, max: u64) -> Result<()> {
    verify_identified(path, expected, max).map(|_| ())
}

// Verify an artifact like `verify` and return the identity its file had while it was hashed. Fail if
// the identity of the open file changed during hashing.
pub fn verify_identified(path: &Path, expected: &Artifact, max: u64) -> Result<FileIdentity> {
    if !hex_digest(&expected.sha256) || expected.bytes > max { return Err("invalid_artifact_descriptor"); }
    let (file, meta) = open_artifact(path, max)?;
    let before = FileIdentity::of(&meta);
    let probe = file.try_clone().map_err(|_| "artifact_unavailable")?;
    let actual = hash_file(file, max)?;
    let after = probe.metadata().map_err(|_| "artifact_unavailable")?;
    if FileIdentity::of(&after) != before { return Err("artifact_changed_while_hashed"); }
    if actual.sha256 != expected.sha256 || actual.bytes != expected.bytes { Err("artifact_digest_mismatch") } else { Ok(before) }
}

// Load a template manifest with bounded manifest-only checks (digest sidecar, strict fields, exact
// host compatibility of architecture, kernel, runc, CRIU, init and layout), cheap enough for every
// create. The CPU check of a warm template is done by the worker (Native::cpu_compatible). Artifact
// contents are not read. Return the manifest and its digest, which keys the node's checkpoint cache.
pub fn load_manifest(root: &Path, id: &str, compatibility: &Compatibility) -> Result<(Manifest, String)> {
    if !valid_id(id) { return Err("invalid_template_id"); }
    let dir = root.join("templates").join(id);
    trusted_directory(&dir)?;
    let digest_file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(dir.join("manifest.sha256")).map_err(|_| "manifest_digest_unavailable")?;
    let meta = digest_file.metadata().map_err(|_| "manifest_digest_unavailable")?;
    if !meta.is_file() || meta.len() != 65 || meta.uid() != 0 || meta.mode() & 0o022 != 0 { return Err("invalid_manifest_digest"); }
    let mut expected = String::new();
    digest_file.take(66).read_to_string(&mut expected).map_err(|_| "invalid_manifest_digest")?;
    let Some(expected) = expected.strip_suffix('\n').map(str::to_owned) else { return Err("invalid_manifest_digest"); };
    if !hex_digest(&expected) || artifact(&dir.join("manifest.json"), 65536)?.sha256 != expected { return Err("manifest_digest_mismatch"); }
    let m: Manifest = read_json(&dir.join("manifest.json"), 65536)?;
    let warm = m.checkpoint.is_some();
    if m.schema_version != MANIFEST_SCHEMA || m.template_id != id || !valid_id(&m.generation)
        || m.runtime != "runc_criu" || &m.compatibility != compatibility
        || !m.network.valid() || m.uid != 65534 || m.gid != 65534
        // A warm template has its sealed upper layer(s) and checkpoint from one capture.
        || warm == m.layers.is_empty() || m.layers.len() > MAX_LAYERS
        // Warm templates require exact resources; cold ones may declare create defaults.
        || (warm && (m.memory_mib.is_none() || m.vcpus.is_none()))
        || m.memory_mib.is_some_and(|v| !(1..=1_048_576).contains(&v)) || m.vcpus.is_some_and(|v| !(1..=4_096).contains(&v))
        || warm != m.oci_config_sha256.is_some() || (warm && CPUINFO_SAVED) != m.cpuinfo.is_some()
        || m.oci_config_sha256.as_ref().is_some_and(|d| !hex_digest(d))
        || m.init_argv.is_empty() || m.init_argv.len() > 64
        || m.init_argv.iter().any(|a| a.len() > 4096 || a.contains('\0')) || !m.init_argv[0].starts_with('/')
    { return Err("incompatible_template"); }
    if !std::iter::once(&m.base).chain(&m.layers).chain(&m.checkpoint).chain(&m.cpuinfo).all(|a| hex_digest(&a.sha256)) { return Err("invalid_artifact_descriptor"); }
    Ok((m, expected))
}

// Durably write the manifest, exclusively create its digest file and sync the containing directory.
pub fn write_manifest(dir: &Path, manifest: &Manifest) -> Result<()> {
    process::atomic_json(&dir.join("manifest.json"), manifest)?;
    let hash = artifact(&dir.join("manifest.json"), 65536)?.sha256;
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW)
        .open(dir.join("manifest.sha256")).map_err(|_| "manifest_digest_write_failed")?;
    file.write_all(format!("{hash}\n").as_bytes()).and_then(|_| file.sync_all()).map_err(|_| "manifest_digest_write_failed")?;
    File::open(dir).and_then(|f| f.sync_all()).map_err(|_| "manifest_sync_failed")
}

// Move a freshly sealed layer into the content-addressed store as layers/<sha256>.erofs without ever
// replacing a published file. If that digest is already published, check the existing file fully
// and drop the new copy. Sync the file and the store directory.
pub fn publish_layer(staged: &Path, layers: &Path, layer: &Artifact, max: u64) -> Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let target = layers.join(format!("{}.erofs", layer.sha256));
    fs::set_permissions(staged, fs::Permissions::from_mode(0o600)).map_err(|_| "artifact_permissions_failed")?;
    File::open(staged).and_then(|f| f.sync_all()).map_err(|_| "artifact_sync_failed")?;
    let from = CString::new(staged.as_os_str().as_bytes()).map_err(|_| "invalid_layer_path")?;
    let to = CString::new(target.as_os_str().as_bytes()).map_err(|_| "invalid_layer_path")?;
    // A loop-mounted layer must never be replaced underneath its mount.
    if unsafe { libc::renameat2(libc::AT_FDCWD, from.as_ptr(), libc::AT_FDCWD, to.as_ptr(), libc::RENAME_NOREPLACE) } != 0 {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) { return Err("layer_publish_failed"); }
        verify(&target, layer, max)?;
        fs::remove_file(staged).map_err(|_| "layer_publish_failed")?;
    }
    File::open(layers).and_then(|f| f.sync_all()).map_err(|_| "layer_sync_failed")
}

// Archive one filesystem tree with ownership, extended attributes, ACLs and sparse files preserved.
// Restrict the resulting archive to its owner and sync it before returning.
pub fn archive(tar: &str, source: &Path, destination: &Path, seconds: u64, search_path: &str, helpers: &process::Helpers) -> Result<()> {
    process::checked(tar, &vec!["--create".into(), "--format=pax".into(), "--file".into(), destination.display().to_string(),
        "--numeric-owner".into(), "--xattrs".into(), "--xattrs-include=*".into(), "--acls".into(), "--sparse".into(),
        "--one-file-system".into(), "--directory".into(), source.display().to_string(), ".".into()], seconds, search_path, helpers, None)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o600)).map_err(|_| "artifact_permissions_failed")?;
    File::open(destination).and_then(|f| f.sync_all()).map_err(|_| "artifact_sync_failed")
}

// Extract a previously verified archive into the supplied private directory, restoring ownership,
// permissions and extended metadata.
pub fn extract(tar: &str, source: &Path, destination: &Path, seconds: u64, search_path: &str, helpers: &process::Helpers) -> Result<()> {
    // GNU tar's default traversal/symlink checks remain enabled. Only verified,
    // administrator-owned publications enter this path; there is no upload API.
    process::checked(tar, &vec!["--extract".into(), "--file".into(), source.display().to_string(),
        "--numeric-owner".into(), "--same-owner".into(), "--same-permissions".into(), "--xattrs".into(),
        "--xattrs-include=*".into(), "--acls".into(), "--directory".into(), destination.display().to_string()], seconds, search_path, helpers, None)
}

// Make a freshly written tree durable without syncing the rest of its filesystem (whose unrelated
// write-back could take seconds): start write-back of every regular file below `root` at once, then
// sync each file, each directory and the root, so the waits overlap instead of adding up. Symbolic
// links are not followed.
pub fn sync_tree(root: &Path) -> Result<()> {
    let (mut files, mut dirs, mut pending) = (Vec::new(), Vec::new(), vec![root.to_path_buf()]);
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).map_err(|_| "tree_sync_failed")? {
            let entry = entry.map_err(|_| "tree_sync_failed")?;
            let kind = entry.file_type().map_err(|_| "tree_sync_failed")?;
            if kind.is_dir() { pending.push(entry.path()); } else if kind.is_file() { files.push(entry.path()); }
        }
        dirs.push(dir);
    }
    use std::os::fd::AsRawFd;
    for file in &files {
        let file = File::open(file).map_err(|_| "tree_sync_failed")?;
        if unsafe { libc::sync_file_range(file.as_raw_fd(), 0, 0, libc::SYNC_FILE_RANGE_WRITE) } != 0 { return Err("tree_sync_failed"); }
    }
    for path in files.iter().chain(dirs.iter().rev()) {
        File::open(path).and_then(|f| f.sync_all()).map_err(|_| "tree_sync_failed")?;
    }
    Ok(())
}

// Check mount inventory for a mount at or beneath the supplied path, failing if the inventory cannot
// be read.
pub fn mounted(path: &Path) -> Result<bool> {
    Ok(crate::mounts::inventory()?.iter().any(|m| m.point.starts_with(path)))
}

// Require an EROFS mount with read-only, nodev and nosuid flags and the expected image: either a
// direct file source or a loop device whose backing file matches. Both forms survive reconciliation.
pub fn verify_lower(path: &Path, image: &Path) -> Result<()> {
    let mounts = crate::mounts::inventory()?;
    let mut matching = mounts.iter().filter(|m| m.point == path);
    let mount = matching.next().ok_or("lower_not_mounted")?;
    if matching.next().is_some() || mount.filesystem != "erofs"
        || !["ro", "nodev", "nosuid"].iter().all(|v| mount.options.iter().any(|o| o == v)) { return Err("unexpected_lower_mount"); }
    if mount.source == image { return Ok(()); }
    let backing = fs::read_to_string(format!("/sys/dev/block/{}/loop/backing_file", mount.device)).map_err(|_| "unexpected_lower_device")?;
    let backing = backing.trim();
    if backing != image.to_str().ok_or("invalid_image_path")? && format!("/{backing}") != image.display().to_string() { return Err("unexpected_lower_image"); }
    Ok(())
}

// Remove an administrator-owned private directory only after confirming no mount remains at or beneath
// it.
pub fn remove_private(path: &Path) -> Result<()> {
    if !path.exists() { return Ok(()); }
    if mounted(path)? { return Err("private_mount_still_live"); }
    let meta = fs::symlink_metadata(path).map_err(|_| "private_state_unavailable")?;
    if !meta.is_dir() || meta.uid() != 0 { return Err("untrusted_private_state"); }
    fs::remove_dir_all(path).map_err(|_| "private_state_remove_failed")
}
