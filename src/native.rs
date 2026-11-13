//! Linux runc/CRIU backend. There is no runtime adapter or simulated success path.
use std::{collections::{BTreeMap, BTreeSet}, fs::{self, File, OpenOptions}, io::Read, os::{fd::AsRawFd, unix::fs::OpenOptionsExt}, path::{Path, PathBuf}, sync::{Condvar, Mutex, PoisonError}, time::Duration};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use crate::{config::NativeConfig, model::SandboxSpec, phases::Phases, process::{self, Result}, storage::{self, Artifact, Compatibility, FileIdentity, Manifest}};

#[derive(Clone, Serialize)]
pub struct Check { pub name: String, pub ok: bool }
#[derive(Clone, Serialize)]
pub struct Preflight {
    pub ready: bool,
    pub qualification: &'static str,
    pub checks: Vec<Check>,
    pub compatibility: Option<Compatibility>,
}

pub struct Native {
    pub config: NativeConfig,
    pub compatibility: Compatibility,
    tools: BTreeMap<String, String>,
    pub search_path: String,
    pub helpers: process::Helpers,
    // Whether sandbox overlays are mounted `volatile` (kernel 5.10 or later; see prepare).
    volatile_overlay: bool,
    // Layer digests whose shared lower this worker mounted and checked (see mount_lower); a create
    // whose layers are all here skips the serialized lower-mount thread. Never held across I/O.
    mounted_lowers: Mutex<BTreeSet<String>>,
    // Layers whose image this worker has fully hashed, by digest: their size and the identity of the
    // image file when hashed. Trusted only while the file keeps that identity; saved in
    // verified-layers.json so a restart does not rehash them.
    verified: Mutex<BTreeMap<String, VerifiedLayer>>,
    // Layer digests being hashed, plus the state-file write; other creates wait on `layer_turn_done`.
    layer_turns: Mutex<BTreeSet<String>>,
    layer_turn_done: Condvar,
    // Checkpoint cache keys being unpacked; other restores of the same key wait on `unpacked`.
    unpacking: Mutex<BTreeSet<String>>,
    unpacked: Condvar,
    // State of each pooled routing slot this worker built (see network.rs); never held across I/O.
    pub(crate) slots: Mutex<BTreeMap<usize, crate::network::SlotState>>,
    // CRIU's answer, by cpuinfo.img digest, to whether this host's CPU can run a warm template's
    // processes (see cpu_check); only definitive answers are kept, never a failed check.
    cpu_checks: Mutex<BTreeMap<String, bool>>,
    _lock: File,
}

// One fully hashed layer: its digest and size, and the identity its image file had when hashed.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedLayer { sha256: String, bytes: u64, file: FileIdentity }
// The saved verified-layer state (root-owned, 0600, replaced atomically).
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedState { schema_version: u32, layers: Vec<VerifiedLayer> }
// The state file's name in the worker root, its format version and its size limit.
const VERIFIED_STATE: &str = "verified-layers.json";
const VERIFIED_STATE_SCHEMA: u32 = 1;
const VERIFIED_STATE_MAX_BYTES: u64 = 16 << 20;
// The layer turn that serializes writes of the state file; never a layer digest.
const VERIFIED_STATE_TURN: &str = "verified-state-write";

// Read the saved verified-layer state of a worker root. A missing, unsafe (not root-owned or writable
// by group or others), oversized or malformed file, or an invalid entry, yields an empty state, so
// every layer is hashed again.
fn load_verified(root: &Path) -> BTreeMap<String, VerifiedLayer> {
    let Ok(state) = storage::read_json::<VerifiedState>(&root.join(VERIFIED_STATE), VERIFIED_STATE_MAX_BYTES) else { return BTreeMap::new() };
    if state.schema_version != VERIFIED_STATE_SCHEMA
        || state.layers.iter().any(|l| !storage::hex_digest(&l.sha256) || l.bytes != l.file.size) { return BTreeMap::new(); }
    state.layers.into_iter().map(|l| (l.sha256.clone(), l)).collect()
}

// Size limit of a template's cpuinfo.img (CRIU's description of the capturing host's CPU).
const CPUINFO_MAX_BYTES: u64 = 1 << 20;
// Deadline of one `criu cpuinfo check` (on the CPU check thread or a create job, never the admission
// coordinator).
const CPU_CHECK_SECONDS: u64 = 5;

// Decide whether `criu cpuinfo check` output is CRIU refusing the CPU itself: at least one error line,
// and every error line comes from CRIU's x86 CPU comparison and says a feature is unsupported or
// mismatched (for example "CPU xfeatures has unsupported bits"). A missing or unreadable image is
// not a refusal.
fn cpu_refusal(stderr: &str) -> bool {
    let errors: Vec<_> = stderr.lines().filter(|l| l.starts_with("Error (")).collect();
    !errors.is_empty() && errors.iter().all(|l| l.starts_with("Error (criu/arch/") && l.contains("cpu.c:")
        && ["unsupported", "not supported", "mismatch", "do not match"].iter().any(|word| l.contains(word)))
}

// Where the reaping init (the trusted static tini) is bind-mounted read-only in every sandbox.
const INIT_PATH: &str = "/.sandbox-init";

// Each running exec gets its own child resource group `exec-<exec id>` of its sandbox.
const EXEC_GROUP_PREFIX: &str = "exec-";

// How one exec ended: its exit code (none if it was stopped or never started), why it was stopped or
// failed, and whether its resource group could not be emptied and removed.
pub struct ExecEnd { pub exit_code: Option<i32>, pub interrupted: bool, pub error: Option<&'static str>, pub cleanup_failed: bool }

// Decide from the kernel release (for example "6.8.0-1-generic") whether to try the `volatile`
// option, introduced in Linux 5.10. Mount refusal still falls back to an ordinary overlay.
fn volatile_overlay_supported(release: &str) -> bool {
    let mut numbers = release.trim().split(|c: char| !c.is_ascii_digit()).map(|n| n.parse::<u32>().ok());
    matches!((numbers.next().flatten(), numbers.next().flatten()), (Some(major), Some(minor)) if (major, minor) >= (5, 10))
}

// Wait up to five seconds, checking every five milliseconds, until a sandbox's resource group holds no
// process; fail if it stays populated or cannot be read.
fn wait_unpopulated(cgroup: &Path) -> Result<()> {
    let start = std::time::Instant::now();
    while fs::read_to_string(cgroup.join("cgroup.events")).map_err(|_| "cgroup_unavailable")?.lines().any(|l| l == "populated 1") {
        if start.elapsed() > Duration::from_secs(5) { return Err("cgroup_still_populated"); }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

// Read at most the last `limit` bytes of a log file as text; an unreadable file reads as empty.
fn tail(path: &Path, limit: u64) -> String {
    use std::io::{Seek, SeekFrom};
    let Ok(mut file) = File::open(path) else { return String::new() };
    let length = file.metadata().map_or(0, |m| m.len());
    let mut bytes = Vec::new();
    if file.seek(SeekFrom::Start(length.saturating_sub(limit))).is_ok() { let _ = file.take(limit).read_to_end(&mut bytes); }
    String::from_utf8_lossy(&bytes).into_owned()
}

// Kill everything in a child resource group, wait up to five seconds for it to empty, then remove
// it. A missing group is already clean.
fn remove_group(path: &Path) -> Result<()> {
    if !path.exists() { return Ok(()); }
    fs::write(path.join("cgroup.kill"), "1").map_err(|_| "exec_cgroup_kill_failed")?;
    let start = std::time::Instant::now();
    while fs::read_to_string(path.join("cgroup.events")).map_err(|_| "exec_cgroup_unavailable")?.lines().any(|l| l == "populated 1") {
        if start.elapsed() > Duration::from_secs(5) { return Err("exec_cgroup_still_populated"); }
        std::thread::sleep(Duration::from_millis(20));
    }
    match fs::remove_dir(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err("exec_cgroup_remove_failed"),
        _ => Ok(()),
    }
}

const TOOL_NAMES: &[&str] = &["runc", "criu", "mount", "umount", "tar", "mkfs.erofs", "ip", "nft", "iptables", "iptables-save", "iptables-restore", "ip6tables-save", "ip6tables-restore", "gzip", "tini"];

// Decide whether a trusted tool is a statically linked ELF executable (no program interpreter), so
// it runs inside any image's root filesystem. Unreadable or malformed files count as not static.
fn static_executable(path: &str) -> bool {
    let mut header = Vec::new();
    if File::open(path).and_then(|f| f.take(65536).read_to_end(&mut header)).is_err() || header.len() < 64 { return false; }
    let word = |at: usize, len: usize| header.get(at..at.saturating_add(len)).map(|b| b.iter().rev().fold(0usize, |v, x| v << 8 | *x as usize));
    // 64-bit little-endian ELF (x86-64 and aarch64): program headers are at e_phoff.
    if header[..4] != *b"\x7fELF" || header[4] != 2 || header[5] != 1 { return false; }
    let (Some(offset), Some(size), Some(count)) = (word(0x20, 8), word(0x36, 2), word(0x38, 2)) else { return false; };
    (0..count).all(|i| word(offset.saturating_add(i.saturating_mul(size)), 4).is_some_and(|kind| kind != 3))
}

// Find executable tools in trusted administrator-owned directories. Reject writable or untrusted
// binaries and disallow symlinks in an explicitly configured tools directory. losetup is optional,
// used only for read-only diagnostics after a failed lower mount.
fn tools(config: Option<&NativeConfig>) -> BTreeMap<String, String> {
    use std::os::unix::fs::MetadataExt;
    let mut tools = BTreeMap::new();
    let configured = config.and_then(|c| c.tools_dir.as_deref());
    for &name in TOOL_NAMES.iter().chain([&"losetup"]) {
        for dir in configured.unwrap_or(process::TOOL_PATH).split(':') {
            let path = Path::new(dir).join(name);
            let resolved = if configured.is_some() {
                if storage::trusted_directory(Path::new(dir)).is_err() || !fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) { continue; }
                Ok(path)
            } else { path.canonicalize() };
            if let Ok(p) = resolved {
                if p.parent().is_some_and(|parent| storage::trusted_directory(parent).is_ok())
                    && fs::metadata(&p).is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.mode() & 0o111 != 0) {
                    tools.insert(name.to_owned(), p.display().to_string()); break;
                }
            }
        }
    }
    tools
}

// Build a search path from verified tool directories and reject any executable that would shadow a
// selected tool.
fn tool_search_path(tools: &BTreeMap<String, String>) -> Result<String> {
    let mut dirs = std::collections::BTreeSet::new();
    for path in tools.values() { if let Some(parent) = Path::new(path).parent() { dirs.insert(parent.display().to_string()); } }
    // Validate the PATH actually inherited by helpers, not just discovery order.
    // A rejected same-named executable in another verified tool's directory must
    // not shadow the selected binary (including the fingerprinted CRIU version).
    for &name in TOOL_NAMES {
        let selected = tools.get(name).ok_or("tool_missing")?;
        let first = dirs.iter().map(|d| Path::new(d).join(name)).find(|p| {
            std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).is_ok_and(|p| unsafe { libc::access(p.as_ptr(), libc::X_OK) } == 0)
        }).ok_or("tool_path_missing")?;
        if first.canonicalize().map_err(|_| "tool_path_unavailable")? != Path::new(selected) { return Err("tool_path_shadowed"); }
    }
    Ok(dirs.into_iter().collect::<Vec<_>>().join(":"))
}

// Inspect host prerequisites, trusted tools, configured bridge and delegated resources without
// creating runtime state. Collect compatibility fingerprints and report readiness only if every check
// passes; qualification stays unvalidated.
pub fn preflight(config: Option<&NativeConfig>) -> Preflight {
    let tools = tools(config);
    let search_path = tool_search_path(&tools);
    let mut checks = Vec::new();
    let mut add = |name: &str, ok: bool| checks.push(Check { name: name.to_owned(), ok });
    add("linux", std::env::consts::OS == "linux");
    add("supported_architecture", matches!(std::env::consts::ARCH, "x86_64" | "aarch64"));
    add("namespaces", ["pid", "mnt", "net", "ipc", "uts", "cgroup"].iter().all(|n| Path::new("/proc/self/ns").join(n).exists()));
    add("loop_control", Path::new("/dev/loop-control").exists());
    add("explicitly_enabled", config.is_some_and(|c| c.enabled));
    add("root", unsafe { libc::geteuid() } == 0);
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let caps = status.lines().find_map(|l| l.strip_prefix("CapEff:\t")).and_then(|v| u64::from_str_radix(v, 16).ok()).unwrap_or(0);
    // Runtime operations require host authority, never workload capabilities.
    let required = [0, 1, 3, 4, 5, 6, 7, 8, 12, 18, 19, 21, 24, 27].into_iter().fold(0u64, |m, b| m | 1 << b);
    add("host_capabilities", caps & required == required);
    for &name in TOOL_NAMES { add(&format!("tool_{name}"), tools.contains_key(name)); }
    add("tool_tini_static", tools.get("tini").is_some_and(|p| static_executable(p)));
    add("helper_path_matches_verified_tools", search_path.is_ok());
    if let Some(network) = config.and_then(|c| c.network.as_ref()) {
        let bridge = tools.get("ip").zip(search_path.as_ref().ok()).and_then(|(ip, path)| process::inspect(ip, &["-j".into(), "-d".into(), "link".into(), "show".into(), "dev".into(), network.bridge.clone()], path).ok())
            .filter(|o| o.exit_code == Some(0) && !o.interrupted).and_then(|o| serde_json::from_str::<Value>(&o.stdout).ok()).is_some_and(|v| v[0]["linkinfo"]["info_kind"] == "bridge");
        let addresses = tools.get("ip").zip(search_path.as_ref().ok()).and_then(|(ip, path)| process::inspect(ip, &["-j".into(), "address".into(), "show".into(), "dev".into(), network.bridge.clone()], path).ok())
            .filter(|o| o.exit_code == Some(0) && !o.interrupted).and_then(|o| serde_json::from_str::<Value>(&o.stdout).ok());
        let gateway = addresses.as_ref().and_then(|a| a.as_array()).is_some_and(|links| links.iter().any(|l| l["addr_info"].as_array().is_some_and(|a| a.iter().any(|a| a["local"] == network.gateway.to_string() && a["prefixlen"] == network.prefix))));
        add("operator_bridge_gateway", bridge && gateway);
    }
    let filesystems = fs::read_to_string("/proc/filesystems").unwrap_or_default();
    for name in ["erofs", "overlay", "cgroup2"] { add(name, filesystems.lines().any(|l| l.split_whitespace().last() == Some(name))); }
    add("seccomp_filter", status.lines().any(|l| l.starts_with("Seccomp:")));
    let root_ok = config.is_some_and(|c| storage::trusted_directory(Path::new(&c.root)).is_ok());
    add("trusted_existing_root", root_ok);
    let filesystem_ok = config.is_some_and(|c| {
        let Ok(path) = std::ffi::CString::new(c.root.as_bytes()) else { return false; };
        let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::statfs(path.as_ptr(), info.as_mut_ptr()) } != 0 { return false; }
        let info = unsafe { info.assume_init() };
        // Restrict the initial upper/work path to ext4/XFS/Btrfs, not nested
        // OverlayFS, NFS or a filesystem whose required semantics are unknown.
        matches!(info.f_type as u64, 0xef53 | 0x58465342 | 0x9123683e)
    });
    add("upper_filesystem_supported_family", filesystem_ok);
    let parent_ok = config.is_some_and(|c| {
        let p = Path::new(&c.cgroup_parent);
        storage::trusted_directory(p).is_ok() && p.join("cgroup.kill").exists()
            && fs::read_to_string(p.join("cgroup.type")).is_ok_and(|v| v.trim() == "domain")
            && ["cpu", "memory", "pids"].iter().all(|name| {
            fs::read_to_string(p.join("cgroup.subtree_control")).unwrap_or_default().split_whitespace().any(|v| v == *name)
        }) && fs::read_to_string(p.join("cgroup.procs")).is_ok_and(|v| v.trim().is_empty())
            && std::ffi::CString::new(c.cgroup_parent.as_bytes()).is_ok_and(|p| unsafe { libc::access(p.as_ptr(), libc::W_OK) } == 0)
    });
    add("delegated_empty_cgroup_parent", parent_ok);
    let version = |name: &str| -> Option<String> {
        let output = process::version(tools.get(name)?, search_path.as_ref().ok()?).ok()?;
        (!output.interrupted && output.exit_code == Some(0)).then(|| output.stdout.trim().to_owned())
    };
    // CPU features are not fingerprinted here: CRIU checks them per warm template (cpu_compatible).
    let compatibility = (|| {
        // Restored processes map the init executable, so its exact bytes are part of compatibility.
        let init = storage::artifact(Path::new(tools.get("tini")?), 1 << 26).ok()?;
        Some(Compatibility { architecture: std::env::consts::ARCH.to_owned(), kernel: fs::read_to_string("/proc/sys/kernel/osrelease").ok()?.trim().to_owned(),
            runc_version: version("runc")?, criu_version: version("criu")?,
            init_sha256: init.sha256, layout: "erofs-sealed-layers-v3-fixed-slot-tcp-established-pmtu-v1-seccomp-v4-agentenv-tini-v1".to_owned() })
    })();
    add("compatibility_fingerprint", compatibility.is_some());
    Preflight { ready: checks.iter().all(|c| c.ok), qualification: "unvalidated", checks, compatibility }
}

impl Native {
    // Require successful preflight and exclusive ownership of the runtime root. Verify tools, drain old
    // helper processes before touching runtime state, create private storage directories (including
    // the slot-pool ownership directory) and drop half-unpacked checkpoint cache entries. Unknown cache
    // entries fail closed. Load the saved verified-layer state (an unusable file means rehashing).
    pub fn open(config: NativeConfig, report: Preflight) -> Result<Self> {
        if !report.ready { return Err("preflight_failed"); }
        let root = Path::new(&config.root);
        // One authority owns each root. The lock lifetime covers reconciliation and serving.
        let lock = OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW).open(root.join("worker.lock")).map_err(|_| "worker_lock_failed")?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 { return Err("worker_root_in_use"); }
        let tools = tools(Some(&config));
        let search_path = tool_search_path(&tools)?;
        // Drain old host-side commands before inspecting/removing ANY runtime or
        // staging state. The reserved name cannot be a valid sandbox ID.
        let helpers = process::Helpers::open(Path::new(&config.cgroup_parent).join(format!(".helpers-{}", storage::digest(config.root.as_bytes()))))?;
        for dir in ["records", "private", "layers", "templates", "staging", "lowers", "runc", "checkpoints", "slots"] { storage::private_dir(&root.join(dir))?; }
        for entry in fs::read_dir(root.join("checkpoints")).map_err(|_| "checkpoint_cache_scan_failed")? {
            let entry = entry.map_err(|_| "checkpoint_cache_scan_failed")?;
            let name = entry.file_name().into_string().map_err(|_| "unknown_checkpoint_cache_state")?;
            match name.strip_suffix(".unpacking") {
                Some(key) if storage::hex_digest(key) => storage::remove_private(&entry.path())?,
                None if storage::hex_digest(&name) => {}
                _ => return Err("unknown_checkpoint_cache_state"),
            }
        }
        let verified = load_verified(root);
        let volatile_overlay = volatile_overlay_supported(&fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default());
        Ok(Self { config, compatibility: report.compatibility.ok_or("compatibility_unavailable")?, tools, search_path, helpers, volatile_overlay, mounted_lowers: Mutex::new(BTreeSet::new()),
            verified: Mutex::new(verified), layer_turns: Mutex::new(BTreeSet::new()), layer_turn_done: Condvar::new(), unpacking: Mutex::new(BTreeSet::new()), unpacked: Condvar::new(), slots: Mutex::new(BTreeMap::new()), cpu_checks: Mutex::new(BTreeMap::new()), _lock: lock })
    }
    // Return the configured root of this worker's runtime storage.
    pub fn root(&self) -> &Path { Path::new(&self.config.root) }
    // Locate a sandbox's private writable state beneath the worker root.
    pub fn private(&self, id: &str) -> PathBuf { self.root().join("private").join(id) }
    // Return the verified executable path, or fail if that tool was not discovered.
    pub fn tool(&self, name: &str) -> Result<&str> { self.tools.get(name).map(String::as_str).ok_or("tool_missing") }
    // Run a verified host tool with the configured deadline and tracked helper cleanup, requiring success.
    // A failure is written to the worker log with the tool name, exit code and bounded error output.
    pub(crate) fn command(&self, tool: &str, args: Vec<String>) -> Result<()> {
        process::checked(self.tool(tool)?, &args, self.config.command_timeout_seconds, &self.search_path, &self.helpers, None)
    }
    // Run a verified host tool (or, for `self`, this worker's own executable as an internal helper) like
    // command, but inside the network namespace pinned at `netns`.
    pub(crate) fn command_in(&self, tool: &str, netns: &Path, args: Vec<String>) -> Result<()> {
        let program = if tool == "self" { format!("/proc/{}/exe", std::process::id()) } else { self.tool(tool)?.to_owned() };
        process::checked(&program, &args, self.config.command_timeout_seconds, &self.search_path, &self.helpers, Some(netns))
    }
    // Run runc with bounded time and output; log every failure with bounded diagnostics. Detached
    // runs/restores inherit /dev/null (CRIU-restorable); only runc's own messages go to runc.log.
    pub fn runc(&self, args: Vec<String>, timeout: Duration, limit: usize) -> Result<process::Output> {
        let detached = args.first().is_some_and(|a| a == "run" || a == "restore");
        let log = match args.last() { Some(id) if detached => self.private(id).join("runc.log").display().to_string(), _ => "/dev/null".into() };
        let tool = format!("runc {}", args.first().map_or("", String::as_str));
        let mut all = vec!["--root".into(), self.root().join("runc").display().to_string(), "--log".into(), log.clone()];
        all.extend(args);
        let out = self.helpers.run(self.tool("runc")?, &all, timeout, limit, detached, &self.search_path, None)
            .inspect_err(|code| process::log_failure(&tool, code, None, ""))?;
        if out.interrupted || out.exit_code != Some(0) {
            let stderr = if detached { tail(Path::new(&log), 4096) } else { out.stderr.clone() };
            let code = if out.interrupted { "runc_deadline_or_output_limit" } else { "runc_failed" };
            process::log_failure(&tool, code, out.exit_code, &stderr);
        }
        Ok(out)
    }
    // Require an uninterrupted successful runc exit; runc logs the bounded failure diagnostics.
    fn runc_checked(&self, args: Vec<String>) -> Result<()> {
        let out = self.runc(args, Duration::from_secs(self.config.command_timeout_seconds), 65536)?;
        if out.interrupted { Err("runc_deadline_or_output_limit") }
        else if out.exit_code != Some(0) { Err("runc_failed") } else { Ok(()) }
    }
    // Load the bounded manifest and digest, checking host compatibility, approved networking and the
    // process limit. Layer/archive hashing and CRIU's CPU decision happen separately.
    pub fn template_manifest(&self, id: &str) -> Result<(Manifest, String)> {
        let (m, digest) = storage::load_manifest(self.root(), id, &self.compatibility)?;
        self.template_usable(&m)?;
        Ok((m, digest))
    }
    // Require the template's network policy to be operator-approved and its process limit to match this
    // worker's configuration.
    fn template_usable(&self, m: &Manifest) -> Result<()> {
        self.network_policy(&m.network)?;
        if m.pids_max != self.config.pids_max { return Err("incompatible_pids_limit"); }
        Ok(())
    }
    // Return CRIU's remembered answer for a CPU description (by cpuinfo.img digest), if it gave one.
    pub fn cpu_known(&self, digest: &str) -> Option<bool> {
        self.cpu_checks.lock().unwrap_or_else(PoisonError::into_inner).get(digest).copied()
    }
    // Verify cpuinfo.img and ask CRIU whether this CPU can restore it, off the admission thread.
    // Cache only success or a definitive CPU refusal; log other failures and retry on a later create.
    // Acceptance can be one-directional between two hosts.
    pub fn cpu_check(&self, template: &str, cpuinfo: &Artifact) -> Result<bool> {
        let dir = self.root().join("templates").join(template);
        storage::verify(&dir.join("cpuinfo.img"), cpuinfo, CPUINFO_MAX_BYTES)?;
        let args = vec!["cpuinfo".into(), "check".into(), "--images-dir".into(), dir.display().to_string()];
        let out = self.helpers.run(self.tool("criu")?, &args, Duration::from_secs(CPU_CHECK_SECONDS), 65536, false, &self.search_path, None)
            .inspect_err(|code| process::log_failure("criu", code, None, ""))?;
        let answer = match (out.interrupted, out.exit_code) {
            (false, Some(0)) => Ok(true),
            (false, Some(_)) if cpu_refusal(&out.stderr) => Ok(false),
            (true, _) | (_, None) => Err("cpu_check_interrupted"),
            _ => Err("cpu_check_failed"),
        };
        match answer {
            Ok(answer) => {
                if !answer { process::log_failure("criu", "cpu_incompatible", out.exit_code, &out.stderr); }
                self.cpu_checks.lock().unwrap_or_else(PoisonError::into_inner).insert(cpuinfo.sha256.clone(), answer);
            }
            Err(code) => process::log_failure("criu", code, out.exit_code, &out.stderr),
        }
        answer
    }
    // Require CRIU to accept this host's CPU for a warm template: the remembered answer, or a check now
    // (see cpu_check). For create jobs, which normally find the answer admission waited for.
    pub fn cpu_compatible(&self, template: &str, cpuinfo: &Artifact) -> Result<()> {
        let compatible = match self.cpu_known(&cpuinfo.sha256) { Some(answer) => answer, None => self.cpu_check(template, cpuinfo)? };
        if compatible { Ok(()) } else { Err("cpu_incompatible") }
    }
    // Write CRIU's description of this host's CPU (`criu cpuinfo dump`) as cpuinfo.img into a capture's
    // staging directory, owner-only, and return its digest; this host is remembered as compatible.
    // CRIU describes x86-64 CPUs only, so on other architectures there is nothing to save.
    pub fn save_cpuinfo(&self, dir: &Path) -> Result<Option<Artifact>> {
        use std::os::unix::fs::PermissionsExt;
        if !storage::CPUINFO_SAVED { return Ok(None); }
        self.command("criu", vec!["cpuinfo".into(), "dump".into(), "--images-dir".into(), dir.display().to_string()]).map_err(|_| "cpuinfo_dump_failed")?;
        let file = dir.join("cpuinfo.img");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).map_err(|_| "artifact_permissions_failed")?;
        let cpuinfo = storage::artifact(&file, CPUINFO_MAX_BYTES)?;
        self.cpu_checks.lock().unwrap_or_else(PoisonError::into_inner).insert(cpuinfo.sha256.clone(), true);
        Ok(Some(cpuinfo))
    }
    // Check that no network, private storage, runtime state or resource group already uses this sandbox
    // ID.
    pub fn resources_absent(&self, id: &str) -> bool {
        self.network_absent(id) && !self.private(id).exists() && !self.root().join("runc").join(id).exists()
            && !Path::new(&self.config.cgroup_parent).join(id).exists()
    }
    // Return the shared read-only mount point of one EROFS layer.
    fn lower(&self, digest: &str) -> PathBuf { self.root().join("lowers").join(digest) }
    // Return the content-addressed image file of one EROFS layer.
    pub fn layer_image(&self, digest: &str) -> PathBuf { self.root().join("layers").join(format!("{digest}.erofs")) }
    // Decide whether a layer can be used without hashing: this worker hashed that digest before and its
    // image file still has the identity it had then (and is administrator-owned and not writable by
    // group or others). A known digest with a different size is rejected.
    fn layer_trusted(&self, layer: &Artifact) -> Result<bool> {
        let known = self.verified.lock().unwrap_or_else(PoisonError::into_inner).get(&layer.sha256).cloned();
        let Some(known) = known else { return Ok(false) };
        if known.bytes != layer.bytes { return Err("artifact_digest_mismatch"); }
        Ok(storage::artifact_identity(&self.layer_image(&layer.sha256), self.config.max_artifact_bytes).is_ok_and(|file| file == known.file))
    }
    // Fully hash every layer image of a create that is not already trusted, on the calling create job,
    // so creates run their hashes in parallel and never wait behind another create's hash. Creates of
    // the same new digest hash it once: the others wait for that turn and then trust the result. New
    // results, and a failed digest's removal, are saved to the state file.
    pub fn verify_layers(&self, layers: &[Artifact]) -> Result<()> {
        let mut changed = false;
        for layer in layers {
            if self.layer_trusted(layer)? { continue; }
            let _turn = KeyTurn::take(&self.layer_turns, &self.layer_turn_done, &layer.sha256);
            if self.layer_trusted(layer)? { continue; }
            let hashed = storage::verify_identified(&self.layer_image(&layer.sha256), layer, self.config.max_artifact_bytes);
            let mut verified = self.verified.lock().unwrap_or_else(PoisonError::into_inner);
            match hashed {
                Ok(file) => { verified.insert(layer.sha256.clone(), VerifiedLayer { sha256: layer.sha256.clone(), bytes: layer.bytes, file }); }
                Err(e) => {
                    verified.remove(&layer.sha256);
                    drop(verified);
                    let _ = self.save_verified();
                    return Err(e);
                }
            }
            changed = true;
        }
        // A failed write only costs a rehash after the next restart.
        if changed { let _ = self.save_verified(); }
        Ok(())
    }
    // Remember a layer this worker just hashed and published, with the identity of its published image,
    // so restores never rehash it; save the state file. A known digest with a different size is
    // rejected.
    pub fn mark_verified(&self, layer: &Artifact) -> Result<()> {
        let file = storage::artifact_identity(&self.layer_image(&layer.sha256), self.config.max_artifact_bytes)?;
        if file.size != layer.bytes { return Err("artifact_digest_mismatch"); }
        {
            let mut verified = self.verified.lock().unwrap_or_else(PoisonError::into_inner);
            if verified.get(&layer.sha256).is_some_and(|known| known.bytes != layer.bytes) { return Err("artifact_digest_mismatch"); }
            verified.insert(layer.sha256.clone(), VerifiedLayer { sha256: layer.sha256.clone(), bytes: layer.bytes, file });
        }
        let _ = self.save_verified();
        Ok(())
    }
    // Atomically replace the state file with the current verified-layer set (root-owned, 0600). Writers
    // take turns; each writes the newest set, and the set's lock is not held during the write.
    fn save_verified(&self) -> Result<()> {
        let _turn = KeyTurn::take(&self.layer_turns, &self.layer_turn_done, VERIFIED_STATE_TURN);
        let layers = self.verified.lock().unwrap_or_else(PoisonError::into_inner).values().cloned().collect();
        process::atomic_json(&self.root().join(VERIFIED_STATE), &VerifiedState { schema_version: VERIFIED_STATE_SCHEMA, layers })
    }
    // Mount one immutable EROFS layer (a template base or a sealed capture layer) if needed. The create
    // job verified it first (see verify_layers); an untrusted layer is refused, never hashed here. Check
    // the mount flags and backing image on every use, including reuse of an existing mount, and
    // remember the layer as mounted.
    pub fn mount_lower(&self, layer: &Artifact) -> Result<()> {
        if !self.layer_trusted(layer)? { return Err("layer_not_verified"); }
        let image = self.layer_image(&layer.sha256);
        let lower = self.lower(&layer.sha256);
        if !lower.exists() { storage::private_dir(&lower)?; }
        storage::trusted_directory(&lower)?;
        if !storage::mounted(&lower)? {
            if let Err(error) = self.command("mount", vec!["--internal-only".into(), "-t".into(), "erofs".into(), "-o".into(), "loop,ro,nodev,nosuid".into(), image.display().to_string(), lower.display().to_string()]) {
                self.lower_mount_diagnostic(&image, &layer.sha256);
                return Err(error);
            }
        }
        storage::verify_lower(&lower, &image)?;
        self.mounted_lowers.lock().unwrap_or_else(PoisonError::into_inner).insert(layer.sha256.clone());
        Ok(())
    }
    // Log bounded, read-only lower-mount diagnostics: actual EROFS feature bits, kernel support,
    // existing loop devices and optional losetup errors. Never allocate or detach a loop device,
    // change readiness, or replace the original mount error with a diagnostic failure.
    fn lower_mount_diagnostic(&self, image: &Path, digest: &str) {
        use std::io::{Seek, SeekFrom};
        let mut header = [0u8; 88];
        let superblock = File::open(image).and_then(|mut f| {
            f.seek(SeekFrom::Start(1024))?;
            f.read_exact(&mut header)
        }).ok().map(|_| {
            let word = |at| u32::from_le_bytes(header[at..at + 4].try_into().unwrap());
            json!({"magic": format!("{:08x}", word(0)), "feature_compat": format!("{:08x}", word(8)),
                "feature_incompat": format!("{:08x}", word(80)), "block_size_bits": header[12]})
        });
        let mut present = 0usize;
        let mut backed = 0usize;
        let mut nodes = 0usize;
        let mut truncated = false;
        if let Ok(entries) = fs::read_dir("/sys/block") {
            for (index, entry) in entries.enumerate() {
                if index >= 4096 { truncated = true; break; }
                let Ok(entry) = entry else { continue };
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.strip_prefix("loop").is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit())) { continue; }
                present += 1;
                backed += usize::from(entry.path().join("loop/backing_file").exists());
                nodes += usize::from(Path::new("/dev").join(name.as_ref()).exists());
            }
        }
        let features: Vec<_> = fs::read_dir("/sys/fs/erofs/features").into_iter().flatten().take(64)
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().chars().take(64).collect::<String>())).collect();
        let control_error = File::open("/dev/loop-control").err().and_then(|e| e.raw_os_error());
        let mut tools = serde_json::Map::new();
        for (name, args) in [("losetup", vec!["--list".into(), "--noheadings".into(), "--output".into(), "NAME".into()]),
            ("mkfs.erofs", vec!["--version".into()])] {
            let Some(tool) = self.tools.get(name) else { tools.insert(name.into(), json!({"available": false})); continue; };
            let result = self.helpers.run(tool, &args, Duration::from_secs(3), 4096, false, &self.search_path, None);
            match result {
                Ok(out) => {
                    if out.interrupted || out.exit_code != Some(0) { process::log_failure(name, "mount_diagnostic_failed", out.exit_code, &out.stderr); }
                    tools.insert(name.into(), json!({"exit": out.exit_code, "interrupted": out.interrupted,
                        "stdout": out.stdout.chars().take(256).collect::<String>(), "stderr": out.stderr.chars().take(256).collect::<String>()}));
                }
                Err(error) => { process::log_failure(name, error, None, ""); tools.insert(name.into(), json!({"error": error})); }
            }
        }
        eprintln!("sandboxd: lower_mount_diagnostic {}", json!({"image_sha256": digest, "erofs_superblock": superblock,
            "kernel": self.compatibility.kernel, "kernel_erofs_features": features, "loop_control_open_errno": control_error,
            "loop_sysfs_present": present, "loop_backed": backed, "loop_device_nodes": nodes, "loop_scan_truncated": truncated,
            "tools": tools}));
    }
    // Decide whether every one of these layers already has a shared lower this worker mounted and
    // checked, so a create can skip the lower-mount thread (prepare still checks each mount).
    pub fn lowers_mounted(&self, layers: &[Artifact]) -> bool {
        let mounted = self.mounted_lowers.lock().unwrap_or_else(PoisonError::into_inner);
        layers.iter().all(|layer| mounted.contains(&layer.sha256))
    }
    // Return shared read-only CRIU images keyed by manifest digest. The first restore verifies and
    // unpacks the archive, syncs its files, then publishes it atomically; failures remove staging.
    // Concurrent restores wait for this unpack; later restores reuse the durable directory.
    pub fn checkpoint_images(&self, manifest: &Manifest, key: &str) -> Result<PathBuf> {
        let archive = manifest.checkpoint.as_ref().ok_or("checkpoint_missing")?;
        if !storage::hex_digest(key) { return Err("invalid_checkpoint_cache_key"); }
        let cache = self.root().join("checkpoints");
        let ready = cache.join(key);
        let _turn = KeyTurn::take(&self.unpacking, &self.unpacked, key);
        if ready.exists() { storage::trusted_directory(&ready)?; return Ok(ready); }
        let staging = cache.join(format!("{key}.unpacking"));
        storage::remove_private(&staging)?;
        storage::exclusive_private_dir(&staging)?;
        let template = self.root().join("templates").join(&manifest.template_id);
        let unpacked = (|| {
            storage::verify(&template.join("checkpoint.tar"), archive, self.config.max_artifact_bytes)?;
            storage::extract(self.tool("tar")?, &template.join("checkpoint.tar"), &staging, self.config.command_timeout_seconds, &self.search_path, &self.helpers)?;
            // tar does not sync what it writes. Every extracted file and directory is synced before the
            // rename makes the cache entry trusted; only those, not the whole host filesystem (whose
            // unrelated write-back could take seconds).
            storage::sync_tree(&staging).map_err(|_| "checkpoint_cache_sync_failed")
        })();
        if let Err(e) = unpacked {
            // Only after every helper drained (tar may have been killed at its deadline).
            let _ = self.helpers.ensure_healthy().and_then(|_| storage::remove_private(&staging));
            return Err(e);
        }
        fs::rename(&staging, &ready).map_err(|_| "checkpoint_cache_publish_failed")?;
        File::open(&cache).and_then(|f| f.sync_all()).map_err(|_| "checkpoint_cache_sync_failed")?;
        Ok(ready)
    }
    // Build a sandbox: private directories, an overlay root whose lowers are the template's verified
    // sealed layers above its base, with a fresh empty upper, plus its resource group, network and
    // execution specification. Then start it cold or restore it from the shared checkpoint images and
    // confirm it runs, timing each step. Partial state is left for the caller's cleanup.
    pub fn prepare(&self, request: &SandboxSpec, manifest: &Manifest, images: Option<&Path>, network_slot: Option<usize>, expires_at: u64, cancelled: &std::sync::atomic::AtomicBool, phases: &mut Phases) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let id = &request.sandbox_id;
        let private = self.private(id);
        storage::private_dir(&private)?;
        for name in ["upper", "work", "rootfs", "criu-work"] { storage::private_dir(&private.join(name))?; }
        // The upper root is the merged root directory, for cold and warm sandboxes alike.
        fs::set_permissions(private.join("upper"), fs::Permissions::from_mode(0o755)).map_err(|_| "upper_permissions_failed")?;
        if images.is_some() != manifest.checkpoint.is_some() { return Err("checkpoint_images_missing"); }
        if manifest.checkpoint.is_some() && (manifest.memory_mib != Some(request.memory_mib) || manifest.vcpus != Some(request.vcpus)) { return Err("incompatible_checkpoint_resources"); }
        phases.mark("rootfs_dirs");
        let mut lowers = Vec::new();
        for layer in manifest.layers.iter().chain(std::iter::once(&manifest.base)) {
            let lower = self.lower(&layer.sha256);
            // A lower that is no longer the checked mount is forgotten, so the next create mounts it
            // again through the lower-mount thread.
            if let Err(e) = storage::verify_lower(&lower, &self.layer_image(&layer.sha256)) {
                self.mounted_lowers.lock().unwrap_or_else(PoisonError::into_inner).remove(&layer.sha256);
                return Err(e);
            }
            lowers.push(lower.display().to_string());
        }
        // Topmost sealed layer first. Work/upper are ordinary private sibling directories. The upper
        // is disposable (a crash or delete removes it; a capture seals it from the page cache), so a
        // volatile overlay skips syncing it: otherwise unmounting it syncs the whole host filesystem
        // that holds it, waiting behind unrelated write-back.
        let volatile = if self.volatile_overlay { ",volatile" } else { "" };
        let options = format!("nodev,nosuid,lowerdir={},upperdir={},workdir={},index=off,metacopy=off,redirect_dir=off,xino=off", lowers.join(":"), private.join("upper").display(), private.join("work").display());
        let mount = |suffix: &str| self.command("mount", vec!["--internal-only".into(), "-t".into(), "overlay".into(), "overlay".into(), "-o".into(),
            format!("{options}{suffix}"), private.join("rootfs").display().to_string()]);
        match mount(volatile) {
            // Vendor kernels/backing filesystems may not support volatile despite the release number.
            // Retry only an exited mount failure, after all helpers drained and no mount was created.
            Err("tool_failed") if !volatile.is_empty() && !storage::mounted(&private.join("rootfs"))? => {
                eprintln!("sandboxd: volatile overlay unavailable; retrying ordinary overlay");
                mount("")?;
            }
            result => result?,
        }
        phases.mark("overlay_mount");
        self.cgroup(request)?;
        phases.mark("cgroup");
        self.prepare_network(id, &manifest.network, network_slot, phases)?;
        self.write_spec(request, manifest)?;
        if manifest.oci_config_sha256.as_ref().is_some_and(|d| self.spec_digest(id).as_ref() != Ok(d)) { return Err("oci_config_mismatch"); }
        phases.mark("oci_spec");
        if expires_at <= crate::engine::now() || cancelled.load(std::sync::atomic::Ordering::Relaxed) { return Err("sandbox_cancelled_or_expired"); }
        if let Some(images) = images { self.restore(id, images)?; phases.mark("runc_restore"); }
        else { self.runc_checked(vec!["run".into(), "--detach".into(), "--bundle".into(), private.display().to_string(), id.clone()])?; phases.mark("runc_run"); }
        self.ensure_running(id)?;
        phases.mark("ensure_running");
        Ok(())
    }
    // Create the sandbox's resource group with its memory (no swap, whole-group OOM kill), process
    // and CPU limits.
    fn cgroup(&self, request: &SandboxSpec) -> Result<()> {
        let p = Path::new(&self.config.cgroup_parent).join(&request.sandbox_id);
        fs::create_dir(&p).map_err(|_| "cgroup_create_failed")?;
        for (name, value) in [("memory.max", (request.memory_mib * 1048576).to_string()), ("memory.swap.max", "0".into()),
            ("memory.oom.group", "1".into()), ("pids.max", self.config.pids_max.to_string()), ("cpu.max", format!("{} 100000", request.vcpus as u64 * 100000))] {
            fs::write(p.join(name), value).map_err(|_| "cgroup_limit_failed")?;
        }
        Ok(())
    }
    // Write the CRIU settings and the runc execution specification: the read-only reaping init running
    // the template's argv unprivileged, private namespaces (joining the prepared guest network
    // namespace), minimal devices, resource limits, masked kernel paths and the syscall policy.
    fn write_spec(&self, request: &SandboxSpec, manifest: &Manifest) -> Result<()> {
        let private = self.private(&request.sandbox_id);
        // Request-specific CRIU options are worker-authored. Administrator-owned
        // system CRIU configuration is part of the trusted host prerequisites.
        fs::write(private.join("criu.conf"), "network-lock nftables\n").map_err(|_| "criu_config_failed")?;
        // PID 1 is tini: it runs init_argv as its child, forwards signals and reaps orphans.
        let process = self.process_spec([INIT_PATH.to_owned(), "--".to_owned()].into_iter().chain(manifest.init_argv.iter().cloned()).collect());
        let mut spec = json!({
            "ociVersion": "1.2.0", "process": process, "root": {"path": "rootfs", "readonly": false}, "hostname": "sandbox",
            "annotations": {"org.criu.config": private.join("criu.conf").display().to_string(), "org.sandbox.network-policy": crate::engine::fingerprint(&manifest.network)},
            "mounts": [
                {"destination":"/proc", "type":"proc", "source":"proc", "options":["nosuid","noexec","nodev"]},
                {"destination":"/dev", "type":"tmpfs", "source":"tmpfs", "options":["nosuid","strictatime","mode=755","size=1m"]},
                {"destination":INIT_PATH, "type":"bind", "source":self.tool("tini")?, "options":["bind","ro","nosuid","nodev"]}
            ],
            "linux": {
                "cgroupsPath": format!("{}/{}", self.config.cgroup_parent.trim_start_matches("/sys/fs/cgroup"), request.sandbox_id),
                "namespaces": [{"type":"pid"},{"type":"mount"},{"type":"network"},{"type":"ipc"},{"type":"uts"},{"type":"cgroup"}],
                "rootfsPropagation":"private",
                "devices": [
                    {"path":"/dev/null","type":"c","major":1,"minor":3,"fileMode":438,"uid":0,"gid":0},
                    {"path":"/dev/zero","type":"c","major":1,"minor":5,"fileMode":438,"uid":0,"gid":0},
                    {"path":"/dev/random","type":"c","major":1,"minor":8,"fileMode":438,"uid":0,"gid":0},
                    {"path":"/dev/urandom","type":"c","major":1,"minor":9,"fileMode":438,"uid":0,"gid":0}
                ],
                "resources": {"memory":{"limit":request.memory_mib * 1048576, "swap":request.memory_mib * 1048576},
                    "cpu":{"quota":request.vcpus as u64 * 100000,"period":100000}, "pids":{"limit":self.config.pids_max},
                    "devices":[{"allow":false,"access":"rwm"},
                        {"allow":true,"type":"c","major":1,"minor":3,"access":"rw"},
                        {"allow":true,"type":"c","major":1,"minor":5,"access":"rw"},
                        {"allow":true,"type":"c","major":1,"minor":8,"access":"rw"},
                        {"allow":true,"type":"c","major":1,"minor":9,"access":"rw"}]},
                "maskedPaths":["/proc/acpi","/proc/asound","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/proc/interrupts"],
                "readonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"],
                "seccomp": seccomp()
            }
        });
        // Every sandbox joins its worker-created guest namespace, isolated ones too.
        spec["linux"]["namespaces"][2]["path"] = json!(format!("/run/netns/{}", self.guest_name(&request.sandbox_id)));
        process::new_private_json(&private.join("config.json"), &spec)
    }
    // Hash the saved execution specification after replacing worker-local reconstruction paths (cgroup,
    // guest netns, CRIU config, init binary) with stable markers.
    pub fn spec_digest(&self, id: &str) -> Result<String> {
        let mut spec: Value = storage::read_json(&self.private(id).join("config.json"), 65536)?;
        // Only worker-local reconstruction paths vary between independent containers.
        spec["linux"]["cgroupsPath"] = Value::String("<private-cgroup>".into());
        if spec["linux"]["namespaces"][2].get("path").is_some() { spec["linux"]["namespaces"][2]["path"] = json!("<private-guest-netns>"); }
        spec["annotations"]["org.criu.config"] = json!("<worker-criu-config>");
        // The init's bytes are pinned by the compatibility fingerprint, not by its host path.
        if let Some(mounts) = spec["mounts"].as_array_mut() {
            for mount in mounts.iter_mut().filter(|m| m["destination"] == INIT_PATH) { mount["source"] = json!("<worker-init>"); }
        }
        Ok(storage::digest(&serde_json::to_vec(&spec).map_err(|_| "spec_encode_failed")?))
    }
    // Describe an unprivileged sandbox process with fixed environment, workspace, empty capabilities and
    // resource limits.
    pub fn process_spec(&self, argv: Vec<String>) -> Value {
        json!({"terminal":false,"user":{"uid":65534,"gid":65534},"args":argv,
            "env":["PATH=/usr/local/bin:/usr/bin:/bin","HOME=/workspace","LANG=C"],"cwd":"/workspace",
            "capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[],"ambient":[]},
            "noNewPrivileges":true,"rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":1024},{"type":"RLIMIT_CORE","hard":0,"soft":0}]})
    }
    // Ask runc for container state and require a successful response reporting it as running.
    pub fn ensure_running(&self, id: &str) -> Result<()> {
        let out = self.runc(vec!["state".into(), id.into()], Duration::from_secs(5), 16384)?;
        let state: Value = serde_json::from_str(&out.stdout).map_err(|_| "container_not_running")?;
        if out.exit_code != Some(0) || state["status"] != "running" { return Err("container_not_running"); }
        Ok(())
    }
    // Freeze every process of the sandbox (cgroup freezer) through runc.
    pub fn pause(&self, id: &str) -> Result<()> { self.runc_checked(vec!["pause".into(), id.into()]).map_err(|_| "pause_failed") }
    // Thaw a paused sandbox through runc.
    pub fn resume(&self, id: &str) -> Result<()> { self.runc_checked(vec!["resume".into(), id.into()]).map_err(|_| "resume_failed") }
    // While the sandbox is frozen, report whether any of its processes has a uprobes mapping (left by a
    // host tracing or security agent). CRIU dumps such processes only with allow-uprobes.
    pub fn uprobes_present(&self, id: &str) -> Result<bool> {
        let procs = fs::read_to_string(Path::new(&self.config.cgroup_parent).join(id).join("cgroup.procs")).map_err(|_| "cgroup_unavailable")?;
        for pid in procs.split_whitespace() {
            let mut maps = String::new();
            File::open(format!("/proc/{pid}/maps")).and_then(|f| f.take(16 << 20).read_to_string(&mut maps)).map_err(|_| "process_maps_unavailable")?;
            if maps.lines().any(|l| l.ends_with("[uprobes]")) { return Ok(true); }
        }
        Ok(false)
    }
    // While frozen, check overlay write-back errors and seal its upper from the page cache into EROFS,
    // preserving whiteouts, opacity, owners, modes and attributes. On a volatile overlay sync writes
    // nothing back; the sealed image itself is synced at publication. Time both steps.
    pub fn seal_upper(&self, id: &str, image: &Path, phases: &mut Phases) -> Result<()> {
        let rootfs = File::open(self.private(id).join("rootfs")).map_err(|_| "rootfs_unavailable")?;
        if unsafe { libc::syncfs(rootfs.as_raw_fd()) } != 0 { return Err("upper_sync_failed"); }
        phases.mark("upper_sync");
        self.command("mkfs.erofs", vec!["--quiet".into(), image.display().to_string(), self.private(id).join("upper").display().to_string()])
            .map_err(|_| "upper_seal_failed")?;
        phases.mark("seal");
        Ok(())
    }
    // Checkpoint the paused source through runc and leave it running afterwards. Save process images,
    // established TCP connections, external Unix sockets and file locks, with the network locked during
    // the dump; skip connections not yet accepted, and allow uprobes mappings only when the caller found
    // some. A dump stopped at its deadline or output limit is `checkpoint_interrupted` (the caller then
    // knows a killed dump may have left the source degraded); any other failure is `checkpoint_failed`.
    pub fn checkpoint(&self, id: &str, images: &Path, allow_uprobes: bool) -> Result<()> {
        // Clients that connect while the source is frozen sit unaccepted in a listen
        // backlog, which CRIU otherwise refuses to dump. The running source still
        // serves them after the thaw; children never had them. runc has no flag for
        // this, so it goes in the per-container CRIU config. Mount compatibility
        // mode is a restore-only option.
        let config = format!("network-lock nftables\nskip-in-flight\n{}", if allow_uprobes { "allow-uprobes\n" } else { "" });
        fs::write(self.private(id).join("criu.conf"), config).map_err(|_| "criu_config_failed")?;
        self.runc_checked(vec!["checkpoint".into(), "--leave-running".into(), "--image-path".into(), images.display().to_string(),
            "--work-path".into(), self.private(id).join("criu-work").display().to_string(),
            "--tcp-established".into(), "--ext-unix-sk".into(), "--file-locks".into(), id.into()])
            .map_err(|e| if e == "runc_deadline_or_output_limit" { "checkpoint_interrupted" } else { "checkpoint_failed" })
    }
    // Restore captured processes, including established TCP connections, external Unix sockets and
    // file locks, into the prepared sandbox without replacing its resource groups; the caller confirms
    // it is running. The image directory is only read. A failure logs CRIU's error lines.
    pub fn restore(&self, id: &str, images: &Path) -> Result<()> {
        // Same restore-only options as the AgentENV container backend, plus the network lock method.
        fs::write(self.private(id).join("criu.conf"), "allow-uprobes\nmntns-compat-mode\nnetwork-lock nftables\n").map_err(|_| "criu_config_failed")?;
        self.runc_checked(vec!["restore".into(), "--detach".into(), "--bundle".into(), self.private(id).display().to_string(),
            "--image-path".into(), images.display().to_string(), "--work-path".into(), self.private(id).join("criu-work").display().to_string(),
            "--tcp-established".into(), "--ext-unix-sk".into(), "--file-locks".into(), "--manage-cgroups-mode".into(), "ignore".into(), id.into()])
            .map_err(|_| {
                // CRIU's own reason is in its restore log, which cleanup removes: log its error lines.
                let log = tail(&self.private(id).join("criu-work").join("restore.log"), 65536);
                let errors: Vec<_> = log.lines().filter(|l| l.contains("Error")).collect();
                process::log_failure("criu restore", "restore_failed", None, &errors.join("\n"));
                "restore_failed"
            })
    }
    // Run and time one runc exec in its own group, streaming chunks to sink (true means stderr).
    // Deadline, output bound or stop kills only this command's group. On every end, remove its
    // background children, group and process file; never kill the sandbox for a command's bound.
    pub fn exec(&self, id: &str, exec: u64, argv: Vec<String>, timeout: Duration, limit: usize, sink: &mut dyn FnMut(bool, &[u8]), stop: &dyn Fn() -> Option<&'static str>, phases: &mut Phases) -> ExecEnd {
        let group = Path::new(&self.config.cgroup_parent).join(id).join(format!("{EXEC_GROUP_PREFIX}{exec}"));
        let file = self.private(id).join(format!("{EXEC_GROUP_PREFIX}{exec}.json"));
        let result = fs::create_dir(&group).map_err(|_| "exec_cgroup_create_failed")
            .and_then(|_| process::new_private_json(&file, &self.process_spec(argv)))
            .and_then(|_| {
                phases.mark("exec_setup");
                let args = vec!["--root".into(), self.root().join("runc").display().to_string(), "--log".into(), "/dev/null".into(), "exec".into(),
                    "--cgroup".into(), format!("{EXEC_GROUP_PREFIX}{exec}"), "--process".into(), file.display().to_string(), id.into()];
                let kill = || { let _ = fs::write(group.join("cgroup.kill"), "1"); };
                let streamed = self.helpers.stream(self.tool("runc")?, &args, timeout, limit, &self.search_path, sink, stop, &kill);
                phases.mark("runc_exec");
                streamed
            });
        let _ = fs::remove_file(&file);
        let cleanup = remove_group(&group);
        phases.mark("exec_cleanup");
        let (exit_code, interrupted, error) = match result {
            Ok(done) => (done.exit_code, done.stopped.is_some(), done.stopped),
            Err(e) => (None, false, Some(e)),
        };
        ExecEnd { exit_code, interrupted, error: error.or(cleanup.err()), cleanup_failed: cleanup.is_err() }
    }
    // Remove every leftover exec resource group of a sandbox after killing its processes. Any other
    // child group is unknown state and fails closed.
    fn remove_exec_groups(&self, id: &str) -> Result<()> {
        let cgroup = Path::new(&self.config.cgroup_parent).join(id);
        if !cgroup.exists() { return Ok(()); }
        for entry in fs::read_dir(&cgroup).map_err(|_| "cgroup_scan_failed")? {
            let entry = entry.map_err(|_| "cgroup_scan_failed")?;
            if !entry.file_type().map_err(|_| "cgroup_scan_failed")?.is_dir() { continue; }
            let name = entry.file_name();
            let known = name.to_str().and_then(|n| n.strip_prefix(EXEC_GROUP_PREFIX)).is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
            if !known { return Err("untracked_cgroup_state"); }
            remove_group(&entry.path())?;
        }
        Ok(())
    }
    // Tear down everything a sandbox owns: kill its processes and remove its exec groups, wait until
    // its processes are gone, delete runc state, remove its resource group, return its network slot
    // to the pool and remove its guest network, unmount its root and delete private files, timing
    // each step. Stop at the first failure so the caller can retry.
    pub fn cleanup(&self, id: &str, network_slot: Option<usize>, phases: &mut Phases) -> Result<()> {
        self.helpers.ensure_healthy()?;
        // A durable record must exist before any of these resources are created.
        let cgroup = Path::new(&self.config.cgroup_parent).join(id);
        if cgroup.exists() {
            fs::write(cgroup.join("cgroup.kill"), "1").map_err(|_| "cgroup_kill_failed")?;
        }
        self.remove_exec_groups(id)?;
        phases.mark("kill");
        // Wait for the killed processes to end first, so a plain runc delete finds the container
        // stopped and removes it at once (`--force` always signals and then sleeps at least 100 ms).
        // A container runc does not yet see as stopped (or still sees as paused) is force-deleted.
        if cgroup.exists() { wait_unpopulated(&cgroup)?; }
        phases.mark("cgroup_drain");
        let state_dir = self.root().join("runc").join(id);
        if state_dir.exists() {
            let plain = self.runc(vec!["delete".into(), id.into()], Duration::from_secs(self.config.command_timeout_seconds), 65536);
            if !plain.is_ok_and(|out| out.exit_code == Some(0) && !out.interrupted) {
                self.helpers.ensure_healthy()?;
                self.runc_checked(vec!["delete".into(), "--force".into(), id.into()])?;
            }
        }
        phases.mark("runc_delete");
        if cgroup.exists() {
            wait_unpopulated(&cgroup)?;
            // runc may have removed its cgroup during delete.
            if cgroup.exists() { fs::remove_dir(&cgroup).map_err(|_| "cgroup_remove_failed")?; }
        }
        phases.mark("cgroup_remove");
        self.cleanup_network(id, network_slot)?;
        phases.mark("network_release");
        let private = self.private(id);
        let rootfs = private.join("rootfs");
        if storage::mounted(&rootfs)? { self.command("umount", vec!["--internal-only".into(), rootfs.display().to_string()])?; }
        phases.mark("rootfs_umount");
        storage::remove_private(&private)?;
        phases.mark("private_remove");
        Ok(())
    }
    // Drain and remove the worker-owned host-command resource groups.
    pub fn remove_helpers(&self) -> Result<()> { self.helpers.remove() }
    // Unmount known shared layer mounts (bases and sealed capture layers) after helper cleanup is
    // healthy, verifying each mount before removal.
    pub fn unmount_lowers(&self) -> Result<()> {
        self.helpers.ensure_healthy()?;
        for entry in fs::read_dir(self.root().join("lowers")).map_err(|_| "lower_scan_failed")? {
            let entry = entry.map_err(|_| "lower_scan_failed")?;
            if !entry.file_name().to_str().is_some_and(storage::hex_digest) { return Err("unknown_lower_state"); }
            if storage::mounted(&entry.path())? {
                storage::verify_lower(&entry.path(), &self.layer_image(&entry.file_name().to_string_lossy()))?;
                self.mounted_lowers.lock().unwrap_or_else(PoisonError::into_inner).remove(&entry.file_name().to_string_lossy().into_owned());
                self.command("umount", vec!["--internal-only".into(), entry.path().display().to_string()])?;
            }
        }
        Ok(())
    }
}

// One job's exclusive turn on a key: a checkpoint cache key (restores unpacking it), a layer digest
// (creates hashing it) or the verified-state write. Waiting releases the set's lock, so no lock is
// held while the holder works; dropping the turn wakes the waiters.
struct KeyTurn<'a> { keys: &'a Mutex<BTreeSet<String>>, changed: &'a Condvar, key: String }
impl<'a> KeyTurn<'a> {
    // Wait until no other job holds this key, then claim it.
    fn take(keys: &'a Mutex<BTreeSet<String>>, changed: &'a Condvar, key: &str) -> Self {
        let mut busy = keys.lock().unwrap_or_else(PoisonError::into_inner);
        while busy.contains(key) { busy = changed.wait(busy).unwrap_or_else(PoisonError::into_inner); }
        busy.insert(key.to_owned());
        Self { keys, changed, key: key.to_owned() }
    }
}
impl Drop for KeyTurn<'_> {
    // Release the key, even after a failure or panic, and wake the jobs waiting for it.
    fn drop(&mut self) {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner).remove(&self.key);
        self.changed.notify_all();
    }
}

// Return the syscall policy: allow everything except the io_uring calls (ENOSYS) and MPTCP sockets
// (EPROTONOSUPPORT), which CRIU cannot checkpoint.
fn seccomp() -> Value {
    // Same pattern as the AgentENV container backend: default-allow, with
    // CRIU checkpointability guards only. CRIU cannot dump io_uring instances or
    // MPTCP sockets, so these return ENOSYS/EPROTONOSUPPORT and callers fall back.
    // Isolation relies on namespaces, no capabilities, no_new_privs, cgroups and
    // network policy, not on this filter.
    let architectures = match std::env::consts::ARCH {
        "aarch64" => json!(["SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM"]),
        _ => json!(["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"]),
    };
    json!({"defaultAction":"SCMP_ACT_ALLOW","architectures":architectures,
        "syscalls":[
            {"names":["io_uring_setup","io_uring_enter","io_uring_register"],"action":"SCMP_ACT_ERRNO","errnoRet":38u32},
            {"names":["socket"],"action":"SCMP_ACT_ERRNO","errnoRet":93u32,
             "args":[{"index":2u32,"value":262u64,"op":"SCMP_CMP_EQ"}]}]})
}
