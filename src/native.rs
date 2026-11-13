//! Linux runc/CRIU backend. There is no runtime adapter or simulated success path.
use std::{collections::BTreeMap, fs::{self, File, OpenOptions}, os::{fd::AsRawFd, unix::fs::OpenOptionsExt}, path::{Path, PathBuf}, time::Duration};
use serde::Serialize;
use serde_json::{Value, json};
use crate::{config::NativeConfig, model::CreateRequest, process::{self, Result}, storage::{self, Compatibility, Manifest}};

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
    _lock: File,
}

const TOOL_NAMES: &[&str] = &["runc", "criu", "mount", "umount", "tar", "mkfs.erofs", "ip", "nft", "iptables", "iptables-save", "iptables-restore", "ip6tables-save", "ip6tables-restore", "gzip"];

fn tools(config: Option<&NativeConfig>) -> BTreeMap<String, String> {
    use std::os::unix::fs::MetadataExt;
    let mut tools = BTreeMap::new();
    let configured = config.and_then(|c| c.tools_dir.as_deref());
    for &name in TOOL_NAMES {
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
    let compatibility = (|| {
        let cpu = fs::read_to_string("/proc/cpuinfo").ok()?;
        let features = cpu.lines().find(|l| l.starts_with("flags") || l.starts_with("Features"))?.split_once(':')?.1.trim();
        Some(Compatibility { architecture: std::env::consts::ARCH.to_owned(), kernel: fs::read_to_string("/proc/sys/kernel/osrelease").ok()?.trim().to_owned(),
            cpu_features_sha256: storage::digest(features.as_bytes()), runc_version: version("runc")?, criu_version: version("criu")?,
            layout: "erofs-overlay-upper-v2-fixed-slot-tcp-pmtu-v1-seccomp-v2".to_owned() })
    })();
    add("compatibility_fingerprint", compatibility.is_some());
    Preflight { ready: checks.iter().all(|c| c.ok), qualification: "unvalidated", checks, compatibility }
}

impl Native {
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
        for dir in ["records", "private", "layers", "templates", "staging", "lowers", "runc"] { storage::private_dir(&root.join(dir))?; }
        Ok(Self { config, compatibility: report.compatibility.ok_or("compatibility_unavailable")?, tools, search_path, helpers, _lock: lock })
    }
    pub fn root(&self) -> &Path { Path::new(&self.config.root) }
    pub fn private(&self, id: &str) -> PathBuf { self.root().join("private").join(id) }
    pub fn tool(&self, name: &str) -> Result<&str> { self.tools.get(name).map(String::as_str).ok_or("tool_missing") }
    pub(crate) fn command(&self, tool: &str, args: Vec<String>) -> Result<()> {
        process::checked(self.tool(tool)?, &args, self.config.command_timeout_seconds, &self.search_path, &self.helpers)
    }
    pub fn runc(&self, args: Vec<String>, timeout: Duration, limit: usize) -> Result<process::Output> {
        let mut all = vec!["--root".into(), self.root().join("runc").display().to_string(), "--log".into(), "/dev/null".into()];
        let detached = args.first().is_some_and(|a| a == "run" || a == "restore");
        all.extend(args);
        self.helpers.run(self.tool("runc")?, &all, timeout, limit, detached, &self.search_path)
    }
    fn runc_checked(&self, args: Vec<String>) -> Result<()> {
        let out = self.runc(args, Duration::from_secs(self.config.command_timeout_seconds), 65536)?;
        if out.interrupted { Err("runc_deadline_or_output_limit") }
        else if out.exit_code != Some(0) { Err("runc_failed") } else { Ok(()) }
    }
    pub fn template(&self, id: &str) -> Result<Manifest> {
        let m = storage::load(self.root(), id, &self.compatibility, self.config.max_artifact_bytes)?;
        self.network_policy(&m.network)?;
        if m.pids_max != self.config.pids_max { return Err("incompatible_pids_limit"); }
        Ok(m)
    }
    pub fn resources_absent(&self, id: &str) -> bool {
        self.network_absent(id) && !self.private(id).exists() && !self.root().join("runc").join(id).exists()
            && !Path::new(&self.config.cgroup_parent).join(id).exists()
    }
    pub fn mount_lower(&self, manifest: &Manifest) -> Result<()> {
        let lower = self.root().join("lowers").join(&manifest.base.sha256);
        if !lower.exists() { storage::private_dir(&lower)?; }
        storage::trusted_directory(&lower)?;
        let image = self.root().join("layers").join(format!("{}.erofs", manifest.base.sha256));
        if !storage::mounted(&lower)? {
            self.command("mount", vec!["--internal-only".into(), "-t".into(), "erofs".into(), "-o".into(), "loop,ro,nodev,nosuid".into(), image.display().to_string(), lower.display().to_string()])?;
        }
        storage::verify_lower(&lower, &image)
    }
    pub fn prepare(&self, request: &CreateRequest, manifest: &Manifest, network_slot: Option<usize>, expires_at: u64, cancelled: &std::sync::atomic::AtomicBool) -> Result<()> {
        let id = &request.sandbox_id;
        let private = self.private(id);
        storage::private_dir(&private)?;
        for name in ["upper", "work", "rootfs", "images", "criu-work"] { storage::private_dir(&private.join(name))?; }
        if manifest.checkpoint.is_none() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(private.join("upper"), fs::Permissions::from_mode(0o755)).map_err(|_| "upper_permissions_failed")?;
        }
        if manifest.checkpoint.is_some() {
            if manifest.memory_mib != Some(request.memory_mib) || manifest.vcpus != Some(request.vcpus) { return Err("incompatible_checkpoint_resources"); }
            let template = self.root().join("templates").join(&manifest.template_id);
            storage::extract(self.tool("tar")?, &template.join("upper.tar"), &private.join("upper"), self.config.command_timeout_seconds, &self.search_path, &self.helpers)?;
            storage::extract(self.tool("tar")?, &template.join("checkpoint.tar"), &private.join("images"), self.config.command_timeout_seconds, &self.search_path, &self.helpers)?;
        }
        let lower = self.root().join("lowers").join(&manifest.base.sha256);
        storage::verify_lower(&lower, &self.root().join("layers").join(format!("{}.erofs", manifest.base.sha256)))?;
        // Work/upper are ordinary sibling directories, never a new lower layer.
        self.command("mount", vec!["--internal-only".into(), "-t".into(), "overlay".into(), "overlay".into(), "-o".into(),
            format!("nodev,nosuid,lowerdir={},upperdir={},workdir={},index=off,metacopy=off,redirect_dir=off,xino=off", lower.display(), private.join("upper").display(), private.join("work").display()),
            private.join("rootfs").display().to_string()])?;
        self.cgroup(request)?;
        self.prepare_network(id, &manifest.network, network_slot)?;
        self.write_spec(request, manifest)?;
        if manifest.oci_config_sha256.as_ref().is_some_and(|d| self.spec_digest(id).as_ref() != Ok(d)) { return Err("oci_config_mismatch"); }
        if expires_at <= crate::engine::now() || cancelled.load(std::sync::atomic::Ordering::Relaxed) { return Err("sandbox_cancelled_or_expired"); }
        if manifest.checkpoint.is_some() { self.restore(id, &private.join("images"))?; }
        else { self.runc_checked(vec!["run".into(), "--detach".into(), "--bundle".into(), private.display().to_string(), id.clone()])?; }
        self.ensure_running(id)
    }
    fn cgroup(&self, request: &CreateRequest) -> Result<()> {
        let p = Path::new(&self.config.cgroup_parent).join(&request.sandbox_id);
        fs::create_dir(&p).map_err(|_| "cgroup_create_failed")?;
        for (name, value) in [("memory.max", (request.memory_mib * 1048576).to_string()), ("memory.swap.max", "0".into()),
            ("memory.oom.group", "1".into()), ("pids.max", self.config.pids_max.to_string()), ("cpu.max", format!("{} 100000", request.vcpus as u64 * 100000))] {
            fs::write(p.join(name), value).map_err(|_| "cgroup_limit_failed")?;
        }
        Ok(())
    }
    fn write_spec(&self, request: &CreateRequest, manifest: &Manifest) -> Result<()> {
        let private = self.private(&request.sandbox_id);
        // Request-specific CRIU options are worker-authored. Administrator-owned
        // system CRIU configuration is part of the trusted host prerequisites.
        fs::write(private.join("criu.conf"), "network-lock nftables\n").map_err(|_| "criu_config_failed")?;
        let process = self.process_spec(manifest.init_argv.clone());
        let mut spec = json!({
            "ociVersion": "1.2.0", "process": process, "root": {"path": "rootfs", "readonly": false}, "hostname": "sandbox",
            "annotations": {"org.criu.config": private.join("criu.conf").display().to_string(), "org.sandbox.network-policy": crate::engine::fingerprint(&manifest.network)},
            "mounts": [
                {"destination":"/proc", "type":"proc", "source":"proc", "options":["nosuid","noexec","nodev"]},
                {"destination":"/dev", "type":"tmpfs", "source":"tmpfs", "options":["nosuid","strictatime","mode=755","size=1m"]}
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
                "seccomp": seccomp(!matches!(manifest.network, crate::model::NetworkPolicy::Isolated))
            }
        });
        if !matches!(manifest.network, crate::model::NetworkPolicy::Isolated) {
            spec["linux"]["namespaces"][2]["path"] = json!(format!("/run/netns/{}", self.network_names(&request.sandbox_id).0));
        }
        process::atomic_json(&private.join("config.json"), &spec)
    }
    pub fn spec_digest(&self, id: &str) -> Result<String> {
        let mut spec: Value = storage::read_json(&self.private(id).join("config.json"), 65536)?;
        // Only worker-local reconstruction paths vary between independent containers.
        spec["linux"]["cgroupsPath"] = Value::String("<private-cgroup>".into());
        if spec["linux"]["namespaces"][2].get("path").is_some() { spec["linux"]["namespaces"][2]["path"] = json!("<private-guest-netns>"); }
        spec["annotations"]["org.criu.config"] = json!("<worker-criu-config>");
        Ok(storage::digest(&serde_json::to_vec(&spec).map_err(|_| "spec_encode_failed")?))
    }
    pub fn process_spec(&self, argv: Vec<String>) -> Value {
        json!({"terminal":false,"user":{"uid":65534,"gid":65534},"args":argv,
            "env":["PATH=/usr/local/bin:/usr/bin:/bin","HOME=/workspace","LANG=C"],"cwd":"/workspace",
            "capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[],"ambient":[]},
            "noNewPrivileges":true,"rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":1024},{"type":"RLIMIT_CORE","hard":0,"soft":0}]})
    }
    pub fn ensure_running(&self, id: &str) -> Result<()> {
        let out = self.runc(vec!["state".into(), id.into()], Duration::from_secs(5), 16384)?;
        let state: Value = serde_json::from_str(&out.stdout).map_err(|_| "container_not_running")?;
        if out.exit_code != Some(0) || state["status"] != "running" { return Err("container_not_running"); }
        Ok(())
    }
    pub fn checkpoint(&self, id: &str, images: &Path) -> Result<()> {
        // Mount compatibility mode is a restore-only CRIU option.
        fs::write(self.private(id).join("criu.conf"), "network-lock nftables\n").map_err(|_| "criu_config_failed")?;
        self.runc_checked(vec!["checkpoint".into(), "--image-path".into(), images.display().to_string(),
            "--work-path".into(), self.private(id).join("criu-work").display().to_string(),
            "--file-locks".into(), id.into()]).map_err(|_| "checkpoint_failed")
    }
    pub fn restore(&self, id: &str, images: &Path) -> Result<()> {
        fs::write(self.private(id).join("criu.conf"), "mntns-compat-mode\nnetwork-lock nftables\n").map_err(|_| "criu_config_failed")?;
        self.runc_checked(vec!["restore".into(), "--detach".into(), "--bundle".into(), self.private(id).display().to_string(),
            "--image-path".into(), images.display().to_string(), "--work-path".into(), self.private(id).join("criu-work").display().to_string(),
            "--file-locks".into(), "--manage-cgroups-mode".into(), "ignore".into(), id.into()]).map_err(|_| "restore_failed")?;
        self.ensure_running(id)
    }
    pub fn restore_source(&self, request: &CreateRequest, images: &Path, expires_at: u64, cancelled: &std::sync::atomic::AtomicBool) -> Result<()> {
        if !Path::new(&self.config.cgroup_parent).join(&request.sandbox_id).exists() { self.cgroup(request)?; }
        if expires_at <= crate::engine::now() || cancelled.load(std::sync::atomic::Ordering::Relaxed) { return Err("sandbox_cancelled_or_expired"); }
        self.restore(&request.sandbox_id, images)
    }
    pub fn forget_stopped(&self, id: &str) -> Result<()> {
        // runc versions may remove stopped state as part of checkpoint itself.
        // Absence is expected; never force-delete a potentially running source.
        if !self.root().join("runc").join(id).exists() { return Ok(()); }
        self.runc_checked(vec!["delete".into(), id.into()]).map_err(|_| "checkpoint_source_delete_failed")
    }
    pub fn create_exec_cgroup(&self, id: &str, operation: &str) -> Result<()> {
        fs::create_dir(Path::new(&self.config.cgroup_parent).join(id).join(format!("exec-{operation}"))).map_err(|_| "exec_cgroup_create_failed")
    }
    pub fn cleanup_exec_cgroup(&self, id: &str, operation: &str) -> Result<()> {
        let path = Path::new(&self.config.cgroup_parent).join(id).join(format!("exec-{operation}"));
        if !path.exists() { return Ok(()); }
        fs::write(path.join("cgroup.kill"), "1").map_err(|_| "exec_cgroup_kill_failed")?;
        let start = std::time::Instant::now();
        while fs::read_to_string(path.join("cgroup.events")).map_err(|_| "exec_cgroup_unavailable")?.lines().any(|l| l == "populated 1") {
            if start.elapsed() > Duration::from_secs(5) { return Err("exec_cgroup_still_populated"); }
            std::thread::sleep(Duration::from_millis(20));
        }
        fs::remove_dir(path).map_err(|_| "exec_cgroup_remove_failed")
    }
    pub fn cleanup(&self, id: &str, operations: &[String]) -> Result<()> {
        self.helpers.ensure_healthy()?;
        // A durable record must exist before any of these resources are created.
        let cgroup = Path::new(&self.config.cgroup_parent).join(id);
        if cgroup.exists() {
            fs::write(cgroup.join("cgroup.kill"), "1").map_err(|_| "cgroup_kill_failed")?;
        }
        for operation in operations { self.cleanup_exec_cgroup(id, operation)?; }
        let state_dir = self.root().join("runc").join(id);
        if state_dir.exists() { self.runc_checked(vec!["delete".into(), "--force".into(), id.into()])?; }
        if cgroup.exists() {
            let start = std::time::Instant::now();
            while fs::read_to_string(cgroup.join("cgroup.events")).map_err(|_| "cgroup_unavailable")?.lines().any(|l| l == "populated 1") {
                if start.elapsed() > Duration::from_secs(5) { return Err("cgroup_still_populated"); }
                std::thread::sleep(Duration::from_millis(20));
            }
            // runc may have removed its cgroup during delete.
            if cgroup.exists() { fs::remove_dir(&cgroup).map_err(|_| "cgroup_remove_failed")?; }
        }
        self.cleanup_network(id)?;
        let private = self.private(id);
        let rootfs = private.join("rootfs");
        if storage::mounted(&rootfs)? { self.command("umount", vec!["--internal-only".into(), rootfs.display().to_string()])?; }
        storage::remove_private(&private)
    }
    pub fn remove_helpers(&self) -> Result<()> { self.helpers.remove() }
    pub fn unmount_lowers(&self) -> Result<()> {
        self.helpers.ensure_healthy()?;
        for entry in fs::read_dir(self.root().join("lowers")).map_err(|_| "lower_scan_failed")? {
            let entry = entry.map_err(|_| "lower_scan_failed")?;
            if !entry.file_name().to_str().is_some_and(storage::hex_digest) { return Err("unknown_lower_state"); }
            if storage::mounted(&entry.path())? {
                let image = self.root().join("layers").join(format!("{}.erofs", entry.file_name().to_string_lossy()));
                storage::verify_lower(&entry.path(), &image)?;
                self.command("umount", vec!["--internal-only".into(), entry.path().display().to_string()])?;
            }
        }
        Ok(())
    }
}

fn seccomp(network: bool) -> Value {
    // Small native-tool profile, not a universal application compatibility claim.
    // Namespace changes, mount, ptrace, bpf, perf and io_uring are absent.
    // Only the explicit network profile adds filtered TCP socket creation. Unknown syscalls fail EPERM rather than default-allow.
    let calls = "read write readv writev pread64 pwrite64 preadv pwritev close close_range lseek open openat openat2 creat fstat stat lstat newfstatat statx statfs fstatfs access faccessat faccessat2 readlink readlinkat getdents getdents64 dup dup2 dup3 fcntl ioctl flock fsync fdatasync sync_file_range truncate ftruncate fallocate rename renameat renameat2 unlink unlinkat mkdir mkdirat rmdir link linkat symlink symlinkat chmod fchmod fchmodat chown fchown lchown fchownat umask utime utimes futimesat utimensat getxattr lgetxattr fgetxattr listxattr llistxattr flistxattr setxattr lsetxattr fsetxattr removexattr lremovexattr fremovexattr mmap mprotect munmap mremap madvise mincore brk msync mlock munlock mlockall munlockall rt_sigaction rt_sigprocmask rt_sigreturn rt_sigsuspend rt_sigtimedwait rt_sigpending sigaltstack kill tkill tgkill restart_syscall nanosleep clock_nanosleep clock_gettime clock_getres gettimeofday time times getpid getppid gettid getuid geteuid getgid getegid getgroups getresuid getresgid getcwd chdir fchdir uname sysinfo getrlimit setrlimit prlimit64 getrusage sched_yield sched_getaffinity sched_setaffinity sched_getparam sched_getscheduler sched_get_priority_max sched_get_priority_min getpriority setpriority arch_prctl prctl set_tid_address set_robust_list get_robust_list futex futex_waitv rseq membarrier fork vfork execve execveat wait4 waitid exit exit_group pipe pipe2 poll ppoll select pselect6 epoll_create epoll_create1 epoll_ctl epoll_wait epoll_pwait epoll_pwait2 eventfd eventfd2 timerfd_create timerfd_settime timerfd_gettime signalfd signalfd4 getrandom memfd_create sendfile copy_file_range splice tee vmsplice fadvise64 getcpu getitimer setitimer alarm capget";
    let mut profile = json!({"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,
        "syscalls":[{"names":calls.split_whitespace().collect::<Vec<_>>(),"action":"SCMP_ACT_ALLOW"},
            {"names":["clone"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":2114060288u64,"valueTwo":0,"op":"SCMP_CMP_MASKED_EQ"}]},
            // clone3 cannot filter its pointed-to flags. ENOSYS permits libc fallback.
            {"names":["clone3"],"action":"SCMP_ACT_ERRNO","errnoRet":38}]});
    if network {
        let rules = profile["syscalls"].as_array_mut().unwrap();
        rules.push(json!({"names":["connect","bind","listen","accept","accept4","getsockname","getpeername","getsockopt","setsockopt","shutdown","sendto","recvfrom","sendmsg","recvmsg","sendmmsg","recvmmsg"],"action":"SCMP_ACT_ALLOW"}));
        // AF_INET + SOCK_STREAM only (CLOEXEC/NONBLOCK flags accepted), protocol
        // zero or TCP. No AF_INET6/UNIX/PACKET/NETLINK, UDP or raw sockets.
        for protocol in [0, 6] {
            rules.push(json!({"names":["socket"],"action":"SCMP_ACT_ALLOW","args":[
                {"index":0,"value":2,"op":"SCMP_CMP_EQ"},
                {"index":1,"value":4294440959u64,"valueTwo":1,"op":"SCMP_CMP_MASKED_EQ"},
                {"index":2,"value":protocol,"op":"SCMP_CMP_EQ"}]}));
        }
    }
    profile
}
