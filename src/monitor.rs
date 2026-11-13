//! Init supervision through conmon, separate from kill-on-return host helpers.
//! Protocol references: conmon v2.1.10 src/{conmon,runtime_args,ctr_logging,cgroup}.c and
//! Podman v4.9.0 libpod/oci_conmon_common.go createOCIContainer/readConmonPipeData.
use std::{fs::{self, File}, io::{Read, Write}, os::{fd::AsRawFd, unix::{net::UnixStream, process::CommandExt}}, path::{Path, PathBuf}, process::{Command, Stdio}, time::{Duration, Instant}};
use serde::{Deserialize, Serialize};
use crate::{process::{self, Result}, storage};

// Monitor ownership survives worker death; per-ID evidence survives sandbox deletion.
pub struct Monitors { pub path: PathBuf, root: PathBuf }

#[derive(Deserialize)]
struct SyncMessage { data: i32 }

#[derive(Deserialize, Serialize)]
struct Exit {
    exit_code: Option<i32>,
    oom: bool,
    oom_kill: Option<u64>,
    monitor_lost: bool,
    runtime_started: bool,
}

// Read a small monitor file without accepting unbounded or malformed contents.
fn small(path: &Path) -> Result<String> {
    let mut text = String::new();
    File::open(path).and_then(|f| f.take(4097).read_to_string(&mut text)).map_err(|_| "monitor_file_unavailable")?;
    if text.len() > 4096 { return Err("monitor_file_oversized"); }
    Ok(text)
}

// Return whether the owned monitor group has drained; absence is already drained.
fn empty(path: &Path) -> Result<bool> {
    if !path.exists() { return Ok(true); }
    Ok(small(&path.join("cgroup.events"))?.lines().any(|l| l == "populated 0"))
}

// Wait a bounded time for monitor processes to finish without killing the init's reaper early.
fn wait_empty(path: &Path) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !empty(path)? {
        if Instant::now() >= deadline { return Err("monitor_still_populated"); }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

// Stop a failed or unresponsive monitor and all runtime children before workload cleanup can race it.
fn drain(path: &Path) -> Result<()> {
    if !path.exists() { return Ok(()); }
    fs::write(path.join("cgroup.kill"), "1").map_err(|_| "monitor_kill_failed")?;
    wait_empty(path)
}

impl Monitors {
    // Open and sync monitor inventory under the worker root lock. Unlike host helpers, do not
    // kill live monitors here: reconciliation first checks ownership and kills their workloads.
    pub fn open(root: &Path, parent: &Path) -> Result<Self> {
        let path = parent.join(format!(".monitors-{}", storage::digest(root.as_os_str().as_encoded_bytes())));
        if !path.exists() { fs::create_dir(&path).map_err(|_| "monitor_cgroup_create_failed")?; }
        let evidence = root.join("monitors");
        storage::private_dir(&evidence)?;
        File::open(root).and_then(|f| f.sync_all()).map_err(|_| "monitor_directory_sync_failed")?;
        Ok(Self { path, root: evidence })
    }

    // Reject unknown monitor files or groups rather than adopting another worker's processes.
    pub fn reconcile(&self, known: &std::collections::BTreeSet<String>) -> Result<()> {
        for base in [&self.path, &self.root] {
            for entry in fs::read_dir(base).map_err(|_| "monitor_scan_failed")? {
                let entry = entry.map_err(|_| "monitor_scan_failed")?;
                if entry.file_type().map_err(|_| "monitor_scan_failed")?.is_dir()
                    && !entry.file_name().to_str().is_some_and(|id| known.contains(id)) { return Err("untracked_monitor_state"); }
                if base == &self.root && !entry.file_type().map_err(|_| "monitor_scan_failed")?.is_dir() { return Err("untracked_monitor_state"); }
            }
        }
        if !small(&self.path.join("cgroup.procs"))?.trim().is_empty() { return Err("untracked_monitor_process"); }
        Ok(())
    }

    // Complete conmon's start gate and bounded PID reply, as Podman's createOCIContainer does.
    // The fresh helper joins the durable group before conmon can fork. Passthrough preserves null
    // standard streams; a private working directory keeps conmon's OOM files inside its evidence.
    pub fn launch(&self, id: &str, conmon: &str, runc: &str, bundle: &Path, runtime_root: &Path,
        images: Option<&Path>, search_path: &str, timeout: Duration) -> Result<i32> {
        let dir = self.root.join(id);
        storage::exclusive_private_dir(&dir)?;
        File::open(&self.root).and_then(|f| f.sync_all()).map_err(|_| "monitor_directory_sync_failed")?;
        let group = self.path.join(id);
        fs::create_dir(&group).map_err(|_| "monitor_cgroup_create_failed")?;
        let (mut sync, sync_child) = UnixStream::pair().map_err(|_| "monitor_socket_failed")?;
        let (mut start, start_child) = UnixStream::pair().map_err(|_| "monitor_socket_failed")?;
        let mut args = vec!["--api-version=1".into(), "--cid".into(), id.into(), "--cuuid".into(), id.into(),
            "--runtime".into(), runc.into(), "--bundle".into(), bundle.display().to_string(),
            "--container-pidfile".into(), dir.join("init.pid").display().to_string(),
            "--conmon-pidfile".into(), dir.join("conmon.pid").display().to_string(),
            "--persist-dir".into(), dir.display().to_string(), "--log-path=passthrough".into()];
        for arg in ["--root".to_owned(), runtime_root.display().to_string(), "--log".into(), bundle.join("runc.log").display().to_string()] {
            args.push("--runtime-arg".into()); args.push(arg);
        }
        if let Some(images) = images {
            args.extend(["--restore".into(), images.display().to_string()]);
            for arg in ["--tcp-established".to_owned(), "--ext-unix-sk".into(), "--file-locks".into(),
                "--manage-cgroups-mode=ignore".into(), format!("--work-path={}", bundle.join("criu-work").display())] {
                args.push("--runtime-opt".into()); args.push(arg);
            }
        }
        let fds = [sync_child.as_raw_fd(), start_child.as_raw_fd()];
        let mut command = Command::new("/proc/self/exe");
        command.current_dir(&dir).arg("internal-exec").arg(std::process::id().to_string()).arg(group.join("cgroup.procs"))
            .arg("-").arg(conmon).args(args).env_clear().env("PATH", search_path).env("LANG", "C")
            .env("_OCI_SYNCPIPE", fds[0].to_string()).env("_OCI_STARTPIPE", fds[1].to_string())
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).process_group(0);
        // Only async-signal-safe descriptor operations occur before the fresh helper replaces us.
        unsafe { command.pre_exec(move || {
            for fd in fds { if libc::fcntl(fd, libc::F_SETFD, 0) < 0 { return Err(std::io::Error::last_os_error()); } }
            Ok(())
        }); }
        let mut child = command.spawn().map_err(|_| "monitor_spawn_failed")?;
        drop(sync_child); drop(start_child);
        let deadline = Instant::now() + timeout;
        let result = (|| {
            start.write_all(&[0]).map_err(|_| "monitor_start_gate_failed")?;
            drop(start);
            // A launcher exit is not a workload exit. Wait for its fork, then the real PID reply.
            loop {
                if let Some(status) = child.try_wait().map_err(|_| "monitor_wait_failed")? {
                    if !status.success() { return Err("runtime_start_failed"); }
                    break;
                }
                if Instant::now() >= deadline { return Err("runtime_start_timeout"); }
                std::thread::sleep(Duration::from_millis(5));
            }
            sync.set_nonblocking(true).map_err(|_| "monitor_socket_failed")?;
            let mut bytes = Vec::new();
            loop {
                let mut buf = [0u8; 1024];
                match sync.read(&mut buf) {
                    Ok(0) => return Err("runtime_start_failed"),
                    Ok(n) => {
                        bytes.extend_from_slice(&buf[..n]);
                        if bytes.len() > 65536 { return Err("monitor_reply_oversized"); }
                        if bytes.contains(&b'\n') {
                            let reply: SyncMessage = serde_json::from_slice(&bytes).map_err(|_| "monitor_reply_invalid")?;
                            return if reply.data > 0 { Ok(reply.data) } else { Err("runtime_start_failed") };
                        }
                    }
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => {},
                    Err(_) => return Err("runtime_start_failed"),
                }
                if Instant::now() >= deadline { return Err("runtime_start_timeout"); }
                std::thread::sleep(Duration::from_millis(5));
            }
        })();
        if result.is_err() {
            // Also kill the launcher if it died before joining the owned group.
            let _ = child.kill();
            drain(&group)?;
            let until = Instant::now() + Duration::from_secs(5);
            while child.try_wait().map_err(|_| "monitor_wait_failed")?.is_none() {
                if Instant::now() >= until { return Err("monitor_still_populated"); }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        result
    }

    // Durably distinguish successful runtime start from a subsequent early workload exit.
    pub fn started(&self, id: &str, pid: i32) -> Result<()> {
        process::atomic_json(&self.root.join(id).join("started.json"), &serde_json::json!({"pid": pid}))
    }

    // Read conmon's persisted exit/OOM evidence, plus cgroup-v2 OOM kills before runc removes it.
    // An exit status of 137 alone is never evidence of an OOM kill (conmon cgroup.c).
    fn evidence(&self, id: &str, workload: &Path) -> Result<Exit> {
        let dir = self.root.join(id);
        let exit_code = if dir.join("exit").exists() {
            let code = small(&dir.join("exit"))?.trim().parse::<i32>().map_err(|_| "monitor_exit_invalid")?;
            if !(0..=255).contains(&code) { return Err("monitor_exit_invalid"); }
            Some(code)
        } else { None };
        let oom_kill = if workload.exists() {
            Some(small(&workload.join("memory.events"))?.lines().find_map(|l| l.strip_prefix("oom_kill "))
                .and_then(|n| n.parse::<u64>().ok()).ok_or("monitor_oom_invalid")?)
        } else { None };
        Ok(Exit { exit_code, oom: dir.join("oom").exists() || oom_kill.is_some_and(|n| n > 0), oom_kill,
            monitor_lost: exit_code.is_none(), runtime_started: dir.join("started.json").exists() })
    }

    // Report a real init exit, or loss of its monitor, without inferring init life from the workload
    // group. Recheck exit evidence after the monitor drains: conmon writes it before exiting, but
    // may do so between our first file check and the group check (v2.1.10 conmon.c).
    pub fn ended(&self, id: &str, workload: &Path) -> Result<Option<&'static str>> {
        if !self.root.join(id).join("exit").exists() && !empty(&self.path.join(id))? { return Ok(None); }
        let evidence = self.evidence(id, workload)?;
        Ok(Some(if evidence.exit_code.is_none() { "monitor_lost" }
            else if evidence.oom_kill.is_some_and(|n| n > 0) { "workload_oom" } else { "workload_exited" }))
    }

    // Stop an unfinished startup before cleanup checks the workload group: a crashed create/restore
    // must not create new workload processes after cleanup has already checked or killed that group.
    pub fn stop_startup(&self, id: &str) -> Result<()> {
        if !self.root.join(id).join("started.json").exists() { drain(&self.path.join(id))?; }
        Ok(())
    }

    // After the workload drains, let conmon reap it and write its files; bound and drain a stuck
    // monitor. Save evidence before removing either group, including incomplete startup. Republish
    // the existing summary on retries: a prior rename may have succeeded but its directory sync
    // failed, so existence alone is not proof that teardown can safely proceed.
    pub fn finish(&self, id: &str, workload: &Path) -> Result<()> {
        let dir = self.root.join(id);
        let group = self.path.join(id);
        if !dir.exists() && !group.exists() { return Ok(()); }
        if !dir.is_dir() { return Err("monitor_evidence_missing"); }
        if wait_empty(&group).is_err() { drain(&group)?; }
        let result = dir.join("result.json");
        let evidence = if result.exists() { storage::read_json::<Exit>(&result, 4096)? } else { self.evidence(id, workload)? };
        process::atomic_json(&result, &evidence)?;
        if group.exists() { fs::remove_dir(&group).map_err(|_| "monitor_cgroup_remove_failed")?; }
        Ok(())
    }

    // Remove the empty monitor parent on graceful shutdown; evidence stays with retained records.
    pub fn remove(&self) -> Result<()> {
        if !self.path.exists() { return Ok(()); }
        fs::remove_dir(&self.path).map_err(|_| "monitor_cgroup_remove_failed")
    }
}
