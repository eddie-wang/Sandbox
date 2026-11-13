//! Blocking, bounded host commands. Called only by the dedicated lifecycle thread
//! or spawn_blocking preflight. Never inherit management credentials into tools.
use std::{fs::{self, OpenOptions}, io::{Read, Write}, os::{fd::{AsRawFd, RawFd}, unix::process::CommandExt}, path::{Path, PathBuf}, process::{Command, Stdio}, sync::atomic::{AtomicBool, AtomicU64, Ordering}, thread, time::{Duration, Instant}};
use serde::{Deserialize, Serialize};

pub const TOOL_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub interrupted: bool,
}

/// Each host command joins a private leaf before exec. Descendants inherit it,
/// including setsid/double-fork children; runc moves workloads to their own cgroups.
/// The root lock must be held before opening/reconciling this owned helper tree.
pub struct Helpers { path: PathBuf, sequence: AtomicU64, failed: AtomicBool }
impl Helpers {
    pub fn open(path: PathBuf) -> Result<Self> {
        let helpers = Self { path, sequence: AtomicU64::new(0), failed: AtomicBool::new(false) };
        helpers.remove()?;
        fs::create_dir(&helpers.path).map_err(|_| "helper_cgroup_create_failed")?;
        Ok(helpers)
    }
    pub fn path(&self) -> &Path { &self.path }
    pub fn ensure_healthy(&self) -> Result<()> {
        if self.failed.load(Ordering::SeqCst) { Err("helper_cleanup_requires_restart") } else { Ok(()) }
    }
    pub fn remove(&self) -> Result<()> {
        if !self.path.exists() { return Ok(()); }
        drain_helpers(&self.path)?;
        for entry in fs::read_dir(&self.path).map_err(|_| "helper_cgroup_scan_failed")? {
            let entry = entry.map_err(|_| "helper_cgroup_scan_failed")?;
            if entry.file_type().map_err(|_| "helper_cgroup_scan_failed")?.is_dir() {
                if !entry.file_name().to_str().is_some_and(|n| n.strip_prefix("command-").is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))) {
                    return Err("untracked_helper_cgroup");
                }
                fs::remove_dir(entry.path()).map_err(|_| "helper_cgroup_remove_failed")?;
            }
        }
        fs::remove_dir(&self.path).map_err(|_| "helper_cgroup_remove_failed")
    }
    pub fn run(&self, program: &str, args: &[String], timeout: Duration, limit: usize, quiet: bool, search_path: &str) -> Result<Output> {
        self.ensure_healthy()?;
        let path = self.path.join(format!("command-{}", self.sequence.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).map_err(|_| "helper_cgroup_create_failed")?;
        let leaf = HelperLeaf(path, &self.failed);
        let result = (|| {
            let procs = OpenOptions::new().write(true).open(leaf.0.join("cgroup.procs")).map_err(|_| "helper_cgroup_open_failed")?;
            run_inner(program, args, timeout, limit, quiet, search_path, Some(procs.as_raw_fd()))
        })();
        // Never reconcile files/mounts after a command until all its helpers drain.
        if let Err(e) = leaf.remove() { self.failed.store(true, Ordering::SeqCst); return Err(e); }
        result
    }
}
struct HelperLeaf<'a>(PathBuf, &'a AtomicBool);
impl HelperLeaf<'_> {
    fn remove(&self) -> Result<()> {
        if !self.0.exists() { return Ok(()); }
        drain_helpers(&self.0)?;
        fs::remove_dir(&self.0).map_err(|_| "helper_cgroup_remove_failed")
    }
}
impl Drop for HelperLeaf<'_> {
    fn drop(&mut self) { if self.remove().is_err() { self.1.store(true, Ordering::SeqCst); } }
}
fn drain_helpers(path: &Path) -> Result<()> {
    fs::write(path.join("cgroup.kill"), "1").map_err(|_| "helper_cgroup_kill_failed")?;
    let start = Instant::now();
    loop {
        let events = fs::read_to_string(path.join("cgroup.events")).map_err(|_| "helper_cgroup_unavailable")?;
        if events.lines().any(|l| l == "populated 0") { return Ok(()); }
        if start.elapsed() >= Duration::from_secs(5) { return Err("helper_cgroup_still_populated"); }
        thread::sleep(Duration::from_millis(20));
    }
}

// Read-only preflight executes only trusted version queries, never storage/runtime
// commands. No cgroup mutation is allowed here; parent-death signaling still applies.
pub fn inspect(program: &str, args: &[String], search_path: &str) -> Result<Output> {
    run_inner(program, args, Duration::from_secs(3), 65536, false, search_path, None)
}

pub fn version(program: &str, search_path: &str) -> Result<Output> {
    run_inner(program, &["--version".into()], Duration::from_secs(3), 4096, false, search_path, None)
}

fn run_inner(program: &str, args: &[String], timeout: Duration, limit: usize, quiet: bool, search_path: &str, helper_procs: Option<RawFd>) -> Result<Output> {
    let mut command = Command::new(program);
    command.args(args).env_clear().env("PATH", search_path).env("LANG", "C")
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    if quiet { command.stdout(Stdio::null()).stderr(Stdio::null()); }
    let parent = unsafe { libc::getpid() };
    // Only async-signal-safe syscalls between fork and exec. An already-open FD
    // fences a delayed child from joining a replacement tree after restart.
    unsafe { command.pre_exec(move || {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 { return Err(std::io::Error::last_os_error()); }
        if libc::getppid() != parent { return Err(std::io::Error::from_raw_os_error(libc::ECHILD)); }
        if let Some(fd) = helper_procs {
            if libc::write(fd, b"0".as_ptr().cast(), 1) != 1 { return Err(std::io::Error::last_os_error()); }
        }
        Ok(())
    }); }
    let mut child = command.spawn().map_err(|_| "tool_spawn_failed")?;
    if quiet {
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().map_err(|_| "tool_wait_failed")? {
                return Ok(Output { exit_code: status.code(), stdout: String::new(), stderr: String::new(), interrupted: false });
            }
            if start.elapsed() >= timeout {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL); }
                let _ = child.kill(); let _ = child.wait();
                return Ok(Output { exit_code: None, stdout: String::new(), stderr: String::new(), interrupted: true });
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    let mut stdout = child.stdout.take().ok_or("tool_pipe_failed")?;
    let mut stderr = child.stderr.take().ok_or("tool_pipe_failed")?;
    // Nonblocking reads avoid unbounded reader threads if a descendant holds a pipe.
    for fd in [std::os::fd::AsRawFd::as_raw_fd(&stdout), std::os::fd::AsRawFd::as_raw_fd(&stderr)] {
        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            let _ = child.kill(); let _ = child.wait(); return Err("tool_pipe_failed");
        }
    }
    let mut out = Vec::new();
    let mut err = Vec::new();
    let start = Instant::now();
    let mut interrupted = false;
    let status = loop {
        let mut made_progress = false;
        for (pipe, buffer) in [(&mut stdout as &mut dyn Read, &mut out), (&mut stderr as &mut dyn Read, &mut err)] {
            let mut chunk = [0u8; 4096];
            // One bounded batch per iteration, including when output is continuous.
            match pipe.read(&mut chunk) {
                Ok(n) => {
                    made_progress |= n != 0;
                    let remaining = limit.saturating_sub(buffer.len());
                    buffer.extend_from_slice(&chunk[..n.min(remaining)]);
                    if n > remaining { interrupted = true; }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {},
                Err(_) => interrupted = true,
            }
        }
        if start.elapsed() >= timeout || out.len() + err.len() > limit { interrupted = true; }
        if interrupted {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL); }
            let _ = child.kill();
            break child.wait().map_err(|_| "tool_wait_failed")?;
        }
        if let Some(status) = child.try_wait().map_err(|_| "tool_wait_failed")? {
            // Drain the remaining bounded pipe data without waiting for descendants.
            for (pipe, buffer) in [(&mut stdout as &mut dyn Read, &mut out), (&mut stderr as &mut dyn Read, &mut err)] {
                let mut tail = Vec::new();
                if pipe.take((limit.saturating_sub(buffer.len()) + 1) as u64).read_to_end(&mut tail).is_err() { interrupted = true; }
                let remaining = limit.saturating_sub(buffer.len());
                if tail.len() > remaining { interrupted = true; }
                buffer.extend_from_slice(&tail[..tail.len().min(remaining)]);
            }
            break status;
        }
        // Check deadline/size after every bounded batch, but do not throttle
        // available pipe data to one 4 KiB read per five milliseconds.
        if !made_progress { thread::sleep(Duration::from_millis(5)); }
    };
    // Use a single combined output budget, even though each pipe is drained separately.
    if out.len() + err.len() > limit { interrupted = true; err.truncate(limit.saturating_sub(out.len())); }
    Ok(Output { exit_code: status.code(), stdout: String::from_utf8_lossy(&out).into_owned(), stderr: String::from_utf8_lossy(&err).into_owned(), interrupted })
}

pub fn checked(program: &str, args: &[String], seconds: u64, search_path: &str, helpers: &Helpers) -> Result<()> {
    let output = helpers.run(program, args, Duration::from_secs(seconds), 65536, false, search_path)?;
    if output.interrupted { Err("tool_deadline_or_output_limit") }
    else if output.exit_code != Some(0) { Err("tool_failed") } else { Ok(()) }
}

pub fn atomic_json<T: Serialize>(path: &std::path::Path, value: &T) -> Result<()> {
    use std::{fs::{self, OpenOptions}, os::unix::fs::OpenOptionsExt};
    let temp = path.with_extension("pending");
    let bytes = serde_json::to_vec(value).map_err(|_| "record_encode_failed")?;
    let mut file = OpenOptions::new().write(true).create(true).truncate(true)
        .mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&temp).map_err(|_| "record_write_failed")?;
    file.write_all(&bytes).and_then(|_| file.sync_all()).map_err(|_| "record_write_failed")?;
    fs::rename(&temp, path).map_err(|_| "record_publish_failed")?;
    fs::File::open(path.parent().ok_or("invalid_record_path")?).and_then(|f| f.sync_all()).map_err(|_| "record_sync_failed")
}
