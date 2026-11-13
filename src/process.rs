//! Blocking, bounded host commands. Called only by dedicated lifecycle and exec
//! threads or spawn_blocking preflight. Never inherit management credentials into tools.
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
    // Drain and remove any previous helper tree, then create a fresh one under the caller's existing root
    // ownership.
    pub fn open(path: PathBuf) -> Result<Self> {
        let helpers = Self { path, sequence: AtomicU64::new(0), failed: AtomicBool::new(false) };
        helpers.remove()?;
        fs::create_dir(&helpers.path).map_err(|_| "helper_cgroup_create_failed")?;
        Ok(helpers)
    }
    // Return the path of the worker-owned helper process tree.
    pub fn path(&self) -> &Path { &self.path }
    // Reject further work if a previous helper cleanup failed and requires restart.
    pub fn ensure_healthy(&self) -> Result<()> {
        if self.failed.load(Ordering::SeqCst) { Err("helper_cleanup_requires_restart") } else { Ok(()) }
    }
    // Kill and drain the helper tree, then remove only recognized command groups and the parent. Unknown
    // child groups prevent removal.
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
    // Run a host command inside a new tracked helper group with bounded time and output. Drain all
    // remaining helpers before returning; a cleanup failure blocks later work.
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
    // Run a host command (a runc exec client) in a new tracked helper group and pass its stdout/stderr
    // chunks to `sink` as they arrive (true marks stderr). Stop it through `kill` when the deadline
    // passes ("exec_timeout"), the combined output would exceed `limit` ("exec_output_limit") or `stop`
    // gives a reason. When the command ends either way, `kill` also ends what it left behind, then the
    // remaining output (up to the limit) is drained. Drain the helper group before returning; a cleanup
    // failure blocks later work.
    pub fn stream(&self, program: &str, args: &[String], timeout: Duration, limit: usize, search_path: &str,
        sink: &mut dyn FnMut(bool, &[u8]), stop: &dyn Fn() -> Option<&'static str>, kill: &dyn Fn()) -> Result<Streamed> {
        self.ensure_healthy()?;
        let path = self.path.join(format!("command-{}", self.sequence.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).map_err(|_| "helper_cgroup_create_failed")?;
        let leaf = HelperLeaf(path, &self.failed);
        let result = (|| {
            let procs = OpenOptions::new().write(true).open(leaf.0.join("cgroup.procs")).map_err(|_| "helper_cgroup_open_failed")?;
            let mut child = spawn(program, args, false, search_path, Some(procs.as_raw_fd()))?;
            let pipes = nonblocking_pipes(&mut child);
            let (stdout, stderr) = match pipes { Ok(p) => p, Err(e) => { kill(); let _ = child.kill(); let _ = child.wait(); return Err(e); } };
            Ok(stream_child(child, stdout, stderr, timeout, limit, sink, stop, kill))
        })();
        if let Err(e) = leaf.remove() { self.failed.store(true, Ordering::SeqCst); return Err(e); }
        result?
    }
}

// How a streamed command ended: its exit code (none when stopped) and why it was stopped, if it was.
pub struct Streamed { pub exit_code: Option<i32>, pub stopped: Option<&'static str> }

// Read a streamed command's pipes until it exits or must stop (see Helpers::stream). Each read
// delivers at most the bytes left in the output budget; an overflow stops the command. After the stop
// or exit, end its leftovers with `kill`, give the client two seconds to exit before killing its
// process group, then drain the pipes for up to five seconds.
fn stream_child(mut child: std::process::Child, stdout: std::process::ChildStdout, stderr: std::process::ChildStderr, timeout: Duration, limit: usize,
    sink: &mut dyn FnMut(bool, &[u8]), stop: &dyn Fn() -> Option<&'static str>, kill: &dyn Fn()) -> Result<Streamed> {
    let mut pipes: [Option<Box<dyn Read>>; 2] = [Some(Box::new(stdout)), Some(Box::new(stderr))];
    let mut total = 0usize;
    let mut stopped = None;
    // Read one bounded batch from each open pipe; report whether anything arrived.
    let mut pump = |pipes: &mut [Option<Box<dyn Read>>; 2], stopped: &mut Option<&'static str>| {
        let mut progress = false;
        for (index, slot) in pipes.iter_mut().enumerate() {
            let Some(pipe) = slot else { continue };
            let mut chunk = [0u8; 16384];
            match pipe.read(&mut chunk) {
                Ok(0) => *slot = None,
                Ok(n) => {
                    progress = true;
                    let keep = n.min(limit - total);
                    if keep > 0 { sink(index == 1, &chunk[..keep]); }
                    total += keep;
                    if n > keep { stopped.get_or_insert("exec_output_limit"); }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => *slot = None,
            }
        }
        progress
    };
    let start = Instant::now();
    let mut status = None;
    while stopped.is_none() && status.is_none() {
        let progress = pump(&mut pipes, &mut stopped);
        if stopped.is_none() { stopped = if start.elapsed() >= timeout { Some("exec_timeout") } else { stop() }; }
        status = child.try_wait().map_err(|_| "tool_wait_failed")?;
        if !progress && stopped.is_none() && status.is_none() { thread::sleep(Duration::from_millis(5)); }
    }
    kill();
    if status.is_none() {
        let waited = Instant::now();
        while status.is_none() && waited.elapsed() < Duration::from_secs(2) {
            thread::sleep(Duration::from_millis(5));
            status = child.try_wait().map_err(|_| "tool_wait_failed")?;
        }
        if status.is_none() {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL); }
            let _ = child.kill();
            status = Some(child.wait().map_err(|_| "tool_wait_failed")?);
        }
    }
    let drained = Instant::now();
    while pipes.iter().any(Option::is_some) {
        if drained.elapsed() >= Duration::from_secs(5) { return Err("exec_output_pipe_held"); }
        if !pump(&mut pipes, &mut stopped) { thread::sleep(Duration::from_millis(5)); }
    }
    let exit_code = if stopped.is_some() { None } else { status.and_then(|s| s.code()) };
    Ok(Streamed { exit_code, stopped })
}
struct HelperLeaf<'a>(PathBuf, &'a AtomicBool);
impl HelperLeaf<'_> {
    // Drain this command's helper group and remove it if it still exists.
    fn remove(&self) -> Result<()> {
        if !self.0.exists() { return Ok(()); }
        drain_helpers(&self.0)?;
        fs::remove_dir(&self.0).map_err(|_| "helper_cgroup_remove_failed")
    }
}
impl Drop for HelperLeaf<'_> {
    // On leaving the command's scope, retry cleanup and remember any failure so later work is blocked.
    fn drop(&mut self) { if self.remove().is_err() { self.1.store(true, Ordering::SeqCst); } }
}
// Kill all processes in the supplied helper group and wait up to five seconds for it to empty.
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

// Run a caller-selected read-only preflight query with short time and output bounds. Do not create
// helper groups here; parent-death signaling still applies.
pub fn inspect(program: &str, args: &[String], search_path: &str) -> Result<Output> {
    run_inner(program, args, Duration::from_secs(3), 65536, false, search_path, None)
}

// Query a trusted tool's version with short time and output bounds, without creating helper groups.
pub fn version(program: &str, search_path: &str) -> Result<Output> {
    run_inner(program, &["--version".into()], Duration::from_secs(3), 4096, false, search_path, None)
}

// Start a host command with a cleared environment, its own process group and parent-death protection,
// joining the helper group behind `helper_procs` (if any) before exec. Output goes to pipes unless
// `quiet`.
fn spawn(program: &str, args: &[String], quiet: bool, search_path: &str, helper_procs: Option<RawFd>) -> Result<std::process::Child> {
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
    command.spawn().map_err(|_| "tool_spawn_failed")
}

// Take a child's stdout and stderr pipes and make them nonblocking, so reads never wait for a
// descendant that still holds a pipe.
fn nonblocking_pipes(child: &mut std::process::Child) -> Result<(std::process::ChildStdout, std::process::ChildStderr)> {
    let stdout = child.stdout.take().ok_or("tool_pipe_failed")?;
    let stderr = child.stderr.take().ok_or("tool_pipe_failed")?;
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 { return Err("tool_pipe_failed"); }
    }
    Ok((stdout, stderr))
}

// Start a host command with a cleared environment, parent-death protection and output/time bounds.
// While monitoring, deadline, read or output failures trigger a command-group kill attempt. Final
// draining or size checks can also mark results interrupted without killing the group. Return exit
// status and output; Helpers::run separately cleans up tracked descendants.
fn run_inner(program: &str, args: &[String], timeout: Duration, limit: usize, quiet: bool, search_path: &str, helper_procs: Option<RawFd>) -> Result<Output> {
    let mut child = spawn(program, args, quiet, search_path, helper_procs)?;
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
    let (mut stdout, mut stderr) = match nonblocking_pipes(&mut child) {
        Ok(pipes) => pipes,
        Err(e) => { let _ = child.kill(); let _ = child.wait(); return Err(e); }
    };
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

// Run a tracked host command with standard output bounds and require an uninterrupted successful exit.
pub fn checked(program: &str, args: &[String], seconds: u64, search_path: &str, helpers: &Helpers) -> Result<()> {
    let output = helpers.run(program, args, Duration::from_secs(seconds), 65536, false, search_path)?;
    if output.interrupted { Err("tool_deadline_or_output_limit") }
    else if output.exit_code != Some(0) { Err("tool_failed") } else { Ok(()) }
}

// Write and sync private JSON to a pending file, rename it into place and sync the parent directory. A
// later sync error can occur after the new record has already replaced the old one.
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
