//! Blocking, bounded host commands. Called only by dedicated lifecycle and exec
//! threads or spawn_blocking preflight. Never inherit management credentials into tools.
use std::{fs::{self, OpenOptions}, io::{Read, Write}, os::{fd::{AsRawFd, FromRawFd, OwnedFd, RawFd}, unix::process::CommandExt}, path::{Path, PathBuf}, process::{Command, Stdio}, sync::atomic::{AtomicBool, AtomicU64, Ordering}, thread, time::{Duration, Instant}};
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
    // Run a host command inside a new tracked helper group with bounded time and output, in the network
    // namespace pinned at `netns` if given. Drain all remaining helpers before returning; a cleanup
    // failure blocks later work.
    pub fn run(&self, program: &str, args: &[String], timeout: Duration, limit: usize, quiet: bool, search_path: &str, netns: Option<&Path>) -> Result<Output> {
        self.ensure_healthy()?;
        let path = self.path.join(format!("command-{}", self.sequence.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).map_err(|_| "helper_cgroup_create_failed")?;
        let leaf = HelperLeaf(path, &self.failed);
        let result = run_inner(program, args, timeout, limit, quiet, search_path, Some(&leaf.0.join("cgroup.procs")), netns);
        // Never reconcile files/mounts after a command until all its helpers drain.
        if let Err(e) = leaf.remove() { self.failed.store(true, Ordering::SeqCst); return Err(e); }
        result
    }
    // Track a runc exec client and stream its bounded output (true marks stderr). Deadline, output
    // overflow or stop kills its group; every end also kills its leftovers and drains bounded output.
    // Drain helpers before returning; failed cleanup blocks later work.
    pub fn stream(&self, program: &str, args: &[String], timeout: Duration, limit: usize, search_path: &str,
        sink: &mut dyn FnMut(bool, &[u8]), stop: &dyn Fn() -> Option<&'static str>, kill: &dyn Fn()) -> Result<Streamed> {
        self.ensure_healthy()?;
        let path = self.path.join(format!("command-{}", self.sequence.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).map_err(|_| "helper_cgroup_create_failed")?;
        let leaf = HelperLeaf(path, &self.failed);
        let result = (|| {
            let mut child = spawn(program, args, false, search_path, Some(&leaf.0.join("cgroup.procs")), None)?;
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

// Read a streamed command's pipes until it exits or must stop (see Helpers::stream), waking as soon as
// output arrives or it exits. Each read delivers at most the bytes left in the output budget; an
// overflow stops the command. After the stop or exit, end its leftovers with `kill`, give the client
// two seconds to exit before killing its process group, then drain the pipes for up to five seconds.
fn stream_child(mut child: std::process::Child, stdout: std::process::ChildStdout, stderr: std::process::ChildStderr, timeout: Duration, limit: usize,
    sink: &mut dyn FnMut(bool, &[u8]), stop: &dyn Fn() -> Option<&'static str>, kill: &dyn Fn()) -> Result<Streamed> {
    let exited = exit_fd(&child);
    let fds = [stdout.as_raw_fd(), stderr.as_raw_fd()];
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
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => {}
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
        // Stop requests are checked at least every five milliseconds; output and exit wake it at once.
        if !progress && stopped.is_none() && status.is_none() {
            let open: Vec<RawFd> = fds.iter().zip(&pipes).filter(|(_, p)| p.is_some()).map(|(fd, _)| *fd).collect();
            wait_for(&open, exited.as_ref(), Duration::from_millis(5));
        }
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
    run_inner(program, args, Duration::from_secs(3), 65536, false, search_path, None, None)
}

// Query a trusted tool's version with short time and output bounds, without creating helper groups.
pub fn version(program: &str, search_path: &str) -> Result<Output> {
    run_inner(program, &["--version".into()], Duration::from_secs(3), 4096, false, search_path, None, None)
}

// Start a command through internal-exec with a cleared environment, private process group and pipes
// (or /dev/null if quiet). Without code between fork and exec, the standard library avoids copying
// the worker's growing memory map. The fresh helper joins its group/namespace before running tools.
fn spawn(program: &str, args: &[String], quiet: bool, search_path: &str, helper_procs: Option<&Path>, netns: Option<&Path>) -> Result<std::process::Child> {
    let parent = std::process::id().to_string();
    let path_or_dash = |p: Option<&Path>| p.map_or_else(|| "-".into(), |p| p.as_os_str().to_owned());
    let mut command = Command::new("/proc/self/exe");
    command.arg("internal-exec").arg(parent).arg(path_or_dash(helper_procs)).arg(path_or_dash(netns)).arg(program).args(args)
        .env_clear().env("PATH", search_path).env("LANG", "C")
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    if quiet { command.stdout(Stdio::null()).stderr(Stdio::null()); }
    command.spawn().map_err(|_| "tool_spawn_failed")
}

// In a fresh helper, set parent-death protection and verify the starting worker is still its parent,
// then join the helper group and optional network namespace before replacing itself with the tool.
// Arguments are worker PID, cgroup.procs or '-', namespace pin or '-', program and its arguments.
// Unlike ip netns exec, this does not copy the mount table. Returns only on failure.
pub fn exec_helper(args: &[std::ffi::OsString]) -> Result<()> {
    let [parent, group, netns, program, rest @ ..] = args else { return Err("helper_exec_usage") };
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 { return Err("helper_parent_signal_failed"); }
    if parent.to_str().and_then(|p| p.parse::<libc::pid_t>().ok()) != Some(unsafe { libc::getppid() }) { return Err("helper_parent_gone"); }
    if group != "-" {
        OpenOptions::new().write(true).open(group).and_then(|mut f| f.write_all(b"0")).map_err(|_| "helper_cgroup_join_failed")?;
    }
    if netns != "-" {
        let namespace = fs::File::open(netns).map_err(|_| "helper_netns_unavailable")?;
        if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 { return Err("helper_netns_join_failed"); }
    }
    let _ = Command::new(program).args(rest).exec();
    Err("helper_exec_failed")
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

// Read what is already in one pipe of an exited command into `buffer`, keeping at most `limit` bytes
// there. Stop at end of file or as soon as the pipe is empty: everything the command itself wrote is
// already in the pipe when it exits, and a pipe that is empty but still open is held by a descendant
// or by another command being started at that moment, which is not a failure and is never waited
// for. A descendant that keeps writing is cut at the limit, so this always ends quickly. Return
// whether the output was cut at the limit or failed to read.
fn drain_exited(pipe: &mut dyn Read, buffer: &mut Vec<u8>, limit: usize) -> bool {
    let mut chunk = [0u8; 4096];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => return false,
            Ok(n) => {
                let remaining = limit.saturating_sub(buffer.len());
                buffer.extend_from_slice(&chunk[..n.min(remaining)]);
                if n > remaining { return true; }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return false,
            Err(_) => return true,
        }
    }
}

// Open a descriptor that becomes readable once the child has exited (a pidfd), so waits can sleep
// until then instead of polling. None on kernels without pidfd_open.
fn exit_fd(child: &std::process::Child) -> Option<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) };
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

// Sleep until one of `pipes` has data or is closed, the child behind `exited` has exited, or `limit`
// passes. Without an exit descriptor, sleep at most five milliseconds, so exits are still noticed.
fn wait_for(pipes: &[RawFd], exited: Option<&OwnedFd>, limit: Duration) {
    let mut fds: Vec<libc::pollfd> = pipes.iter().chain(exited.map(AsRawFd::as_raw_fd).as_ref())
        .map(|fd| libc::pollfd { fd: *fd, events: libc::POLLIN, revents: 0 }).collect();
    let limit = if exited.is_some() { limit } else { limit.min(Duration::from_millis(5)) };
    // Round up, so a wait shorter than a millisecond does not spin.
    let ms = limit.as_micros().div_ceil(1000).min(i32::MAX as u128) as i32;
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms); }
}

// Run a bounded host command. Deadline/read/output failures kill its process group; after exit,
// drain only available output without waiting for descendants. Return its status and bounded output;
// Helpers::run separately drains tracked descendants before allowing cleanup.
fn run_inner(program: &str, args: &[String], timeout: Duration, limit: usize, quiet: bool, search_path: &str, helper_procs: Option<&Path>, netns: Option<&Path>) -> Result<Output> {
    let mut child = spawn(program, args, quiet, search_path, helper_procs, netns)?;
    let exited = exit_fd(&child);
    let start = Instant::now();
    if quiet {
        loop {
            if let Some(status) = child.try_wait().map_err(|_| "tool_wait_failed")? {
                return Ok(Output { exit_code: status.code(), stdout: String::new(), stderr: String::new(), interrupted: false });
            }
            if start.elapsed() >= timeout {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL); }
                let _ = child.kill(); let _ = child.wait();
                return Ok(Output { exit_code: None, stdout: String::new(), stderr: String::new(), interrupted: true });
            }
            wait_for(&[], exited.as_ref(), timeout.saturating_sub(start.elapsed()));
        }
    }
    let (mut stdout, mut stderr) = match nonblocking_pipes(&mut child) {
        Ok(pipes) => pipes,
        Err(e) => { let _ = child.kill(); let _ = child.wait(); return Err(e); }
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut interrupted = false;
    // Pipes not yet at end of file; only these are waited on.
    let mut open = [true, true];
    let fds = [stdout.as_raw_fd(), stderr.as_raw_fd()];
    let status = loop {
        let mut made_progress = false;
        for (index, (pipe, buffer)) in [(&mut stdout as &mut dyn Read, &mut out), (&mut stderr as &mut dyn Read, &mut err)].into_iter().enumerate() {
            let mut chunk = [0u8; 4096];
            // One bounded batch per iteration, including when output is continuous.
            match pipe.read(&mut chunk) {
                Ok(n) => {
                    made_progress |= n != 0;
                    if n == 0 { open[index] = false; }
                    let remaining = limit.saturating_sub(buffer.len());
                    buffer.extend_from_slice(&chunk[..n.min(remaining)]);
                    if n > remaining { interrupted = true; }
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => {},
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
            // An empty pipe that is still held open ends the read; it is not an interruption.
            for (pipe, buffer) in [(&mut stdout as &mut dyn Read, &mut out), (&mut stderr as &mut dyn Read, &mut err)] {
                interrupted |= drain_exited(pipe, buffer, limit);
            }
            break status;
        }
        // Check deadline/size after every bounded batch, but do not throttle available pipe data;
        // otherwise sleep until output, the exit or the deadline.
        if !made_progress {
            let waiting: Vec<RawFd> = fds.iter().zip(open).filter(|(_, o)| *o).map(|(fd, _)| *fd).collect();
            wait_for(&waiting, exited.as_ref(), timeout.saturating_sub(start.elapsed()));
        }
    };
    // Use a single combined output budget, even though each pipe is drained separately.
    if out.len() + err.len() > limit { interrupted = true; err.truncate(limit.saturating_sub(out.len())); }
    Ok(Output { exit_code: status.code(), stdout: String::from_utf8_lossy(&out).into_owned(), stderr: String::from_utf8_lossy(&err).into_owned(), interrupted })
}

// Run a tracked host command with standard output bounds, in the network namespace pinned at `netns`
// if given, and require an uninterrupted successful exit. A failure is written to the worker log with
// the tool's name, exit code and bounded error output (see log_failure).
pub fn checked(program: &str, args: &[String], seconds: u64, search_path: &str, helpers: &Helpers, netns: Option<&Path>) -> Result<()> {
    // This worker's own helpers (/proc/<pid>/exe) are named by their subcommand.
    let tool = match Path::new(program).file_name().and_then(|n| n.to_str()) {
        Some("exe") => args.first().map_or("sandboxd", String::as_str),
        name => name.unwrap_or("unknown"),
    };
    let output = helpers.run(program, args, Duration::from_secs(seconds), 65536, false, search_path, netns)
        .inspect_err(|code| log_failure(tool, code, None, ""))?;
    let result = if output.interrupted { Err("tool_deadline_or_output_limit") }
        else if output.exit_code != Some(0) { Err("tool_failed") } else { Ok(()) };
    if let Err(code) = result { log_failure(tool, code, output.exit_code, &output.stderr); }
    result
}

// Most bytes of a failed tool's error output that go into the worker log.
const LOGGED_STDERR_BYTES: usize = 512;

// Write one worker log line about a failed host tool: its name (never its arguments), the error code,
// its exit code if it exited, and the last LOGGED_STDERR_BYTES of its error output on one line with
// control characters escaped. Tools run with a cleared environment, so their output holds no
// management credentials.
pub fn log_failure(tool: &str, code: &str, exit: Option<i32>, stderr: &str) {
    let trimmed = stderr.trim_end();
    let mut start = trimmed.len().saturating_sub(LOGGED_STDERR_BYTES);
    while !trimmed.is_char_boundary(start) { start += 1; }
    let tail: String = trimmed[start..].chars().flat_map(char::escape_default).collect();
    let exit = exit.map_or_else(|| "none".to_owned(), |c| c.to_string());
    eprintln!("sandboxd: host tool {tool} failed: {code} exit={exit} stderr=\"{tail}\"");
}

// Create a new private (0600) JSON file without following a symlink, failing if it exists. Not synced:
// for per-sandbox files (execution and command specifications) that crash recovery deletes anyway.
pub fn new_private_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let bytes = serde_json::to_vec(value).map_err(|_| "record_encode_failed")?;
    OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path)
        .and_then(|mut file| file.write_all(&bytes)).map_err(|_| "record_write_failed")
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
