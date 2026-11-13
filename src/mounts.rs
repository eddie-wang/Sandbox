//! Mount inventory and bounded teardown, following Moby mountinfo and containerd mount.
use std::{ffi::{CString, OsString}, fs, os::unix::ffi::OsStringExt, path::{Path, PathBuf}, time::Duration};
use crate::process::Result;

pub struct Mount {
    pub point: PathBuf,
    pub source: PathBuf,
    pub device: String,
    pub filesystem: OsString,
    pub options: Vec<String>,
    pub optional: Vec<String>,
    pub super_options: Vec<String>,
}

// Decode the octal-escaped path fields emitted by Linux, including non-UTF-8 names.
// Behavioral port of moby/sys mountinfo v0.7.2 mountinfo_linux.go (Apache-2.0).
fn unescape(input: &[u8]) -> Result<PathBuf> {
    let mut bytes = Vec::new();
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\\' {
            let digits = input.get(i + 1..i + 4).ok_or("invalid_mountinfo_escape")?;
            if !digits.iter().all(|b| (b'0'..=b'7').contains(b)) { return Err("invalid_mountinfo_escape"); }
            let value = ((digits[0] - b'0') as u16) * 64 + ((digits[1] - b'0') as u16) * 8 + (digits[2] - b'0') as u16;
            if value == 0 || value > 255 { return Err("invalid_mountinfo_escape"); }
            bytes.push(value as u8);
            i += 4;
        } else { bytes.push(input[i]); i += 1; }
    }
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

// Read this thread's mount view, accepting optional propagation fields before the separator.
// Like Moby's parser, decode names only after splitting fields; malformed inventory fails closed.
pub fn inventory() -> Result<Vec<Mount>> {
    let text = fs::read("/proc/thread-self/mountinfo").map_err(|_| "mountinfo_unavailable")?;
    text.split(|b| *b == b'\n').filter(|line| !line.is_empty()).map(|line| {
        let fields: Vec<_> = line.split(|b| *b == b' ').collect();
        let separator = fields.iter().position(|f| *f == b"-").ok_or("invalid_mountinfo")?;
        if separator < 6 || fields.len() != separator + 4 { return Err("invalid_mountinfo"); }
        let ascii = |i: usize| std::str::from_utf8(fields[i]).map_err(|_| "invalid_mountinfo");
        if ascii(0)?.parse::<u64>().is_err() || ascii(1)?.parse::<u64>().is_err()
            || !ascii(2)?.split_once(':').is_some_and(|(a, b)| a.parse::<u32>().is_ok() && b.parse::<u32>().is_ok())
        { return Err("invalid_mountinfo"); }
        let _root = unescape(fields[3])?;
        let optional = (6..separator).map(|i| ascii(i).map(str::to_owned)).collect::<Result<Vec<_>>>()?;
        Ok(Mount { point: unescape(fields[4])?, source: unescape(fields[separator + 2])?, device: ascii(2)?.into(),
            filesystem: unescape(fields[separator + 1])?.into_os_string(), options: ascii(5)?.split(',').map(str::to_owned).collect(), optional,
            super_options: ascii(separator + 3)?.split(',').map(str::to_owned).collect() })
    }).collect()
}

// Decide whether a mount neither sends nor receives propagated mount events.
fn private(mount: &Mount) -> bool {
    !mount.optional.iter().any(|s| s.starts_with("shared:") || s.starts_with("master:") || s.starts_with("propagate_from:"))
}

// Require a private covering mount and private mounts beneath the path; do not alter ancestors.
pub fn private_tree(path: &Path) -> Result<()> {
    let mounts = inventory()?;
    let covering = mounts.iter().filter(|m| path.starts_with(&m.point)).max_by_key(|m| m.point.components().count()).ok_or("mount_boundary_missing")?;
    if !private(covering) || mounts.iter().any(|m| m.point.starts_with(path) && !private(m)) { return Err("mount_boundary_not_private"); }
    Ok(())
}

// Before worker threads start, verify the operator's pod-private boundary and detach netns-anchor
// propagation locally. runc v1.3.6 rootfsParentMountPrivate motivates this check; never privatize /.
// ip may subsequently share /run/netns locally, but its parent must remain private on every restart.
pub fn prepare_boundary(root: &Path) -> Result<()> {
    crate::storage::trusted_directory(root)?;
    private_tree(root)?;
    crate::storage::trusted_directory(Path::new("/run/netns"))?;
    let mounts = inventory()?;
    let parent = mounts.iter().filter(|m| Path::new("/run").starts_with(&m.point)).max_by_key(|m| m.point.components().count()).ok_or("mount_boundary_missing")?;
    if !private(parent) { return Err("netns_parent_not_private"); }
    if mounts.iter().any(|m| m.point == Path::new("/run/netns"))
        && unsafe { libc::mount(std::ptr::null(), c"/run/netns".as_ptr(), std::ptr::null(), libc::MS_PRIVATE | libc::MS_REC, std::ptr::null()) } != 0
    { return Err("netns_boundary_failed"); }
    private_tree(Path::new("/run/netns"))
}

// Retry only EBUSY, fifty attempts 50 ms apart, as containerd v2.2.0 core/mount/mount_unix.go
// unmount does (Apache-2.0). No lazy detach: even EINVAL/ENOENT needs proof no mount remains.
// Run this in a deadline-bound helper because a single kernel unmount can block on write-back.
pub fn unmount(path: &Path) -> Result<()> {
    let target = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| "invalid_mount_path")?;
    for attempt in 0..50 {
        if unsafe { libc::umount2(target.as_ptr(), 0) } == 0 { return Ok(()); }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EBUSY) if attempt < 49 => std::thread::sleep(Duration::from_millis(50)),
            Some(libc::EINVAL | libc::ENOENT) if !crate::storage::mounted(path)? => return Ok(()),
            Some(libc::EBUSY) => return Err("unmount_busy"),
            _ => return Err("unmount_failed"),
        }
    }
    Err("unmount_busy")
}
