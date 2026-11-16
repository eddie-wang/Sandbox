//! Active backing-directory checks, not kernel-version or filesystem-name guesses.
use std::{ffi::{CStr, CString}, fs, os::unix::fs::MetadataExt, path::Path};
use crate::process::Result;

// Build the explicit overlay options and enforce the kernel's single-page mount-data bound,
// as containerd's overlay mounts do. Never silently enable index, metacopy, redirects or xino.
pub fn options(lowers: &[String], upper: &Path, work: &Path, volatile: bool) -> Result<String> {
    if lowers.is_empty() || lowers.iter().any(|p| p.contains([',', ':', '\\', '\0']))
        || [upper, work].iter().any(|p| p.as_os_str().as_encoded_bytes().iter().any(|b| b",:\\\0".contains(b)))
    { return Err("invalid_overlay_path"); }
    let data = format!("lowerdir={},upperdir={},workdir={},index=off,metacopy=off,redirect_dir=off,xino=off{}",
        lowers.join(":"), upper.display(), work.display(), if volatile { ",volatile" } else { "" });
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 || data.len() >= page as usize { return Err("overlay_mount_data_too_long"); }
    Ok(data)
}

// Check actual directory-entry types, without falling back to stat (which would hide missing d_type).
// Follows containerd v2.2.0 NewSnapshotter's SupportsDType check (Apache-2.0).
fn directory_types(path: &Path) -> Result<()> {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| "invalid_overlay_path")?;
    let dir = unsafe { libc::opendir(path.as_ptr()) };
    if dir.is_null() { return Err("overlay_dtype_probe_failed"); }
    let result = (|| {
        let mut found = 0;
        loop {
            unsafe { *libc::__errno_location() = 0; }
            let entry = unsafe { libc::readdir(dir) };
            if entry.is_null() {
                if std::io::Error::last_os_error().raw_os_error() != Some(0) { return Err("overlay_dtype_probe_failed"); }
                break;
            }
            let entry = unsafe { &*entry };
            let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) }.to_bytes();
            let expected = match name { b"file" => libc::DT_REG, b"directory" => libc::DT_DIR, b"link" => libc::DT_LNK, _ => continue };
            if entry.d_type != expected { return Err("overlay_dtype_unsupported"); }
            found += 1;
        }
        if found != 3 { return Err("overlay_dtype_probe_failed"); }
        Ok(())
    })();
    unsafe { libc::closedir(dir); }
    result
}

// Round-trip the user and trusted attributes retained by copy-up and upper-image cloning.
fn attributes(path: &Path) -> Result<()> {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| "invalid_overlay_path")?;
    for name in [c"user.sandbox-probe", c"trusted.overlay.sandbox-probe"] {
        let mut value = [0u8; 1];
        if unsafe { libc::setxattr(path.as_ptr(), name.as_ptr(), c"y".as_ptr().cast(), 1, 0) } != 0
            || unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), value.as_mut_ptr().cast(), 1) } != 1
            || value != *b"y" || unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) } != 0
        { return Err("overlay_xattrs_unsupported"); }
    }
    Ok(())
}

// Mount one probe with the same options and security flags as a sandbox, reporting the real errno.
fn mount_probe(probe: &Path, volatile: bool) -> std::result::Result<(), i32> {
    let data = options(&[probe.join("lower").display().to_string()], &probe.join("upper"), &probe.join("work"), volatile).map_err(|_| libc::E2BIG)?;
    let data = CString::new(data).map_err(|_| libc::EINVAL)?;
    let target = CString::new(probe.join("mount").as_os_str().as_encoded_bytes()).map_err(|_| libc::EINVAL)?;
    if unsafe { libc::mount(c"overlay".as_ptr(), target.as_ptr(), c"overlay".as_ptr(), libc::MS_NODEV | libc::MS_NOSUID, data.as_ptr().cast()) } == 0 { Ok(()) }
    else { Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)) }
}

// Qualify the actual private ext4 backing directory and ordinary overlay in a tracked helper.
// Volatile mode is disabled: filesystem freezes must include all sandbox writes.
pub fn probe(probe: &Path) -> Result<bool> {
    for name in ["lower", "upper", "work", "mount", "directory"] { crate::storage::private_dir(&probe.join(name))?; }
    fs::write(probe.join("file"), b"probe").map_err(|_| "overlay_probe_write_failed")?;
    std::os::unix::fs::symlink("file", probe.join("link")).map_err(|_| "overlay_probe_write_failed")?;
    directory_types(probe)?;
    attributes(&probe.join("file"))?;
    fs::write(probe.join("lower/file"), b"lower").map_err(|_| "overlay_probe_write_failed")?;
    mount_probe(probe, false).map_err(|_| "overlay_mount_unsupported")?;
    let merged = probe.join("mount/file");
    if fs::read(&merged).map_err(|_| "overlay_probe_read_failed")? != b"lower" { return Err("overlay_probe_content_mismatch"); }
    fs::write(&merged, b"copied").map_err(|_| "overlay_copy_up_failed")?;
    fs::hard_link(&merged, probe.join("mount/alias")).map_err(|_| "overlay_hardlink_failed")?;
    if fs::metadata(&merged).map_err(|_| "overlay_probe_read_failed")?.ino()
        != fs::metadata(probe.join("mount/alias")).map_err(|_| "overlay_probe_read_failed")?.ino()
        || fs::read(probe.join("lower/file")).map_err(|_| "overlay_probe_read_failed")? != b"lower"
    { return Err("overlay_probe_content_mismatch"); }
    crate::mounts::unmount(&probe.join("mount"))?;
    Ok(false)
}
