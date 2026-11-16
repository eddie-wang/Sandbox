//! Private ext4 block images preserve upper-file inodes across captures. Fresh integration of
//! containerd v2.0.0 blockfile/losetup and Apptainer v1.4.2 loop-node patterns; see docs/contracts.md.
use std::{ffi::CString, fs::{self, File, OpenOptions}, os::{fd::AsRawFd, unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt}}, path::Path, time::{Duration, Instant}};
use crate::{native::Native, phases::Phases, process::Result, storage::{self, Manifest}};
use std::{collections::{BTreeMap, BTreeSet}, sync::{Arc, Condvar, Mutex}, thread::JoinHandle};

// One bounded, hot-template copy pool. Busy entries are never offered or reused until handoff finishes.
#[derive(Default)]
pub(crate) struct UpperPool { state: Mutex<PoolState>, changed: Condvar, thread: Mutex<Option<JoinHandle<()>>> }
#[derive(Default)]
struct PoolState { target: Option<(Manifest, String)>, ready: BTreeMap<usize, String>, busy: BTreeSet<usize>, stopped: bool, failed: bool }

// Linux UAPI linux/loop.h: kept here because libc does not expose these structures.
#[repr(C)]
struct LoopInfo { device: u64, inode: u64, rdevice: u64, offset: u64, size_limit: u64, number: u32, encrypt_type: u32, encrypt_key_size: u32, flags: u32, file_name: [u8; 64], crypt_name: [u8; 64], encrypt_key: [u8; 32], init: [u64; 2] }
#[repr(C)]
struct LoopConfig { fd: u32, block_size: u32, info: LoopInfo, reserved: [u64; 8] }
const GET_FREE: libc::c_ulong = 0x4c82;
const CONFIGURE: libc::c_ulong = 0x4c0a;
const GET_STATUS: libc::c_ulong = 0x4c05;
const CLEAR: libc::c_ulong = 0x4c01;
const FLAGS: u32 = 4 | 16; // AUTOCLEAR | DIRECT_IO

// Return the ordinary default quota: 1 GiB includes ext4 metadata and fits a 450 MiB upper.
pub fn default_mib() -> u64 { 1024 }

// Open loop-control without allocating anything, for the read-only preflight report.
pub fn available() -> bool { OpenOptions::new().read(true).write(true).open("/dev/loop-control").is_ok() }

// Convert an owned path to the byte string accepted by Linux, rejecting embedded zero bytes.
fn path_string(path: &Path) -> Result<CString> { CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| "invalid_upper_path") }

// Read a loop association; an unassociated device is harmless, every other error fails closed.
fn status(device: &File) -> Result<Option<LoopInfo>> {
    let mut info: LoopInfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(device.as_raw_fd(), GET_STATUS, &mut info) } == 0 { return Ok(Some(info)); }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENXIO) { Ok(None) } else { Err("loop_status_failed") }
}

// Open only the worker's administrator-owned private loop node, never a symlink or arbitrary device.
fn open_node(private: &Path) -> Result<Option<File>> {
    let node = private.join("loop");
    let meta = match fs::symlink_metadata(&node) { Ok(m) => m, Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None), Err(_) => return Err("loop_node_unavailable") };
    if !meta.file_type().is_block_device() || meta.uid() != 0 || meta.mode() & 0o077 != 0 || libc::major(meta.rdev()) != 7 { return Err("untrusted_loop_node"); }
    OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW).open(node).map(Some).map_err(|_| "loop_open_failed")
}

// Check the mount and loop's exact backing-file identity before operating on a sandbox filesystem.
pub fn verify(private: &Path) -> Result<()> {
    let image = storage::artifact_identity(&private.join("writable.ext4"), 65536 << 20)?;
    let device = open_node(private)?.ok_or("loop_node_missing")?;
    let info = status(&device)?.ok_or("loop_not_attached")?;
    if info.device != image.dev || info.inode != image.ino || info.offset != 0 || info.size_limit != 0 || info.flags != FLAGS { return Err("unexpected_upper_loop"); }
    let mounts = crate::mounts::inventory()?;
    let mut matching = mounts.iter().filter(|m| m.point == private.join("upperfs"));
    let mount = matching.next().ok_or("upper_not_mounted")?;
    if matching.next().is_some() || mount.filesystem != "ext4" || mount.device != format!("7:{}", info.number)
        || !["rw", "nodev", "nosuid"].iter().all(|o| mount.options.iter().any(|v| v == o)) { return Err("unexpected_upper_mount"); }
    Ok(())
}

// Allocate with loop-control, creating a private block node even when the pod has a static /dev.
// Configure autoclear and direct I/O atomically, verify both, and hold the descriptor through mount.
// A failed or killed helper automatically releases an attachment that was not mounted.
pub fn mount(private: &Path) -> Result<()> {
    storage::trusted_directory(private)?;
    let image = OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW).open(private.join("writable.ext4")).map_err(|_| "upper_image_unavailable")?;
    let control = OpenOptions::new().read(true).write(true).open("/dev/loop-control").map_err(|_| "loop_control_unavailable")?;
    let node = private.join("loop");
    for attempt in 0..100 {
        let number = unsafe { libc::ioctl(control.as_raw_fd(), GET_FREE) };
        if number < 0 { return Err("loop_devices_unavailable"); }
        if unsafe { libc::mknod(path_string(&node)?.as_ptr(), libc::S_IFBLK | 0o600, libc::makedev(7, number as u32)) } != 0 { return Err("loop_node_create_failed"); }
        let device = open_node(private)?.ok_or("loop_node_missing")?;
        let mut config = LoopConfig { fd: image.as_raw_fd() as u32, block_size: 4096, info: unsafe { std::mem::zeroed() }, reserved: [0; 8] };
        config.info.flags = FLAGS;
        if unsafe { libc::ioctl(device.as_raw_fd(), CONFIGURE, &config) } != 0 {
            let busy = std::io::Error::last_os_error().raw_os_error() == Some(libc::EBUSY);
            drop(device);
            fs::remove_file(&node).map_err(|_| "loop_node_remove_failed")?;
            if busy { std::thread::sleep(Duration::from_millis(1 + attempt)); continue; }
            return Err("loop_configure_direct_io_failed");
        }
        if status(&device)?.is_none_or(|i| i.flags != FLAGS) { return Err("loop_direct_io_unavailable"); }
        if unsafe { libc::mount(path_string(&node)?.as_ptr(), path_string(&private.join("upperfs"))?.as_ptr(), c"ext4".as_ptr(), libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOATIME, c"errors=remount-ro".as_ptr().cast()) } != 0 { return Err("ext4_mount_failed"); }
        return verify(private);
    }
    Err("loop_allocation_busy")
}

// Freeze or thaw only a verified private ext4 filesystem. Thawing an already thawed filesystem is OK.
pub fn freeze(private: &Path, frozen: bool) -> Result<()> {
    verify(private)?;
    let file = File::open(private.join("upperfs")).map_err(|_| "upper_unavailable")?;
    if unsafe { libc::ioctl(file.as_raw_fd(), if frozen { 0xc0045877 as libc::c_ulong } else { 0xc0045878 as libc::c_ulong }, 0) } == 0 { return Ok(()); }
    if !frozen && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) { Ok(()) } else { Err("upper_freeze_or_thaw_failed") }
}

// Discard a disposable copy only after its workload has drained, before either mount is removed.
// Linux ext4's NOLOGFLUSH shutdown drops dirty data and journal work; never use this during capture.
pub fn discard(private: &Path) -> Result<()> {
    verify(private)?;
    let file = File::open(private.join("upperfs")).map_err(|_| "upper_unavailable")?;
    let flags: u32 = 2; // EXT4_GOING_FLAGS_NOLOGFLUSH, Linux fs/ext4/ioctl.c
    if unsafe { libc::ioctl(file.as_raw_fd(), 0x8004587d as libc::c_ulong, &flags) } == 0 { Ok(()) } else { Err("upper_shutdown_failed") }
}

// After normal unmount, detach only a loop still associated with this exact image and wait for release.
// A reused loop belongs to someone else: remove only our private node, never detach their device.
pub fn detach(private: &Path) -> Result<()> {
    if storage::mounted(&private.join("upperfs"))? { return Err("upper_mount_still_live"); }
    let Some(device) = open_node(private)? else { return Ok(()); };
    let image = storage::artifact_identity(&private.join("writable.ext4"), 65536 << 20)?;
    if status(&device)?.is_none_or(|i| i.device != image.dev || i.inode != image.ino) { return Ok(()); }
    if unsafe { libc::ioctl(device.as_raw_fd(), CLEAR, 0) } != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENXIO) { return Err("loop_detach_failed"); }
    // Drop our descriptor so autoclear can finish; a later cleanup retry can verify release.
    drop(device);
    let started = Instant::now();
    while let Some(probe) = open_node(private)? {
        if status(&probe)?.is_none_or(|i| i.device != image.dev || i.inode != image.ino) { return Ok(()); }
        if started.elapsed() > Duration::from_secs(5) { return Err("loop_still_attached"); }
        drop(probe);
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

// Sync a private block image and discard its host file cache before loop direct I/O uses it.
// The mounted ext4 page cache is the sole cache for subsequent sandbox reads and writes.
pub fn sync_image(image: &Path) -> Result<()> {
    let file = File::open(image).map_err(|_| "upper_image_unavailable")?;
    file.sync_all().map_err(|_| "upper_image_sync_failed")?;
    if unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) } != 0 { return Err("upper_image_cache_drop_failed"); }
    Ok(())
}

impl Native {
    // Store idle copies beneath private so existing disk accounting includes the entire ready pool.
    fn pool_path(&self, index: usize) -> std::path::PathBuf { self.root().join("private/upper-pool").join(index.to_string()) }

    // Remove only recognized owned pool entries, including interrupted builds, before admitting work.
    // Mounted copies are disposable; failed release keeps their paths for the next cleanup attempt.
    pub(crate) fn clear_upper_pool(&self) -> Result<()> {
        let root = self.root().join("private/upper-pool");
        if !root.exists() { return Ok(()); }
        storage::trusted_directory(&root)?;
        for entry in fs::read_dir(&root).map_err(|_| "upper_pool_scan_failed")? {
            let entry = entry.map_err(|_| "upper_pool_scan_failed")?;
            if !entry.file_name().to_str().is_some_and(|n| n.parse::<usize>().is_ok_and(|i| i < 32 && n == i.to_string())) { return Err("unknown_upper_pool_state"); }
            self.remove_idle_upper(&entry.path())?;
        }
        storage::remove_private(&root)
    }

    // Shut down and normally unmount an unused copy, detach its loop, then remove its private files.
    fn remove_idle_upper(&self, private: &Path) -> Result<()> {
        self.helpers.ensure_healthy()?;
        if storage::mounted(&private.join("upperfs"))? {
            self.upper_helper("discard", private)?;
            self.unmount(&private.join("upperfs"))?;
        }
        if private.exists() { self.upper_helper("detach", private)?; }
        storage::remove_private(private)
    }

    // Start one bounded background refiller; no lock is held while copying, mounting or cleaning up.
    pub(crate) fn start_upper_pool(self: &Arc<Self>) -> Result<()> {
        if self.config.upper_pool_size == 0 { return Ok(()); }
        storage::private_dir(&self.root().join("private/upper-pool"))?;
        let native = self.clone();
        let thread = std::thread::Builder::new().name("sandbox-upper-pool".into()).spawn(move || native.refill_uppers()).map_err(|_| "upper_pool_thread_failed")?;
        *self.upper_pool.thread.lock().unwrap() = Some(thread);
        Ok(())
    }

    // Stop refilling and join its bounded helper work before removing idle copies or shared resources.
    pub(crate) fn stop_upper_pool(&self) -> Result<()> {
        self.upper_pool.state.lock().unwrap().stopped = true;
        self.upper_pool.changed.notify_all();
        let thread = self.upper_pool.thread.lock().unwrap().take();
        if thread.is_some_and(|t| t.join().is_err()) { return Err("upper_pool_thread_failed"); }
        self.clear_upper_pool()
    }

    // Select the latest warm template for background prewarming. An empty pool always falls back to
    // normal synchronous copying; prewarming neither delays a capture reply nor reserves a sandbox.
    pub(crate) fn request_uppers(&self, manifest: &Manifest, key: &str) {
        if self.config.upper_pool_size == 0 { return; }
        self.upper_pool.state.lock().unwrap().target = Some((manifest.clone(), key.into()));
        self.upper_pool.changed.notify_all();
    }

    // Claim only a ready copy for this exact cache key. Rename its whole directory under the sandbox's
    // already-durable record and sync both parents; keep the slot unavailable throughout the handoff.
    pub(crate) fn take_upper(&self, private: &Path, images: &Path) -> Result<bool> {
        let key = images.file_name().and_then(|n| n.to_str()).ok_or("invalid_checkpoint_cache_key")?;
        let index = {
            let mut pool = self.upper_pool.state.lock().unwrap();
            if pool.failed { return Err("upper_pool_cleanup_failed"); }
            let Some(index) = pool.ready.iter().find(|(_, k)| k.as_str() == key).map(|(i, _)| *i) else { return Ok(false); };
            pool.ready.remove(&index); pool.busy.insert(index); index
        };
        let from = self.pool_path(index);
        let moved = fs::rename(&from, private).map_err(|_| "upper_pool_handoff_failed").and_then(|_| {
            for parent in [from.parent().unwrap(), private.parent().unwrap()] {
                File::open(parent).and_then(|f| f.sync_all()).map_err(|_| "upper_pool_handoff_sync_failed")?;
            }
            Ok(())
        });
        let mut pool = self.upper_pool.state.lock().unwrap();
        if moved.is_ok() { pool.busy.remove(&index); } else { pool.failed = true; }
        self.upper_pool.changed.notify_all();
        moved.map(|_| true)
    }

    // Refill the bounded hot-template pool, replacing idle copies of older templates. A failed build
    // is cleaned up and disables prewarming until another request; failed cleanup blocks pool use.
    fn refill_uppers(&self) {
        loop {
            let (index, manifest, key) = {
                let mut pool = self.upper_pool.state.lock().unwrap();
                loop {
                    if pool.stopped || pool.failed { return; }
                    if let Some((manifest, key)) = pool.target.clone() {
                        if let Some(index) = (0..self.config.upper_pool_size).find(|i| !pool.busy.contains(i) && pool.ready.get(i) != Some(&key)) {
                            pool.ready.remove(&index); pool.busy.insert(index);
                            break (index, manifest, key);
                        }
                    }
                    pool = self.upper_pool.changed.wait(pool).unwrap();
                }
            };
            let private = self.pool_path(index);
            let result = self.remove_idle_upper(&private).and_then(|_| {
                let images = self.checkpoint_images(&manifest, &key)?;
                storage::exclusive_private_dir(&private)?;
                File::open(private.parent().unwrap()).and_then(|f| f.sync_all()).map_err(|_| "upper_pool_ownership_failed")?;
                self.prepare_upper(&private, manifest.writable_mib, Some(&images))
            });
            let cleanup = if result.is_err() { self.remove_idle_upper(&private) } else { Ok(()) };
            let mut pool = self.upper_pool.state.lock().unwrap();
            pool.busy.remove(&index);
            if cleanup.is_err() { pool.failed = true; }
            if result.is_ok() { pool.ready.insert(index, key); }
            else if pool.target.as_ref().is_some_and(|(_, target)| target == &key) { pool.target = None; }
        }
    }

    // Copy whole filesystem blocks into a new image, preferring reflinks and preserving holes otherwise.
    pub(crate) fn copy_upper(&self, source: &Path, target: &Path) -> Result<()> {
        if target.try_exists().map_err(|_| "upper_image_unavailable")? { return Err("upper_image_already_exists"); }
        self.command("cp", vec!["--reflink=auto".into(), "--sparse=always".into(), "--no-clobber".into(), source.display().to_string(), target.display().to_string()])?;
        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).map_err(|_| "upper_image_permissions_failed")?;
        sync_image(target)?;
        sync_image(source)
    }
    // Format a sparse ext4 image with eager inode/journal initialization and no root-reserved blocks.
    pub(crate) fn format_upper(&self, image: &Path, mib: u64) -> Result<()> {
        let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(image).map_err(|_| "upper_image_create_failed")?;
        file.set_len(mib << 20).map_err(|_| "upper_image_resize_failed")?;
        self.command("mkfs.ext4", vec!["-q".into(), "-F".into(), "-b".into(), "4096".into(), "-m".into(), "0".into(), "-E".into(), "lazy_itable_init=0,lazy_journal_init=0".into(), image.display().to_string()])?;
        sync_image(image)
    }
    // Clone a quota-sized scratch or captured image, mount it through an owned loop and use the same upper/work
    // locations for cold and restored sandboxes. Partial state belongs to a durable record or pool directory.
    pub(crate) fn prepare_upper(&self, private: &Path, writable_mib: u64, images: Option<&Path>) -> Result<()> {
        storage::private_dir(&private.join("upperfs"))?;
        let image = private.join("writable.ext4");
        if let Some(images) = images {
            self.copy_upper(&images.join("writable.ext4"), &image)?;
        } else {
            let scratch = self.scratch_image(writable_mib)?;
            self.copy_upper(&scratch, &image)?;
        }
        self.upper_helper("mount", private)?;
        for name in ["upper", "work"] { storage::private_dir(&private.join("upperfs").join(name))?; }
        fs::set_permissions(private.join("upperfs/upper"), fs::Permissions::from_mode(0o755)).map_err(|_| "upper_permissions_failed")
    }
    // Run potentially blocking loop/mount/freeze operations in the existing tracked, bounded helpers.
    pub(crate) fn upper_helper(&self, operation: &str, private: &Path) -> Result<()> {
        crate::process::checked(&format!("/proc/{}/exe", std::process::id()),
            &["internal-upper".into(), operation.into(), private.display().to_string()], self.config.command_timeout_seconds, &self.search_path, &self.helpers, None)
    }
    // Freeze the source filesystem while copying its blocks, then attempt thaw before checkpoint/resume.
    // Recovery retries thaw after a failed or killed helper; if thaw or cleanup still fails,
    // retain cleanup ownership rather than claiming the filesystem is thawed.
    pub fn capture_upper(&self, id: &str, image: &Path, phases: &mut Phases) -> Result<()> {
        let private = self.private(id);
        let result = self.upper_helper("freeze", &private).and_then(|_| {
            phases.mark("upper_freeze");
            self.copy_upper(&private.join("writable.ext4"), image)
        });
        let thaw = self.upper_helper("thaw", &private);
        phases.mark("upper_copy");
        result.and(thaw)
    }
}
