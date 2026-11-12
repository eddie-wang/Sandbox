//! Serialized durable admission/state transitions, bounded parallel runtime I/O.
//! Each sandbox has at most one in-flight job. HTTP cancellation never owns jobs.
use std::{collections::{BTreeMap, BTreeSet}, fs, path::Path, sync::{Arc, RwLock, mpsc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use serde::{Deserialize, Serialize};
use crate::{config::WorkerConfig, model::{CaptureRequest, CreateRequest, ExecRequest, Runtime, RuntimeCapability, Usage, WorkerStatus}, native::{Native, Preflight}, process::{self, Result}, storage};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub fingerprint: String,
    pub kind: String,
    pub state: String,
    pub error: Option<String>,
    pub output: Option<process::Output>,
    pub template_id: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema_version: u32,
    pub request: CreateRequest,
    pub state: String,
    pub error: Option<String>,
    pub expires_at: u64,
    #[serde(default)]
    pub delete_requested: bool,
    pub operations: BTreeMap<String, Operation>,
}
impl Record {
    pub fn reserved(&self) -> bool { !matches!(self.state.as_str(), "deleted" | "failed") }
    fn exec_operations(&self) -> Vec<String> { self.operations.iter().filter(|(_, op)| op.kind == "exec").map(|(id, _)| id.clone()).collect() }
}
pub struct Snapshot {
    pub status: WorkerStatus,
    pub records: BTreeMap<String, Arc<Record>>,
    cancels: BTreeMap<String, Arc<AtomicBool>>,
}
#[derive(Clone)]
pub struct Handle { pub snapshot: Arc<RwLock<Snapshot>>, pub preflight: Preflight, pub sender: Option<mpsc::SyncSender<Work>> }
pub type Ack = tokio::sync::oneshot::Sender<Result<()>>;
pub enum Work {
    Create(CreateRequest, Ack), Exec(String, ExecRequest, Ack), Capture(String, CaptureRequest, Ack), Delete(String, Ack),
    Complete(usize, Box<Record>), Exited(String), Stop(mpsc::Sender<Result<()>>),
}
enum Action { Create, Exec(ExecRequest), Capture(CaptureRequest), Delete }
struct Job { record: Record, action: Action, cancelled: Arc<AtomicBool> }
struct Flight { slot: usize, restore: bool, output_bytes: usize, template: Option<String>, cancelled: Arc<AtomicBool> }
struct Lower { manifest: storage::Manifest, done: mpsc::Sender<Result<()>> }
pub fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }
pub fn fingerprint<T: Serialize>(input: &T) -> String { storage::digest(&serde_json::to_vec(input).expect("serialize validated input")) }
fn output_bytes(record: &Record) -> usize {
    record.operations.values().filter_map(|o| o.output.as_ref()).map(|o| serde_json::to_vec(o).map_or(usize::MAX / 2, |v| v.len())).sum()
}

impl Handle {
    pub fn start(config: &WorkerConfig, report: Preflight) -> Result<Self> {
        let enabled = config.native.as_ref().is_some_and(|c| c.enabled) && report.ready;
        let status = WorkerStatus { schema_version: 1, node_id: config.node_id.clone(), architecture: std::env::consts::ARCH.to_owned(), os: std::env::consts::OS.to_owned(),
            capacity: config.capacity.clone(), usage: enabled.then_some(Usage { memory_mib: 0, vcpus: 0, sandboxes: 0, restores: 0 }), admission_ready: false,
            runtimes: vec![RuntimeCapability { runtime: Runtime::RuncCriu, ready: false, reason: if enabled { "reconciling" } else if config.native.as_ref().is_some_and(|c| c.enabled) { "preflight_failed" } else { "runtime_disabled" }.into() }],
            cpu_overcommit: config.native.as_ref().map_or(1, |c| c.cpu_overcommit), qualification: "unvalidated".into() };
        let snapshot = Arc::new(RwLock::new(Snapshot { status, records: BTreeMap::new(), cancels: BTreeMap::new() }));
        if !enabled { return Ok(Self { snapshot, preflight: report, sender: None }); }
        let native = Arc::new(Native::open(config.native.clone().ok_or("native_config_missing")?, report.clone())?);
        let mut engine = Engine { native: native.clone(), snapshot: snapshot.clone(), records: BTreeMap::new(), healthy: true,
            pool: Vec::new(), flights: BTreeMap::new(), retry_after: BTreeMap::new(), stopping: None, stop_attempted: BTreeSet::new() };
        engine.reconcile()?;
        let restored = engine.records.iter().map(|(id, r)| (id.clone(), Arc::new(r.clone()))).collect();
        snapshot.write().expect("snapshot poisoned").records = restored;
        let (tx, rx) = mpsc::sync_channel(32);
        // Shared lower creation is serialized by its own bounded mailbox, never
        // by holding a lock over mount I/O or blocking the admission authority.
        let (lower_tx, lower_rx) = mpsc::sync_channel::<Lower>(native.config.max_concurrent_operations);
        let lower_native = native.clone();
        std::thread::Builder::new().name("sandbox-lowers".into()).spawn(move || {
            while let Ok(job) = lower_rx.recv() { let _ = job.done.send(lower_native.mount_lower(&job.manifest)); }
        }).map_err(|_| "lower_thread_failed")?;
        for slot in 0..native.config.max_concurrent_operations {
            let (job_tx, job_rx) = mpsc::sync_channel::<Job>(1);
            let completion = tx.clone();
            let runtime = native.clone();
            let lowers = lower_tx.clone();
            std::thread::Builder::new().name(format!("sandbox-operation-{slot}")).spawn(move || {
                while let Ok(job) = job_rx.recv() {
                    let mut runner = Runner { native: &runtime, lowers: &lowers, record: job.record, cancelled: job.cancelled };
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runner.perform(job.action))).is_err() {
                        runner.record.state = "cleanup_failed".into();
                        runner.record.error = Some("operation_worker_panicked".into());
                        for op in runner.record.operations.values_mut().filter(|o| o.state == "pending") {
                            op.state = "failed".into(); op.error = Some("operation_worker_panicked".into());
                        }
                    }
                    if completion.send(Work::Complete(slot, Box::new(runner.record))).is_err() { break; }
                }
            }).map_err(|_| "operation_thread_failed")?;
            engine.pool.push(job_tx);
        }
        drop(lower_tx);
        engine.publish();
        let watchdog_stop = Arc::new(AtomicBool::new(false));
        let stop = watchdog_stop.clone();
        let view = snapshot.clone();
        let events = tx.clone();
        let parent = native.config.cgroup_parent.clone();
        std::thread::Builder::new().name("sandbox-expiry".into()).spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let scan: Vec<_> = {
                    let s = view.read().expect("snapshot poisoned");
                    s.records.iter().filter(|(_, r)| r.reserved()).map(|(id, r)|
                        (id.clone(), r.expires_at <= now() || r.delete_requested || !s.status.admission_ready, r.state == "running", s.cancels.get(id).cloned())).collect()
                };
                for (id, kill, running, cancelled) in scan {
                    if kill {
                        if let Some(c) = cancelled { c.store(true, Ordering::Relaxed); }
                        let _ = fs::write(Path::new(&parent).join(&id).join("cgroup.kill"), "1");
                    } else if running && cancelled.is_none() && fs::read_to_string(Path::new(&parent).join(&id).join("cgroup.events"))
                        .is_ok_and(|text| text.lines().any(|l| l == "populated 0")) {
                        let _ = events.try_send(Work::Exited(id));
                    }
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }).map_err(|_| "expiry_thread_failed")?;
        std::thread::Builder::new().name("sandbox-admission".into()).spawn(move || {
            loop {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(Work::Complete(slot, record)) => engine.complete(slot, *record),
                    Ok(Work::Stop(done)) => { engine.healthy = false; engine.stopping = Some(done); engine.publish(); },
                    Ok(Work::Exited(id)) => {
                        if !engine.flights.contains_key(&id) && engine.records.get(&id).is_some_and(|r| r.state == "running") {
                            engine.records.get_mut(&id).unwrap().error = Some("workload_exited".into());
                            let _ = engine.request_delete(&id);
                        }
                    }
                    Ok(work) => engine.accept(work),
                    Err(mpsc::RecvTimeoutError::Timeout) => {},
                    Err(mpsc::RecvTimeoutError::Disconnected) => { engine.healthy = false; },
                }
                engine.maintenance();
                if engine.stopping.is_some() && engine.flights.is_empty()
                    && engine.records.iter().all(|(id, r)| !r.reserved() || engine.stop_attempted.contains(id)) {
                    let cleanup = if !engine.records.values().any(Record::reserved) { engine.native.unmount_lowers().and_then(|_| engine.native.remove_helpers()) } else { Err("private_cleanup_failed") };
                    let durable = process::atomic_json(&engine.native.root().join("worker-status.json"), &serde_json::json!({"cleanup_error":cleanup.err()}));
                    let _ = engine.stopping.take().unwrap().send(cleanup.and(durable));
                    break;
                }
            }
            watchdog_stop.store(true, Ordering::Relaxed);
        }).map_err(|_| "admission_thread_failed")?;
        Ok(Self { snapshot, preflight: report, sender: Some(tx) })
    }
}

struct Engine {
    native: Arc<Native>, snapshot: Arc<RwLock<Snapshot>>, records: BTreeMap<String, Record>, healthy: bool,
    pool: Vec<mpsc::SyncSender<Job>>, flights: BTreeMap<String, Flight>, retry_after: BTreeMap<String, Instant>,
    stopping: Option<mpsc::Sender<Result<()>>>, stop_attempted: BTreeSet<String>,
}
impl Engine {
    fn save(&mut self, id: &str) -> Result<()> {
        let result = process::atomic_json(&self.native.root().join("records").join(format!("{id}.json")), &self.records[id]);
        if result.is_err() { self.healthy = false; }
        let record = Arc::new(self.records[id].clone());
        self.snapshot.write().expect("snapshot poisoned").records.insert(id.into(), record);
        self.publish(); result
    }
    fn usage(&self) -> Usage {
        let mut u = Usage { memory_mib: 0, vcpus: 0, sandboxes: 0, restores: self.flights.values().filter(|f| f.restore).count() as u32 };
        for r in self.records.values().filter(|r| r.reserved()) { u.memory_mib += r.request.memory_mib; u.vcpus += r.request.vcpus; u.sandboxes += 1; }
        u
    }
    fn publish(&self) {
        let usage = self.usage();
        let mut s = self.snapshot.write().expect("snapshot poisoned");
        s.status.usage = Some(usage); s.status.admission_ready = self.healthy;
        s.status.runtimes[0].ready = self.healthy;
        s.status.runtimes[0].reason = if self.healthy { "experimental_preflight_passed" } else if self.stopping.is_some() { "shutting_down" } else { "durability_failure" }.into();
    }
    fn idle_slot(&self) -> Option<usize> { (0..self.pool.len()).find(|slot| !self.flights.values().any(|f| f.slot == *slot)) }
    fn launch(&mut self, id: &str, action: Action, slot: usize) {
        let restore = matches!(action, Action::Create | Action::Capture(_));
        let output_bytes = match &action { Action::Exec(r) => r.max_output_bytes as usize * 6 + 4096, _ => 0 };
        let template = match &action { Action::Capture(r) => Some(r.template_id.clone()), _ => None };
        let cancelled = Arc::new(AtomicBool::new(false));
        self.flights.insert(id.into(), Flight { slot, restore, output_bytes, template, cancelled: cancelled.clone() });
        self.snapshot.write().expect("snapshot poisoned").cancels.insert(id.into(), cancelled.clone());
        if self.pool[slot].try_send(Job { record: self.records[id].clone(), action, cancelled }).is_err() {
            self.healthy = false;
            self.flights.remove(id);
            self.snapshot.write().expect("snapshot poisoned").cancels.remove(id);
            self.records.get_mut(id).unwrap().state = "cleanup_failed".into();
            self.records.get_mut(id).unwrap().error = Some("operation_worker_unavailable".into());
            let _ = self.save(id);
        }
        self.publish();
    }
    fn complete(&mut self, slot: usize, mut record: Record) {
        if self.native.helpers.ensure_healthy().is_err() { self.healthy = false; }
        let id = record.request.sandbox_id.clone();
        if !self.flights.get(&id).is_some_and(|f| f.slot == slot) { self.healthy = false; self.publish(); return; }
        self.flights.remove(&id);
        self.snapshot.write().expect("snapshot poisoned").cancels.remove(&id);
        record.delete_requested |= self.records[&id].delete_requested || !self.healthy || record.expires_at <= now();
        if record.reserved() && record.delete_requested && record.state != "cleanup_failed" { record.state = "deleting".into(); }
        if record.state == "cleanup_failed" { self.retry_after.insert(id.clone(), Instant::now() + Duration::from_secs(2)); }
        self.records.insert(id.clone(), record);
        let _ = self.save(&id);
    }
    fn accept(&mut self, work: Work) {
        if self.native.helpers.ensure_healthy().is_err() { self.healthy = false; self.publish(); }
        match work {
            Work::Delete(id, ack) => { let result = self.request_delete(&id); let _ = ack.send(result); },
            Work::Create(r, ack) => { if self.healthy { self.create(r, ack); } else { let _ = ack.send(Err("worker_unavailable")); } },
            Work::Exec(id, r, ack) => { if self.healthy { self.operation(&id, Action::Exec(r), ack); } else { let _ = ack.send(Err("worker_unavailable")); } },
            Work::Capture(id, r, ack) => { if self.healthy { self.operation(&id, Action::Capture(r), ack); } else { let _ = ack.send(Err("worker_unavailable")); } },
            _ => unreachable!(),
        }
    }
    fn create(&mut self, request: CreateRequest, ack: Ack) {
        let id = request.sandbox_id.clone();
        if let Some(r) = self.records.get(&id) { let _ = ack.send(if r.request == request { Ok(()) } else { Err("idempotency_conflict") }); return; }
        if self.records.len() >= self.native.config.max_records { let _ = ack.send(Err("record_limit")); return; }
        let Some(slot) = self.idle_slot() else { let _ = ack.send(Err("busy")); return; };
        let u = self.usage(); let s = self.snapshot.read().expect("snapshot poisoned").status.clone();
        if u.restores >= s.capacity.max_concurrent_restores { let _ = ack.send(Err("busy")); return; }
        let admitted = request.architecture == s.architecture && request.memory_mib <= s.capacity.memory_mib.saturating_sub(u.memory_mib)
            && request.vcpus <= s.capacity.vcpus.saturating_mul(s.cpu_overcommit).saturating_sub(u.vcpus) && u.sandboxes < s.capacity.max_sandboxes;
        if !self.native.resources_absent(&id) { let _ = ack.send(Err("resource_name_conflict")); return; }
        let error = if !admitted { Some("admission_exhausted") } else { None };
        self.records.insert(id.clone(), Record { schema_version: 1, expires_at: now() + request.ttl_seconds as u64, request, state: if error.is_none() { "creating" } else { "failed" }.into(),
            error: error.map(str::to_owned), delete_requested: false, operations: BTreeMap::new() });
        let saved = self.save(&id);
        if saved.is_ok() && error.is_none() { self.launch(&id, Action::Create, slot); }
        let _ = ack.send(saved);
    }
    fn operation(&mut self, id: &str, action: Action, ack: Ack) {
        let (op_id, hash, kind) = match &action {
            Action::Exec(r) => (r.operation_id.clone(), fingerprint(r), "exec"),
            Action::Capture(r) => (r.operation_id.clone(), fingerprint(r), "capture"), _ => unreachable!(),
        };
        let Some(record) = self.records.get(id) else { let _ = ack.send(Err("sandbox_not_found")); return; };
        if let Some(op) = record.operations.get(&op_id) { let _ = ack.send(if op.fingerprint == hash && op.kind == kind { Ok(()) } else { Err("idempotency_conflict") }); return; }
        if record.operations.len() >= self.native.config.max_operations_per_sandbox { let _ = ack.send(Err("operation_limit")); return; }
        if self.flights.contains_key(id) { let _ = ack.send(Err("busy")); return; }
        let Some(slot) = self.idle_slot() else { let _ = ack.send(Err("busy")); return; };
        if let Action::Capture(r) = &action {
            let limit = self.snapshot.read().expect("snapshot poisoned").status.capacity.max_concurrent_restores;
            if self.usage().restores >= limit || self.flights.values().any(|f| f.template.as_deref() == Some(&r.template_id)) { let _ = ack.send(Err("busy")); return; }
        }
        if let Action::Exec(r) = &action {
            let reserved = r.max_output_bytes as usize * 6 + 4096;
            if self.records.values().map(output_bytes).sum::<usize>() + self.flights.values().map(|f| f.output_bytes).sum::<usize>() + reserved > self.native.config.max_retained_output_bytes
                || output_bytes(record) + reserved > 8388608 { let _ = ack.send(Err("result_limit")); return; }
        }
        let running = record.state == "running" && record.expires_at > now() && !record.delete_requested;
        let record = self.records.get_mut(id).unwrap();
        record.operations.insert(op_id, Operation { fingerprint: hash, kind: kind.into(), state: if running { "pending" } else { "failed" }.into(),
            error: (!running).then(|| "sandbox_not_running".into()), output: None, template_id: None });
        if running && kind == "capture" { record.state = "capturing".into(); }
        let saved = self.save(id);
        if saved.is_ok() && running { self.launch(id, action, slot); }
        let _ = ack.send(saved);
    }
    fn request_delete(&mut self, id: &str) -> Result<()> {
        let record = self.records.get_mut(id).ok_or("sandbox_not_found")?;
        if !record.reserved() { return Ok(()); }
        record.delete_requested = true; record.state = "deleting".into();
        if let Some(f) = self.flights.get(id) { f.cancelled.store(true, Ordering::Relaxed); }
        self.save(id)
    }
    fn maintenance(&mut self) {
        let ids: Vec<_> = self.records.iter().filter(|(_, r)| r.reserved() && (!self.healthy || r.expires_at <= now() || r.delete_requested || r.state == "cleanup_failed"))
            .map(|(id, _)| id.clone()).collect();
        for id in ids {
            if !self.records[&id].delete_requested { let _ = self.request_delete(&id); }
            if self.flights.contains_key(&id) { continue; }
            if self.stopping.is_some() && self.stop_attempted.contains(&id) { continue; }
            if self.stopping.is_none() && self.retry_after.get(&id).is_some_and(|t| *t > Instant::now()) { continue; }
            let Some(slot) = self.idle_slot() else { break; };
            if self.stopping.is_some() { self.stop_attempted.insert(id.clone()); }
            // Previously durable ownership permits cleanup even if saving its
            // transition fails. A disk error cannot disable termination.
            self.launch(&id, Action::Delete, slot);
        }
    }
    fn reconcile(&mut self) -> Result<()> {
        for entry in fs::read_dir(self.native.root().join("records")).map_err(|_| "record_scan_failed")? {
            let path = entry.map_err(|_| "record_scan_failed")?.path();
            if path.extension().is_some_and(|e| e == "pending") { continue; }
            let id = path.file_stem().and_then(|n| n.to_str()).ok_or("invalid_record_name")?;
            let node = self.snapshot.read().expect("snapshot poisoned").status.node_id.clone();
            if crate::model::sandbox_owner(id) != Some(node.as_str()) || path.extension().is_none_or(|e| e != "json") { return Err("invalid_record_name"); }
            let r: Record = storage::read_json(&path, 16777216)?;
            if r.schema_version != 1 || r.request.sandbox_id != id || !r.request.valid() || self.records.len() >= self.native.config.max_records { return Err("invalid_record"); }
            self.records.insert(id.into(), r);
        }
        for name in ["private", "runc"] {
            for entry in fs::read_dir(self.native.root().join(name)).map_err(|_| "private_scan_failed")? {
                if !entry.map_err(|_| "private_scan_failed")?.file_name().to_str().is_some_and(|id| self.records.contains_key(id)) { return Err("untracked_private_state"); }
            }
        }
        for entry in fs::read_dir(&self.native.config.cgroup_parent).map_err(|_| "cgroup_scan_failed")? {
            let e = entry.map_err(|_| "cgroup_scan_failed")?;
            if e.file_type().map_err(|_| "cgroup_scan_failed")?.is_dir() && e.path() != self.native.helpers.path() && !e.file_name().to_str().is_some_and(|id| self.records.contains_key(id)) { return Err("untracked_cgroup_state"); }
        }
        let ids: Vec<_> = self.records.keys().cloned().collect();
        for id in ids {
            if self.records[&id].reserved() || !self.native.resources_absent(&id) {
                let r = self.records.get_mut(&id).unwrap();
                r.delete_requested = true; r.state = "deleting".into();
                for op in r.operations.values_mut().filter(|o| o.state == "pending") { op.state = "failed".into(); op.error = Some("worker_restarted".into()); }
                let _ = self.save(&id);
                let cleanup = self.native.cleanup(&id, &self.records[&id].exec_operations());
                let r = self.records.get_mut(&id).unwrap();
                r.state = if cleanup.is_ok() { "deleted" } else { "cleanup_failed" }.into(); r.error = cleanup.err().map(str::to_owned);
                let _ = self.save(&id);
            }
        }
        if !self.records.values().any(Record::reserved) { self.native.unmount_lowers()?; }
        for entry in fs::read_dir(self.native.root().join("staging")).map_err(|_| "staging_scan_failed")? { storage::remove_private(&entry.map_err(|_| "staging_scan_failed")?.path())?; }
        if !self.healthy { return Err("reconciliation_durability_failed"); }
        process::atomic_json(&self.native.root().join("worker-status.json"), &serde_json::json!({"cleanup_error": if self.records.values().any(Record::reserved) { Some("private_cleanup_failed") } else { None }}))
    }
}

struct Runner<'a> { native: &'a Native, lowers: &'a mpsc::SyncSender<Lower>, record: Record, cancelled: Arc<AtomicBool> }
impl Runner<'_> {
    fn active(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) || self.record.expires_at <= now() { Err("sandbox_cancelled_or_expired") } else { Ok(()) }
    }
    fn perform(&mut self, action: Action) {
        match action { Action::Create => self.create(), Action::Exec(r) => self.exec(r), Action::Capture(r) => self.capture(r), Action::Delete => self.delete() }
    }
    fn delete(&mut self) {
        let result = self.native.cleanup(&self.record.request.sandbox_id, &self.record.exec_operations());
        self.record.state = if result.is_ok() { "deleted" } else { "cleanup_failed" }.into();
        if let Err(e) = result { self.record.error = Some(e.into()); }
    }
    fn create(&mut self) {
        let result = (|| -> Result<()> {
            self.active()?;
            let manifest = self.native.template(&self.record.request.template_id)?;
            let (tx, rx) = mpsc::channel();
            self.lowers.send(Lower { manifest: manifest.clone(), done: tx }).map_err(|_| "lower_worker_unavailable")?;
            rx.recv().map_err(|_| "lower_worker_unavailable")??;
            self.active()?;
            self.native.prepare(&self.record.request, &manifest, self.record.expires_at, &self.cancelled)
        })();
        if let Err(e) = result { self.delete(); if self.record.state == "deleted" { self.record.state = "failed".into(); self.record.error = Some(e.into()); } }
        else { self.record.state = "running".into(); }
    }
    fn finish(&mut self, id: &str, error: Option<&str>) {
        let op = self.record.operations.get_mut(id).unwrap(); op.state = if error.is_some() { "failed" } else { "complete" }.into(); op.error = error.map(str::to_owned);
    }
    fn exec(&mut self, request: ExecRequest) {
        let id = self.record.request.sandbox_id.clone();
        let file = self.native.private(&id).join("exec.json");
        let result = self.active().and_then(|_| self.native.create_exec_cgroup(&id, &request.operation_id))
            .and_then(|_| process::atomic_json(&file, &self.native.process_spec(request.argv))).and_then(|_| {
            let remaining = self.record.expires_at.saturating_sub(now()).saturating_mul(1000);
            self.native.runc(vec!["exec".into(), "--cgroup".into(), format!("exec-{}", request.operation_id), "--process".into(), file.display().to_string(), id.clone()], Duration::from_millis(request.timeout_ms.min(remaining.max(1))), request.max_output_bytes as usize)
        });
        let _ = fs::remove_file(&file);
        let cleanup = self.native.cleanup_exec_cgroup(&id, &request.operation_id);
        let result = result.and_then(|output| cleanup.map(|_| output));
        match result {
            Ok(output) => {
                let interrupted = output.interrupted;
                self.record.operations.get_mut(&request.operation_id).unwrap().output = Some(output);
                if interrupted { self.delete(); self.finish(&request.operation_id, Some("exec_deadline_or_output_limit")); }
                else { self.finish(&request.operation_id, None); }
            }
            Err(e) => { self.delete(); self.finish(&request.operation_id, Some(e)); }
        }
    }
    fn recover(&self, images: &Path) -> Result<()> {
        self.active()?;
        self.native.forget_stopped(&self.record.request.sandbox_id)?;
        self.native.restore_source(&self.record.request, images, self.record.expires_at, &self.cancelled)
    }
    fn capture(&mut self, request: CaptureRequest) {
        let id = self.record.request.sandbox_id.clone();
        // Length prefix makes the pair injective even when either ID contains hyphens.
        let stage = self.native.root().join("staging").join(format!("{}-{id}-{}", id.len(), request.operation_id));
        let mut stage_owned = false;
        let destination = self.native.root().join("templates").join(&request.template_id);
        let mut stopped = false;
        let mut checkpoint_attempted = false;
        let mut checkpoint_completed = false;
        let result = (|| -> Result<()> {
            self.active()?;
            if destination.exists() { return Err("template_already_exists"); }
            let mut manifest = self.native.template(&self.record.request.template_id)?;
            storage::exclusive_private_dir(&stage)?;
            stage_owned = true;
            let images = stage.join("images"); storage::private_dir(&images)?;
            checkpoint_attempted = true;
            self.native.checkpoint(&id, &images)?;
            checkpoint_completed = true;
            stopped = true;
            storage::archive(self.native.tool("tar")?, &self.native.private(&id).join("upper"), &stage.join("upper.tar"), self.native.config.command_timeout_seconds, &self.native.search_path, &self.native.helpers)?;
            storage::archive(self.native.tool("tar")?, &images, &stage.join("checkpoint.tar"), self.native.config.command_timeout_seconds, &self.native.search_path, &self.native.helpers)?;
            manifest.template_id = request.template_id.clone(); manifest.generation = request.operation_id.clone();
            manifest.upper = Some(storage::artifact(&stage.join("upper.tar"), self.native.config.max_artifact_bytes)?);
            manifest.checkpoint = Some(storage::artifact(&stage.join("checkpoint.tar"), self.native.config.max_artifact_bytes)?);
            manifest.memory_mib = Some(self.record.request.memory_mib); manifest.vcpus = Some(self.record.request.vcpus);
            manifest.oci_config_sha256 = Some(self.native.spec_digest(&id)?);
            storage::write_manifest(&stage, &manifest)?;
            self.recover(&images)?; stopped = false;
            self.active()?;
            storage::remove_private(&images)?;
            fs::File::open(&stage).and_then(|f| f.sync_all()).map_err(|_| "template_sync_failed")?;
            fs::rename(&stage, &destination).map_err(|_| "template_publish_failed")?;
            stage_owned = false;
            fs::File::open(destination.parent().ok_or("invalid_template_path")?).and_then(|f| f.sync_all()).map_err(|_| "template_sync_failed")?;
            Ok(())
        })();
        // A failed dump can leave a live PID with uncertain process state. Do
        // not equate runc's PID liveness with successful CRIU failure recovery.
        let recovery = if checkpoint_attempted && !checkpoint_completed { Err("checkpoint_failed_source_terminated") }
            else if stopped { self.recover(&stage.join("images")) }
            else { self.active().and_then(|_| self.native.ensure_running(&id)) };
        if recovery.is_ok() { self.record.state = "running".into(); } else { self.delete(); }
        let cleanup = if stage_owned { self.native.helpers.ensure_healthy().and_then(|_| storage::remove_private(&stage)) } else { Ok(()) };
        let error = result.err().or(recovery.err()).or(cleanup.err());
        if error.is_none() { self.record.operations.get_mut(&request.operation_id).unwrap().template_id = Some(request.template_id); }
        self.finish(&request.operation_id, error);
    }
}
