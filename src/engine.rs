//! Serialized durable admission/state transitions, bounded parallel runtime I/O.
//! Each sandbox has at most one in-flight job. A management request waits on a
//! oneshot reply for the job's real outcome, but never owns the job: if the client
//! disconnects or its wait expires, the job still runs to a terminal state with
//! normal cleanup and its reply is discarded. An undeliverable create reply instead
//! deletes the new sandbox (`create_response_lost`); a reply lost after hand-over
//! is bounded by TTL.
use std::{collections::{BTreeMap, BTreeSet}, fs, path::Path, sync::{Arc, RwLock, mpsc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use serde::{Deserialize, Serialize};
use crate::{config::WorkerConfig, model::{CaptureRequest, CreateRequest, ExecRequest, HttpOutput, HttpRequest, Runtime, RuntimeCapability, SandboxSpec, Usage, WorkerStatus}, native::{Native, Preflight}, process::{self, Result}, storage};

const RECORD_SCHEMA: u32 = 2;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema_version: u32,
    pub request: SandboxSpec,
    pub state: String,
    pub error: Option<String>,
    pub expires_at: u64,
    pub delete_requested: bool,
    pub network_slot: Option<usize>,
    pub network_policy: Option<crate::model::NetworkPolicy>,
}
impl Record {
    // Keep capacity reserved until the record is deleted or failed.
    pub fn reserved(&self) -> bool { !matches!(self.state.as_str(), "deleted" | "failed") }
    // Return the public view of this sandbox: IDs, state, error and expiry time.
    pub fn view(&self) -> SandboxView {
        SandboxView { sandbox_id: self.request.sandbox_id.clone(), template_id: self.request.template_id.clone(),
            state: self.state.clone(), error: self.error.clone(), expires_at: self.expires_at }
    }
}
#[derive(Serialize)]
pub struct SandboxView { pub sandbox_id: String, pub template_id: String, pub state: String, pub error: Option<String>, pub expires_at: u64 }
#[derive(Serialize)]
pub struct ExecResult {
    pub exit_code: Option<i32>, pub stdout: String, pub stderr: String, pub interrupted: bool,
    pub error: Option<&'static str>, pub sandbox_state: String,
}
#[derive(Serialize)]
pub struct CaptureResult { pub sandbox_id: String, pub template_id: String, pub generation: String, pub state: String }
pub enum Outcome { Created(SandboxView), Sandbox(SandboxView), Exec(ExecResult), Http(HttpOutput), Captured(CaptureResult) }
pub type Reply = tokio::sync::oneshot::Sender<Result<Outcome>>;

pub struct Snapshot {
    pub status: WorkerStatus,
    pub records: BTreeMap<String, Arc<Record>>,
    cancels: BTreeMap<String, Arc<AtomicBool>>,
}
#[derive(Clone)]
pub struct Handle {
    pub snapshot: Arc<RwLock<Snapshot>>, pub preflight: Preflight, pub sender: Option<mpsc::SyncSender<Work>>,
    pub application_http_limits: crate::config::ApplicationHttpLimits, pub deadlines: crate::config::OperationDeadlines,
}
pub enum Work {
    Create(CreateRequest, Reply), Http(String, HttpRequest, Reply), Exec(String, ExecRequest, Reply), Capture(String, CaptureRequest, Reply), Delete(String, Reply),
    Complete(usize, Box<(Record, Result<Outcome>)>), Exited(String), Stop(mpsc::Sender<Result<()>>),
}
enum Action { Create, Http(HttpRequest), Exec(ExecRequest), Capture(CaptureRequest, String), Delete }
struct Job { record: Record, action: Action, cancelled: Arc<AtomicBool> }
struct Flight { slot: usize, restore: bool, template: Option<String>, cancelled: Arc<AtomicBool>, reply: Option<Reply> }
struct Lower { manifest: storage::Manifest, done: mpsc::Sender<Result<()>> }
// Return seconds since the Unix epoch, falling back to zero if the clock is earlier.
pub fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }
// Hash a value's serialized form; used to stamp the template network policy into the saved
// execution specification.
pub fn fingerprint<T: Serialize>(input: &T) -> String { storage::digest(&serde_json::to_vec(input).expect("serialize validated input")) }
// Send a result to a waiting request, if any, ignoring a requester that already gave up.
fn answer(reply: Option<Reply>, result: Result<Outcome>) { if let Some(reply) = reply { let _ = reply.send(result); } }

impl Handle {
    // Return an unavailable handle if the runtime is disabled or preflight fails. Otherwise reconcile
    // durable state, then start the lower-mount thread, bounded operation workers, serialized admission
    // and expiry/exit monitoring; accepted jobs continue independently of HTTP connections.
    // Shutdown waits for in-flight jobs and one cleanup attempt per remaining sandbox.
    pub fn start(config: &WorkerConfig, report: Preflight) -> Result<Self> {
        let enabled = config.native.as_ref().is_some_and(|c| c.enabled) && report.ready;
        let status = WorkerStatus { schema_version: 1, node_id: config.node_id.clone(), architecture: std::env::consts::ARCH.to_owned(), os: std::env::consts::OS.to_owned(),
            capacity: config.capacity.clone(), usage: enabled.then_some(Usage { memory_mib: 0, vcpus: 0, sandboxes: 0, restores: 0 }), admission_ready: false,
            runtimes: vec![RuntimeCapability { runtime: Runtime::RuncCriu, ready: false, reason: if enabled { "reconciling" } else if config.native.as_ref().is_some_and(|c| c.enabled) { "preflight_failed" } else { "runtime_disabled" }.into() }],
            cpu_overcommit: config.native.as_ref().map_or(1, |c| c.cpu_overcommit), qualification: "unvalidated".into() };
        let snapshot = Arc::new(RwLock::new(Snapshot { status, records: BTreeMap::new(), cancels: BTreeMap::new() }));
        if !enabled { return Ok(Self { snapshot, preflight: report, sender: None, application_http_limits: config.server.application_http.clone(), deadlines: config.server.operation_deadlines.clone() }); }
        let native = Arc::new(Native::open(config.native.clone().ok_or("native_config_missing")?, report.clone())?);
        let mut engine = Engine { native: native.clone(), snapshot: snapshot.clone(), records: BTreeMap::new(), healthy: true,
            pool: Vec::new(), flights: BTreeMap::new(), delete_waiters: BTreeMap::new(), retry_after: BTreeMap::new(), stopping: None, stop_attempted: BTreeSet::new() };
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
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runner.perform(job.action))).unwrap_or_else(|_| {
                        runner.record.state = "cleanup_failed".into();
                        runner.record.error = Some("operation_worker_panicked".into());
                        Err("operation_worker_panicked")
                    });
                    if completion.send(Work::Complete(slot, Box::new((runner.record, outcome)))).is_err() { break; }
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
                    Ok(Work::Complete(slot, done)) => { let (record, outcome) = *done; engine.complete(slot, record, outcome) },
                    Ok(Work::Stop(done)) => { engine.healthy = false; engine.stopping = Some(done); engine.publish(); },
                    Ok(Work::Exited(id)) => {
                        if !engine.flights.contains_key(&id) && engine.records.get(&id).is_some_and(|r| r.state == "running") {
                            engine.records.get_mut(&id).unwrap().error = Some("workload_exited".into());
                            engine.request_delete(&id, None);
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
        Ok(Self { snapshot, preflight: report, sender: Some(tx), application_http_limits: config.server.application_http.clone(), deadlines: config.server.operation_deadlines.clone() })
    }
}

struct Engine {
    native: Arc<Native>, snapshot: Arc<RwLock<Snapshot>>, records: BTreeMap<String, Record>, healthy: bool,
    pool: Vec<mpsc::SyncSender<Job>>, flights: BTreeMap<String, Flight>,
    // At most one waiting DELETE per sandbox; it is answered after cleanup.
    delete_waiters: BTreeMap<String, Reply>, retry_after: BTreeMap<String, Instant>,
    stopping: Option<mpsc::Sender<Result<()>>>, stop_attempted: BTreeSet<String>,
}
impl Engine {
    // Persist a sandbox record and refresh its public snapshot. A save failure closes admission, even
    // though the in-memory view is still updated.
    fn save(&mut self, id: &str) -> Result<()> {
        let result = process::atomic_json(&self.native.root().join("records").join(format!("{id}.json")), &self.records[id]);
        if result.is_err() { self.healthy = false; }
        let record = Arc::new(self.records[id].clone());
        self.snapshot.write().expect("snapshot poisoned").records.insert(id.into(), record);
        self.publish(); result
    }
    // Total reserved memory, CPUs and sandbox slots, plus in-flight create/capture slots; not measured
    // memory use.
    fn usage(&self) -> Usage {
        let mut u = Usage { memory_mib: 0, vcpus: 0, sandboxes: 0, restores: self.flights.values().filter(|f| f.restore).count() as u32 };
        for r in self.records.values().filter(|r| r.reserved()) { u.memory_mib += r.request.memory_mib; u.vcpus += r.request.vcpus; u.sandboxes += 1; }
        u
    }
    // Publish reservation totals and admission readiness, with a reason when the engine is unhealthy.
    fn publish(&self) {
        let usage = self.usage();
        let mut s = self.snapshot.write().expect("snapshot poisoned");
        s.status.usage = Some(usage); s.status.admission_ready = self.healthy;
        s.status.runtimes[0].ready = self.healthy;
        s.status.runtimes[0].reason = if self.healthy { "experimental_preflight_passed" } else if self.stopping.is_some() { "shutting_down" } else { "durability_failure" }.into();
    }
    // Find the first operation worker slot not assigned to an in-flight job.
    fn idle_slot(&self) -> Option<usize> { (0..self.pool.len()).find(|slot| !self.flights.values().any(|f| f.slot == *slot)) }
    // Hand a job to the chosen idle operation worker and record it as in flight with a cancel flag. A
    // delete takes over the waiting DELETE reply. If the worker cannot take the job, mark the sandbox
    // cleanup_failed, close admission and fail the reply.
    fn launch(&mut self, id: &str, action: Action, slot: usize, reply: Option<Reply>) {
        let restore = matches!(action, Action::Create | Action::Capture(..));
        let template = match &action { Action::Capture(r, _) => Some(r.template_id.clone()), _ => None };
        let reply = if matches!(action, Action::Delete) { self.delete_waiters.remove(id) } else { reply };
        let cancelled = Arc::new(AtomicBool::new(false));
        self.flights.insert(id.into(), Flight { slot, restore, template, cancelled: cancelled.clone(), reply });
        self.snapshot.write().expect("snapshot poisoned").cancels.insert(id.into(), cancelled.clone());
        if self.pool[slot].try_send(Job { record: self.records[id].clone(), action, cancelled }).is_err() {
            self.healthy = false;
            let flight = self.flights.remove(id);
            self.snapshot.write().expect("snapshot poisoned").cancels.remove(id);
            self.records.get_mut(id).unwrap().state = "cleanup_failed".into();
            self.records.get_mut(id).unwrap().error = Some("operation_worker_unavailable".into());
            let _ = self.save(id);
            answer(flight.and_then(|f| f.reply), Err("operation_worker_unavailable"));
        }
        self.publish();
    }
    // Save a finished job's record, turning it into a pending delete if deletion, expiry or ill health
    // arrived meanwhile, and deliver its outcome with the current state. Answer a waiting DELETE once the
    // sandbox is gone, and delete a new sandbox whose create reply could not be delivered.
    fn complete(&mut self, slot: usize, mut record: Record, outcome: Result<Outcome>) {
        if self.native.helpers.ensure_healthy().is_err() { self.healthy = false; }
        let id = record.request.sandbox_id.clone();
        if !self.flights.get(&id).is_some_and(|f| f.slot == slot) { self.healthy = false; self.publish(); return; }
        let flight = self.flights.remove(&id).unwrap();
        self.snapshot.write().expect("snapshot poisoned").cancels.remove(&id);
        record.delete_requested |= self.records[&id].delete_requested || !self.healthy || record.expires_at <= now();
        if record.reserved() && record.delete_requested && record.state != "cleanup_failed" { record.state = "deleting".into(); }
        if record.state == "cleanup_failed" { self.retry_after.insert(id.clone(), Instant::now() + Duration::from_secs(2)); }
        self.records.insert(id.clone(), record);
        let _ = self.save(&id);
        let record = &self.records[&id];
        let outcome = match outcome {
            Ok(Outcome::Created(_)) if record.state != "running" => Err("sandbox_cancelled_or_expired"),
            Ok(Outcome::Created(_)) => Ok(Outcome::Created(record.view())),
            Ok(Outcome::Exec(mut result)) => { result.sandbox_state = record.state.clone(); Ok(Outcome::Exec(result)) }
            Ok(Outcome::Captured(mut result)) => { result.state = record.state.clone(); Ok(Outcome::Captured(result)) }
            other => other,
        };
        let created = matches!(outcome, Ok(Outcome::Created(_)));
        let delivered = flight.reply.is_some_and(|reply| reply.send(outcome).is_ok());
        if !record.reserved() { let view = record.view(); answer(self.delete_waiters.remove(&id), Ok(Outcome::Sandbox(view))); }
        // Nobody can learn a controller-generated ID whose create reply was lost
        // (client disconnect, expired wait): delete it instead of holding capacity
        // until TTL. Other outcomes are just discarded; their sandboxes stay known.
        if created && !delivered {
            self.records.get_mut(&id).unwrap().error = Some("create_response_lost".into());
            self.request_delete(&id, None);
        }
    }
    // Route submitted work to admission or deletion after checking helper health. Unhealthy workers reject
    // new work but still accept deletion requests.
    fn accept(&mut self, work: Work) {
        if self.native.helpers.ensure_healthy().is_err() { self.healthy = false; self.publish(); }
        match work {
            Work::Delete(id, reply) => self.request_delete(&id, Some(reply)),
            Work::Create(r, reply) => { if self.healthy { self.create(r, reply); } else { let _ = reply.send(Err("worker_unavailable")); } },
            Work::Http(id, r, reply) => { if self.healthy { self.operation(&id, Action::Http(r), reply); } else { let _ = reply.send(Err("worker_unavailable")); } },
            Work::Exec(id, r, reply) => { if self.healthy { self.operation(&id, Action::Exec(r), reply); } else { let _ = reply.send(Err("worker_unavailable")); } },
            Work::Capture(id, r, reply) => {
                if !self.healthy { let _ = reply.send(Err("worker_unavailable")); return; }
                // Worker-generated, so callers need no operation identifier.
                let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
                let generation = storage::digest(format!("{id}:{}:{nanos}", r.template_id).as_bytes())[..32].to_owned();
                self.operation(&id, Action::Capture(r, generation), reply);
            }
            _ => unreachable!(),
        }
    }
    // Admit a create. A known ID returns its state for an identical retry (conflict or busy otherwise).
    // Reject without writing a record when records, operation or restore slots, the template, its
    // resources, leftover resource names, capacity or network slots do not allow it. Otherwise save a
    // creating record and launch the job.
    fn create(&mut self, request: CreateRequest, reply: Reply) {
        let id = request.sandbox_id.clone();
        if let Some(r) = self.records.get(&id) {
            // Identical retry returns current state; it never launches a second time.
            let result = if !request.matches(&r.request) { Err("idempotency_conflict") }
                else if self.flights.contains_key(&id) { Err("sandbox_busy") } else { Ok(Outcome::Sandbox(r.view())) };
            let _ = reply.send(result); return;
        }
        if self.records.len() >= self.native.config.max_records { let _ = reply.send(Err("record_limit")); return; }
        let Some(slot) = self.idle_slot() else { let _ = reply.send(Err("busy")); return; };
        let u = self.usage(); let s = self.snapshot.read().expect("snapshot poisoned").status.clone();
        if u.restores >= s.capacity.max_concurrent_restores { let _ = reply.send(Err("busy")); return; }
        // Bounded manifest read on this dedicated thread (never Tokio). A template this
        // worker cannot launch is rejected before any record, so the controller may
        // place the create elsewhere. Artifact digests are verified by the job.
        let Ok(manifest) = self.native.template_manifest(&request.template_id) else { let _ = reply.send(Err("template_unavailable")); return; };
        let warm = manifest.checkpoint.is_some();
        let resolve = |explicit: Option<u64>, template: Option<u64>| match (explicit, template) {
            (Some(e), Some(t)) if warm && e != t => Err("template_resource_mismatch"),
            (Some(e), _) | (None, Some(e)) => Ok(e),
            (None, None) => Err("resources_required"),
        };
        let resources = resolve(request.memory_mib, manifest.memory_mib)
            .and_then(|m| resolve(request.vcpus.map(u64::from), manifest.vcpus.map(u64::from)).map(|v| (m, v as u32)));
        let (memory_mib, vcpus) = match resources { Ok(r) => r, Err(e) => { let _ = reply.send(Err(e)); return; } };
        let spec = SandboxSpec { sandbox_id: id.clone(), template_id: request.template_id, memory_mib, vcpus, ttl_seconds: request.ttl_seconds };
        let admitted = spec.memory_mib <= s.capacity.memory_mib.saturating_sub(u.memory_mib)
            && spec.vcpus <= s.capacity.vcpus.saturating_mul(s.cpu_overcommit).saturating_sub(u.vcpus) && u.sandboxes < s.capacity.max_sandboxes;
        if !self.native.resources_absent(&id) { let _ = reply.send(Err("resource_name_conflict")); return; }
        let network_slot = self.native.config.network.as_ref().and_then(|n| (0..n.addresses.len()).find(|slot| !self.records.values().any(|r| r.reserved() && r.network_slot == Some(*slot))));
        // A capacity rejection writes no record: the controller-generated ID is never
        // reused and nothing was created, so failover attempts cannot exhaust max_records.
        if !admitted || (self.native.config.network.is_some() && network_slot.is_none()) { let _ = reply.send(Err("admission_exhausted")); return; }
        self.records.insert(id.clone(), Record { schema_version: RECORD_SCHEMA, expires_at: now() + spec.ttl_seconds as u64, request: spec, state: "creating".into(),
            error: None, delete_requested: false, network_slot, network_policy: None });
        match self.save(&id) {
            Err(e) => { let _ = reply.send(Err(e)); }
            Ok(()) => self.launch(&id, Action::Create, slot, Some(reply)),
        }
    }
    // Start an exec, HTTP call or capture on a running sandbox, rejecting it at once if the sandbox is
    // missing, busy, not running or no slot is free. A capture also needs a restore slot and an unused
    // template name, and is saved as capturing first.
    fn operation(&mut self, id: &str, action: Action, reply: Reply) {
        let Some(record) = self.records.get(id) else { let _ = reply.send(Err("sandbox_not_found")); return; };
        // Conflicting same-sandbox work is rejected immediately, never queued.
        if self.flights.contains_key(id) || self.delete_waiters.contains_key(id) { let _ = reply.send(Err("sandbox_busy")); return; }
        if record.state != "running" || record.expires_at <= now() || record.delete_requested { let _ = reply.send(Err("sandbox_not_running")); return; }
        let Some(slot) = self.idle_slot() else { let _ = reply.send(Err("busy")); return; };
        if let Action::Capture(r, _) = &action {
            let limit = self.snapshot.read().expect("snapshot poisoned").status.capacity.max_concurrent_restores;
            if self.usage().restores >= limit { let _ = reply.send(Err("busy")); return; }
            if self.flights.values().any(|f| f.template.as_deref() == Some(&r.template_id)) { let _ = reply.send(Err("template_busy")); return; }
            self.records.get_mut(id).unwrap().state = "capturing".into();
            if let Err(e) = self.save(id) { let _ = reply.send(Err(e)); return; }
        }
        self.launch(id, action, slot, Some(reply));
    }
    // Mark a sandbox for deletion and cancel its in-flight job; maintenance launches the cleanup. An
    // already gone sandbox is answered at once, a second waiting DELETE gets sandbox_busy, and the
    // first waits for the cleanup result.
    fn request_delete(&mut self, id: &str, reply: Option<Reply>) {
        let Some(record) = self.records.get_mut(id) else { answer(reply, Err("sandbox_not_found")); return; };
        if !record.reserved() { let view = record.view(); answer(reply, Ok(Outcome::Sandbox(view))); return; }
        if let Some(reply) = reply {
            if self.delete_waiters.contains_key(id) { let _ = reply.send(Err("sandbox_busy")); return; }
            self.delete_waiters.insert(id.into(), reply);
            self.retry_after.remove(id);
        }
        if let Some(f) = self.flights.get(id) { f.cancelled.store(true, Ordering::Relaxed); }
        let record = self.records.get_mut(id).unwrap();
        if !record.delete_requested {
            record.delete_requested = true; record.state = "deleting".into();
            let _ = self.save(id);
        }
    }
    // Arrange deletion for expired, cancelled or unhealthy sandboxes and retry failed cleanup. Wait for
    // active jobs and available slots; shutdown attempts each remaining cleanup once.
    fn maintenance(&mut self) {
        let ids: Vec<_> = self.records.iter().filter(|(_, r)| r.reserved() && (!self.healthy || r.expires_at <= now() || r.delete_requested || r.state == "cleanup_failed"))
            .map(|(id, _)| id.clone()).collect();
        for id in ids {
            if !self.records[&id].delete_requested { self.request_delete(&id, None); }
            if self.flights.contains_key(&id) { continue; }
            if self.stopping.is_some() && self.stop_attempted.contains(&id) { continue; }
            if self.stopping.is_none() && self.retry_after.get(&id).is_some_and(|t| *t > Instant::now()) { continue; }
            let Some(slot) = self.idle_slot() else { break; };
            if self.stopping.is_some() { self.stop_attempted.insert(id.clone()); }
            // Previously durable ownership permits cleanup even if saving its
            // transition fails. A disk error cannot disable termination.
            self.launch(&id, Action::Delete, slot, None);
        }
    }
    // Load saved sandbox records and reject invalid or untracked resources. Kill and clean up every
    // sandbox left from before the restart and remove abandoned staging. Release unused lower mounts and
    // save cleanup status; durability failures prevent startup.
    fn reconcile(&mut self) -> Result<()> {
        for entry in fs::read_dir(self.native.root().join("records")).map_err(|_| "record_scan_failed")? {
            let path = entry.map_err(|_| "record_scan_failed")?.path();
            if path.extension().is_some_and(|e| e == "pending") { continue; }
            let id = path.file_stem().and_then(|n| n.to_str()).ok_or("invalid_record_name")?;
            let node = self.snapshot.read().expect("snapshot poisoned").status.node_id.clone();
            if crate::model::sandbox_owner(id) != Some(node.as_str()) || path.extension().is_none_or(|e| e != "json") { return Err("invalid_record_name"); }
            // Records hold only lifecycle metadata; operation results are never stored.
            let r: Record = storage::read_json(&path, 65536)?;
            if r.schema_version != RECORD_SCHEMA || r.request.sandbox_id != id || !r.request.valid() || self.records.len() >= self.native.config.max_records { return Err("invalid_record"); }
            if r.network_slot.is_some_and(|slot| slot >= 256 || (r.reserved() && self.records.values().any(|other| other.reserved() && other.network_slot == Some(slot)))) { return Err("invalid_network_slot_record"); }
            self.records.insert(id.into(), r);
        }
        self.native.verify_network_names(self.records.keys().map(String::as_str))?;
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
                let _ = self.save(&id);
                let cleanup = self.native.cleanup(&id);
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
    // Refuse further runtime work once the sandbox is cancelled or expired.
    fn active(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) || self.record.expires_at <= now() { Err("sandbox_cancelled_or_expired") } else { Ok(()) }
    }
    // Run one job on this operation worker and return its outcome; a delete succeeds only if cleanup
    // finished.
    fn perform(&mut self, action: Action) -> Result<Outcome> {
        match action {
            Action::Create => self.create(), Action::Http(r) => self.http(r), Action::Exec(r) => self.exec(r),
            Action::Capture(r, generation) => self.capture(r, generation),
            Action::Delete => { self.delete(); if self.record.state == "deleted" { Ok(Outcome::Sandbox(self.record.view())) } else { Err("cleanup_failed") } }
        }
    }
    // Remove the sandbox's owned resources and mark it deleted, or retain a cleanup failure.
    fn delete(&mut self) {
        let result = self.native.cleanup(&self.record.request.sandbox_id);
        self.record.state = if result.is_ok() { "deleted" } else { "cleanup_failed" }.into();
        if let Err(e) = result { self.record.error = Some(e.into()); }
    }
    // Verify the template, wait for its shared lower mount, then prepare and start or restore the
    // sandbox. On failure, clean up and record it as failed (or cleanup_failed).
    fn create(&mut self) -> Result<Outcome> {
        let result = (|| -> Result<()> {
            self.active()?;
            let manifest = self.native.template(&self.record.request.template_id)?;
            self.record.network_policy = Some(manifest.network.clone());
            let (tx, rx) = mpsc::channel();
            self.lowers.send(Lower { manifest: manifest.clone(), done: tx }).map_err(|_| "lower_worker_unavailable")?;
            rx.recv().map_err(|_| "lower_worker_unavailable")??;
            self.active()?;
            self.native.prepare(&self.record.request, &manifest, self.record.network_slot, self.record.expires_at, &self.cancelled)
        })();
        match result {
            Ok(()) => { self.record.state = "running".into(); Ok(Outcome::Created(self.record.view())) }
            Err(e) => {
                self.delete();
                if self.record.state == "deleted" { self.record.state = "failed".into(); self.record.error = Some(e.into()); }
                Err(e)
            }
        }
    }
    // Run one command with runc exec in the sandbox's exec cgroup, bounded by its timeout (capped by
    // the remaining TTL) and output limit, then kill and remove that cgroup. A bound violation or any
    // error deletes the whole sandbox.
    fn exec(&mut self, request: ExecRequest) -> Result<Outcome> {
        let id = self.record.request.sandbox_id.clone();
        let file = self.native.private(&id).join("exec.json");
        let result = self.active().and_then(|_| self.native.create_exec_cgroup(&id))
            .and_then(|_| process::atomic_json(&file, &self.native.process_spec(request.argv))).and_then(|_| {
            let remaining = self.record.expires_at.saturating_sub(now()).saturating_mul(1000);
            self.native.runc(vec!["exec".into(), "--cgroup".into(), crate::native::EXEC_CGROUP.into(), "--process".into(), file.display().to_string(), id.clone()], Duration::from_millis(request.timeout_ms.min(remaining.max(1))), request.max_output_bytes as usize)
        });
        let _ = fs::remove_file(&file);
        let cleanup = self.native.cleanup_exec_cgroup(&id);
        match result.and_then(|output| cleanup.map(|_| output)) {
            Ok(output) => {
                // A bound violation terminates the whole sandbox, never only the runc client.
                let error = output.interrupted.then_some("exec_deadline_or_output_limit");
                if output.interrupted { self.delete(); }
                Ok(Outcome::Exec(ExecResult { exit_code: output.exit_code, stdout: output.stdout, stderr: output.stderr,
                    interrupted: output.interrupted, error, sandbox_state: self.record.state.clone() }))
            }
            Err(e) => { self.delete(); Err(e) }
        }
    }
    // Make one application HTTP call to the sandbox under its template network policy, capped by the
    // remaining TTL. A failure fails only this call, not the sandbox.
    fn http(&mut self, request: HttpRequest) -> Result<Outcome> {
        let policy = self.active().and_then(|_| self.record.network_policy.as_ref().ok_or("network_policy_unavailable"))?;
        self.native.application_http(&self.record.request.sandbox_id, &request, policy, self.record.expires_at.saturating_sub(now()).saturating_mul(1000)).map(Outcome::Http)
    }
    // Check that the source is still active, remove stopped runtime state and restore its captured
    // processes.
    fn recover(&self, images: &Path) -> Result<()> {
        self.active()?;
        self.native.forget_stopped(&self.record.request.sandbox_id)?;
        self.native.restore_source(&self.record.request, images, self.record.expires_at, &self.cancelled)
    }
    // Capture a running sandbox as a new warm template: require no active TCP, checkpoint and stop the
    // source, archive its upper layer and process images, write the manifest, restore the source and
    // publish the template. Delete the source if it cannot be recovered; succeed only if both
    // publication and recovery did.
    fn capture(&mut self, request: CaptureRequest, generation: String) -> Result<Outcome> {
        let id = self.record.request.sandbox_id.clone();
        // The admission coordinator reserves the template name among in-flight
        // captures, so this exclusively created leaf is unique to this job.
        let stage = self.native.root().join("staging").join(&request.template_id);
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
            self.native.capture_network_ready(&id, self.record.network_policy.as_ref())?;
            checkpoint_attempted = true;
            self.native.checkpoint(&id, &images)?;
            checkpoint_completed = true;
            stopped = true;
            storage::archive(self.native.tool("tar")?, &self.native.private(&id).join("upper"), &stage.join("upper.tar"), self.native.config.command_timeout_seconds, &self.native.search_path, &self.native.helpers)?;
            storage::archive(self.native.tool("tar")?, &images, &stage.join("checkpoint.tar"), self.native.config.command_timeout_seconds, &self.native.search_path, &self.native.helpers)?;
            manifest.template_id = request.template_id.clone(); manifest.generation = generation.clone();
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
        // Success means both publication and verified source recovery.
        result.and(recovery).and(cleanup).map(|_| Outcome::Captured(CaptureResult {
            sandbox_id: id, template_id: request.template_id, generation, state: self.record.state.clone() }))
    }
}
