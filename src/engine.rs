//! Serialized durable admission/state transitions, bounded parallel runtime I/O.
//! Each sandbox has at most one in-flight create, capture or delete job, which
//! excludes commands; several commands (execs) may run at once, each on its own
//! thread and in its own resource group. A management request waits on a reply for
//! the real outcome, but never owns the work: if the client disconnects or its wait
//! expires, the job or command still runs to a terminal state with normal cleanup
//! and its reply is discarded. An undeliverable create reply instead deletes the new
//! sandbox (`create_response_lost`); a reply lost after hand-over is bounded by TTL.
use std::{collections::{BTreeMap, BTreeSet}, fs, path::Path, sync::{Arc, RwLock, mpsc, atomic::{AtomicBool, AtomicU8, Ordering}}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use serde::{Deserialize, Serialize};
use crate::{config::{ProxyLimits, WorkerConfig}, model::{CaptureRequest, CreateRequest, ExecRequest, Runtime, RuntimeCapability, SandboxSpec, Usage, WorkerStatus}, native::{ExecEnd, Native, Preflight}, process::{self, Result}, storage};

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
pub struct CaptureResult { pub sandbox_id: String, pub template_id: String, pub generation: String, pub state: String }
#[derive(Serialize)]
pub struct KillResult { pub sandbox_id: String, pub exec_id: u64, pub state: &'static str }
pub enum Outcome { Created(SandboxView), Sandbox(SandboxView), Captured(CaptureResult), Killed(KillResult) }
pub type Reply = tokio::sync::oneshot::Sender<Result<Outcome>>;
// One event of a running command, in order: output chunks as they arrive, then how it ended.
pub enum ExecEvent { Stdout(Vec<u8>), Stderr(Vec<u8>), End(ExecEnd) }
// Where an exec request hears back: its exec ID (or why it was refused), then its events. Events are
// unbounded but each command's output is capped by its max_output_bytes.
pub struct ExecSink { pub started: tokio::sync::oneshot::Sender<Result<u64>>, pub events: tokio::sync::mpsc::UnboundedSender<ExecEvent> }

pub struct Snapshot {
    pub status: WorkerStatus,
    pub records: BTreeMap<String, Arc<Record>>,
    cancels: BTreeMap<String, Arc<AtomicBool>>,
    // Close signal per sandbox with proxied app traffic: dropping the sender (when deletion starts or
    // the sandbox stops running) ends its open proxy exchanges.
    pub proxy_close: BTreeMap<String, tokio::sync::watch::Sender<()>>,
}
#[derive(Clone)]
pub struct Handle {
    pub snapshot: Arc<RwLock<Snapshot>>, pub preflight: Preflight, pub sender: Option<mpsc::SyncSender<Work>>,
    pub deadlines: crate::config::OperationDeadlines, pub native: Option<Arc<Native>>,
    pub proxy: ProxyLimits, pub proxy_permits: Arc<tokio::sync::Semaphore>,
}
pub enum Work {
    Create(CreateRequest, Reply), Exec(String, ExecRequest, ExecSink), Kill(String, u64, Reply), Capture(String, CaptureRequest, Reply), Delete(String, Reply),
    Complete(usize, Box<(Record, Result<Outcome>)>), ExecDone(String, u64, bool), Exited(String), Stop(mpsc::Sender<Result<()>>),
}
enum Action { Create, Capture(CaptureRequest, String), Delete }
// A running command: why it must stop (0 not, 1 killed by request, 2 sandbox deleted or expired) and
// the kill requests waiting for it to end.
struct RunningExec { stop: Arc<AtomicU8>, kill_waiters: Vec<Reply> }
struct Job { record: Record, action: Action, cancelled: Arc<AtomicBool> }
// One in-flight job of a sandbox: its operation worker slot, whether it holds a restore slot (create
// or capture), whether it is the delete cleanup (which has no reply of its own; waiting DELETEs are
// answered when it completes), the template name a capture reserves, its cancel flag and its reply.
struct Flight { slot: usize, restore: bool, delete: bool, template: Option<String>, cancelled: Arc<AtomicBool>, reply: Option<Reply> }
// Mount these shared layers, already verified by the create job: a template's sealed layers and its
// base.
struct Lower { layers: Vec<storage::Artifact>, done: mpsc::Sender<Result<()>> }
// Concurrent DELETE requests waiting for one sandbox's cleanup (and kill requests waiting for one
// command's end); more are refused as busy.
const MAX_DELETE_WAITERS: usize = 64;
const STOP_KILLED: u8 = 1;
const STOP_SANDBOX: u8 = 2;
// Return seconds since the Unix epoch, falling back to zero if the clock is earlier.
pub fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }
// Hash a value's serialized form; used to stamp the template network policy into the saved
// execution specification.
pub fn fingerprint<T: Serialize>(input: &T) -> String { storage::digest(&serde_json::to_vec(input).expect("serialize validated input")) }
// Send a result to a waiting request, if any, ignoring a requester that already gave up.
fn answer(reply: Option<Reply>, result: Result<Outcome>) { if let Some(reply) = reply { let _ = reply.send(result); } }

impl Handle {
    // Return an unavailable handle if the runtime is disabled or preflight fails. Otherwise reconcile
    // durable state (rebuilding the network slot pool), then start the lower-mount thread, operation
    // workers, admission and expiry/exit monitoring; jobs and commands continue independently of HTTP
    // connections. Shutdown waits for jobs, commands and one cleanup per sandbox, then removes shared
    // mounts and the slot pool.
    pub fn start(config: &WorkerConfig, report: Preflight) -> Result<Self> {
        let enabled = config.native.as_ref().is_some_and(|c| c.enabled) && report.ready;
        let status = WorkerStatus { schema_version: 1, node_id: config.node_id.clone(), architecture: std::env::consts::ARCH.to_owned(), os: std::env::consts::OS.to_owned(),
            capacity: config.capacity.clone(), usage: enabled.then_some(Usage { memory_mib: 0, vcpus: 0, sandboxes: 0, restores: 0 }), admission_ready: false,
            runtimes: vec![RuntimeCapability { runtime: Runtime::RuncCriu, ready: false, reason: if enabled { "reconciling" } else if config.native.as_ref().is_some_and(|c| c.enabled) { "preflight_failed" } else { "runtime_disabled" }.into() }],
            cpu_overcommit: config.native.as_ref().map_or(1, |c| c.cpu_overcommit), qualification: "unvalidated".into() };
        let snapshot = Arc::new(RwLock::new(Snapshot { status, records: BTreeMap::new(), cancels: BTreeMap::new(), proxy_close: BTreeMap::new() }));
        let proxy_permits = Arc::new(tokio::sync::Semaphore::new(config.server.proxy.max_connections));
        let handle = |sender, native| Self { snapshot: snapshot.clone(), preflight: report.clone(), sender, deadlines: config.server.operation_deadlines.clone(),
            native, proxy: config.server.proxy.clone(), proxy_permits: proxy_permits.clone() };
        if !enabled { return Ok(handle(None, None)); }
        let native = Arc::new(Native::open(config.native.clone().ok_or("native_config_missing")?, report.clone())?);
        let (tx, rx) = mpsc::sync_channel(32);
        let mut engine = Engine { native: native.clone(), snapshot: snapshot.clone(), records: BTreeMap::new(), healthy: true,
            pool: Vec::new(), flights: BTreeMap::new(), delete_waiters: BTreeMap::new(), retry_after: BTreeMap::new(), stopping: None, stop_attempted: BTreeSet::new(),
            execs: BTreeMap::new(), next_exec: 0, events: tx.clone() };
        engine.reconcile()?;
        let restored = engine.records.iter().map(|(id, r)| (id.clone(), Arc::new(r.clone()))).collect();
        snapshot.write().expect("snapshot poisoned").records = restored;
        // Shared lower creation is serialized by its own bounded mailbox, never
        // by holding a lock over mount I/O or blocking the admission authority.
        // Hashing never happens here: create jobs verify layers before sending.
        let (lower_tx, lower_rx) = mpsc::sync_channel::<Lower>(native.config.max_concurrent_operations);
        let lower_native = native.clone();
        std::thread::Builder::new().name("sandbox-lowers".into()).spawn(move || {
            while let Ok(job) = lower_rx.recv() { let _ = job.done.send(job.layers.iter().try_for_each(|layer| lower_native.mount_lower(layer))); }
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
                    Ok(Work::ExecDone(id, exec, cleanup_failed)) => engine.exec_done(&id, exec, cleanup_failed),
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
                if engine.stopping.is_some() && engine.flights.is_empty() && engine.execs.is_empty()
                    && engine.records.iter().all(|(id, r)| !r.reserved() || engine.stop_attempted.contains(id)) {
                    let cleanup = if !engine.records.values().any(Record::reserved) {
                        engine.native.unmount_lowers().and_then(|_| engine.native.remove_slot_pool()).and_then(|_| engine.native.remove_helpers())
                    } else { Err("private_cleanup_failed") };
                    let durable = process::atomic_json(&engine.native.root().join("worker-status.json"), &serde_json::json!({"cleanup_error":cleanup.err()}));
                    let _ = engine.stopping.take().unwrap().send(cleanup.and(durable));
                    break;
                }
            }
            watchdog_stop.store(true, Ordering::Relaxed);
        }).map_err(|_| "admission_thread_failed")?;
        Ok(handle(Some(tx), Some(native)))
    }
}

struct Engine {
    native: Arc<Native>, snapshot: Arc<RwLock<Snapshot>>, records: BTreeMap<String, Record>, healthy: bool,
    pool: Vec<mpsc::SyncSender<Job>>, flights: BTreeMap<String, Flight>,
    // Waiting DELETE requests per sandbox; all get the result of the one cleanup (AgentENV pattern).
    delete_waiters: BTreeMap<String, Vec<Reply>>, retry_after: BTreeMap<String, Instant>,
    stopping: Option<mpsc::Sender<Result<()>>>, stop_attempted: BTreeSet<String>,
    // Running commands per sandbox (no empty entries), the last exec ID and this loop's own mailbox,
    // which exec threads use to report that they ended.
    execs: BTreeMap<String, BTreeMap<u64, RunningExec>>, next_exec: u64, events: mpsc::SyncSender<Work>,
}
impl Engine {
    // Persist a sandbox record and refresh its public snapshot. A sandbox that is no longer running
    // (or capturing) or whose deletion was requested loses its proxy close signal, which ends its open
    // proxy exchanges. A save failure closes admission, even though the in-memory view is still updated.
    fn save(&mut self, id: &str) -> Result<()> {
        let result = process::atomic_json(&self.native.root().join("records").join(format!("{id}.json")), &self.records[id]);
        if result.is_err() { self.healthy = false; }
        let record = Arc::new(self.records[id].clone());
        {
            let mut snapshot = self.snapshot.write().expect("snapshot poisoned");
            if record.delete_requested || !matches!(record.state.as_str(), "running" | "capturing") { snapshot.proxy_close.remove(id); }
            snapshot.records.insert(id.into(), record);
        }
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
    // delete has no reply of its own: waiting DELETE requests are answered when it completes. If the
    // worker cannot take the job, mark the sandbox cleanup_failed, close admission and fail the reply.
    fn launch(&mut self, id: &str, action: Action, slot: usize, reply: Option<Reply>) {
        let restore = matches!(action, Action::Create | Action::Capture(..));
        let delete = matches!(action, Action::Delete);
        let template = match &action { Action::Capture(r, _) => Some(r.template_id.clone()), _ => None };
        let cancelled = Arc::new(AtomicBool::new(false));
        self.flights.insert(id.into(), Flight { slot, restore, delete, template, cancelled: cancelled.clone(), reply });
        self.snapshot.write().expect("snapshot poisoned").cancels.insert(id.into(), cancelled.clone());
        if self.pool[slot].try_send(Job { record: self.records[id].clone(), action, cancelled }).is_err() {
            self.healthy = false;
            let flight = self.flights.remove(id);
            self.snapshot.write().expect("snapshot poisoned").cancels.remove(id);
            self.records.get_mut(id).unwrap().state = "cleanup_failed".into();
            self.records.get_mut(id).unwrap().error = Some("operation_worker_unavailable".into());
            let _ = self.save(id);
            answer(flight.and_then(|f| f.reply), Err("operation_worker_unavailable"));
            if delete { for waiter in self.delete_waiters.remove(id).unwrap_or_default() { answer(Some(waiter), Err("operation_worker_unavailable")); } }
        }
        self.publish();
    }
    // Save a finished job's record, turning it into a pending delete if deletion, expiry or ill health
    // arrived meanwhile, and deliver its outcome with the current state. Answer every waiting DELETE
    // once the sandbox is gone, or with the failure of a delete job, and delete a new sandbox whose
    // create reply could not be delivered.
    fn complete(&mut self, slot: usize, mut record: Record, outcome: Result<Outcome>) {
        if self.native.helpers.ensure_healthy().is_err() { self.healthy = false; }
        let id = record.request.sandbox_id.clone();
        if !self.flights.get(&id).is_some_and(|f| f.slot == slot) { self.healthy = false; self.publish(); return; }
        let mut flight = self.flights.remove(&id).unwrap();
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
            Ok(Outcome::Captured(mut result)) => { result.state = record.state.clone(); Ok(Outcome::Captured(result)) }
            other => other,
        };
        let created = matches!(outcome, Ok(Outcome::Created(_)));
        let delivered = flight.reply.take().is_some_and(|reply| reply.send(outcome).is_ok());
        if !record.reserved() || flight.delete {
            for waiter in self.delete_waiters.remove(&id).unwrap_or_default() {
                answer(Some(waiter), if record.reserved() { Err("cleanup_failed") } else { Ok(Outcome::Sandbox(record.view())) });
            }
        }
        // Nobody can learn a controller-generated ID whose create reply was lost
        // (client disconnect, expired wait): delete it instead of holding capacity
        // until TTL. Other outcomes are just discarded; their sandboxes stay known.
        if created && !delivered {
            self.records.get_mut(&id).unwrap().error = Some("create_response_lost".into());
            self.request_delete(&id, None);
        }
    }
    // Route submitted work to admission, command control or deletion after checking helper health.
    // Unhealthy workers reject new work but still accept deletion and kill requests.
    fn accept(&mut self, work: Work) {
        if self.native.helpers.ensure_healthy().is_err() { self.healthy = false; self.publish(); }
        match work {
            Work::Delete(id, reply) => self.request_delete(&id, Some(reply)),
            Work::Kill(id, exec, reply) => self.kill(&id, exec, reply),
            Work::Create(r, reply) => { if self.healthy { self.create(r, reply); } else { let _ = reply.send(Err("worker_unavailable")); } },
            Work::Exec(id, r, sink) => { if self.healthy { self.exec(id, r, sink); } else { let _ = sink.started.send(Err("worker_unavailable")); } },
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
        // place the create elsewhere. The job hashes each layer image once per node
        // (first use, kept across restarts while the file is unchanged) and each
        // checkpoint archive once (first unpack).
        let Ok((manifest, _)) = self.native.template_manifest(&request.template_id) else { let _ = reply.send(Err("template_unavailable")); return; };
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
    // Start a capture on a running sandbox, rejecting it at once if the sandbox is missing, busy (a job
    // or a command is running), not running or no slot is free. A capture also needs a restore slot
    // and an unused template name, and is saved as capturing first.
    fn operation(&mut self, id: &str, action: Action, reply: Reply) {
        let Some(record) = self.records.get(id) else { let _ = reply.send(Err("sandbox_not_found")); return; };
        // Conflicting same-sandbox work is rejected immediately, never queued. Commands hold pipes to the
        // host, which a checkpoint cannot capture.
        if self.flights.contains_key(id) || self.execs.contains_key(id) || self.delete_waiters.get(id).is_some_and(|w| !w.is_empty()) { let _ = reply.send(Err("sandbox_busy")); return; }
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
    // Admit a command into a running sandbox and start it on its own thread, outside the operation
    // pool. Refuse it at once if the sandbox is missing, not running, or has a create, capture or delete
    // in flight, or if the per-sandbox or worker command limit is reached. The thread streams events to
    // the requester and reports its end here.
    fn exec(&mut self, id: String, request: ExecRequest, sink: ExecSink) {
        let ExecSink { started, events } = sink;
        let _ = started.send(self.start_exec(id, request, events));
    }
    // Check exec admission and spawn the command's thread (see exec); return its exec ID or the refusal.
    fn start_exec(&mut self, id: String, request: ExecRequest, events: tokio::sync::mpsc::UnboundedSender<ExecEvent>) -> Result<u64> {
        let record = self.records.get(&id).ok_or("sandbox_not_found")?;
        if self.flights.contains_key(&id) || self.delete_waiters.get(&id).is_some_and(|w| !w.is_empty()) { return Err("sandbox_busy"); }
        if record.state != "running" || record.expires_at <= now() || record.delete_requested { return Err("sandbox_not_running"); }
        if self.execs.get(&id).map_or(0, BTreeMap::len) >= self.native.config.max_execs_per_sandbox { return Err("exec_limit"); }
        if self.execs.values().map(BTreeMap::len).sum::<usize>() >= self.native.config.max_concurrent_execs { return Err("busy"); }
        let exec = self.next_exec + 1;
        let stop = Arc::new(AtomicU8::new(0));
        let (native, done, flag, sandbox, expires_at) = (self.native.clone(), self.events.clone(), stop.clone(), id.clone(), record.expires_at);
        let spawned = std::thread::Builder::new().name(format!("sandbox-exec-{exec}")).spawn(move || {
            // The deadline is the command's timeout, capped by the remaining TTL.
            let remaining = expires_at.saturating_sub(now()).saturating_mul(1000);
            let timeout = Duration::from_millis(request.timeout_ms.min(remaining.max(1)));
            let reason = || match flag.load(Ordering::Relaxed) {
                STOP_KILLED => Some("exec_killed"),
                STOP_SANDBOX => Some("sandbox_cancelled_or_expired"),
                _ => (expires_at <= now()).then_some("sandbox_cancelled_or_expired"),
            };
            let mut sink = |stderr: bool, bytes: &[u8]| { let _ = events.send(if stderr { ExecEvent::Stderr(bytes.to_vec()) } else { ExecEvent::Stdout(bytes.to_vec()) }); };
            let end = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| native.exec(&sandbox, exec, request.argv, timeout, request.max_output_bytes as usize, &mut sink, &reason)))
                .unwrap_or(ExecEnd { exit_code: None, interrupted: false, error: Some("exec_worker_panicked"), cleanup_failed: true });
            let cleanup_failed = end.cleanup_failed;
            let _ = events.send(ExecEvent::End(end));
            let _ = done.send(Work::ExecDone(sandbox, exec, cleanup_failed));
        });
        spawned.map_err(|_| "busy")?;
        self.next_exec = exec;
        self.execs.entry(id).or_default().insert(exec, RunningExec { stop, kill_waiters: Vec::new() });
        Ok(exec)
    }
    // Ask one running command to stop; the reply waits until it has ended and its group is gone (up to
    // MAX_DELETE_WAITERS waiting requests). An unknown or finished command is exec_not_found.
    fn kill(&mut self, id: &str, exec: u64, reply: Reply) {
        let Some(running) = self.execs.get_mut(id).and_then(|commands| commands.get_mut(&exec)) else {
            let _ = reply.send(Err(if self.records.contains_key(id) { "exec_not_found" } else { "sandbox_not_found" }));
            return;
        };
        let _ = running.stop.compare_exchange(0, STOP_KILLED, Ordering::Relaxed, Ordering::Relaxed);
        running.kill_waiters.retain(|waiter| !waiter.is_closed());
        if running.kill_waiters.len() >= MAX_DELETE_WAITERS { let _ = reply.send(Err("waiter_limit")); return; }
        running.kill_waiters.push(reply);
    }
    // Forget a finished command and answer the kill requests waiting for it. A command whose resource
    // group could not be emptied may have left processes behind, so its sandbox is deleted.
    fn exec_done(&mut self, id: &str, exec: u64, cleanup_failed: bool) {
        if let Some(commands) = self.execs.get_mut(id) {
            if let Some(running) = commands.remove(&exec) {
                for waiter in running.kill_waiters {
                    answer(Some(waiter), Ok(Outcome::Killed(KillResult { sandbox_id: id.into(), exec_id: exec, state: "exited" })));
                }
            }
            if commands.is_empty() { self.execs.remove(id); }
        }
        if cleanup_failed && self.records.get(id).is_some_and(Record::reserved) {
            self.records.get_mut(id).unwrap().error = Some("exec_cleanup_failed".into());
            self.request_delete(id, None);
        }
    }
    // Mark a sandbox for deletion and cancel its in-flight job and running commands; maintenance
    // launches the cleanup once they have ended. An already gone sandbox is answered at once. Every
    // concurrent DELETE waits for the same cleanup and gets its result (up to MAX_DELETE_WAITERS;
    // abandoned waits are dropped first).
    fn request_delete(&mut self, id: &str, reply: Option<Reply>) {
        let Some(record) = self.records.get_mut(id) else { answer(reply, Err("sandbox_not_found")); return; };
        if !record.reserved() { let view = record.view(); answer(reply, Ok(Outcome::Sandbox(view))); return; }
        if let Some(reply) = reply {
            let waiters = self.delete_waiters.entry(id.into()).or_default();
            waiters.retain(|waiter| !waiter.is_closed());
            if waiters.len() >= MAX_DELETE_WAITERS { let _ = reply.send(Err("waiter_limit")); return; }
            waiters.push(reply);
            self.retry_after.remove(id);
        }
        if let Some(f) = self.flights.get(id) { f.cancelled.store(true, Ordering::Relaxed); }
        for running in self.execs.get(id).into_iter().flat_map(BTreeMap::values) {
            let _ = running.stop.compare_exchange(0, STOP_SANDBOX, Ordering::Relaxed, Ordering::Relaxed);
        }
        let record = self.records.get_mut(id).unwrap();
        if !record.delete_requested {
            record.delete_requested = true; record.state = "deleting".into();
            let _ = self.save(id);
        }
    }
    // Arrange deletion for expired, cancelled or unhealthy sandboxes and retry failed cleanup. Wait for
    // active jobs, running commands and available slots; shutdown attempts each remaining cleanup once.
    fn maintenance(&mut self) {
        let ids: Vec<_> = self.records.iter().filter(|(_, r)| r.reserved() && (!self.healthy || r.expires_at <= now() || r.delete_requested || r.state == "cleanup_failed"))
            .map(|(id, _)| id.clone()).collect();
        for id in ids {
            if !self.records[&id].delete_requested { self.request_delete(&id, None); }
            if self.flights.contains_key(&id) || self.execs.contains_key(&id) { continue; }
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
    // sandbox left from before the restart and remove abandoned staging. Release unused lower mounts,
    // replace the network slot pool with freshly built slots and save cleanup status; durability or
    // slot-removal failures prevent startup.
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
                let cleanup = self.native.cleanup(&id, self.records[&id].network_slot);
                let r = self.records.get_mut(&id).unwrap();
                r.state = if cleanup.is_ok() { "deleted" } else { "cleanup_failed" }.into(); r.error = cleanup.err().map(str::to_owned);
                let _ = self.save(&id);
            }
        }
        if !self.records.values().any(Record::reserved) { self.native.unmount_lowers()?; }
        for entry in fs::read_dir(self.native.root().join("staging")).map_err(|_| "staging_scan_failed")? { storage::remove_private(&entry.map_err(|_| "staging_scan_failed")?.path())?; }
        // Pre-create the slots admission can hand out (it picks the lowest free index).
        let held = self.records.values().filter(|r| r.reserved()).filter_map(|r| r.network_slot).collect();
        let count = self.snapshot.read().expect("snapshot poisoned").status.capacity.max_sandboxes as usize;
        self.native.start_slot_pool(count, &held)?;
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
            Action::Create => self.create(), Action::Capture(r, generation) => self.capture(r, generation),
            Action::Delete => { self.delete(); if self.record.state == "deleted" { Ok(Outcome::Sandbox(self.record.view())) } else { Err("cleanup_failed") } }
        }
    }
    // Remove the sandbox's owned resources (returning its network slot to the pool) and mark it
    // deleted, or retain a cleanup failure.
    fn delete(&mut self) {
        let result = self.native.cleanup(&self.record.request.sandbox_id, self.record.network_slot);
        self.record.state = if result.is_ok() { "deleted" } else { "cleanup_failed" }.into();
        if let Err(e) = result { self.record.error = Some(e.into()); }
    }
    // Check the template manifest, verify its layer images here (hashing only those not yet trusted on
    // this node), wait for their shared mounts, take the node's cached checkpoint images of a warm
    // template (unpacked once per manifest digest), then prepare and start or restore the sandbox. On
    // failure, clean up and record it as failed (or cleanup_failed).
    fn create(&mut self) -> Result<Outcome> {
        let result = (|| -> Result<()> {
            self.active()?;
            let (manifest, digest) = self.native.template_manifest(&self.record.request.template_id)?;
            self.record.network_policy = Some(manifest.network.clone());
            let (tx, rx) = mpsc::channel();
            let layers: Vec<_> = manifest.layers.iter().chain(std::iter::once(&manifest.base)).cloned().collect();
            self.native.verify_layers(&layers)?;
            self.active()?;
            self.lowers.send(Lower { layers, done: tx }).map_err(|_| "lower_worker_unavailable")?;
            rx.recv().map_err(|_| "lower_worker_unavailable")??;
            self.active()?;
            let images = if manifest.checkpoint.is_some() { Some(self.native.checkpoint_images(&manifest, &digest)?) } else { None };
            self.active()?;
            self.native.prepare(&self.record.request, &manifest, images.as_deref(), self.record.network_slot, self.record.expires_at, &self.cancelled)
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
    // Capture a running sandbox as a new warm template without stopping it (AgentENV order): freeze it,
    // flush and seal its upper directory into an EROFS layer, checkpoint it with CRIU leaving it running,
    // then thaw it. Afterwards archive the images, write the manifest and publish the layer and template.
    // On an ordinary failure thaw the source and keep it if it runs; a source that stays frozen or was
    // cancelled is deleted, and so is one whose dump was interrupted at its deadline (its state is
    // uncertain). Success means publication and a running source.
    fn capture(&mut self, request: CaptureRequest, generation: String) -> Result<Outcome> {
        let id = self.record.request.sandbox_id.clone();
        let max = self.native.config.max_artifact_bytes;
        // The admission coordinator reserves the template name among in-flight
        // captures, so this exclusively created leaf is unique to this job.
        let stage = self.native.root().join("staging").join(&request.template_id);
        let mut stage_owned = false;
        let destination = self.native.root().join("templates").join(&request.template_id);
        let mut paused = false;
        let result = (|| -> Result<()> {
            self.active()?;
            if destination.exists() { return Err("template_already_exists"); }
            let (mut manifest, _) = self.native.template_manifest(&self.record.request.template_id)?;
            if manifest.layers.len() >= storage::MAX_LAYERS { return Err("template_layer_limit"); }
            storage::exclusive_private_dir(&stage)?;
            stage_owned = true;
            let images = stage.join("images"); storage::private_dir(&images)?;
            let sealed = stage.join("layer.erofs");
            // Frozen window: the sealed files and the process images describe one instant.
            paused = true;
            self.native.pause(&id)?;
            let uprobes = self.native.uprobes_present(&id)?;
            self.native.seal_upper(&id, &sealed)?;
            self.native.checkpoint(&id, &images, uprobes)?;
            self.native.resume(&id)?;
            paused = false;
            let layer = storage::artifact(&sealed, max)?;
            storage::archive(self.native.tool("tar")?, &images, &stage.join("checkpoint.tar"), self.native.config.command_timeout_seconds, &self.native.search_path, &self.native.helpers)?;
            manifest.template_id = request.template_id.clone(); manifest.generation = generation.clone();
            manifest.layers.insert(0, layer.clone());
            manifest.checkpoint = Some(storage::artifact(&stage.join("checkpoint.tar"), max)?);
            manifest.memory_mib = Some(self.record.request.memory_mib); manifest.vcpus = Some(self.record.request.vcpus);
            manifest.oci_config_sha256 = Some(self.native.spec_digest(&id)?);
            storage::write_manifest(&stage, &manifest)?;
            storage::remove_private(&images)?;
            self.active()?;
            // Content-addressed and hashed just above: restores never rehash it on this node.
            storage::publish_layer(&sealed, &self.native.root().join("layers"), &layer, max)?;
            self.native.mark_verified(&layer)?;
            fs::File::open(&stage).and_then(|f| f.sync_all()).map_err(|_| "template_sync_failed")?;
            fs::rename(&stage, &destination).map_err(|_| "template_publish_failed")?;
            stage_owned = false;
            fs::File::open(destination.parent().ok_or("invalid_template_path")?).and_then(|f| f.sync_all()).map_err(|_| "template_sync_failed")?;
            Ok(())
        })();
        // CRIU leaves the dumped tasks alive, so a failed step needs only a thaw. A
        // resume error is not final: runc state decides (a paused source is not running).
        // A dump killed midway may leave CRIU's network lock, repaired sockets or
        // parasite code behind, so that source is deleted even if it runs.
        if paused { let _ = self.native.resume(&id); }
        let recovery = if matches!(result, Err("checkpoint_interrupted")) { Err("checkpoint_interrupted") }
            else { self.active().and_then(|_| self.native.ensure_running(&id)) };
        if recovery.is_ok() { self.record.state = "running".into(); } else {
            if recovery == Err("checkpoint_interrupted") { self.record.error = Some("checkpoint_interrupted".into()); }
            self.delete();
        }
        let cleanup = if stage_owned { self.native.helpers.ensure_healthy().and_then(|_| storage::remove_private(&stage)) } else { Ok(()) };
        // Success means both publication and a running source.
        result.and(recovery).and(cleanup).map(|_| Outcome::Captured(CaptureResult {
            sandbox_id: id, template_id: request.template_id, generation, state: self.record.state.clone() }))
    }
}
