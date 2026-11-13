//! Per-operation phase timings. Every create, restore, delete, capture and exec yields one structured
//! worker log line with the duration of each of its steps, and adds them to cumulative histograms in
//! the authenticated worker status. Phase names are fixed strings in the code, so the histogram set
//! is bounded.
use std::{collections::BTreeMap, time::Instant};
use serde::{Deserialize, Serialize};

// Upper bounds, in milliseconds, of the histogram buckets; one more bucket counts everything slower.
pub const BUCKETS_MS: [u64; 14] = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1_000, 2_000, 5_000, 10_000, 60_000];
// Most histograms a status may carry (operations times their phases, with room to spare).
pub const MAX_HISTOGRAMS: usize = 160;

// The steps of one operation so far: when it started, when the last step ended, and each step's name
// and duration in microseconds, in order.
pub struct Phases { started: Instant, last: Instant, spans: Vec<(&'static str, u64)> }
impl Phases {
    // Start timing an operation that began at `started` (for example when its request arrived).
    pub fn since(started: Instant) -> Self { Self { started, last: started, spans: Vec::new() } }
    // Record the time since the previous step ended (or the operation started) as step `name`.
    pub fn mark(&mut self, name: &'static str) {
        let now = Instant::now();
        self.spans.push((name, now.duration_since(self.last).as_micros() as u64));
        self.last = now;
    }
    // Record elapsed time to the first confirmed running result; this is not an application health probe.
    pub fn first_ready(&mut self) { self.spans.push(("first_ready", self.total_us())); }
    // Return the microseconds from the start of the operation until now.
    pub fn total_us(&self) -> u64 { self.started.elapsed().as_micros() as u64 }
    // Return the recorded steps in order (name and microseconds).
    pub fn spans(&self) -> &[(&'static str, u64)] { &self.spans }
    // Format the worker log line for a finished operation: its kind, sandbox, result (`ok` or the
    // error code), total and per-step milliseconds. Holds no credentials, arguments or paths.
    pub fn log_line(&self, operation: &str, sandbox: &str, result: Result<(), &str>) -> String {
        let ms = |us: u64| serde_json::Number::from_f64(us as f64 / 1000.0).map_or(serde_json::Value::Null, serde_json::Value::Number);
        // A step repeated within one operation (a retry) is summed.
        let mut sums = BTreeMap::<&str, u64>::new();
        for (name, us) in &self.spans { *sums.entry(name).or_default() += us; }
        let steps: serde_json::Map<String, serde_json::Value> = sums.into_iter().map(|(name, us)| (name.to_owned(), ms(us))).collect();
        let line = serde_json::json!({"op": operation, "sandbox_id": sandbox, "result": result.err().unwrap_or("ok"),
            "total_ms": ms(self.total_us()), "phases": steps});
        format!("sandboxd: phases {line}")
    }
}

// Cumulative distribution of one step's durations: how many, their total and largest milliseconds,
// and the count per bucket of BUCKETS_MS (the last bucket counts everything slower).
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Histogram { pub count: u64, pub total_ms: f64, pub max_ms: f64, pub buckets: Vec<u64> }
impl Histogram {
    // Start an empty histogram.
    fn new() -> Self { Self { count: 0, total_ms: 0.0, max_ms: 0.0, buckets: vec![0; BUCKETS_MS.len() + 1] } }
    // Count one duration given in microseconds.
    fn add(&mut self, us: u64) {
        let ms = us as f64 / 1000.0;
        self.count += 1;
        self.total_ms += ms;
        self.max_ms = self.max_ms.max(ms);
        let bucket = BUCKETS_MS.iter().position(|bound| us <= bound * 1000).unwrap_or(BUCKETS_MS.len());
        self.buckets[bucket] += 1;
    }
    // Check the bucket count and that the numbers are finite and not negative.
    pub fn valid(&self) -> bool {
        self.buckets.len() == BUCKETS_MS.len() + 1 && self.total_ms.is_finite() && self.total_ms >= 0.0 && self.max_ms.is_finite() && self.max_ms >= 0.0
    }
}

// Add one finished operation's steps, and its total as step `total`, to the histograms keyed
// `<operation>.<step>`. Keys are fixed names from the code; past MAX_HISTOGRAMS new keys are dropped.
pub fn record(histograms: &mut BTreeMap<String, Histogram>, operation: &str, phases: &Phases) {
    let total = phases.total_us();
    for (name, us) in phases.spans().iter().copied().chain(std::iter::once(("total", total))) {
        let key = format!("{operation}.{name}");
        if !histograms.contains_key(&key) && histograms.len() >= MAX_HISTOGRAMS { continue; }
        histograms.entry(key).or_insert_with(Histogram::new).add(us);
    }
}
