use std::{env, fs::File, io::Read, net::SocketAddr, path::Path, time::Duration};

use serde::Deserialize;

use crate::model::{Capacity, Runtime, valid_id};

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: Option<SocketAddr>,
    pub max_in_flight: usize,
    pub request_timeout_ms: u64,
    pub max_body_bytes: usize,
    pub application_http: ApplicationHttpLimits,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApplicationHttpLimits {
    pub max_body_bytes: usize,
    pub max_response_bytes: u64,
    pub max_timeout_ms: u64,
}
impl Default for ApplicationHttpLimits {
    // Use small default application HTTP body, response and deadline limits.
    fn default() -> Self { Self { max_body_bytes: 8192, max_response_bytes: 65536, max_timeout_ms: 30000 } }
}
impl ApplicationHttpLimits {
    // Reserve room for the largest response after JSON escaping and metadata.
    pub fn response_reservation(&self) -> usize { self.max_response_bytes as usize * 6 + 8192 }
    // Check that application HTTP sizes and deadlines stay within supported bounds.
    fn valid(&self) -> bool {
        (1..=16384).contains(&self.max_body_bytes) && (1..=8388608).contains(&self.max_response_bytes)
            && (1..=600000).contains(&self.max_timeout_ms)
    }
}

impl Default for ServerConfig {
    // Set default management request limits and leave the listen address unspecified.
    fn default() -> Self {
        Self {
            listen: None,
            max_in_flight: 64,
            request_timeout_ms: 5_000,
            max_body_bytes: 16_384,
            application_http: ApplicationHttpLimits::default(),
        }
    }
}

impl ServerConfig {
    // Reject out-of-range request limits or an enlarged application body without enough JSON envelope
    // space.
    fn validate(&self) -> Result<(), &'static str> {
        if !(1..=1_024).contains(&self.max_in_flight)
            || !(100..=30_000).contains(&self.request_timeout_ms)
            || !(256..=131_072).contains(&self.max_body_bytes)
            || !self.application_http.valid()
            // Opt-in larger text bodies need room for worst-case JSON escaping.
            || (self.application_http.max_body_bytes > 8192
                && self.max_body_bytes < self.application_http.max_body_bytes * 6 + 8192)
        {
            return Err("invalid server limits");
        }
        Ok(())
    }

    // Use the configured listen address, or loopback with the supplied default port.
    pub fn address(&self, port: u16) -> SocketAddr {
        self.listen.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], port)))
    }

    // Return the configured management request deadline.
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSource {
    env: Option<String>,
    file: Option<String>,
}

impl CredentialSource {
    // Read exactly one credential source, allowing one line ending in a bounded secret file. Reject
    // missing sources, invalid encoding, whitespace and out-of-range token lengths.
    pub fn load(&self) -> Result<String, &'static str> {
        let token = match (&self.env, &self.file) {
            (Some(name), None) if !name.is_empty() => {
                env::var(name).map_err(|_| "credential environment variable unavailable")?
            }
            (None, Some(path)) if !path.is_empty() => {
                let bytes = read_bounded(Path::new(path), 1_026)
                    .map_err(|_| "credential file unavailable or too large")?;
                let mut text = String::from_utf8(bytes).map_err(|_| "invalid credential encoding")?;
                // Permit one conventional line ending in a secret file, not arbitrary whitespace.
                if text.ends_with('\n') {
                    text.pop();
                    if text.ends_with('\r') {
                        text.pop();
                    }
                }
                text
            }
            _ => return Err("configure exactly one credential source: env or file"),
        };
        if !(32..=1_024).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("credentials must contain 32 to 1024 printable ASCII bytes without whitespace");
        }
        Ok(token)
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerEndpoint {
    pub node_id: String,
    pub url: String,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PollConfig {
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub freshness_ms: u64,
    pub fanout: usize,
}

impl Default for PollConfig {
    // Set default polling frequency, deadline, freshness window and parallelism.
    fn default() -> Self {
        Self { interval_ms: 1_000, timeout_ms: 1_000, freshness_ms: 5_000, fanout: 8 }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerConfig {
    #[serde(default)]
    pub server: ServerConfig,
    pub auth: CredentialSource,
    pub worker_auth: CredentialSource,
    #[serde(default)]
    pub poll: PollConfig,
    #[serde(default)]
    pub workers: Vec<WorkerEndpoint>,
}

impl ControllerConfig {
    // Validate server and polling limits, unique worker identities and HTTP(S) origins. Reject worker URLs
    // containing credentials or extra path, query or fragment data.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.server.validate()?;
        if self.workers.len() > 128
            || !(100..=30_000).contains(&self.poll.interval_ms)
            || !(100..=10_000).contains(&self.poll.timeout_ms)
            || !(500..=60_000).contains(&self.poll.freshness_ms)
            || self.poll.freshness_ms < self.poll.interval_ms
            || !(1..=16).contains(&self.poll.fanout)
        {
            return Err("invalid worker polling limits");
        }
        for (index, worker) in self.workers.iter().enumerate() {
            if !valid_id(&worker.node_id)
                || self.workers[..index].iter().any(|other| other.node_id == worker.node_id)
            {
                return Err("invalid or duplicate worker node ID");
            }
            let url = reqwest::Url::parse(&worker.url).map_err(|_| "invalid worker URL")?;
            if worker.url.len() > 2_048
                || !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
            {
                return Err("worker URLs must be HTTP(S) origins without credentials, path, query or fragment");
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerConfig {
    #[serde(default)]
    pub server: ServerConfig,
    pub auth: CredentialSource,
    pub node_id: String,
    pub capacity: Capacity,
    pub runtimes: Vec<Runtime>,
    #[serde(default)]
    pub native: Option<NativeConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConfig {
    pub enabled: bool,
    pub root: String,
    pub cgroup_parent: String,
    #[serde(default)]
    pub tools_dir: Option<String>,
    pub cpu_overcommit: u32,
    pub pids_max: u32,
    pub max_records: usize,
    pub max_operations_per_sandbox: usize,
    #[serde(default = "default_concurrent_operations")]
    pub max_concurrent_operations: usize,
    #[serde(default = "default_retained_output")]
    pub max_retained_output_bytes: usize,
    #[serde(default = "default_sandbox_retained_output")]
    pub max_retained_output_per_sandbox_bytes: usize,
    pub max_artifact_bytes: u64,
    pub command_timeout_seconds: u64,
    #[serde(default)]
    pub network: Option<NetworkConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub bridge: String,
    pub gateway: std::net::Ipv4Addr,
    pub prefix: u8,
    pub addresses: Vec<std::net::Ipv4Addr>,
    pub egress: Vec<crate::model::TcpDestination>,
    pub service_ports: Vec<u16>,
}
impl NetworkConfig {
    // Check bridge naming, pool size and allowed destinations and ports. Require distinct usable pool
    // addresses in the gateway subnet, excluding the gateway and egress targets.
    fn valid(&self) -> bool {
        if self.bridge.is_empty() || self.bridge.len() > 15 || !self.bridge.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || !(8..=30).contains(&self.prefix) || self.addresses.is_empty() || self.addresses.len() > 256
            || self.egress.len() > 64 || self.service_ports.len() > 16 || self.service_ports.contains(&0) { return false; }
        let mask = u32::MAX << (32 - self.prefix);
        let network = u32::from(self.gateway) & mask;
        let valid_ip = |ip| crate::model::TcpDestination { ip, port: 1 }.valid()
            && u32::from(ip) & mask == network && u32::from(ip) & !mask != 0 && u32::from(ip) & !mask != !mask;
        valid_ip(self.gateway) && self.addresses.iter().enumerate().all(|(i, ip)| valid_ip(*ip) && *ip != self.gateway && !self.addresses[..i].contains(ip))
            && self.egress.iter().all(|e| e.valid() && !self.addresses.contains(&e.ip))
    }
}

// Default to a 16 MiB worker-wide retained-output budget.
fn default_retained_output() -> usize { 16777216 }
// Default to an 8 MiB retained-output budget per sandbox.
fn default_sandbox_retained_output() -> usize { 8388608 }
// Default to sixteen concurrent lifecycle operations.
fn default_concurrent_operations() -> usize { 16 }

impl NativeConfig {
    // Reject unsafe native paths, invalid network settings and out-of-range resource or retention limits.
    fn validate(&self) -> Result<(), &'static str> {
        for path in [&self.root, &self.cgroup_parent].into_iter().chain(self.tools_dir.iter()) {
            if !path.starts_with('/') || path.len() > 256
                || !path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
                || std::path::Path::new(path).components().any(|c| !matches!(c, std::path::Component::RootDir | std::path::Component::Normal(_)))
                || path.split('/').any(|p| p == "." || p == "..")
            {
                return Err("native paths must be clean absolute paths");
            }
        }
        if self.network.as_ref().is_some_and(|n| !n.valid()) { return Err("invalid native network policy or address pool"); }
        if self.root == "/" || !self.cgroup_parent.starts_with("/sys/fs/cgroup/")
            || !(1..=16).contains(&self.cpu_overcommit)
            || !(16..=65536).contains(&self.pids_max)
            || !(1..=100000).contains(&self.max_records)
            || !(1..=64).contains(&self.max_operations_per_sandbox)
            || !(1..=64).contains(&self.max_concurrent_operations)
            || !(1048576..=4294967296).contains(&self.max_retained_output_bytes)
            || !(1048576..=67108864).contains(&self.max_retained_output_per_sandbox_bytes)
            || !(1048576..=1099511627776).contains(&self.max_artifact_bytes)
            || !(10..=300).contains(&self.command_timeout_seconds)
        { return Err("invalid native runtime bounds"); }
        Ok(())
    }
}

impl WorkerConfig {
    // Validate worker identity, capacity and runtime settings. Require HTTP result reservations, network
    // slots and restore concurrency to fit their enclosing budgets.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.server.validate()?;
        if !valid_id(&self.node_id) || !self.capacity.valid() {
            return Err("invalid worker identity or capacity budget");
        }
        if let Some(native) = &self.native {
            native.validate()?;
            let reservation = self.server.application_http.response_reservation();
            if reservation > native.max_retained_output_bytes || reservation > native.max_retained_output_per_sandbox_bytes {
                return Err("application HTTP response ceiling exceeds retained output budget");
            }
            if native.network.as_ref().is_some_and(|n| n.addresses.len() < self.capacity.max_sandboxes as usize) { return Err("network slots must cover sandbox capacity"); }
            if self.capacity.max_concurrent_restores as usize > native.max_concurrent_operations {
                return Err("restore slots must fit the bounded operation pool");
            }
        }
        if self.runtimes.len() != 1 {
            return Err("configure exactly one runtime: runc_criu");
        }
        Ok(())
    }
}

// Read a bounded configuration file and decode it without exposing file contents in errors.
pub fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, &'static str> {
    let bytes = read_bounded(path, 65_536).map_err(|_| "configuration file unavailable or too large")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "invalid configuration encoding")?;
    // Do not print parser diagnostics: an accidentally embedded credential could appear in them.
    toml::from_str(text).map_err(|_| "invalid configuration: check fields and types")
}

// Read only a regular file, rejecting contents larger than the supplied byte limit.
fn read_bounded(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(std::io::Error::other("expected regular file"));
    }
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("file too large"));
    }
    Ok(bytes)
}
