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
    pub operation_deadlines: OperationDeadlines,
    pub proxy: ProxyLimits,
}

// How long a blocking management request waits for its operation's real outcome.
// Exec waits for its own timeout_ms plus margin_ms (teardown and cleanup).
// If a wait expires, the work still runs to a terminal state; only the result is lost
// (an undelivered create is deleted as create_response_lost).
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OperationDeadlines {
    pub create_ms: u64,
    pub capture_ms: u64,
    pub delete_ms: u64,
    pub margin_ms: u64,
}
impl Default for OperationDeadlines {
    // Use default outcome waits: two minutes for create and delete, five for capture, 30 s margin.
    fn default() -> Self { Self { create_ms: 120_000, capture_ms: 300_000, delete_ms: 120_000, margin_ms: 30_000 } }
}
impl OperationDeadlines {
    // Check that each outcome wait and the exec margin are within their allowed ranges.
    fn valid(&self) -> bool {
        (1_000..=1_800_000).contains(&self.create_ms) && (1_000..=3_600_000).contains(&self.capture_ms)
            && (1_000..=1_800_000).contains(&self.delete_ms) && (1_000..=300_000).contains(&self.margin_ms)
    }
}

// Bounds for streamed traffic (the app proxy and streaming exec forwards): how many exchanges may be
// open at once and how long one may go without moving a byte in either direction (including the wait
// for the response head). There is no total deadline; the client decides when to give up.
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyLimits {
    pub max_connections: usize,
    pub idle_timeout_ms: u64,
}
impl Default for ProxyLimits {
    // Use 256 open exchanges and AgentENV's ten-minute response-head wait as the idle timeout.
    fn default() -> Self { Self { max_connections: 256, idle_timeout_ms: 600_000 } }
}
impl ProxyLimits {
    // Check the connection count and idle timeout against their allowed ranges.
    fn valid(&self) -> bool {
        (1..=65_536).contains(&self.max_connections) && (1_000..=3_600_000).contains(&self.idle_timeout_ms)
    }
    // Return the idle timeout as a duration.
    pub fn idle(&self) -> Duration { Duration::from_millis(self.idle_timeout_ms) }
}

impl Default for ServerConfig {
    // Set default management request limits and leave the listen address unspecified.
    fn default() -> Self {
        Self {
            listen: None,
            max_in_flight: 64,
            request_timeout_ms: 5_000,
            max_body_bytes: 16_384,
            operation_deadlines: OperationDeadlines::default(),
            proxy: ProxyLimits::default(),
        }
    }
}

impl ServerConfig {
    // Reject out-of-range request limits, outcome waits or proxy bounds.
    fn validate(&self) -> Result<(), &'static str> {
        if !(1..=1_024).contains(&self.max_in_flight)
            || !(100..=30_000).contains(&self.request_timeout_ms)
            || !(256..=131_072).contains(&self.max_body_bytes)
            || !self.operation_deadlines.valid()
            || !self.proxy.valid()
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

    // Return the longest outcome wait of a blocking route (create, delete, exec, exec kill, capture),
    // or nothing for short routes, which use only request_timeout_ms. Proxied app traffic has no
    // route deadline at all (see ProxyLimits).
    pub fn route_wait(&self, method: &axum::http::Method, path: &str) -> Option<Duration> {
        use axum::http::Method;
        let d = &self.operation_deadlines;
        let ms = match (method, path.rsplit('/').next()) {
            (&Method::POST, _) if path == "/v1/sandboxes" => d.create_ms,
            (&Method::DELETE, _) if path.starts_with("/v1/sandboxes/") => d.delete_ms,
            (&Method::POST, Some("exec")) => crate::model::MAX_EXEC_TIMEOUT_MS + d.margin_ms,
            (&Method::POST, Some("kill")) => d.margin_ms,
            (&Method::POST, Some("capture")) => d.capture_ms,
            _ => return None,
        };
        Some(Duration::from_millis(ms))
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
    // App traffic for `<port>-<sandbox-id>.<proxy_domain>` hosts is proxied (AgentENV host routing).
    #[serde(default)]
    pub proxy_domain: Option<String>,
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
    // Validate server and polling limits, the optional proxy domain, unique worker identities and
    // HTTP(S) origins. Reject worker URLs containing credentials or extra path, query or fragment data.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.server.validate()?;
        if self.proxy_domain.as_deref().is_some_and(|d| !crate::proxy::valid_domain(d)) {
            return Err("proxy_domain must be a lowercase DNS name");
        }
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
    #[serde(default = "default_concurrent_operations")]
    pub max_concurrent_operations: usize,
    #[serde(default = "default_concurrent_execs")]
    pub max_concurrent_execs: usize,
    #[serde(default = "default_execs_per_sandbox")]
    pub max_execs_per_sandbox: usize,
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

// Use 16 parallel operation workers unless configured.
fn default_concurrent_operations() -> usize { 16 }
// Allow 64 running commands per worker unless configured.
fn default_concurrent_execs() -> usize { 64 }
// Allow 8 running commands per sandbox unless configured.
fn default_execs_per_sandbox() -> usize { 8 }

impl NativeConfig {
    // Reject unsafe native paths, invalid network settings and out-of-range resource, record or command
    // limits.
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
            || !(1..=64).contains(&self.max_concurrent_operations)
            || !(1..=1024).contains(&self.max_concurrent_execs)
            || !(1..=64).contains(&self.max_execs_per_sandbox)
            || !(1048576..=1099511627776).contains(&self.max_artifact_bytes)
            || !(10..=300).contains(&self.command_timeout_seconds)
        { return Err("invalid native runtime bounds"); }
        Ok(())
    }
}

impl WorkerConfig {
    // Validate server limits, worker identity, capacity and native runtime settings, and require exactly
    // one runtime. Require network slots to cover sandbox capacity and restore slots to fit the
    // operation pool.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.server.validate()?;
        if !valid_id(&self.node_id) || !self.capacity.valid() {
            return Err("invalid worker identity or capacity budget");
        }
        if let Some(native) = &self.native {
            native.validate()?;
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
