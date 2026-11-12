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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: None,
            max_in_flight: 64,
            request_timeout_ms: 5_000,
            max_body_bytes: 16_384,
        }
    }
}

impl ServerConfig {
    fn validate(&self) -> Result<(), &'static str> {
        if !(1..=1_024).contains(&self.max_in_flight)
            || !(100..=30_000).contains(&self.request_timeout_ms)
            || !(256..=65_536).contains(&self.max_body_bytes)
        {
            return Err("invalid server limits");
        }
        Ok(())
    }

    pub fn address(&self, port: u16) -> SocketAddr {
        self.listen.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], port)))
    }

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
}

impl WorkerConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.server.validate()?;
        if !valid_id(&self.node_id) || !self.capacity.valid() {
            return Err("invalid worker identity or capacity budget");
        }
        if self.runtimes.len() != 1 {
            return Err("configure exactly one runtime: runc_criu");
        }
        Ok(())
    }
}

pub fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, &'static str> {
    let bytes = read_bounded(path, 65_536).map_err(|_| "configuration file unavailable or too large")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "invalid configuration encoding")?;
    // Do not print parser diagnostics: an accidentally embedded credential could appear in them.
    toml::from_str(text).map_err(|_| "invalid configuration: check fields and types")
}

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
