use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Runtime {
    RuncCriu,
    RunscNative,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capacity {
    pub memory_mib: u64,
    pub vcpus: u32,
    pub max_sandboxes: u32,
    pub max_concurrent_restores: u32,
}

impl Capacity {
    pub fn valid(&self) -> bool {
        (1..=1_048_576).contains(&self.memory_mib)
            && (1..=4_096).contains(&self.vcpus)
            && (1..=1_000_000).contains(&self.max_sandboxes)
            && (1..=1_024).contains(&self.max_concurrent_restores)
            && self.max_concurrent_restores <= self.max_sandboxes
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub memory_mib: u64,
    pub vcpus: u32,
    pub sandboxes: u32,
    pub restores: u32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCapability {
    pub runtime: Runtime,
    pub ready: bool,
    pub reason: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerStatus {
    pub schema_version: u32,
    pub node_id: String,
    pub architecture: String,
    pub os: String,
    pub capacity: Capacity,
    pub usage: Option<Usage>,
    pub admission_ready: bool,
    pub runtimes: Vec<RuntimeCapability>,
}

impl WorkerStatus {
    pub fn valid_for(&self, node_id: &str) -> bool {
        self.schema_version == 1 && self.node_id == node_id
            && self.architecture.len() <= 32 && self.os.len() <= 32
            && self.capacity.valid() && !self.runtimes.is_empty() && self.runtimes.len() <= 2
            && self.runtimes.iter().enumerate().all(|(i, capability)| {
                capability.reason.len() <= 128
                    && !self.runtimes[..i].iter().any(|other| other.runtime == capability.runtime)
            })
            && self.usage.as_ref().is_none_or(|usage| {
                usage.memory_mib <= self.capacity.memory_mib
                    && usage.vcpus <= self.capacity.vcpus
                    && usage.sandboxes <= self.capacity.max_sandboxes
                    && usage.restores <= self.capacity.max_concurrent_restores
            })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    pub template_id: String,
    pub runtime: Runtime,
    pub architecture: String,
    pub memory_mib: u64,
    pub vcpus: u32,
    pub ttl_seconds: u32,
}

impl CreateRequest {
    pub fn valid(&self) -> bool {
        valid_id(&self.template_id)
            && matches!(self.architecture.as_str(), "x86_64" | "aarch64")
            && (1..=1_048_576).contains(&self.memory_mib)
            && (1..=4_096).contains(&self.vcpus)
            && (1..=86_400).contains(&self.ttl_seconds)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
}

impl ExecRequest {
    pub fn valid(&self) -> bool {
        !self.argv.is_empty() && self.argv.len() <= 64 && !self.argv[0].is_empty()
            && self.argv.iter().all(|arg| arg.len() <= 4_096 && !arg.contains('\0'))
            && (1..=60_000).contains(&self.timeout_ms)
            && (1..=1_048_576).contains(&self.max_output_bytes)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRequest {
    pub template_id: String,
    pub runtime: Runtime,
}

pub fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}
