use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Runtime {
    RuncCriu,
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
    pub cpu_overcommit: u32,
    pub qualification: String,
}

impl WorkerStatus {
    pub fn valid_for(&self, node_id: &str) -> bool {
        self.schema_version == 1 && self.node_id == node_id
            && self.architecture.len() <= 32 && self.os.len() <= 32
            && self.capacity.valid() && self.runtimes.len() == 1
            && (1..=16).contains(&self.cpu_overcommit) && self.qualification.len() <= 64
            && self.runtimes[0].reason.len() <= 128
            && self.usage.as_ref().is_none_or(|usage| {
                usage.memory_mib <= self.capacity.memory_mib
                    && usage.vcpus <= self.capacity.vcpus.saturating_mul(self.cpu_overcommit)
                    && usage.sandboxes <= self.capacity.max_sandboxes
                    && usage.restores <= self.capacity.max_concurrent_restores
            })
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    pub sandbox_id: String,
    pub template_id: String,
    pub runtime: Runtime,
    pub architecture: String,
    pub memory_mib: u64,
    pub vcpus: u32,
    pub ttl_seconds: u32,
}

impl CreateRequest {
    pub fn valid(&self) -> bool {
        sandbox_owner(&self.sandbox_id).is_some() && valid_id(&self.template_id)
            && matches!(self.architecture.as_str(), "x86_64" | "aarch64")
            && (1..=1_048_576).contains(&self.memory_mib)
            && (1..=4_096).contains(&self.vcpus)
            && (1..=86_400).contains(&self.ttl_seconds)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecRequest {
    pub operation_id: String,
    pub argv: Vec<String>,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
}

impl ExecRequest {
    pub fn valid(&self) -> bool {
        valid_id(&self.operation_id) && !self.argv.is_empty() && self.argv.len() <= 64 && !self.argv[0].is_empty()
            && self.argv.iter().all(|arg| arg.len() <= 4_096 && !arg.contains('\0'))
            && (1..=60_000).contains(&self.timeout_ms)
            && (1..=1_048_576).contains(&self.max_output_bytes)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRequest {
    pub operation_id: String,
    pub template_id: String,
    pub runtime: Runtime,
}

pub fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

// Ownership is part of the caller-chosen id, so retries and controller restarts
// cannot route a possibly accepted create to a different worker.
pub fn sandbox_owner(value: &str) -> Option<&str> {
    let (node, local) = value.split_once('.')?;
    (valid_id(node) && valid_id(local)).then_some(node)
}
