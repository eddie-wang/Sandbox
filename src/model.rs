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
    // Check capacity bounds and require restore slots not to exceed sandbox slots.
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
    // Check status schema, expected node identity and field bounds. Require reported reservations to fit
    // capacity, including the configured CPU overcommit allowance.
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

// Accept omitted resources, or memory and CPU counts within the supported ranges.
fn valid_resources(memory_mib: Option<u64>, vcpus: Option<u32>) -> bool {
    memory_mib.is_none_or(|m| (1..=1_048_576).contains(&m)) && vcpus.is_none_or(|v| (1..=4_096).contains(&v))
}

// Client-facing create input. The controller chooses the owner and generates the
// ID; the owner's template supplies architecture and default resources.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreateSpec {
    pub template_id: String,
    #[serde(default)]
    pub memory_mib: Option<u64>,
    #[serde(default)]
    pub vcpus: Option<u32>,
    pub ttl_seconds: u32,
}

impl CreateSpec {
    // Check the template ID, any supplied resources and the time-to-live range.
    pub fn valid(&self) -> bool {
        valid_id(&self.template_id) && valid_resources(self.memory_mib, self.vcpus) && (1..=86_400).contains(&self.ttl_seconds)
    }
    // Build the worker create request carrying the controller-generated sandbox ID.
    pub fn with_id(self, sandbox_id: String) -> CreateRequest {
        CreateRequest { sandbox_id, template_id: self.template_id, memory_mib: self.memory_mib, vcpus: self.vcpus, ttl_seconds: self.ttl_seconds }
    }
}

// Controller-to-worker create, with the controller-generated owner-prefixed ID.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    pub sandbox_id: String,
    pub template_id: String,
    pub memory_mib: Option<u64>,
    pub vcpus: Option<u32>,
    pub ttl_seconds: u32,
}

impl CreateRequest {
    // Require an owner-prefixed sandbox ID, then check the template ID, any supplied resources and the
    // time-to-live range.
    pub fn valid(&self) -> bool {
        sandbox_owner(&self.sandbox_id).is_some() && valid_id(&self.template_id)
            && valid_resources(self.memory_mib, self.vcpus) && (1..=86_400).contains(&self.ttl_seconds)
    }
    // Decide whether this create repeats the saved one. An identical retry may omit values that were
    // resolved from the template.
    pub fn matches(&self, spec: &SandboxSpec) -> bool {
        self.sandbox_id == spec.sandbox_id && self.template_id == spec.template_id && self.ttl_seconds == spec.ttl_seconds
            && self.memory_mib.is_none_or(|m| m == spec.memory_mib) && self.vcpus.is_none_or(|v| v == spec.vcpus)
    }
}

// A create with resources resolved by the worker at admission; durable in records.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SandboxSpec {
    pub sandbox_id: String,
    pub template_id: String,
    pub memory_mib: u64,
    pub vcpus: u32,
    pub ttl_seconds: u32,
}

impl SandboxSpec {
    // Check a saved record's owner-prefixed ID, template ID, resolved resources and time to live.
    pub fn valid(&self) -> bool {
        sandbox_owner(&self.sandbox_id).is_some() && valid_id(&self.template_id)
            && valid_resources(Some(self.memory_mib), Some(self.vcpus)) && (1..=86_400).contains(&self.ttl_seconds)
    }
}

pub const MAX_EXEC_TIMEOUT_MS: u64 = 60_000;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    // Stream output as server-sent events instead of returning one JSON result at the end.
    #[serde(default)]
    pub stream: bool,
}

impl ExecRequest {
    // Check for a nonempty command, argument count/size limits and output/deadline bounds.
    pub fn valid(&self) -> bool {
        !self.argv.is_empty() && self.argv.len() <= 64 && !self.argv[0].is_empty()
            && self.argv.iter().all(|arg| arg.len() <= 4_096 && !arg.contains('\0'))
            && (1..=MAX_EXEC_TIMEOUT_MS).contains(&self.timeout_ms)
            && (1..=1_048_576).contains(&self.max_output_bytes)
    }
    // Return the largest valid blocking JSON exec result: lossy UTF-8 and escaping expand raw output
    // bytes up to 6x, plus room for the other fields.
    pub fn max_result_bytes(&self) -> usize { self.max_output_bytes as usize * 6 + 8192 }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRequest {
    pub template_id: String,
    pub runtime: Runtime,
}

// Accept only short, nonempty IDs made of ASCII letters, digits, hyphens and underscores.
pub fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

// The controller embeds the chosen owner in the generated ID, so later calls and
// controller restarts route without an assignment table. Clients treat it as opaque.
pub fn sandbox_owner(value: &str) -> Option<&str> {
    let (node, local) = value.split_once('.')?;
    (valid_id(node) && valid_id(local)).then_some(node)
}

// Policies are immutable template input; callers cannot author a broader policy.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TcpDestination { pub ip: std::net::Ipv4Addr, pub port: u16 }
impl TcpDestination {
    // Reject a zero TCP port or zero-prefix, loopback, link-local, multicast/reserved or fixed guest-range
    // IPv4 addresses.
    pub fn valid(&self) -> bool {
        let o = self.ip.octets();
        self.port != 0 && o[0] != 0 && o[0] != 127 && o[0] < 224
            && !self.ip.is_link_local() && o[..3] != [192, 0, 2]
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum NetworkPolicy {
    Isolated,
    TcpAllowlist { egress: Vec<TcpDestination>, service_ports: Vec<u16> },
}
impl NetworkPolicy {
    // Accept isolation or a bounded list of valid TCP destinations and nonzero service ports.
    pub fn valid(&self) -> bool {
        match self {
            Self::Isolated => true,
            Self::TcpAllowlist { egress, service_ports } => egress.len() <= 64 && service_ports.len() <= 16
                && egress.iter().all(TcpDestination::valid) && service_ports.iter().all(|p| *p != 0),
        }
    }
    // Decide whether app traffic may reach this guest port: only an approved service port of a TCP
    // policy.
    pub fn serves(&self, port: u16) -> bool {
        matches!(self, Self::TcpAllowlist { service_ports, .. } if service_ports.contains(&port))
    }
}
