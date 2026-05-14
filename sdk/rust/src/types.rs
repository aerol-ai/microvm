use serde::{Deserialize, Serialize};

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MountType {
    S3,
    Nfs,
    Sshfs,
    Rclone,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegistryAuth {
    pub server: String,
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MountSpec {
    #[serde(rename = "type")]
    pub mount_type: MountType,
    pub target: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "read_only", skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MountSpecRedacted {
    #[serde(rename = "type")]
    pub mount_type: MountType,
    pub target: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "read_only", default)]
    pub read_only: bool,
    #[serde(rename = "has_credentials", default)]
    pub has_credentials: bool,
}

/// GPU hardware vendor for sandbox GPU allocation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GPUVendor {
    /// NVIDIA GPUs via nvidia-container-runtime. Requires
    /// nvidia-container-toolkit on the host.
    Nvidia,
    /// AMD GPUs via ROCm (/dev/kfd + /dev/dri). Requires ROCm drivers
    /// on the host.
    Amd,
    /// Apple Silicon GPU via Docker Desktop's experimental Metal support.
    /// Only functional on macOS with Docker Desktop.
    Apple,
}

/// GPU resources to attach to a sandbox at creation time. Not compatible
/// with runtime `"gvisor"`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GPUOptions {
    /// GPU hardware vendor. Required.
    pub vendor: GPUVendor,
    /// Number of GPUs. `-1` = all available, `0`/omit = default (1).
    /// Ignored for AMD (all AMD GPUs on the host are exposed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i32>,
    /// For NVIDIA: GPU indices (`"0"`, `"1"`) or UUIDs (`"GPU-abc123..."`).
    /// For AMD and Apple: ignored.
    #[serde(rename = "device_ids", skip_serializing_if = "Option::is_none")]
    pub device_ids: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateOptions {
    pub image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<u32>,
    #[serde(rename = "memory_mb", skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u32>,
    #[serde(rename = "disk_gb", skip_serializing_if = "Option::is_none")]
    pub disk_gb: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "os_user", skip_serializing_if = "Option::is_none")]
    pub os_user: Option<String>,
    #[serde(rename = "network_block_all", skip_serializing_if = "Option::is_none")]
    pub network_block_all: Option<bool>,
    /// Cap on bytes the sandbox may receive before its ingress is dropped via
    /// per-IP iptables rule. `0` (or omit) means unlimited. Limits can be
    /// raised or lifted at runtime via [`Client::set_network_limits`].
    #[serde(rename = "network_bytes_in_limit", skip_serializing_if = "Option::is_none")]
    pub network_bytes_in_limit: Option<i64>,
    /// Cap on bytes the sandbox may send before its egress is dropped. `0`
    /// (or omit) means unlimited. The block reuses the same iptables row as
    /// `network_block_all`; clearing the quota does not lift an operator-set
    /// blanket egress block.
    #[serde(rename = "network_bytes_out_limit", skip_serializing_if = "Option::is_none")]
    pub network_bytes_out_limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegistryAuth>,
    #[serde(rename = "container_command", skip_serializing_if = "Option::is_none")]
    pub container_command: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<MountSpec>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<Lifecycle>,
    /// Container runtime for this sandbox. Omit to inherit the host default
    /// (SB_CONTAINER_RUNTIME). Use `"gvisor"` for runsc-backed isolation when
    /// running untrusted workloads. `"kata"` is reserved and rejected by the
    /// API today. Not compatible with `gpus`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// Attach GPU resources to the sandbox. Omit for CPU-only workloads.
    /// Not compatible with `runtime = "gvisor"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpus: Option<GPUOptions>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Lifecycle {
    #[serde(rename = "stop_if_idle_for", default, skip_serializing_if = "is_zero_u64")]
    pub stop_if_idle_for: u64,
    #[serde(rename = "destroy_if_idle_for", default, skip_serializing_if = "is_zero_u64")]
    pub destroy_if_idle_for: u64,
    #[serde(rename = "stop_at_age", default, skip_serializing_if = "is_zero_u64")]
    pub stop_at_age: u64,
    #[serde(rename = "destroy_at_age", default, skip_serializing_if = "is_zero_u64")]
    pub destroy_at_age: u64,
}

pub type UpdateLifecycleOptions = Lifecycle;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ResizeOptions {
    pub cpu: Option<u32>,
    #[serde(rename = "memory_mb", skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u32>,
    #[serde(rename = "disk_gb", skip_serializing_if = "Option::is_none")]
    pub disk_gb: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExposedPort {
    #[serde(rename = "sandbox_id")]
    pub sandbox_id: String,
    pub port: u16,
    #[serde(rename = "public_url")]
    pub public_url: String,
    #[serde(rename = "created_at")]
    pub created_at: String,
}

/// Wire protocol an exposure publishes through.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExposeProtocol {
    /// Caddy HTTP reverse proxy at `https://<id>-<port>.<domain>`.
    Http,
    /// Raw caddy-l4 listener on a parent-host port.
    Tcp,
    /// caddy-l4 TLS-SNI route on the shared layer4 server.
    Tls,
}

impl Default for ExposeProtocol {
    fn default() -> Self {
        ExposeProtocol::Http
    }
}

/// Options for [`Sandbox::expose_port`] / [`Client::expose_port`]. Defaults to
/// `ExposeProtocol::Http` so `ExposeOptions::default()` keeps the historical
/// behavior.
#[derive(Default, Debug, Clone, Copy)]
pub struct ExposeOptions {
    pub protocol: ExposeProtocol,
}

impl ExposeOptions {
    pub fn http() -> Self {
        Self {
            protocol: ExposeProtocol::Http,
        }
    }
    pub fn tcp() -> Self {
        Self {
            protocol: ExposeProtocol::Tcp,
        }
    }
    pub fn tls() -> Self {
        Self {
            protocol: ExposeProtocol::Tls,
        }
    }
}

/// Outcome of a successful expose call. The `Tcp` variant carries `host` and
/// `host_port` because native protocol clients (psql, redis-cli, mysql,
/// mongosh) need them to dial; HTTP and TLS exposures only need the URL.
#[derive(Debug, Clone)]
pub enum ExposeResult {
    Http {
        url: String,
    },
    Tcp {
        url: String,
        host: String,
        host_port: u16,
    },
    Tls {
        url: String,
    },
}

/// Wire shape for the expose response — kept private; callers consume the
/// public [`ExposeResult`] enum instead.
#[derive(Deserialize)]
pub(crate) struct ExposePortResponseWire {
    pub protocol: String,
    #[serde(rename = "public_url")]
    pub public_url: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(rename = "host_port", default)]
    pub host_port: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Sandbox {
    pub id: String,
    pub image: String,
    pub status: String,
    #[serde(rename = "public_url")]
    pub public_url: String,
    #[serde(rename = "container_id")]
    pub container_id: Option<String>,
    #[serde(rename = "container_ip")]
    pub container_ip: Option<String>,
    pub cpu: u32,
    #[serde(rename = "memory_mb")]
    pub memory_mb: u32,
    #[serde(rename = "disk_gb")]
    pub disk_gb: u32,
    #[serde(rename = "os_user")]
    pub os_user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "network_block_all")]
    pub network_block_all: bool,
    #[serde(rename = "toolbox_enabled")]
    pub toolbox_enabled: bool,
    #[serde(rename = "ssh_public_key", skip_serializing_if = "Option::is_none")]
    pub ssh_public_key: Option<String>,
    #[serde(rename = "exposed_ports", skip_serializing_if = "Option::is_none")]
    pub exposed_ports: Option<Vec<ExposedPort>>,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(rename = "updated_at")]
    pub updated_at: String,
    #[serde(rename = "last_active_at")]
    pub last_active_at: String,
    #[serde(rename = "last_error", skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(rename = "container_command", skip_serializing_if = "Option::is_none")]
    pub container_command: Option<Vec<String>>,
    #[serde(default)]
    pub lifecycle: Lifecycle,
    /// Container runtime this sandbox is running under. Empty string indicates
    /// a pre-migration row that resolves to the host default at start time.
    #[serde(default)]
    pub runtime: String,
    /// GPU configuration this sandbox was created with. `None` means no GPU
    /// was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpus: Option<GPUOptions>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateSandboxResponse {
    #[serde(flatten)]
    pub sandbox: Sandbox,
    #[serde(rename = "ssh_private_key", skip_serializing_if = "Option::is_none")]
    pub ssh_private_key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SandboxSnapshot {
    pub name: String,
    pub image: String,
    #[serde(rename = "image_id", skip_serializing_if = "Option::is_none")]
    pub image_id: Option<String>,
    #[serde(rename = "source_sandbox_id")]
    pub source_sandbox_id: String,
    #[serde(rename = "created_at")]
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthStatus {
    pub status: String,
    pub sandboxes: u32,
    pub docker: String,
    pub caddy: String,
    #[serde(rename = "ssh_gateway", default)]
    pub ssh_gateway: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecRequest {
    pub command: String,
    #[serde(rename = "workdir", skip_serializing_if = "Option::is_none")]
    pub work_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "timeout_seconds", skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    #[serde(rename = "exit_code")]
    pub exit_code: i32,
    #[serde(rename = "duration_ms")]
    pub duration_ms: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExecExitInfo {
    pub code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CreateSessionOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(rename = "workdir", skip_serializing_if = "Option::is_none")]
    pub work_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pty: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cols: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Running,
    Exited,
    Killed,
    Failed,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub argv: Vec<String>,
    #[serde(rename = "workdir", skip_serializing_if = "Option::is_none")]
    pub work_dir: Option<String>,
    pub pty: bool,
    pub status: SessionStatus,
    #[serde(rename = "exit_code")]
    pub exit_code: i32,
    #[serde(rename = "exit_signal", skip_serializing_if = "Option::is_none")]
    pub exit_signal: Option<String>,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(rename = "started_at")]
    pub started_at: String,
    #[serde(rename = "exited_at", skip_serializing_if = "Option::is_none")]
    pub exited_at: Option<String>,
    pub recording: bool,
    pub bytes: i64,
    pub attached: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SessionList {
    pub sessions: Vec<Session>,
}

/// Per-sandbox network byte counters and the configured caps that drive the
/// quota enforcer. `bytes_in` is traffic the container received (ingress);
/// `bytes_out` is traffic the container sent (egress). A `*_limit` of `0`
/// means unlimited. `quota_exceeded` flips true the first time the meter
/// crosses either configured cap and stays true until the operator raises
/// the limit.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NetworkUsage {
    #[serde(rename = "sandbox_id")]
    pub sandbox_id: String,
    #[serde(rename = "bytes_in")]
    pub bytes_in: i64,
    #[serde(rename = "bytes_out")]
    pub bytes_out: i64,
    #[serde(rename = "bytes_in_limit")]
    pub bytes_in_limit: i64,
    #[serde(rename = "bytes_out_limit")]
    pub bytes_out_limit: i64,
    #[serde(rename = "quota_exceeded")]
    pub quota_exceeded: bool,
    #[serde(rename = "quota_exceeded_at", skip_serializing_if = "Option::is_none")]
    pub quota_exceeded_at: Option<String>,
    /// Absent (`None`) until the netstats poller has produced at least one
    /// sample. `default` lets us deserialize a server response that omits the
    /// field entirely (pre-first-tick) rather than failing.
    #[serde(rename = "last_sampled_at", default, skip_serializing_if = "Option::is_none")]
    pub last_sampled_at: Option<String>,
}

/// Patch body for [`Client::set_network_limits`]. Each field is `Option`-wrapped
/// so an unset key serializes as missing (server reads as "leave alone");
/// `Some(0)` means unlimited.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SetNetworkLimitsOptions {
    #[serde(rename = "network_bytes_in_limit", skip_serializing_if = "Option::is_none")]
    pub network_bytes_in_limit: Option<i64>,
    #[serde(rename = "network_bytes_out_limit", skip_serializing_if = "Option::is_none")]
    pub network_bytes_out_limit: Option<i64>,
}
