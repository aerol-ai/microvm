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

/// Per-request push directive for `Client::build_image_with_options`.
/// Credentials are forwarded to the daemon as a one-shot `X-Registry-Auth`
/// header on the underlying push call and are never persisted server-side.
#[derive(Debug, Clone, Default)]
pub struct BuildImagePushOptions {
    /// Destination repository, e.g. `"ghcr.io/my-org/my-image"`.
    pub registry: String,
    /// Destination tag. The daemon defaults to `"latest"` when empty.
    pub tag: Option<String>,
    /// Registry serveraddress, e.g. `"ghcr.io"`. Sent inside `X-Registry-Auth`.
    pub server: Option<String>,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Default)]
pub struct BuildImageOptions {
    pub push: Option<BuildImagePushOptions>,
}

#[derive(Debug, Clone)]
pub struct BuildImageResult {
    /// Local content-addressed tag (always returned).
    pub image: String,
    /// Pushed reference (e.g. `"ghcr.io/x/y:v1"`) when push was requested.
    pub pushed: Option<String>,
}

/// Clone-generation marker for a sandbox.
///
/// `generation` changes every time the sandbox is resumed from a snapshot
/// (i.e. it is a clone). A long-lived process running *inside* the sandbox can
/// poll this and reseed its own userspace PRNGs when the token changes — two
/// clones otherwise share the snapshot's frozen seed state. Read-only: the SDK
/// cannot reseed an in-guest process from the client side. See the "Randomness
/// in cloned sandboxes" docs page.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CloneGeneration {
    /// Opaque token that changes on every resume-from-snapshot.
    pub generation: String,
    /// Host wall-clock of the last resume, in unix nanoseconds. 0 = never resumed.
    #[serde(default)]
    pub resumed_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct RegisterSnapshotOptions {
    /// Human-readable identifier other callers use in create-time snapshot references.
    pub name: String,
    /// Pre-built registry image reference. Mutually exclusive with `dockerfile_content`.
    pub image: Option<String>,
    /// Literal Dockerfile the daemon will build. Mutually exclusive with `image`.
    pub dockerfile_content: Option<String>,
    /// Uploaded build-context hashes for future COPY/ADD resolution.
    pub context_hashes: Vec<String>,
    /// Optional command override persisted on the snapshot row.
    pub entrypoint: Vec<String>,
    /// Region hint persisted for read-back.
    pub region_id: Option<String>,
    /// Resource hints surfaced back on the snapshot row.
    pub cpu: Option<f64>,
    pub gpu: Option<f64>,
    pub memory_mb: Option<u32>,
    pub disk_gb: Option<u32>,
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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
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
    /// Egress allowlist of CIDRs: when set, the sandbox may reach only these
    /// destinations and all other outbound traffic is dropped by the host
    /// firewall. Mutually exclusive with `network_deny_out`; use
    /// `network_block_all` for a full block.
    #[serde(rename = "network_allow_out", skip_serializing_if = "Option::is_none")]
    pub network_allow_out: Option<Vec<String>>,
    /// Egress blocklist of CIDRs: the sandbox may reach anything except these
    /// destinations. Mutually exclusive with `network_allow_out`.
    #[serde(rename = "network_deny_out", skip_serializing_if = "Option::is_none")]
    pub network_deny_out: Option<Vec<String>>,
    /// Cap on bytes the sandbox may receive before its ingress is dropped via
    /// per-IP iptables rule. `0` (or omit) means unlimited. Limits can be
    /// raised or lifted at runtime via [`Client::set_network_limits`].
    #[serde(
        rename = "network_bytes_in_limit",
        skip_serializing_if = "Option::is_none"
    )]
    pub network_bytes_in_limit: Option<i64>,
    /// Cap on bytes the sandbox may send before its egress is dropped. `0`
    /// (or omit) means unlimited. The block reuses the same iptables row as
    /// `network_block_all`; clearing the quota does not lift an operator-set
    /// blanket egress block.
    #[serde(
        rename = "network_bytes_out_limit",
        skip_serializing_if = "Option::is_none"
    )]
    pub network_bytes_out_limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegistryAuth>,
    #[serde(rename = "container_command", skip_serializing_if = "Option::is_none")]
    pub container_command: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<MountSpec>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<Lifecycle>,
    /// Owner-node death policy. Omit for non-HA sandboxes; set
    /// `Failover { policy: "recreate".into() }` to opt into best-effort
    /// cluster recreation from the replicated create spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failover: Option<Failover>,
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
    /// Custom hostnames to attach to the sandbox at create time. Each entry
    /// is server-normalized (lowercased, trailing dot stripped). Server-side
    /// cap: `MaxCustomDomainsPerCreateRequest` (5). After create, manage the
    /// list via [`Sandbox::add_custom_domain`] / [`Sandbox::remove_custom_domain`].
    #[serde(rename = "custom_domains", skip_serializing_if = "Option::is_none")]
    pub custom_domains: Option<Vec<String>>,
    /// Survival class across daemon restarts. Omit for the runtime default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub durability: Option<String>,
    /// WASM module reference. When runtime is wasm, may be used instead of image.
    #[serde(rename = "module_ref", skip_serializing_if = "Option::is_none")]
    pub module_ref: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Lifecycle {
    #[serde(
        rename = "stop_if_idle_for",
        default,
        skip_serializing_if = "is_zero_u64"
    )]
    pub stop_if_idle_for: u64,
    #[serde(
        rename = "destroy_if_idle_for",
        default,
        skip_serializing_if = "is_zero_u64"
    )]
    pub destroy_if_idle_for: u64,
    #[serde(rename = "stop_at_age", default, skip_serializing_if = "is_zero_u64")]
    pub stop_at_age: u64,
    #[serde(
        rename = "destroy_at_age",
        default,
        skip_serializing_if = "is_zero_u64"
    )]
    pub destroy_at_age: u64,
    /// Opts the sandbox into HTTP wake-on-request: auto-stop when idle,
    /// resume on the next inbound HTTP request. Requires `stop_if_idle_for`
    /// to be set; the server rejects `serverless = true` without an idle
    /// window.
    #[serde(default, skip_serializing_if = "is_false")]
    pub serverless: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

pub type UpdateLifecycleOptions = Lifecycle;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Failover {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy: String,
}

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

/// Per-domain lifecycle state surfaced through the API. Mirrors
/// `pkg/models/custom_domain.go::CustomDomainStatus` on the server.
/// - `PendingDns`: row exists, Caddy has not yet asked for the hostname.
/// - `Issuing`: first ask hit, ACME flow started.
/// - `Ready`: cert in shared storage, serving connections.
/// - `Failed`: Caddy gave up on ACME for this host (see `last_error`).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CustomDomainStatus {
    PendingDns,
    Issuing,
    Ready,
    Failed,
}

/// Per-hostname row returned by the custom-domains endpoints. Mirrors
/// `pkg/models.CustomDomain`. `last_error` is only populated when
/// `status == CustomDomainStatus::Failed`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CustomDomain {
    pub hostname: String,
    pub status: CustomDomainStatus,
    #[serde(rename = "last_error", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(rename = "updated_at")]
    pub updated_at: String,
    /// Container port traffic to this hostname dials. `0` (the default) means
    /// the sandbox's toolbox port — preserves the pre-target-port behavior.
    /// Set once at attach time via [`AddCustomDomainOptions::port`].
    #[serde(rename = "target_port", default, skip_serializing_if = "is_zero_u16")]
    pub target_port: u16,
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

/// Options for [`Sandbox::add_custom_domain`]. `port` pins the container port
/// traffic to this hostname dials; leave `None` (or set to `0`) to route to the
/// sandbox's toolbox port (the default). Re-adding the same hostname with a
/// different port returns 409 — detach first.
#[derive(Debug, Clone, Default)]
pub struct AddCustomDomainOptions {
    pub port: Option<u16>,
}

impl AddCustomDomainOptions {
    pub fn with_port(port: u16) -> Self {
        Self { port: Some(port) }
    }
}

/// Wire envelope returned by the custom-domains endpoints — kept private;
/// callers consume the public `Vec<CustomDomain>` instead.
#[derive(Deserialize)]
pub(crate) struct CustomDomainListWire {
    #[serde(rename = "custom_domains", default)]
    pub custom_domains: Vec<CustomDomain>,
}

/// Cluster-published address(es) DNS for a custom domain must point at.
/// Mirrors `pkg/models.IngressTarget` on the server.
///
/// - `source = "hostname"`: cluster advertises a stable hostname — DNS for
///   custom domains is a CNAME to `hostname`.
/// - `source = "ips"`: cluster advertises one or more raw IPs — DNS is one A
///   (and AAAA for IPv6) record per entry in `ips`.
/// - `source = "mixed"`: some ingress nodes gossip a hostname, others gossip
///   raw IPs. Prefer the hostname; render both for apex domains without
///   CNAME flattening.
/// - `source = "unknown"`: no ingress node has gossiped a public address yet.
///   Treat the target as unusable rather than guessing.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct IngressTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<String>,
    pub source: String,
}

/// One DNS row a user must add at their provider to make a custom domain
/// reach the cluster. Mirrors `pkg/models.DNSRecord`. `notes` carries
/// provider-specific gotchas the server pre-renders (e.g. Cloudflare
/// "DNS only, gray cloud" warning) when relevant. `record_type` is one of
/// `CNAME`, `A`, `AAAA`, `ANAME`, or `ALIAS` — the last two appear only for
/// an apex domain on a hostname ingress, as mutually-exclusive flattening
/// alternatives to `CNAME` (add the one your provider supports, per `notes`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub hostname: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Response body for `GET /v1/sandboxes/{id}/custom-domains/dns`. Mirrors
/// `pkg/models.CustomDomainDNSRecords`. `records` is the flat ready-to-paste
/// list (one row per custom domain × per ingress address); `target` is the
/// raw aggregation the records were composed from, so callers can render
/// their own UI without a second fetch.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CustomDomainDnsRecords {
    #[serde(default)]
    pub records: Vec<DnsRecord>,
    pub target: IngressTarget,
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
    /// Owner-node death policy this sandbox was created with. `None` means
    /// the default non-HA behavior.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failover: Option<Failover>,
    /// Container runtime this sandbox is running under. Empty string indicates
    /// a pre-migration row that resolves to the host default at start time.
    #[serde(default)]
    pub runtime: String,
    /// GPU configuration this sandbox was created with. `None` means no GPU
    /// was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpus: Option<GPUOptions>,
    /// Survival class this sandbox was created with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub durability: Option<String>,
    #[serde(rename = "module_ref", skip_serializing_if = "Option::is_none")]
    pub module_ref: Option<String>,
    #[serde(rename = "module_digest", skip_serializing_if = "Option::is_none")]
    pub module_digest: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateSandboxResponse {
    #[serde(flatten)]
    pub sandbox: Sandbox,
    #[serde(rename = "ssh_private_key", skip_serializing_if = "Option::is_none")]
    pub ssh_private_key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SandboxSnapshot {
    pub name: String,
    pub image: String,
    #[serde(rename = "image_id", skip_serializing_if = "Option::is_none")]
    pub image_id: Option<String>,
    #[serde(rename = "source_sandbox_id")]
    pub source_sandbox_id: String,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entrypoint: Vec<String>,
    #[serde(rename = "region_id", skip_serializing_if = "Option::is_none")]
    pub region_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<f64>,
    #[serde(rename = "memory_mb", skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u32>,
    #[serde(rename = "disk_gb", skip_serializing_if = "Option::is_none")]
    pub disk_gb: Option<u32>,
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
    #[serde(
        rename = "last_sampled_at",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_sampled_at: Option<String>,
}

/// Lifecycle states for a Firecracker rootfs template. See the daemon-side
/// plan `snapshot-clone-fast-boot.md` for the state machine.
///
/// - `Pending` / `BuildingRootfs` / `Snapshotting`: build pipeline in
///   flight; sandbox creations against this template will not see fast-boot
///   until the row reaches `Ready`.
/// - `Ready`: cold boot + fast snapshot clone both available.
/// - `ReadyNoSnapshot`: cold boot works; the snapshot phase failed and
///   `snapshot_error` carries the cause.
/// - `Unhealthy`: snapshot was detected as corrupt; a rebuild is in flight
///   (or pending the next daemon restart).
/// - `Failed`: terminal state from a failed initial build; the row must be
///   deleted and recreated.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemplateStatus {
    Pending,
    BuildingRootfs,
    Snapshotting,
    Ready,
    ReadyNoSnapshot,
    Failed,
    Unhealthy,
}

/// Background-push state for a template's artifacts.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemplatePushState {
    Active,
    Pending,
    Pushing,
    Error,
}

/// A Firecracker rootfs template. Created once from an OCI image and
/// boot-shared across many sandboxes. Construct one with
/// [`Client::create_template`]; poll [`Client::get_template`] until
/// `status` reaches `Ready` (fast-boot) or `ReadyNoSnapshot` (cold boot
/// only).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Template {
    pub id: String,
    pub image: String,
    pub status: TemplateStatus,
    #[serde(rename = "rootfs_size_bytes", skip_serializing_if = "Option::is_none")]
    pub rootfs_size_bytes: Option<i64>,
    #[serde(rename = "min_size_mib", skip_serializing_if = "Option::is_none")]
    pub min_size_mib: Option<u32>,
    #[serde(rename = "last_error", skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(rename = "updated_at")]
    pub updated_at: String,
    #[serde(rename = "ready_at", skip_serializing_if = "Option::is_none")]
    pub ready_at: Option<String>,
    #[serde(
        rename = "snapshot_size_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub snapshot_size_bytes: Option<i64>,
    #[serde(rename = "snapshot_error", skip_serializing_if = "Option::is_none")]
    pub snapshot_error: Option<String>,
    #[serde(rename = "has_snapshot")]
    pub has_snapshot: bool,
    #[serde(rename = "has_overlay")]
    pub has_overlay: bool,
    #[serde(rename = "push_state", skip_serializing_if = "Option::is_none")]
    pub push_state: Option<TemplatePushState>,
    #[serde(rename = "push_error", skip_serializing_if = "Option::is_none")]
    pub push_error: Option<String>,
}

/// Request body for [`Client::create_template`]. An explicit `id` lets
/// retried CI steps be idempotent: a duplicate id is rejected with 409 so
/// you don't end up with two rows for the same logical template.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CreateTemplateOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub image: String,
    #[serde(rename = "min_size_mib", skip_serializing_if = "Option::is_none")]
    pub min_size_mib: Option<u32>,
}

/// Catalogue lifecycle for POST /v1/wasm-modules rows.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WasmModuleStatus {
    Ready,
    Failed,
}

/// A WASM module catalogue entry on the host.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WasmModule {
    pub id: String,
    #[serde(rename = "module_ref")]
    pub module_ref: String,
    pub status: WasmModuleStatus,
    #[serde(rename = "module_size_bytes", skip_serializing_if = "Option::is_none")]
    pub module_size_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<String>,
    #[serde(rename = "has_warm")]
    pub has_warm: bool,
    #[serde(rename = "last_error", skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(rename = "updated_at")]
    pub updated_at: String,
    #[serde(rename = "ready_at", skip_serializing_if = "Option::is_none")]
    pub ready_at: Option<String>,
}

/// Request body for [`Client::create_wasm_module`].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateWasmModuleOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "module_ref")]
    pub module_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<String>,
}

/// Input for [`Client::push_wasm_module`]: a BYO compiled core-wasip1 upload.
/// The daemon validates and forwards the bytes to the registry under your own
/// credentials; it never stores them.
#[derive(Debug, Clone, Default)]
pub struct PushWasmModuleOptions {
    /// Target repository path, e.g. `tenant/my-app`.
    pub name: String,
    /// Image tag; defaults to `latest` when empty.
    pub tag: String,
    /// The compiled core-wasip1 module bytes.
    pub module: Vec<u8>,
    /// Registry login (your AOCR username).
    pub registry_username: String,
    /// Registry token (your AOCR PAT). Required.
    pub registry_token: String,
}

/// Result of [`Client::push_wasm_module`].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PushWasmModuleResponse {
    /// The `oci://` ref to pass as `module_ref` on create.
    #[serde(rename = "module_ref")]
    pub module_ref: String,
    /// sha256 content digest of the uploaded module.
    pub digest: String,
    /// Uploaded size in bytes.
    #[serde(rename = "size_bytes")]
    pub size_bytes: i64,
}

/// Patch body for [`Client::set_network_limits`]. Each field is `Option`-wrapped
/// so an unset key serializes as missing (server reads as "leave alone");
/// `Some(0)` means unlimited.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SetNetworkLimitsOptions {
    #[serde(
        rename = "network_bytes_in_limit",
        skip_serializing_if = "Option::is_none"
    )]
    pub network_bytes_in_limit: Option<i64>,
    #[serde(
        rename = "network_bytes_out_limit",
        skip_serializing_if = "Option::is_none"
    )]
    pub network_bytes_out_limit: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: Option<i32>,
    pub base_delay_ms: Option<u64>,
    pub max_delay_ms: Option<u64>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: Some(3),
            base_delay_ms: Some(200),
            max_delay_ms: Some(5000),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ClientConfig {
    pub api_url: Option<String>,
    pub pat_token: Option<String>,
    pub retry: Option<RetryConfig>,
}
