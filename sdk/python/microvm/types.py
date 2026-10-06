from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Dict, List, Literal, Optional, TypedDict, Union

if TYPE_CHECKING:
    from .image import Image


MountType = Literal["s3", "nfs", "sshfs", "rclone"]


class RegistryAuth(TypedDict, total=False):
    server: str
    username: str
    password: str


class BuildImagePushOptions(TypedDict, total=False):
    """Per-request push directive for :meth:`MicroVM.build_image_with_push`.

    Credentials are forwarded to the daemon as a one-shot ``X-Registry-Auth``
    header on the underlying push call and are never persisted server-side.
    """

    registry: str  # required: e.g. "ghcr.io/my-org/my-image"
    tag: str       # optional: defaults to "latest" on the daemon
    server: str    # optional: serveraddress in X-Registry-Auth
    username: str  # required
    password: str  # required


@dataclass(frozen=True)
class BuildImageResult:
    image: str
    pushed: Optional[str] = None


@dataclass(frozen=True)
class CloneGeneration:
    """Clone-generation marker for a sandbox.

    ``generation`` changes every time the sandbox is resumed from a snapshot
    (i.e. it is a clone). A long-lived process running *inside* the sandbox can
    poll this and reseed its own userspace PRNGs when the token changes — two
    clones otherwise share the snapshot's frozen seed state. Read-only: the SDK
    cannot reseed an in-guest process from the client side. See the "Randomness
    in cloned sandboxes" docs page.
    """

    generation: str
    resumedAt: int = 0


class RegisterSnapshotOptions(TypedDict, total=False):
    name: str
    image: str
    dockerfileContent: str
    contextHashes: List[str]
    entrypoint: List[str]
    regionID: str
    cpu: float
    gpu: float
    memoryMB: int
    diskGB: int


class MountSpec(TypedDict, total=False):
    type: MountType
    target: str
    source: str
    options: Dict[str, str]
    credentials: Dict[str, str]
    readOnly: bool


class PlatformVolumeMount(TypedDict, total=False):
    # Named, operator-backed persistent volume to attach by name. The operator
    # configures the shared backend (S3/NFS); the caller supplies nothing else.
    name: str
    path: str
    readOnly: bool


class MountSpecRedacted(TypedDict, total=False):
    type: MountType
    target: str
    source: str
    options: Dict[str, str]
    readOnly: bool
    hasCredentials: bool


class Lifecycle(TypedDict, total=False):
    # Durations are integer nanoseconds to match the API wire format.
    stopIfIdleFor: int
    destroyIfIdleFor: int
    stopAtAge: int
    destroyAtAge: int
    # serverless=True opts the sandbox into HTTP wake-on-request:
    # auto-stop when idle, resume on the next inbound HTTP request.
    # stopIfIdleFor must also be set explicitly — the server rejects
    # serverless=True without an idle window.
    serverless: bool


UpdateLifecycleOptions = Lifecycle


FailoverPolicy = Literal["none", "recreate"]


class Failover(TypedDict, total=False):
    # "none" (default) returns 410 Gone after owner-node death. "recreate"
    # opts into best-effort cluster recreation from the replicated create spec.
    policy: FailoverPolicy


GPUVendor = Literal["nvidia", "amd", "apple"]


class GPUOptions(TypedDict, total=False):
    """GPU resources to attach to a sandbox at creation time.

    Not compatible with runtime="gvisor" — the API returns an error if both
    gpus and runtime="gvisor" are set.

    vendor values:
    - "nvidia": NVIDIA GPUs via nvidia-container-runtime. Requires
      nvidia-container-toolkit on the host.
    - "amd": AMD GPUs via ROCm (/dev/kfd + /dev/dri). Requires ROCm
      drivers on the host.
    - "apple": Apple Silicon GPU via Docker Desktop's experimental Metal
      support. Only functional on macOS with Docker Desktop.
    """
    vendor: GPUVendor
    # Number of GPUs. -1 = all available. 0/omit = default (1).
    # Ignored for AMD (all AMD GPUs on the host are exposed).
    count: int
    # For NVIDIA: indices ("0", "1") or UUIDs ("GPU-abc123...").
    # For AMD and Apple: ignored.
    deviceIDs: List[str]


class CreateOptions(TypedDict, total=False):
    image: Union[str, "Image"]
    # Optional name, unique among the caller's sandboxes (another account may
    # use the same name); a repeat create with a held name returns HTTP 409.
    # Names starting with "owner:" or shaped like a sandbox ID ("sb-" plus 16
    # hex) are rejected.
    name: str
    # Free-form key/value labels; filter on them with list(tags=...).
    tags: Dict[str, str]
    # cpu accepts fractional cores: 0.5 = half a core, 1.5 = one and a half.
    cpu: float
    memoryMB: int
    diskGB: int
    env: Dict[str, str]
    osUser: str
    networkBlockAll: bool
    # Egress policy. networkAllowOut takes CIDRs, hostnames, *.suffix wildcards
    # and host:port entries; alone the sandbox may reach ONLY these.
    # networkDenyOut takes CIDRs only; alone the sandbox may reach anything
    # EXCEPT these. Both together: allow wins, then deny, then allow by default
    # (a 0.0.0.0/0 deny makes it an allowlist). A full block is networkBlockAll.
    networkAllowOut: List[str]
    networkDenyOut: List[str]
    # Named egress profiles whose entries join networkAllowOut (see
    # put_egress_profile). A profile change reaches every sandbox using it.
    egressProfiles: List[str]
    # "learn" gives the sandbox open egress and records what it reaches, so
    # learned() can suggest an allow list. Trusted runs only. Omitted is
    # "enforce".
    networkEgressMode: str
    # Method and path rules that refine hosts the allow list already admits
    # (at most 32). An inspect rule makes the egress gateway terminate TLS on
    # 443 with the node's CA, which only a sandbox created with such a rule
    # trusts, so set inspect rules here rather than adding them later.
    networkEgressRules: List["EgressRule"]
    # Whether the sandbox may be exposed publicly. Omitted defaults to private
    # (no public URL, expose_port fails). True opts in; False permanently refuses.
    allowPublicTraffic: bool
    # Rewrite the upstream Host header on ingress to exposed HTTP ports to this
    # value so frameworks that validate Host (Vite, Django ALLOWED_HOSTS,
    # webpack-dev-server) accept the request. Empty/unset passes it through.
    # HTTP-only; TCP/TLS exposures ignore it.
    maskRequestHost: str
    # Caps on network bytes the sandbox may receive (in) / send (out) before
    # per-IP iptables block fires. 0 (default) means unlimited; both can be
    # raised or lifted at runtime via set_network_limits.
    networkBytesInLimit: int
    networkBytesOutLimit: int
    registry: RegistryAuth
    containerCommand: List[str]
    mounts: List[MountSpec]
    # Named, operator-backed persistent volumes to attach by name. Requires the
    # operator to have enabled platform volumes (else the create returns 412).
    platformVolumes: List[PlatformVolumeMount]
    lifecycle: Lifecycle
    failover: Failover
    # Container runtime to use for this sandbox. Omit to inherit the host
    # default (SB_CONTAINER_RUNTIME). Use "gvisor" for runsc-backed isolation
    # when running untrusted workloads. "kata" is reserved and rejected by the
    # API today. Not compatible with gpus.
    runtime: Literal["docker", "gvisor", "kata", "firecracker", "wasm", "isolate"]
    # Survival class across daemon restarts. Omit for the runtime default.
    durability: Literal["ephemeral", "passivatable", "durable"]
    # WASM module / isolate bundle reference. When runtime is wasm or isolate,
    # may be used instead of image.
    module_ref: str
    # Isolate-group key for runtime=isolate. Server-authorized; when omitted
    # the group key falls back to the authenticated identity. Ignored by other
    # runtimes.
    tenant_id: str
    # Attach GPU resources to the sandbox. Omit for CPU-only workloads.
    # Not compatible with runtime="gvisor".
    gpus: GPUOptions
    # Operator-provided public hostnames to attach to this sandbox at create
    # time. Server-side cap: ``MaxCustomDomainsPerCreateRequest`` (5). Each
    # host is normalized + validated; the server lowercases for you.
    customDomains: List[str]


class ResizeOptions(TypedDict, total=False):
    cpu: float
    memoryMB: int
    diskGB: int


class CreateSessionOptions(TypedDict, total=False):
    name: str
    argv: List[str]
    command: str
    workDir: str
    env: Dict[str, str]
    pty: bool
    cols: int
    rows: int


class ExecRequest(TypedDict, total=False):
    command: str
    workDir: str
    env: Dict[str, str]
    timeoutSeconds: int


class ExecResult(TypedDict):
    stdout: str
    stderr: str
    exitCode: int
    durationMS: int


ChunkCallback = Callable[[bytes], None]
ErrorCallback = Callable[[str], None]


class ExecStreamOptions(TypedDict, total=False):
    command: str
    workdir: str
    env: Dict[str, str]
    tty: bool
    cols: int
    rows: int
    onStdout: ChunkCallback
    onStderr: ChunkCallback
    onError: ErrorCallback


class ExecExitInfo(TypedDict, total=False):
    code: int
    signal: str


SessionStatus = Literal["running", "exited", "killed", "failed"]


class Session(TypedDict, total=False):
    id: str
    name: str
    argv: List[str]
    workDir: str
    pty: bool
    status: SessionStatus
    exitCode: int
    exitSignal: str
    createdAt: str
    startedAt: str
    exitedAt: str
    recording: bool
    bytes: int
    attached: int


ExitCallback = Callable[[ExecExitInfo], None]


class SessionAttachOptions(TypedDict, total=False):
    onStdout: ChunkCallback
    onStderr: ChunkCallback
    onError: ErrorCallback
    onExit: ExitCallback
    cols: int
    rows: int


class ExposedPort(TypedDict, total=False):
    sandboxID: str
    port: int
    publicURL: str
    createdAt: str


# Per-domain lifecycle state surfaced through the API. Mirrors
# pkg/models/custom_domain.go::CustomDomainStatus on the server.
# - "pending_dns": row exists, Caddy has not yet asked for the hostname.
# - "issuing":     first ask hit, ACME flow started.
# - "ready":       cert in shared storage, serving connections.
# - "failed":      Caddy gave up on ACME for this host (see ``lastError``).
CustomDomainStatus = Literal["pending_dns", "issuing", "ready", "failed"]


class CustomDomain(TypedDict, total=False):
    """Per-hostname row returned by the custom-domains endpoints.

    Mirrors ``pkg/models.CustomDomain``. ``lastError`` is only present when
    ``status == "failed"``.
    """

    hostname: str
    status: CustomDomainStatus
    lastError: str
    createdAt: str
    updatedAt: str
    # Container port traffic to this hostname dials. 0 (or absent) means the
    # sandbox's toolbox port (the default). Set once at attach time.
    targetPort: int


class IngressTarget(TypedDict, total=False):
    """DNS target a custom hostname should point at to reach this daemon.

    Mirrors ``pkg/models.IngressTarget`` on the server. ``source`` is one of
    ``"hostname"``, ``"ips"``, ``"mixed"``, or ``"unknown"`` and describes
    the shape of the target (NOT how it was resolved):

    - ``"hostname"`` — ``hostname`` is set; DNS for custom domains is a
      CNAME to it.
    - ``"ips"`` — ``ips`` is populated; DNS is one A/AAAA per IP.
    - ``"mixed"`` — both fields populated (ingress nodes advertise a mix);
      callers should prefer hostname for subdomains and IPs at apex.
    - ``"unknown"`` — no usable target; callers should render an
      operator-must-configure-ingress error rather than fake records.
    """

    hostname: str
    ips: List[str]
    source: str


class DNSRecord(TypedDict, total=False):
    """Single DNS record the operator should create for a custom hostname.

    Mirrors ``pkg/models.DNSRecord`` on the server. ``notes`` is optional and
    only set when the server has additional human-readable guidance to attach
    (TTL recommendations, CNAME vs A choice rationale, etc.).

    ``type`` is one of ``CNAME``, ``A``, ``AAAA``, ``ANAME``, or ``ALIAS``. The
    last two appear only for an apex domain on a hostname ingress, as
    mutually-exclusive flattening alternatives to ``CNAME`` — add the one your
    DNS provider supports (see ``notes``).
    """

    hostname: str
    type: str
    name: str
    value: str
    notes: str


class CustomDomainDNSRecords(TypedDict, total=False):
    """Response shape of ``GET /sandboxes/{id}/custom-domains/dns``.

    Bundles the per-hostname records the operator needs to publish with the
    underlying :class:`IngressTarget` that all hostnames ultimately resolve
    to, so a caller can render a single instruction list without a follow-up
    call to :meth:`MicroVM.dns_target`.
    """

    records: List[DNSRecord]
    target: IngressTarget


class SandboxSnapshot(TypedDict, total=False):
    name: str
    image: str
    imageID: str
    sourceSandboxID: str
    createdAt: str
    entrypoint: List[str]
    regionID: str
    cpu: float
    gpu: float
    memoryMB: int
    diskGB: int


# Wire protocol an exposure publishes through. "http" maps to the Caddy HTTP
# reverse proxy; "tcp" and "tls" map to caddy-l4 surfaces.
ExposeProtocol = Literal["http", "tcp", "tls"]


@dataclass(frozen=True)
class ExposeResult:
    """Result of ``MicroVM.expose_port`` / ``Sandbox.expose_port``.

    ``host`` and ``host_port`` are populated only when ``protocol == "tcp"`` —
    they are what native protocol clients (psql, redis-cli, mysql, mongosh)
    need to dial. For ``"http"`` and ``"tls"`` exposures the dialable URL is
    in ``url`` and the host/port fields are ``None``.
    """

    protocol: ExposeProtocol
    url: str
    host: Optional[str] = None
    host_port: Optional[int] = None


class SandboxData(TypedDict, total=False):
    id: str
    # Name set at create time, unique per owner. Absent for unnamed sandboxes.
    name: str
    tags: Dict[str, str]
    image: str
    status: str
    publicURL: str
    containerID: str
    containerIP: str
    cpu: float
    memoryMB: int
    diskGB: int
    osUser: str
    env: Dict[str, str]
    networkBlockAll: bool
    # Hostname-egress state on get (container runtimes): "active", "held" or
    # "unavailable". Absent otherwise.
    egressStatus: str
    # Egress profiles this sandbox references, and the generation of each
    # that is live on it.
    egressProfiles: List[str]
    egressProfilesApplied: List["EgressProfileRef"]
    # "learn" while the sandbox records its egress; absent otherwise.
    networkEgressMode: str
    # Method and path rules on the sandbox's egress; absent when it has none.
    networkEgressRules: List["EgressRule"]
    toolboxEnabled: bool
    sshPublicKey: str
    sshPrivateKey: str
    exposedPorts: List[ExposedPort]
    customDomains: List[CustomDomain]
    createdAt: str
    updatedAt: str
    lastActiveAt: str
    lastError: str
    containerCommand: List[str]
    lifecycle: Lifecycle
    failover: Failover
    # Container runtime this sandbox is running under. Empty string indicates
    # a pre-migration row that resolves to the host default at start time.
    runtime: Literal["", "docker", "gvisor", "kata", "firecracker", "wasm", "isolate"]
    durability: Literal["ephemeral", "passivatable", "durable"]
    module_ref: str
    module_digest: str
    # Isolate-group key this sandbox was created under (runtime=isolate only).
    tenant_id: str
    # GPU configuration this sandbox was created with. Absent means no GPU.
    gpus: GPUOptions


class NetworkUsage(TypedDict, total=False):
    sandboxID: str
    bytesIn: int
    bytesOut: int
    bytesInLimit: int
    bytesOutLimit: int
    quotaExceeded: bool
    quotaExceededAt: str
    # Absent until the netstats poller has produced at least one sample.
    lastSampledAt: str


class AuditEvent(TypedDict, total=False):
    """One record from a sandbox's audit log (``sandbox.audit()``).

    ``kind`` is ``"egress"`` for outbound connections and denials; a denial
    has ``result`` ``"failure"`` and the policy ``reason``
    (``"host_not_allowed"``, ``"sni_not_allowed"``, ...).
    """

    time: str
    kind: str
    result: str
    reason: str
    destination: str
    network: str
    actor: str
    ref: str
    eventID: str
    incarnationID: str
    dropped: int


class AuditCoverage(TypedDict):
    answered: List[str]
    missing: List[str]
    partial: bool


class AuditPage(TypedDict, total=False):
    events: List[AuditEvent]
    coverage: AuditCoverage
    # Pass to ``audit({"cursor": ...})`` for the next page.
    nextCursor: str


class AuditOptions(TypedDict, total=False):
    kind: str
    limit: int
    cursor: str
    incarnationID: str


class NetworkPolicyCheckOptions(TypedDict, total=False):
    """Would a sandbox created with these egress fields reach ``destination``?

    ``destination`` is "host", "host:port", "IP" or "IP:port"; a bare host is
    checked as the web ports.
    """

    networkBlockAll: bool
    networkAllowOut: List[str]
    networkDenyOut: List[str]
    destination: str


class NetworkPolicyCheckResult(TypedDict, total=False):
    allowed: bool
    # The entry that decided; "" when the default verdict did.
    matchedRule: str
    # "allow" or "deny": what happens to a destination no entry matches.
    defaultVerdict: str
    # The first allow entry outside this deployment's ceiling, if any.
    outsideCeiling: str


class EgressProfileRef(TypedDict):
    name: str
    generation: int


class EgressProfile(TypedDict, total=False):
    """A named allowlist sandboxes reference through ``egressProfiles``.
    Profiles belong to your account; ``generation`` goes up on every change."""

    name: str
    # Hostnames, *. wildcards, host:port entries and CIDRs (at most 512 hostnames).
    allowOut: List[str]
    description: str
    generation: int
    createdAt: str
    updatedAt: str


class EgressProfileOptions(TypedDict, total=False):
    """The body of ``put_egress_profile``: a full replace."""

    allowOut: List[str]
    description: str


class ListEgressProfilesOptions(TypedDict, total=False):
    cursor: str
    limit: int


class EgressProfileList(TypedDict, total=False):
    profiles: List[EgressProfile]
    # Pass back as ``cursor`` for the next page; absent on the last one.
    nextCursor: str


class NetworkPolicyOptions(TypedDict, total=False):
    """A sandbox's whole egress policy, for ``set_network_policy``.

    It replaces the current policy: a key left out is cleared, so ``{}``
    means open egress. The grammar is the create one (hostnames, ``*.``
    wildcards, ``host:port`` and CIDRs in the allow list; CIDRs only in the
    deny list).
    """

    networkBlockAll: bool
    networkAllowOut: List[str]
    networkDenyOut: List[str]
    egressProfiles: List[str]
    networkEgressMode: str
    # Replaces the method and path rules. Adding an inspect rule to a
    # container sandbox created without one is refused with 409: recreate it
    # with the rule.
    networkEgressRules: List["EgressRule"]


class NetworkPolicy(TypedDict, total=False):
    networkBlockAll: bool
    networkAllowOut: List[str]
    networkDenyOut: List[str]
    egressProfiles: List[str]
    # "enforce" or "learn".
    networkEgressMode: str
    networkEgressRules: List["EgressRule"]
    # Hostname entries in force: inline plus every profile's (at most 1024).
    effectiveHostnameCount: int
    # "active", "held" or "unavailable" for hostname rules on a container.
    egressStatus: str


class EgressRule(TypedDict, total=False):
    """One method and path rule. Rules refine a host the allow list
    already admits: a request to a ruled host passes when some rule for that
    host admits its method and path, and gets a 403 otherwise. A host no rule
    names keeps its allow-list decision."""

    # An exact name or "*." wildcard, without a port. Required.
    host: str
    # [80] by default, or [443] with inspect; only 80 and 443.
    ports: List[int]
    # Exact, upper case ("GET", "POST"); empty allows any.
    methods: List[str]
    # Path globs: "*" within one segment, "**" as a whole segment for any
    # number of them. Empty allows any path.
    paths: List[str]
    # Terminate TLS on 443 with the node's CA so the rule can see requests.
    # The request's Host must then equal the TLS server name.
    inspect: bool
    # Replace a header on the requests this rule allows with a secret from
    # the sandbox's own env, which the sandbox itself only sees as a
    # placeholder. Needs inspect.
    inject: "EgressInject"


class EgressInject(TypedDict):
    """A rule's credential injection. The sandbox's env holds
    ``aerolvm-placeholder:<KEY>`` in place of the value, and the egress
    gateway replaces ``header`` with the real value on each request the rule
    allows, so code in the sandbox never holds the secret."""

    # The header to replace, such as "Authorization". It is replaced, never
    # added to a body or URL. Headers that frame or route the request, such
    # as Host or Content-Length, can't be injected.
    header: str
    # "env:<KEY>": a key in the create's env, whose value is the whole header
    # value (for example "Bearer ghp_..."). Sent as secret_ref on the wire.
    # Rotating it means recreating the sandbox.
    secretRef: str


class NetworkLearnedEntry(TypedDict, total=False):
    host: str
    # Connection ports; empty when the name was only resolved.
    ports: List[int]
    firstSeen: str
    lastSeen: str
    hits: int


class NetworkLearned(TypedDict, total=False):
    """What a sandbox reached in learn mode, and the allow list that would
    have allowed it: ``suggestedAllowOut`` when it fits 64 hostnames,
    otherwise ``suggestedProfile`` (a body for ``put_egress_profile``)."""

    mode: str
    truncated: bool
    entries: List[NetworkLearnedEntry]
    cidrs: List[str]
    suggestedAllowOut: List[str]
    suggestedProfile: "EgressProfileOptions"


class SetNetworkLimitsOptions(TypedDict, total=False):
    # Omit a key to leave that direction unchanged. 0 means unlimited.
    networkBytesInLimit: int
    networkBytesOutLimit: int


class HealthStatus(TypedDict):
    status: str
    sandboxes: int
    docker: str
    caddy: str
    sshGateway: str
    version: str


class RetryConfig(TypedDict, total=False):
    maxRetries: int
    baseDelayMs: int
    maxDelayMs: int


class MicroVMConfig(TypedDict, total=False):
    apiUrl: str
    patToken: str
    retry: RetryConfig


# Firecracker rootfs templates. The lifecycle mirrors the daemon's
# state machine; see plans/snapshot-clone-fast-boot.md for the
# transitions. A template is created once from an OCI image and
# boot-shared across many sandboxes; the SDK exposes CRUD + rebuild on
# the MicroVM client so application code can drive the pipeline.
TemplateStatus = Literal[
    "pending",
    "building_rootfs",
    "snapshotting",
    "ready",
    "ready_no_snapshot",
    "failed",
    "unhealthy",
]


TemplatePushState = Literal["active", "pending", "pushing", "error"]


class CreateTemplateOptions(TypedDict, total=False):
    # Optional explicit ID — supplying one lets retries be idempotent
    # (a duplicate ID returns 409). Omit to let the daemon generate.
    id: str
    image: str  # required: skopeo-style ref, e.g. "docker://python:3.11"
    minSizeMiB: int  # optional ext4 floor


class Template(TypedDict, total=False):
    id: str
    image: str
    status: TemplateStatus
    rootfsSizeBytes: int
    minSizeMiB: int
    lastError: str
    createdAt: str
    updatedAt: str
    readyAt: str
    snapshotSizeBytes: int
    snapshotError: str
    hasSnapshot: bool
    hasOverlay: bool
    pushState: TemplatePushState
    pushError: str


WasmModuleStatus = Literal["ready", "failed"]


class CreateWasmModuleOptions(TypedDict, total=False):
    id: str
    moduleRef: str  # required
    entrypoint: str


class WasmModule(TypedDict, total=False):
    id: str
    moduleRef: str
    status: WasmModuleStatus
    moduleSizeBytes: int
    digest: str
    entrypoint: str
    hasWarm: bool
    lastError: str
    createdAt: str
    updatedAt: str
    readyAt: str


class PushWasmModuleOptions(TypedDict, total=False):
    name: str  # required: target repo path, e.g. "tenant/my-app"
    tag: str  # defaults to "latest"
    module: bytes  # required: compiled core-wasip1 bytes
    registryUsername: str
    registryToken: str  # required: your registry PAT


class PushWasmModuleResult(TypedDict, total=False):
    moduleRef: str
    digest: str
    sizeBytes: int
