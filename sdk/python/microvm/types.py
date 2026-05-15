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


class MountSpec(TypedDict, total=False):
    type: MountType
    target: str
    source: str
    options: Dict[str, str]
    credentials: Dict[str, str]
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


UpdateLifecycleOptions = Lifecycle


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
    # cpu accepts fractional cores: 0.5 = half a core, 1.5 = one and a half.
    cpu: float
    memoryMB: int
    diskGB: int
    env: Dict[str, str]
    osUser: str
    networkBlockAll: bool
    # Caps on network bytes the sandbox may receive (in) / send (out) before
    # per-IP iptables block fires. 0 (default) means unlimited; both can be
    # raised or lifted at runtime via set_network_limits.
    networkBytesInLimit: int
    networkBytesOutLimit: int
    registry: RegistryAuth
    containerCommand: List[str]
    mounts: List[MountSpec]
    lifecycle: Lifecycle
    # Container runtime to use for this sandbox. Omit to inherit the host
    # default (SB_CONTAINER_RUNTIME). Use "gvisor" for runsc-backed isolation
    # when running untrusted workloads. "kata" is reserved and rejected by the
    # API today. Not compatible with gpus.
    runtime: Literal["docker", "gvisor", "kata"]
    # Attach GPU resources to the sandbox. Omit for CPU-only workloads.
    # Not compatible with runtime="gvisor".
    gpus: GPUOptions


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


class SandboxSnapshot(TypedDict, total=False):
    name: str
    image: str
    imageID: str
    sourceSandboxID: str
    createdAt: str


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
    toolboxEnabled: bool
    sshPublicKey: str
    sshPrivateKey: str
    exposedPorts: List[ExposedPort]
    createdAt: str
    updatedAt: str
    lastActiveAt: str
    lastError: str
    containerCommand: List[str]
    lifecycle: Lifecycle
    # Container runtime this sandbox is running under. Empty string indicates
    # a pre-migration row that resolves to the host default at start time.
    runtime: Literal["", "docker", "gvisor", "kata"]
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


class MicroVMConfig(TypedDict, total=False):
    apiUrl: str
    patToken: str
