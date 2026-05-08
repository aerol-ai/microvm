from __future__ import annotations

from typing import Callable, Dict, List, Literal, TypedDict


MountType = Literal["s3", "nfs", "sshfs", "rclone"]


class RegistryAuth(TypedDict, total=False):
    server: str
    username: str
    password: str


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


class CreateOptions(TypedDict, total=False):
    image: str
    # cpu accepts fractional cores: 0.5 = half a core, 1.5 = one and a half.
    cpu: float
    memoryMB: int
    diskGB: int
    env: Dict[str, str]
    osUser: str
    networkBlockAll: bool
    registry: RegistryAuth
    containerCommand: List[str]
    mounts: List[MountSpec]
    lifecycle: Lifecycle
    # Container runtime to use for this sandbox. Omit to inherit the host
    # default (SB_CONTAINER_RUNTIME). Use "gvisor" for runsc-backed isolation
    # when running untrusted workloads. "kata" is reserved and rejected by the
    # API today.
    runtime: Literal["docker", "gvisor", "kata"]


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
