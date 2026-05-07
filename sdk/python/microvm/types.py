from __future__ import annotations

from typing import Callable, Dict, List, TypedDict


class RegistryAuth(TypedDict, total=False):
    server: str
    username: str
    password: str


class CreateOptions(TypedDict, total=False):
    image: str
    cpu: int
    memoryMB: int
    diskGB: int
    env: Dict[str, str]
    osUser: str
    networkBlockAll: bool
    registry: RegistryAuth
    containerCommand: List[str]


class ResizeOptions(TypedDict, total=False):
    cpu: int
    memoryMB: int
    diskGB: int


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
    cpu: int
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


class HealthStatus(TypedDict):
    status: str
    sandboxes: int
    docker: str
    caddy: str
    version: str


class MicroVMConfig(TypedDict, total=False):
    apiUrl: str
    patToken: str
