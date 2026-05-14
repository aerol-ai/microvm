export type SandboxStatus = "creating" | "started" | "stopped" | "destroyed" | "error";

export interface RegistryAuth {
  server: string;
  username: string;
  password: string;
}

export type MountType = "s3" | "nfs" | "sshfs" | "rclone";

export interface MountSpec {
  type: MountType;
  target: string;
  source: string;
  options?: Record<string, string>;
  credentials?: Record<string, string>;
  readOnly?: boolean;
}

export interface MountSpecRedacted {
  type: MountType;
  target: string;
  source: string;
  options?: Record<string, string>;
  readOnly: boolean;
  hasCredentials: boolean;
}

export interface Lifecycle {
  /** Duration in integer nanoseconds. */
  stopIfIdleFor?: number;
  /** Duration in integer nanoseconds. */
  destroyIfIdleFor?: number;
  /** Duration in integer nanoseconds. */
  stopAtAge?: number;
  /** Duration in integer nanoseconds. */
  destroyAtAge?: number;
}

export type UpdateLifecycleOptions = Lifecycle;

export type GPUVendor = "nvidia" | "amd" | "apple";

export interface GPUOptions {
  /**
   * GPU hardware vendor. Required when gpus is set.
   * - "nvidia": NVIDIA GPUs via nvidia-container-runtime. Requires
   *   nvidia-container-toolkit on the host.
   * - "amd": AMD GPUs via ROCm (/dev/kfd + /dev/dri). Requires ROCm
   *   drivers on the host.
   * - "apple": Apple Silicon GPU via Docker Desktop's experimental Metal
   *   support. Only functional on macOS with Docker Desktop.
   *
   * GPU access is not supported with runtime="gvisor" — the API returns
   * an error if both gpus and runtime="gvisor" are set.
   */
  vendor: GPUVendor;
  /**
   * Number of GPUs to allocate. Use -1 to request all GPUs on the host.
   * Defaults to 1 when omitted. Ignored for AMD (all AMD GPUs are exposed
   * via /dev/kfd and /dev/dri).
   */
  count?: number;
  /**
   * Pin the sandbox to specific GPU device indices or UUIDs.
   * For NVIDIA: indices ("0", "1") or UUIDs ("GPU-abc123...").
   * For AMD and Apple: ignored.
   */
  deviceIDs?: string[];
}

import type { Image } from "./Image.js";

export interface CreateOptions {
  /**
   * The base image for this sandbox. A bare image reference (e.g.
   * `"ubuntu:22.04"`) is pulled by the daemon as-is. An {@link Image} builder
   * is compiled to a Dockerfile and sent to the daemon's
   * `POST /v1/images/build` endpoint; the resulting content-addressed tag is
   * used for the sandbox. The daemon must have an image builder configured
   * (every official deployment does); otherwise the build call returns 503.
   */
  image: string | Image;
  /** Number of CPU cores to allocate. Fractional values are supported (e.g. 0.5 = half a core). */
  cpu?: number;
  memoryMB?: number;
  diskGB?: number;
  env?: Record<string, string>;
  osUser?: string;
  networkBlockAll?: boolean;
  /**
   * Cap on bytes the sandbox may receive from outside the container before its
   * ingress is dropped via per-IP iptables rule. `0` (default) is unlimited.
   * Limits can be raised or lifted at runtime via `setNetworkLimits`.
   */
  networkBytesInLimit?: number;
  /**
   * Cap on bytes the sandbox may send to outside the container before its
   * egress is dropped. `0` (default) is unlimited. The block reuses the same
   * iptables row as `networkBlockAll`; clearing the quota does not lift an
   * operator-set blanket egress block.
   */
  networkBytesOutLimit?: number;
  registry?: RegistryAuth;
  containerCommand?: string[];
  mounts?: MountSpec[];
  lifecycle?: Lifecycle;
  /**
   * Container runtime to use for this sandbox. Omit to inherit the host
   * default (`SB_CONTAINER_RUNTIME`). Use `"gvisor"` for runsc-backed
   * isolation when running untrusted workloads — note that gVisor rejects
   * privileged containers and ignores per-sandbox disk quotas. `"kata"` is
   * reserved for future Kata Containers support and is rejected by the API
   * today.
   *
   * GPU access is not supported with `"gvisor"`.
   */
  runtime?: "docker" | "gvisor" | "kata";
  /**
   * Attach GPU resources to the sandbox. Omit for CPU-only workloads.
   * Not compatible with runtime="gvisor".
   */
  gpus?: GPUOptions;
}

export interface ResizeOptions {
  /** Number of CPU cores. Fractional values supported (e.g. 0.5). */
  cpu?: number;
  memoryMB?: number;
  diskGB?: number;
}

export interface CreateSessionOptions {
  name?: string;
  argv?: string[];
  command?: string;
  workDir?: string;
  env?: Record<string, string>;
  pty?: boolean;
  cols?: number;
  rows?: number;
}

export type SessionStatus = "running" | "exited" | "killed" | "failed";

export interface Session {
  id: string;
  name: string;
  argv: string[];
  workDir?: string;
  pty: boolean;
  status: SessionStatus;
  exitCode: number;
  exitSignal?: string;
  createdAt: string;
  startedAt: string;
  exitedAt?: string;
  recording: boolean;
  bytes: number;
  attached: number;
}

export interface ExposedPort {
  sandboxID: string;
  port: number;
  publicURL: string;
  createdAt: string;
}

/**
 * Wire protocol an exposure publishes through:
 *   - "http": Caddy HTTP reverse proxy at https://<id>-<port>.<domain>.
 *   - "tcp":  raw caddy-l4 listener on a parent-host port.
 *   - "tls":  caddy-l4 TLS-SNI route on the shared :443 listener.
 */
export type ExposeProtocol = "http" | "tcp" | "tls";

export interface ExposePortOptions {
  /** Defaults to "http" when omitted. */
  protocol?: ExposeProtocol;
}

export interface SandboxSnapshot {
  name: string;
  image: string;
  imageID?: string;
  sourceSandboxID: string;
  createdAt: string;
}

/**
 * Discriminated result from `exposePort`. Branch on `protocol` to access the
 * fields that are meaningful for the chosen wire protocol — only the raw-TCP
 * variant carries `host` and `hostPort`, which are what native protocol
 * clients (psql, redis-cli, mysql, mongosh, …) need to dial.
 */
export type ExposeResult =
  | { protocol: "http"; url: string }
  | { protocol: "tcp"; url: string; host: string; hostPort: number }
  | { protocol: "tls"; url: string };

export interface Sandbox {
  id: string;
  image: string;
  status: SandboxStatus;
  publicURL: string;
  containerID?: string;
  containerIP?: string;
  cpu: number;
  memoryMB: number;
  diskGB: number;
  osUser: string;
  env?: Record<string, string>;
  networkBlockAll: boolean;
  toolboxEnabled: boolean;
  sshPublicKey?: string;
  sshPrivateKey?: string;
  exposedPorts?: ExposedPort[];
  createdAt: string;
  updatedAt: string;
  lastActiveAt: string;
  lastError?: string;
  containerCommand?: string[];
  lifecycle: Lifecycle;
  /**
   * Container runtime this sandbox is running under. Empty string indicates
   * a pre-migration row that resolves to the host default at start time.
   */
  runtime: "" | "docker" | "gvisor" | "kata";
  /** GPU configuration this sandbox was created with. Absent means no GPU. */
  gpus?: GPUOptions;
}

/**
 * Per-sandbox network byte counters and the configured caps that drive the
 * quota enforcer. `bytesIn` is traffic the container received (ingress);
 * `bytesOut` is traffic the container sent (egress). A `*Limit` of `0` means
 * unlimited. `quotaExceeded` flips true the first time the meter crosses
 * either configured cap and stays true until the operator raises the limit.
 */
export interface NetworkUsage {
  sandboxID: string;
  bytesIn: number;
  bytesOut: number;
  bytesInLimit: number;
  bytesOutLimit: number;
  quotaExceeded: boolean;
  quotaExceededAt?: string;
  /** Absent until the netstats poller has produced at least one sample. */
  lastSampledAt?: string;
}

export interface SetNetworkLimitsOptions {
  /** Omit (undefined) to leave unchanged. `0` means unlimited. */
  networkBytesInLimit?: number;
  networkBytesOutLimit?: number;
}

export interface ExecRequest {
  command: string;
  workDir?: string;
  env?: Record<string, string>;
  timeoutSeconds?: number;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMS: number;
}

export interface ExecStreamOptions {
  command: string;
  workdir?: string;
  env?: Record<string, string>;
  tty?: boolean;
  cols?: number;
  rows?: number;
  onStdout?: (chunk: Uint8Array) => void;
  onStderr?: (chunk: Uint8Array) => void;
  onError?: (message: string) => void;
}

export interface ExecExitInfo {
  code: number;
  signal?: string;
}

export interface ExecStreamHandle {
  /** Send raw stdin bytes (or a UTF-8 string) to the process. */
  write(data: Uint8Array | string): void;
  /** PTY mode only — tell the process its terminal size has changed. */
  resize(cols: number, rows: number): void;
  /** Send a signal (e.g. "INT", "TERM") to the process group. */
  signal(name: string): void;
  /** Close stdin and gracefully end the stream. The process keeps running until it exits on its own. */
  close(): void;
  /** Resolves when the process exits, with its final exit code/signal. */
  done: Promise<ExecExitInfo>;
}

export interface SessionAttachOptions {
  onStdout?: (chunk: Uint8Array) => void;
  onStderr?: (chunk: Uint8Array) => void;
  onExit?: (info: ExecExitInfo) => void;
  onError?: (message: string) => void;
  cols?: number;
  rows?: number;
}

export interface SessionAttachHandle {
  /** Send raw stdin bytes (or a UTF-8 string) to the attached session. */
  write(data: Uint8Array | string): void;
  /** PTY sessions only — tell the session its terminal size has changed. */
  resize(cols: number, rows: number): void;
  /** Send a signal (e.g. "INT", "TERM", "KILL") to the session process group. */
  signal(name: string): void;
  /** Detach from the live stream without killing the session. */
  close(): void;
  /** Resolves when the session exits, or rejects if the attach stream drops first. */
  done: Promise<ExecExitInfo>;
}

export interface HealthStatus {
  status: string;
  sandboxes: number;
  docker: string;
  caddy: string;
  sshGateway: string;
  version: string;
}

export type BinaryLike = Uint8Array | ArrayBuffer | Blob | string;