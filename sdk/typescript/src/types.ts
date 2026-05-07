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

export interface CreateOptions {
  image: string;
  /** Number of CPU cores to allocate. Fractional values are supported (e.g. 0.5 = half a core). */
  cpu?: number;
  memoryMB?: number;
  diskGB?: number;
  env?: Record<string, string>;
  osUser?: string;
  networkBlockAll?: boolean;
  registry?: RegistryAuth;
  containerCommand?: string[];
  mounts?: MountSpec[];
  lifecycle?: Lifecycle;
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