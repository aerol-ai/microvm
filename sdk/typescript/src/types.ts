export type SandboxStatus = "creating" | "started" | "stopped" | "destroyed" | "error";

export interface RegistryAuth {
  server: string;
  username: string;
  password: string;
}

export interface CreateOptions {
  image: string;
  cpu?: number;
  memoryMB?: number;
  diskGB?: number;
  env?: Record<string, string>;
  osUser?: string;
  networkBlockAll?: boolean;
  registry?: RegistryAuth;
  containerCommand?: string[];
}

export interface ResizeOptions {
  cpu?: number;
  memoryMB?: number;
  diskGB?: number;
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
  exposedPorts?: ExposedPort[];
  createdAt: string;
  updatedAt: string;
  lastActiveAt: string;
  lastError?: string;
  containerCommand?: string[];
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

export interface HealthStatus {
  status: string;
  sandboxes: number;
  docker: string;
  caddy: string;
  version: string;
}

export type BinaryLike = Uint8Array | ArrayBuffer | Blob | string;