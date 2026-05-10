import { basename } from "node:path";

import type {
  BinaryLike,
  CreateOptions,
  CreateSessionOptions,
  ExecExitInfo,
  ExecRequest,
  ExecResult,
  ExecStreamHandle,
  ExecStreamOptions,
  ExposedPort,
  HealthStatus,
  Lifecycle,
  MountSpec,
  MountSpecRedacted,
  ResizeOptions,
  Sandbox,
  Session,
  SessionAttachHandle,
  SessionAttachOptions,
} from "../types.js";

type FetchLike = typeof fetch;

export interface APIClientConfig {
  baseURL: string;
  patToken?: string;
  fetch?: FetchLike;
}

interface ApiExposedPort {
  sandbox_id: string;
  port: number;
  public_url: string;
  created_at: string;
}

interface ApiLifecycle {
  stop_if_idle_for?: number;
  destroy_if_idle_for?: number;
  stop_at_age?: number;
  destroy_at_age?: number;
}

interface ApiSandbox {
  id: string;
  image: string;
  status: Sandbox["status"];
  public_url: string;
  container_id?: string;
  container_ip?: string;
  cpu: number;
  memory_mb: number;
  disk_gb: number;
  os_user: string;
  env?: Record<string, string>;
  network_block_all: boolean;
  toolbox_enabled: boolean;
  ssh_public_key?: string;
  exposed_ports?: ApiExposedPort[];
  created_at: string;
  updated_at: string;
  last_active_at: string;
  last_error?: string;
  container_command?: string[];
  lifecycle?: ApiLifecycle;
  runtime?: string;
}

interface ApiCreateSandboxResponse extends ApiSandbox {
  ssh_private_key?: string;
}

interface ApiSession {
  id: string;
  name: string;
  argv: string[];
  workdir?: string;
  pty: boolean;
  status: Session["status"];
  exit_code: number;
  exit_signal?: string;
  created_at: string;
  started_at: string;
  exited_at?: string;
  recording: boolean;
  bytes: number;
  attached: number;
}

interface ApiSessionList {
  sessions: ApiSession[];
}

interface ApiExecResult {
  stdout: string;
  stderr: string;
  exit_code: number;
  duration_ms: number;
}

interface ApiHealthStatus {
  status: string;
  sandboxes: number;
  docker: string;
  caddy: string;
  ssh_gateway?: string;
  version: string;
}

interface ApiMountSpec {
  type: MountSpec["type"];
  target: string;
  source: string;
  options?: Record<string, string>;
  credentials?: Record<string, string>;
  read_only?: boolean;
}

interface ApiMountSpecRedacted {
  type: MountSpecRedacted["type"];
  target: string;
  source: string;
  options?: Record<string, string>;
  read_only?: boolean;
  has_credentials: boolean;
}

interface ApiMountList {
  mounts: ApiMountSpecRedacted[];
}

export class APIClient {
  readonly baseURL: string;

  private readonly patToken: string;
  private readonly fetchFn: FetchLike;

  constructor(config: APIClientConfig) {
    this.baseURL = config.baseURL.replace(/\/+$/, "");
    this.patToken = config.patToken ?? "";
    this.fetchFn = config.fetch ?? fetch;
  }

  async create(options: CreateOptions): Promise<SandboxResource> {
    const response = await this.doJSON<ApiCreateSandboxResponse>("POST", "/v1/sandboxes", toApiCreateOptions(options));
    return new SandboxResource(this, fromApiCreateSandboxResponse(response));
  }

  async list(): Promise<SandboxResource[]> {
    const response = await this.doJSON<ApiSandbox[]>("GET", "/v1/sandboxes");
    return response.map((item) => this.wrap(item));
  }

  async get(id: string): Promise<SandboxResource> {
    const response = await this.doJSON<ApiSandbox>("GET", `/v1/sandboxes/${id}`);
    return this.wrap(response);
  }

  async start(id: string): Promise<SandboxResource> {
    const response = await this.doJSON<ApiSandbox>("POST", `/v1/sandboxes/${id}/start`);
    return this.wrap(response);
  }

  async stop(id: string): Promise<SandboxResource> {
    const response = await this.doJSON<ApiSandbox>("POST", `/v1/sandboxes/${id}/stop`);
    return this.wrap(response);
  }

  async destroy(id: string): Promise<void> {
    await this.doJSON<void>("DELETE", `/v1/sandboxes/${id}`);
  }

  async resize(id: string, options: ResizeOptions): Promise<SandboxResource> {
    const response = await this.doJSON<ApiSandbox>("POST", `/v1/sandboxes/${id}/resize`, toApiResizeOptions(options));
    return this.wrap(response);
  }

  async updateLifecycle(id: string, lifecycle: Lifecycle): Promise<SandboxResource> {
    const response = await this.doJSON<ApiSandbox>("PUT", `/v1/sandboxes/${id}/lifecycle`, toApiLifecycle(lifecycle));
    return this.wrap(response);
  }

  async exec(id: string, request: ExecRequest): Promise<ExecResult> {
    const response = await this.doJSON<ApiExecResult>("POST", `/v1/sandboxes/${id}/toolbox/process/execute`, toApiExecRequest(request));
    return fromApiExecResult(response);
  }

  execStream(id: string, options: ExecStreamOptions): ExecStreamHandle {
    return openExecStream(this.baseURL, this.patToken, id, options);
  }

  async createSession(id: string, options: CreateSessionOptions): Promise<Session> {
    const response = await this.doJSON<ApiSession>("POST", `/v1/sandboxes/${id}/sessions`, toApiCreateSessionOptions(options));
    return fromApiSession(response);
  }

  async listSessions(id: string): Promise<Session[]> {
    const response = await this.doJSON<ApiSessionList>("GET", `/v1/sandboxes/${id}/sessions`);
    return response.sessions.map(fromApiSession);
  }

  async getSession(id: string, sessionID: string): Promise<Session> {
    const response = await this.doJSON<ApiSession>("GET", `/v1/sandboxes/${id}/sessions/${sessionID}`);
    return fromApiSession(response);
  }

  async deleteSession(id: string, sessionID: string): Promise<void> {
    await this.doJSON<void>("DELETE", `/v1/sandboxes/${id}/sessions/${sessionID}`);
  }

  async signalSession(id: string, sessionID: string, signal: string): Promise<void> {
    await this.doJSON<void>("POST", `/v1/sandboxes/${id}/sessions/${sessionID}/signal`, { signal });
  }

  async resizeSession(id: string, sessionID: string, cols: number, rows: number): Promise<void> {
    await this.doJSON<void>("POST", `/v1/sandboxes/${id}/sessions/${sessionID}/resize`, { cols, rows });
  }

  async sessionLog(id: string, sessionID: string): Promise<Uint8Array> {
    return this.doBytes(`/v1/sandboxes/${id}/sessions/${sessionID}/log`);
  }

  async sessionRecording(id: string, sessionID: string): Promise<Uint8Array> {
    return this.doBytes(`/v1/sandboxes/${id}/sessions/${sessionID}/recording`);
  }

  attachSession(id: string, sessionID: string, options: SessionAttachOptions = {}): SessionAttachHandle {
    return openSessionAttach(this.baseURL, this.patToken, id, sessionID, options);
  }

  async uploadFile(id: string, targetPath: string, data: BinaryLike): Promise<void> {
    const form = new FormData();
    form.set("path", targetPath);
    form.set("file", toBlob(data), basename(targetPath));

    const response = await this.request("POST", `/v1/sandboxes/${id}/toolbox/files/upload`, { body: form });
    if (!response.ok) {
      throw await decodeError(response);
    }
  }

  async downloadFile(id: string, targetPath: string): Promise<Uint8Array> {
    const response = await this.request("GET", `/v1/sandboxes/${id}/toolbox/files/download?path=${encodeURIComponent(targetPath)}`);
    if (!response.ok) {
      throw await decodeError(response);
    }
    return new Uint8Array(await response.arrayBuffer());
  }

  async exposePort(id: string, port: number): Promise<string> {
    return this.exposePortWithProtocol(id, port);
  }

  /**
   * Publish a raw TCP port through caddy-l4. The returned URL is in
   * `tcp://<host>:<port>` form and works directly with `psql`, `redis-cli`,
   * `mysql`, `mongosh`, and any other native-protocol client.
   */
  async exposeTCPPort(id: string, port: number): Promise<string> {
    return this.exposePortWithProtocol(id, port, "tcp");
  }

  /**
   * Publish a TCP port behind the shared TLS-SNI multiplexer. Returns
   * `tls://<id>-<port>.<domain>:<l4-port>`. Requires the daemon to have a
   * domain configured AND `SB_L4_TLS_LISTEN` set.
   */
  async exposeTLSPort(id: string, port: number): Promise<string> {
    return this.exposePortWithProtocol(id, port, "tls");
  }

  private async exposePortWithProtocol(id: string, port: number, protocol?: string): Promise<string> {
    const body = protocol ? { protocol } : undefined;
    const response = await this.doJSON<{ public_url: string }>("POST", `/v1/sandboxes/${id}/ports/${port}`, body);
    return response.public_url;
  }

  async unexposePort(id: string, port: number): Promise<void> {
    await this.doJSON<void>("DELETE", `/v1/sandboxes/${id}/ports/${port}`);
  }

  async reconcile(): Promise<void> {
    await this.doJSON<unknown>("POST", "/v1/admin/reconcile");
  }

  async health(): Promise<HealthStatus> {
    const response = await this.doJSON<ApiHealthStatus>("GET", "/health");
    return fromApiHealthStatus(response);
  }

  async mounts(id: string): Promise<MountSpecRedacted[]> {
    const response = await this.doJSON<ApiMountList>("GET", `/v1/sandboxes/${id}/mounts`);
    return response.mounts.map(fromApiMountSpecRedacted);
  }

  private wrap(sandbox: ApiSandbox): SandboxResource {
    return new SandboxResource(this, fromApiSandbox(sandbox));
  }

  private async doJSON<T>(method: string, path: string, body?: unknown): Promise<T> {
    const init: RequestInit = {};
    if (body !== undefined) {
      init.body = JSON.stringify(body);
      init.headers = {
        "Content-Type": "application/json",
      };
    }

    const response = await this.request(method, path, init);
    if (!response.ok) {
      throw await decodeError(response);
    }
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }

  private async doBytes(path: string): Promise<Uint8Array> {
    const response = await this.request("GET", path);
    if (!response.ok) {
      throw await decodeError(response);
    }
    return new Uint8Array(await response.arrayBuffer());
  }

  private request(method: string, path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (this.patToken !== "") {
      headers.set("Authorization", `Bearer ${this.patToken}`);
    }
    return this.fetchFn(`${this.baseURL}${path}`, {
      ...init,
      method,
      headers,
    });
  }
}

export class SandboxResource implements Sandbox {
  declare id: string;
  declare image: string;
  declare status: Sandbox["status"];
  declare publicURL: string;
  declare containerID?: string;
  declare containerIP?: string;
  declare cpu: number;
  declare memoryMB: number;
  declare diskGB: number;
  declare osUser: string;
  declare env?: Record<string, string>;
  declare networkBlockAll: boolean;
  declare toolboxEnabled: boolean;
  declare sshPublicKey?: string;
  declare sshPrivateKey?: string;
  declare exposedPorts?: ExposedPort[];
  declare createdAt: string;
  declare updatedAt: string;
  declare lastActiveAt: string;
  declare lastError?: string;
  declare containerCommand?: string[];
  declare lifecycle: Lifecycle;
  declare runtime: Sandbox["runtime"];

  protected readonly client: APIClient;

  constructor(client: APIClient, sandbox: Sandbox) {
    this.client = client;
    this.apply(sandbox);
  }

  async refresh(): Promise<this> {
    const updated = await this.client.get(this.id);
    this.apply(updated.toJSON());
    return this;
  }

  async exec(command: string | ExecRequest): Promise<ExecResult> {
    return this.client.exec(this.id, typeof command === "string" ? { command } : command);
  }

  execStream(options: ExecStreamOptions): ExecStreamHandle {
    return this.client.execStream(this.id, options);
  }

  async createSession(options: CreateSessionOptions): Promise<Session> {
    return this.client.createSession(this.id, options);
  }

  async listSessions(): Promise<Session[]> {
    return this.client.listSessions(this.id);
  }

  async getSession(sessionID: string): Promise<Session> {
    return this.client.getSession(this.id, sessionID);
  }

  async deleteSession(sessionID: string): Promise<void> {
    await this.client.deleteSession(this.id, sessionID);
  }

  async signalSession(sessionID: string, signal: string): Promise<void> {
    await this.client.signalSession(this.id, sessionID, signal);
  }

  async resizeSession(sessionID: string, cols: number, rows: number): Promise<void> {
    await this.client.resizeSession(this.id, sessionID, cols, rows);
  }

  async sessionLog(sessionID: string): Promise<Uint8Array> {
    return this.client.sessionLog(this.id, sessionID);
  }

  async sessionRecording(sessionID: string): Promise<Uint8Array> {
    return this.client.sessionRecording(this.id, sessionID);
  }

  attachSession(sessionID: string, options: SessionAttachOptions = {}): SessionAttachHandle {
    return this.client.attachSession(this.id, sessionID, options);
  }

  async uploadFile(targetPath: string, data: BinaryLike): Promise<void> {
    await this.client.uploadFile(this.id, targetPath, data);
  }

  async downloadFile(targetPath: string): Promise<Uint8Array> {
    return this.client.downloadFile(this.id, targetPath);
  }

  async exposePort(port: number): Promise<string> {
    return this.client.exposePort(this.id, port);
  }

  async exposeTCPPort(port: number): Promise<string> {
    return this.client.exposeTCPPort(this.id, port);
  }

  async exposeTLSPort(port: number): Promise<string> {
    return this.client.exposeTLSPort(this.id, port);
  }

  async unexposePort(port: number): Promise<void> {
    await this.client.unexposePort(this.id, port);
  }

  async start(): Promise<this> {
    const updated = await this.client.start(this.id);
    this.apply(updated.toJSON());
    return this;
  }

  async stop(): Promise<this> {
    const updated = await this.client.stop(this.id);
    this.apply(updated.toJSON());
    return this;
  }

  async destroy(): Promise<void> {
    await this.client.destroy(this.id);
  }

  async resize(options: ResizeOptions): Promise<this> {
    const updated = await this.client.resize(this.id, options);
    this.apply(updated.toJSON());
    return this;
  }

  async updateLifecycle(lifecycle: Lifecycle): Promise<this> {
    const updated = await this.client.updateLifecycle(this.id, lifecycle);
    this.apply(updated.toJSON());
    return this;
  }

  toJSON(): Sandbox {
    return cloneSandbox(this);
  }

  private apply(sandbox: Sandbox): void {
    Object.assign(this, cloneSandbox(sandbox));
  }
}

function toApiCreateOptions(options: CreateOptions): Record<string, unknown> {
  return {
    image: options.image,
    cpu: options.cpu,
    memory_mb: options.memoryMB,
    disk_gb: options.diskGB,
    env: options.env,
    os_user: options.osUser,
    network_block_all: options.networkBlockAll,
    registry: options.registry,
    container_command: options.containerCommand,
    mounts: options.mounts?.map(toApiMountSpec),
    lifecycle: options.lifecycle ? toApiLifecycle(options.lifecycle) : undefined,
    runtime: options.runtime,
  };
}

function toApiResizeOptions(options: ResizeOptions): Record<string, unknown> {
  return {
    cpu: options.cpu,
    memory_mb: options.memoryMB,
    disk_gb: options.diskGB,
  };
}

function toApiExecRequest(request: ExecRequest): Record<string, unknown> {
  return {
    command: request.command,
    workdir: request.workDir,
    env: request.env,
    timeout_seconds: request.timeoutSeconds,
  };
}

function toApiCreateSessionOptions(options: CreateSessionOptions): Record<string, unknown> {
  return {
    name: options.name,
    argv: options.argv,
    command: options.command,
    workdir: options.workDir,
    env: options.env,
    pty: options.pty,
    cols: options.cols,
    rows: options.rows,
  };
}

function toApiLifecycle(lifecycle: Lifecycle): ApiLifecycle {
  return {
    stop_if_idle_for: lifecycle.stopIfIdleFor,
    destroy_if_idle_for: lifecycle.destroyIfIdleFor,
    stop_at_age: lifecycle.stopAtAge,
    destroy_at_age: lifecycle.destroyAtAge,
  };
}

function fromApiSandbox(sandbox: ApiSandbox): Sandbox {
  return {
    id: sandbox.id,
    image: sandbox.image,
    status: sandbox.status,
    publicURL: sandbox.public_url,
    containerID: sandbox.container_id,
    containerIP: sandbox.container_ip,
    cpu: sandbox.cpu,
    memoryMB: sandbox.memory_mb,
    diskGB: sandbox.disk_gb,
    osUser: sandbox.os_user,
    env: sandbox.env,
    networkBlockAll: sandbox.network_block_all,
    toolboxEnabled: sandbox.toolbox_enabled,
    sshPublicKey: sandbox.ssh_public_key,
    exposedPorts: sandbox.exposed_ports?.map(fromApiExposedPort),
    createdAt: sandbox.created_at,
    updatedAt: sandbox.updated_at,
    lastActiveAt: sandbox.last_active_at,
    lastError: sandbox.last_error,
    containerCommand: sandbox.container_command,
    lifecycle: fromApiLifecycle(sandbox.lifecycle),
    runtime: normalizeRuntime(sandbox.runtime),
  };
}

// normalizeRuntime narrows the wire-level string to the union we expose, while
// tolerating older sandboxd versions that don't send the field at all (treat
// as "" — i.e. host default at start time).
function normalizeRuntime(value: string | undefined): Sandbox["runtime"] {
  if (value === "docker" || value === "gvisor" || value === "kata") {
    return value;
  }
  return "";
}

function fromApiCreateSandboxResponse(response: ApiCreateSandboxResponse): Sandbox {
  return {
    ...fromApiSandbox(response),
    sshPrivateKey: response.ssh_private_key,
  };
}

function fromApiSession(session: ApiSession): Session {
  return {
    id: session.id,
    name: session.name,
    argv: session.argv,
    workDir: session.workdir,
    pty: session.pty,
    status: session.status,
    exitCode: session.exit_code,
    exitSignal: session.exit_signal,
    createdAt: session.created_at,
    startedAt: session.started_at,
    exitedAt: session.exited_at,
    recording: session.recording,
    bytes: session.bytes,
    attached: session.attached,
  };
}

function fromApiExposedPort(port: ApiExposedPort): ExposedPort {
  return {
    sandboxID: port.sandbox_id,
    port: port.port,
    publicURL: port.public_url,
    createdAt: port.created_at,
  };
}

function fromApiExecResult(result: ApiExecResult): ExecResult {
  return {
    stdout: result.stdout,
    stderr: result.stderr,
    exitCode: result.exit_code,
    durationMS: result.duration_ms,
  };
}

function fromApiHealthStatus(status: ApiHealthStatus): HealthStatus {
  return {
    status: status.status,
    sandboxes: status.sandboxes,
    docker: status.docker,
    caddy: status.caddy,
    sshGateway: status.ssh_gateway ?? "",
    version: status.version,
  };
}

function toApiMountSpec(mount: MountSpec): ApiMountSpec {
  return {
    type: mount.type,
    target: mount.target,
    source: mount.source,
    options: mount.options,
    credentials: mount.credentials,
    read_only: mount.readOnly,
  };
}

function fromApiMountSpecRedacted(mount: ApiMountSpecRedacted): MountSpecRedacted {
  return {
    type: mount.type,
    target: mount.target,
    source: mount.source,
    options: mount.options,
    readOnly: mount.read_only ?? false,
    hasCredentials: mount.has_credentials,
  };
}

function fromApiLifecycle(lifecycle?: ApiLifecycle): Lifecycle {
  const result: Lifecycle = {};
  if (lifecycle?.stop_if_idle_for !== undefined) {
    result.stopIfIdleFor = lifecycle.stop_if_idle_for;
  }
  if (lifecycle?.destroy_if_idle_for !== undefined) {
    result.destroyIfIdleFor = lifecycle.destroy_if_idle_for;
  }
  if (lifecycle?.stop_at_age !== undefined) {
    result.stopAtAge = lifecycle.stop_at_age;
  }
  if (lifecycle?.destroy_at_age !== undefined) {
    result.destroyAtAge = lifecycle.destroy_at_age;
  }
  return result;
}

function cloneSandbox(sandbox: Sandbox): Sandbox {
  return {
    ...sandbox,
    env: sandbox.env ? { ...sandbox.env } : undefined,
    exposedPorts: sandbox.exposedPorts?.map((port) => ({ ...port })),
    containerCommand: sandbox.containerCommand ? [...sandbox.containerCommand] : undefined,
    lifecycle: { ...sandbox.lifecycle },
  };
}

function toBlob(data: BinaryLike): Blob {
  if (data instanceof Blob) {
    return data;
  }
  if (typeof data === "string") {
    return new Blob([data]);
  }
  if (data instanceof ArrayBuffer) {
    return new Blob([new Uint8Array(data)]);
  }
  return new Blob([Uint8Array.from(data)]);
}

async function decodeError(response: Response): Promise<Error> {
  try {
    const payload = (await response.json()) as { error?: string };
    if (typeof payload.error === "string" && payload.error !== "") {
      return new Error(payload.error);
    }
  } catch {
    // Fall through to status-based error.
  }
  return new Error(`request failed with status ${response.status}`);
}

const STREAM_PREFIX_STDOUT = 0x01;
const STREAM_PREFIX_STDERR = 0x02;

// Pull whatever diagnostic detail the runtime gave us off a WebSocket "error"
// event. Node 22's native WebSocket fires an ErrorEvent with `.error` /
// `.message`; browsers' base WebSocket fires a bare Event. Returns "" when
// nothing useful is there so callers can fall back to a generic label.
function describeWSError(event: unknown): string {
  if (!event || typeof event !== "object") return "";
  const e = event as { error?: unknown; message?: unknown };
  if (e.error instanceof Error && e.error.message) return e.error.message;
  if (typeof e.error === "string" && e.error !== "") return e.error;
  if (typeof e.message === "string" && e.message !== "") return e.message;
  return "";
}

function describeWSClose(event: unknown): string {
  if (!event || typeof event !== "object") return "";
  const e = event as { code?: unknown; reason?: unknown; wasClean?: unknown };
  const parts: string[] = [];
  if (typeof e.code === "number") parts.push(`code=${e.code}`);
  if (typeof e.reason === "string" && e.reason !== "") parts.push(`reason=${JSON.stringify(e.reason)}`);
  if (typeof e.wasClean === "boolean") parts.push(`wasClean=${e.wasClean}`);
  return parts.join(" ");
}

function toWebSocketBinaryFrame(data: Uint8Array | string): Uint8Array<ArrayBuffer> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const frame = new Uint8Array(bytes.byteLength);
  frame.set(bytes);
  return frame;
}

function openExecStream(baseURL: string, patToken: string, sandboxID: string, options: ExecStreamOptions): ExecStreamHandle {
  const wsURL = baseURL.replace(/^http/, "ws") + `/v1/sandboxes/${encodeURIComponent(sandboxID)}/toolbox/process/exec/stream`;

  const WS = (globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
  if (!WS) {
    throw new Error("WebSocket is not available in this runtime — Node 22+ or a browser is required");
  }

  // Browsers cannot attach Authorization headers to WebSocket handshakes,
  // so sandboxd accepts the PAT via `Sec-WebSocket-Protocol` as
  // `sandbox.bearer, <token>`.
  const ws = new WS(wsURL, ["sandbox.bearer", patToken]);
  ws.binaryType = "arraybuffer";

  // Captured by the "error" listener and consumed by "close" so we report the
  // root cause (e.g. "Unexpected server response: 502") rather than the
  // generic "stream closed before exit" that would otherwise win the race.
  let lastErrorDetail = "";

  let exitResolve: ((info: ExecExitInfo) => void) | undefined;
  let exitReject: ((err: Error) => void) | undefined;
  const done = new Promise<ExecExitInfo>((resolve, reject) => {
    exitResolve = resolve;
    exitReject = reject;
  });

  let resolved = false;
  const finishWith = (info: ExecExitInfo) => {
    if (resolved) return;
    resolved = true;
    exitResolve?.(info);
  };
  const failWith = (msg: string) => {
    if (resolved) return;
    resolved = true;
    exitReject?.(new Error(msg));
  };

  ws.addEventListener("open", () => {
    ws.send(JSON.stringify({
      command: options.command,
      workdir: options.workdir,
      env: options.env,
      tty: options.tty ?? false,
      cols: options.cols ?? 0,
      rows: options.rows ?? 0,
    }));
  });

  ws.addEventListener("message", (event: MessageEvent) => {
    if (typeof event.data === "string") {
      try {
        const msg = JSON.parse(event.data) as { type: string; code?: number; signal?: string; message?: string };
        if (msg.type === "exit") {
          finishWith({ code: msg.code ?? 0, signal: msg.signal });
          ws.close();
        } else if (msg.type === "error") {
          options.onError?.(msg.message ?? "stream error");
          failWith(msg.message ?? "stream error");
          ws.close();
        }
      } catch {
        // ignore
      }
      return;
    }
    const buf = event.data instanceof ArrayBuffer ? new Uint8Array(event.data) : new Uint8Array((event.data as Uint8Array).buffer);
    if (buf.length === 0) return;
    const stream = buf[0];
    const payload = buf.subarray(1);
    if (stream === STREAM_PREFIX_STDOUT) {
      options.onStdout?.(payload);
    } else if (stream === STREAM_PREFIX_STDERR) {
      options.onStderr?.(payload);
    }
  });

  ws.addEventListener("close", (event) => {
    const closeDetail = describeWSClose(event);
    const parts = [lastErrorDetail, closeDetail].filter((s) => s !== "");
    const suffix = parts.length > 0 ? ` (${parts.join("; ")})` : "";
    failWith(`stream closed before exit${suffix}`);
  });

  ws.addEventListener("error", (event) => {
    const detail = describeWSError(event);
    if (detail !== "") {
      lastErrorDetail = detail;
    }
    options.onError?.(detail !== "" ? detail : "websocket error");
    failWith(detail !== "" ? `websocket error: ${detail}` : "websocket error");
  });

  const sendBinary = (data: Uint8Array | string) => {
    ws.send(toWebSocketBinaryFrame(data));
  };

  return {
    write: sendBinary,
    resize(cols: number, rows: number) {
      ws.send(JSON.stringify({ type: "resize", cols, rows }));
    },
    signal(name: string) {
      ws.send(JSON.stringify({ type: "signal", signal: name }));
    },
    close() {
      ws.send(JSON.stringify({ type: "close" }));
    },
    done,
  };
}

function openSessionAttach(
  baseURL: string,
  patToken: string,
  sandboxID: string,
  sessionID: string,
  options: SessionAttachOptions,
): SessionAttachHandle {
  const wsURL = baseURL.replace(/^http/, "ws") + `/v1/sandboxes/${encodeURIComponent(sandboxID)}/sessions/${encodeURIComponent(sessionID)}/attach`;

  const WS = (globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
  if (!WS) {
    throw new Error("WebSocket is not available in this runtime — Node 22+ or a browser is required");
  }

  const ws = new WS(wsURL, ["sandbox.bearer", patToken]);
  ws.binaryType = "arraybuffer";

  let exitResolve: ((info: ExecExitInfo) => void) | undefined;
  let exitReject: ((err: Error) => void) | undefined;
  const done = new Promise<ExecExitInfo>((resolve, reject) => {
    exitResolve = resolve;
    exitReject = reject;
  });

  let settled = false;
  let lastErrorDetail = "";
  const finishWith = (info: ExecExitInfo) => {
    if (settled) return;
    settled = true;
    options.onExit?.(info);
    exitResolve?.(info);
  };
  const failWith = (msg: string) => {
    if (settled) return;
    settled = true;
    exitReject?.(new Error(msg));
  };

  ws.addEventListener("open", () => {
    if ((options.cols ?? 0) > 0 && (options.rows ?? 0) > 0) {
      ws.send(JSON.stringify({ type: "resize", cols: options.cols, rows: options.rows }));
    }
  });

  ws.addEventListener("message", (event: MessageEvent) => {
    if (typeof event.data === "string") {
      try {
        const msg = JSON.parse(event.data) as { type: string; code?: number; signal?: string; message?: string };
        if (msg.type === "exit") {
          finishWith({ code: msg.code ?? 0, signal: msg.signal });
          ws.close();
        } else if (msg.type === "error") {
          options.onError?.(msg.message ?? "session error");
          failWith(msg.message ?? "session error");
          ws.close();
        }
      } catch {
        // ignore malformed control frames
      }
      return;
    }

    const buf = event.data instanceof ArrayBuffer ? new Uint8Array(event.data) : new Uint8Array((event.data as Uint8Array).buffer);
    if (buf.length === 0) {
      return;
    }
    const stream = buf[0];
    const payload = buf.subarray(1);
    if (stream === STREAM_PREFIX_STDOUT) {
      options.onStdout?.(payload);
    } else if (stream === STREAM_PREFIX_STDERR) {
      options.onStderr?.(payload);
    }
  });

  ws.addEventListener("close", (event) => {
    if (!settled) {
      const closeDetail = describeWSClose(event);
      const parts = [lastErrorDetail, closeDetail].filter((s) => s !== "");
      const suffix = parts.length > 0 ? ` (${parts.join("; ")})` : "";
      failWith(`session stream closed before exit${suffix}`);
    }
  });

  ws.addEventListener("error", (event) => {
    const detail = describeWSError(event);
    if (detail !== "") {
      lastErrorDetail = detail;
    }
    options.onError?.(detail !== "" ? detail : "websocket error");
    failWith(detail !== "" ? `websocket error: ${detail}` : "websocket error");
  });

  const sendBinary = (data: Uint8Array | string) => {
    ws.send(toWebSocketBinaryFrame(data));
  };

  return {
    write: sendBinary,
    resize(cols: number, rows: number) {
      ws.send(JSON.stringify({ type: "resize", cols, rows }));
    },
    signal(name: string) {
      ws.send(JSON.stringify({ type: "signal", signal: name }));
    },
    close() {
      ws.send(JSON.stringify({ type: "close" }));
      ws.close();
    },
    done,
  };
}