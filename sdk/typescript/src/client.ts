import { basename } from "node:path";

import type {
  BinaryLike,
  CreateOptions,
  ExecRequest,
  ExecResult,
  ExposedPort,
  HealthStatus,
  ResizeOptions,
  Sandbox,
} from "./types.js";

type FetchLike = typeof fetch;

interface ClientOptions {
  fetch?: FetchLike;
}

interface ApiExposedPort {
  sandbox_id: string;
  port: number;
  public_url: string;
  created_at: string;
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
  exposed_ports?: ApiExposedPort[];
  created_at: string;
  updated_at: string;
  last_active_at: string;
  last_error?: string;
  container_command?: string[];
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
  version: string;
}

export class Client {
  readonly baseURL: string;
  private readonly token: string;
  private readonly fetchFn: FetchLike;

  constructor(baseURL: string, token = "", options: ClientOptions = {}) {
    this.baseURL = baseURL.replace(/\/+$/, "");
    this.token = token;
    this.fetchFn = options.fetch ?? fetch;
  }

  async create(options: CreateOptions): Promise<SandboxHandle> {
    const response = await this.doJSON<ApiSandbox>("POST", "/v1/sandboxes", toApiCreateOptions(options));
    return this.wrap(response);
  }

  async list(): Promise<SandboxHandle[]> {
    const response = await this.doJSON<ApiSandbox[]>("GET", "/v1/sandboxes");
    return response.map((item) => this.wrap(item));
  }

  async get(id: string): Promise<SandboxHandle> {
    const response = await this.doJSON<ApiSandbox>("GET", `/v1/sandboxes/${id}`);
    return this.wrap(response);
  }

  async start(id: string): Promise<SandboxHandle> {
    const response = await this.doJSON<ApiSandbox>("POST", `/v1/sandboxes/${id}/start`);
    return this.wrap(response);
  }

  async stop(id: string): Promise<SandboxHandle> {
    const response = await this.doJSON<ApiSandbox>("POST", `/v1/sandboxes/${id}/stop`);
    return this.wrap(response);
  }

  async destroy(id: string): Promise<void> {
    await this.doJSON<void>("DELETE", `/v1/sandboxes/${id}`);
  }

  async resize(id: string, options: ResizeOptions): Promise<SandboxHandle> {
    const response = await this.doJSON<ApiSandbox>("POST", `/v1/sandboxes/${id}/resize`, toApiResizeOptions(options));
    return this.wrap(response);
  }

  async exec(id: string, request: ExecRequest): Promise<ExecResult> {
    const response = await this.doJSON<ApiExecResult>("POST", `/v1/sandboxes/${id}/toolbox/process/execute`, toApiExecRequest(request));
    return fromApiExecResult(response);
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
    const response = await this.doJSON<{ public_url: string }>("POST", `/v1/sandboxes/${id}/ports/${port}`);
    return response.public_url;
  }

  async unexposePort(id: string, port: number): Promise<void> {
    await this.doJSON<void>("DELETE", `/v1/sandboxes/${id}/ports/${port}`);
  }

  async health(): Promise<HealthStatus> {
    const response = await this.doJSON<ApiHealthStatus>("GET", "/health");
    return fromApiHealthStatus(response);
  }

  private wrap(sandbox: ApiSandbox): SandboxHandle {
    return new SandboxHandle(this, fromApiSandbox(sandbox));
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

  private request(method: string, path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (this.token !== "") {
      headers.set("Authorization", `Bearer ${this.token}`);
    }
    return this.fetchFn(`${this.baseURL}${path}`, {
      ...init,
      method,
      headers,
    });
  }
}

export class SandboxHandle implements Sandbox {
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
  declare exposedPorts?: ExposedPort[];
  declare createdAt: string;
  declare updatedAt: string;
  declare lastActiveAt: string;
  declare lastError?: string;
  declare containerCommand?: string[];

  readonly #client: Client;

  constructor(client: Client, sandbox: Sandbox) {
    this.#client = client;
    this.apply(sandbox);
  }

  async refresh(): Promise<this> {
    const updated = await this.#client.get(this.id);
    this.apply(updated.toJSON());
    return this;
  }

  async exec(command: string | ExecRequest): Promise<ExecResult> {
    return this.#client.exec(this.id, typeof command === "string" ? { command } : command);
  }

  async uploadFile(targetPath: string, data: BinaryLike): Promise<void> {
    await this.#client.uploadFile(this.id, targetPath, data);
  }

  async downloadFile(targetPath: string): Promise<Uint8Array> {
    return this.#client.downloadFile(this.id, targetPath);
  }

  async exposePort(port: number): Promise<string> {
    return this.#client.exposePort(this.id, port);
  }

  async start(): Promise<this> {
    const updated = await this.#client.start(this.id);
    this.apply(updated.toJSON());
    return this;
  }

  async stop(): Promise<this> {
    const updated = await this.#client.stop(this.id);
    this.apply(updated.toJSON());
    return this;
  }

  async destroy(): Promise<void> {
    await this.#client.destroy(this.id);
  }

  async resize(options: ResizeOptions): Promise<this> {
    const updated = await this.#client.resize(this.id, options);
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
    exposedPorts: sandbox.exposed_ports?.map(fromApiExposedPort),
    createdAt: sandbox.created_at,
    updatedAt: sandbox.updated_at,
    lastActiveAt: sandbox.last_active_at,
    lastError: sandbox.last_error,
    containerCommand: sandbox.container_command,
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
    version: status.version,
  };
}

function cloneSandbox(sandbox: Sandbox): Sandbox {
  return {
    ...sandbox,
    env: sandbox.env ? { ...sandbox.env } : undefined,
    exposedPorts: sandbox.exposedPorts?.map((port) => ({ ...port })),
    containerCommand: sandbox.containerCommand ? [...sandbox.containerCommand] : undefined,
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
