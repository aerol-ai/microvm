import { APIClient, type APIVersion } from "./internal/client.js";
import { Sandbox } from "./Sandbox.js";
import type {
  CreateOptions,
  CreateSessionOptions,
  ExecStreamHandle,
  ExecStreamOptions,
  HealthStatus,
  Lifecycle,
  MountSpecRedacted,
  ResizeOptions,
  Sandbox as SandboxData,
  SandboxSnapshot,
  Session,
  SessionAttachHandle,
  SessionAttachOptions,
} from "./types.js";

const defaultAPIURL = "http://127.0.0.1:21212";
const authRequiredErrorMessage = "PAT token is required. Set patToken or SB_PAT_TOKEN.";

type FetchLike = typeof fetch;

export interface MicroVMConfig {
  patToken?: string;
  apiUrl?: string;
  fetch?: FetchLike;
  /**
   * Wire version of the sandbox daemon API to call. Defaults to the SDK's
   * pinned default ("v1" today). The SDK package version and the API wire
   * version evolve independently — you can pin one without affecting the
   * other.
   */
  apiVersion?: APIVersion;
}

export class MicroVM {
  readonly apiUrl: string;
  readonly patToken: string;

  private readonly client: APIClient;

  constructor(config: MicroVMConfig = {}) {
    const patToken = config.patToken ?? readEnv("SB_PAT_TOKEN") ?? "";
    const apiUrl = normalizeURL(config.apiUrl ?? readEnv("SB_API_URL") ?? defaultAPIURL);

    if (patToken === "") {
      throw new Error(authRequiredErrorMessage);
    }

    this.apiUrl = apiUrl;
    this.patToken = patToken;
    this.client = new APIClient({
      baseURL: apiUrl,
      patToken,
      fetch: config.fetch,
      apiVersion: config.apiVersion,
    });
  }

  async create(options: CreateOptions): Promise<Sandbox> {
    const sandbox = await this.client.create(options);
    return this.wrap(sandbox.toJSON());
  }

  async list(): Promise<Sandbox[]> {
    const sandboxes = await this.client.list();
    return sandboxes.map((sandbox) => this.wrap(sandbox.toJSON()));
  }

  async get(id: string): Promise<Sandbox> {
    const sandbox = await this.client.get(id);
    return this.wrap(sandbox.toJSON());
  }

  async start(id: string): Promise<Sandbox> {
    const sandbox = await this.client.start(id);
    return this.wrap(sandbox.toJSON());
  }

  async stop(id: string): Promise<Sandbox> {
    const sandbox = await this.client.stop(id);
    return this.wrap(sandbox.toJSON());
  }

	async createSnapshot(id: string, name: string): Promise<SandboxSnapshot> {
		return this.client.createSnapshot(id, name);
	}

  async destroy(id: string): Promise<void> {
    await this.client.destroy(id);
  }

  async resize(id: string, options: ResizeOptions): Promise<Sandbox> {
    const sandbox = await this.client.resize(id, options);
    return this.wrap(sandbox.toJSON());
  }

  async updateLifecycle(id: string, lifecycle: Lifecycle): Promise<Sandbox> {
    const sandbox = await this.client.updateLifecycle(id, lifecycle);
    return this.wrap(sandbox.toJSON());
  }

  async reconcile(): Promise<void> {
    await this.client.reconcile();
  }

  async health(): Promise<HealthStatus> {
    return this.client.health();
  }

  async mounts(sandboxID: string): Promise<MountSpecRedacted[]> {
    return this.client.mounts(sandboxID);
  }

  execStream(sandboxID: string, options: ExecStreamOptions): ExecStreamHandle {
    return this.client.execStream(sandboxID, options);
  }

  async createSession(sandboxID: string, options: CreateSessionOptions): Promise<Session> {
    return this.client.createSession(sandboxID, options);
  }

  async listSessions(sandboxID: string): Promise<Session[]> {
    return this.client.listSessions(sandboxID);
  }

  async getSession(sandboxID: string, sessionID: string): Promise<Session> {
    return this.client.getSession(sandboxID, sessionID);
  }

  async deleteSession(sandboxID: string, sessionID: string): Promise<void> {
    await this.client.deleteSession(sandboxID, sessionID);
  }

  async signalSession(sandboxID: string, sessionID: string, signal: string): Promise<void> {
    await this.client.signalSession(sandboxID, sessionID, signal);
  }

  async resizeSession(sandboxID: string, sessionID: string, cols: number, rows: number): Promise<void> {
    await this.client.resizeSession(sandboxID, sessionID, cols, rows);
  }

  async sessionLog(sandboxID: string, sessionID: string): Promise<Uint8Array> {
    return this.client.sessionLog(sandboxID, sessionID);
  }

  async sessionRecording(sandboxID: string, sessionID: string): Promise<Uint8Array> {
    return this.client.sessionRecording(sandboxID, sessionID);
  }

  attachSession(sandboxID: string, sessionID: string, options: SessionAttachOptions = {}): SessionAttachHandle {
    return this.client.attachSession(sandboxID, sessionID, options);
  }

  private wrap(sandbox: SandboxData): Sandbox {
    return new Sandbox(this.client, sandbox);
  }
}

function normalizeURL(value: string): string {
  return value.replace(/\/+$/, "");
}

function readEnv(name: string): string | undefined {
  if (typeof process === "undefined" || !process.env) {
    return undefined;
  }
  const value = process.env[name];
  return typeof value === "string" && value !== "" ? value : undefined;
}