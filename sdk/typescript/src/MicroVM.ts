import { APIClient } from "./internal/client.js";
import { Sandbox } from "./Sandbox.js";
import type { CreateOptions, HealthStatus, ResizeOptions, Sandbox as SandboxData } from "./types.js";

const defaultAPIURL = "http://127.0.0.1:8080";
const authRequiredErrorMessage = "PAT token is required. Set patToken or SB_PAT_TOKEN.";

type FetchLike = typeof fetch;

export interface MicroVMConfig {
  patToken?: string;
  apiUrl?: string;
  fetch?: FetchLike;
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

  async destroy(id: string): Promise<void> {
    await this.client.destroy(id);
  }

  async resize(id: string, options: ResizeOptions): Promise<Sandbox> {
    const sandbox = await this.client.resize(id, options);
    return this.wrap(sandbox.toJSON());
  }

  async health(): Promise<HealthStatus> {
    return this.client.health();
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