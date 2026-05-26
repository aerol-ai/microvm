import { APIClient, type APIVersion } from "./internal/client.js";
import { Sandbox } from "./Sandbox.js";
import { Image } from "./Image.js";
import type {
  BuildImageOptions,
  BuildImageResult,
  CreateOptions,
  CreateSessionOptions,
  CreateTemplateOptions,
  ExecStreamHandle,
  ExecStreamOptions,
  HealthStatus,
  IngressTarget,
  Lifecycle,
  ListOptions,
  MountSpecRedacted,
  RegisterSnapshotOptions,
  ResizeOptions,
  Sandbox as SandboxData,
  SandboxSnapshot,
  Session,
  SessionAttachHandle,
  SessionAttachOptions,
  Template,
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

  async list(options?: ListOptions): Promise<Sandbox[]> {
    const sandboxes = await this.client.list(options);
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

  async registerSnapshot(options: RegisterSnapshotOptions): Promise<SandboxSnapshot> {
    return this.client.registerSnapshot(options);
  }

  async registerSnapshotFromImage(
    name: string,
    image: Image,
    options: Omit<RegisterSnapshotOptions, "name" | "image" | "dockerfileContent"> = {},
  ): Promise<SandboxSnapshot> {
    return this.client.registerSnapshotFromImage(name, image, options);
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

  /**
   * Build an {@link Image} on the daemon and optionally push the result to a
   * remote registry. Push credentials are forwarded per request and never
   * persisted by the daemon. Returns the local content-addressed tag and,
   * when push was requested, the pushed reference.
   */
  async buildImage(image: Image, options?: BuildImageOptions): Promise<BuildImageResult> {
    return this.client.buildImage(image, options);
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

  /**
   * Register a Firecracker rootfs template. Returns immediately with a
   * `status: "pending"` row; poll {@link MicroVM.getTemplate} until the
   * status reaches `"ready"` (fast-boot available) or `"ready_no_snapshot"`
   * (cold boot only — see {@link Template.snapshotError}).
   *
   * Idempotent when {@link CreateTemplateOptions.id} is supplied: a
   * duplicate ID returns 409 so a retried CI step does not create two
   * rows for the same logical template.
   */
  async createTemplate(options: CreateTemplateOptions): Promise<Template> {
    return this.client.createTemplate(options);
  }

  async listTemplates(): Promise<Template[]> {
    return this.client.listTemplates();
  }

  async getTemplate(id: string): Promise<Template> {
    return this.client.getTemplate(id);
  }

  async deleteTemplate(id: string): Promise<void> {
    await this.client.deleteTemplate(id);
  }

  /**
   * Re-run the snapshot phase against an existing template. Idempotent
   * under concurrent retry: the daemon's CAS collapses N parallel calls
   * for the same ready template into one rebuild kick. Returns the row in
   * its post-transition state (typically `unhealthy`) — poll
   * {@link MicroVM.getTemplate} to observe the transition back to `ready`.
   *
   * Returns 412 (raised as an error) when the template is in a state
   * where rebuild is not safe (build in flight) or not supported
   * (`ready_no_snapshot` / `failed` — those need delete+recreate today).
   */
  async rebuildTemplate(id: string): Promise<Template> {
    return this.client.rebuildTemplate(id);
  }

  /**
   * Cluster-level DNS helpers. Exposed as a namespaced accessor (rather
   * than a flat `ingressDNS()` method) so call sites read like
   * `microvm.dns.target()`, mirroring the per-sandbox `sandbox.customDomains`
   * pattern. A fresh object is returned per access so the closures always
   * see the current client even if MicroVM is later extended.
   */
  get dns(): { target(): Promise<IngressTarget> } {
    const client = this.client;
    return {
      target: () => client.ingressDNS(),
    };
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