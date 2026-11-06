import { APIClient, stripTrailingSlashes, type APIVersion, type RetryConfig } from "./internal/client.js";
import { Sandbox } from "./Sandbox.js";
import { Image } from "./Image.js";
import type {
  APITokenList,
  CallOptions,
  DestroyAllOptions,
  BuildImageOptions,
  BuildImageResult,
  CloneGeneration,
  CreateAPITokenOptions,
  CreatedAPIToken,
  CreateOptions,
  CreateSessionOptions,
  CreateTemplateOptions,
  CreateWasmModuleOptions,
  PushWasmModuleOptions,
  PushWasmModuleResult,
  ExecStreamHandle,
  ExecStreamOptions,
  FileEvent,
  FileWatchHandle,
  HealthStatus,
  EgressProfile,
  EgressProfileList,
  EgressProfileOptions,
  IdentityRole,
  IdentityRoleList,
  IdentityRoleOptions,
  ListEgressProfilesOptions,
  TeamQuota,
  TeamQuotaOptions,
  WarmPool,
  WarmPoolOptions,
  ListIdentityRolesOptions,
  NetworkPolicyCheckOptions,
  NetworkPolicyCheckResult,
  IngressTarget,
  Lifecycle,
  GetOptions,
  ListOptions,
  MountSpecRedacted,
  CreateSnapshotOptions,
  RegisterSnapshotOptions,
  ListSnapshotsOptions,
  SnapshotList,
  ResizeOptions,
  Sandbox as SandboxData,
  SandboxSnapshot,
  Session,
  SessionAttachHandle,
  SessionAttachOptions,
  Template,
  WasmModule,
  WatchFilesOptions,
  WhoAmI,
} from "./types.js";

const defaultAPIURL = "http://127.0.0.1:21212";
const authRequiredErrorMessage = "PAT token is required. Set patToken, SB_PAT_TOKEN or SB_API_TOKEN.";

type FetchLike = typeof fetch;

/** Scoped API token calls, reached as `microvm.tokens`. */
export interface Tokens {
  /**
   * Mint a token (admin only). The result's `token` is the secret, returned
   * this once and never again. A 409 means the name is taken, possibly by an
   * earlier attempt whose reply was lost; that secret cannot be recovered,
   * so revoke the token and create it again.
   */
  create(options: CreateAPITokenOptions, call?: CallOptions): Promise<CreatedAPIToken>;
  /** List every token (auditor or admin); expired ones stay listed for 30 days. */
  list(call?: CallOptions): Promise<APITokenList>;
  /** Revoke a token by id (admin only). Revoking one already gone succeeds. */
  revoke(id: string, call?: CallOptions): Promise<void>;
}

/** What {@link MicroVM.getOrCreate} found or made. */
export interface GetOrCreateResult {
  sandbox: Sandbox;
  /** True only when this call created the sandbox. */
  created: boolean;
}

export interface MicroVMConfig {
  /**
   * The bearer every request carries: the operator PAT, an `avm_` API token
   * or an OIDC ID token. Defaults to `SB_PAT_TOKEN`, then its alias
   * `SB_API_TOKEN`; when both are set, `SB_PAT_TOKEN` wins.
   */
  patToken?: string;
  apiUrl?: string;
  /**
   * The team requests act for, sent as the `X-AerolVM-Team` header on every
   * HTTP request. Defaults to `SB_TEAM`; with neither, no header is sent and
   * the server uses the credential's first matching binding. The header only
   * chooses among teams the credential is already bound to (a team it does
   * not hold is refused with 403), and the operator PAT ignores it.
   * WebSocket streams (`execStream`, `attachSession`) cannot carry custom
   * headers from a browser or Node, so they go without it.
   */
  team?: string;
  fetch?: FetchLike;
  /**
   * Wire version of the sandbox daemon API to call. Defaults to the SDK's
   * pinned default ("v1" today). The SDK package version and the API wire
   * version evolve independently — you can pin one without affecting the
   * other.
   */
  apiVersion?: APIVersion;
  /**
   * Retry policy for transient transport errors (socket closed, connection
   * reset) and retryable HTTP status codes (421, 429, 502, 503, 504). The SDK
   * retries up to 3 times with exponential backoff by default. `exec` retries
   * only failures that prove the command never reached the server
   * (connection refused, connect timeout, DNS) and HTTP 429/503, so a command
   * never runs twice. Pass `{ maxRetries: 0 }` to disable. A 429 or 503
   * waits as long as the server's `Retry-After` asks, up to
   * `retry.maxRetryAfterMs` (30 s by default).
   */
  retry?: RetryConfig;
  /**
   * Cancels the client's HTTP requests: aborting it ends the request in
   * flight and any retry wait, so a call never sits out a long
   * `Retry-After` once aborted. Pass `AbortSignal.timeout(ms)` to bound
   * how long the client may run. WebSocket streams are not affected. To
   * cancel or time-limit one call, pass `{ signal }` as that call's last
   * argument ({@link CallOptions}).
   */
  signal?: AbortSignal;
}

export class MicroVM {
  readonly apiUrl: string;
  readonly patToken: string;
  /** The team sent as `X-AerolVM-Team`, or `""` when none is. */
  readonly team: string;

  private readonly client: APIClient;

  constructor(config: MicroVMConfig = {}) {
    const patToken = config.patToken ?? readEnv("SB_PAT_TOKEN") ?? readEnv("SB_API_TOKEN") ?? "";
    const apiUrl = normalizeURL(config.apiUrl ?? readEnv("SB_API_URL") ?? defaultAPIURL);
    const team = (config.team ?? readEnv("SB_TEAM") ?? "").trim();

    if (patToken === "") {
      throw new Error(authRequiredErrorMessage);
    }

    this.apiUrl = apiUrl;
    this.patToken = patToken;
    this.team = team;
    this.client = new APIClient({
      baseURL: apiUrl,
      patToken,
      team,
      fetch: config.fetch,
      apiVersion: config.apiVersion,
      retry: config.retry,
      signal: config.signal,
    });
  }

  async create(options: CreateOptions, call?: CallOptions): Promise<Sandbox> {
    const sandbox = await this.clientFor(call).create(options);
    const wrapped = this.wrap(sandbox.toJSON());
    wrapped.destroyOnExit = options.destroyOnExit ?? false;
    return wrapped;
  }

  async list(options?: ListOptions, call?: CallOptions): Promise<Sandbox[]> {
    const sandboxes = await this.clientFor(call).list(options);
    return sandboxes.map((sandbox) => this.wrap(sandbox.toJSON()));
  }

  /**
   * Iterates one server page at a time. Use this for large fleet inventories so
   * the SDK does not retain every sandbox in memory.
   */
  async *listPages(options?: ListOptions, call?: CallOptions): AsyncGenerator<Sandbox[]> {
    for await (const page of this.clientFor(call).listPages(options)) {
      yield page.map((sandbox) => this.wrap(sandbox.toJSON()));
    }
  }

  async get(id: string, options?: GetOptions, call?: CallOptions): Promise<Sandbox> {
    const sandbox = await this.clientFor(call).get(id, options);
    return this.wrap(sandbox.toJSON());
  }

  /**
   * Returns the caller's sandbox with this name, or `null` when there is none.
   * Names are unique per owner. Throws when the server predates name lookup
   * (it ignores `?name=`), rather than guessing from an unfiltered list.
   */
  async getByName(name: string, options?: GetOptions, call?: CallOptions): Promise<Sandbox | null> {
    const sandbox = await this.clientFor(call).getByName(name, options);
    return sandbox === null ? null : this.wrap(sandbox.toJSON());
  }

  /**
   * Returns the caller's sandbox called `name`, creating it from `options`
   * when there is none. `created` is true only when this call made the
   * sandbox. Safe to retry and to run at the same time from many processes:
   * names are unique per owner, so when two callers race to create the same
   * name, one gets a 409 and reads the winner's sandbox instead. An existing
   * sandbox is returned as it is; its image and settings are not compared
   * with `options`.
   */
  async getOrCreate(name: string, options: CreateOptions, call?: CallOptions): Promise<GetOrCreateResult> {
    const result = await this.clientFor(call).getOrCreate(name, options);
    const sandbox = this.wrap(result.sandbox.toJSON());
    sandbox.destroyOnExit = options.destroyOnExit ?? false;
    return { sandbox, created: result.created };
  }

  async start(id: string, call?: CallOptions): Promise<Sandbox> {
    const sandbox = await this.clientFor(call).start(id);
    return this.wrap(sandbox.toJSON());
  }

  async stop(id: string, call?: CallOptions): Promise<Sandbox> {
    const sandbox = await this.clientFor(call).stop(id);
    return this.wrap(sandbox.toJSON());
  }

	async createSnapshot(id: string, name: string, options: CreateSnapshotOptions = {}, call?: CallOptions): Promise<SandboxSnapshot> {
		return this.clientFor(call).createSnapshot(id, name, options);
	}

  async registerSnapshot(options: RegisterSnapshotOptions, call?: CallOptions): Promise<SandboxSnapshot> {
    return this.clientFor(call).registerSnapshot(options);
  }

  async registerSnapshotFromImage(
    name: string,
    image: Image,
    options: Omit<RegisterSnapshotOptions, "name" | "image" | "dockerfileContent"> = {},
    call?: CallOptions,
  ): Promise<SandboxSnapshot> {
    return this.clientFor(call).registerSnapshotFromImage(name, image, options);
  }

  /** Look a snapshot up by name. In a cluster the request is routed to the node holding the image. */
  async getSnapshot(name: string, call?: CallOptions): Promise<SandboxSnapshot> {
    return this.clientFor(call).getSnapshot(name);
  }

  /** List the caller's snapshots, one name-ordered page at a time. */
  async listSnapshots(options: ListSnapshotsOptions = {}, call?: CallOptions): Promise<SnapshotList> {
    return this.clientFor(call).listSnapshots(options);
  }

  /** Delete a snapshot by name (idempotent 404 if it does not exist). */
  async deleteSnapshot(name: string, call?: CallOptions): Promise<void> {
    return this.clientFor(call).deleteSnapshot(name);
  }

  async destroy(id: string, call?: CallOptions): Promise<void> {
    await this.clientFor(call).destroy(id);
  }

  /**
   * Deletes every sandbox of yours that carries all of `options.tags` and
   * returns the IDs of the ones now gone. It lists every page first, then
   * deletes them one at a time. A sandbox that is already gone (404) counts
   * as deleted, so a second call, or two calls at once, is safe. Any other
   * failed delete stops the call and is thrown; the sandboxes already
   * deleted stay deleted, and calling it again finishes the job. `tags`
   * must not be empty.
   */
  async destroyAll(options: DestroyAllOptions, call?: CallOptions): Promise<string[]> {
    return this.clientFor(call).destroyAll(options.tags);
  }

  async resize(id: string, options: ResizeOptions, call?: CallOptions): Promise<Sandbox> {
    const sandbox = await this.clientFor(call).resize(id, options);
    return this.wrap(sandbox.toJSON());
  }

  async updateLifecycle(id: string, lifecycle: Lifecycle, call?: CallOptions): Promise<Sandbox> {
    const sandbox = await this.clientFor(call).updateLifecycle(id, lifecycle);
    return this.wrap(sandbox.toJSON());
  }

  async reconcile(call?: CallOptions): Promise<void> {
    await this.clientFor(call).reconcile();
  }

  /**
   * Build an {@link Image} on the daemon and optionally push the result to a
   * remote registry. Push credentials are forwarded per request and never
   * persisted by the daemon. Returns the local content-addressed tag and,
   * when push was requested, the pushed reference.
   */
  async buildImage(image: Image, options?: BuildImageOptions, call?: CallOptions): Promise<BuildImageResult> {
    return this.clientFor(call).buildImage(image, options);
  }

  async health(call?: CallOptions): Promise<HealthStatus> {
    return this.clientFor(call).health();
  }

  /**
   * Asks whether a sandbox created with these egress fields would reach a
   * destination, using the same matcher the filter enforces. No sandbox is
   * needed.
   */
  async checkNetworkPolicy(options: NetworkPolicyCheckOptions, call?: CallOptions): Promise<NetworkPolicyCheckResult> {
    return this.clientFor(call).checkNetworkPolicy(options);
  }

  /**
   * Creates or replaces a named egress profile (a full replace: the same body
   * twice is a no-op). Sandboxes reference it through `egressProfiles`, and a
   * change reaches every one of them.
   */
  async putEgressProfile(name: string, options: EgressProfileOptions, call?: CallOptions): Promise<EgressProfile> {
    return this.clientFor(call).putEgressProfile(name, options);
  }

  async getEgressProfile(name: string, call?: CallOptions): Promise<EgressProfile> {
    return this.clientFor(call).getEgressProfile(name);
  }

  async listEgressProfiles(options?: ListEgressProfilesOptions, call?: CallOptions): Promise<EgressProfileList> {
    return this.clientFor(call).listEgressProfiles(options);
  }

  /** Deletes a profile; one that sandboxes still reference is refused (409). */
  async deleteEgressProfile(name: string, call?: CallOptions): Promise<void> {
    return this.clientFor(call).deleteEgressProfile(name);
  }

  /**
   * Sets how many ready sandboxes every server with a warm pool keeps for an
   * image (a full replace: the same call twice is a no-op). A create that names
   * the image then starts from a warm sandbox. Admin only.
   */
  async putWarmPool(image: string, options: WarmPoolOptions, call?: CallOptions): Promise<WarmPool> {
    return this.clientFor(call).putWarmPool(image, options);
  }

  /** Returns an image's warm-pool entry with its status (ready and target, per server). */
  async getWarmPool(image: string, call?: CallOptions): Promise<WarmPool> {
    return this.clientFor(call).getWarmPool(image);
  }

  /** Returns every warm-pool entry, by image, with its status. */
  async listWarmPools(call?: CallOptions): Promise<WarmPool[]> {
    return this.clientFor(call).listWarmPools();
  }

  /** Deletes an image's warm-pool entry; its warm sandboxes are removed. Deleting a missing entry succeeds. */
  async deleteWarmPool(image: string, call?: CallOptions): Promise<void> {
    return this.clientFor(call).deleteWarmPool(image);
  }

  /**
   * Puts a role tag on a team's cloud identity allow list, or changes its
   * minimum caller role (`"runner"` or `"admin"`). Admin only. The same call
   * twice changes nothing, so it is safe to retry.
   */
  async putIdentityRole(tag: string, options: IdentityRoleOptions, call?: CallOptions): Promise<IdentityRole> {
    return this.clientFor(call).putIdentityRole(tag, options);
  }

  /** Lists a team's cloud identity allow list, one page at a time. Admin only. */
  async listIdentityRoles(options?: ListIdentityRolesOptions, call?: CallOptions): Promise<IdentityRoleList> {
    return this.clientFor(call).listIdentityRoles(options);
  }

  /**
   * Takes a role tag off a team's allow list. Admin only. Sandboxes that use
   * it keep their current token (at most one hour) and get no new one.
   * Deleting a tag that is already gone succeeds.
   */
  async deleteIdentityRole(tag: string, options?: { team?: string }, call?: CallOptions): Promise<void> {
    return this.clientFor(call).deleteIdentityRole(tag, options);
  }

  /**
   * Sets a team's quota: the most sandboxes, CPU and memory its sandboxes
   * may hold. Admin only. The same limits twice change nothing. A create,
   * resize or start past the quota fails with 429 `team_quota_exceeded`.
   */
  async putTeamQuota(team: string, options: TeamQuotaOptions, call?: CallOptions): Promise<TeamQuota> {
    return this.clientFor(call).putTeamQuota(team, options);
  }

  /** Reads a team's quota and what the team holds now. 404 if it has none. */
  async getTeamQuota(team: string, call?: CallOptions): Promise<TeamQuota> {
    return this.clientFor(call).getTeamQuota(team);
  }

  /** Removes a team's quota. Removing one that is already gone succeeds. */
  async deleteTeamQuota(team: string, call?: CallOptions): Promise<void> {
    return this.clientFor(call).deleteTeamQuota(team);
  }

  async mounts(sandboxID: string, call?: CallOptions): Promise<MountSpecRedacted[]> {
    return this.clientFor(call).mounts(sandboxID);
  }

  /**
   * Read a sandbox's clone-generation token. The token changes whenever the
   * sandbox is resumed from a snapshot, so a change signals "this is a clone."
   * Read-only — the SDK cannot reseed a process inside the guest; see the
   * "Randomness in cloned sandboxes" docs page for the in-guest reseed pattern.
   */
  async cloneGeneration(sandboxID: string, call?: CallOptions): Promise<CloneGeneration> {
    return this.clientFor(call).cloneGeneration(sandboxID);
  }

  execStream(sandboxID: string, options: ExecStreamOptions): ExecStreamHandle {
    return this.client.execStream(sandboxID, options);
  }

  /**
   * Watch a folder in a sandbox for changes: `onEvent` gets each create,
   * write, remove, rename and chmod, in batches every 250 ms. Resolves once
   * the watch is in place. gVisor and Firecracker sandboxes only; Docker,
   * containerd, WASM and isolate sandboxes reject with a 501
   * `MicroVMApiError`. A sandbox whose agent predates file watching rejects
   * with `MicroVMUnsupportedFeatureError`.
   */
  async watchFiles(sandboxID: string, path: string, onEvent: (event: FileEvent) => void, options: WatchFilesOptions = {}): Promise<FileWatchHandle> {
    return this.client.watchFiles(sandboxID, path, onEvent, options);
  }

  async createSession(sandboxID: string, options: CreateSessionOptions, call?: CallOptions): Promise<Session> {
    return this.clientFor(call).createSession(sandboxID, options);
  }

  async listSessions(sandboxID: string, call?: CallOptions): Promise<Session[]> {
    return this.clientFor(call).listSessions(sandboxID);
  }

  async getSession(sandboxID: string, sessionID: string, call?: CallOptions): Promise<Session> {
    return this.clientFor(call).getSession(sandboxID, sessionID);
  }

  async deleteSession(sandboxID: string, sessionID: string, call?: CallOptions): Promise<void> {
    await this.clientFor(call).deleteSession(sandboxID, sessionID);
  }

  async signalSession(sandboxID: string, sessionID: string, signal: string, call?: CallOptions): Promise<void> {
    await this.clientFor(call).signalSession(sandboxID, sessionID, signal);
  }

  async resizeSession(sandboxID: string, sessionID: string, cols: number, rows: number, call?: CallOptions): Promise<void> {
    await this.clientFor(call).resizeSession(sandboxID, sessionID, cols, rows);
  }

  async sessionLog(sandboxID: string, sessionID: string, call?: CallOptions): Promise<Uint8Array> {
    return this.clientFor(call).sessionLog(sandboxID, sessionID);
  }

  async sessionRecording(sandboxID: string, sessionID: string, call?: CallOptions): Promise<Uint8Array> {
    return this.clientFor(call).sessionRecording(sandboxID, sessionID);
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
  async createTemplate(options: CreateTemplateOptions, call?: CallOptions): Promise<Template> {
    return this.clientFor(call).createTemplate(options);
  }

  async listTemplates(call?: CallOptions): Promise<Template[]> {
    return this.clientFor(call).listTemplates();
  }

  async getTemplate(id: string, call?: CallOptions): Promise<Template> {
    return this.clientFor(call).getTemplate(id);
  }

  async deleteTemplate(id: string, call?: CallOptions): Promise<void> {
    await this.clientFor(call).deleteTemplate(id);
  }

  /**
   * Register a WASM module in the host catalogue. Resolution is synchronous —
   * the returned row is typically already `ready`. Use the row's `id` or
   * `moduleRef` on subsequent `create` calls with `runtime: "wasm"`.
   */
  async createWasmModule(options: CreateWasmModuleOptions, call?: CallOptions): Promise<WasmModule> {
    return this.clientFor(call).createWasmModule(options);
  }

  async listWasmModules(call?: CallOptions): Promise<WasmModule[]> {
    return this.clientFor(call).listWasmModules();
  }

  async getWasmModule(id: string, call?: CallOptions): Promise<WasmModule> {
    return this.clientFor(call).getWasmModule(id);
  }

  async deleteWasmModule(id: string, call?: CallOptions): Promise<void> {
    await this.clientFor(call).deleteWasmModule(id);
  }

  /**
   * Upload a compiled core-wasip1 module to the registry under your own
   * credentials and get back the `oci://` ref to use as `moduleRef` on create.
   * The daemon validates and forwards the bytes; it never stores them.
   */
  async pushWasmModule(options: PushWasmModuleOptions, call?: CallOptions): Promise<PushWasmModuleResult> {
    return this.clientFor(call).pushWasmModule(options);
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
  async rebuildTemplate(id: string, call?: CallOptions): Promise<Template> {
    return this.clientFor(call).rebuildTemplate(id);
  }

  /**
   * Cluster-level DNS helpers. Exposed as a namespaced accessor (rather
   * than a flat `ingressDNS()` method) so call sites read like
   * `microvm.dns.target()`, mirroring the per-sandbox `sandbox.customDomains`
   * pattern. A fresh object is returned per access so the closures always
   * see the current client even if MicroVM is later extended.
   */
  get dns(): { target(call?: CallOptions): Promise<IngressTarget> } {
    const client = this.client;
    return {
      target: (call?: CallOptions) => client.withSignal(call?.signal).ingressDNS(),
    };
  }

  /**
   * Who the server says the caller is: principal, role, team and when the
   * credential expires. Every valid credential may ask.
   */
  async whoami(call?: CallOptions): Promise<WhoAmI> {
    return this.clientFor(call).whoami();
  }

  /**
   * Scoped API tokens (`avm_…`) for services and CI, as
   * `microvm.tokens.create/list/revoke`. Same namespaced shape as
   * {@link MicroVM.dns}.
   */
  get tokens(): Tokens {
    const client = this.client;
    return {
      create: (options, call) => client.withSignal(call?.signal).createAPIToken(options),
      list: (call) => client.withSignal(call?.signal).listAPITokens(),
      revoke: (id, call) => client.withSignal(call?.signal).revokeAPIToken(id),
    };
  }

  /** The client for one call: the real one, or a view carrying the call's signal. */
  private clientFor(call?: CallOptions): APIClient {
    return this.client.withSignal(call?.signal);
  }

  private wrap(sandbox: SandboxData): Sandbox {
    return new Sandbox(this.client, sandbox);
  }
}

function normalizeURL(value: string): string {
  return stripTrailingSlashes(value);
}

function readEnv(name: string): string | undefined {
  if (typeof process === "undefined" || !process.env) {
    return undefined;
  }
  const value = process.env[name];
  return typeof value === "string" && value !== "" ? value : undefined;
}
