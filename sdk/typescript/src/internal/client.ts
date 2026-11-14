import { lstat, readdir, readFile, readlink, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import { gzipSync } from "node:zlib";

import { tarArchive, type TarEntry } from "./tar.js";

import {
  PATH_PREFIX as V1_PATH_PREFIX,
  ingressDNSPath as v1IngressDNSPath,
  sandboxCustomDomainDNSPath as v1SandboxCustomDomainDNSPath,
  sandboxCustomDomainPath as v1SandboxCustomDomainPath,
  sandboxCustomDomainsPath as v1SandboxCustomDomainsPath,
} from "./api/v1/paths.js";
import {
  MicroVMApiError,
  MicroVMConflictError,
  MicroVMFileTooLargeError,
  MicroVMNotFoundError,
  MicroVMUnsupportedFeatureError,
  apiErrorFor,
} from "../errors.js";
import { Image } from "../Image.js";
import type {
  CallOptions,
  AddCustomDomainOptions,
  APIToken,
  APITokenList,
  BinaryLike,
  BuildImageOptions,
  BuildImageResult,
  CreateAPITokenOptions,
  CreatedAPIToken,
  CreateOptions,
  CreateSandboxTokenOptions,
  RevokeSandboxTokensResult,
  SandboxToken,
  CreateSessionOptions,
  CreateTemplateOptions,
  CreateWasmModuleOptions,
  PushWasmModuleOptions,
  PushWasmModuleResult,
  CustomDomain,
  CloneGeneration,
  CustomDomainDNSRecords,
  CustomDomainStatus,
  ExecExitInfo,
  ExecRequest,
  ExecResult,
  ExecStreamHandle,
  ExecStreamOptions,
  ExposedPort,
  ExposePortOptions,
  ExposeProtocol,
  ExposeResult,
  Failover,
  FileEvent,
  FileWatchHandle,
  FileInfo,
  FileList,
  FileMatch,
  UploadFileOptions,
  DownloadFileOptions,
  ListFilesOptions,
  DeleteFileOptions,
  MakeDirOptions,
  MoveFileOptions,
  CopyFileOptions,
  GPUOptions,
  HealthStatus,
  IngressTarget,
  Lifecycle,
  GetOptions,
  ListOptions,
  MountSpec,
  MountSpecRedacted,
  NetworkUsage,
  AuditEvent,
  AuditOptions,
  AuditPage,
  EgressProfile,
  EgressProfileList,
  EgressProfileOptions,
  EgressProfileRef,
  TeamQuota,
  TeamQuotaOptions,
  IdentityOptions,
  IdentityRole,
  IdentityRoleList,
  IdentityRoleOptions,
  ListIdentityRolesOptions,
  SandboxIdentity,
  EgressRule,
  ListEgressProfilesOptions,
  WarmPool,
  WarmPoolOptions,
  WarmPoolStatus,
  NetworkLearned,
  NetworkPolicy,
  NetworkPolicyCheckOptions,
  NetworkPolicyCheckResult,
  NetworkPolicyOptions,
  PlatformVolumeMount,
  ListSnapshotsOptions,
  CreateSnapshotOptions,
  RegisterSnapshotOptions,
  SnapshotList,
  SetNetworkLimitsOptions,
  ResizeOptions,
  Sandbox,
  SandboxSnapshot,
  Session,
  SessionAttachHandle,
  SessionAttachOptions,
  StatusReason,
  Template,
  TemplatePushState,
  TemplateStatus,
  WasmModule,
  WasmModuleStatus,
  WhoAmI,
  WatchFilesOptions,
} from "../types.js";

type FetchLike = typeof fetch;

/**
 * The request header that selects which of a credential's teams a request
 * acts for. Keep in sync with pkg/api.HeaderTeam on the server.
 */
export const TEAM_HEADER = "X-AerolVM-Team";

/**
 * The response header a 421 carries when the sandbox lives in another cell
 * (a separate AerolVM install in the same federation): that cell's base URL.
 * Keep in sync with models.CellEndpointHeader on the server.
 */
export const CELL_ENDPOINT_HEADER = "X-Aerolvm-Cell-Endpoint";

/**
 * Wire version of the v1-style sandbox endpoints (`/v1/sandboxes`, etc.) this
 * client speaks. The SDK and the server version independently — bumping the
 * SDK package does not move the wire version. Today only "v1" exists; future
 * breaking changes to the sandbox endpoints will land in a new version
 * prefix.
 *
 * The `/v1/images/build` endpoint used by {@link Image}-shaped image inputs
 * is called unconditionally when an Image is supplied to
 * {@link APIClient.create}, regardless of `apiVersion`. Daemons older than
 * the image-build feature return 404; the SDK turns that into a clear
 * "daemon does not support image builds" error so the user can switch to a
 * string image.
 */
export type APIVersion = "v1";

const DEFAULT_API_VERSION: APIVersion = "v1";

const PATH_PREFIXES: Record<APIVersion, string> = {
  v1: V1_PATH_PREFIX,
};

/**
 * Retry configuration for transient transport and server errors.
 * All fields are optional — the SDK ships sensible defaults.
 */
export interface RetryConfig {
  /**
   * Maximum number of retry attempts after the initial request fails.
   * Set to `0` to disable retry entirely. Defaults to `3`.
   */
  maxRetries?: number;
  /**
   * Initial backoff delay in milliseconds. Subsequent retries double this
   * value (exponential backoff). Defaults to `200`.
   */
  baseDelayMs?: number;
  /**
   * Hard ceiling on the computed delay in milliseconds. Prevents unbounded
   * waits when `maxRetries` is high. Defaults to `5000`.
   */
  maxDelayMs?: number;
  /**
   * Cap in milliseconds on the wait before re-sending a 429 or 503. The SDK
   * waits as long as the server's `Retry-After` header asks (seconds or an
   * HTTP date), never less than its own backoff, plus up to a fifth more so
   * clients told the same value spread out; a longer ask is cut to this. A
   * missing or malformed header uses the backoff above. Defaults to
   * `30000`; `0` ignores `Retry-After`.
   */
  maxRetryAfterMs?: number;
}

export interface APIClientConfig {
  baseURL: string;
  patToken?: string;
  /**
   * Sent as the {@link TEAM_HEADER} header on every HTTP request. Empty or
   * absent sends no header.
   */
  team?: string;
  fetch?: FetchLike;
  /**
   * Wire version to call. Defaults to "v1". Pin this if you need a specific
   * version — otherwise the SDK will track its own default, which may move in
   * a future major SDK release.
   */
  apiVersion?: APIVersion;
  /**
   * Retry policy for transient transport errors (socket closed, connection
   * reset) and retryable HTTP status codes (421, 429, 502, 503, 504). `exec`
   * is narrower: it retries only failures that prove the command never
   * reached the server (connection refused, connect timeout, DNS) and HTTP
   * 429/503. Pass `{ maxRetries: 0 }` to disable retry entirely.
   */
  retry?: RetryConfig;
  /**
   * Cancels the client's HTTP requests: aborting it ends the request in
   * flight and any retry wait, so a call never sits out a long
   * `Retry-After` once aborted. WebSocket streams are not affected.
   */
  signal?: AbortSignal;
}

interface ApiWhoAmI {
  principal: { kind: string; id: string; name?: string };
  role: string;
  team?: string;
  expires_at?: string;
}

interface ApiAPIToken {
  id: string;
  name: string;
  role: string;
  team: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  expired: boolean;
}

function fromApiWhoAmI(w: ApiWhoAmI): WhoAmI {
  const out: WhoAmI = {
    principal: { kind: w.principal.kind, id: w.principal.id },
    role: w.role,
  };
  if (w.principal.name) out.principal.name = w.principal.name;
  if (w.team) out.team = w.team;
  if (w.expires_at) out.expiresAt = w.expires_at;
  return out;
}

function fromApiAPIToken(t: ApiAPIToken): APIToken {
  return {
    id: t.id,
    name: t.name,
    role: t.role,
    team: t.team,
    createdBy: t.created_by,
    createdAt: t.created_at,
    expiresAt: t.expires_at,
    expired: t.expired === true,
  };
}

interface ApiExposedPort {
  sandbox_id: string;
  port: number;
  public_url: string;
  created_at: string;
  visibility?: string;
}

interface ApiExposePortResponse {
  protocol: ExposeProtocol;
  public_url: string;
  host?: string;
  host_port?: number;
  visibility?: string;
}

interface ApiSandboxToken {
  token: string;
  token_id: string;
  sandbox_id: string;
  port?: number;
  path_prefix?: string;
  methods?: string[];
  expires_at: string;
}

interface ApiRevokeSandboxTokens {
  sandbox_id: string;
  tokens_not_before: string;
}

interface ApiCustomDomain {
  hostname: string;
  status: CustomDomainStatus;
  last_error?: string;
  created_at: string;
  updated_at: string;
  target_port?: number;
}

interface ApiCustomDomainList {
  custom_domains: ApiCustomDomain[];
}

interface ApiLifecycle {
  stop_if_idle_for?: number;
  destroy_if_idle_for?: number;
  stop_at_age?: number;
  destroy_at_age?: number;
  serverless?: boolean;
  restart_on_failure?: boolean;
  destroy_after_exit_for?: number;
  destroy_at?: string;
}

interface ApiFailover {
  policy?: string;
}

interface ApiTeamQuota {
  team: string;
  max_sandboxes?: number;
  max_cpu?: number;
  max_memory_mb?: number;
  generation: number;
  created_at: string;
  updated_at: string;
  usage?: { sandboxes: number; cpu: number; memory_mb: number };
}

function fromApiTeamQuota(q: ApiTeamQuota): TeamQuota {
  const out: TeamQuota = { team: q.team, generation: q.generation, createdAt: q.created_at, updatedAt: q.updated_at };
  if (q.max_sandboxes) out.maxSandboxes = q.max_sandboxes;
  if (q.max_cpu) out.maxCPU = q.max_cpu;
  if (q.max_memory_mb) out.maxMemoryMB = q.max_memory_mb;
  if (q.usage) out.usage = { sandboxes: q.usage.sandboxes, cpu: q.usage.cpu, memoryMB: q.usage.memory_mb };
  return out;
}

interface ApiEgressProfile {
  name: string;
  allow_out: string[] | null;
  description?: string;
  generation: number;
  created_at: string;
  updated_at: string;
}

function fromApiEgressProfile(p: ApiEgressProfile): EgressProfile {
  const out: EgressProfile = {
    name: p.name,
    allowOut: p.allow_out ?? [],
    generation: p.generation,
    createdAt: p.created_at,
    updatedAt: p.updated_at,
  };
  if (p.description) out.description = p.description;
  return out;
}

interface ApiWarmPool {
  image: string;
  depth: number;
  min_depth?: number;
  max_depth?: number;
  on_image_change?: string;
  generation: number;
  created_at: string;
  updated_at: string;
  status?: {
    ready: number;
    target: number;
    outdated?: number;
    servers: { node_id: string; ready: number; target: number; outdated?: number; stale?: boolean }[] | null;
  };
}

function fromApiWarmPool(p: ApiWarmPool): WarmPool {
  const out: WarmPool = {
    image: p.image,
    depth: p.depth,
    onImageChange: (p.on_image_change || "replace_now") as WarmPool["onImageChange"],
    generation: p.generation,
    createdAt: p.created_at,
    updatedAt: p.updated_at,
  };
  if (p.min_depth) out.minDepth = p.min_depth;
  if (p.max_depth) out.maxDepth = p.max_depth;
  if (p.status) {
    const status: WarmPoolStatus = { ready: p.status.ready, target: p.status.target, outdated: p.status.outdated ?? 0, servers: [] };
    for (const s of p.status.servers ?? []) {
      const server: WarmPoolStatus["servers"][number] = { nodeId: s.node_id, ready: s.ready, target: s.target, outdated: s.outdated ?? 0 };
      if (s.stale) server.stale = true;
      status.servers.push(server);
    }
    out.status = status;
  }
  return out;
}

// An image is the rest of the warm-pool path. Each segment is escaped and the
// slashes are kept, so ghcr.io/acme/agent:1 reaches the server as written and
// no proxy has an encoded slash to rewrite.
function warmPoolPath(image: string): string {
  return `/warm-pools/${image.split("/").map(encodeURIComponent).join("/")}`;
}

// Only inject's secretRef is spelled differently on the wire, so a rule
// otherwise goes through as written and the server applies its own port
// default.
type ApiEgressRule = Omit<EgressRule, "inject"> & { inject?: { header: string; secret_ref: string } };

function toApiEgressRule({ inject, ...rule }: EgressRule): ApiEgressRule {
  return inject ? { ...rule, inject: { header: inject.header, secret_ref: inject.secretRef } } : rule;
}

function fromApiEgressRule({ inject, ...rule }: ApiEgressRule): EgressRule {
  return inject ? { ...rule, inject: { header: inject.header, secretRef: inject.secret_ref } } : rule;
}

interface ApiSandbox {
  id: string;
  name?: string;
  tags?: Record<string, string>;
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
  egress_status?: string;
  egress_profiles?: string[];
  egress_profiles_applied?: { name: string; generation: number }[];
  network_egress_mode?: string;
  network_egress_rules?: ApiEgressRule[] | null;
  toolbox_enabled: boolean;
  ssh_public_key?: string;
  exposed_ports?: ApiExposedPort[];
  created_at: string;
  updated_at: string;
  last_active_at: string;
  last_error?: string;
  status_reason?: string;
  exit_code?: number | null;
  container_command?: string[];
  lifecycle?: ApiLifecycle;
  failover?: ApiFailover;
  runtime?: string;
  durability?: string;
  module_ref?: string;
  module_digest?: string;
  tenant_id?: string;
  identity?: ApiSandboxIdentity;
}

interface ApiSandboxIdentity {
  role_tag: string;
  audience: string;
  subject: string;
  aws_role_arn?: string;
  azure_client_id?: string;
  azure_tenant_id?: string;
  token_file: string;
  token_expires_at?: string;
  last_error?: string;
}

interface ApiIdentityRole {
  tag: string;
  min_role: string;
  team?: string;
  created_at: string;
  updated_at: string;
}

function fromApiIdentityRole(r: ApiIdentityRole): IdentityRole {
  const out: IdentityRole = { tag: r.tag, minRole: r.min_role, createdAt: r.created_at, updatedAt: r.updated_at };
  if (r.team) out.team = r.team;
  return out;
}

function fromApiSandboxIdentity(i: ApiSandboxIdentity | undefined): SandboxIdentity | undefined {
  if (!i) return undefined;
  const out: SandboxIdentity = { roleTag: i.role_tag, audience: i.audience, subject: i.subject, tokenFile: i.token_file };
  if (i.aws_role_arn) out.awsRoleArn = i.aws_role_arn;
  if (i.azure_client_id) out.azureClientId = i.azure_client_id;
  if (i.azure_tenant_id) out.azureTenantId = i.azure_tenant_id;
  if (i.token_expires_at) out.tokenExpiresAt = i.token_expires_at;
  if (i.last_error) out.lastError = i.last_error;
  return out;
}

function toApiIdentity(i: IdentityOptions): Record<string, unknown> {
  return {
    role_tag: i.roleTag,
    audience: i.audience,
    aws_role_arn: i.awsRoleArn,
    azure_client_id: i.azureClientId,
    azure_tenant_id: i.azureTenantId,
  };
}

interface ApiCreateSandboxResponse extends ApiSandbox {
  ssh_private_key?: string;
}

interface ApiTemplate {
  id: string;
  image: string;
  status: TemplateStatus;
  rootfs_size_bytes?: number;
  min_size_mib?: number;
  last_error?: string;
  created_at: string;
  updated_at: string;
  ready_at?: string;
  snapshot_size_bytes?: number;
  snapshot_error?: string;
  has_snapshot: boolean;
  has_overlay: boolean;
  push_state?: TemplatePushState;
  push_error?: string;
}

interface ApiWasmModule {
  id: string;
  module_ref: string;
  status: WasmModuleStatus;
  module_size_bytes?: number;
  digest?: string;
  entrypoint?: string;
  has_warm: boolean;
  last_error?: string;
  created_at: string;
  updated_at: string;
  ready_at?: string;
}

interface ApiSandboxSnapshot {
  name: string;
  image: string;
  image_id?: string;
  source_sandbox_id: string;
  created_at: string;
  entrypoint?: string[];
  region_id?: string;
  cpu?: number;
  gpu?: number;
  memory_mb?: number;
  disk_gb?: number;
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
  timed_out?: boolean;
  stdout_truncated?: boolean;
  stderr_truncated?: boolean;
  signal?: string;
}

interface ApiHealthStatus {
  status: string;
  sandboxes: number;
  docker: string;
  caddy: string;
  ssh_gateway?: string;
  version: string;
}

interface ApiCloneGeneration {
  generation: string;
  resumed_at: number;
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

interface ApiPlatformVolumeMount {
  name: string;
  path: string;
  read_only?: boolean;
  delete_with_sandbox?: boolean;
}

interface ApiAuditEvent {
  time: string;
  kind?: string;
  result: string;
  reason?: string;
  destination?: string;
  network?: string;
  actor?: string;
  ref?: string;
  event_id?: string;
  incarnation_id?: string;
  dropped?: number;
}

interface ApiAuditPage {
  events: ApiAuditEvent[] | null;
  coverage?: { answered?: string[] | null; missing?: string[] | null; partial?: boolean };
  next_cursor?: string;
}

interface ApiNetworkUsage {
  sandbox_id: string;
  bytes_in: number;
  bytes_out: number;
  bytes_in_limit: number;
  bytes_out_limit: number;
  quota_exceeded: boolean;
  quota_exceeded_at?: string | null;
  last_sampled_at?: string | null;
}

/** HTTP status codes the retry loop considers transient. */
// 421 Misdirected Request: an owner answered for a sandbox it doesn't hold
// (HTTP/2 connection coalescing, or a stale ingress route after failover).
// The server closes the connection, so the retry reconnects and the ingress
// re-routes it (plans/ingress-proxy-routing.md, review 2A).
const RETRYABLE_STATUS_CODES = new Set([421, 429, 502, 503, 504]);

// The subset a non-idempotent request (exec) may retry: 429 and 503 are the
// server turning the request away before doing any work. 421, 502 and 504 come
// from forwarding/proxy hops, and the status alone can't prove that no hop
// already handed the command to the sandbox, so exec surfaces them. They are
// also the statuses whose Retry-After paces clients: 429 when this caller is
// over its share, 503 when the node sheds load. A Retry-After on a 421, 502 or
// 504 is a hop's, not the server's, so those use the normal backoff.
const REFUSED_STATUS_CODES = new Set([429, 503]);

// Bounds the sandbox-to-cell map, so a long-lived client that touches many
// sandboxes in other cells cannot grow without end. A dropped entry costs
// only one more 421 the next time.
const MAX_REMEMBERED_CELLS = 10_000;

/**
 * A 421 that names a cell is the cell router's answer, which sending to the
 * same place again cannot change. The retry loop hands it back at once and
 * {@link APIClient.request} decides whether to follow it.
 */
function isCellAnswer(response: Response): boolean {
  return response.status === 421 && (response.headers.get(CELL_ENDPOINT_HEADER) ?? "").trim() !== "";
}

// fetch reads a stream while it sends it, so only a body held whole in
// memory can go out a second time.
function isReplayableBody(body: BodyInit | null | undefined): boolean {
  return (
    body == null ||
    typeof body === "string" ||
    body instanceof ArrayBuffer ||
    ArrayBuffer.isView(body) ||
    body instanceof Blob ||
    body instanceof FormData ||
    body instanceof URLSearchParams
  );
}

/** The sandbox ID a per-sandbox path names: the segment right after `prefix` (".../sandboxes/"). */
function sandboxIDInPath(path: string, prefix: string): string | undefined {
  if (!path.startsWith(prefix)) return undefined;
  const rest = path.slice(prefix.length);
  const end = rest.search(/[/?#]/);
  const segment = end === -1 ? rest : rest.slice(0, end);
  if (segment === "") return undefined;
  // Some call sites escape the ID and some do not; decoding keys both alike.
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/**
 * The toolboxd feature (on /version) behind the file verbs' options: list
 * depth and cap, the move and copy overwrite guard, mkdir without parents and
 * the copy route. An older agent ignores those options (overwrite=false would
 * overwrite), so the calls that send them check first.
 */
const FEATURE_FILE_VERBS = "files.verbs";

/**
 * The toolboxd feature behind upload's write options. An older agent ignores
 * them: createOnly would replace an existing file.
 */
const FEATURE_WRITE_OPTIONS = "files.write_options";

/**
 * The toolboxd feature behind upload's extract=true (uploadDir). An older
 * agent ignores extract and would store the archive itself as a file.
 */
const FEATURE_EXTRACT = "files.extract";

/** The entry cap `listFiles` sends when the caller gives none. */
export const DEFAULT_LIST_LIMIT = 10_000;

/** Per-call options for {@link APIClient.request}. */
interface RequestOptions {
  /**
   * For a call whose retry can find its own work done (a delete finds the
   * path gone, a mkdir its folder): when a re-sent attempt gets an error
   * carrying this toolbox error code after an earlier attempt whose reply
   * was lost (a dropped connection, 502 or 504), that attempt did the work
   * and the call succeeds with an empty 204. After a 421, 429 or 503 the
   * server did nothing, so the error stands.
   */
  doneCode?: string;
  /** Send the request once, never retried: a body plan section 10 says is never re-sent (a folder upload). */
  sendOnce?: boolean;
  /**
   * `false` for a request the server must not receive twice: re-sending an
   * exec runs the caller's command again. Only failures that prove the
   * request never left the client, plus 429/503, are then retried. Defaults
   * to `true` because the daemon designs every other endpoint for idempotent
   * retry.
   */
  idempotent?: boolean;
  /** Extra request headers, sent unchanged on every retry. */
  headers?: Record<string, string>;
}

/**
 * The header a sandbox create carries so the server can recognise a retry of
 * it. Keep in sync with clustercreate.HeaderIdempotencyKey on the server.
 */
export const IDEMPOTENCY_KEY_HEADER = "Idempotency-Key";

/** A fresh create key: 128 random bits as 32 lowercase hex characters. */
export function newIdempotencyKey(): string {
  // getRandomValues, unlike randomUUID, also works on a page served over
  // plain http.
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Default retry settings when the caller doesn't supply a RetryConfig. */
const DEFAULT_RETRY: Required<RetryConfig> = {
  maxRetries: 3,
  baseDelayMs: 200,
  maxDelayMs: 5_000,
  // An overloaded node asks for about a second, so the cap only bites on a
  // long ask (maintenance, a misconfigured proxy), which should not hold a
  // call for minutes per retry.
  maxRetryAfterMs: 30_000,
};

// IMF-fixdate, the HTTP-date form servers send ("Sun, 06 Nov 1994 08:49:37
// GMT"). Date.parse alone would also take "1" or a date with no zone, read in
// local time.
const IMF_FIXDATE = /^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/;

/**
 * Reads a `Retry-After` value in either form RFC 9110 allows: delta-seconds
 * (`"120"`) or an HTTP date. Returns the wait in milliseconds (0 for a date
 * already past), or `undefined` for an absent or malformed value.
 */
export function parseRetryAfter(value: string | null | undefined, nowMs: number): number | undefined {
  const trimmed = (value ?? "").trim();
  if (/^[0-9]+$/.test(trimmed)) {
    return Number(trimmed) * 1000;
  }
  if (!IMF_FIXDATE.test(trimmed)) {
    return undefined;
  }
  const when = Date.parse(trimmed);
  return Number.isNaN(when) ? undefined : Math.max(when - nowMs, 0);
}

/**
 * How long {@link APIClient.request} waits before re-sending. `attempt`
 * counts from 0, `retryAfter` is a 429/503's `Retry-After` header (null
 * otherwise) and `random` is uniform in [0, 1).
 *
 * Without a usable header it is the exponential backoff ±25%. With one, it
 * never retries sooner than the server asked (nor sooner than the backoff)
 * and adds up to a fifth so clients told the same value spread out.
 * `maxRetryAfterMs` is a hard ceiling: when the server asks for at least
 * that long the client is early anyway, so the spread goes below it instead.
 */
export function retryDelayMs(
  config: Required<RetryConfig>,
  attempt: number,
  retryAfter: string | null,
  nowMs: number,
  random: number,
): number {
  const backoff = Math.min(config.baseDelayMs * 2 ** attempt, config.maxDelayMs);
  const limit = config.maxRetryAfterMs;
  const hint = limit > 0 ? parseRetryAfter(retryAfter, nowMs) : undefined;
  if (hint === undefined) {
    return backoff * (0.75 + 0.5 * random);
  }
  const target = Math.max(hint, backoff);
  if (target >= limit) {
    return limit - limit * 0.2 * random;
  }
  const upper = Math.min(target * 1.2, limit);
  return target + (upper - target) * random;
}

/**
 * Returns `true` when the thrown `error` looks like a transport-level failure
 * that vanishes on retry (connection reset, socket closed by peer, DNS
 * blip). `undici` and Node core use several `cause.code` values; we check
 * the full cause chain. A reset, EPIPE, read/headers/body timeout or "other
 * side closed" can fire after the server already received the request, so
 * this classification is only safe for idempotent requests.
 */
function isTransientTransportError(error: unknown): boolean {
  const codes = new Set([
    "UND_ERR_SOCKET",
    "ECONNRESET",
    "ECONNREFUSED",
    "ETIMEDOUT",
    "EPIPE",
    "EAI_AGAIN",
    "UND_ERR_CONNECT_TIMEOUT",
    "UND_ERR_BODY_TIMEOUT",
    "UND_ERR_HEADERS_TIMEOUT",
  ]);
  let current: unknown = error;
  for (let depth = 0; depth < 5 && current != null; depth++) {
    if (current instanceof Error) {
      const code = (current as NodeJS.ErrnoException).code;
      if (code && codes.has(code)) return true;
      if (current.message && /socket hang up|other side closed/i.test(current.message)) return true;
      current = (current as { cause?: unknown }).cause;
    } else {
      break;
    }
  }
  return false;
}

/**
 * Returns `true` only for transport failures that prove the request never
 * left the client: the connection was refused, did not open before the
 * connect timeout, or the host name did not resolve (transiently; ENOTFOUND
 * is not retried for any request). Any other code in the cause chain means
 * bytes may have reached the server, so the answer is `false`.
 */
function isUnsentTransportError(error: unknown): boolean {
  let current: unknown = error;
  for (let depth = 0; depth < 5 && current instanceof Error; depth++) {
    const err = current as NodeJS.ErrnoException;
    switch (err.code) {
      case undefined:
        break;
      case "ECONNREFUSED":
      case "EAI_AGAIN":
      case "UND_ERR_CONNECT_TIMEOUT":
        return true;
      case "ETIMEDOUT":
        // Node uses ETIMEDOUT both for a connect that never completed and for
        // an open socket that stopped answering; only the first is unsent.
        return failedWhileConnecting(err);
      default:
        return false;
    }
    current = err.cause;
  }
  return false;
}

function failedWhileConnecting(err: NodeJS.ErrnoException): boolean {
  if (err.syscall === "connect") return true;
  // With autoSelectFamily (Node's default), a host with several addresses
  // fails with an AggregateError holding one error per connect attempt and no
  // syscall of its own.
  return (
    err instanceof AggregateError &&
    err.errors.length > 0 &&
    err.errors.every((inner) => (inner as NodeJS.ErrnoException | undefined)?.syscall === "connect")
  );
}

/**
 * Trim trailing slashes from a URL without a backtracking regex. The natural
 * `value.replace(/\/+$/, "")` is an anchored `+` quantifier — a polynomial
 * ReDoS shape that CodeQL flags — so we strip by index instead, which is O(n).
 */
export function stripTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47 /* "/" */) {
    end--;
  }
  return value.slice(0, end);
}

/** A signal that aborts when any of `signals` does, with that one's reason. */
function anySignal(signals: AbortSignal[]): AbortSignal {
  const native = (AbortSignal as unknown as { any?: (signals: AbortSignal[]) => AbortSignal }).any;
  if (typeof native === "function") return native.call(AbortSignal, signals);
  const controller = new AbortController();
  for (const signal of signals) {
    if (signal.aborted) {
      controller.abort(signal.reason);
      break;
    }
    signal.addEventListener("abort", () => controller.abort(signal.reason), { once: true });
  }
  return controller.signal;
}

/** Waits `ms`, or rejects with the signal's reason as soon as it aborts. */
function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export class APIClient {
  readonly baseURL: string;
  readonly apiVersion: APIVersion;

  // Not enumerable (set in the constructor): JSON.stringify, object spread
  // and Object.keys of a client must never carry the token.
  declare private readonly patToken: string;
  private readonly team: string;
  private readonly fetchFn: FetchLike;
  private readonly versionPrefix: string;
  private readonly retryConfig: Required<RetryConfig>;
  private readonly signal: AbortSignal | undefined;
  /** The client a {@link withSignal} view was made from; unset on a real client. */
  private readonly root: APIClient | undefined;
  /**
   * Features each sandbox's agent listed on /version (requireToolboxFeatures).
   * Refreshed on a miss, because a restart can bring a newer agent.
   */
  private readonly toolboxFeatures = new Map<string, Set<string>>();
  /**
   * The base URL of the cell each sandbox in another cell lives in, learned
   * from a 421 that named it, oldest first. Shared with {@link withSignal}
   * views, so what one call learns routes the next. Entries are dropped only
   * on a 404 from that cell (the sandbox may be gone) or past
   * {@link MAX_REMEMBERED_CELLS}: the cell is minted into the ID, so it
   * never changes.
   */
  private readonly sandboxCells = new Map<string, string>();

  constructor(config: APIClientConfig) {
    this.baseURL = stripTrailingSlashes(config.baseURL);
    Object.defineProperty(this, "patToken", { value: config.patToken ?? "", enumerable: false });
    this.team = (config.team ?? "").trim();
    this.fetchFn = config.fetch ?? fetch;
    this.apiVersion = config.apiVersion ?? DEFAULT_API_VERSION;
    this.versionPrefix = PATH_PREFIXES[this.apiVersion];
    this.retryConfig = {
      maxRetries: config.retry?.maxRetries ?? DEFAULT_RETRY.maxRetries,
      baseDelayMs: config.retry?.baseDelayMs ?? DEFAULT_RETRY.baseDelayMs,
      maxDelayMs: config.retry?.maxDelayMs ?? DEFAULT_RETRY.maxDelayMs,
      maxRetryAfterMs: config.retry?.maxRetryAfterMs ?? DEFAULT_RETRY.maxRetryAfterMs,
    };
    this.signal = config.signal;
  }

  /**
   * Build a versioned API path. Pass the suffix beginning with "/" (e.g.
   * "/sandboxes") and the active version's prefix is prepended. Use this for
   * every versioned API call so a future wire version can be selected by the
   * apiVersion option without touching call sites.
   */
  private versioned(suffix: string): string {
    return `${this.versionPrefix}${suffix}`;
  }

  /**
   * This client with `signal` added to its own: either one aborting ends a
   * request and any retry wait. A per-call signal (plan S6) rides on a view
   * like this rather than a parameter on every internal method. The view
   * shares everything else, the per-sandbox feature cache included, and the
   * sandboxes it returns hold the real client, so the call's signal never
   * outlives the call. Without a signal it is this client.
   */
  withSignal(signal: AbortSignal | undefined): APIClient {
    if (!signal) return this;
    const view = Object.create(this) as APIClient;
    Object.defineProperty(view, "signal", { value: this.signal ? anySignal([this.signal, signal]) : signal });
    Object.defineProperty(view, "root", { value: this.root ?? this });
    return view;
  }

  async create(options: CreateOptions): Promise<SandboxResource> {
    const resolved = await this.resolveImage(options);
    // One key per call, sent unchanged on each of its automatic retries: a
    // create retried after a timeout gets back the sandbox the first attempt
    // made instead of making a second one.
    const key = options.idempotencyKey?.trim() || newIdempotencyKey();
    const response = await this.doJSON<ApiCreateSandboxResponse>("POST", this.versioned("/sandboxes"), toApiCreateOptions(resolved), {
      headers: { [IDEMPOTENCY_KEY_HEADER]: key },
    });
    return new SandboxResource(this, fromApiCreateSandboxResponse(response));
  }

  /**
   * Compile a fluent {@link Image} into a content-addressed image tag by
   * POSTing its Dockerfile to `/v1/images/build`. The daemon caches by
   * content hash, so repeated calls with the same Dockerfile are a no-op.
   * String images are passed through unchanged.
   *
   * Daemons predating the image-build feature do not register the route and
   * return 404; this method translates that into a clear error telling the
   * caller to pass a string image instead, rather than the generic "request
   * failed with status 404" the JSON decoder would otherwise produce.
   */
  async buildImage(image: Image, options?: BuildImageOptions): Promise<BuildImageResult> {
    const body: {
      dockerfile_content: string;
      push?: {
        registry: string;
        tag?: string;
        server?: string;
        username: string;
        password: string;
      };
    } = { dockerfile_content: image.dockerfile };
    if (options?.push) {
      const p = options.push;
      if (!p.registry) {
        throw new Error("buildImage: push.registry is required when push is set");
      }
      if (!p.username || !p.password) {
        throw new Error("buildImage: push.username and push.password are required when push is set");
      }
      body.push = {
        registry: p.registry,
        tag: p.tag,
        server: p.server,
        username: p.username,
        password: p.password,
      };
    }
    const response = await this.request(
      "POST",
      "/v1/images/build",
      {
        body: JSON.stringify(body),
        headers: { "Content-Type": "application/json" },
      },
    );
    if (response.status === 404) {
      await response.text().catch(() => undefined);
      throw new Error(
        "this daemon does not support Image builds (POST /v1/images/build is not registered) — pass a string image reference (e.g. \"ubuntu:22.04\") instead, or upgrade the daemon",
      );
    }
    if (!response.ok) {
      throw await decodeError(response);
    }
    const payload = (await response.json()) as { image: string; pushed?: string };
    return { image: payload.image, pushed: payload.pushed };
  }

  private async resolveImage(options: CreateOptions): Promise<CreateOptions & { image: string }> {
    if (typeof options.image === "string") {
      return options as CreateOptions & { image: string };
    }
    if (!(options.image instanceof Image)) {
      throw new TypeError("CreateOptions.image must be a string or Image");
    }
    const result = await this.buildImage(options.image);
    return { ...options, image: result.image };
  }

  async list(options?: ListOptions): Promise<SandboxResource[]> {
    const items: SandboxResource[] = [];
    for await (const page of this.listPages(options)) {
      items.push(...page);
    }
    return items;
  }

  /** Streams bounded cluster-list pages and never accumulates the full fleet. */
  async *listPages(options?: ListOptions): AsyncGenerator<SandboxResource[]> {
    const basePath = this.versioned("/sandboxes") + buildSandboxListQuery(options);
    let pageToken = "";
    for (let page = 0; page < 100000; page++) {
      const path = appendQueryParam(basePath, "page_token", pageToken);
      const response = await this.request("GET", path);
      if (!response.ok) {
        throw await decodeError(response);
      }
      const partial = response.headers.get("X-Cluster-List-Partial");
      const placementReady = response.headers.get("X-Cluster-List-Placement-Ready");
      if (partial === "true" || placementReady === "false") {
        throw new Error("incomplete cluster list");
      }
      const body = (await response.json()) as ApiSandbox[] | null;
      yield (body ?? []).map((item) => this.wrap(item));
      pageToken = (response.headers.get("X-Cluster-List-Next-Page-Token") ?? "").trim();
      if (pageToken === "") {
        return;
      }
    }
    throw new Error("incomplete cluster list: exceeded max pages");
  }

  /**
   * Looks up the caller's sandbox by name with one request. The reply is only
   * trusted when it holds at most one sandbox and that sandbox carries the
   * requested name: a server that predates `?name=` ignores the filter and
   * returns an ordinary list page, and acting on its first row would target
   * the wrong sandbox.
   */
  async getByName(name: string, options?: GetOptions): Promise<SandboxResource | null> {
    const trimmed = name.trim();
    if (trimmed === "") {
      throw new Error("sandbox name is required");
    }
    const path = this.versioned("/sandboxes") + buildSandboxListQuery({ name: trimmed, includeEnv: options?.includeEnv });
    const body = await this.doJSON<ApiSandbox[] | null>("GET", path);
    const items = body ?? [];
    if (items.length === 0) {
      return null;
    }
    if (items.length > 1 || items[0].name !== trimmed) {
      throw new Error(
        `${this.baseURL} does not support sandbox name lookup; use the sandbox ID or upgrade the server`,
      );
    }
    return this.wrap(items[0]);
  }

  /**
   * The caller's sandbox called `name`, created from `options` when there is
   * none; `created` is true only when this call made it. Safe to retry and to
   * run concurrently: names are unique per owner, so a caller that loses a
   * race to create the name gets a 409 and reads the winner's sandbox.
   */
  async getOrCreate(name: string, options: CreateOptions): Promise<{ sandbox: SandboxResource; created: boolean }> {
    const wanted = name.trim();
    if (wanted === "") {
      throw new Error("sandbox name is required");
    }
    const given = options.name?.trim() ?? "";
    if (given !== "" && given !== wanted) {
      throw new Error(`options name "${given}" differs from "${wanted}"`);
    }
    const existing = await this.getByName(wanted);
    if (existing !== null) {
      return { sandbox: existing, created: false };
    }
    try {
      return { sandbox: await this.create({ ...options, name: wanted }), created: true };
    } catch (err) {
      if (!(err instanceof MicroVMConflictError)) throw err;
      // Another caller created the name after the lookup. A 409 whose name
      // still cannot be found is a conflict on something else, so the
      // create's own error stands.
      const winner = await this.getByName(wanted);
      if (winner === null) throw err;
      return { sandbox: winner, created: false };
    }
  }

  async get(id: string, options?: GetOptions): Promise<SandboxResource> {
    const q = buildIncludeEnvQuery(options?.includeEnv);
    const response = await this.doJSON<ApiSandbox>("GET", `${this.versionPrefix}/sandboxes/${id}${q}`);
    return this.wrap(response);
  }

  async start(id: string): Promise<SandboxResource> {
    const response = await this.doJSON<ApiSandbox>("POST", `${this.versionPrefix}/sandboxes/${id}/start`);
    return this.wrap(response);
  }

  async stop(id: string): Promise<SandboxResource> {
    const response = await this.doJSON<ApiSandbox>("POST", `${this.versionPrefix}/sandboxes/${id}/stop`);
    return this.wrap(response);
  }

	async createSnapshot(id: string, name: string, options: CreateSnapshotOptions = {}): Promise<SandboxSnapshot> {
		const body: { name: string; allow_pause?: boolean } = { name };
		if (options.allowPause !== undefined) {
			body.allow_pause = options.allowPause;
		}
		const response = await this.doJSON<ApiSandboxSnapshot>("POST", `${this.versionPrefix}/sandboxes/${id}/snapshot`, body);
		return fromApiSandboxSnapshot(response);
	}

  async registerSnapshot(options: RegisterSnapshotOptions): Promise<SandboxSnapshot> {
    const name = options.name.trim();
    if (name === "") {
      throw new Error("name is required");
    }

    const image = options.image?.trim() ?? "";
    const dockerfileContent = options.dockerfileContent?.trim() ?? "";
    if (image === "" && dockerfileContent === "") {
      throw new Error("image or dockerfile_content is required");
    }
    if (image !== "" && dockerfileContent !== "") {
      throw new Error("image and dockerfile_content are mutually exclusive");
    }

    const response = await this.doJSON<ApiSandboxSnapshot>(
      "POST",
      this.versioned("/snapshots"),
      toApiRegisterSnapshotOptions({
        ...options,
        name,
        image: image || undefined,
        dockerfileContent: dockerfileContent || undefined,
        regionID: options.regionID?.trim() || undefined,
      }),
    );
    return fromApiSandboxSnapshot(response);
  }

  async registerSnapshotFromImage(
    name: string,
    image: Image,
    options: Omit<RegisterSnapshotOptions, "name" | "image" | "dockerfileContent"> = {},
  ): Promise<SandboxSnapshot> {
    return this.registerSnapshot({
      ...options,
      name,
      dockerfileContent: image.dockerfile,
    });
  }

  async getSnapshot(name: string): Promise<SandboxSnapshot> {
    return fromApiSandboxSnapshot(
      await this.doJSON<ApiSandboxSnapshot>("GET", this.versioned(`/snapshots/${encodeURIComponent(name)}`)),
    );
  }

  async listSnapshots(options: ListSnapshotsOptions = {}): Promise<SnapshotList> {
    const params = new URLSearchParams();
    if (options.limit) params.set("limit", String(options.limit));
    if (options.startingAfter) params.set("starting_after", options.startingAfter);
    const query = params.toString();
    const response = await this.doJSON<{ snapshots: ApiSandboxSnapshot[] | null; has_more?: boolean }>(
      "GET",
      this.versioned(`/snapshots${query ? `?${query}` : ""}`),
    );
    return {
      snapshots: (response.snapshots ?? []).map(fromApiSandboxSnapshot),
      hasMore: response.has_more ?? false,
    };
  }

  async deleteSnapshot(name: string): Promise<void> {
    await this.doJSON<void>("DELETE", this.versioned(`/snapshots/${encodeURIComponent(name)}`));
  }

  async destroy(id: string): Promise<void> {
    await this.doJSON<void>("DELETE", `${this.versionPrefix}/sandboxes/${id}`);
  }

  /**
   * Deletes every sandbox carrying all of `tags`, one at a time, after
   * listing every page; returns the IDs now gone. A 404 counts as deleted,
   * so the call is safe to repeat. Any other failure stops it and is thrown.
   */
  async destroyAll(tags: Record<string, string>): Promise<string[]> {
    if (!tags || Object.keys(tags).length === 0) {
      throw new Error("destroyAll needs at least one tag; with none it would delete every sandbox you own");
    }
    const ids: string[] = [];
    for await (const page of this.listPages({ tags })) {
      ids.push(...page.map((sandbox) => sandbox.id));
    }
    const gone: string[] = [];
    for (const id of ids) {
      try {
        await this.destroy(id);
      } catch (err) {
        if (!(err instanceof MicroVMNotFoundError)) throw err;
      }
      gone.push(id);
    }
    return gone;
  }

  async resize(id: string, options: ResizeOptions): Promise<SandboxResource> {
    const response = await this.doJSON<ApiSandbox>("POST", `${this.versionPrefix}/sandboxes/${id}/resize`, toApiResizeOptions(options));
    return this.wrap(response);
  }

  async updateLifecycle(id: string, lifecycle: Lifecycle): Promise<SandboxResource> {
    const response = await this.doJSON<ApiSandbox>("PUT", `${this.versionPrefix}/sandboxes/${id}/lifecycle`, toApiLifecycle(lifecycle));
    return this.wrap(response);
  }

  /**
   * Fails closed unless the sandbox's agent lists every feature. toolboxd
   * ignores request options it does not know, so sending a newer option to an
   * older agent would silently skip it.
   */
  async requireToolboxFeatures(id: string, ...features: string[]): Promise<void> {
    if (features.length === 0) {
      return;
    }
    let have = this.toolboxFeatures.get(id);
    let version = "";
    let runtime = "";
    if (!have || !features.every((feature) => have!.has(feature))) {
      const info = await this.doJSON<{ version?: string; features?: unknown; runtime?: unknown }>(
        "GET",
        `${this.versionPrefix}/sandboxes/${id}/toolbox/version`,
      );
      have = new Set(Array.isArray(info?.features) ? info.features.map(String) : []);
      this.toolboxFeatures.set(id, have);
      version = typeof info?.version === "string" ? info.version : "";
      runtime = typeof info?.runtime === "string" ? info.runtime : "";
    }
    const missing = features.filter((feature) => !have!.has(feature));
    if (missing.length > 0) {
      throw new MicroVMUnsupportedFeatureError(id, missing, version, runtime);
    }
  }

  async exec(id: string, request: ExecRequest): Promise<ExecResult> {
    // An older agent ignores the caps and returns all output, and refuses
    // argv with a confusing "command is required"; check first.
    const features: string[] = [];
    if (request.maxStdoutBytes || request.maxStderrBytes) {
      features.push("exec.max_output_bytes");
    }
    if (request.argv?.length) {
      features.push("exec.argv");
    }
    await this.requireToolboxFeatures(id, ...features);
    // Not idempotent: a re-sent exec runs the caller's command a second time.
    const response = await this.doJSON<ApiExecResult>(
      "POST",
      `${this.versionPrefix}/sandboxes/${id}/toolbox/process/execute`,
      toApiExecRequest(request),
      { idempotent: false },
    );
    return fromApiExecResult(response);
  }

  execStream(id: string, options: ExecStreamOptions): ExecStreamHandle {
    if (options.command?.trim() && options.argv?.length) {
      throw new Error("set command or argv, not both");
    }
    // argv waits for the feature check: the start message goes out only once
    // the agent has listed exec.argv, so an older one never receives it.
    const ready = options.argv?.length ? this.requireToolboxFeatures(id, "exec.argv") : undefined;
    return openExecStream(this.baseURLFor(id), this.versionPrefix, this.patToken, id, options, ready);
  }

  /**
   * Watch a folder in the sandbox for changes. Resolves once the watch is in
   * place, so a change made after it resolves is reported. gVisor and
   * Firecracker sandboxes only: the others answer 501. Not retried: a stream
   * is opened once.
   */
  async watchFiles(id: string, path: string, onEvent: (event: FileEvent) => void, options: WatchFilesOptions = {}): Promise<FileWatchHandle> {
    const query = `path=${encodeURIComponent(path)}${options.recursive ? "&recursive=true" : ""}`;
    const routePath = `${this.versioned(`/sandboxes/${encodeURIComponent(id)}/toolbox/files/watch`)}?${query}`;
    return openFileWatch(this.baseURLFor(id), routePath, this.patToken, onEvent, (detail) => this.fileWatchRefusal(id, routePath, detail));
  }

  /**
   * Explains a watch whose WebSocket handshake failed. The WebSocket API
   * hides a refused handshake's status and body, so the same request is sent
   * again as plain HTTP: toolboxd checks the runtime, the path and its limits
   * before the upgrade, so it answers with the real reason (501 on Docker or
   * containerd, 404 for a missing folder, 429 at the watch limit). That GET
   * is a diagnosis, sent once, never a retry of the stream.
   */
  private async fileWatchRefusal(id: string, routePath: string, detail: string): Promise<Error> {
    const fallback = new Error(`file watch failed to start${detail}`);
    let response: Response;
    let text: string;
    try {
      response = await this.fetchFn(`${this.baseURLFor(id)}${routePath}`, {
        method: "GET",
        headers: this.authHeaders(),
        ...(this.signal ? { signal: this.signal } : {}),
      });
      text = await response.text();
    } catch {
      return fallback;
    }
    let message: unknown;
    try {
      message = (JSON.parse(text) as { error?: unknown }).error;
    } catch {
      // Not JSON: a proxy's error page, or the upgrade's own refusal.
    }
    // An agent that predates file watching has no such route.
    if (response.status === 404 && (response.headers.get(TOOLBOX_ROUTE_HEADER) === "none" || message === "not found")) {
      return new MicroVMUnsupportedFeatureError(id, [FILE_WATCH_FEATURE]);
    }
    // toolboxd accepted the watch and only refused the plain-HTTP upgrade:
    // the stream failed for some other reason, which `detail` holds.
    if (response.ok || response.headers.has("sec-websocket-version")) {
      return fallback;
    }
    return decodeError(new Response(text, { status: response.status, headers: response.headers }));
  }

  async createSession(id: string, options: CreateSessionOptions): Promise<Session> {
    const response = await this.doJSON<ApiSession>("POST", `${this.versionPrefix}/sandboxes/${id}/sessions`, toApiCreateSessionOptions(options));
    return fromApiSession(response);
  }

  async listSessions(id: string): Promise<Session[]> {
    const response = await this.doJSON<ApiSessionList>("GET", `${this.versionPrefix}/sandboxes/${id}/sessions`);
    return response.sessions.map(fromApiSession);
  }

  async getSession(id: string, sessionID: string): Promise<Session> {
    const response = await this.doJSON<ApiSession>("GET", `${this.versionPrefix}/sandboxes/${id}/sessions/${sessionID}`);
    return fromApiSession(response);
  }

  async deleteSession(id: string, sessionID: string): Promise<void> {
    await this.doJSON<void>("DELETE", `${this.versionPrefix}/sandboxes/${id}/sessions/${sessionID}`);
  }

  async signalSession(id: string, sessionID: string, signal: string): Promise<void> {
    await this.doJSON<void>("POST", `${this.versionPrefix}/sandboxes/${id}/sessions/${sessionID}/signal`, { signal });
  }

  async resizeSession(id: string, sessionID: string, cols: number, rows: number): Promise<void> {
    await this.doJSON<void>("POST", `${this.versionPrefix}/sandboxes/${id}/sessions/${sessionID}/resize`, { cols, rows });
  }

  async sessionLog(id: string, sessionID: string): Promise<Uint8Array> {
    return this.doBytes(`${this.versionPrefix}/sandboxes/${id}/sessions/${sessionID}/log`);
  }

  async sessionRecording(id: string, sessionID: string): Promise<Uint8Array> {
    return this.doBytes(`${this.versionPrefix}/sandboxes/${id}/sessions/${sessionID}/recording`);
  }

  attachSession(id: string, sessionID: string, options: SessionAttachOptions = {}): SessionAttachHandle {
    return openSessionAttach(this.baseURLFor(id), this.versionPrefix, this.patToken, id, sessionID, options);
  }

  /**
   * Plain and atomic uploads retry on 421/429/502/503/504; `append` and
   * `createOnly` only on 429/503, because a second send would append twice
   * or find the first one's file.
   */
  async uploadFile(id: string, targetPath: string, data: BinaryLike, options: UploadFileOptions = {}): Promise<void> {
    const path = await this.uploadPath(id, options);
    const form = new FormData();
    form.set("path", targetPath);
    form.set("file", toBlob(data), basename(targetPath));

    const response = await this.request("POST", path, { body: form }, { idempotent: !(options.append || options.createOnly) });
    if (!response.ok) {
      throw await decodeError(response);
    }
  }

  /** The upload route with the write options as query, after the /version check they need. */
  private async uploadPath(id: string, options: UploadFileOptions): Promise<string> {
    const query = new URLSearchParams();
    if (options.append) query.set("append", "true");
    if (options.createOnly) query.set("create_only", "true");
    if (options.atomic) query.set("atomic", "true");
    if (options.mode !== undefined) query.set("mode", options.mode.toString(8));
    if (query.size > 0) {
      // An older agent ignores these; createOnly would replace a file.
      await this.requireToolboxFeatures(id, FEATURE_WRITE_OPTIONS);
    }
    return `${this.versionPrefix}/sandboxes/${id}/toolbox/files/upload${query.size > 0 ? `?${query.toString()}` : ""}`;
  }

  /**
   * Upload from a stream a piece at a time, so a large file never sits in
   * memory. The options are {@link uploadFile}'s. The data is read as it is
   * sent, so the request is sent once and never retried. Needs a `fetch` that
   * can send a streamed body (Node.js 18 and later).
   */
  async uploadFileStream(
    id: string,
    targetPath: string,
    data: ReadableStream<Uint8Array> | AsyncIterable<Uint8Array>,
    options: UploadFileOptions = {},
  ): Promise<void> {
    const path = await this.uploadPath(id, options);
    const boundary = `----aerolvm-${newIdempotencyKey()}`;
    const encoder = new TextEncoder();
    const head = encoder.encode(
      `--${boundary}\r\nContent-Disposition: form-data; name="path"\r\n\r\n${targetPath}\r\n` +
        `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${basename(targetPath)}"\r\n` +
        "Content-Type: application/octet-stream\r\n\r\n",
    );
    const tail = encoder.encode(`\r\n--${boundary}--\r\n`);
    const parts = (async function* () {
      yield head;
      if (data instanceof ReadableStream) {
        const reader = data.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          yield value;
        }
      } else {
        yield* data;
      }
      yield tail;
    })();
    const body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        const next = await parts.next();
        if (next.done) controller.close();
        else controller.enqueue(next.value);
      },
    });
    const init = {
      body,
      // Node's fetch sends a streamed body only with duplex "half".
      duplex: "half",
      headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` },
    } as RequestInit;
    const response = await this.request("POST", path, init, { idempotent: false, sendOnce: true });
    if (!response.ok) {
      throw await decodeError(response);
    }
  }

  /**
   * Copy the local folder `localDir` into `remoteDir` in the sandbox (made if
   * missing). The folder is packed as a gzipped tar and the sandbox unpacks it
   * safely: no entry can land outside `remoteDir`. Symlinks are sent as links,
   * hard-linked files as separate files; devices, pipes and sockets are
   * skipped. The archive is built in memory and sent once, never retried.
   * Node.js only.
   */
  async uploadDir(id: string, localDir: string, remoteDir: string): Promise<void> {
    if (!(await stat(localDir)).isDirectory()) {
      throw new Error(`${localDir} is not a folder`);
    }
    await this.requireToolboxFeatures(id, FEATURE_EXTRACT);
    const archive = gzipSync(tarArchive(await folderEntries(localDir, "")));
    const form = new FormData();
    form.set("path", remoteDir);
    form.set("file", new Blob([archive]), "upload.tar.gz");
    const response = await this.request(
      "POST",
      `${this.versionPrefix}/sandboxes/${id}/toolbox/files/upload?extract=true`,
      { body: form },
      { idempotent: false, sendOnce: true },
    );
    if (!response.ok) {
      throw await decodeError(response);
    }
  }

  async downloadFile(id: string, targetPath: string, options: DownloadFileOptions = {}): Promise<Uint8Array> {
    const stream = await this.downloadFileStream(id, targetPath, options);
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  /**
   * Open a file for reading a piece at a time, so a large file never sits in
   * memory. With `maxBytes`, a larger file is refused before reading when the
   * server states the size, and otherwise the stream errors as soon as more
   * arrives. The request retries until the file starts to arrive.
   */
  async downloadFileStream(id: string, targetPath: string, options: DownloadFileOptions = {}): Promise<ReadableStream<Uint8Array>> {
    const response = await this.request("GET", `${this.versionPrefix}/sandboxes/${id}/toolbox/files/download?path=${encodeURIComponent(targetPath)}`);
    if (!response.ok) {
      throw await decodeError(response);
    }
    const body = response.body ?? new Response(new Uint8Array()).body!;
    const max = options.maxBytes;
    if (max === undefined) {
      return body;
    }
    const length = response.headers.get("content-length");
    if (length !== null && Number(length) > max) {
      await body.cancel().catch(() => undefined);
      throw new MicroVMFileTooLargeError(targetPath, max);
    }
    let seen = 0;
    return body.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          if (seen + chunk.length > max) {
            controller.enqueue(chunk.subarray(0, max - seen));
            controller.error(new MicroVMFileTooLargeError(targetPath, max));
            return;
          }
          seen += chunk.length;
          controller.enqueue(chunk);
        },
      }),
    );
  }

  // File verbs beyond upload and download (plans/agent-sandbox-feature-
  // parity.md, F1), through the sandbox's toolbox. A sandbox whose agent
  // predates them fails closed with MicroVMUnsupportedFeatureError instead of
  // ignoring a safety option; WASM and V8 isolate sandboxes answer 501.
  //
  // Retries: listFiles, getFileInfo, fileExists, searchFiles, findInFiles,
  // deleteFile and makeDir are safe to re-send and retry on 421, 429, 502,
  // 503 and 504 (a retried delete or mkdir whose work is already done counts
  // as success). moveFile and copyFile retry only on 429 and 503, because a
  // lost reply may hide a move that happened.

  private toolboxPath(id: string, route: string, query: Record<string, string>): string {
    return `${this.versionPrefix}/sandboxes/${encodeURIComponent(id)}/toolbox${route}?${new URLSearchParams(query).toString()}`;
  }

  /** Sends a body-less file call and discards a success reply. */
  private async fileCall(method: string, path: string, options: RequestOptions): Promise<void> {
    const response = await this.request(method, path, {}, options);
    if (!response.ok) {
      throw await decodeError(response);
    }
    await response.body?.cancel().catch(() => undefined);
  }

  async listFiles(id: string, path: string, options: ListFilesOptions = {}): Promise<FileList> {
    const depth = options.depth ?? 1;
    const limit = options.limit ?? DEFAULT_LIST_LIMIT;
    if (depth < 1 || limit < 1) {
      throw new Error("depth and limit must be at least 1");
    }
    await this.requireToolboxFeatures(id, FEATURE_FILE_VERBS);
    const response = await this.request(
      "GET",
      this.toolboxPath(id, "/files", { path, depth: String(depth), limit: String(limit), extended: "true" }),
    );
    if (!response.ok) {
      throw await decodeError(response);
    }
    const items = ((await response.json()) ?? []) as ApiFileInfo[];
    const base = path.replace(/\/+$/, "");
    return {
      entries: items.map((item) => fromApiFileInfo(item, `${base}/${item.name ?? ""}`)),
      truncated: response.headers.get("x-toolbox-truncated") === "true",
    };
  }

  async getFileInfo(id: string, path: string): Promise<FileInfo> {
    // extended=true only adds fields; an older agent that ignores it answers
    // fields this still reads, so no /version check.
    const item = await this.doJSON<ApiFileInfo>("GET", this.toolboxPath(id, "/files/info", { path, extended: "true" }));
    return fromApiFileInfo(item ?? {}, path);
  }

  async fileExists(id: string, path: string): Promise<boolean> {
    try {
      await this.getFileInfo(id, path);
      return true;
    } catch (err) {
      if (isMissingFile(err)) {
        return false;
      }
      throw err;
    }
  }

  async deleteFile(id: string, path: string, options: DeleteFileOptions = {}): Promise<void> {
    const query: Record<string, string> = { path };
    if (options.recursive) {
      query.recursive = "true";
    }
    await this.fileCall("DELETE", this.toolboxPath(id, "/files", query), { doneCode: "file_not_found" });
  }

  async makeDir(id: string, path: string, options: MakeDirOptions = {}): Promise<void> {
    const parents = options.parents ?? false;
    if (!parents) {
      // An older agent ignores parents=false and makes them anyway.
      await this.requireToolboxFeatures(id, FEATURE_FILE_VERBS);
    }
    const query: Record<string, string> = { path, parents: String(parents) };
    if (options.mode !== undefined) {
      query.mode = options.mode.toString(8);
    }
    await this.fileCall("POST", this.toolboxPath(id, "/files/folder", query), { doneCode: "folder_exists" });
  }

  async moveFile(id: string, source: string, destination: string, options: MoveFileOptions = {}): Promise<void> {
    const overwrite = options.overwrite ?? false;
    if (!overwrite) {
      // An older agent ignores overwrite=false and replaces the destination.
      await this.requireToolboxFeatures(id, FEATURE_FILE_VERBS);
    }
    await this.fileCall(
      "POST",
      this.toolboxPath(id, "/files/move", { source, destination, overwrite: String(overwrite) }),
      { idempotent: false },
    );
  }

  async copyFile(id: string, source: string, destination: string, options: CopyFileOptions = {}): Promise<void> {
    await this.requireToolboxFeatures(id, FEATURE_FILE_VERBS);
    const query = {
      source,
      destination,
      overwrite: String(options.overwrite ?? false),
      recursive: String(options.recursive ?? false),
    };
    await this.fileCall("POST", this.toolboxPath(id, "/files/copy", query), { idempotent: false });
  }

  async searchFiles(id: string, path: string, pattern: string): Promise<string[]> {
    const response = await this.doJSON<{ files?: unknown }>("GET", this.toolboxPath(id, "/files/search", { path, pattern }));
    return Array.isArray(response?.files) ? response.files.map(String) : [];
  }

  async findInFiles(id: string, path: string, text: string): Promise<FileMatch[]> {
    const response = await this.doJSON<unknown>("GET", this.toolboxPath(id, "/files/find", { path, pattern: text }));
    if (!Array.isArray(response)) {
      return [];
    }
    return response.map((m: { file?: unknown; line?: unknown; content?: unknown }) => ({
      file: String(m.file ?? ""),
      line: Number(m.line ?? 0),
      content: String(m.content ?? ""),
    }));
  }

  /**
   * Publish a sandbox container port. The chosen wire protocol is selected by
   * `options.protocol` (defaults to `"http"`):
   *
   *   - `"http"`: Caddy HTTP reverse proxy at `https://<id>-<port>.<domain>`.
   *   - `"tcp"`:  raw caddy-l4 listener on a parent-host port — pair with
   *               native protocol clients (psql, redis-cli, mysql, mongosh).
   *   - `"tls"`:  caddy-l4 TLS-SNI route on the shared listener. Requires the
   *               daemon to have a domain configured AND `SB_L4_TLS_LISTEN` set.
   *
   * Returns a discriminated result keyed on `protocol`. Only the `"tcp"`
   * variant carries `host` / `hostPort` — everything else is in `url`.
   */
  async exposePort(id: string, port: number, options: ExposePortOptions = {}): Promise<ExposeResult> {
    // Only what the caller set: an omitted visibility keeps an exposed
    // port's gate, so a plain retry never opens a token port.
    const fields: { protocol?: ExposeProtocol; visibility?: string } = {};
    if (options.protocol) {
      fields.protocol = options.protocol;
    }
    if (options.visibility) {
      fields.visibility = options.visibility;
    }
    const body = Object.keys(fields).length > 0 ? fields : undefined;
    const response = await this.doJSON<ApiExposePortResponse>(
      "POST",
      `${this.versionPrefix}/sandboxes/${id}/ports/${port}`,
      body,
    );
    return fromApiExposePortResponse(response);
  }

  async unexposePort(id: string, port: number): Promise<void> {
    await this.doJSON<void>("DELETE", `${this.versionPrefix}/sandboxes/${id}/ports/${port}`);
  }

  /**
   * Issue a signed token scoped to one sandbox (POST /v1/sandboxes/{id}/tokens).
   * Not idempotent by nature: every call makes a new token, and the server
   * stores none. It uses the normal retry tier: a retry after a lost answer
   * makes a second token that nobody holds, which simply expires.
   */
  async createSandboxToken(id: string, options: CreateSandboxTokenOptions): Promise<SandboxToken> {
    const body: Record<string, unknown> = { expires_in: options.expiresIn };
    if (options.port !== undefined && options.port !== 0) {
      body.port = options.port;
    }
    if (options.pathPrefix) {
      body.path_prefix = options.pathPrefix;
    }
    if (options.methods && options.methods.length > 0) {
      body.methods = options.methods;
    }
    const r = await this.doJSON<ApiSandboxToken>("POST", `${this.versionPrefix}/sandboxes/${id}/tokens`, body);
    return {
      token: r.token,
      tokenID: r.token_id,
      sandboxID: r.sandbox_id,
      ...(r.port ? { port: r.port } : {}),
      ...(r.path_prefix ? { pathPrefix: r.path_prefix } : {}),
      ...(r.methods && r.methods.length > 0 ? { methods: r.methods } : {}),
      expiresAt: r.expires_at,
    };
  }

  /**
   * Make every token issued for one sandbox so far stop working
   * (POST /v1/sandboxes/{id}/tokens/revoke). A token issued after it works.
   * Safe to retry: a repeated call refuses the same tokens again (plus any
   * issued in between), so it uses the normal retry tier.
   */
  async revokeSandboxTokens(id: string): Promise<RevokeSandboxTokensResult> {
    const r = await this.doJSON<ApiRevokeSandboxTokens>("POST", `${this.versionPrefix}/sandboxes/${id}/tokens/revoke`);
    return { sandboxID: r.sandbox_id, tokensNotBefore: r.tokens_not_before };
  }

  /**
   * Bind a custom hostname to a sandbox. The server lowercases the hostname
   * and returns the post-add list of bindings (sorted by hostname). Calling
   * with an already-registered hostname is idempotent and returns the
   * existing list.
   */
  async addCustomDomain(
    id: string,
    hostname: string,
    options?: AddCustomDomainOptions,
  ): Promise<CustomDomain[]> {
    const body: { hostname: string; target_port?: number } = { hostname };
    if (options?.port !== undefined && options.port !== 0) {
      body.target_port = options.port;
    }
    const response = await this.doJSON<ApiCustomDomainList>(
      "POST",
      v1SandboxCustomDomainsPath(this.versionPrefix, id),
      body,
    );
    return response.custom_domains.map(fromApiCustomDomain);
  }

  async listCustomDomains(id: string): Promise<CustomDomain[]> {
    const response = await this.doJSON<ApiCustomDomainList>(
      "GET",
      v1SandboxCustomDomainsPath(this.versionPrefix, id),
    );
    return response.custom_domains.map(fromApiCustomDomain);
  }

  async removeCustomDomain(id: string, hostname: string): Promise<void> {
    await this.doJSON<void>(
      "DELETE",
      v1SandboxCustomDomainPath(this.versionPrefix, id, hostname),
    );
  }

  /**
   * Fetch the cluster's published ingress address(es) — the CNAME/A target
   * a user must point custom-domain DNS at. Field names already match the
   * SDK's camelCase shape on the wire, so no translation is needed.
   */
  async ingressDNS(): Promise<IngressTarget> {
    return this.doJSON<IngressTarget>("GET", v1IngressDNSPath(this.versionPrefix));
  }

  /**
   * Fetch the ready-to-paste DNS records for one sandbox's custom-domain
   * bindings, along with the {@link IngressTarget} they were composed from.
   */
  async customDomainDNS(id: string): Promise<CustomDomainDNSRecords> {
    return this.doJSON<CustomDomainDNSRecords>(
      "GET",
      v1SandboxCustomDomainDNSPath(this.versionPrefix, id),
    );
  }

  async reconcile(): Promise<void> {
    await this.doJSON<unknown>("POST", this.versioned("/admin/reconcile"));
  }

  async health(): Promise<HealthStatus> {
    const response = await this.doJSON<ApiHealthStatus>("GET", "/health");
    return fromApiHealthStatus(response);
  }

  async checkNetworkPolicy(options: NetworkPolicyCheckOptions): Promise<NetworkPolicyCheckResult> {
    const response = await this.doJSON<{
      allowed: boolean;
      matched_rule: string;
      default_verdict: string;
      outside_ceiling?: string;
    }>("POST", this.versioned("/network/policy/check"), {
      network_block_all: options.networkBlockAll,
      network_allow_out: options.networkAllowOut,
      network_deny_out: options.networkDenyOut,
      destination: options.destination,
    });
    const result: NetworkPolicyCheckResult = {
      allowed: response.allowed,
      matchedRule: response.matched_rule ?? "",
      defaultVerdict: response.default_verdict,
    };
    if (response.outside_ceiling) result.outsideCeiling = response.outside_ceiling;
    return result;
  }

  async mounts(id: string): Promise<MountSpecRedacted[]> {
    const response = await this.doJSON<ApiMountList>("GET", `${this.versionPrefix}/sandboxes/${id}/mounts`);
    return response.mounts.map(fromApiMountSpecRedacted);
  }

  async cloneGeneration(id: string): Promise<CloneGeneration> {
    const response = await this.doJSON<ApiCloneGeneration>(
      "GET",
      `${this.versionPrefix}/sandboxes/${id}/toolbox/clone-generation`,
    );
    return fromApiCloneGeneration(response);
  }

  async getNetworkUsage(id: string): Promise<NetworkUsage> {
    const response = await this.doJSON<ApiNetworkUsage>("GET", `${this.versionPrefix}/sandboxes/${id}/network/usage`);
    return fromApiNetworkUsage(response);
  }

  async getAudit(id: string, options: AuditOptions = {}): Promise<AuditPage> {
    const params = new URLSearchParams();
    if (options.kind) params.set("kind", options.kind);
    if (options.limit !== undefined) params.set("limit", String(options.limit));
    if (options.cursor) params.set("cursor", options.cursor);
    if (options.incarnationID) params.set("incarnation_id", options.incarnationID);
    if (options.caller) params.set("caller", options.caller);
    const query = params.toString();
    const response = await this.doJSON<ApiAuditPage>(
      "GET",
      `${this.versionPrefix}/sandboxes/${id}/audit${query ? `?${query}` : ""}`,
    );
    return fromApiAuditPage(response);
  }

  async setNetworkLimits(id: string, options: SetNetworkLimitsOptions): Promise<NetworkUsage> {
    const response = await this.doJSON<ApiNetworkUsage>(
      "PATCH",
      `${this.versionPrefix}/sandboxes/${id}/network/limits`,
      toApiSetNetworkLimitsOptions(options),
    );
    return fromApiNetworkUsage(response);
  }

  async setNetworkPolicy(id: string, options: NetworkPolicyOptions): Promise<NetworkPolicy> {
    const response = await this.doJSON<{
      network_block_all: boolean;
      network_allow_out: string[] | null;
      network_deny_out: string[] | null;
      egress_profiles?: string[] | null;
      network_egress_mode?: string;
      network_egress_rules?: ApiEgressRule[] | null;
      effective_hostname_count?: number;
      egress_status?: string;
    }>("PUT", `${this.versionPrefix}/sandboxes/${id}/network/policy`, {
      network_block_all: options.networkBlockAll ?? false,
      network_allow_out: options.networkAllowOut ?? [],
      network_deny_out: options.networkDenyOut ?? [],
      egress_profiles: options.egressProfiles ?? [],
      network_egress_mode: options.networkEgressMode,
      network_egress_rules: options.networkEgressRules?.map(toApiEgressRule),
    });
    const policy: NetworkPolicy = {
      networkBlockAll: response.network_block_all,
      networkAllowOut: response.network_allow_out ?? [],
      networkDenyOut: response.network_deny_out ?? [],
      egressProfiles: response.egress_profiles ?? [],
      networkEgressMode: response.network_egress_mode ?? "enforce",
      networkEgressRules: (response.network_egress_rules ?? []).map(fromApiEgressRule),
      effectiveHostnameCount: response.effective_hostname_count ?? 0,
    };
    if (response.egress_status) policy.egressStatus = response.egress_status;
    return policy;
  }

  async getNetworkLearned(id: string): Promise<NetworkLearned> {
    const r = await this.doJSON<{
      mode: string;
      truncated: boolean;
      entries: { host: string; ports: number[] | null; first_seen: string; last_seen: string; hits: number }[] | null;
      cidrs: string[] | null;
      suggested_allow_out: string[] | null;
      suggested_profile?: { allow_out: string[] | null; description?: string } | null;
    }>("GET", `${this.versionPrefix}/sandboxes/${id}/network/learned`);
    const learned: NetworkLearned = {
      mode: r.mode,
      truncated: r.truncated,
      entries: (r.entries ?? []).map((e) => ({ host: e.host, ports: e.ports ?? [], firstSeen: e.first_seen, lastSeen: e.last_seen, hits: e.hits })),
      cidrs: r.cidrs ?? [],
      suggestedAllowOut: r.suggested_allow_out ?? [],
    };
    if (r.suggested_profile) {
      learned.suggestedProfile = { allowOut: r.suggested_profile.allow_out ?? [], description: r.suggested_profile.description };
    }
    return learned;
  }

  async putEgressProfile(name: string, options: EgressProfileOptions): Promise<EgressProfile> {
    const response = await this.doJSON<ApiEgressProfile>("PUT", this.versioned(`/egress-profiles/${encodeURIComponent(name)}`), {
      allow_out: options.allowOut,
      description: options.description,
    });
    return fromApiEgressProfile(response);
  }

  async getEgressProfile(name: string): Promise<EgressProfile> {
    return fromApiEgressProfile(await this.doJSON<ApiEgressProfile>("GET", this.versioned(`/egress-profiles/${encodeURIComponent(name)}`)));
  }

  async listEgressProfiles(options: ListEgressProfilesOptions = {}): Promise<EgressProfileList> {
    const params = new URLSearchParams();
    if (options.cursor) params.set("cursor", options.cursor);
    if (options.limit) params.set("limit", String(options.limit));
    const query = params.toString();
    const response = await this.doJSON<{ profiles: ApiEgressProfile[] | null; next_cursor?: string }>(
      "GET",
      this.versioned(`/egress-profiles${query ? `?${query}` : ""}`),
    );
    const list: EgressProfileList = { profiles: (response.profiles ?? []).map(fromApiEgressProfile) };
    if (response.next_cursor) list.nextCursor = response.next_cursor;
    return list;
  }

  async deleteEgressProfile(name: string): Promise<void> {
    await this.doJSON<void>("DELETE", this.versioned(`/egress-profiles/${encodeURIComponent(name)}`));
  }

  // Warm pools are PUT/GET/DELETE of one entry: every call is safe to retry,
  // so they keep the default (idempotent) retry tier.
  async putWarmPool(image: string, options: WarmPoolOptions): Promise<WarmPool> {
    return fromApiWarmPool(
      await this.doJSON<ApiWarmPool>("PUT", this.versioned(warmPoolPath(image)), {
        depth: options.depth ?? 0,
        min_depth: options.minDepth,
        max_depth: options.maxDepth,
        on_image_change: options.onImageChange,
      }),
    );
  }

  async getWarmPool(image: string): Promise<WarmPool> {
    return fromApiWarmPool(await this.doJSON<ApiWarmPool>("GET", this.versioned(warmPoolPath(image))));
  }

  async listWarmPools(): Promise<WarmPool[]> {
    const response = await this.doJSON<{ pools: ApiWarmPool[] | null }>("GET", this.versioned("/warm-pools"));
    return (response.pools ?? []).map(fromApiWarmPool);
  }

  async deleteWarmPool(image: string): Promise<void> {
    await this.doJSON<void>("DELETE", this.versioned(warmPoolPath(image)));
  }

  async putIdentityRole(tag: string, options: IdentityRoleOptions): Promise<IdentityRole> {
    const response = await this.doJSON<ApiIdentityRole>("PUT", this.identityRolePath(tag, options.team), {
      min_role: options.minRole,
    });
    return fromApiIdentityRole(response);
  }

  async listIdentityRoles(options: ListIdentityRolesOptions = {}): Promise<IdentityRoleList> {
    const params = new URLSearchParams();
    if (options.team) params.set("team", options.team);
    if (options.cursor) params.set("cursor", options.cursor);
    if (options.limit) params.set("limit", String(options.limit));
    const query = params.toString();
    const response = await this.doJSON<{ roles: ApiIdentityRole[] | null; next_cursor?: string }>(
      "GET",
      this.versioned(`/identity/roles${query ? `?${query}` : ""}`),
    );
    const list: IdentityRoleList = { roles: (response.roles ?? []).map(fromApiIdentityRole) };
    if (response.next_cursor) list.nextCursor = response.next_cursor;
    return list;
  }

  async deleteIdentityRole(tag: string, options: { team?: string } = {}): Promise<void> {
    await this.doJSON<void>("DELETE", this.identityRolePath(tag, options.team));
  }

  private identityRolePath(tag: string, team?: string): string {
    const path = `/identity/roles/${encodeURIComponent(tag)}`;
    return this.versioned(team ? `${path}?team=${encodeURIComponent(team)}` : path);
  }

  async putTeamQuota(team: string, options: TeamQuotaOptions): Promise<TeamQuota> {
    const response = await this.doJSON<ApiTeamQuota>("PUT", this.versioned(`/teams/${encodeURIComponent(team)}/quota`), {
      max_sandboxes: options.maxSandboxes,
      max_cpu: options.maxCPU,
      max_memory_mb: options.maxMemoryMB,
    });
    return fromApiTeamQuota(response);
  }

  async getTeamQuota(team: string): Promise<TeamQuota> {
    return fromApiTeamQuota(await this.doJSON<ApiTeamQuota>("GET", this.versioned(`/teams/${encodeURIComponent(team)}/quota`)));
  }

  async deleteTeamQuota(team: string): Promise<void> {
    await this.doJSON<void>("DELETE", this.versioned(`/teams/${encodeURIComponent(team)}/quota`));
  }

  async createTemplate(options: CreateTemplateOptions): Promise<Template> {
    const response = await this.doJSON<ApiTemplate>("POST", this.versioned("/templates"), {
      id: options.id,
      image: options.image,
      min_size_mib: options.minSizeMiB,
    });
    return fromApiTemplate(response);
  }

  async listTemplates(): Promise<Template[]> {
    const response = await this.doJSON<ApiTemplate[]>("GET", this.versioned("/templates"));
    // The daemon returns `null` rather than `[]` when the table is empty;
    // normalize so callers always get an array.
    return (response ?? []).map(fromApiTemplate);
  }

  async getTemplate(id: string): Promise<Template> {
    const response = await this.doJSON<ApiTemplate>("GET", `${this.versionPrefix}/templates/${id}`);
    return fromApiTemplate(response);
  }

  async deleteTemplate(id: string): Promise<void> {
    await this.doJSON<void>("DELETE", `${this.versionPrefix}/templates/${id}`);
  }

  async createWasmModule(options: CreateWasmModuleOptions): Promise<WasmModule> {
    const response = await this.doJSON<ApiWasmModule>("POST", this.versioned("/wasm-modules"), {
      id: options.id,
      module_ref: options.moduleRef,
      entrypoint: options.entrypoint,
    });
    return fromApiWasmModule(response);
  }

  async listWasmModules(): Promise<WasmModule[]> {
    const response = await this.doJSON<ApiWasmModule[]>("GET", this.versioned("/wasm-modules"));
    return (response ?? []).map(fromApiWasmModule);
  }

  async getWasmModule(id: string): Promise<WasmModule> {
    const response = await this.doJSON<ApiWasmModule>("GET", `${this.versionPrefix}/wasm-modules/${id}`);
    return fromApiWasmModule(response);
  }

  async deleteWasmModule(id: string): Promise<void> {
    await this.doJSON<void>("DELETE", `${this.versionPrefix}/wasm-modules/${id}`);
  }

  async pushWasmModule(options: PushWasmModuleOptions): Promise<PushWasmModuleResult> {
    const params = new URLSearchParams({ name: options.name });
    if (options.tag) {
      params.set("tag", options.tag);
    }
    const headers: Record<string, string> = {
      "Content-Type": "application/octet-stream",
      "X-Registry-Token": options.registryToken,
    };
    if (options.registryUsername) {
      headers["X-Registry-Username"] = options.registryUsername;
    }
    const response = await this.request(
      "POST",
      this.versioned(`/wasm-modules/push?${params.toString()}`),
      { body: options.module as unknown as BodyInit, headers },
    );
    if (!response.ok) {
      throw await decodeError(response);
    }
    const r = (await response.json()) as { module_ref: string; digest: string; size_bytes: number };
    return { moduleRef: r.module_ref, digest: r.digest, sizeBytes: r.size_bytes };
  }

  async rebuildTemplate(id: string): Promise<Template> {
    const response = await this.doJSON<ApiTemplate>("POST", `${this.versionPrefix}/templates/${id}/rebuild`);
    return fromApiTemplate(response);
  }

  async whoami(): Promise<WhoAmI> {
    return fromApiWhoAmI(await this.doJSON<ApiWhoAmI>("GET", this.versioned("/whoami")));
  }

  async createAPIToken(options: CreateAPITokenOptions): Promise<CreatedAPIToken> {
    const response = await this.doJSON<ApiAPIToken & { token: string }>("POST", this.versioned("/tokens"), {
      name: options.name,
      role: options.role,
      team: options.team,
      expires_in: options.expiresIn,
    });
    return { ...fromApiAPIToken(response), token: response.token };
  }

  async listAPITokens(): Promise<APITokenList> {
    const response = await this.doJSON<{ tokens: ApiAPIToken[] | null }>("GET", this.versioned("/tokens"));
    return { tokens: (response.tokens ?? []).map(fromApiAPIToken) };
  }

  async revokeAPIToken(id: string): Promise<void> {
    const trimmed = id.trim();
    if (trimmed === "") {
      throw new Error("token id is required");
    }
    await this.doJSON<void>("DELETE", this.versioned(`/tokens/${encodeURIComponent(trimmed)}`));
  }

  private wrap(sandbox: ApiSandbox): SandboxResource {
    return new SandboxResource(this.root ?? this, fromApiSandbox(sandbox));
  }

  private async doJSON<T>(method: string, path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    const init: RequestInit = { headers: { ...options?.headers } };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
      init.headers = { ...init.headers, "Content-Type": "application/json" };
    }

    const response = await this.request(method, path, init, options);
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

  private authHeaders(base?: HeadersInit): Headers {
    const headers = new Headers(base);
    if (this.patToken !== "") {
      headers.set("Authorization", `Bearer ${this.patToken}`);
    }
    if (this.team !== "") {
      headers.set(TEAM_HEADER, this.team);
    }
    return headers;
  }

  /**
   * Low-level HTTP request with automatic retry for transient failures.
   *
   * Transport-level errors (socket closed, connection reset, timeouts, DNS
   * blip) and HTTP 421/429/502/503/504 are retried regardless of HTTP method.
   * Several of those failures can happen after the server received the
   * request, so a retry may deliver it twice; that is safe only because every
   * mutating endpoint in the daemon is designed for idempotent retry (e.g.
   * INSERT OR IGNORE + disambiguation).
   *
   * A request passed `{ idempotent: false }` (exec) retries only transport
   * failures that prove the request never left the client and HTTP 429/503;
   * everything else is surfaced to the caller rather than risk running the
   * command twice.
   *
   * A 429 or 503 waits as long as its `Retry-After` asks (see
   * {@link retryDelayMs}). The client's `signal` ends the request and any
   * wait.
   *
   * A 421 that names another cell ({@link CELL_ENDPOINT_HEADER}) is not
   * retried in place: the same request goes once to that cell instead, and
   * later requests for that sandbox go straight there.
   */
  private async request(method: string, path: string, init: RequestInit = {}, options: RequestOptions = {}): Promise<Response> {
    const headers = this.authHeaders(init.headers);
    const signal = init.signal ?? this.signal;
    const requestInit: RequestInit = { ...init, method, headers, ...(signal ? { signal } : {}) };
    const sandboxID = sandboxIDInPath(path, this.versioned("/sandboxes/"));

    let base = this.baseURLFor(sandboxID);
    let response = await this.send(`${base}${path}`, requestInit, options);
    const cell = this.cellEndpoint(response);
    if (cell !== undefined) {
      // Remembered even when the body cannot go again, so the caller's own
      // retry goes to the right cell.
      if (sandboxID !== undefined) this.rememberCell(sandboxID, cell);
      // The cell router answers before any work is done, so even an exec or
      // a folder upload may go again; only a body that fetch has already
      // read cannot.
      if (!isReplayableBody(init.body)) return response;
      response.body?.cancel().catch(() => undefined);
      base = cell;
      // send hands back a second 421 naming a cell as it is, and nothing
      // follows it: two cells that disagree cannot bounce a request between
      // them.
      response = await this.send(`${base}${path}`, requestInit, options);
    }
    // A 404 from the remembered cell may mean the sandbox was deleted, so the
    // next call asks the configured server again. A missing file says nothing
    // about the sandbox, and forgetting on it would add a 421 to every poll.
    if (
      response.status === 404 &&
      sandboxID !== undefined &&
      this.sandboxCells.get(sandboxID) === base &&
      !isMissingFile(await decodeError(response.clone()))
    ) {
      this.sandboxCells.delete(sandboxID);
    }
    return response;
  }

  /** Where requests for sandbox `id` go: the cell it was found in, else the configured server. */
  private baseURLFor(id: string | undefined): string {
    return (id !== undefined && this.sandboxCells.get(id)) || this.baseURL;
  }

  private rememberCell(id: string, cell: string): void {
    // Re-inserted so a re-learned entry counts as the newest.
    this.sandboxCells.delete(id);
    this.sandboxCells.set(id, cell);
    if (this.sandboxCells.size > MAX_REMEMBERED_CELLS) {
      const oldest = this.sandboxCells.keys().next().value;
      if (oldest !== undefined) this.sandboxCells.delete(oldest);
    }
  }

  /**
   * The cell base URL a 421 names, or `undefined` when it names none this
   * client may send its token to: not an absolute http(s) URL, or plain http
   * while the client was configured for https, which would let one bad
   * answer move the token to clear text.
   */
  private cellEndpoint(response: Response): string | undefined {
    if (!isCellAnswer(response)) return undefined;
    let url: URL;
    try {
      url = new URL((response.headers.get(CELL_ENDPOINT_HEADER) ?? "").trim());
    } catch {
      return undefined;
    }
    if (url.host === "" || (url.protocol !== "https:" && (url.protocol !== "http:" || /^https:/i.test(this.baseURL)))) {
      return undefined;
    }
    // Built like the configured base URL: the cell's own path prefix stays,
    // so /v1/... lands under it. A query, fragment or userinfo has no place
    // in a base URL and is dropped.
    return url.origin + stripTrailingSlashes(url.pathname);
  }

  /** One request to `url` with the retry loop described on {@link request}. */
  private async send(url: string, requestInit: RequestInit, options: RequestOptions): Promise<Response> {
    const signal = requestInit.signal ?? undefined;
    const maxRetries = options.sendOnce ? 0 : this.retryConfig.maxRetries;
    const idempotent = options.idempotent ?? true;
    const retryableStatusCodes = idempotent ? RETRYABLE_STATUS_CODES : REFUSED_STATUS_CODES;
    const isRetryableError = idempotent ? isTransientTransportError : isUnsentTransportError;

    let mayHaveRun = false;
    for (let attempt = 0; ; attempt++) {
      let retryAfter: string | null = null;
      try {
        const response = await this.fetchFn(url, requestInit);
        if (mayHaveRun && options.doneCode && !response.ok && (await errorCode(response)) === options.doneCode) {
          response.body?.cancel().catch(() => undefined);
          return new Response(null, { status: 204 });
        }
        if (response.status === 502 || response.status === 504) {
          mayHaveRun = true;
        }
        if (!retryableStatusCodes.has(response.status) || attempt >= maxRetries || isCellAnswer(response)) {
          return response;
        }
        if (REFUSED_STATUS_CODES.has(response.status)) {
          retryAfter = response.headers.get("retry-after");
        }
        // Free the connection instead of holding it through the wait.
        response.body?.cancel().catch(() => undefined);
      } catch (error: unknown) {
        // Only retry transport-level failures; anything else propagates. An
        // aborted signal surfaces whatever fetch threw for it.
        if (signal?.aborted || !isRetryableError(error) || attempt >= maxRetries) {
          throw error;
        }
        mayHaveRun ||= !isUnsentTransportError(error);
      }
      await sleep(retryDelayMs(this.retryConfig, attempt, retryAfter, Date.now(), Math.random()), signal);
    }
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
  declare egressStatus?: string;
  declare egressProfiles?: string[];
  declare egressProfilesApplied?: EgressProfileRef[];
  declare networkEgressMode?: string;
  declare networkEgressRules?: EgressRule[];
  declare toolboxEnabled: boolean;
  declare sshPublicKey?: string;
  declare sshPrivateKey?: string;
  declare exposedPorts?: ExposedPort[];
  declare createdAt: string;
  declare updatedAt: string;
  declare lastActiveAt: string;
  declare name?: string;
  declare tags?: Record<string, string>;
  declare lastError?: string;
  declare statusReason?: StatusReason;
  declare exitCode?: number;
  declare containerCommand?: string[];
  declare lifecycle: Lifecycle;
  declare failover?: Failover;
  declare runtime: Sandbox["runtime"];
  declare identity?: SandboxIdentity;

  declare protected readonly client: APIClient;

  /**
   * When true, leaving an `await using` block deletes the sandbox (see
   * `[Symbol.asyncDispose]`). Off by default, so the block ends without
   * touching it; set it here or with `destroyOnExit` on `create` and
   * `getOrCreate`.
   */
  destroyOnExit = false;

  private disposed = false;

  /** The client for one call: the real one, or a view carrying the call's signal. */
  private api(call?: CallOptions): APIClient {
    return this.client.withSignal(call?.signal);
  }

  constructor(client: APIClient, sandbox: Sandbox) {
    // Not enumerable: it holds the token, so it must never reach toJSON,
    // JSON.stringify or a log of the sandbox.
    Object.defineProperty(this, "client", { value: client, enumerable: false });
    this.apply(sandbox);
  }

  /**
   * Called when an `await using` block holding this sandbox ends. Deletes the
   * sandbox only when {@link destroyOnExit} is true; otherwise does nothing.
   * A sandbox that is already gone counts as deleted, and a second call does
   * nothing.
   */
  async [Symbol.asyncDispose](): Promise<void> {
    if (!this.destroyOnExit || this.disposed) return;
    try {
      await this.client.destroy(this.id);
    } catch (err) {
      if (!(err instanceof MicroVMNotFoundError)) throw err;
    }
    this.disposed = true;
  }

  async refresh(call?: CallOptions): Promise<this> {
    const updated = await this.api(call).get(this.id);
    this.apply(updated.toJSON());
    return this;
  }

  async exec(command: string | ExecRequest, call?: CallOptions): Promise<ExecResult> {
    return this.api(call).exec(this.id, typeof command === "string" ? { command } : command);
  }

  /**
   * Read this sandbox's clone-generation token. The token changes whenever the
   * sandbox is resumed from a snapshot. Use it to detect that a sandbox is a
   * clone (e.g. to re-run setup). It does NOT reseed in-guest PRNGs — see the
   * "Randomness in cloned sandboxes" docs page for the in-guest pattern.
   */
  async cloneGeneration(call?: CallOptions): Promise<CloneGeneration> {
    return this.api(call).cloneGeneration(this.id);
  }

  execStream(options: ExecStreamOptions): ExecStreamHandle {
    return this.client.execStream(this.id, options);
  }

  /**
   * Watch a folder in this sandbox for changes; see
   * {@link APIClient.watchFiles}. gVisor and Firecracker sandboxes only.
   */
  async watchFiles(path: string, onEvent: (event: FileEvent) => void, options: WatchFilesOptions = {}): Promise<FileWatchHandle> {
    return this.client.watchFiles(this.id, path, onEvent, options);
  }

  async createSession(options: CreateSessionOptions, call?: CallOptions): Promise<Session> {
    return this.api(call).createSession(this.id, options);
  }

  async listSessions(call?: CallOptions): Promise<Session[]> {
    return this.api(call).listSessions(this.id);
  }

  async getSession(sessionID: string, call?: CallOptions): Promise<Session> {
    return this.api(call).getSession(this.id, sessionID);
  }

  async deleteSession(sessionID: string, call?: CallOptions): Promise<void> {
    await this.api(call).deleteSession(this.id, sessionID);
  }

  async signalSession(sessionID: string, signal: string, call?: CallOptions): Promise<void> {
    await this.api(call).signalSession(this.id, sessionID, signal);
  }

  async resizeSession(sessionID: string, cols: number, rows: number, call?: CallOptions): Promise<void> {
    await this.api(call).resizeSession(this.id, sessionID, cols, rows);
  }

  async sessionLog(sessionID: string, call?: CallOptions): Promise<Uint8Array> {
    return this.api(call).sessionLog(this.id, sessionID);
  }

  async sessionRecording(sessionID: string, call?: CallOptions): Promise<Uint8Array> {
    return this.api(call).sessionRecording(this.id, sessionID);
  }

  attachSession(sessionID: string, options: SessionAttachOptions = {}): SessionAttachHandle {
    return this.client.attachSession(this.id, sessionID, options);
  }

  /** Copy a local folder into the sandbox (Node.js only). See {@link APIClient.uploadDir}. */
  async uploadDir(localDir: string, remoteDir: string, call?: CallOptions): Promise<void> {
    await this.api(call).uploadDir(this.id, localDir, remoteDir);
  }

  /** Upload a file. See {@link UploadFileOptions} for append, create-only, atomic and mode. */
  async uploadFile(targetPath: string, data: BinaryLike, options: UploadFileOptions = {}, call?: CallOptions): Promise<void> {
    await this.api(call).uploadFile(this.id, targetPath, data, options);
  }

  async downloadFile(targetPath: string, options: DownloadFileOptions = {}, call?: CallOptions): Promise<Uint8Array> {
    return this.api(call).downloadFile(this.id, targetPath, options);
  }

  /** Read a file as a stream. See {@link APIClient.downloadFileStream}. */
  async downloadFileStream(targetPath: string, options: DownloadFileOptions = {}, call?: CallOptions): Promise<ReadableStream<Uint8Array>> {
    return this.api(call).downloadFileStream(this.id, targetPath, options);
  }

  /** Upload from a stream, sent once. See {@link APIClient.uploadFileStream}. */
  async uploadFileStream(
    targetPath: string,
    data: ReadableStream<Uint8Array> | AsyncIterable<Uint8Array>,
    options: UploadFileOptions = {},
    call?: CallOptions,
  ): Promise<void> {
    await this.api(call).uploadFileStream(this.id, targetPath, data, options);
  }

  /** List a folder. See {@link ListFilesOptions}; `truncated` means more entries exist. */
  async listFiles(path: string, options: ListFilesOptions = {}, call?: CallOptions): Promise<FileList> {
    return this.api(call).listFiles(this.id, path, options);
  }

  /** Describe one path. A symlink is followed. */
  async getFileInfo(path: string, call?: CallOptions): Promise<FileInfo> {
    return this.api(call).getFileInfo(this.id, path);
  }

  /** Whether a path exists. A missing sandbox throws; it is not `false`. */
  async fileExists(path: string, call?: CallOptions): Promise<boolean> {
    return this.api(call).fileExists(this.id, path);
  }

  /** Delete a file, or a folder and its contents with `recursive: true`. */
  async deleteFile(path: string, options: DeleteFileOptions = {}, call?: CallOptions): Promise<void> {
    await this.api(call).deleteFile(this.id, path, options);
  }

  /** Make a folder; with `parents: true`, like `mkdir -p`. */
  async makeDir(path: string, options: MakeDirOptions = {}, call?: CallOptions): Promise<void> {
    await this.api(call).makeDir(this.id, path, options);
  }

  /** Move or rename a file or folder. Without `overwrite`, an existing destination is refused (409). */
  async moveFile(source: string, destination: string, options: MoveFileOptions = {}, call?: CallOptions): Promise<void> {
    await this.api(call).moveFile(this.id, source, destination, options);
  }

  /** Copy a file, or a folder with `recursive: true`. */
  async copyFile(source: string, destination: string, options: CopyFileOptions = {}, call?: CallOptions): Promise<void> {
    await this.api(call).copyFile(this.id, source, destination, options);
  }

  /** Paths under `path` whose name matches a glob such as `*.ts`. */
  async searchFiles(path: string, pattern: string, call?: CallOptions): Promise<string[]> {
    return this.api(call).searchFiles(this.id, path, pattern);
  }

  /** Each line under `path` that contains `text` (plain text). */
  async findInFiles(path: string, text: string, call?: CallOptions): Promise<FileMatch[]> {
    return this.api(call).findInFiles(this.id, path, text);
  }

  async exposePort(port: number, options?: ExposePortOptions, call?: CallOptions): Promise<ExposeResult> {
    return this.api(call).exposePort(this.id, port, options);
  }

  async unexposePort(port: number, call?: CallOptions): Promise<void> {
    await this.api(call).unexposePort(this.id, port);
  }

  /**
   * Issue a signed token for this sandbox only, to hand to a browser or an
   * end user. See {@link CreateSandboxTokenOptions}. Each call makes a new
   * token; the server keeps no copy.
   */
  async createToken(options: CreateSandboxTokenOptions, call?: CallOptions): Promise<SandboxToken> {
    return this.api(call).createSandboxToken(this.id, options);
  }

  /**
   * Make every token issued for this sandbox so far stop working, toolbox
   * and port tokens alike. A token made after the call works. Safe to call
   * again.
   */
  async revokeTokens(call?: CallOptions): Promise<RevokeSandboxTokensResult> {
    return this.api(call).revokeSandboxTokens(this.id);
  }

  /**
   * Per-sandbox custom-hostname bindings. Exposed as a namespaced accessor
   * (rather than `addCustomDomain`/`removeCustomDomain`/`listCustomDomains`
   * methods on the resource) so call sites read like
   * `sandbox.customDomains.add("api.acme.com")`, mirroring the noun in the
   * `/v1/.../custom-domains` URL space. A fresh object is returned per access
   * so the closures always see the current `id` even after `refresh()`.
   */
  get customDomains(): {
    add(hostname: string, options?: AddCustomDomainOptions, call?: CallOptions): Promise<CustomDomain[]>;
    remove(hostname: string, call?: CallOptions): Promise<void>;
    list(call?: CallOptions): Promise<CustomDomain[]>;
    dns(call?: CallOptions): Promise<CustomDomainDNSRecords>;
  } {
    const client = this.client;
    const id = this.id;
    return {
      add: (hostname: string, options?: AddCustomDomainOptions, call?: CallOptions) =>
        client.withSignal(call?.signal).addCustomDomain(id, hostname, options),
      remove: (hostname: string, call?: CallOptions) => client.withSignal(call?.signal).removeCustomDomain(id, hostname),
      list: (call?: CallOptions) => client.withSignal(call?.signal).listCustomDomains(id),
      dns: (call?: CallOptions) => client.withSignal(call?.signal).customDomainDNS(id),
    };
  }

	async createSnapshot(name: string, options: CreateSnapshotOptions = {}, call?: CallOptions): Promise<SandboxSnapshot> {
		return this.api(call).createSnapshot(this.id, name, options);
	}

  async start(call?: CallOptions): Promise<this> {
    const updated = await this.api(call).start(this.id);
    this.apply(updated.toJSON());
    return this;
  }

  async stop(call?: CallOptions): Promise<this> {
    const updated = await this.api(call).stop(this.id);
    this.apply(updated.toJSON());
    return this;
  }

  async destroy(call?: CallOptions): Promise<void> {
    await this.api(call).destroy(this.id);
  }

  async resize(options: ResizeOptions, call?: CallOptions): Promise<this> {
    const updated = await this.api(call).resize(this.id, options);
    this.apply(updated.toJSON());
    return this;
  }

  async updateLifecycle(lifecycle: Lifecycle, call?: CallOptions): Promise<this> {
    const updated = await this.api(call).updateLifecycle(this.id, lifecycle);
    this.apply(updated.toJSON());
    return this;
  }

  async getNetworkUsage(call?: CallOptions): Promise<NetworkUsage> {
    return this.api(call).getNetworkUsage(this.id);
  }

  async setNetworkLimits(options: SetNetworkLimitsOptions, call?: CallOptions): Promise<NetworkUsage> {
    return this.api(call).setNetworkLimits(this.id, options);
  }

  /**
   * Replaces this sandbox's egress policy while it runs. The call returns
   * once the new policy is enforced; sending the same policy again is a
   * no-op, so it is safe to retry.
   */
  async setNetworkPolicy(options: NetworkPolicyOptions, call?: CallOptions): Promise<NetworkPolicy> {
    const policy = await this.api(call).setNetworkPolicy(this.id, options);
    this.networkBlockAll = policy.networkBlockAll;
    this.egressStatus = policy.egressStatus;
    this.egressProfiles = policy.egressProfiles.length ? policy.egressProfiles : undefined;
    this.networkEgressMode = policy.networkEgressMode === "learn" ? "learn" : undefined;
    this.networkEgressRules = policy.networkEgressRules.length ? policy.networkEgressRules : undefined;
    return policy;
  }

  /**
   * Reads what this sandbox reached in learn mode and the allow list that
   * would have allowed it. A recording stays readable after the sandbox
   * switches to enforce, until it is destroyed.
   */
  async learned(call?: CallOptions): Promise<NetworkLearned> {
    return this.api(call).getNetworkLearned(this.id);
  }

  /**
   * Reads this sandbox's audit log: outbound connections and egress denials
   * (`kind: "egress"`), and secret reads. Denials carry `result: "failure"`
   * and the policy `reason`.
   */
  async audit(options?: AuditOptions, call?: CallOptions): Promise<AuditPage> {
    return this.api(call).getAudit(this.id, options);
  }

  toJSON(): Sandbox {
    // Only the sandbox's own fields, not the SDK's flags on this object.
    const { destroyOnExit: _destroyOnExit, disposed: _disposed, ...data } = this as unknown as Record<string, unknown>;
    return cloneSandbox(data as unknown as Sandbox);
  }

  private apply(sandbox: Sandbox): void {
    Object.assign(this, cloneSandbox(sandbox));
  }
}

function toApiCreateOptions(options: CreateOptions): Record<string, unknown> {
  return {
    name: options.name,
    tags: options.tags,
    image: options.image,
    cpu: options.cpu,
    memory_mb: options.memoryMB,
    disk_gb: options.diskGB,
    env: options.env,
    os_user: options.osUser,
    network_block_all: options.networkBlockAll,
    network_allow_out: options.networkAllowOut,
    network_deny_out: options.networkDenyOut,
    egress_profiles: options.egressProfiles,
    network_egress_mode: options.networkEgressMode,
    network_egress_rules: options.networkEgressRules?.map(toApiEgressRule),
    allow_public_traffic: options.allowPublicTraffic,
    mask_request_host: options.maskRequestHost,
    network_bytes_in_limit: options.networkBytesInLimit,
    network_bytes_out_limit: options.networkBytesOutLimit,
    registry: options.registry,
    container_command: options.containerCommand,
    mounts: options.mounts?.map(toApiMountSpec),
    platform_volumes: options.platformVolumes?.map(toApiPlatformVolumeMount),
    lifecycle: options.lifecycle ? toApiLifecycle(options.lifecycle) : undefined,
    failover: options.failover ? toApiFailover(options.failover) : undefined,
    placement: options.placement ? { zone: options.placement.zone, labels: options.placement.labels } : undefined,
    runtime: options.runtime,
    durability: options.durability,
    module_ref: options.moduleRef,
    tenant_id: options.tenantId,
    custom_domains: options.customDomains,
    gpus: options.gpus ? toApiGPUOptions(options.gpus) : undefined,
    template_id: options.templateId,
    identity: options.identity ? toApiIdentity(options.identity) : undefined,
  };
}

function toApiGPUOptions(gpus: GPUOptions): Record<string, unknown> {
  return {
    vendor: gpus.vendor,
    count: gpus.count,
    device_ids: gpus.deviceIDs,
  };
}

function toApiRegisterSnapshotOptions(options: RegisterSnapshotOptions): Record<string, unknown> {
  return {
    name: options.name,
    image: options.image,
    dockerfile_content: options.dockerfileContent,
    context_hashes: options.contextHashes,
    entrypoint: options.entrypoint,
    region_id: options.regionID,
    cpu: options.cpu,
    gpu: options.gpu,
    memory_mb: options.memoryMB,
    disk_gb: options.diskGB,
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
    argv: request.argv,
    workdir: request.workDir,
    env: request.env,
    timeout_seconds: request.timeoutSeconds,
    max_stdout_bytes: request.maxStdoutBytes,
    max_stderr_bytes: request.maxStderrBytes,
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
    serverless: lifecycle.serverless,
    restart_on_failure: lifecycle.restartOnFailure,
    destroy_after_exit_for: lifecycle.destroyAfterExitFor,
    destroy_at: lifecycle.destroyAt instanceof Date ? lifecycle.destroyAt.toISOString() : lifecycle.destroyAt,
  };
}

function toApiFailover(failover: Failover): ApiFailover {
  return {
    policy: failover.policy,
  };
}

function fromApiSandbox(sandbox: ApiSandbox): Sandbox {
  return {
    id: sandbox.id,
    name: sandbox.name || undefined,
    tags: sandbox.tags,
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
    egressStatus: sandbox.egress_status || undefined,
    egressProfiles: sandbox.egress_profiles?.length ? sandbox.egress_profiles : undefined,
    egressProfilesApplied: sandbox.egress_profiles_applied?.length ? sandbox.egress_profiles_applied : undefined,
    networkEgressMode: sandbox.network_egress_mode || undefined,
    networkEgressRules: sandbox.network_egress_rules?.length ? sandbox.network_egress_rules.map(fromApiEgressRule) : undefined,
    toolboxEnabled: sandbox.toolbox_enabled,
    sshPublicKey: sandbox.ssh_public_key,
    exposedPorts: sandbox.exposed_ports?.map(fromApiExposedPort),
    createdAt: sandbox.created_at,
    updatedAt: sandbox.updated_at,
    lastActiveAt: sandbox.last_active_at,
    lastError: sandbox.last_error,
    statusReason: (sandbox.status_reason || undefined) as StatusReason | undefined,
    // 0 is a real exit code; only an absent or null one is left out.
    exitCode: sandbox.exit_code ?? undefined,
    containerCommand: sandbox.container_command,
    lifecycle: fromApiLifecycle(sandbox.lifecycle),
    failover: fromApiFailover(sandbox.failover),
    runtime: normalizeRuntime(sandbox.runtime),
    durability: sandbox.durability as Sandbox["durability"] | undefined,
    moduleRef: sandbox.module_ref,
    moduleDigest: sandbox.module_digest,
    tenantId: sandbox.tenant_id,
    identity: fromApiSandboxIdentity(sandbox.identity),
  };
}

// normalizeRuntime narrows the wire-level string to the union we expose, while
// tolerating older sandboxd versions that don't send the field at all (treat
// as "" — i.e. host default at start time).
function normalizeRuntime(value: string | undefined): Sandbox["runtime"] {
  if (
    value === "docker" ||
    value === "gvisor" ||
    value === "kata" ||
    value === "firecracker" ||
    value === "wasm" ||
    value === "isolate"
  ) {
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

function fromApiTemplate(template: ApiTemplate): Template {
  return {
    id: template.id,
    image: template.image,
    status: template.status,
    rootfsSizeBytes: template.rootfs_size_bytes,
    minSizeMiB: template.min_size_mib,
    lastError: template.last_error,
    createdAt: template.created_at,
    updatedAt: template.updated_at,
    readyAt: template.ready_at,
    snapshotSizeBytes: template.snapshot_size_bytes,
    snapshotError: template.snapshot_error,
    hasSnapshot: template.has_snapshot,
    hasOverlay: template.has_overlay,
    pushState: template.push_state,
    pushError: template.push_error,
  };
}

function fromApiWasmModule(module: ApiWasmModule): WasmModule {
  return {
    id: module.id,
    moduleRef: module.module_ref,
    status: module.status,
    moduleSizeBytes: module.module_size_bytes,
    digest: module.digest,
    entrypoint: module.entrypoint,
    hasWarm: module.has_warm,
    lastError: module.last_error,
    createdAt: module.created_at,
    updatedAt: module.updated_at,
    readyAt: module.ready_at,
  };
}

function fromApiSandboxSnapshot(snapshot: ApiSandboxSnapshot): SandboxSnapshot {
  return {
    name: snapshot.name,
    image: snapshot.image,
    imageID: snapshot.image_id,
    sourceSandboxID: snapshot.source_sandbox_id,
    createdAt: snapshot.created_at,
    entrypoint: snapshot.entrypoint,
    regionID: snapshot.region_id,
    cpu: snapshot.cpu,
    gpu: snapshot.gpu,
    memoryMB: snapshot.memory_mb,
    diskGB: snapshot.disk_gb,
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

function fromApiCustomDomain(domain: ApiCustomDomain): CustomDomain {
  return {
    hostname: domain.hostname,
    status: domain.status,
    lastError: domain.last_error,
    createdAt: domain.created_at,
    updatedAt: domain.updated_at,
    targetPort: domain.target_port,
  };
}

function fromApiExposedPort(port: ApiExposedPort): ExposedPort {
  return {
    sandboxID: port.sandbox_id,
    port: port.port,
    publicURL: port.public_url,
    createdAt: port.created_at,
    ...(port.visibility === "token" ? { visibility: "token" as const } : {}),
  };
}

function fromApiExposePortResponse(response: ApiExposePortResponse): ExposeResult {
  switch (response.protocol) {
    case "tcp":
      return {
        protocol: "tcp",
        url: response.public_url,
        host: response.host ?? "",
        hostPort: response.host_port ?? 0,
      };
    case "tls":
      return { protocol: "tls", url: response.public_url };
    case "http":
      return response.visibility === "token"
        ? { protocol: "http", url: response.public_url, visibility: "token" }
        : { protocol: "http", url: response.public_url };
  }
}

function fromApiExecResult(result: ApiExecResult): ExecResult {
  return {
    stdout: result.stdout,
    stderr: result.stderr,
    exitCode: result.exit_code,
    durationMS: result.duration_ms,
    timedOut: result.timed_out ?? false,
    stdoutTruncated: result.stdout_truncated ?? false,
    stderrTruncated: result.stderr_truncated ?? false,
    signal: result.signal || undefined,
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

function fromApiCloneGeneration(gen: ApiCloneGeneration): CloneGeneration {
  return {
    generation: gen.generation,
    resumedAt: gen.resumed_at ?? 0,
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

function toApiPlatformVolumeMount(volume: PlatformVolumeMount): ApiPlatformVolumeMount {
  return {
    name: volume.name,
    path: volume.path,
    read_only: volume.readOnly,
    delete_with_sandbox: volume.deleteWithSandbox,
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

function fromApiAuditPage(page: ApiAuditPage): AuditPage {
  const out: AuditPage = {
    events: (page.events ?? []).map((e): AuditEvent => ({
      time: e.time,
      kind: e.kind,
      result: e.result,
      reason: e.reason,
      destination: e.destination,
      network: e.network,
      actor: e.actor,
      ref: e.ref,
      eventID: e.event_id,
      incarnationID: e.incarnation_id,
      dropped: e.dropped,
    })),
    coverage: {
      answered: page.coverage?.answered ?? [],
      missing: page.coverage?.missing ?? [],
      partial: page.coverage?.partial ?? false,
    },
  };
  if (page.next_cursor) out.nextCursor = page.next_cursor;
  return out;
}

function fromApiNetworkUsage(usage: ApiNetworkUsage): NetworkUsage {
  return {
    sandboxID: usage.sandbox_id,
    bytesIn: usage.bytes_in,
    bytesOut: usage.bytes_out,
    bytesInLimit: usage.bytes_in_limit,
    bytesOutLimit: usage.bytes_out_limit,
    quotaExceeded: usage.quota_exceeded,
    quotaExceededAt: usage.quota_exceeded_at ?? undefined,
    lastSampledAt: usage.last_sampled_at ?? undefined,
  };
}

function toApiSetNetworkLimitsOptions(options: SetNetworkLimitsOptions): Record<string, unknown> {
  return {
    network_bytes_in_limit: options.networkBytesInLimit,
    network_bytes_out_limit: options.networkBytesOutLimit,
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
  if (lifecycle?.serverless) {
    result.serverless = true;
  }
  if (lifecycle?.restart_on_failure) {
    result.restartOnFailure = true;
  }
  if (lifecycle?.destroy_after_exit_for !== undefined) {
    result.destroyAfterExitFor = lifecycle.destroy_after_exit_for;
  }
  return result;
}

function fromApiFailover(failover?: ApiFailover): Failover | undefined {
  const policy = failover?.policy;
  if (policy !== "recreate" && policy !== "none") {
    return undefined;
  }
  return { policy };
}

// buildTagQuery renders ListOptions.tags as the server's wire format. The
// `tag.` prefix is literal — the server's parseTagFilter does a prefix check
// on the *decoded* query key, so only the user-supplied key and value get
// percent-encoded. An empty or absent map returns "" so the request URL is
// byte-identical to the pre-filter call site (no trailing "?"), keeping
// fixtures and middleware that match on path stable.
function buildTagQuery(tags: Record<string, string> | undefined): string {
  if (!tags) return "";
  const entries = Object.entries(tags);
  if (entries.length === 0) return "";
  const parts = entries.map(
    ([key, value]) => `tag.${encodeURIComponent(key)}=${encodeURIComponent(value)}`,
  );
  return "?" + parts.join("&");
}

function buildIncludeEnvQuery(includeEnv: boolean | undefined): string {
  return includeEnv ? "?include_env=true" : "";
}

function buildSandboxListQuery(options?: ListOptions): string {
  let query = buildTagQuery(options?.tags);
  if (options?.includeEnv) {
    query = appendQueryParam(query, "include_env", "true");
  }
  const name = options?.name?.trim();
  if (name) {
    query = appendQueryParam(query, "name", name);
  }
  return query;
}

function appendQueryParam(path: string, key: string, value: string): string {
  if (!value) {
    return path;
  }
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
}

function cloneSandbox(sandbox: Sandbox): Sandbox {
  return {
    ...sandbox,
    env: sandbox.env ? { ...sandbox.env } : undefined,
    tags: sandbox.tags ? { ...sandbox.tags } : undefined,
    exposedPorts: sandbox.exposedPorts?.map((port) => ({ ...port })),
    containerCommand: sandbox.containerCommand ? [...sandbox.containerCommand] : undefined,
    lifecycle: { ...sandbox.lifecycle },
    failover: sandbox.failover ? { ...sandbox.failover } : undefined,
    identity: sandbox.identity ? { ...sandbox.identity } : undefined,
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

/** The folder's contents as tar entries, names relative to it, sorted. */
async function folderEntries(root: string, prefix: string): Promise<TarEntry[]> {
  const entries: TarEntry[] = [];
  const names = (await readdir(join(root, prefix))).sort();
  for (const name of names) {
    const rel = prefix === "" ? name : `${prefix}/${name}`;
    const full = join(root, rel);
    const info = await lstat(full);
    const base = { name: rel, mode: info.mode & 0o7777, mtime: Math.floor(info.mtimeMs / 1000) };
    if (info.isSymbolicLink()) {
      entries.push({ ...base, type: "symlink", linkname: await readlink(full) });
    } else if (info.isDirectory()) {
      entries.push({ ...base, type: "dir" }, ...(await folderEntries(root, rel)));
    } else if (info.isFile()) {
      entries.push({ ...base, type: "file", data: await readFile(full) });
    }
    // Devices, pipes and sockets are skipped: the sandbox refuses them.
  }
  return entries;
}

/** The `code` of a JSON error reply, read from a clone so the body stays readable. */
async function errorCode(response: Response): Promise<string | undefined> {
  try {
    const payload = (await response.clone().json()) as { code?: unknown };
    return typeof payload.code === "string" ? payload.code : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A missing file, not a missing sandbox (also a 404). Current agents say
 * file_not_found; older ones send no code, but their message is the OS
 * error, which ends "no such file or directory".
 */
function isMissingFile(err: unknown): boolean {
  if (!(err instanceof MicroVMApiError) || err.status !== 404) {
    return false;
  }
  return err.code === "file_not_found" || (err.code === undefined && err.message.endsWith("no such file or directory"));
}

/** Wire shape of toolboxd's file info with extended=true. */
interface ApiFileInfo {
  name?: string;
  path?: string;
  isDir?: boolean;
  size?: number;
  size_bytes?: number;
  mode?: string;
  permissions?: string;
  owner?: string;
  group?: string;
  modTime?: string;
  symlink_target?: string;
}

/**
 * An older agent ignores extended=true and sends only Daytona's fields (a
 * 32-bit size, no path), so each extended field falls back.
 */
function fromApiFileInfo(item: ApiFileInfo, fallbackPath: string): FileInfo {
  const info: FileInfo = {
    name: item.name ?? "",
    path: item.path || fallbackPath,
    isDir: item.isDir ?? false,
    size: item.size_bytes ?? item.size ?? 0,
    mode: item.mode ?? "",
    permissions: item.permissions ?? "",
    owner: item.owner ?? "",
    group: item.group ?? "",
    modTime: item.modTime ?? "",
  };
  if (typeof item.symlink_target === "string") {
    info.symlinkTarget = item.symlink_target;
  }
  return info;
}

async function decodeError(response: Response): Promise<MicroVMApiError> {
  const retryAfterMs = parseRetryAfter(response.headers.get("retry-after"), Date.now());
  try {
    const payload = (await response.json()) as { error?: unknown; code?: unknown };
    if (typeof payload.error === "string" && payload.error !== "") {
      const code = typeof payload.code === "string" && payload.code !== "" ? payload.code : undefined;
      return apiErrorFor(response.status, payload.error, { code, retryAfterMs });
    }
  } catch {
    // Not JSON (a proxy's error page) or no body: fall through to the
    // status-based message, with no code.
  }
  return apiErrorFor(response.status, `request failed with status ${response.status}`, { retryAfterMs });
}

const STREAM_PREFIX_STDOUT = 0x01;
const STREAM_PREFIX_STDERR = 0x02;

// toolboxd marks a 404 that means "no such route" with this header, as
// opposed to a route that answered 404 for a missing file.
const TOOLBOX_ROUTE_HEADER = "x-toolbox-route";
const FILE_WATCH_FEATURE = "files.watch";

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

function openExecStream(
  baseURL: string,
  versionPrefix: string,
  patToken: string,
  sandboxID: string,
  options: ExecStreamOptions,
  ready?: Promise<void>,
): ExecStreamHandle {
  const wsURL = baseURL.replace(/^http/, "ws") + `${versionPrefix}/sandboxes/${encodeURIComponent(sandboxID)}/toolbox/process/exec/stream`;

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
  const failWith = (msg: string | Error) => {
    if (resolved) return;
    resolved = true;
    exitReject?.(typeof msg === "string" ? new Error(msg) : msg);
  };

  // Frames the caller sends after the socket opened but before a delayed
  // start message (argv's feature check) wait here, so the start message is
  // always first. Before the socket opens, send fails as it always has.
  let started = false;
  const pending: (string | Uint8Array<ArrayBuffer>)[] = [];
  const send = (data: string | Uint8Array<ArrayBuffer>) => {
    if (!started && ws.readyState === 1) {
      pending.push(data);
      return;
    }
    ws.send(data);
  };
  const sendStart = () => {
    ws.send(JSON.stringify({
      command: options.command,
      argv: options.argv,
      workdir: options.workdir,
      env: options.env,
      tty: options.tty ?? false,
      cols: options.cols ?? 0,
      rows: options.rows ?? 0,
    }));
    started = true;
    for (const data of pending.splice(0)) {
      ws.send(data);
    }
  };

  // The check can fail before the socket opens; mark it handled now so
  // Node does not report an unhandled rejection, and act on it at "open".
  ready?.catch(() => undefined);
  ws.addEventListener("open", () => {
    if (!ready) {
      sendStart();
      return;
    }
    ready.then(
      () => {
        if (!resolved) {
          sendStart();
        }
      },
      (err: unknown) => {
        failWith(err instanceof Error ? err : new Error(String(err)));
        ws.close();
      },
    );
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
    send(toWebSocketBinaryFrame(data));
  };

  return {
    write: sendBinary,
    resize(cols: number, rows: number) {
      send(JSON.stringify({ type: "resize", cols, rows }));
    },
    signal(name: string) {
      send(JSON.stringify({ type: "signal", signal: name }));
    },
    close() {
      send(JSON.stringify({ type: "close" }));
    },
    done,
  };
}

function openSessionAttach(
  baseURL: string,
  versionPrefix: string,
  patToken: string,
  sandboxID: string,
  sessionID: string,
  options: SessionAttachOptions,
): SessionAttachHandle {
  const wsURL = baseURL.replace(/^http/, "ws") + `${versionPrefix}/sandboxes/${encodeURIComponent(sandboxID)}/sessions/${encodeURIComponent(sessionID)}/attach`;

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

function fromApiFileEvent(raw: unknown): FileEvent {
  const e = (raw ?? {}) as { type?: unknown; path?: unknown; is_dir?: unknown; reason?: unknown };
  const event: FileEvent = {
    type: typeof e.type === "string" ? e.type : "",
    path: typeof e.path === "string" ? e.path : "",
    isDir: e.is_dir === true,
  };
  if (typeof e.reason === "string" && e.reason !== "") {
    event.reason = e.reason;
  }
  return event;
}

// openFileWatch opens toolboxd's /files/watch stream and resolves with its
// handle once the "start" frame says the watch is in place. `refusal`
// explains a handshake that never opened.
// How long a file watch waits for the agent to say the watch is armed.
export const WATCH_START_TIMEOUT_MS = 60_000;

function openFileWatch(
  baseURL: string,
  routePath: string,
  patToken: string,
  onEvent: (event: FileEvent) => void,
  refusal: (detail: string) => Promise<Error>,
): Promise<FileWatchHandle> {
  const WS = (globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
  if (!WS) {
    return Promise.reject(new Error("WebSocket is not available in this runtime — Node 22+ or a browser is required"));
  }
  // The PAT rides the subprotocol, as on execStream: browsers cannot set
  // Authorization on a WebSocket handshake.
  const ws = new WS(baseURL.replace(/^http/, "ws") + routePath, ["sandbox.bearer", patToken]);

  let startResolve!: (handle: FileWatchHandle) => void;
  let startReject!: (err: Error) => void;
  const started = new Promise<FileWatchHandle>((resolve, reject) => {
    startResolve = resolve;
    startReject = reject;
  });
  let endResolve!: () => void;
  let endReject!: (err: Error) => void;
  const ended = new Promise<void>((resolve, reject) => {
    endResolve = resolve;
    endReject = reject;
  });
  // A caller that never calls wait() must not see an unhandled rejection.
  ended.catch(() => undefined);

  let opened = false;
  let isStarted = false;
  let startFailed = false;
  let settled = false;
  let lastErrorDetail = "";

  const finish = (err?: Error) => {
    if (settled) return;
    settled = true;
    if (err) {
      endReject(err);
    } else {
      endResolve();
    }
  };
  const handle: FileWatchHandle = {
    stop() {
      finish();
      ws.close();
    },
    wait() {
      return ended;
    },
  };
  const fail = (detail: string) => {
    clearTimeout(startTimer);
    if (isStarted) {
      finish(new Error(`file watch stream closed${detail}`));
      return;
    }
    if (startFailed) return;
    startFailed = true;
    if (opened) {
      startReject(new Error(`file watch closed before it started${detail}`));
      return;
    }
    void refusal(detail).then(startReject, startReject);
  };

  // The wait for "start" is bounded: a proxy that accepts the upgrade and
  // then goes quiet would otherwise leave the caller waiting forever. Later
  // frames are not bounded, since a quiet folder sends nothing.
  const startTimer = setTimeout(() => {
    if (isStarted || startFailed) return;
    startFailed = true;
    startReject(new Error(`file watch did not start within ${WATCH_START_TIMEOUT_MS / 1000}s`));
    ws.close();
  }, WATCH_START_TIMEOUT_MS);
  // In Node, the pending wait alone must not keep the process alive.
  (startTimer as { unref?: () => void }).unref?.();

  ws.addEventListener("open", () => {
    opened = true;
  });

  ws.addEventListener("message", (event: MessageEvent) => {
    if (typeof event.data !== "string") return;
    let msg: { type?: unknown; events?: unknown; reason?: unknown };
    try {
      msg = JSON.parse(event.data) as typeof msg;
    } catch {
      return;
    }
    switch (msg.type) {
      case "start":
        clearTimeout(startTimer);
        if (!isStarted && !startFailed) {
          isStarted = true;
          startResolve(handle);
        }
        return;
      case "events":
        if (!Array.isArray(msg.events)) return;
        for (const raw of msg.events) {
          // stop() inside the callback ends delivery at once.
          if (settled) return;
          try {
            onEvent(fromApiFileEvent(raw));
          } catch (err: unknown) {
            // A throwing callback ends the watch; wait() reports why.
            finish(err instanceof Error ? err : new Error(String(err)));
            ws.close();
            return;
          }
        }
        return;
      case "end":
        finish(new Error(typeof msg.reason === "string" && msg.reason !== "" ? msg.reason : "file watch ended"));
        ws.close();
        return;
    }
  });

  ws.addEventListener("close", (event) => {
    const parts = [lastErrorDetail, describeWSClose(event)].filter((s) => s !== "");
    fail(parts.length > 0 ? ` (${parts.join("; ")})` : "");
  });

  ws.addEventListener("error", (event) => {
    const detail = describeWSError(event);
    if (detail !== "") {
      lastErrorDetail = detail;
    }
    fail(detail !== "" ? ` (${detail})` : "");
  });

  return started;
}
