export type SandboxStatus =
  | "creating"
  | "started"
  | "stopped"
  | "destroyed"
  | "error"
  | "passivated"
  | "awaiting_runtime";

export type Durability = "ephemeral" | "passivatable" | "durable";

export interface RegistryAuth {
  server: string;
  username: string;
  password: string;
}

/**
 * Per-request push directive for `MicroVM.buildImage`. Credentials are
 * forwarded to the daemon as a one-shot `X-Registry-Auth` header on the
 * push call and are never persisted.
 */
export interface BuildImagePushOptions {
  /** Destination repository, e.g. "ghcr.io/my-org/my-image". */
  registry: string;
  /** Destination tag. Defaults to "latest" on the daemon when omitted. */
  tag?: string;
  /** Registry serveraddress, e.g. "ghcr.io". Sent inside X-Registry-Auth. */
  server?: string;
  username: string;
  password: string;
}

export interface BuildImageOptions {
  push?: BuildImagePushOptions;
}

export interface BuildImageResult {
  /** Local content-addressed tag (always returned). */
  image: string;
  /** Pushed reference, e.g. "ghcr.io/my-org/my-image:v1.2.3". */
  pushed?: string;
}

export interface RegisterSnapshotOptions {
  /** Human-readable identifier other callers use in `CreateOptions.snapshot`. */
  name: string;
  /** Pre-built registry reference. Mutually exclusive with `dockerfileContent`. */
  image?: string;
  /** Literal Dockerfile the daemon will build. Mutually exclusive with `image`. */
  dockerfileContent?: string;
  /** Uploaded build-context hashes for future COPY/ADD resolution. */
  contextHashes?: string[];
  /** Optional command override persisted on the snapshot row. */
  entrypoint?: string[];
  /** Region hint persisted for read-back. */
  regionID?: string;
  /** Resource hints surfaced back on the snapshot row. */
  cpu?: number;
  gpu?: number;
  memoryMB?: number;
  diskGB?: number;
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

/**
 * A named, operator-backed persistent volume to attach by name. The operator
 * configures the shared backend (S3/NFS); you never supply storage coordinates
 * or credentials. Persists across the sandbox lifecycle and can be re-attached
 * by name from another sandbox.
 */
export interface PlatformVolumeMount {
  /** Volume name, scoped to your tenant. */
  name: string;
  /** Absolute path to mount it at inside the sandbox. */
  path: string;
  /** Mount read-only. Defaults to read-write. */
  readOnly?: boolean;
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
  /**
   * Opt the sandbox into HTTP wake-on-request: auto-stop when idle,
   * resume on the next inbound HTTP request. Requires `stopIfIdleFor`
   * to be set explicitly — the server rejects `serverless: true`
   * without an idle window. TCP and TLS exposures stay always-on.
   */
  serverless?: boolean;
}

export type UpdateLifecycleOptions = Lifecycle;

export type FailoverPolicy = "none" | "recreate";

export interface Failover {
  /**
   * "none" (default) returns 410 Gone after owner-node death. "recreate"
   * opts into best-effort cluster recreation from the replicated create spec.
   */
  policy: FailoverPolicy;
}

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
   * Optional name, unique among the caller's sandboxes (another account may
   * use the same name). A repeat create with a name the caller already holds
   * returns HTTP 409. Names starting with `owner:` or shaped like a sandbox
   * ID (`sb-` plus 16 hex) are rejected.
   */
  name?: string;
  /** Free-form key/value labels; filter on them with `ListOptions.tags`. */
  tags?: Record<string, string>;
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
   * Egress allowlist: CIDRs, hostnames (`pypi.org`), `*.suffix` wildcards and
   * `host:port` entries. Alone, the sandbox may reach only these. With
   * `networkDenyOut`, allow wins, then deny, then the default is allow; a
   * deny of `0.0.0.0/0` makes it an allowlist. For a full block use
   * `networkBlockAll`.
   */
  networkAllowOut?: string[];
  /**
   * Egress blocklist of CIDRs (never hostnames). Alone, the sandbox may reach
   * anything except these destinations.
   */
  networkDenyOut?: string[];
  /**
   * Named egress profiles whose entries join `networkAllowOut` (see
   * `putEgressProfile`). A profile change reaches every sandbox that
   * references it.
   */
  egressProfiles?: string[];
  /**
   * `"learn"` gives the sandbox open egress and records what it reaches, so
   * `learned()` can suggest an allow list. Trusted runs only. Needs no lists,
   * profiles or block-all. Omitted is `"enforce"`.
   */
  networkEgressMode?: "enforce" | "learn";
  /**
   * Method and path rules that refine hosts the allow list already admits
   * (at most 32). A rule with `inspect: true` makes the egress gateway
   * terminate TLS on 443 with the node's CA, which only a sandbox created
   * with such a rule trusts, so set inspect rules here rather than adding
   * them later.
   */
  networkEgressRules?: EgressRule[];
  /**
   * Whether the sandbox may be exposed to the public internet. Omitted defaults
   * to private (no public URL, `exposePort` fails). Set `true` to opt in to
   * public exposure; `false` permanently refuses it for this sandbox.
   */
  allowPublicTraffic?: boolean;
  /**
   * Rewrite the upstream `Host` header on ingress to exposed HTTP ports to this
   * value. Frameworks that validate the Host (Vite `allowedHosts`,
   * webpack-dev-server, Django `ALLOWED_HOSTS`) reject the per-sandbox public
   * hostname; set this to a value they accept (e.g. `"localhost"`). Empty/unset
   * passes the host through unchanged. HTTP-only; TCP/TLS exposures ignore it.
   */
  maskRequestHost?: string;
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
  /**
   * Named, operator-backed persistent volumes to attach by name. Requires the
   * operator to have enabled platform volumes; otherwise the create is rejected
   * with 412. Only supported on the docker/gvisor runtimes.
   */
  platformVolumes?: PlatformVolumeMount[];
  lifecycle?: Lifecycle;
  failover?: Failover;
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
  runtime?: "docker" | "gvisor" | "kata" | "firecracker" | "wasm" | "isolate";
  /**
   * Survival class across daemon restarts. Omit for the runtime default:
   * `passivatable` for docker/gvisor/firecracker, `ephemeral` for wasm/isolate.
   * `durable` is wasm-only and not yet implemented.
   */
  durability?: Durability;
  /** WASM module / isolate bundle reference. When runtime is wasm or isolate, may be used instead of image. */
  moduleRef?: string;
  /**
   * Isolate-group key for `runtime: "isolate"`. Sandboxes with the same
   * tenant share one workerd process. Server-authorized; when omitted the
   * group key falls back to the authenticated identity. Ignored by other
   * runtimes.
   */
  tenantId?: string;
  /**
   * Attach GPU resources to the sandbox. Omit for CPU-only workloads.
   * Not compatible with runtime="gvisor".
   */
  gpus?: GPUOptions;
  /**
   * Custom hostnames to bind to this sandbox at create-time. Each entry is
   * lowercased server-side and progresses through the standard custom-domain
   * lifecycle (pending_dns → issuing → ready). Equivalent to calling
   * `sandbox.customDomains.add(host)` for each entry after create.
   */
  customDomains?: string[];
}

export interface ResizeOptions {
  /** Number of CPU cores. Fractional values supported (e.g. 0.5). */
  cpu?: number;
  memoryMB?: number;
  diskGB?: number;
}

export interface ListOptions {
  /**
   * Filter the result to only sandboxes whose `tags` map contains every
   * key/value pair given here (AND semantics on the server). Wire format is
   * `?tag.<key>=<value>`; the SDK URL-encodes keys and values for you. Omit
   * or pass an empty map to list every sandbox visible to the PAT.
   */
  tags?: Record<string, string>;
  /**
   * When true, include sandbox env vars in the response (`?include_env=true`).
   * Env is omitted by default — opt-in reads are audited server-side.
   */
  includeEnv?: boolean;
  /**
   * Filter to the caller's sandbox with exactly this name (`?name=<name>`);
   * the result has zero or one entries. Names are unique per owner. Servers
   * that predate name lookup ignore the filter and return a normal list, so
   * prefer `MicroVM.getByName`, which checks the reply.
   */
  name?: string;
}

export interface GetOptions {
  /**
   * When true, include sandbox env vars in the response (`?include_env=true`).
   * Env is omitted by default — opt-in reads are audited server-side.
   */
  includeEnv?: boolean;
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
 * Lifecycle states for a per-sandbox custom hostname.
 *  - "pending_dns": hostname registered; awaiting DNS to point at the daemon.
 *  - "issuing":     DNS resolves; Caddy is acquiring an ACME certificate.
 *  - "ready":       certificate issued; traffic served end-to-end on the host.
 *  - "failed":      ACME or DNS validation failed; see `lastError`.
 */
export type CustomDomainStatus = "pending_dns" | "issuing" | "ready" | "failed";

export interface CustomDomain {
  hostname: string;
  status: CustomDomainStatus;
  lastError?: string;
  createdAt: string;
  updatedAt: string;
  /**
   * Target container port traffic to this hostname dials. `0` (or omitted)
   * means the sandbox's toolbox port — the default that preserves the
   * pre-target-port behavior. Set once at attach time; to change it, remove
   * the binding and re-add it with the new port.
   */
  targetPort?: number;
}

/**
 * Options for `sandbox.customDomains.add()`. `port` pins the container port
 * traffic to this hostname dials; omit it to route to the sandbox's toolbox
 * port (the default). Re-adding the same hostname with a different `port`
 * returns 409 — detach first.
 */
export interface AddCustomDomainOptions {
  port?: number;
}

/**
 * Where the SDK derived the ingress address(es) from. Reflects how the
 * operator deployed the cluster:
 *   - "hostname": the cluster gossips a stable hostname (CNAME target).
 *   - "ips":      one or more raw ingress IPs (one A/AAAA record per IP).
 *   - "mixed":    some nodes gossip a hostname, others raw IPs — prefer
 *                 the hostname but render both so apex domains still work.
 *   - "unknown":  no ingress node has gossiped a public address yet; the
 *                 target is unusable and callers should surface that, not
 *                 guess.
 */
export type IngressTargetSource = "hostname" | "ips" | "mixed" | "unknown";

/**
 * The cluster's published ingress address(es) — the value that DNS for a
 * custom domain must ultimately resolve to. Returned by `microvm.dns.target()`
 * and embedded in {@link CustomDomainDNSRecords}.
 */
export interface IngressTarget {
  hostname?: string;
  ips?: string[];
  source: IngressTargetSource;
}

/**
 * DNS record types the daemon emits for custom-domain wiring. `ANAME` and
 * `ALIAS` only appear for an apex domain on a hostname ingress, where they are
 * mutually-exclusive flattening alternatives to `CNAME` (add the one your
 * provider supports — see each record's `notes`).
 */
export type DNSRecordType = "CNAME" | "A" | "AAAA" | "ANAME" | "ALIAS";

/**
 * One ready-to-paste DNS record a user adds at their DNS provider to make a
 * custom domain reach the cluster. `name` is the leftmost label (or "@" for
 * apex) the way DNS UIs accept it. `notes` carries provider-specific gotchas
 * the daemon pre-renders (e.g. Cloudflare "DNS only, gray cloud") when
 * applicable.
 */
export interface DNSRecord {
  hostname: string;
  type: DNSRecordType;
  name: string;
  value: string;
  notes?: string;
}

/**
 * Response from `sandbox.customDomains.dns()`. `records` is the flat
 * ready-to-paste list (one row per custom domain × per ingress address);
 * `target` is the raw aggregation the records were composed from, included
 * so callers can render their own UI without a second round trip.
 */
export interface CustomDomainDNSRecords {
  records: DNSRecord[];
  target: IngressTarget;
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
  entrypoint?: string[];
  regionID?: string;
  cpu?: number;
  gpu?: number;
  memoryMB?: number;
  diskGB?: number;
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
  /** Name set at create time, unique per owner. Absent for unnamed sandboxes. */
  name?: string;
  /** Labels set at create time. */
  tags?: Record<string, string>;
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
  /**
   * Hostname-egress state on `get` for a sandbox whose allow list names
   * hosts (container runtimes): "active", "held" or "unavailable". Absent
   * otherwise, and on list results.
   */
  egressStatus?: string;
  /** Egress profiles this sandbox references. */
  egressProfiles?: string[];
  /**
   * The generation of each referenced profile that is live on the sandbox,
   * so a caller can see when a profile change has reached it.
   */
  egressProfilesApplied?: EgressProfileRef[];
  /** `"learn"` while the sandbox records its egress; absent otherwise. */
  networkEgressMode?: string;
  /** Method and path rules on the sandbox's egress; absent when it has none. */
  networkEgressRules?: EgressRule[];
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
  failover?: Failover;
  /**
   * Container runtime this sandbox is running under. Empty string indicates
   * a pre-migration row that resolves to the host default at start time.
   */
  runtime: "" | "docker" | "gvisor" | "kata" | "firecracker" | "wasm" | "isolate";
  /** Survival class this sandbox was created with. */
  durability?: Durability;
  /** Resolved WASM module / isolate bundle reference when runtime is wasm or isolate. */
  moduleRef?: string;
  /** sha256 hex digest of the resolved WASM module bytes. */
  moduleDigest?: string;
  /** Isolate-group key this sandbox was created under (`runtime: "isolate"` only). */
  tenantId?: string;
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

/** One record from a sandbox's audit log (`sandbox.audit()`). */
export interface AuditEvent {
  time: string;
  /** "egress" for outbound connections and denials; secret kinds otherwise. */
  kind?: string;
  /** "success", or "failure" for a denial. */
  result: string;
  /** Why it was denied, e.g. "host_not_allowed", "sni_not_allowed". */
  reason?: string;
  /** host:port (or host) the sandbox tried to reach. */
  destination?: string;
  network?: string;
  actor?: string;
  ref?: string;
  eventID?: string;
  incarnationID?: string;
  /** Records lost at this point (a gap record). */
  dropped?: number;
}

export interface AuditPage {
  events: AuditEvent[];
  /** Which nodes answered; `partial` is true when some could not. */
  coverage: { answered: string[]; missing: string[]; partial: boolean };
  /** Pass to `audit({ cursor })` for the next page. */
  nextCursor?: string;
}

export interface AuditOptions {
  /** Only this kind, e.g. "egress". */
  kind?: string;
  limit?: number;
  cursor?: string;
  incarnationID?: string;
}

/**
 * Would a sandbox created with these egress fields reach `destination`?
 * `destination` is "host", "host:port", "IP" or "IP:port"; a bare host is
 * checked as the web ports.
 */
export interface NetworkPolicyCheckOptions {
  networkBlockAll?: boolean;
  networkAllowOut?: string[];
  networkDenyOut?: string[];
  destination: string;
}

export interface NetworkPolicyCheckResult {
  allowed: boolean;
  /** The entry that decided; "" when the default verdict did. */
  matchedRule: string;
  /** "allow" or "deny": what happens to a destination no entry matches. */
  defaultVerdict: string;
  /** The first allow entry outside this deployment's ceiling, if any. */
  outsideCeiling?: string;
}

/**
 * A sandbox's whole egress policy, for `setNetworkPolicy`. It replaces the
 * current policy: a field left out is cleared, so `{}` means open egress.
 * The grammar is the create one (hostnames, `*.` wildcards, `host:port` and
 * CIDRs in the allow list; CIDRs only in the deny list).
 */
export interface NetworkPolicyOptions {
  networkBlockAll?: boolean;
  networkAllowOut?: string[];
  networkDenyOut?: string[];
  egressProfiles?: string[];
  networkEgressMode?: "enforce" | "learn";
  /**
   * Replaces the method and path rules. Adding an inspect rule to a
   * container sandbox created without one is refused with 409: recreate it
   * with the rule.
   */
  networkEgressRules?: EgressRule[];
}

/** The policy a sandbox enforces after `setNetworkPolicy`. */
export interface NetworkPolicy {
  networkBlockAll: boolean;
  networkAllowOut: string[];
  networkDenyOut: string[];
  egressProfiles: string[];
  /** `"enforce"` or `"learn"`. */
  networkEgressMode: string;
  networkEgressRules: EgressRule[];
  /** Hostname entries in force: inline plus every profile's (at most 1024). */
  effectiveHostnameCount: number;
  /** "active", "held" or "unavailable" for hostname rules on a container. */
  egressStatus?: string;
}

/**
 * One method and path rule. Rules refine a host the allow list already
 * admits: a request to a ruled host passes when some rule for that host
 * admits its method and path, and gets a 403 otherwise. A host no rule names
 * keeps its allow-list decision.
 */
export interface EgressRule {
  /** An exact name or `*.` wildcard, without a port. */
  host: string;
  /** `[80]` by default, or `[443]` with `inspect`; only 80 and 443. */
  ports?: number[];
  /** Exact, upper case (`GET`, `POST`); empty allows any. */
  methods?: string[];
  /**
   * Path globs: `*` within one segment, `**` as a whole segment for any
   * number of them. Empty allows any path.
   */
  paths?: string[];
  /**
   * Terminate TLS on 443 with the node's CA so the rule can see requests.
   * The request's Host must then equal the TLS server name.
   */
  inspect?: boolean;
}

/**
 * A named allowlist sandboxes reference through `egressProfiles`. Profiles
 * belong to your account; `generation` goes up by one on every change.
 */
export interface EgressProfile {
  name: string;
  /** Hostnames, `*.` wildcards, `host:port` entries and CIDRs (at most 512 hostnames). */
  allowOut: string[];
  description?: string;
  generation: number;
  createdAt: string;
  updatedAt: string;
}

/** The body of `putEgressProfile`: a full replace. */
export interface EgressProfileOptions {
  allowOut: string[];
  description?: string;
}

export interface ListEgressProfilesOptions {
  cursor?: string;
  limit?: number;
}

export interface EgressProfileList {
  profiles: EgressProfile[];
  /** Pass back as `cursor` for the next page; absent on the last one. */
  nextCursor?: string;
}

/** One destination a learn-mode sandbox reached. */
export interface NetworkLearnedEntry {
  host: string;
  /** Connection ports; empty when the name was only resolved. */
  ports: number[];
  firstSeen: string;
  lastSeen: string;
  hits: number;
}

/**
 * What a sandbox reached in learn mode, and the allow list that would have
 * allowed it: `suggestedAllowOut` when it fits 64 hostnames, otherwise
 * `suggestedProfile` (a body for `putEgressProfile`).
 */
export interface NetworkLearned {
  mode: string;
  /** Recording stopped at its cap. */
  truncated: boolean;
  entries: NetworkLearnedEntry[];
  cidrs: string[];
  suggestedAllowOut: string[];
  suggestedProfile?: EgressProfileOptions;
}

/** A referenced profile and the generation of it that is live on a sandbox. */
export interface EgressProfileRef {
  name: string;
  generation: number;
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

/**
 * Clone-generation marker for a sandbox. The `generation` token changes every
 * time the sandbox is resumed from a snapshot (i.e. it is a clone). A
 * long-lived process running *inside* the sandbox can poll this and reseed its
 * own userspace PRNGs when the token changes — two clones otherwise share the
 * snapshot's frozen seed state. This is a read-only signal; the SDK cannot
 * reseed an in-guest process from the client side. See the "Randomness in
 * cloned sandboxes" docs page.
 */
export interface CloneGeneration {
  /** Opaque token that changes on every resume-from-snapshot. */
  generation: string;
  /** Host wall-clock of the last resume, in unix nanoseconds. 0 = never resumed. */
  resumedAt: number;
}

export type BinaryLike = Uint8Array | ArrayBuffer | Blob | string;

/**
 * Lifecycle states reported by a Firecracker rootfs template. See
 * `plans/snapshot-clone-fast-boot.md` for the state machine.
 *
 * - `pending`, `building_rootfs`, `snapshotting`: the build pipeline is in
 *   flight; no sandbox creation against this template will succeed yet.
 * - `ready`: cold boot + fast snapshot clone both available.
 * - `ready_no_snapshot`: cold boot works; snapshot phase failed and
 *   sandboxes will not get the fast-boot path until a rebuild succeeds.
 * - `unhealthy`: snapshot was detected as corrupt; an async rebuild is in
 *   flight (or pending the next daemon restart).
 * - `failed`: terminal state from a failed initial build; the row must be
 *   deleted and recreated.
 */
export type TemplateStatus =
  | "pending"
  | "building_rootfs"
  | "snapshotting"
  | "ready"
  | "ready_no_snapshot"
  | "failed"
  | "unhealthy";

/**
 * Background-push state for the template's artifacts (rootfs.ext4 +
 * snapshot.*). "active" means push succeeded or push is disabled; "pending"
 * / "pushing" are in-flight states; "error" carries `pushError` for the
 * last failure.
 */
export type TemplatePushState = "active" | "pending" | "pushing" | "error";

/**
 * A Firecracker rootfs template. Created once from an OCI image and
 * boot-shared across many sandboxes. Use {@link MicroVM.createTemplate} to
 * register one, then pass its {@link Template.id} on subsequent sandbox
 * `create` calls (when the sandbox runtime is `firecracker`).
 */
export interface Template {
  id: string;
  image: string;
  status: TemplateStatus;
  rootfsSizeBytes?: number;
  /** Optional floor for the ext4 image size, in MiB. */
  minSizeMiB?: number;
  /** Last build-pipeline error, populated when `status` is `failed`. */
  lastError?: string;
  createdAt: string;
  updatedAt: string;
  /** First time the template reached `ready` / `ready_no_snapshot`. */
  readyAt?: string;
  snapshotSizeBytes?: number;
  /** Populated when `status` is `ready_no_snapshot` — why the snapshot phase failed. */
  snapshotError?: string;
  /** True when the template has a usable snapshot for fast-boot. */
  hasSnapshot: boolean;
  /** True when the template was built with a per-sandbox writable overlay placeholder. */
  hasOverlay: boolean;
  pushState?: TemplatePushState;
  /** Populated when `pushState` is `error` — the last push failure. */
  pushError?: string;
}

export interface CreateTemplateOptions {
  /** Optional explicit ID. Empty means the daemon generates one. Supplying an explicit ID lets retries be idempotent — a duplicate ID returns 409. */
  id?: string;
  /** skopeo-style image reference, e.g. `"docker://python:3.11"`. */
  image: string;
  /** Optional floor for the ext4 image size, in MiB. */
  minSizeMiB?: number;
}

/** Catalogue lifecycle for POST /v1/wasm-modules rows. */
export type WasmModuleStatus = "ready" | "failed";

/**
 * A WASM module catalogue entry. Resolved synchronously on the host and
 * referenced by `moduleRef` when creating `runtime: "wasm"` sandboxes.
 */
export interface WasmModule {
  id: string;
  moduleRef: string;
  status: WasmModuleStatus;
  moduleSizeBytes?: number;
  digest?: string;
  entrypoint?: string;
  hasWarm: boolean;
  lastError?: string;
  createdAt: string;
  updatedAt: string;
  readyAt?: string;
}

export interface CreateWasmModuleOptions {
  /** Optional explicit ID. Empty means the daemon uses the module digest. */
  id?: string;
  /** Module reference resolved on this host (file path, URL, etc.). */
  moduleRef: string;
  /** WASI entry export; defaults to `_start` on the daemon. */
  entrypoint?: string;
}

/**
 * Upload a compiled core-wasip1 `.wasm` to the registry. The daemon validates
 * and forwards it under YOUR registry credentials — it never stores the bytes.
 * The returned {@link PushWasmModuleResult.moduleRef} is what you pass as
 * `moduleRef` on a later `create`.
 */
export interface PushWasmModuleOptions {
  /** Target repository path, e.g. `tenant/my-app`. */
  name: string;
  /** Image tag; defaults to `latest`. */
  tag?: string;
  /** The compiled core-wasip1 module bytes. */
  module: Uint8Array;
  /** Registry login (your AOCR username). */
  registryUsername?: string;
  /** Registry token (your AOCR PAT). Required. */
  registryToken: string;
}

export interface PushWasmModuleResult {
  /** The `oci://` ref to pass as `moduleRef` on create. */
  moduleRef: string;
  /** sha256 content digest of the uploaded module. */
  digest: string;
  /** Uploaded size in bytes. */
  sizeBytes: number;
}
