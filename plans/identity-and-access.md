# Plan: Identity and access — named callers, roles, SSO, and the caller in every audit record

Status: **draft, 2026-10-16. Founder decisions folded in the same day** (§5.0 and §12): the login architecture is locked, and the other choices stand at the written recommendations. Not eng-reviewed. Next gates: `/plan-eng-review` → stacked implementation (§7).

Answers three Ideas proposals as one feature: [scoped tokens and roles #646](https://github.com/aerol-ai/microvm/discussions/646), [SSO #647](https://github.com/aerol-ai/microvm/discussions/647), [caller identity in audit #649](https://github.com/aerol-ai/microvm/discussions/649). Unblocks [per-team quotas #648](https://github.com/aerol-ai/microvm/discussions/648), which needs a team to count against.

## 0. TL;DR

The enterprise-readiness gap, in the buyer's words: *users have their own login (SSO), roles, and every action is tied to a named person.* Today all three are proposals. There is one shared API token per server, and audit records name the server, not the caller. This is the most likely blocker in a security review, so it is built first.

The plan builds it in four layers, each on the one before:

1. **A principal on every request.** One authentication function for every surface (v1, Daytona, E2B, Runloop, MCP, dashboard). It answers *who* (a principal with a kind, an id and a display name) and *what they may do* (a role, scoped to one team or the whole fleet). The operator token (PAT) and the managed control plane map onto it unchanged.
2. **Roles enforced at the route.** Four built-in roles: `viewer`, `runner`, `auditor` and `admin`. Every route declares the permission it needs, and a test fails the build if a route declares none. Team scoping reuses the existing owner scoping (`OwnerRef`), so a team is just an owner.
3. **Named credentials.** Scoped API tokens for services and CI (`avm_…`, hashed, expiring, revocable; SQLite on one node, Raft in a cluster). SSO for people through OIDC, the Kubernetes way: sandboxd checks the identity provider's signed token itself, so there is no session store. `aerolvm login --sso` and the dashboard both use it. CI can sign in with GitHub Actions or Kubernetes workload tokens, with no stored secret at all.
4. **The caller in the evidence.** Every audit record gets a hash-chained `caller` field. Create, delete, exec, file, port, snapshot and token calls now write chain records too (kind `api`). Today they write none. A forwarded request is attributed on the owner node, with the edge node recorded as `via`.

**Added in the CEO review (2026-10-16):**
- Named credentials can be **enforced**: `SB_PAT_SCOPE=host` confines the shared operator token to the host and cluster peers, so remote people must use SSO or a scoped token. Enterprise mode requires it (D4, D5).
- A Prometheus scrape needs no admin token (`metrics.read`, D6).
- `aerolvm access review` produces SOC 2 access-review evidence (D7).
- The CLI warns before a token expires (D8).
- A 403 names the role that would allow the call (D9).
- OAuth for remote MCP, so MCP connectors such as claude.ai sign in with the company's SSO. ChatGPT is claimed only after a live check passes (D10).
- Google dashboard sign-in uses Google Identity Services, with no secret on the server (D2).

What stays the same: with identity off (the default), a server behaves exactly as today, except that audit records gain `caller: operator` or `caller: system`. Single-node and local Docker mode need nothing new. The PAT stays as the break-glass and node-to-node credential.

## 1. The problem

| Buyer question | Answer today | Evidence |
|---|---|---|
| Can each person sign in with their company account? | No. The dashboard asks you to paste the PAT. The CLI saves the PAT. | `pkg/api/dashboard.html:266,300`; `cmd/aerolvm/login.go:231-323` |
| Can I give CI a token that can only create sandboxes? | No. The PAT is the only credential the open-source build accepts. Every other token is rejected. | `pkg/controlplane/controlplane.go:265-267`; `pkg/api/middleware.go:115-128` |
| Can I remove one person without rotating everyone? | No. And the PAT cannot be rotated without downtime: no second token, no reload. | `internal/config/config.go:129,1685,2064` |
| Who read this sandbox's secrets? Who ran this command? Who deleted it? | A server name. `actor` and `node_id` both hold the writing node's id. Exec, files, create, delete and snapshot calls write no chain record at all. | `internal/service/secret_audit.go:2257-2265`; §2 |

## 2. Where the code stands (verified 2026-10-16)

### 2.1 Authentication

- **Three near-identical wrappers.** `requireAuth`, `requireE2BAuth` and `requireRunloopAuth` do the same thing: PAT → `Access{Operator:true}`, else `validator.Validate` → owner-scoped `Access{Identity}` (`pkg/api/middleware.go:115-196`). An identity with an empty `OwnerRef` is refused, so a validator cannot fail open (`:188-193`).
- **Seam.** `controlplane.Identity{ExternalID, OwnerRef}` and `Access{Identity, Operator}` (`pkg/controlplane/controlplane.go:42-60`). The open-source `Noop()` validator rejects every token (`:265`). A managed build wires a real one (`pkg/daemon/daemon.go:86-98`).
- **Operator gate.** `withAuthOperator` → `apihttp.RequireOperator`, which checks `access.Operator` (`pkg/api/v1/operator_auth.go:18-24`, `pkg/api/apihttp/apihttp.go:128-136`). It guards reconcile, ingress DNS, audit verify, templates, all of `/cluster/*`, `/debug/vars` and `/v1/metrics`.
- **Every other route** only needs a valid token (`pkg/api/v1/routes.go`). The facades have no operator gating anywhere.
- **Fail-open default.** No `Access` in context means fleet-wide. This is deliberate for background loops (`internal/service/owner_scope.go:12-27`). The flip side: a route registered without `d.Auth` is unscoped. Nothing catches that today.
- **Surfaces with no API principal:** `/health` (public by design), ingress proxy (loopback; Caddy is the boundary, `pkg/api/ingressproxy/routes.go:7-8`), the SSH gateway (a per-sandbox Ed25519 key, `pkg/sshgateway/gateway.go:225-299`), and `/e2b/runtime` (the sandbox's toolbox token, and nothing at all when the caller set `secure:false`, `pkg/api/e2b/runtime_proxy.go:38-46`).
- **CLI and SDKs.** `aerolvm login` saves one URL and token in `~/.config/aerolvm/config.json`, mode 0600 (`cmd/aerolvm/login.go:46-115`). All five SDKs read `SB_PAT_TOKEN` and send `Authorization: Bearer`. WebSockets use the `sandbox.bearer, <token>` subprotocol (`pkg/api/middleware.go:76-93`).

### 2.2 Cluster

- **A forwarded request carries the caller's own token.** The owner node checks it again with the same `requireAuth`. The internal mTLS listener mounts the same handler (`internal/cluster/forward.go:95-113`; `pkg/daemon/daemon.go:954-956`). No header asserts identity. `X-Cluster-*` headers are accepted only from a live mTLS peer (`pkg/api/middleware.go:33-60`).
- **Node-to-node control calls send the shared PAT over mTLS.** So on a peer they look exactly like an operator (`internal/cluster/agent.go:1569-1571`, `client.go:43-50`). The one thing that tells a forwarded user request apart is `X-Cluster-Forwarded: 1`, set by the forward Director (`forward.go:84`).
- **Replicated state.** One `command` struct per op, applied by the Raft FSM, gob snapshot. Next free op code: 31. Only the server tier holds it, at most 7 nodes (`internal/cluster/topology.go:15-27`). Worker and ingress nodes read from the server tier over mTLS with a TTL cache (`internal/cluster/egress_profiles.go:243-275`) or a change feed (`agent_placement_feed.go:11-26`).
- **Dual-mode precedent.** Egress profiles live in SQLite on one node and in Raft in a cluster, behind one interface (`internal/service/egress_profiles.go:59-78`). New ops are gated on every server advertising the gossip `fv` version (`internal/cluster/fsm_egress_profiles.go:24-41`).
- **Operator file precedent.** `SB_EGRESS_OPERATOR_FILE`: strict YAML, last-good kept in an `atomic.Pointer`, mtime poll plus SIGHUP, a bad file at boot refuses creates, hash label on a metric (`internal/egress/operator/watch.go:13-115`; `pkg/daemon/egress_operator_wiring.go:17-68`).

### 2.3 Audit

- **One record type,** `auditlog.Event` (`pkg/auditlog/event.go:16-50`). No caller, principal, token or request field.
- **Hash** = SHA-256(`prev || 0x00 || json.Marshal(ev)`), covering every field in struct order (`pkg/auditlog/hash.go:14-27`). A new **appended, `omitempty`** field keeps old records verifying. `OwnerRef` was added this way (`event.go:36-39`). But a binary that predates the field drops it on decode and computes a different hash. So **rolling back below the version that writes it fails strict boot verification** (§5.8).
- **Chain records today:** `secret_open` (env, mounts, registry, cluster secrets), `egress`, `gap`, `retention_checkpoint`, `retention_redacted`. Create, delete, stop and templates write plain `slog` lines that start with "audit ". Exec, files, expose port and snapshot write nothing (`internal/service/service.go:2306,3413`, and others).
- **Correlation.** `X-Correlation-ID` or `X-Request-ID` reaches the record only on `include_env` paths (`pkg/api/v1/audit_handler.go:108`). The list fan-out drops it (`pkg/api/clusterlist/list.go:591-606`). The sink is `Emit(SecretAuditEvent)` with no `ctx`, so no emitter can see `Access`.
- **Per-node log,** witnessed (S3 Object Lock) and exported (file, webhook, S3) as raw JSONL bytes, so new fields ship with no exporter change (`pkg/auditexport/backend.go:21-32`). `aerolvm audit verify` walks exported batches (`cmd/aerolvm/audit.go`, `pkg/auditlog/verify.go:139`).
- **Read API:** per sandbox only, `GET /v1/sandboxes/{id}/audit` (`pkg/api/v1/routes.go:98`). There is no fleet-wide or by-caller query.

### 2.4 Holes found while surveying

These are fixed inside the plan, because roles would otherwise inherit them:

| # | Hole | Where | Fix |
|---|---|---|---|
| H1 | The WASM module catalogue has no owner model. Any authenticated non-PAT token can list, read and delete every module. The catalogue id defaults to the module's content digest (`internal/service/wasm_module_api.go:127-175`), so two tenants who upload the same module share one row. | list, get and delete `internal/service/wasm_module_api.go:215-285`; routes `pkg/api/v1/routes.go:125-129` | T0: ownership tracked per tenant, like `jsbundle`'s `TenantOwns` (`pkg/jsbundle`), not one `owner_ref` column. A single column would hand a shared digest row to whoever wrote it first. Owner `""` (operator-published) stays readable by everyone and writable only by admin. **Fixed in main by #724** (merged 2026-10-17): `wasm_modules.owner_ref`; list, get, delete and create-time use are scoped; `/v1/capacity` redacts module ids for non-operators. |
| H2 | The PAT cannot be rotated, and operator volumes live under `op-<hash(PAT)>`, so a rotation would also move them. | `pkg/volumes/volumes.go:116-131` | T10: accept a previous PAT, and pin the operator volume scope. |
| H3 | The list fan-out drops `X-Correlation-ID`, so peers record fresh random ids. | `pkg/api/clusterlist/list.go:591-606` | T4: forward it. |
| H4 | A route registered without `d.Auth` is fleet-wide, and nothing catches it. | `internal/service/owner_scope.go:21-27` | T2: a registry test that requires a permission on every route. |
| H5 | The three auth wrappers repeat the same logic. | `pkg/api/middleware.go:115-168` | T1: one `authenticate`. |

Noted, not in this plan: toolboxd and the WASM toolhost compare the toolbox token with `!=`, not in constant time (`cmd/toolboxd/main.go:573`, `internal/runtime/wasm/toolhost/host.go:133`). This is a separate small fix.

## 3. Goals and non-goals

**Goals**

- G1. Every authenticated request carries a **named principal**: who, by which credential, and through which node.
- G2. **Least privilege:** a credential can be limited to reading, or to one team's sandboxes, and cannot reach fleet operations unless it is an admin.
- G3. **People sign in with their company identity** (Okta, Entra ID, Google, Keycloak, any OIDC provider) in the CLI and the dashboard. Removing them at the identity provider removes their access.
- G4. **Services and CI get their own revocable, expiring tokens**, or no stored token at all (workload identity).
- G5. **Every mutating action and every secret read is in the hash chain with its caller.** Auditors can answer "who did X to sandbox Y" and "what did person Z do".
- G6. **Zero behavior change when identity is off.** PAT-only servers, single-node and local Docker work exactly as before. The managed build's validator keeps working unchanged.
- G7. Holds at 2,000 nodes × 100,000 sandboxes × ~100 ingress nodes, with no per-request call to the server tier.

**Non-goals (v1)**

- Custom roles or per-resource ACLs. Four fixed roles; see §12 I1.
- SAML and SCIM. Every target identity provider speaks OIDC. SAML-only shops bridge through Keycloak or Dex. Deprovisioning works through the identity provider plus short token lifetimes (§5.5).
- A sandboxd-run login or session service. sandboxd checks tokens; it does not issue them for people.
- Per-team quotas (#648). Teams exist after this plan; quotas are their own plan.

## 4. Threat model

| Actor | Must be stopped | How |
|---|---|---|
| Former employee with a saved CLI login | Any access after removal at the identity provider | ID tokens last about 1 h and refresh fails at the provider. For an immediate block, an emergency deny list in the identity file applies on each node within one poll of the updated file reaching it (§5.5). |
| Leaked CI token | Fleet-wide damage | Token scoped to one team and role, with an expiry. Revocation reaches every node in ≤ 15 s (§5.4). A greppable `avm_` prefix for secret scanners. |
| Team A member | Reading or touching team B's sandboxes | Owner scoping returns 404, as today (`owner_scope.go:29-41`). |
| Auditor | Changing anything, or reading secrets | `auditor` role: fleet-wide reads and audit access, no write, exec or env read. |
| Token-spray attacker | DoS on the server tier or the IdP | API tokens are checked against a local in-memory mirror (no remote call). Malformed tokens fail the checksum before any lookup. An unknown JWT `kid` triggers at most one JWKS fetch per issuer per minute. |
| Forged identity headers | Asserting another caller | No identity header is trusted. The owner node re-checks the original credential, as today. `via` comes only from the mTLS peer id. |
| JWT tricks | `alg: none`, HMAC confusion, wrong audience, very long lifetime | Allow only RS256, ES256 and EdDSA. Exact `iss`; `aud` must match. `exp` and `nbf` with 60 s leeway. A max token lifetime cap. |

**Out of scope:** a compromised node. It holds the PAT and can already act as anyone; the witness bounds what it can rewrite (`plans/open-audit-witness.md`). Also out of scope: a compromised identity provider.

## 5. Design

### 5.0 Locked by the founder (2026-10-16): the login architecture

These are founder decisions. Eng review checks how they are built, not whether. A design change that breaks one of them goes back to the founder.

AerolVM does not run a login service and does not issue sessions for people. The company's identity provider logs the person in. sandboxd is a **resource server**, the same model as the Kubernetes API server with `--oidc-issuer-url`.

| # | Constraint | Where the plan meets it |
|---|---|---|
| L1 | Check the identity provider's signed token directly (I3). Each node verifies the signature locally from the provider's published keys. No session store, no server-side session, no client secret on the server for the CLI. | §5.5, §5.6 |
| L2 | A request is checked on the ingress node that received it, and again on the sandbox's owner node. No identity header is trusted. Any node can do this check without a per-request call to a login service or to the server tier. | §5.2, §5.4 (local mirror), §5.5 (offline JWT check), §5.8 (`via` comes from the mTLS peer, not a header) |
| L3 | People use `aerolvm login --sso` and the dashboard against that provider: Okta, Entra ID, Google, Keycloak, any OIDC issuer. | §5.6, §5.7 |
| L4 | CI uses GitHub Actions or Kubernetes workload tokens, checked the same way (offline, from published keys), with no secret stored on AerolVM. | §5.5 |
| L5 | Service tokens (`avm_…`) stay as written: admin-minted through the API, stored hashed, mirrored from the server tier, revocable in about 15 seconds. | §5.4 |
| L6 | Group-to-role bindings live in the identity config file. The API is only for service tokens (I4). | §5.5 |
| L7 | Enterprise mode requires identity on, not SSO. Tokens-only must keep working for air-gapped buyers (I7). | §5.12 |
| L8 | Identity off stays the default. The operator token and the managed control-plane login keep their current behavior. | §5.1 invariants, §5.2 |

**Ruled out:** a sandboxd-issued session; a shared login store; any design in which a node calls one login service per request. The per-node in-memory caches in this plan (verified-JWT LRU, service-token mirror) are local to each node and are not shared. A JWKS fetch happens hourly, or at most once a minute on an unknown key id. It is never per request.

### 5.1 The principal

`controlplane.Access` grows from "operator or one owner" to "who, what, where":

```go
// pkg/controlplane
type PrincipalKind string // "operator" | "token" | "oidc" | "controlplane" | "node" | "system" | "sandbox_key"

type Principal struct {
    Kind PrincipalKind
    ID   string // stable: "operator", "tok_7Hq2…", "oidc:okta:00u1ab…", "node:n3", "system:lifecycle"
    Name string // for people and logs: "ci-deploy", "ana@acme.com"; informational only
}

type Access struct {
    Identity  Identity  // unchanged: OwnerRef is the team the request is scoped to
    Fleet     bool      // renamed from Operator: unscoped reads/writes across owners
    Role      Role      // viewer | runner | auditor | admin
    Principal Principal
    Via       string    // edge node id when the request arrived forwarded over mTLS
}

type Identity struct {
    ExternalID string
    OwnerRef   string
    Role       Role   // NEW, optional: a managed provider may set viewer or runner only, never a fleet role; "" means runner (Section 1, finding 1.4)
    Name       string // NEW, optional
}
```

`Operator` is renamed to `Fleet` because the `auditor` role needs fleet-wide visibility without operator power. Today that one bit means both. There are about a dozen call sites, all listed in §2.1 (`owner_scope.go:22`, `apihttp.go:130`, `cluster_handler.go:1105`, …). The rename is mechanical, and every operator-only gate moves to a permission check (§5.3).

**Invariants. A test pins each one:**

| Credential | Access | Today's equivalent |
|---|---|---|
| PAT on the public listener | `{Fleet, admin, operator}` | `Access{Operator:true}` |
| PAT plus mTLS peer plus `X-Cluster-Forwarded` | `{Fleet, admin, operator, Via: peer}` | same |
| PAT plus mTLS peer, not forwarded | `{Fleet, admin, node:<peer>}` | same powers; now named `node:` in audit |
| Managed provider token | `{OwnerRef, Identity.Role or runner, controlplane:<ExternalID>}` | `Access{Identity}`: same verbs (§5.3 runner = today's owner-scoped set) |
| No `Access` (background) | unscoped; caller in audit = `system:<subsystem>` | unchanged |

**Scope is not power (eng review D3).** `Fleet` (unscoped) answers only *which owners a caller sees*. It no longer implies operator powers.
- Operator-only capabilities ask a separate, explicit predicate, `hostCapable(ctx)`. It is true for the PAT/operator, `node:` principals, internal calls with no `Access`, and the `admin` role. It is false for `viewer`, `runner` (team or `*`), `auditor` and managed identities.
- The capabilities: raw host-side mounts, `file://` bundle refs, and custom domains without the DNS proof. Four existing gates move from `!scoped` to `hostCapable`: `service.go:1611`, `isolate.go:94`, `custom_domains.go:469`, `dns_verify.go:37-39`.
- `facade_state.go:159` (`requireVisibleSnapshot`) is a visibility check, so it keeps following `Fleet` (eng review D7). A fleet runner may alias and see any team's snapshots, consistent with its cross-team writes.
- A call-site test lists every `ownerScope` use and fails on an unreviewed new `!scoped` capability check.

Teams are owners. A token or OIDC binding for team `payments` gets `OwnerRef = "team:payments"`. The `team:` prefix keeps open-source teams out of the managed build's account namespace. Fleet-scoped principals create sandboxes with owner `""`, exactly as the PAT does today.

### 5.2 One authentication function

```
authenticate(r) (Access, error)
  1. token := bearer or WS subprotocol (Daytona/Runloop) | bearer or X-API-KEY (E2B)
  2. PAT (or previous PAT, §5.11)?  → operator / node principal (table above)
  3. "avm_" prefix?                 → token mirror lookup (§5.4)         [identity on]
  4. three base64url segments?      → OIDC verifier (§5.5)               [identity on]
  5. otherwise                      → provider Validator (managed build; Noop rejects)
```

**Code shape (eng review D6).** One entry point tries an ordered list of authenticators: `pat`, `apiToken`, `jwt`, `provider`. Each implements `Authenticate(r, bearer) (controlplane.Access, matched bool, err error)`, and the first `matched` wins. Then three separate steps run, in order: the surface rule (`mcp_audiences` only on `/mcp` or a marked forward), team selection (`X-AerolVM-Team`), and 401/403 reason mapping (D9, D17). Adding a credential kind means appending one authenticator.

**Where it runs (L2).** `authenticate` runs on the ingress node that received the request. It runs again on the owner node when the request is forwarded, because the internal listener mounts the same handler (§2.2) and the original credential travels with the request. Both checks are local: a constant-time compare (PAT), an in-memory mirror lookup (`avm_`), or an offline signature check (JWT). No identity header is read. Four markers matter, and all are accepted only from a live mTLS peer: `X-Cluster-Forwarded`, the mTLS peer id, `X-Cluster-PAT-Origin` (§5.11) and `X-Cluster-Surface` (§5.14). They decide three things: whether a PAT caller is shown as `operator` or `node:`, whether a forwarded PAT is allowed under `host` scope, and whether `mcp_audiences` is accepted. None of them supplies an identity, and none grants anything the credential doesn't already carry. Every forward path sets them through one helper, `cluster.StampForward(req, access)` (Section 1, finding 1.2). On fan-out clients that build fresh requests (`clusterlist/list.go:591-606`, `clusterlist/facade_list.go`, the build and template fan-outs), the same helper also copies `X-AerolVM-Team` (D13) and `X-Correlation-ID` (H3). Today those clients copy only `Authorization` and `X-API-KEY`, so a multi-team caller's list would be answered for different teams on different peers (eng review E6).

**Why a 401 failed (CEO review D17).** For `avm_` and JWT failures, the 401 carries RFC 6750 `WWW-Authenticate: Bearer error="invalid_token", error_description="<reason>"`, and the JSON body carries the same `reason`.
- The reasons: `expired`, `not_yet_valid` (clock skew), `unknown_issuer`, `wrong_audience`, `too_long_lived`, `invalid_signature`, `malformed`, and `unknown_or_revoked`. An `avm_` token can't tell those last two apart.
- Never disclosed: claim values, key ids, which check inside a signature failed, or whether an `avm_` id exists.
- PAT, managed and unclassified bearer failures keep today's 401 byte for byte (L8).
- `aerolvm_auth_failures_total{kind,reason}` counts each reason, and a debug log names the issuer.

The three `require*Auth` wrappers become one function plus three error writers (H5). Token extraction moves to one shared `apihttp.BearerToken(r)`, used by `authenticate` and by remote MCP's `serverFor` (eng review D5). It matches the scheme case-insensitively (RFC 7235), trims, then reads the `sandbox.bearer, <token>` subprotocol. So the token that authenticated is always the token the MCP tools use. Steps 3 and 4 run only with `SB_IDENTITY_ENABLED=true`. **The daemon refuses to boot** if identity is on and the provider supplies a non-noop `Validator`. Two identity sources would have to share one owner namespace, and the managed build already has its own login. This mirrors how a provider-supplied witness wins (`plans/open-audit-witness.md`, "Where it plugs in").

**The test-only static validator is retired (eng review D4).** `SB_ITEST_IDENTITY_FILE` (b4e152b1, `pkg/daemon/daemon.go:100-114`) maps plaintext tokens to owners in every release binary.
- **Until T3 lands,** T1 adds two guards: identity on plus that env var → boot error, and enterprise mode refuses the env var.
- **T3 then deletes** the env path, `pkg/daemon/itest_identity.go` and its test.
- The harness mints real `avm_` tokens with the PAT at scenario setup, and uses the T12 test issuer for OIDC.

`GET /v1/whoami` returns the resolved principal, role, team and token expiry. The CLI, the dashboard and support tickets all use it.

### 5.3 Roles and permissions

**Permissions:**

| Permission | Covers |
|---|---|
| `sandbox.read` | get and list sandboxes (no env), mounts list, network usage, custom domains (list and DNS), snapshots (get and list), egress profiles (get and list), WASM modules and JS bundles (get and list), capacity |
| `sandbox.secrets` | `include_env` reads (the existing `secret_open` path) |
| `sandbox.write` | create, start, stop, delete, resize, pause and resume, lifecycle, ports, custom domains, network limits and policy, snapshot create, register and delete, image build, egress profile put and delete, JS bundle and WASM module create and delete |
| `sandbox.exec` | the whole toolbox proxy: exec, files, sessions, terminals, `/e2b` envd routes reached through the API |
| `audit.read` | `GET /v1/sandboxes/{id}/audit` |
| `audit.verify` | `POST /v1/audit/verify` |
| `token.read` / `token.write` | list tokens / create and revoke tokens |
| `metrics.read` | `GET /v1/metrics` (CEO review D6). Held only by roles bound to `*`, because the counters describe the whole fleet (`pkg/api/dashboard.go:20-25`). |
| `fleet.admin` | templates, `/cluster/*`, admin reconcile, ingress DNS, `/debug/vars` |
| `cluster.internal` | `/cluster/internal/*`: only the `node:` principal, never a role |

**Roles** (team = the bound team only; fleet = every owner):

| | `viewer` | `runner` | `auditor` | `admin` |
|---|---|---|---|---|
| `sandbox.read` | team | team | fleet | fleet |
| `sandbox.secrets` | — | team | — | fleet |
| `sandbox.write` | — | team | — | fleet |
| `sandbox.exec` | — | team | — | fleet |
| `audit.read` | team | team | fleet | fleet |
| `audit.verify`, `token.read` | — | — | fleet | fleet |
| `token.write`, `fleet.admin` | — | — | — | fleet |
| `metrics.read` | fleet, only when bound to `*` | fleet, only when bound to `*` | fleet | fleet |

- `runner` is exactly today's owner-scoped set. That is what keeps the managed build unchanged.
- `auditor` and `admin` must be bound fleet-wide. `viewer` and `runner` may be bound to a team or to `*`. A `runner` on `*` creates and runs sandboxes for every team, but never gets operator-only capabilities: those require `hostCapable` (admin or operator), per eng review D3.
- One team per principal (§12 I2). A person in several teams picks one at login (`--team`). The choice travels on each request as the header `X-AerolVM-Team: <name>` (CEO review D13), because a provider token can't carry it and there is no session.
  - The header **selects among the bindings the verified token already matches**. It never grants: a team not among them gets 403 with the D9 hint, and without the header the first matching binding wins.
  - It is an ordinary header, so a forward keeps it and the owner node re-applies the same selection offline (L2).
  - The CLI saves the team per login, and the five SDKs read `SB_TEAM` or a client option (T9). The dashboard sends no team header (design review DR2): only fleet-bound admins use it (DR1), so they have no team to pick.
  - `caller` in audit records also names the selected team. This keeps `ownerScope` single-valued, so no store query or fan-out changes shape.
- **Status codes:** another team's sandbox → **404**, as today (no probing). Your own team's sandbox but a missing verb → **403**, naming the permission. For `token` and `oidc` principals only, it also names the caller's own role and team, and the role that would allow it (CEO review D9): "role viewer on team payments cannot sandbox.exec; ask an admin for role runner on team payments". v1 adds `required_permission` and `role` fields to the 403 body. The facades keep their own body shape and carry the hint in the message. A 404 never carries a hint. PAT and managed (`controlplane`) callers get exactly today's body, for example `operator authorization required` (`pkg/api/apihttp/apihttp.go:131`); a test pins it (L8). A fleet route without `fleet.admin` → 403, as `RequireOperator` already does.
- **v1 soft-freeze:** PAT and managed callers see no new status codes. 403 is new only for principals that did not exist before. This is called out in the T2 PR.

**Enforcement.** Each route is registered through `d.Route(perm, handler)`, which authenticates, then authorizes, then audits (§5.9). This replaces `d.Auth(...)` and `withAuthOperator(...)`. A registry test registers every v1 and facade route (v1, Daytona, E2B, Runloop, MCP, dashboard) into a recording mux. It fails if any handler is not permission-tagged, except an explicit public allowlist (`/health`, `/ui`, `/.well-known/aerolvm-auth`, `/.well-known/oauth-protected-resource*`, the e2b runtime proxy). This closes H4 for good. Two routes need only a valid principal (pseudo-permission `authenticated`): `/v1/whoami`, and `/mcp` itself. Each MCP tool's inner API call is then authorized by that route's own permission (§5.14).

The toolbox proxy needs one permission per route, not per sub-path. Everything under it is `sandbox.exec`. A viewer cannot read files, since files can hold secrets.

### 5.4 API tokens

**Format:** `avm_<id:12>_<secret:43>_<crc:6>`, base62 and base64url. The id is the lookup key and the audit `caller.id`. The secret is 256 random bits. The checksum lets a malformed token be refused with no lookup, and lets secret scanners validate offline (the GitHub pattern). Plaintext is returned once at create and never stored, logged or put in Raft. Only `SHA-256(secret)` is stored, compared in constant time. A slow hash is pointless for 256-bit random secrets.

**Record** (about 200 B): `id, name, role, owner_ref, created_by (principal id), created_at, expires_at`.

**Storage, behind one interface (the egress-profile pattern):**

- *Single node:* SQLite table `api_tokens` (`/add-store-column`), with an in-memory map loaded at boot and updated on every write. One process, so no cache staleness.
- *Cluster:* FSM ops `opPutAPIToken` (31) and `opDeleteAPIToken` (32), an `apiTokens` map in the FSM, the snapshot payload, and `Restore` (nil means empty, so old snapshots load). Writes are gated on `fv` like egress profiles, so a half-upgraded cluster answers `ErrClusterVersion` rather than splitting.
- *Every non-Raft node keeps a full mirror.* It polls `GET /v1/cluster/internal/tokens?since=<version>` on a live server every 5 s with jitter. An unchanged version is an in-memory compare that answers 304. A changed version returns the delta from a bounded change ring, or a full page walk when the cursor is too old. The ring keeps the last 10 minutes of mutations, at least 1,024 and at most 65,536 (about 13 MB on a server), so a burst of token creates doesn't push every mirror into a resnapshot. Resnapshots are jittered over 30 s, so 2,000 nodes never page-walk at once (Section 7, finding 7.3). Deletes ride the ring as versioned tombstones, and a merge keeps the higher version, so a page walk racing a revoke can never resurrect the token (Section 4, finding 4.4; the placement-feed rule). This is the placement-feed pattern, simplified to polling.
  - Why a full mirror and not a per-token cache: a cache miss would turn every random token in a spray into a server-tier call. With a mirror, an unknown id is a local map miss.
- **Revocation latency:** immediate on server nodes; ≤ 5 s plus one request on others (target ≤ 15 s, UC-271).
- **Staleness:** if a mirror cannot sync for `SB_IDENTITY_MAX_STALE` (60 s), that node refuses API tokens with 503. The PAT and OIDC still work, because neither needs replicated state. A server tier that is down for 60 s already blocks creates, since placement needs Raft, so this adds no new outage class.
  - **One exception (CEO review D16):** a request whose route needs only `metrics.read` is still accepted from a stale mirror, so worker metrics keep flowing during a server-tier outage. Every other permission fails closed as above. Each stale accept is counted in `aerolvm_identity_stale_accept_total` and logged at most once a minute. The cost: a scrape token revoked during the outage keeps reading counters on workers until the mirror syncs.

**Lifecycle:**

- **Create:** `POST /v1/tokens {name, role, team, expires_in}`, `token.write`. `team` is a team name, or `*` for fleet scope. `auditor` and `admin` require `*`.
  - Validation (Section 3, finding 3.6): team names `[a-z0-9-]{1,63}`; token names `[A-Za-z0-9._-]{1,64}`; a bad `X-AerolVM-Team` → 400.
  - Claim-derived display names are truncated to 256 characters, with control characters stripped, before they reach a record, a hint or a report.
  - Names are unique per team. A concurrent duplicate gets 409, and two live tokens never share a name.
  - If the response is lost, the caller cannot recover the secret. They revoke and recreate, as with GitHub PATs.
  - The secret is generated on the receiving node, and only the hash is proposed. The plaintext is returned after the apply succeeds.
- **List:** `GET /v1/tokens`, `token.read`; never returns a hash. Expired tokens stay listed, with `expired: true`, until the GC sweep removes them 30 d after expiry. **Revoke:** `DELETE /v1/tokens/{id}` → 204, also when it is already gone (idempotent). Revoke deletes the row at once. The evidence is the `api` record of that `DELETE` call (§5.9), which names who revoked it.
- **Expiry is required.** The default max is 365 d (`SB_TOKEN_MAX_TTL`); enterprise mode caps it at 90 d (§12 I10). Expired tokens are refused at check time. The leader's daily sweep deletes rows 30 d after expiry, so the access-review list still shows recent ones.
- No last-used timestamp. Writing one per request would be a Raft write per request. Access reviews query the audit chain by caller instead (§5.10).

**CLI:** `aerolvm token create|list|revoke`. **Self-service:** admin only in v1 (§12 I8).

### 5.5 SSO with OIDC

**Model: sandboxd is a resource server, like the Kubernetes API server with `--oidc-issuer-url`** (§12 I3). The CLI and dashboard get an ID token from the identity provider and send it as the bearer. Every node verifies it offline:

- the signature against the issuer's JWKS;
- `iss`, `aud`, `exp` and `nbf`;
- the max lifetime;
- `email_verified` when the binding matches on email.

The node then maps claims to a team and role through bindings. There is no session store, no server-side refresh, and no client secret on the server for the CLI. Enterprise buyers already know this pattern from `kubectl`.

**The identity file** (`SB_IDENTITY_FILE`) uses the egress operator file machinery: strict YAML, last-good pointer, mtime poll plus SIGHUP, a hash metric for drift between nodes. Bindings live in a file, not in Raft, so they are reviewable and GitOps-friendly (§12 I4):

```yaml
version: 1
issuers:
  - name: okta                         # stable; part of the principal id
    display_name: Acme Okta            # dashboard button label (design review DR3)
    url: https://acme.okta.com/oauth2/default
    audiences: [0oa1cli, 0oa1dash]     # client ids of the CLI and dashboard apps
    clients: { cli: 0oa1cli, dashboard: 0oa1dash }   # published in discovery
    claims: { username: email, groups: groups }
    max_token_lifetime: 12h
    mcp: true                          # listed in RFC 9728 metadata (§5.14)
    mcp_audiences: [api://aerolvm-mcp] # access-token audiences accepted only on /mcp
  - name: google
    display_name: Google
    kind: google                       # dashboard uses Google Identity Services (§5.7)
    url: https://accounts.google.com
    audiences: [123-cli.apps.googleusercontent.com, 123-dash.apps.googleusercontent.com]
    clients: { cli: 123-cli.apps.googleusercontent.com, dashboard: 123-dash.apps.googleusercontent.com }
    claims: { username: email }
  - name: github-actions               # workload identity: CI with no stored token
    url: https://token.actions.githubusercontent.com
    audiences: [aerolvm]
    claims: { username: sub }
  - name: eks-prod                     # workload identity: Kubernetes service-account tokens
    url: https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE   # the cluster's --service-account-issuer
    audiences: [aerolvm]               # projected token with audience "aerolvm"
    claims: { username: sub }          # "system:serviceaccount:<ns>:<sa>"
bindings:                              # first match wins, top to bottom
  - { issuer: okta, group: platform-admins, role: admin }
  - { issuer: okta, group: secops,          role: auditor }
  - { issuer: okta, group: payments-eng,    role: runner, team: payments }
  - { issuer: github-actions, claim: { repository: acme/payments, ref: refs/heads/main }, role: runner, team: payments }
  - { issuer: eks-prod, claim: { sub: "system:serviceaccount:payments:ci" }, role: runner, team: payments }
deny_subjects: []                      # emergency block, "<issuer>:<sub>", applied on reload
mcp:
  resource: https://api.acme.dev/mcp   # one resource URL, as RFC 9728 requires (§5.14)
```

**Schema** (strict: unknown fields fail the load; an empty file is invalid, so unset `SB_IDENTITY_FILE` for tokens-only mode, per Section 4, finding 4.3):

| Field | Type | Meaning |
|---|---|---|
| `version` | int, required | `1` |
| `issuers[].name` | string, required, `[a-z0-9-]` | Stable; part of every principal id |
| `issuers[].display_name` | string, optional, 1–40 characters, control characters stripped | The dashboard button label, "Sign in with <display_name>"; falls back to `name`. Published in `/.well-known/aerolvm-auth`. Never used in principal ids or audit records (design review DR3). |
| `issuers[].kind` | `oidc` (default) or `google` | `google` switches the dashboard to Google Identity Services (§5.7) |
| `issuers[].url` | URL, required | Must equal the token's `iss` |
| `issuers[].jwks_file` | path, optional | A static JWKS instead of discovery, for issuers the nodes cannot reach |
| `issuers[].audiences` | list, required | ID-token and workload-token audiences (client ids, `aerolvm`) |
| `issuers[].mcp_audiences` | list, optional | Access-token audiences accepted **only** on `/mcp`. Must not overlap `audiences`; the load fails if they do (§5.14). |
| `issuers[].clients.cli`, `.dashboard` | string, optional | Published in `/.well-known/aerolvm-auth` |
| `issuers[].claims.username` / `.groups` / `.roles` | claim names | `roles` is for Entra app roles (see overage below) |
| `issuers[].max_token_lifetime` | duration, default `24h` | Tokens whose `exp − iat` exceeds it are refused. The default fits provider ID tokens (about 1 h), GitHub Actions tokens (minutes) and projected service-account tokens (1 h by default), and refuses long-lived workload tokens unless an operator raises it per issuer (Section 9, finding 9.1). |
| `issuers[].mcp` | bool | Listed in RFC 9728 `authorization_servers` |
| `bindings[]` | `{issuer, group \| app_role \| claim: {…}, role, team}` | First match wins. `group` matches the `groups` claim, `app_role` matches the `roles` claim, and `role` is the AerolVM role granted. `team` is a name or `*`. List fleet bindings (`admin`, `auditor`) above team bindings. A person matched by both resolves to the first one, and the dashboard sends no team header to pick another (design review DR2). |
| `deny_subjects[]` | `"<issuer>:<sub>"` | Refused on every request after reload |
| `mcp.resource` | URL | The single protected-resource URL for `/mcp` |

**Binding changes are evidence (CEO review D20).** On every effective reload, and at boot when the file's hash differs from the last recorded one, each node writes one chain record:
- kind `identity_config`, caller `system:identity-file`;
- the old and new hash;
- a binding diff: added and removed `issuer + match → role/team` lines, and deny-list changes.

The file can't say who edited it. The record points at the hash, and the operator's config history (git, Ansible) names the author; the docs say so. In a cluster, each node records its own reload, one per node per change. Changes are rare.

**Entra group overage.** Above 200 groups, Entra leaves out the `groups` claim and sends an overage pointer (`_claim_names`). L2 rules out a per-request Microsoft Graph call, so the verifier does not try one. It refuses with an explicit hint: "group overage: bind on Entra app roles". Bindings can match the `roles` claim instead, which Entra always sends: `{issuer: entra, app_role: AerolVM.Runner, role: runner, team: payments}`.

**Workload tokens (L4)** are just more issuers, checked offline like any other.

- **GitHub Actions** mints a token with `core.getIDToken('aerolvm')`.
- **Kubernetes** projects a service-account token with `audience: aerolvm`. The node checks it against the cluster's service-account issuer discovery, which EKS, GKE and AKS publish. There is **no TokenReview call.** TokenReview is a per-request call to the Kubernetes API server, which L2 rules out.
  - This supersedes the "ServiceAccount auth via the TokenReview API" row for API auth in `plans/kubernetes-deployment.md` §5.5.
  - The node-certificate bootstrap in that plan (§5.3) is separate and unchanged.
  - A cluster whose issuer is not reachable from the AerolVM nodes can publish its JWKS as a static file (`jwks_file:` in place of discovery).

- **Principal:** `oidc:<issuer>:<sub>`. `sub` is stable and the email is only the display `Name`, so renaming an email does not split one person's audit history.
- **No binding matched:** 403 with "no role binding for ana@acme.com", and an `api` audit record with `result: denied` (Section 2, finding 2.3). The message also names the issuer and the groups the token carried (D9). These are the caller's own claims, so the person can tell IT what is missing. The v1 body also carries them as fields for the dashboard (design review DR8): `reason` (`no_binding` or `group_overage`), `issuer`, `name` and `groups[]`. The facades keep their body shape.
- **JWKS:** fetched at daemon start with the lazy-bootstrap latch (`atomic.Bool` plus mutex single-flight, CLAUDE.md rule 3), then hourly.
  - On an unknown `kid`, at most one refetch per issuer per minute, single-flight. The request waits up to 2 s for it.
  - If the provider is unreachable at boot, OIDC tokens get 503 until the first fetch succeeds. API tokens and the PAT are unaffected.
- **Size caps (Section 5, finding 5.5):** 16 KB per JWT, 1 MiB for the identity file, 1 MiB for a discovery or JWKS document. Over the cap → refused, with a metric.
- **Verified-token cache:** an LRU keyed by `SHA-256(jwt)`, held until `exp`, bounded at 10k entries **and** 16 MB (Section 7, finding 7.4). It saves the ~50 µs RS256 verify on repeat calls.
- **Key rules (Section 3, finding 3.5):**
  - Keys come only from the issuer's discovery or its `jwks_file`. The JWT headers `jku`, `x5u` and an embedded `jwk` are ignored.
  - Allowed algorithms = the issuer's advertised set ∩ {RS256, ES256, EdDSA}.
  - Issuer URLs must be `https`, verified against the system trust store. A private-cloud issuer with an internal CA uses that store like every other TLS client on the host. Tests inject an `*http.Client` instead (Section 5, finding 5.4).
- **Library:** `github.com/coreos/go-oidc/v3` (verifier and discovery; pulls `go-jose/v4`) on the server; `golang.org/x/oauth2` (already indirect) in the CLI for PKCE and the device flow. Both are new direct dependencies, called out in the PR, pinned to current releases (go-jose has shipped parsing denial-of-service fixes before) and checked with govulncheck (Section 3, finding 3.8).
- **Deprovisioning without SCIM:** remove the person at the provider. Their refresh fails and their last ID token dies within its lifetime (about 1 h; capped by `max_token_lifetime`). For "now", add their `sub` to `deny_subjects`. The identity file is per node, like the egress operator file, so push it with the same Terraform or Ansible step. Each node applies it within one poll (10 s) of the file arriving, or at once on SIGHUP.

### 5.6 CLI

- **`aerolvm login <url>`** first reads the unauthenticated `GET /.well-known/aerolvm-auth`, which lists issuers and their CLI client ids.
  - If SSO is offered, it runs the authorization-code flow with PKCE and a loopback redirect (RFC 8252). `--device` uses the device flow (RFC 8628) for SSH sessions.
  - It saves the ID token and refresh token in the existing config file, mode 0600. `--token-stdin` keeps working for PATs and `avm_` tokens.
- **Refresh:** every command refreshes the ID token when less than 60 s is left. Precedence is unchanged: `SB_PAT_TOKEN` wins, and a saved credential is sent only to its own URL (`login.go:121-152`).
- **Wording (design review DR15).** The DR15 table in the design review is the contract for every message these commands print: the issuer choice by display name, the browser and device prompts, success, no binding, refresh failure, the expiry warning and the `whoami` layout. Notes go to stderr in the existing `aerolvm:` style, and `--json` output is unchanged.
- **`aerolvm auth token`** prints a fresh bearer for scripts and SDKs (`SB_PAT_TOKEN=$(aerolvm auth token)`), like `gcloud auth print-access-token`. **`aerolvm whoami`** prints the principal, role, team and expiry.
- **Expiry warnings** (CEO review D8):
  - When the saved `avm_` token has less than 7 days left, the CLI prints one warning line on stderr. The expiry is cached from `whoami` at login and refreshed at most daily.
  - **Tokens from the environment** (`SB_PAT_TOKEN` or `SB_API_TOKEN` holding an `avm_` token, the CI case): the CLI checks `whoami` at most once a day per token id, cached under `$XDG_CACHE_HOME/aerolvm`. A fresh CI runner checks once per run (CEO review D15).
  - When an SSO refresh fails, the CLI says "aerolvm: your sign-in to <url> expired and couldn't be renewed. Sign in again: aerolvm login --sso <url>" (design review DR15).
  - Tokens no CLI uses, such as the scrape token, are covered by `aerolvm access review` ("expiring within 30 d") and by the runbook's rotation step: mint a replacement, swap it, revoke the old one (T10). No server metric is added (D8 is CLI-only).
  - Never in stdout, `--json` or MCP output. No server header is added (v1 soft-freeze).
- **`aerolvm mcp`** (local) uses the CLI connection, so MCP clients inherit SSO for free.
- **The CLI is a public client** (L1): PKCE, no secret.
  - Google's "Desktop app" client type still expects its `client_secret` value at the token endpoint. Google documents that value as not confidential for installed apps.
  - To keep L1 literal, the value never reaches the server: not in the identity file, not in discovery.
    - The CLI takes it once, with `aerolvm login --sso --client-secret-stdin`, and saves it with that login.
    - The operator hands it out in onboarding, the way Google's docs expect for installed apps.
    - Other providers need no secret.
- **Caddy:** add `/.well-known/aerolvm-auth` (and, for §5.14, `/.well-known/oauth-protected-resource*`) to the `@api` matcher in `install.sh` and `packaging/Caddyfile.template`. `/mcp` was missed the same way once (memory: MCP plan step 8).

### 5.7 Dashboard

- **Sign in:** `/ui` shows one "Sign in with <display_name>" button per issuer that has `clients.dashboard`, in identity-file order, plus a "use a token" fallback (today's paste box). Workload issuers (no dashboard client id) get no button, because a browser sign-in can't start without one (design review DR3). The browser runs code flow with PKCE against the provider and keeps the ID token in `sessionStorage`, as it keeps the PAT today, and sends it as a bearer. No cookies means no CSRF surface.
- **Sign-in box layout (design review DR4).** The box keeps its 360 px width and the dashboard's tokens.
  - **Heading.** "AerolVM", then the page's host in muted text. The old "sandboxd" heading is gone, so the box matches the page header.
  - **Line under it.** "Sign in with your company account." With no SSO button, it reads "Sign in with an API token."
  - **SSO buttons.** Full width, stacked, in DR3 order. Every button matches Google's geometry (design review DR11).
    - **Google's button.** `google.accounts.id.renderButton` with `theme: "filled_black"`, `size: "large"` (40 px), `shape: "rectangular"`, `text: "signin_with"`, `logo_alignment: "left"` and `width` set to the box's measured inner width: 312 px on desktop, 200–400 px as GIS allows, re-rendered on resize (design review DR12).
    - **Other providers.** 40 px tall, `width: 100%` (312 px on desktop), radius 4 px, 14 px text, in the existing `button` look (`--panel2` fill, hover `--accent`). No accent fill, so every provider has equal weight. The border is 1 px `--muted2` (3.76:1 against the box), close to Google's own stroke, instead of `--border` (1.34:1) (design review DR14).
  - **Token box.** After an "or" divider, behind a `<details>` labelled "Use an API token instead". It is closed when any SSO button shows. When none do, it is open and is the only content (identity off, no dashboard issuers, or plain HTTP).
  - **Token field.** A visible `<label for="pat-input">API token</label>`, with the hint "An avm_ token or the server's PAT." The placeholder is no longer the only label.
  - PAT sign-in behaves exactly as today (L8). Only the box's text and order change.

  ```
  ┌────────────────────────────────────┐
  │ AerolVM                            │
  │ api.acme.dev                (muted)│
  │ Sign in with your company account. │
  │ ┌────────────────────────────────┐ │
  │ │    Sign in with Acme Okta      │ │
  │ └────────────────────────────────┘ │
  │ ┌────────────────────────────────┐ │
  │ │  (Google Identity button)      │ │
  │ └────────────────────────────────┘ │
  │ ────────────── or ──────────────── │
  │ ▸ Use an API token instead         │
  └────────────────────────────────────┘
  ```
- **Okta, Entra ID and Keycloak** run the browser flow as a public SPA client: PKCE, no secret anywhere.
- **Google** (CEO review D2, 2026-10-16). Google's token endpoint wants a client secret for web clients even with PKCE, so the dashboard does not use the code flow for Google. It uses **Google Identity Services**: `google.accounts.id.initialize({client_id, nonce, callback})` in popup mode.
  - The browser receives Google's signed ID token directly, and sandboxd checks it offline like any other issuer.
  - There is **no relay endpoint and no client secret anywhere on the server.** sandboxd takes no part in any login.
  - Costs:
    - The `/ui` page loads `https://accounts.google.com/gsi/client`, which the CSP below allows.
    - A Google dashboard session is the ID token's lifetime, about 1 h. GIS auto-select re-issues it silently while the Google session lives.
  - Selected by `kind: google` on the issuer entry. Every other issuer uses the generic SPA path.
- **Address (CEO review D18).** Caddy's `@api` matcher gains `/ui /ui/*` (`scripts/install.sh:1289`, `packaging/Caddyfile.template`), so the dashboard is served at `https://<api-domain>/ui`. That URL is what operators register as the redirect URI and JS origin.
  - Sign-in buttons appear only when the page is served over HTTPS or from a localhost origin (an SSH tunnel). On plain `http` from another host, the page says "SSO sign-in needs a secure connection. Open <ui_url>". `ui_url` comes from discovery, which publishes `https://<SB_DOMAIN>/ui` when `SB_DOMAIN` is set (design review DR9). Without a domain, it says "… Reach this page through an SSH tunnel to localhost:21212."
  - The existing token-paste box stays (L8), with a warning line on plain HTTP.
- **Content-Security-Policy (CEO review D19).** `/ui` sends `default-src 'none'; script-src 'sha256-<inline script>' https://accounts.google.com/gsi/client; style-src 'unsafe-inline'; connect-src 'self' <issuer token-endpoint origins>; frame-src https://accounts.google.com; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`.
  - The script hash is computed at boot from the embedded page, so it can't drift.
  - `connect-src` is rebuilt from the current identity file on each `/ui` request.
  - Inline event handlers stay banned; the page has none today.
  - `style-src` has no hash, because a hash would make browsers ignore `'unsafe-inline'` and block the page's one `style=` attribute.
- **Expiry mid-session (Section 4, finding 4.2; design review DR6).** The plan first said "re-run sign-in silently with `prompt=none`". For SPA providers that can't work in a hidden iframe: the CSP blocks it, and browsers block the provider's cookie there. So renewal works like this:
  - **When.** At `exp − 120 s` while the tab is visible, and on any 401 with `reason: expired`. A background tab renews when it becomes visible.
  - **One at a time.** Only one renewal runs. Auto-refresh pauses, and other API calls wait for it, so four panels' 401s start one renewal, not four.
  - **Okta, Entra, Keycloak.** A full-page redirect with `prompt=none`.
    - First the page saves the view in `sessionStorage`: the placements filter and page, the auto-refresh setting, open `<details>` and the scroll position. It restores them on return.
    - If a request or a confirm prompt is in progress, the redirect waits for it.
    - The browser only ever holds the ID token (about 1 h). There is no refresh token in the browser.
  - **Google.** GIS auto-select, inside the allowed `accounts.google.com` frame, with no reload.
  - **On failure** (`login_required`, an error, or auto-select declined): a banner at the top, "Your sign-in expired. [Sign in again]", with `role="alert"`. The view stays, and Sign in again restores it the same way.
- **Who the console is for (design review DR1).** Every data panel except Health reads a `fleet.admin` route (`dashboard.html:551,552,634,733`), so the console is for admins.
  - After sign-in the page calls `whoami`. The `admin` role and PAT/operator callers get the overview.
  - Every other role (viewer, runner, auditor, including `*`-bound ones) gets one **signed-in screen** instead: their name, role and team, the line "This console shows fleet health and needs the admin role.", a CLI pointer (`aerolvm login https://<host>`, then `aerolvm list`; design review DR10), and Sign out.
  - The overview's panels never load for those callers, so no 403 ever reaches a panel. Admins and operators hold every permission, so the overview needs no per-button hiding. The server enforces every route regardless.
  - The signed-in screen reuses the sign-in box (same width and tokens), with this content in this order:

  ```
  ┌────────────────────────────────────┐
  │ AerolVM                            │
  │ api.acme.dev                (muted)│
  │ Signed in as alice@acme.com        │
  │ Role viewer · team payments        │
  │ This console shows fleet health    │
  │ and needs the admin role.          │
  │ From a terminal:                   │
  │ aerolvm login https://api.acme.dev │
  │ aerolvm list                       │
  │                        [ Sign out ]│
  └────────────────────────────────────┘
  ```
- **Keyboard focus (design review DR13).**
  - **Where focus starts.** On the first focusable element in the box that isn't Google's iframe, which a script can't reliably focus. In order: an SSO button, else "Use a different account", else the token disclosure's summary, else the token field when it is the only content. The no-access screen focuses its heading (DR8).
  - **No autofocus.** The token field's `autofocus` attribute (`dashboard.html:156`) is removed, so focus is never stolen.
  - **Focus ring.** New elements get `:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px }`. `--accent` on `--panel` is 7.21:1.
  - **Tab order** follows visual order. The overview is `hidden` while a box shows, so no focus trap is needed.
- **Narrow screens (design review DR12).** The new screens fit a 320 px viewport with no horizontal scroll.
  - **Header.** Below 720 px it wraps to two rows: brand and node summary, then identity and controls. The name's `max-width` drops to 140 px.
  - **Boxes.** Below 400 px they keep `max-width: 92vw` and use 16 px padding.
  - **Banner.** Below 480 px its text wraps and "Sign in again" drops below it.
  - **Overview tables.** They keep today's horizontal scroll inside `.card .body`.
- **State wording (design review DR9).** The DR9 wording table and the Pass 2 consolidated state table in the design review are T8's acceptance criteria for every sign-in state. Reason codes appear in parentheses so support can match them. The PAT's rejection text is unchanged (L8).
- **Sign out and switching accounts (design review DR7).**
  - **Sign out** clears the stored token and the DR6 saved view, and calls `google.accounts.id.disableAutoSelect()`. Without that call, Google's auto-select signs the person straight back in.
    - Auto-select resumes only after the next explicit Google sign-in, so DR6's silent renewal still works afterwards.
    - The page returns to the sign-in box with a muted "Signed out." line. Focus follows the DR13 rule.
  - **No provider sign-out.** The person stays signed in to their company account, as with other SSO apps.
  - **"Use a different account".** A link under the SSO buttons. It sends `prompt=select_account` when the issuer's discovery lists it in `prompt_values_supported`, and `prompt=login` otherwise. For Google it opens the GIS account chooser.
- **No access screen (design review DR8).** When `whoami` returns the "no binding" 403, the box shows:

  ```
  ┌────────────────────────────────────┐
  │ AerolVM                            │
  │ api.acme.dev                (muted)│
  │ You're signed in, but you don't    │
  │ have access here.                  │
  │ alice@acme.com · Acme Okta         │
  │ No access rule on this server      │
  │ matches your account. Ask your     │
  │ AerolVM admin to add one for a     │
  │ group you're in.                   │
  │ ▸ Groups your sign-in carried (12) │
  │ Use a different account  [Sign out]│
  └────────────────────────────────────┘
  ```
  - **Groups.** The toggle lists up to 50 groups, then "and N more". With no groups claim, the toggle is replaced by "Your sign-in carried no groups."
  - **Entra overage** (`reason: group_overage`). No list. It says "Your sign-in carried too many groups to list. Ask your admin to bind an Entra app role instead."
  - **Announcement.** Focus moves to the heading, and the box has `role="alert"`. Every value renders through `textContent` (Section 3, finding 3.6).
- **Header identity (design review DR5).** On the overview's right side, before auto-refresh, Refresh and Sign out:
  - **Name and role.** The `whoami` display name (`max-width: 200px`, ellipsis, full value in `title`), then a muted role pill: `admin`.
  - **PAT or operator session.** "Server token" with an `operator` pill.
  - **Warning color, identity on only.** With identity on, the `operator` pill uses `--warn` text, and its `title` reads "Actions are recorded as the server, not a person." With identity off, the pill stays muted. A default install has nothing to steer people toward, and L8 keeps identity-off behavior as it is today.

### 5.8 The caller in audit records

**Fields.** Two pointers are appended after `WitnessedThrough`, both `omitempty`, never reordered:

```go
Caller  *Caller  `json:"caller,omitempty"`  // {kind, id, name, via}
Request *Request `json:"request,omitempty"` // {method, route, status, digest, count, surface, argv, target} — §5.9; surface, argv and target omitempty
```

Old records re-marshal byte for byte (nil pointers are omitted), so they still verify. Retention stubs drop both fields automatically (`chain.go:44-54`). The hash covers `caller`, so attribution is tamper-evident. Exporters ship raw lines, so SIEMs get the fields with no exporter change.

**Propagation.** Emitters get the caller from `ctx`:

- `secretAuditEventFor(ctx, …)` fills `Caller` from `Access`. Without `Access`, it uses `system:<subsystem>`, set with `ContextWithSystemCaller` at the background entry points: boot restore, reconcile, lifecycle, failover recreate and image GC.
- `loadEnv`, `loadMounts`, `UnsealRegistry` and `OpenClusterSecretsForNode` already take a `ctx`. Only the event construction changes.
- `actor` and `node_id` keep meaning the writing node, so existing consumers see no change.

**Cluster attribution.** The owner node re-authenticates the forwarded credential (§2.2), so it holds the real caller. It records `via` from the authenticated mTLS peer id, never from a header. The list fan-out forwards `X-Correlation-ID` (H3). One API call can then be followed across nodes.

**Rollout and rollback** (§12 I6):

- **Cluster.** Nodes write the new fields **and the new record kinds** only once every live member advertises `fv ≥ auditCallerVersion` in gossip. The gate covers `caller`, `request`, and the kinds `api`, `auth_denied` and `identity_config`, plus the `api` `rate_limited` markers (Section 6, finding 6.1). Every one of them is hash-covered and unknown to old readers. Readers of a peer's records may be on either version during a rolling upgrade, so the gate covers all members, not only servers. Until then, records are written without `caller`, as they are today.
- **Single node.** Writes start at once.
- **Rollback floor.** Once a node has written `caller`, a binary older than this release fails strict boot verification on that log. The release notes and the runbook say so. Recovery is to roll back no further than this release, or to boot once with `SB_SECRET_AUDIT_BOOT_VERIFY=warn`. An older `aerolvm audit verify` fails the same way, so upgrade the CLI first.

### 5.9 API action records (kind `api`)

`d.Route` writes one chain record per call, after the handler returns.

**What it records:**

| | |
|---|---|
| Always | Every non-GET call. Every toolbox-proxy call, including file reads. `audit/verify`. Token list. |
| Opt-in | Plain GETs, with `SB_AUDIT_API_RECORDS=all`. |
| Never | `/health`, and `cluster.internal` routes (`/v1/cluster/internal/*`, node-to-node control traffic, not caller actions; Section 7, finding 7.2). |

**Record shape:**

- `kind: api` and `ref: "POST /v1/sandboxes/{id}/exec"` (the route pattern, not the raw path).
- `sandbox_id` and `owner_ref` when the route has a sandbox.
- `request.target`: the id of the object a non-sandbox route acts on: the token id for `/v1/tokens/{id}`, the snapshot, egress-profile, WASM-module or JS-bundle id, or a template id. It comes from the route's path parameters, so a revoke record names the token it revoked (Section 7, finding 7.1; needed by D7). Token create also records the new token's id, role and team, so "who minted this admin token" survives the row's deletion.
- `result: ok|denied|error`, `caller`, and `request.{method, route, status}`.

**Exec:**

- `request.digest` = SHA-256 of the request body, hashed as it streams with a `TeeReader`, never buffered.
- `SB_AUDIT_EXEC_COMMAND=full` also records `argv` (never env). The default is digest only, because commands can carry secrets (§12 I5).
- WebSocket sessions and exec streams are recorded at upgrade (status 101).

**Denied calls:**

- 403s are recorded as `result: denied`. They answer "who tried what they were not allowed".
- 401s are counted in a metric. They are also recorded as `auth_denied`, rate-limited to one per source IP per minute, so a spray cannot fill the disk. The source IP is the TCP peer on TCP listeners. On the public socket (§5.11), and on Caddy's TCP upstream under `any` scope, it is `X-AerolVM-Client-IP`, which install.sh makes Caddy set from `{remote_host}`, the peer Caddy itself saw. That peer is the real client only because the caddy-l4 SNI fallback now sends a PROXY v2 header to the 8443 site (CEO review D12). Today it dials `127.0.0.1:8443` plain (`pkg/caddy/client.go:1203-1210`), so every caller would look like 127.0.0.1. With `SB_L4_FALLBACK_PROXY_PROTOCOL` off, the header is not set and sandboxd uses the TCP peer. A client-supplied `X-Forwarded-For` is never used, so `trusted_proxies` settings cannot make it spoofable. sandboxd trusts `X-AerolVM-Client-IP` only on the public socket or from a loopback TCP peer. From any other peer, for example a remote caller hitting `0.0.0.0:21212` directly, it is dropped and counted (Section 3, finding 3.4).

**Forwarding:** only the node that runs the handler records the call. Every forward path marks a per-request holder as "forwarded" through `cluster.StampForward`, and the edge then skips its own record. The forward paths are `clusterroute.Wrap`, `clustercreate`, the `clusterlist` client, the runloop `forwardToNode`, `pkg/api/v1/js_bundle.go`, and the `cluster_handler.go` fan-outs. If the forward itself fails (502), the edge records that failure.

**Cost and floods:**

- Records use the existing buffered `Emit`, not `EmitDurable`. There is no fsync on the request path, and overflow becomes a `gap` record with a `Dropped` count, as today.
- **Flood control (CEO review D14)** is selectable per install with `SB_AUDIT_API_FLOOD_CONTROL`:
  - **`budget` (default, including identity off):** the existing per-sandbox token bucket in `internal/service/secret_audit_quota.go` gains an `api` bucket keyed `(sandbox, caller)` (`SB_AUDIT_API_RATE`, default 20/s; `SB_AUDIT_API_BURST`, default 100). Over budget, calls are counted into one `rate_limited` record that names the caller, the count and the routes. Secret-open records and gap markers are never budgeted, as today.
  - **`coalesce`:** identical `(caller, route, sandbox, status, digest)` calls within one second merge into one record with `request.count`. Different commands never merge (I5). There is no cap.
  - **`both`:** coalesce first, then the budget.
  - **Shared nodes always get the budget.** The audit log is per machine, so one uncapped flood could push another customer's records out. When this node hosts sandboxes of more than one owner (distinct `OwnerRef`s among its live sandboxes, `""` included), `coalesce` runs as `both`. So coalesce-only is honored only when one customer has the node to themselves. The node re-evaluates on every local create and delete. The effective mode is exported as `aerolvm_audit_api_flood_mode{configured,effective}`, and every change of effective mode writes one chain record, so the switch is visible in the evidence.
  - Records with no sandbox (token ops, cluster admin) are never budgeted or merged: they are rare and admin-only.
- `SB_AUDIT_API_DURABLE=true` makes token create, token revoke and sandbox delete wait for fsync. It is off by default and on in enterprise mode.
- **Crash window (Section 4, finding 4.1).** Buffered records are fsynced on the writer's ticker (`secretAuditSyncInterval`), so an unclean crash can lose records not yet synced: the same window secret-open and egress records have today. The docs claim "every mutating action is recorded, except calls in the last sync interval before an unclean crash, unless the call is durable".

**System actions:** lifecycle auto-stop and auto-delete, the reconcile reap, and the orphan delete become chain records with `caller: system:<subsystem>`. Today they are only `slog` lines. "Who deleted this sandbox" always has an answer. The creator is found through the create record, by `sandbox_id`.

**SSH:** gateway session open writes `kind: api`, `ref: ssh`, `caller: {kind: sandbox_key, id: <sandbox>}` (D3). The key belongs to whoever created the sandbox, and the create record names them. Binding SSH keys to people is §13.

**MCP:** the outer `/mcp` request writes no record. Each tool's inner API call writes its own, with the MCP caller as `caller` and `request.surface: mcp`, so one tool call is one record (§5.14).

### 5.10 Answering the auditor

- **Per sandbox:** `GET /v1/sandboxes/{id}/audit?kind=api&caller=<id>` adds a `caller` filter over the page. The read index is unchanged, since it already narrows to one sandbox.
- **"What did Ana do this week":** `aerolvm audit search --export <dir|s3://…> --caller ana@acme.com --since 7d`. It reuses the batch reader from `aerolvm audit verify` and verifies each chain while it searches, so results are tamper-checked. A live fleet-wide query would fan out to 2,000 nodes. That is the SIEM's job, and the export already feeds it.
- **Access review** (CEO review D7): `aerolvm access review --export <dir|s3://…> --since 90d [--identity-file f] [--format md|csv]`.
  - It joins `GET /v1/tokens` (`token.read`: auditor or admin) with the verified export into one report the customer files as SOC 2 CC6.2/6.3 evidence. Two inputs:
    - every listed token: name, role, team, creator, expiry and whether it has expired;
    - every token revoked in the window, from the `api` records of `DELETE /v1/tokens/{id}`, with who revoked it;
    - every principal seen in the window: last action, and counts by kind.
  - **Binding changes in the window**, from the `identity_config` records (D20).
  - Flags: tokens with **no recorded action** in the window, **expired** tokens not yet swept, tokens expiring within 30 d, tokens revoked in the window, every admin principal, and principals with denied attempts. Bindings from the identity file are included when `--identity-file` is given.
  - Reads are recorded only with `SB_AUDIT_API_RECORDS=all`. So a read-only token (viewer, auditor, scrape) shows "no recorded action" under the default. The report prints the setting it found, so a reviewer doesn't read that flag as "unused".
  - **Scale.** Each node's chain is independent, so the command reads and verifies nodes in parallel. At G7 scale with heavy exec traffic, a quarter of export can be tens of TB, so for large fleets the documented answer is to run the same join in the SIEM. The report format is specified in the docs so a SIEM query can reproduce it.
  - It cannot know about people the provider binds who never called the API, and the report says so.
  - No new server endpoint, table or replicated state. The code lives in `cmd/aerolvm` and `pkg/auditlog` (the CLI dependency guard).
  - A tampered batch fails the report, the same way `audit verify` fails.
  - Output escaping (finding 3.6): Markdown special characters are escaped, and CSV cells starting with `=`, `+`, `-` or `@` get a leading `'` (formula injection).

### 5.11 The PAT

The PAT stays the break-glass credential. It is also how nodes call each other, so it cannot be turned off.

- **Rotation:** `SB_PAT_TOKEN_PREVIOUS` is accepted (in constant time) during a rolling restart, and nodes send the current PAT. The runbook procedure: add the new PAT as current and the old one as previous on every node, restart in turn, then remove previous.
- **Operator volume scope (H2):** a new setting, `SB_OPERATOR_VOLUME_SCOPE`. When it is unset, the scope is the legacy `op-<hash(PAT)>`, and boot logs the effective value. Rotation step 0 is to pin it. Existing installs see no change.
- **Monitoring:** `aerolvm_auth_requests_total{kind,origin}`, plus a Prometheus alert on PAT use from outside the cluster ("break-glass PAT used"). The `origin` label is `host` (loopback TCP peer), `peer` (mTLS) or `public` (Caddy, or a remote TCP peer). The label is reliable only once D12's PROXY protocol gives Caddy the real client.
- **Client IP through Caddy (D12).**
  - The caddy-l4 fallback route (`tlsMuxFallbackRoute` in `EnsureLayer4`) adds `"proxy_protocol": "v2"`.
  - The 8443 site gets `listener_wrappers { proxy_protocol { allow 127.0.0.1/32 } tls }`. Its default fallback policy accepts connections without a header, so the order of the two changes is safe.
  - install.sh writes the wrapper and sets `SB_L4_FALLBACK_PROXY_PROTOCOL=true` in the same step. A binary-only upgrade leaves the flag off, so HTTPS cannot break.
  - `EnsureLayer4` is a fragile path (CLAUDE.md rule 5): the regression test goes in `internal/service/layer4_bootstrap_test.go`, and T10's PR carries the call-out.
  - Side effect: preview sites (`*.$DOMAIN:8443`) see real client IPs too.
- **Enforced SSO: `SB_PAT_SCOPE=host`** (CEO review D4, 2026-10-16). The default `any` keeps today's behavior (L8). With `host`:
  - **The PAT is accepted only on two listeners:**
    - the mTLS internal listener, for cluster peers;
    - the existing API listener, **only when the TCP peer is loopback**.
  - **The API listener keeps its bind.** Domain installs bind `0.0.0.0:21212` (`scripts/install.sh:1071`). Terraform opens it to admin CIDRs (`Terraform/network.tf:126-133`), and the obs stack scrapes `private_ip:21212` (`Terraform/obs.tf:131`).
    - Under `host`, a non-loopback peer on that listener is public. SSO and `avm_` tokens work, so remote SDKs and a token-based scrape keep working. A PAT gets 401.
  - **Caddy also connects from loopback, so under `host` it moves to its own listener.** Otherwise its traffic would look host-local.
    - sandboxd opens a Unix socket, `SB_PUBLIC_API_SOCKET`, default `/run/sandboxd-public/api.sock`. The directory is `root:caddy 0750` and the socket `0660`, because `/run/sandboxd` is `0700` (`scripts/install.sh:1066`).
    - When the flag is set, install.sh and `packaging/Caddyfile.template` point Caddy's `reverse_proxy` at that socket.
    - Every request on the socket is public.
    - Today Caddy and the host scripts share `127.0.0.1:21212` (`scripts/install.sh:1297`, `scripts/sandboxd-node-lifecycle.sh:100`), so without a second listener the two could not be told apart.
    - Any other reverse proxy an operator runs on the host must also use the socket. The docs say so.
  - A refused PAT gets 401: "the operator token works only on this host; sign in with `aerolvm login --sso` or use a named token".
  - **What keeps working:** the setup scripts and runbooks that call `http://127.0.0.1:21212` with the PAT. A host-local call to a sandbox on another node is forwarded over mTLS, and the owner accepts it as today.
  - **What must move:** remote tools that use the PAT. The dashboard, remote `/mcp`, remote SDK scripts, and the Prometheus scrape (`setup/obs/prometheus.yml.tftpl:14-16`) need SSO or a named token. For the scrape, Terraform takes an **optional** `metrics_token` in `config/secrets.yml` next to `pat_token`. When it is unset, the scrape keeps using the PAT, so default clusters (identity off, `any` scope) lose nothing (G6, L8). Turning on `host` scope is a two-step bootstrap: the cluster comes up, the operator mints a `viewer` token on `*` from the host (D6), sets `metrics_token`, and re-applies. T10 owns `Terraform/locals.tf:411`, `Terraform/obs.tf:130` and `config/secrets.example.yml`.
  - **Break-glass** when the provider is down and no admin token exists: SSH to the host and use the host-local listener.
  - **First admin token** (runbook step, T10): in enterprise tokens-only mode with `host` scope, the first `admin` token can only be minted with the PAT from the host. Run `aerolvm token create --role admin --team '*'` on a node with `SB_API_URL=http://127.0.0.1:21212`.
  - **Forwarded PAT requests.** Each node sets `SB_PAT_SCOPE` itself, so one node left on `any` could accept a remote PAT and forward it. To stop that:
    - When a node forwards a PAT request on any forward path (through `cluster.StampForward`), it adds `X-Cluster-PAT-Origin: host|public`. Like every `X-Cluster-*` header, it is accepted only from a live mTLS peer.
    - An owner under `host` refuses `public` and refuses a missing origin. So `host` is turned on only after every node runs this release; the runbook says so.
    - Nodes advertise their scope in gossip, and `aerolvm_pat_scope_drift` counts members whose scope differs from this node's. A shipped alert fires on any drift.

### 5.12 Enterprise mode

Added to the enterprise-mode checks (`internal/config/config.go:2532-2584`):

- `SB_IDENTITY_ENABLED=true`;
- token max TTL ≤ 90 d;
- `SB_AUDIT_API_RECORDS` ≠ `off`;
- `SB_AUDIT_API_DURABLE=true`;
- `SB_PAT_SCOPE=host` (CEO review D5). Boot refuses `any` with an error that names both steps: point Caddy at `SB_PUBLIC_API_SOCKET`, and move remote tools that use the PAT to a named token or SSO. The release notes carry this migration next to the L7 step.

With that, enterprise mode **enforces named credentials** for people: SSO or a scoped token, never the shared operator token from outside the host. In tokens-only mode, which L7 allows, there is no SSO, so the enterprise matrix row says "named credentials enforced", not "SSO enforced".

OIDC itself is not required (L7, I7). **Tokens-only mode** is `SB_IDENTITY_ENABLED=true` with no `SB_IDENTITY_FILE`. It is a fully supported configuration, including in enterprise mode, for air-gapped buyers. UC-283 covers both halves: enterprise mode refuses identity off, and boots with tokens only.

### 5.13 Reuse map (DRY / YAGNI)

| Need | Reuses | New code |
|---|---|---|
| Identity file | egress operator watcher (`internal/egress/operator`) | schema and bindings matcher |
| Token store, both modes | egress-profile backend split, `fv` gate, FSM op pattern | two ops, one table |
| Mirror on workers | the placement feed's cursor idea (`agent_placement_feed.go`) | a 5 s poll; no long-poll |
| Team scoping | `ownerScope`, `enforceOwner`, `OwnerRef` | none |
| Evidence | the secret-audit chain, witness, export, retention, read index | two optional fields, one record kind |
| Search | `auditlog.VerifyNode` batch reader | a filter |
| Pluggable identity | the `controlplane.Validator` seam | the local implementation |

There is no new database, no new audit log, and no session store.

### 5.14 OAuth for remote MCP (CEO review D10)

This pulls the MCP plan's Phase 4 into this plan, at the founder's choice (D10). It reopens that plan's demand checkpoint (MCP CEO review D2, 2026-10-04). It stays inside §5.0: sandboxd remains a resource server, the provider does the login, and every token is checked offline.

- **Discovery (RFC 9728).** `GET /.well-known/oauth-protected-resource`, plus the path form `/.well-known/oauth-protected-resource/mcp`. It returns a static document built from the identity file:
  - `resource`: the configured `/mcp` resource URL;
  - `authorization_servers`: the issuers that set `mcp:`;
  - `bearer_methods_supported: [header]`.
- **Challenge.** A 401 from `/mcp` carries `WWW-Authenticate: Bearer resource_metadata="<that URL>"`, so a connector learns where to sign in.
- **Accepted tokens.** JWT access tokens whose `aud` contains one of the issuer's `mcp_audiences`, verified offline exactly like §5.5 ID tokens.
  - Providers fill `aud` differently: Entra v2 uses the API app's client id, Okta custom authorization servers use the configured audience, and Keycloak uses an audience mapper. So the audience is configured per issuer and never assumed to be the resource URL.
  - **Entra** issues custom-API access tokens in v1 format (`iss` = `https://sts.windows.net/{tid}/`) unless the API app's manifest sets `accessTokenAcceptedVersion: 2`. The exact-`iss` check refuses a v1 token with the hint "set accessTokenAcceptedVersion: 2 on the API app". The Entra connector docs include that step, and T13 has a v1-token fixture.
  - `typ: at+jwt` (RFC 9068) is not required, because Entra and Keycloak don't send it. Access tokens are told apart from ID tokens by audience alone, and the identity-file load fails if `mcp_audiences` overlaps `audiences`.
  - An `mcp_audiences` token is accepted **only on `/mcp`**; every other route refuses it.
  - Bindings and roles apply unchanged.
  - Opaque access tokens are refused, because checking them would need an introspection call per request, which L2 rules out. Google therefore cannot be used for MCP OAuth.
- **Inner tool calls.** Today the in-process transport re-sends the caller's `Authorization` header through the whole API handler (`pkg/api/remotemcp/inprocess.go:11-15`).
  - With this plan, `/mcp` authenticates once. The transport then carries the resolved `Access` under a context key that only the in-process transport sets; it can never come from the wire.
  - `authenticate` (§5.2) uses that `Access` for inner calls instead of re-checking a bearer. So an `/mcp`-audience token never has to be valid on `/v1`, and `/v1` refuses one that arrives from outside.
  - Each inner call is still authorized by its route permission and recorded once (§5.9).
  - **Never the operator by accident** (eng review E4; keeps b374ec3d). The `agenttools` client is always built with the caller's own bearer, carried for forwarding, plus the hand-off `Access`. An empty bearer still gets 400 before any tool runs, because the SDK client falls back to `SB_PAT_TOKEN` on an empty token. No inner call may run with the SDK's environment default.
  - **Across nodes.** An inner call on a sandbox owned by another node is forwarded like any API call, with the caller's original bearer attached, so the owner can verify it offline (L2).
    - The edge marks the forward with `X-Cluster-Surface: mcp` through `cluster.StampForward`, on every forward path, including the `clusterlist` fan-out an MCP list tool triggers. Like every `X-Cluster-*` header, it is accepted only from a live mTLS peer.
    - On that forwarded request, and only there, the owner also accepts `mcp_audiences` for the token's issuer. Signature, issuer, expiry and bindings are checked exactly as on the edge.
    - The marker widens the accepted audience; it never supplies an identity.
    - UC-286 covers this on `cluster-3-mixed`.
- **Which credentials each route accepts:**

  | Credential | `/v1`, facades, `/ui` API calls | `/mcp` | Forwarded over mTLS with `X-Cluster-Surface: mcp` |
  |---|---|---|---|
  | PAT | yes (subject to `SB_PAT_SCOPE`) | yes (subject to `SB_PAT_SCOPE`) | yes (subject to the origin rule, §5.11) |
  | `avm_` token | yes | yes | yes |
  | ID token (`audiences`) | yes | yes, for Claude Code or Cursor with a header | yes |
  | MCP access token (`mcp_audiences`) | **no** | yes | yes |
  | Opaque access token | no | no | no |

  So UC-286's "ID token refused on `/mcp`" is wrong as first written. An ID token is accepted on `/mcp`, since bearer clients send one today. The OAuth connector flow is what yields an `mcp_audiences` token, and that token is refused on `/v1`.
- **Identity file.** The single resource URL is the top-level `mcp.resource`. An issuer opts in with `mcp: true` and its `mcp_audiences` (schema in §5.5).
- **Client registration** happens at the provider, never at sandboxd. The customer's admin registers the claude.ai or ChatGPT connector as an OAuth client in Okta, Entra ID or Keycloak. The docs give the steps for each. sandboxd hosts no registration endpoint and proxies none. **We have no evidence yet that ChatGPT connectors accept a pre-registered client.** T13 tests both connectors live, and the docs claim only what passed.
- **Caddy:** `/.well-known/oauth-protected-resource*` joins the `@api` matcher, next to `/.well-known/aerolvm-auth`.
- **Proof.** Offline: handler tests for the metadata and challenge, plus access-token verify tests. In the harness: the MCP TypeScript SDK's OAuth client against the test issuer (UC-286). Live: one manual connector run per provider with claude.ai and ChatGPT, recorded in the runbook. A connector change on their side is outside our tests, so the docs date-stamp what was verified.

### 5.15 Observability (CEO review D22)

| Kind | What |
|---|---|
| Metrics | `aerolvm_auth_requests_total{kind,origin}`, `aerolvm_auth_failures_total{kind,reason}`, `aerolvm_identity_mirror_age_seconds`, `aerolvm_identity_stale_accept_total`, `aerolvm_identity_jwks_fetch_total{issuer,result}` + `aerolvm_identity_jwks_last_success_timestamp{issuer}`, `aerolvm_identity_file_info{hash}`, `aerolvm_identity_file_load_errors_total`, `aerolvm_audit_api_records_total{result}`, `aerolvm_audit_api_rate_limited_total`, `aerolvm_audit_api_flood_mode{configured,effective}`, `aerolvm_api_tokens{role}` (server tier), `aerolvm_pat_scope_drift` |
| Alerts (`setup/prometheus/sandboxd-alerts.yml`) | break-glass PAT use from `origin="public"`; PAT-scope drift; mirror age > 30 s for 2 m (warning) and > 60 s (critical: tokens refused); JWKS fetch failing 15 m per issuer; identity-file hash differs across nodes for 10 m; identity-file load errors |
| Dashboard | an "Identity and access" row in `setup/grafana/d9-security-isolation.json`: requests by kind and origin, failures by reason, mirror age per node, JWKS health per issuer, distinct identity-file hashes, `api` records and rate-limited counts, flood mode per node. `dashboard_metrics_test.go` keeps every panel's metric real. |
| Runbook | `setup/runbooks/identity-and-access.md`: one entry per alert, plus rotation (PAT and scrape token), first admin token, provider outage, and the PROXY-protocol mismatch |
| Traces | the existing request span (`pkg/api/middleware.go:198-210`) gains `aerolvm.principal.kind`, `aerolvm.principal.id`, `aerolvm.team`, `aerolvm.permission` and `aerolvm.auth.result`. Display names are never attributes. |
| Logs | info: token create and revoke (id, role, team, actor), identity reload (old → new hash), mirror resnapshot, stale entry and exit. Debug: 401 reason with issuer. Never a token, secret or claim value beyond the principal id. |
| CLI | `aerolvm whoami --explain`: which binding matched (its index and text), and the caller's own claims considered (issuer, groups, roles), never anyone else's |

## 6. Scale and cost

| Path | Cost | At 2,000 nodes × 100k sandboxes |
|---|---|---|
| PAT check | constant-time compare, ns | — |
| API-token check | checksum, map lookup, SHA-256 of 32 B: < 2 µs | local; zero server-tier calls |
| OIDC check | cached: < 1 µs; first time: ~50 µs RS256 | zero server-tier calls; JWKS hourly per node = 2,000 req/h to the provider |
| Token mirror | 304 poll every 5 s | 400 req/s over ≤ 7 servers (~57 each); in-memory compare |
| Token state | ~200 B per token | 10k tokens = 2 MB in the FSM and in each mirror |
| `api` records | ~400 B buffered append, flood-controlled per `SB_AUDIT_API_FLOOD_CONTROL` (budget by default: ≤ 20/s per sandbox and caller after a burst of 100) | e.g. 10k calls/s fleet-wide = 5/s/node = ~170 MB/node/day before coalescing, inside the existing 30-day retention and export. Called out to operators in `setup/config-defaults.md`. |
| `CreateSandbox` boot path | one in-memory permission check plus one buffered record enqueue, a few µs | no fsync, no network, no lock on the path (pr-review §2) |

## 7. Phasing: stacked PRs, merge nothing until the stack is green

T0 shipped on its own as #724 (H1 is fixed in main). T0b (per-owner module ids, eng review D8) joins the stack ahead of T1. Everything else stacks on `plans/identity-and-access`, each branch on the one before.

| Task | Content | Tests | Size |
|---|---|---|---|
| **T0** | **Shipped as #724** (merged 2026-10-17, part of the `xtenant` series). It added a single `wasm_modules.owner_ref` column and backfilled existing rows to `""` (operator-published: readable by everyone, writable only by the operator). Create idempotency echoes only a row the caller may write; otherwise `ErrWasmModuleIDConflict`. **Residual, now T0b (eng review D8):** the catalogue id defaults to the module's content digest, so a second tenant registering identical bytes without an explicit id gets that conflict instead of its own row. | `TestWasmModuleCatalogue_OwnerScoping` (in #724) | done |
| **T0b** | **Per-owner WASM module ids** (eng review D8; follows the #731 snapshot-namespace pattern).<br>• **Identity:** a module's identity becomes `(owner_ref, id)`, via an idempotent store migration (`/add-store-column`). Rows backfilled by #724 keep `owner_ref = ""`.<br>• **Create:** `CreateWasmModule` defaults the id to the digest *within the caller's namespace*, so a second owner registering identical bytes gets its own row and no cross-owner conflict or existence signal.<br>• **Read, boot and delete:** reads and create-time boots resolve the caller's own namespace first, then operator-published (`""`). `ResolveOwnedWasmModule` and the warm-pool and inventory keys carry the owner. Delete acts only inside the caller's namespace.<br>• The catalogue is per host (no Raft change). | two owners with identical bytes → two rows; each sees its own row plus `""` rows, never the other's; a create-time boot picks the own row before `""`; a warm-upgrade migration test (old rows intact, idempotent rerun); the existing `TestWasmModuleCatalogue_OwnerScoping` stays green; UC-294 | M |
| **T1** | `Principal`, `Access.Fleet`, `Role`, `Via`; one `authenticate` over an ordered authenticator list (`pat`, `apiToken`, `jwt`, `provider`) with post-match steps (D6); `apihttp.BearerToken` shared with `remotemcp.serverFor`, replacing `extractBearerToken` and `remotemcp.bearerToken` (D5); node vs forwarded-operator split; `GET /v1/whoami`; 401 reasons for `avm_` and JWT failures (D17); interim guards for `SB_ITEST_IDENTITY_FILE`: identity on → boot error, enterprise mode → refused (D4); principal trace attributes and auth metrics (D22). The managed path maps to `runner`. Behavior identical. | the §5.1 invariant table as a test; the existing middleware tests unchanged; a per-reason 401 table, with the PAT 401 body byte for byte unchanged (D17); `BenchmarkAuthenticate{PAT,Token,JWTCached,JWTCold}` with CI budgets (p99 ≤ 50 µs on cached paths) and `FuzzParseAPIToken`/`FuzzJWTHeader` (D21); a boot-guard table for `SB_ITEST_IDENTITY_FILE` (D4); a `BearerToken` table: case, whitespace, subprotocol, empty, E2B `X-API-KEY` fallthrough (D5); one table per authenticator plus a post-match-steps table (D6) | M |
| **T2** | Permissions, built-in roles, `d.Route(perm, …)` on every v1, facade, MCP and dashboard route; `withAuthOperator` removed; `hostCapable(ctx)` replaces `!scoped` on the four operator-only gates (D3, D7); the registry test (H4). | registry test; `hostCapable` table (each principal kind × each of the four gates: only operator, node, internal and admin pass) plus a row where runner@* upserts an alias onto a team snapshot (D7); the `ownerScope` call-site test (D3); a `runner@*` create stamps owner `""` and resolves only `""` snapshots (§5.1 with `snapshotResolvableForCreate`, `owner_scope.go:70-90`); a per-role matrix test over a recording mux, including `metrics.read` (D6); facade tests; per-surface 403 hint tests, and a test that a 404 carries no hint (D9) | M |
| **T3** | Token store (SQLite plus FSM ops 31 and 32, snapshot, restore, `fv` gate, change ring, worker mirror, GC sweep); token format and validation in `pkg/identitywire`; the mirror on the existing `Agent.doControlPlaneJSON` helper (5.2); `/v1/tokens`; `aerolvm token`; delete `SB_ITEST_IDENTITY_FILE`, `pkg/daemon/itest_identity.go` and its test (D4). | `fsm_tokens_test.go` (apply, snapshot, restore, old snapshot); mirror staleness (a stale mirror refuses `sandbox.read` but accepts `metrics.read`, D16); checksum fuzz; a paused page walk racing a revoke never resurrects the token (4.4); a mirror page over 12 MiB is refused (5.5); a token spray at 10k req/s of malformed and unknown tokens makes zero server-tier calls (D21); 5,000 creates in a minute stay inside the ring, so no mirror resnapshots; forced resnapshots spread over ≥ 30 s (7.3); idempotency (409, 204) | L |
| **T4** | `Caller` field; ctx-based event construction; system caller contexts; cluster `fv` write gate; `via`; correlation forward in list fan-out (H3); `cluster.StampForward` and its use on every forward path (finding 1.2). | old-chain verify golden test; mixed-version gate test; forwarded attribution test; call-site test that every forward path calls `StampForward`; a list fan-out from a multi-team principal with `X-AerolVM-Team` returns only that team from every peer, with one correlation id (E6) | M |
| **T5** | `api` and `auth_denied` records, coalescing, exec digest via tee, forward dedupe, system destructive actions, SSH session record, `caller` filter, `aerolvm audit search`. | record-per-route table; flood control in all three modes (D14): budget table (burst, refill, marker names caller/count/routes, secret-open exempt, per-caller isolation), coalesce table (different digests never merge), both, and a node gaining a second owner switching `coalesce` to `both`, with its chain record; edge-skip-on-forward; one record per MCP tool call; SSH gateway test: session open emits one record (D3, UC-287); search over a fixture export; `BenchmarkAPIRecordEmit` (≤ 5 µs, D21); `request.target` on token, snapshot, profile, module, bundle and template routes; `cluster.internal` writes no record (7.1, 7.2) | L |
| **T5b** | `aerolvm access review` (D7): token list joined with the verified export; Markdown and CSV output; unused, expiring, admin and denied flags. | golden-file tests over a fixture export and token list; a tampered batch → FAIL; `cmd/aerolvm/deps_test.go` stays green | M |
| **T6** | OIDC verifier, identity file and watcher, bindings, deny list, JWKS latch and rate limit, verified-token cache, `/.well-known/aerolvm-auth`, Caddy matcher. | an httptest issuer: `alg:none`, HS256, wrong aud and iss, expired, nbf, kid rotation, lifetime cap, first-match bindings, reload, deny; the "no binding" 403 hint lists only the caller's own claims (D9), and the v1 body carries `reason`, `issuer`, `name` and `groups[]` with overage → `reason: group_overage` and no groups (DR8); Entra group overage → explicit refusal; `X-AerolVM-Team` selects among matching bindings, a non-matching team → 403 with the hint, and a forwarded request keeps the selection; reload writes one `identity_config` record with the correct diff, an unchanged reload writes none, and a boot with a changed file writes one (D20); an empty file is invalid (4.3); `display_name` over 40 characters or with control characters is stripped or refused at load, and discovery publishes it (DR3); discovery publishes `ui_url` = `https://<SB_DOMAIN>/ui` and omits it when `SB_DOMAIN` is empty (DR9); over-cap JWT, identity file or JWKS refused (5.5); `jku`/`x5u`/`jwk` headers ignored and HS256/none refused (3.5); `FuzzIdentityFile` (D21); the same cached JWT with two different `X-AerolVM-Team` values resolves two teams, so the LRU never pins a team (E7); `BenchmarkAuthenticate{JWTCached}` stays within D21's budget with a 10k-binding identity file (cache the matched binding set, not the selected team; E8) | L |
| **T7** | CLI: `login --sso` (PKCE loopback, `--device`), refresh, `auth token`, `whoami`, `--team` saved per login and sent as `X-AerolVM-Team` (D13), expiry warnings and the refresh-failure hint (D8), `whoami --explain` (D22). | fake issuer end to end; refresh edge; precedence unchanged; 6 d → warning, 8 d → none, `--json` stdout unchanged; env token with no cache → one `whoami`, cached → none (D15); golden `whoami --explain` output (D22); golden fixtures for every DR15 message: issuer choice, browser and device prompts, success with role and team, no binding with the 10-group cap and overage wording, refresh failure, expiry warning, `whoami` text layout (DR15) | M |
| **T8** | Dashboard sign-in: generic SPA code flow with PKCE, a Google Identity Services path for `kind: google` issuers (D2), the admin-only console with a signed-in screen for every other role (design review DR1); no team picker and no `X-AerolVM-Team` from the dashboard (DR2). No relay endpoint. `/ui /ui/*` in Caddy's `@api` matcher, plus HTTPS-or-localhost sign-in (D18); the `/ui` CSP with a boot-computed script hash (D19); the design review's consolidated state table (Pass 2), the DR9 wording and the Pass 6 accessibility rules as acceptance criteria (they replace the Section 11 table). | dashboard token-handling tests (nonce, `aud`, expiry); a `/browse` check on a local daemon; Caddyfile render test; buttons hidden on non-local plain HTTP; with the §5.5 example file, exactly two buttons render ("Sign in with Acme Okta", "Sign in with Google") and none for `github-actions` or `eks-prod` (DR3); the token disclosure is closed with buttons and open with none, the heading reads "AerolVM", and the token field has a visible label (DR4); the Google button renders with the DR11 options and every SSO button is 40 px tall and as wide as the box (DR11); at 320 px and 375 px viewports the new screens have no horizontal scroll and the Google button fits its box, and below 720 px the header wraps to two rows (DR12); keyboard focus starts on the first non-Google element (Okta when Google is listed first; "Use a different account" when Google is the only issuer), the token field has no `autofocus`, and new elements show the accent focus ring (DR13); non-Google SSO buttons have a `--muted2` border (DR14); the header shows the name and an `admin` pill for an SSO admin, and "Server token" with an `operator` pill for the PAT, in `--warn` only with identity on (DR5); after Sign out, Google auto-select does not fire and the box says "Signed out."; "Use a different account" sends `prompt=select_account` or `prompt=login` per the issuer's discovery (DR7); the no-access screen renders the heading, the group toggle with its count, the 50 cap, the overage and no-groups wording, and moves focus to the heading (DR8); UC-290; CSP header test (the hash matches the served script); `/browse` check that the dashboard loads and signs in with the CSP on; four simultaneous 401 `expired` responses start exactly one renewal; at `exp − 120 s` an SPA issuer gets a `prompt=none` redirect that restores the saved view; the redirect waits for an in-flight request; a failed renewal shows the "Your sign-in expired" banner and keeps the view (4.2, DR6); `/browse` check that a viewer token gets the signed-in screen, with the two-line CLI pointer naming the page's host, and the page makes no `/v1/cluster/*` or `/debug/vars` request (DR1, DR10) | M |
| **T9** | SDK parity in all 5 SDKs: `whoami`, `tokens.create/list/revoke` (`/add-sdk-method`); `SB_API_TOKEN` as an alias of `SB_PAT_TOKEN`; `SB_TEAM` / a client option that sends `X-AerolVM-Team` (D13). | per-SDK unit tests | M |
| **T10** | `SB_PAT_TOKEN_PREVIOUS`, `SB_OPERATOR_VOLUME_SCOPE`, `SB_PAT_SCOPE=host` with the public socket and the install.sh/Caddyfile wiring (D4), PROXY protocol on the L4 fallback plus the 8443 listener wrapper and `X-AerolVM-Client-IP` (D12), Terraform `metrics_token` (`Terraform/locals.tf:411`, `Terraform/obs.tf:130`, `config/secrets.example.yml`) with PAT fallback, the Caddy `header_up X-AerolVM-Client-IP {remote_host}` line, enterprise-mode checks, the §5.15 alerts, the Grafana row in `d9-security-isolation.json` and the per-alert runbook entries (D22), `setup/runbooks/identity-and-access.md`. | config tests; volume scope stable across rotation; listener split (PAT refused on the public socket and from a non-loopback peer on 21212, accepted from a loopback peer and from mTLS peers); socket directory permissions; the forwarded-PAT origin rule; the scope-drift metric; `layer4_bootstrap_test.go`: the fallback route carries `proxy_protocol` only with the flag on; UC-288 | M |
| **T11** | Docs: new `enterprise/access-control.mdx` (five-tab examples, `/add-docs-page`, Security group in `content.config.ts`; states the fleet-bindings-first rule, design review DR2); `cli.mdx`, `dashboard.mdx` (the console is admin-only, other roles get the signed-in screen; issuer `display_name` and `ui_url`; design review DR1, DR3, DR9), `mcp.mdx`; matrix rows in `enterprise/index.mdx`; rows in `responsibility.mdx`; the control mapping in `audit-evidence.mdx` (CC6.1–6.3, CC7.2); `setup/config-defaults.md`; `DESIGN.md`'s actor and action tables (Section 1, finding 1.7); the two mermaid diagrams and the credential tables in `enterprise/architecture.mdx` that show "apps hold the API token" (stale-diagram audit); the crash-window claim wording (4.1); the Prometheus scrape config (`setup/obs/prometheus.yml.tftpl`) using `metrics_token` when set and the PAT otherwise. `audit-evidence.mdx` discloses that `caller.name` holds email addresses and how retention bounds them (Section 3, finding 3.7). The TODOS.md "Metrics-scoped read-only token" item is marked resolved with a caveat (D6): the scrape credential is **read-only**, not metrics-only, because a `viewer` on `*` can also read every team's sandbox metadata and audit records. replies on #646, #647 and #649. | `make docs-build` with npm 10 | M |
| **T12** | Integration: an in-harness test issuer (discovery, JWKS, mint), UC-268–UC-294, live `single-node` and `cluster-3-mixed`; cross-tenant scenarios mint team `avm_` tokens at setup instead of a static token file (D4); chaos UCs 291–293 and the token-spray test (D21). | §8 | M |
| **T13** | OAuth for remote MCP (§5.14, D10): RFC 9728 metadata, the `/mcp` 401 challenge, `mcp_audiences` checks, the in-process `Access` hand-off in `pkg/api/remotemcp`, the identity-file fields, the Caddy matcher, per-provider connector docs, and a runbook entry for the live connector check. | metadata and challenge handler tests; access-token verify table (wrong `aud`, opaque → refused, overlapping audiences → load error); `mcp_audiences` token refused on `/v1`; inner calls use the hand-off on the edge, and a missing hand-off returns 500 without ever falling back to the bearer (finding 2.5); a cross-node forward with `X-Cluster-Surface: mcp` is accepted, and the same marker from a non-peer gets 403 in cluster mode (`clusterControlHeaderGuard`, `pkg/api/middleware.go:47-56`) and is stripped on a single node; an Entra v1 token gets the hint; an empty bearer on `/mcp` → 400, and no inner call ever reaches the SDK's `SB_PAT_TOKEN` fallback (E4); UC-286; manual claude.ai and ChatGPT runs | M |

Coverage: every new package and file ships with tests that keep its package at or above 85% (`/maintain-coverage` before each PR).

## 8. Use cases (verification matrix)

| UC | Scenario | Pass when |
|---|---|---|
| 268 | `runner` token for team payments creates, execs and deletes | all succeed; sandbox `owner_ref = team:payments`; three `api` records name `tok_…` |
| 269 | the same token reads a team-checkout sandbox | 404, not 403 |
| 270 | `viewer` token execs | 403 naming `sandbox.exec`; a `denied` record |
| 271 | revoke on node A, use on worker C | refused on C within 15 s |
| 272 | expired token; malformed checksum | 401; no mirror lookup for the malformed one (metric) |
| 273 | create via edge E, exec forwarded to owner O | O's record has `caller=tok_…, via=E`; E writes no record |
| 274 | `include_env` list fan-out | every peer's `secret_open` names the caller and shares one correlation id |
| 275 | test-issuer JWT, group payments-eng | `whoami` shows runner on payments; wrong `aud` → 401; unknown `kid` → one JWKS fetch |
| 276 | add `sub` to `deny_subjects`, SIGHUP or wait one poll | refused on every node |
| 277 | PAT rotation with previous | old and new both work during rollout; peers keep calling; volumes still mount |
| 278 | `auditor`; `viewer` on `*`; `viewer` on a team | auditor reads fleet audit and lists sandboxes, while exec, env and create → 403. Viewer on `*` scrapes `/v1/metrics`. Viewer on a team → 403 on `/v1/metrics`. `/debug/vars` → 403 for all three. |
| 279 | `aerolvm audit search` and `aerolvm access review` over an S3 export | search finds the UC-268 actions and verifies the chain. The review lists the UC-268 token with its last action, flags the UC-272 expired token, and lists every admin. |
| 280 | E2B, Daytona and Runloop SDKs with a team token | sandboxes owned by the team; records name the token |
| 281 | rolling upgrade, mixed `fv` | no `caller`/`request` field and no `api`, `auth_denied` or `identity_config` record written until all members are upgraded; no verify failure on any node; writes start once the last member advertises the new `fv` |
| 282 | `aerolvm login --sso --device` against the test issuer | the saved login works; refresh after expiry |
| 283 | enterprise mode with identity off; with `SB_PAT_SCOPE=any`; then with identity on, `host` scope and no identity file | the first two refuse to boot, each with a clear error; then it boots, and `avm_` tokens work with no OIDC configured |
| 284 | projected Kubernetes service-account token (test issuer playing the cluster issuer) | runner on the bound team; no call to any Kubernetes API during the request |
| 285 | `SB_PAT_SCOPE=host` on `single-node` and `cluster-3-mixed` | PAT through Caddy → 401 with the SSO hint. PAT from a remote host to `private_ip:21212` → 401. PAT from a loopback peer on `127.0.0.1:21212` works and reaches a sandbox owned by another node. SSO and `avm_` tokens work through Caddy and on `private_ip:21212`. A `viewer` token on `*` scrapes `private_ip:21212/v1/metrics`. |
| 286 | MCP TypeScript SDK OAuth client against `/mcp` with the test issuer | 401 carries `resource_metadata`; the client discovers the issuer, gets an access token for the `/mcp` audience, and lists tools as runner on its team; a wrong-audience or opaque token is refused on `/mcp`; the `mcp_audiences` token is refused on `/v1/sandboxes`. On `cluster-3-mixed`, a tool call on a sandbox owned by another node succeeds through the `X-Cluster-Surface: mcp` forward. |
| 287 | open an SSH session to a sandbox | one `api` record with `ref: ssh` and `caller.kind: sandbox_key`; the sandbox's create record names its creator |
| 288 | a request with a bad token from a remote host through Caddy (D12 on) | its `auth_denied` record and `aerolvm_auth_requests_total{origin="public"}` carry the remote IP, not 127.0.0.1; a preview site still serves |
| 289 | `SB_AUDIT_API_FLOOD_CONTROL=coalesce`; one team floods exec on a node it has alone, then a second team creates a sandbox there | alone: identical calls merge and nothing is capped. After the second owner arrives: effective mode `both`, the flood is capped with a `rate_limited` record naming the caller, the mode change is in the chain, and the second team's records are never pushed into a gap. |
| 290 | open `https://<domain>/ui` on a domain install with the test issuer | sign-in completes and `whoami` shows the bound role. On `http://<host>:21212/ui` from another machine, no sign-in buttons, and the HTTPS pointer is shown. |
| 291 | chaos: partition one worker from the server tier for 90 s on `cluster-3-mixed` | after 60 s: `avm_` → 503 `identity data is stale`; `metrics.read` scrape keeps working (D16); OIDC and PAT unaffected; after heal the mirror resyncs within one poll |
| 292 | chaos: kill the Raft leader during a burst of 50 token creates | no two live tokens share a name; every 201 returned a secret for a token that exists; every 503 left a token that is either absent or listed (never a secret for an unapplied token) |
| 293 | chaos: rotate the test issuer's signing key under 1k req/s | ≤ 1 JWKS refetch per minute per node; no 5xx beyond the unknown-kid wait; requests signed with the new key succeed within one refetch |
| 294 | two teams register the same WASM module bytes with no explicit id (T0b) | each gets its own catalogue row; neither sees nor can delete the other's; neither gets an id conflict; a sandbox boot by catalogue id resolves the caller's own row, then an operator-published one |

## 9. pr-review.md axes (pre-filled)

1. **Idempotency.**
   - Token create: unique name per team, so a duplicate gets 409 and two live tokens never share a name.
   - Revoke: 204 also when the token is already gone.
   - Retried API calls write one record per call. That is true: each retry was a real call.
   - Sandbox API idempotency is untouched.
2. **Boot-path latency.** `CreateSandbox` gains a permission check and a buffered audit enqueue: µs, with no I/O. First call: JWKS is fetched at daemon start, not on the request. Only an unknown `kid` waits on the request (≤ 2 s, at most once per minute per issuer), and only after the provider rotates keys.
3. **Lazy bootstrap.** JWKS fetch and the first mirror sync use the `atomic.Bool` plus `sync.Mutex` single-flight latch (`Service.EnsureLayer4Ready` pattern), with tests next to it.
4. **Failure-path consistency.**
   - A token create is one Raft apply, and the secret is returned only after it succeeds.
   - If the apply result is unknown (leader change), the caller gets 503. The token may exist without its secret. The documented recovery: list tokens, find it by name, revoke it by id, then recreate (Section 2, finding 2.4).
   - No caddy writes. Audit records are single appends.
5. **TCP host-port pool and L4.** The host-port pool is untouched. **L4 bootstrap is touched (D12):** `EnsureLayer4`'s fallback route gains `proxy_protocol` behind `SB_L4_FALLBACK_PROXY_PROTOCOL`. There is a regression test in `layer4_bootstrap_test.go` and a call-out in the T10 PR. The `l4Ready` latch is unchanged.
6. **Cluster.**
   - New FSM ops 31 and 32 and a snapshot field, with `fsm_tokens_test.go`.
   - Applies are deterministic: the proposer stamps time, so replay is safe.
   - A follower forwards one hop to the leader. Leader change mid-create → 503 (above).
   - Split brain is not possible beyond Raft's own guarantees. Mirrors only read.
   - The `fv` gate covers rolling upgrades: token ops, and audit fields and kinds (§5.8).
   - **New forwarding markers.** `X-Cluster-PAT-Origin` and `X-Cluster-Surface` are set on every forward path by `cluster.StampForward`, with a call-site test. They are trusted only from live mTLS peers. Replay is safe because they ride on individual requests and are never stored.
   - **Gossip.** Nodes advertise `SB_PAT_SCOPE`, which feeds the drift metric. Split brain cannot widen access: an owner under `host` refuses a missing or `public` origin, whatever the sender advertises.
   - **Leader change** does not affect the markers; they ride on each request.
   - Single node uses the SQLite backend. `Noop` cluster: no mirror, no polls.

## 10. Config (rows for `setup/config-defaults.md`)

| Setting | Default | Why this default |
|---|---|---|
| `SB_IDENTITY_ENABLED` | `false` | Zero change for existing installs. Enterprise mode requires it. |
| `SB_IDENTITY_FILE` | empty | Empty with identity on = tokens-only mode (L7). No OIDC until an operator names a provider. |
| `SB_IDENTITY_SYNC_INTERVAL` | `5s` | Revocation in seconds at 400 req/s fleet-wide. |
| `SB_IDENTITY_MAX_STALE` | `60s` | Fail closed on API tokens after one minute without the server tier. |
| `SB_TOKEN_MAX_TTL` | `8760h` (90 d in enterprise) | No immortal tokens. |
| `SB_AUDIT_API_FLOOD_CONTROL` | `budget` (values: `budget`, `coalesce`, `both`) | Per-install choice (D14). A node hosting more than one owner always applies the budget: `coalesce` runs as `both`. |
| `SB_AUDIT_API_RATE` / `SB_AUDIT_API_BURST` | `20` / `100` per sandbox and caller | The `api` budget, on the existing egress-budget machinery. |
| `SB_AUDIT_API_RECORDS` | `mutations` (values: `off`, `mutations`, `all`) | Answers every "who changed what" question without logging reads. `all` adds plain GETs. `off` is refused in enterprise mode. |
| `SB_AUDIT_EXEC_COMMAND` | `digest` | Commands can carry secrets. |
| `SB_AUDIT_API_DURABLE` | `false` (true in enterprise) | Keeps fsync off the hot path unless asked. |
| `SB_PAT_TOKEN_PREVIOUS` | empty | Only during a rotation. |
| `SB_L4_FALLBACK_PROXY_PROTOCOL` | `false` (install.sh sets `true` together with the 8443 listener wrapper) | Gives sandboxd the real client IP through Caddy (D12). On without the wrapper, HTTPS breaks, so only install.sh flips it. |
| `SB_OPERATOR_VOLUME_SCOPE` | empty (legacy hash) | Pin before rotating the PAT. |
| `SB_PAT_SCOPE` | `any` (`host` required in enterprise mode) | `host` enforces named credentials for people (SSO or scoped tokens): the PAT works only from a loopback peer and from cluster peers (D4, D5). |
| `SB_PUBLIC_API_SOCKET` | `/run/sandboxd-public/api.sock` | Caddy's upstream when `SB_PAT_SCOPE=host`; unused otherwise. The directory is `root:caddy 0750`. |
| `SB_API_HOST` | unchanged (`0.0.0.0` on domain installs) | `host` scope works by peer address, not by bind. |
| `SB_TEAM` | empty | Selects a team for multi-team principals, via the `X-AerolVM-Team` header (D13). Empty = first matching binding. |
| `SB_API_TOKEN` | empty | Alias of `SB_PAT_TOKEN` in all five SDKs and the CLI (T9). It holds any bearer: an `avm_` token, an ID token, or the PAT. |

## 11. Failure modes

| Failure | Effect | Recovery |
|---|---|---|
| Identity provider down | New SSO logins fail; issued ID tokens work until they expire. Tokens and PAT unaffected. | Wait, or use a token. |
| Provider rotates keys | The first request with the new `kid` triggers one fetch. | Automatic. |
| Server tier unreachable | Workers keep their mirror for 60 s, then refuse API tokens with 503. OIDC and PAT unaffected. | Automatic when the server tier returns. |
| Bad identity file at boot | OIDC tokens get 503 with the parse error in `/v1/whoami` and a metric. Tokens and PAT work. | Fix the file; SIGHUP. |
| Bad identity file on reload | Last good is kept, plus a metric. | Fix the file. |
| Identity files differ across nodes | Each node decides for the requests it serves; the hash metric shows the drift. | Ship one file via Terraform or Ansible; alert on the hash label. |
| Clock skew | 60 s leeway on `exp` and `nbf`. | NTP (already required for Raft). |
| Audit queue overflow | A `gap` record with a count, as today. | Existing alert. |
| Leaked token | — | Revoke: ≤ 15 s fleet-wide. The prefix makes it greppable. |
| `SB_PAT_SCOPE=host`, provider down, no admin token | No remote admin access. | SSH to the host and use the host-local listener. Outside enterprise mode, you can also set `any` and restart. |
| `SB_L4_FALLBACK_PROXY_PROTOCOL=true` but the 8443 site has no `proxy_protocol` wrapper (hand-edited Caddyfile) | All public HTTPS fails the TLS handshake. | Boot logs the flag; the runbook says to re-run install.sh, or to set the flag false and restart. |
| One node's `SB_PAT_SCOPE` differs from the rest | Owners under `host` refuse that node's forwarded `public` PAT requests. The drift alert fires. | Set the same scope everywhere (Terraform or Ansible). |
| Public socket missing or wrongly permissioned under `host` | Caddy returns 502 for the whole public API; the host-local listener still works. | Boot fails loudly if it cannot create the socket with `root:caddy 0750`. The runbook checks `stat` on the socket. |

## 12. Founder decisions (2026-10-16)

**Locked:** I3, I4 and I7, with the login architecture in §5.0 (L1–L8). Eng review does not reopen them. **Stand at the written recommendation:** I1, I2, I5, I6, I8, I9 and I10, which the founder left as written.

| # | Question | Decision | Status | Why |
|---|---|---|---|---|
| I1 | Three roles (as posted in #646) or four, adding `auditor`? | **Four.** | recommendation stands | SOC 2 reviewers ask for separation of duties: read the evidence without being able to change it. |
| I2 | One team per principal or session, or several? | **One.** | recommendation stands | It keeps `ownerScope` single-valued: no change to store queries, list fan-out or caches. Multi-team users pick at login. |
| I3 | Check the provider's tokens directly (Kubernetes style), or run a sandboxd login that issues its own sessions? | **Provider tokens, checked locally on every node.** | **locked** (§5.0 L1, L2) | No session store to replicate across 2,000 nodes, no client secret for the CLI, and a pattern buyers know. |
| I4 | Role bindings in a file, or managed by API in Raft? | **File** for OIDC and bindings; **API only** for service tokens. | **locked** (§5.0 L6) | Bindings change rarely and want review. Tokens are minted often. |
| I5 | Exec in audit: digest, full `argv`, or nothing? | **Digest by default,** `full` as an opt-in. | recommendation stands | Commands carry secrets; the digest still proves which command ran. |
| I6 | Accept a rollback floor for the new audit fields, or ship readers one release before writers? | **Rollback floor,** documented. | recommendation stands | Two releases conflicts with landing the stack whole. The floor only bites a downgrade, and there is an escape hatch. |
| I7 | Should enterprise mode require OIDC, or only identity on? | **Identity on only;** tokens-only keeps working. | **locked** (§5.0 L7) | Air-gapped buyers may use tokens only. |
| I8 | Can a team runner mint its own CI tokens? | **Not in v1.** Admin only. | recommendation stands | Self-service needs team-admin delegation, a fifth role. Wait for demand. |
| I9 | SAML or SCIM in v1? | **No.** Document the Keycloak or Dex bridge, plus short token life for deprovisioning. | recommendation stands | Every provider on the target list speaks OIDC. |
| I10 | Require token expiry? | **Yes:** 365 d max by default, 90 d in enterprise. | recommendation stands | Immortal tokens are the first finding in an access review. |

## 13. NOT in scope (and what it would take)

- **Custom roles, or per-resource ACLs.** They need a policy language. Revisit when a buyer names a role the four don't cover.
- **Multi-team sessions.** `ownerScope` would return a set, and every scoped query and fan-out would change.
- **SAML, SCIM.** See I9.
- **Token last-used timestamps.** That is a Raft write per request; use audit search.
- **OS keychain for the CLI.** It is already a CLI follow-up (memory: CLI login stack).
- **SSH key bound to a person.** Needs a key re-issue endpoint (memory: `aerolvm ssh` not built). Until then, SSH is attributed to the sandbox key and, through the create record, to its creator.
- **Per-team quotas (#648).** Its own plan, now unblocked.
- **A live fleet-wide audit query.** That is the SIEM's job, fed by the export.

## 14. Messaging after ship

- `enterprise/index.mdx`: the rows "Single sign-on (SSO)", "Scoped API tokens and roles" and "The API caller's name in audit records" go from *Proposed* to *Shipped (vX.Y)*. The "Who can call the API?" answer changes.
- `enterprise/responsibility.mdx:86,89`: the two limits become controls you configure.
- Discussions #646, #647 and #649: reply with the release and the docs link, then close them.

---

# CEO review: `/plan-ceo-review` 2026-10-16

## Review setup

- **Depth:** implementation-ready. **Working plan:** this file. **Base branch:** `main`. Not committed and no PR (founder instruction).
- **Design reference:** `DESIGN.md` ("Actors and actions"). This plan changes its actor table: "API client" stops being one token holder.
- **Prior deferral this plan touches:** TODOS.md "Metrics-scoped read-only token" (`pkg/api/dashboard.go:27`, the Prometheus scrape holds the PAT).
- **Prior learning applied:** `aerolvm-cli-dep-guard`. `cmd/aerolvm` cannot import server packages, so the token format/checksum and the discovery document types live in `pkg/`, not `internal/`.

## Decision ledger

| ID and owner | Contract and evidence | Current | Proposed | Status | Exact approval and scope |
|---|---|---|---|---|---|
| F-LOGIN (founder) | §5.0 L1–L8; §12 I3, I4, I7 | as written in §5.0 | — | approved | Founder message 2026-10-16: "Founder decision on the login architecture … Do not reopen it." Scope: L1–L8, I3, I4, I7. |
| F-RECS (founder) | §12 I1, I2, I5, I6, I8, I9, I10 | the written recommendations | — | approved | Same message: "Leave I1, I2, I5, I6, I8, I9, and I10 at the plan's written recommendations." |
| F-NOCOMMIT (founder) | git state | uncommitted | — | approved | Same message: "Do not commit or open a PR." |
| R-EXCHANGE (founder) | §5.7 Google dashboard sign-in. L3 requires Google for the dashboard. Third-party tests report Google's token endpoint requires `client_secret` for web clients even with PKCE. Google Identity Services (`google.accounts.id.initialize`) returns an ID token to the browser configured with only a client id. | Google Identity Services path for `kind: google`; no relay, no server secret (§5.7, T8) | — | approved | D2 answered 2026-10-16: "Use Google Identity Services for Google (recommended)". Scope: §5.7 Google bullet and the T8 row; the relay endpoint and `client_secret_file` are removed. |
| S-SSH (founder) | §5.9 SSH session records attribute to the sandbox key, not a person (§13: key-to-person binding not built) | kept in T5 | — | approved | D3 answered 2026-10-16: "Keep it in scope (recommended)". Scope: the SSH session-open record in §5.9/T5, unchanged. |
| E-PATCONF (founder) | 0A premise gap: SSO not *enforced* while the PAT works from anywhere. Boundary: L8 keeps the default unchanged. | `SB_PAT_SCOPE=host` opt-in, public socket for Caddy (§5.11, T10, §10, UC-285, §11) | — | approved | D4 answered 2026-10-16: "Add to this plan's scope (recommended)". Scope: the opt-in flag, listener split and wiring. Enterprise-mode forcing is not included and is asked separately (E-PATCONF-ENT). |
| E-PATCONF-ENT (founder) | Whether enterprise mode requires `SB_PAT_SCOPE=host` | enterprise mode refuses `any` (§5.12, §10, UC-283) | — | approved | D5 answered 2026-10-16: "Add to this plan's scope (recommended)". Scope: the §5.12 check, its boot error, and the release-note migration. |
| E-METRICS (founder) | TODOS.md "Metrics-scoped read-only token". I1 fixes four roles, so this adds no new role. | `metrics.read` for any role bound to `*`; `/debug/vars` stays `fleet.admin` (§5.3, T2, T11, UC-278) | — | approved | D6 answered 2026-10-16: "Add to this plan's scope (recommended)". Scope: the permission, its role-table row, the scrape-config move, and closing the TODOS.md item. |
| E-ACCESSREVIEW (founder) | SOC 2 CC6.2/6.3 access reviews; reuses T3 token list and T5 audit search | `aerolvm access review` (§5.10, T5b, UC-279) | — | approved | D7 answered 2026-10-16: "Add to this plan's scope (recommended)". Scope: the CLI command, its report contents and flags; no server endpoint. |
| E-EXPIRYWARN (founder) | CLI UX | stderr warning under 7 d; sign-in hint on refresh failure (§5.6, T7) | — | approved | D8 answered 2026-10-16: "Add to this plan's scope (recommended)". Scope: CLI only; no server header. |
| E-DENYHINT (founder) | §5.3 403 names only the permission | 403 names the caller's role and team and the allowing role; "no binding" lists the caller's claims; 404 bare (§5.3, §5.5, T2) | — | approved | D9 answered 2026-10-16: "Add to this plan's scope (recommended)". Scope: 403 messages and the v1 403 body fields (T2), and the "no binding" hint (T6); facades keep their body shape. |
| E-MCPOAUTH (founder) | The MCP CEO review (2026-10-04, D2) kept OAuth at Phase 4 behind a demand checkpoint. Changed assumption: §5.5 makes sandboxd an OIDC resource server. | §5.14 and T13 in this plan; removed from §13 | — | approved | D10 answered 2026-10-16: "Add to this plan's scope" (against the Defer recommendation). Scope: §5.14 and T13 as written, and UC-286. It reopens the MCP plan's Phase 4 timing; no other MCP plan decision changes. |
| A1 (founder, Section 1) | Finding 1.1: the caddy-l4 fallback hides the client IP (`pkg/caddy/client.go:1203-1210`) | PROXY v2 on the fallback plus the 8443 listener wrapper, gated by `SB_L4_FALLBACK_PROXY_PROTOCOL` set by install.sh (§5.9, §5.11, T10, §9.5, §10, §11, UC-288) | — | approved | D12 answered 2026-10-16: "PROXY protocol on the fallback (recommended)". Scope: the fallback route, the listener wrapper, the flag, the regression test and the call-out. |
| A3 (founder, Section 1) | Finding 1.3: `--team` has no wire mechanism (I2) | `X-AerolVM-Team` selects among matching bindings, never grants (§5.3, T6–T9, §10) | — | approved | D13 answered 2026-10-16: "Team-selection header (recommended)". Scope: the header, its selection rule, the CLI/dashboard/SDK senders, and the audit team field. Amended 2026-10-17 by design review DR2: the dashboard sender is dropped; CLI and SDK senders unchanged. |
| A5 (founder, Section 1) | Finding 1.5 / 0G HOLD 1: two flood controls | `SB_AUDIT_API_FLOOD_CONTROL=budget\|coalesce\|both`, default `budget`; a node with more than one owner always budgets (`coalesce` → `both`) (§5.9, §6, §10, T5, UC-289) | — | approved | D14 answered 2026-10-16 (custom): "Build all three flood controls, and let me choose per customer install. Default is the existing audit budget… On a node that hosts more than one customer, budget always applies. Coalesce-only is honored only when that customer has the node to themselves… Document the setting and test all three. Default installs, including identity off, use budget." Interpretation recorded: a customer is a sandbox owner; on a shared node `coalesce` runs as `both`. |
| A6 (founder, Section 1) | Finding 1.6: the env-token expiry check exceeds D8's scope | kept: one `whoami` per token per day, stderr only (§5.6, T7) | — | approved | D15 answered 2026-10-16: "Keep the CI warning (recommended)". Scope: the env-token check and its T7 test. |
| S2a (founder, Section 2) | Finding 2.1: worker scrapes fail once the mirror is stale | stale mirror still accepts `metrics.read`-only routes; counted and logged (§5.4, T3) | — | approved | D16 answered 2026-10-16: "Keep metrics flowing (recommended)". Scope: the `metrics.read` exception, its metric and log, and the T3 tests. |
| S2b (founder, Section 2) | Finding 2.2: bare 401s for SSO and `avm_` failures | RFC 6750 `error_description` + `reason` for `avm_`/JWT; PAT and managed 401 unchanged (§5.2, T1) | — | approved | D17 answered 2026-10-16: "Standard reason in the 401 (recommended)". Scope: the reasons list, the non-disclosure rule, the metric and the tests. |
| S3a (founder, Section 3) | Finding 3.1: the dashboard has no HTTPS origin | `/ui /ui/*` in Caddy's `@api`; sign-in only on HTTPS or localhost (§5.7, T8, UC-290) | — | approved | D18 answered 2026-10-16: "Serve /ui through Caddy on HTTPS (recommended)". Scope: the matcher change, the sign-in visibility rule and the tests. |
| S3b (founder, Section 3) | Finding 3.2: no CSP on `/ui` while it holds tokens | CSP with a boot-computed script hash (§5.7, T8) | — | approved | D19 answered 2026-10-16: "Add the CSP (recommended)". Scope: the header as written in §5.7, and its tests. |
| S3c (founder, Section 3) | Finding 3.3: identity-file changes leave no evidence | `identity_config` chain record with a binding diff on each effective reload or changed boot; listed in the access review (§5.5, §5.10, T6) | — | approved | D20 answered 2026-10-16: "Record each change with a binding diff (recommended)". Scope: the record kind, its contents, the access-review section and the tests. |
| S6a (founder, Section 6) | Finding 6.4: no load, fuzz or chaos verification | benchmarks with CI budgets, three fuzz targets, the spray test, chaos UCs 291–293 (T1, T3, T5, T6, T12, §8) | — | approved | D21 answered 2026-10-16: "Benchmarks, fuzz, spray and chaos (recommended)". Scope: exactly those additions. |
| S8a (founder, Section 8) | Finding 8.1: the identity features have scattered metrics, two alerts, no dashboard and no per-alert runbook | §5.15: metrics, six alerts, the Grafana row, runbook entries, trace attributes, logs, `whoami --explain` (T1, T7, T10) | — | approved | D22 answered 2026-10-16: "Full pack plus whoami --explain (recommended)". Scope: exactly §5.15. |

Approval readiness: PASS. Checked rows: F-LOGIN, F-RECS, F-NOCOMMIT (founder message 2026-10-16); R-EXCHANGE (D2); S-SSH (D3); E-PATCONF (D4); E-PATCONF-ENT (D5); E-METRICS (D6); E-ACCESSREVIEW (D7); E-EXPIRYWARN (D8); E-DENYHINT (D9); E-MCPOAUTH (D10); A1 (D12); A3 (D13); A5 (D14, custom); A6 (D15); S2a (D16); S2b (D17); S3a (D18); S3b (D19); S3c (D20); S6a (D21); S8a (D22). Unresolved, outside accepted work: 5.1 (`/plan-eng-review`). 9.2 was settled by #724 merging (backfill to `""`).

## Step 0

### 0A. Premise

- **Real problem.** A buyer's security review fails on three rows: per-person SSO, least privilege, and attribution. The do-nothing cost is concrete. The enterprise matrix keeps *Proposed* on its Identity and Audit rows (`enterprise/index.mdx:82-85`). Buyers must build their own authenticating gateway and audit trail (`responsibility.mdx:86,89`), and most won't. H1 also stays open in the managed build.
- **Direct or proxy?** The plan answers all three rows directly. **One gap in the premise:** questionnaires ask whether SSO is *enforced*, not only offered. The PAT still works for anyone who holds it, and §5.11 only alerts on human PAT use. A reviewer will ask how a person is stopped from skipping SSO with the shared token. See the 0G candidate "PAT confinement". *(Written before D4 and D5, which added the enforcement.)*

### 0B. Existing code leverage

The §5.13 reuse map holds, and each piece was checked in §2:

- the egress operator watcher, for the identity file;
- the egress-profile dual backend and the `fv` gate, for the token store;
- the placement-feed cursor, for the mirror;
- `ownerScope`, for teams;
- the secret-audit chain, witness and export, for evidence;
- `auditlog.VerifyNode`, for search;
- the `controlplane.Validator` seam.

Nothing is rebuilt. One refactor replaces a copy: the three `require*Auth` wrappers (`pkg/api/middleware.go:115-168`) collapse into one function.

### 0C. Dream state

```
  CURRENT STATE                    THIS PLAN                           12-MONTH IDEAL
  one shared PAT per server  --->  named principals, 4 roles,   --->  security team signs off in one review:
  audit names the server           service tokens, OIDC SSO           SSO enforced, no long-lived secrets
  create/exec/delete unaudited     (CLI + dashboard + workload),      anywhere (workload identity), an
  dashboard: paste the PAT         caller in every chained record,    access-review report generated from
                                   api records for every mutation     the chain, per-team quotas and
                                                                      policy, OAuth for MCP connectors
```

The plan moves straight toward the ideal. What it left for later when this was written: enforced SSO, an access-review report, per-team quotas (#648), per-team policy defaults, and MCP OAuth. D4–D10 then added enforced SSO, the access review and MCP OAuth. Per-team quotas and policy defaults remain for later.

### Landscape (web search; Aside unavailable)

- **[Layer 1]** The Kubernetes structured authentication config (KEP-3331): an ordered list of JWT issuers, each with claim mappings and validation rules, hot-reloaded from one file. It rejects usernames with the reserved `system:` prefix. §5.5 matches this shape. Our principal ids are prefixed (`oidc:<issuer>:`), so a provider username can never collide with `operator`, `node:` or `system:`.
- **[Layer 2]** The most cited OIDC bug is sending the ID token to an API whose audience it was not minted for. Opaque access tokens would need an introspection call on every request, which L2 rules out. Kubernetes accepts ID tokens anyway, by setting the audience to the client id. The plan follows Kubernetes, but §5.5 does not yet say which token types it accepts (finding for Section 1).
- **[Layer 3]** Competing hosted sandbox platforms put SSO on their own console. None of the search results showed a self-hosted sandbox API with SSO, roles and a witnessed, caller-attributed audit chain in the free build. That combination, building on the open audit witness shipped in v0.6.7, is the differentiation: provable who-did-what, not just a log.

Sources: [KEP-3331](https://www.kubernetes.dev/resources/keps/3331/), [kube-apiserver config v1](https://v1-35.docs.kubernetes.io/docs/reference/config-api/apiserver-config.v1/), [OIDC token validation pitfalls](https://ssojet.com/blog/oidc-token-validation-id-token-access-token), [E2B security](https://e2b.dev/security.md), [Modal enterprise SSO change](https://pricingsaas.com/companies/modal/diffs/2026D254).

### Taste calibration

- **Follow:** `plans/open-audit-witness.md` ("what it proves, and what it does not": claims bounded honestly); the egress-profile dual backend (`internal/service/egress_profiles.go:59-78`); the operator-file watcher (`internal/egress/operator/watch.go`).
- **Avoid:** three copy-pasted auth wrappers (`pkg/api/middleware.go:115-168`); replicated state whose owner and lifetime are fuzzy (memory: `capacity_lease.go` regressed twice in the #374 rounds).

### 0E. Mode

**SELECTIVE EXPANSION** (D1, answered 2026-10-16; recommendation was SCOPE REDUCTION). Current scope is hardened first, then extras are offered one at a time.

### 0G. Selective expansion analysis

**HOLD-scope checks:**

1. **Complexity.** About 130 changed files (estimate), with four new moving parts: the token mirror, the OIDC verifier with its JWKS cache, the `api` recorder, and its one-second coalescer. The identity watcher is reused, not new. The token mirror is locked (L5), and the verifier is the feature itself. **The coalescer duplicates existing machinery.** `internal/service/secret_audit_quota.go` already runs a per-sandbox token bucket and writes coalesced `rate_limited` markers for egress records. *Pending for Section 1:* fold `api` records into that budget, keyed by sandbox and caller, instead of adding a second flood control.
2. **Minimum for the goal.** The three questionnaire rows need T1–T8. T8 is in because L3 locks the dashboard. T11 and T12 are needed to ship and prove it. T9 follows the repo's SDK-parity rule. T10 is needed because L7 adds an enterprise-mode check and H2 blocks rotation. T0 is standalone. **Deferrable without blocking the goal:** SSH session records (S-SSH). They name a sandbox key, not a person, until key-to-person binding exists (§13).
3. **Invariants kept:** §5.0 L1–L8 and G6 (zero change with identity off).

**10x check.** The same build, plus three things, makes AerolVM the sandbox platform a security team signs off on in one meeting:
- named credentials *enforced* for people, not just offered: SSO or a scoped token, never the shared token from outside the host (E-PATCONF);
- a scrape credential that can read but never create, run or delete (E-METRICS);
- quarterly access-review evidence from one command (E-ACCESSREVIEW).

Each one reuses this plan's principal, role and chain. None adds a store.

**Delight scan:**
- warn before a saved login or token expires (E-EXPIRYWARN);
- a 403 that says which binding to ask for (E-DENYHINT);
- `whoami` shown in the dashboard header (already in T8);
- "created by" on dashboard sandbox cards (not proposed: it needs a `created_by` column and a v1 response change).

**Platform potential:** MCP OAuth for claude.ai and ChatGPT connectors (E-MCPOAUTH). Not proposed now: an OCSF-shaped export for SIEMs, and per-team default egress profiles bound in the identity file.

## Answered: R-EXCHANGE (D2 → B, Google Identity Services)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| Google works for dashboard sign-in | approved (F-LOGIN L3) | yes, via relay | yes, via relay | yes, via Google Identity Services |
| Confidential client secret on the server | L1 forbids it for the CLI only; pending for the dashboard | yes, in the identity file on every node | yes | no |
| sandboxd takes part in a login | §5.0 spirit: the provider logs the person in | relays the code exchange | relays the code exchange | none |
| Okta, Entra ID, Keycloak dashboard path | approved (L3) | SPA code flow with PKCE, no secret | unchanged | unchanged |
| Provider-specific dashboard code | pending | none | none | one Google-only path |
| External script on `/ui` | pending | none | none | `accounts.google.com/gsi/client` |
| Google session length in the dashboard | pending | refresh token via relay | refresh token via relay | ID token about 1 h, silent re-issue via auto-select |
| API check of the token | approved (L1, L2) | offline JWT verify | unchanged | unchanged |
| Tests | pending | handler test for the relay | handler test for the relay | dashboard token-handling test; no relay to test |

Question: D2 — R-EXCHANGE: How should the dashboard sign people in with Google?
Project/branch/task: plans/identity-and-access.md §5.7, dashboard SSO (T8).
ELI10: Google won't finish a normal browser sign-in unless the app sends a secret password that belongs to the app. The plan has the server add that secret for the dashboard. That puts the secret in the identity file on every node, and sandboxd takes a small part in the login. Google also offers its own sign-in button that hands the browser a signed ID token with no secret at all. sandboxd would then check that token like any other.
Stakes if we pick wrong: Keep the relay, and a confidential Google secret sits on every node, and sandboxd is part of the login after all. Switch to Google's button, and Google dashboard users re-sign in about hourly, and the dashboard carries one Google-specific code path.
Recommendation: B because it keeps sandboxd completely out of the login and keeps any confidential secret off the nodes, while Google still works on the dashboard as L3 requires.
Note: options differ in kind, not coverage — no completeness score.
Net: You are trading all-day Google dashboard sessions against keeping every confidential secret, and every part of the login, off AerolVM's nodes.
Header: Google login
A) Keep the dashboard relay
Keep `/ui/auth/exchange`: the browser sends Google's code and PKCE verifier, and the server adds the client secret and returns Google's tokens unchanged. Effort S, risk medium, reuses the plan as written; verified by a handler test.
✅ One generic code flow for every provider, with refresh tokens, so Google users stay signed in all day
✅ Already written into §5.7 and T8, so no plan rework and no provider-specific dashboard code
❌ A confidential Google client secret is copied into the identity file on every node in the fleet
B) Use Google Identity Services for Google (recommended)
For Google only, the dashboard uses Google's sign-in button, which returns a signed ID token to the browser with just the client id; drop the relay. Effort S, risk low, reuses the existing offline JWT check; verified by a dashboard token-handling test.
✅ No confidential secret anywhere on the server, and sandboxd never takes part in a login, matching §5.0 exactly
✅ Google still works on the dashboard as L3 requires, and the API checks the token exactly like Okta's
❌ Google dashboard sessions last about an hour with silent re-issue, and `/ui` loads one Google script

## Answered: S-SSH (D3 → keep in scope)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| SSH session open writes a chain record (`kind: api`, `ref: ssh`) | pending (T5) | in T5 | deferred to TODOS.md | kept in T5 |
| Caller on that record | pending | `sandbox_key:<sandbox>`; creator found via the create record | — | same |
| Exec, files and sessions through the API are recorded | approved scope (G5, T5) | yes | unchanged | unchanged |
| Docs claim about SSH | pending | "SSH sessions are recorded" | must say "SSH sessions are not in the audit chain yet" | "recorded, attributed to the sandbox key" |
| Key-to-person binding | NOT in scope (§13) | not built | not built | not built |
| Tests | pending | gateway test: session open emits one record | none | gateway test: session open emits one record |

Question: D3 — S-SSH: Keep the SSH session audit record in T5, or defer it?
Project/branch/task: plans/identity-and-access.md §5.9, API action records (T5).
ELI10: People can open a shell in a sandbox over SSH with the sandbox's own key, without touching the API. The plan writes one audit record when such a session starts. It can only name the sandbox key, not a person, because keys are not tied to people yet. The person is found through the sandbox's create record. Deferring it shrinks T5 a little. But then SSH becomes the one way to run commands that leaves no record.
Stakes if we pick wrong: Defer it, and an auditor finds an exec path with no record, and our docs must admit it. Keep it, and T5 carries one more small emit point and test.
Recommendation: B because it is a small change, and without it SSH is the one way to run commands that is missing from the evidence we tell auditors is complete.
Note: options differ in kind, not coverage — no completeness score.
Net: You are trading a slightly smaller T5 against having no unrecorded way to run commands in a sandbox.
Header: SSH record
A) Defer this item to TODOS.md
Drop the SSH session record from T5 and add a TODOS.md entry tied to key-to-person binding. Effort S, risk low, zero implementation work now; docs state the gap.
✅ T5 gets slightly smaller, and the record ships later with a real person attached once keys bind to people
✅ No record that names only a key, which an auditor could read as weaker evidence than the API records
❌ SSH stays a way to run commands with no audit record, and the docs must say so plainly
B) Keep it in scope (recommended)
Keep one record at SSH session open in T5, naming the sandbox key; the create record names the person. Effort S, risk low, reuses the T5 recorder; verified by a gateway test.
✅ Every way to run a command in a sandbox leaves a hash-chained record, so the evidence claim holds
✅ Small change: one emit at session open in the existing gateway, using the recorder T5 already builds
❌ The record names a key, not a person, until key-to-person binding lands (§13)

## Answered: E-PATCONF (D4 → add)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Default PAT behavior | approved (F-LOGIN L8) | accepted everywhere | unchanged | unchanged | unchanged |
| `SB_PAT_SCOPE=host` opt-in: PAT only from mTLS peers and a host-local admin listener | pending | not in plan | added (T10) | TODOS.md | NOT in scope |
| Caddy's public upstream gets its own socket when the flag is set, so the two listeners differ (install.sh, `packaging/Caddyfile.template`) | pending | not in plan | added | deferred | none |
| Ops scripts and runbooks calling `http://127.0.0.1:21212` with the PAT | existing (`scripts/sandboxd-node-lifecycle.sh:100`, `cluster-init.sh:494`) | work | keep working (host-local listener) | unchanged | unchanged |
| Remote Prometheus scrape with the PAT (`setup/obs/prometheus.yml.tftpl:14-16`) | existing | works | needs E-METRICS or an admin token when the flag is on | unchanged | unchanged |
| Enterprise mode forces the flag | not proposed here | — | separate question, only if A | — | — |
| Answer to "is SSO enforced for people?" | 0A premise gap | "no: the shared token skips it" | "yes, with `SB_PAT_SCOPE=host`" | "no, planned" | "no" |
| Tests | pending | — | listener-split tests; PAT refused on the public upstream; peers and host-local accepted; UC | — | — |

Question: D4 — E-PATCONF: Add an opt-in mode that confines the operator token to the host and cluster peers?
Project/branch/task: plans/identity-and-access.md §5.11 (PAT), T10.
ELI10: After this plan ships, people sign in with SSO. But anyone holding the old shared operator token can still skip SSO from anywhere on the internet. Security questionnaires ask whether SSO is *enforced*. With this opt-in setting, the shared token works only between cluster nodes and from the server itself, through its local port, which the setup scripts already use. Remote people must use SSO or a named token. Caddy forwards public traffic on that same local port today, so with the flag on, public traffic moves to its own socket. Otherwise the two can't be told apart.
Stakes if we pick wrong: Skip it, and the honest questionnaire answer stays "SSO is optional". Add it, and install-time Caddy wiring changes when the flag is on. A remote Prometheus scrape that uses the shared token breaks until it moves to a scoped token.
Recommendation: A because it turns "SSO offered" into "SSO enforced", the questionnaire row this plan would otherwise still fail, without changing the default (L8).
Note: options differ in kind, not coverage — no completeness score.
Net: You are trading one more install-time listener split against being able to say SSO is enforced.
Header: Enforce SSO
A) Add to this plan's scope (recommended)
Add `SB_PAT_SCOPE=host` (default `any`) to T10: the PAT works only from mTLS peers and a host-local admin listener; Caddy's upstream moves to its own socket when set. Effort M, risk medium, reuses the existing listeners and install.sh wiring; verified by listener tests plus a live UC.
✅ Lets a buyer answer "yes, SSO is enforced for people" while setup scripts and runbooks keep using the token on the host
✅ Default is untouched, so existing installs, single-node and local Docker behave exactly as today (L8)
❌ Changes install-time Caddy wiring when the flag is on, and a remote PAT scrape must move to a scoped token
B) Defer to TODOS.md
Record it in TODOS.md with the trigger "first buyer asks whether SSO is enforced"; ship SSO as optional first. Effort S, risk low, zero implementation work now.
✅ No change to Caddy wiring or listeners in this already large stack
✅ The idea and its design (listener split, scrape dependency) are written down for later
❌ Until it ships, the honest answer to "is SSO enforced?" is no, because the shared token skips it
C) Skip
Leave it out; rely on the §5.11 alert on PAT use as the control. Effort S, risk low, zero implementation work.
✅ Smallest stack; the alert still shows every human use of the shared token
✅ No new setting to document or test
❌ Detection only, never prevention, and the questionnaire row stays a "no" with no plan to fix it

## Answered: E-PATCONF-ENT (D5 → add)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| `SB_PAT_SCOPE=host` exists as an opt-in | approved (D4) | in T10 | unchanged | unchanged | unchanged |
| Enterprise mode requires identity on | approved (F-LOGIN L7) | in §5.12 | unchanged | unchanged | unchanged |
| Enterprise mode refuses to boot with `SB_PAT_SCOPE=any` | pending | no | yes (§5.12, T10, UC-283) | TODOS.md | NOT in scope |
| Upgrade of an existing enterprise-mode install (v0.6.7+) | existing users | — | must switch Caddy to the public socket and move remote PAT tools (scrape, dashboard) to tokens or SSO, in the same upgrade where L7 already requires identity on | only L7's change | only L7's change |
| Enterprise matrix claim | pending | — | "enterprise mode enforces SSO" | "SSO can be enforced" | "SSO can be enforced" |
| Tests | pending | — | config test (enterprise + `any` → boot error); UC-283 extended | — | — |

Question: D5 — E-PATCONF-ENT: Should enterprise mode require the confined operator token?
Project/branch/task: plans/identity-and-access.md §5.12 (enterprise mode), T10.
ELI10: You just added an opt-in switch that stops the shared operator token from working outside the server. Enterprise mode is the "strict settings an auditor expects" switch, and it already will require identity on (L7). If it also forces this new switch, then "enterprise mode" means "SSO is enforced", a clean claim for buyers. The cost lands on people already running enterprise mode. When they upgrade, they must re-point Caddy and move remote tools that use the shared token, such as a Prometheus scrape, to a named token. They already have to turn identity on in the same upgrade.
Stakes if we pick wrong: Force it, and an enterprise-mode upgrade refuses to boot until Caddy is re-pointed and remote tools are moved. Don't force it, and enterprise mode can still run with SSO optional, so the strict mode doesn't guarantee the questionnaire answer.
Recommendation: A because enterprise mode exists to guarantee the auditor-facing answers, and its upgrade already requires action under L7, so this adds one step to a migration users must do anyway.
Note: options differ in kind, not coverage — no completeness score.
Net: You are trading one more upgrade step for enterprise-mode users against a strict mode that actually guarantees enforced SSO.
Header: Enterprise PAT
A) Add to this plan's scope (recommended)
Enterprise mode refuses to boot unless `SB_PAT_SCOPE=host`, with an error that names the Caddy and token steps; the release notes carry the migration. Effort S, risk medium, reuses the §5.12 checks; verified by a config test and UC-283.
✅ "Enterprise mode enforces SSO for people" becomes a true, testable claim on the enterprise matrix
✅ One more line in the existing enterprise-mode checks, landing in the same upgrade that already requires identity on
❌ Existing enterprise-mode installs must re-point Caddy and move any remote PAT tools before the upgrade boots
B) Defer to TODOS.md
Keep the switch opt-in everywhere for now; record "enterprise mode forces host scope" in TODOS.md with the trigger "first enterprise-mode user asks for enforced SSO". Effort S, risk low, zero implementation work now.
✅ Enterprise-mode upgrades need only the identity change L7 already requires
✅ Gives existing enterprise users a release to adopt the switch on their own
❌ Enterprise mode does not guarantee enforced SSO, so docs must say "can be enforced", not "is enforced"
C) Skip
Leave enterprise mode as it is; the switch stays opt-in with no plan to force it. Effort S, risk low, zero implementation work.
✅ No extra upgrade step and nothing to document for enterprise mode
✅ Operators keep full choice over their Caddy wiring
❌ The strict mode never covers enforced SSO, a gap a reviewer may point at

## Answered: E-METRICS (D6 → add)

*Note:* the grid below says "T2 + T10 docs". The body puts the TODOS.md closure and the scrape-config move in T11.

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Four built-in roles, no new role | approved (F-RECS I1) | four | four | four | four |
| `GET /v1/metrics` permission | §5.3 | `fleet.admin` (admin only) | new `metrics.read`, held by any role bound to `*` (viewer@\*, runner@\*, auditor, admin) | `fleet.admin` | `fleet.admin` |
| `/debug/vars` (expvar, includes process internals) | §5.3 | `fleet.admin` | stays `fleet.admin` | unchanged | unchanged |
| Team-bound roles | §5.3 | no metrics | still none (metrics are fleet-wide counts) | unchanged | unchanged |
| Remote Prometheus scrape under enterprise mode (D5 forces `SB_PAT_SCOPE=host`) | approved (D5) | — | an expiring `viewer` token on `*` | needs an admin token | needs an admin token |
| TODOS.md "Metrics-scoped read-only token" | prior deferral | open | closed by this plan (T2 + T10 docs) | stays open | stays open |
| Tests | pending | — | role-matrix rows for `metrics.read`; viewer@\* scrape works; team viewer 403 | — | — |

Question: D6 — E-METRICS: Let any fleet-wide role read /v1/metrics, so a Prometheus scrape needs no admin token?
Project/branch/task: plans/identity-and-access.md §5.3 (roles), T2; closes the TODOS.md "metrics-scoped read-only token" item.
ELI10: Prometheus pulls numbers from `/v1/metrics` every few seconds, so its credential sits in a config file. Today that credential is the all-powerful shared token. The plan as written makes metrics admin-only. Under the enterprise mode you just approved, the scrape would then need an admin token. Leak that file, and someone can delete every sandbox. This change adds a "read metrics" permission. A fleet-wide viewer token, read-only and expiring, can then do the scrape. Still four roles, no new one.
Stakes if we pick wrong: Skip it, and every Prometheus setup holds an admin credential, the exact risk the TODOS.md item was opened for. Add it, and fleet-wide viewers can also read fleet counters, which is harmless.
Recommendation: A because D5 forces remote scrapes off the shared token, and without this the only option left is an admin token sitting in a Prometheus config.
Note: options differ in kind, not coverage — no completeness score.
Net: You are trading a small change to the role table against every scrape config holding admin power.
Header: Metrics read
A) Add to this plan's scope (recommended)
Add a `metrics.read` permission on `GET /v1/metrics`, held by any role bound to `*`; `/debug/vars` stays admin-only. Effort S, risk low, reuses the T2 permission table; verified by role-matrix tests and a scrape check in UC-278.
✅ A leaked Prometheus config can read counters but cannot create, exec or delete anything
✅ Closes the open TODOS.md item with no new role, keeping I1's four roles intact
❌ Fleet-wide viewer and runner tokens can also read fleet-wide counters, slightly widening what they see
B) Defer to TODOS.md
Keep metrics admin-only; leave the TODOS.md item open with the trigger "first enterprise-mode scrape". Effort S, risk low, zero implementation work now.
✅ The role table stays exactly as written, with metrics behind admin
✅ The item stays tracked with its original context
❌ Under enterprise mode every remote scrape must hold an admin token until this ships
C) Skip
Metrics stay admin-only permanently; scrapes use an admin token. Effort S, risk low, zero implementation work.
✅ Simplest role table, with no new permission to test
✅ No change to who can see fleet counters
❌ Every scrape credential is an admin credential, the risk the TODOS.md item describes

## Answered: E-ACCESSREVIEW (D7 → add)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| `aerolvm audit search` over the export, verifying chains | approved scope (T5) | in T5 | unchanged | unchanged | unchanged |
| `aerolvm token list` (`token.read`: auditor, admin) | approved scope (T3) | in T3 | unchanged | unchanged | unchanged |
| `aerolvm access review --export <dir\|s3://…> --since 90d [--identity-file f] [--format md\|csv]` | pending | not in plan | added (new task T5b, after T5) | TODOS.md | NOT in scope |
| Report contents | pending | — | every live token (name, role, team, creator, expiry); every principal seen in the window with last action and counts by kind; flags for unused tokens, expiry within 30 d, admins, and denied attempts; bindings from the identity file when given | — | — |
| What it cannot know | pending | — | people bound by the provider who never called the API; the report says so | — | — |
| New server endpoint | pending | — | none: built from `GET /v1/tokens` and the export | — | — |
| CLI package rule | learning `aerolvm-cli-dep-guard` | — | code in `cmd/aerolvm` + `pkg/auditlog` | — | — |
| Tests | pending | — | fixture export + token list → golden Markdown/CSV; tampered batch → FAIL | — | — |

Question: D7 — E-ACCESSREVIEW: Add an `aerolvm access review` command that produces the quarterly access-review evidence?
Project/branch/task: plans/identity-and-access.md §5.10 (answering the auditor); new task T5b.
ELI10: Every SOC 2 company must show, every quarter, who has access and whether it is still needed. Today that is a spreadsheet someone fills in by hand. This plan already builds the two raw pieces: a token list and a tamper-checked search of the audit export. This command joins them into one report: each token and person, their role and team, what they did recently, and warnings like "this admin token was never used" or "expires in 2 weeks". The output is a Markdown or CSV file the customer can hand to their auditor.
Stakes if we pick wrong: Skip it, and customers still assemble access reviews by hand from two commands. Add it, and the stack grows by one medium CLI task.
Recommendation: A because it turns pieces this plan already builds into the evidence a security team actually files, with no new server endpoint or store.
Note: options differ in kind, not coverage — no completeness score.
Net: You are trading one medium CLI task against handing customers their quarterly access-review evidence from one command.
Header: Access review
A) Add to this plan's scope (recommended)
Add T5b: `aerolvm access review` joins the token list with the verified export into a Markdown/CSV report with unused, expiring and admin flags. Effort M, risk low, reuses T3's token list and T5's export reader; verified by golden-file tests over a fixture export.
✅ Customers get filed-ready SOC 2 access-review evidence from one command, tamper-checked as it is built
✅ No new server endpoint, table or replicated state: only CLI code over pieces already in the plan
❌ One more medium task in the stack, and it only sees principals who appear in the export
B) Defer to TODOS.md
Record it in TODOS.md with the trigger "first customer asks for access-review evidence"; ship search and token list first. Effort S, risk low, zero implementation work now.
✅ Keeps the stack at its current size while the raw pieces still ship
✅ The report's design and data sources are written down for later
❌ Customers build access reviews by hand from two commands until it ships
C) Skip
Leave access reviews to the customer's own tooling over the export. Effort S, risk low, zero implementation work.
✅ Smallest scope; SIEM users may already have a report
✅ No report format to keep stable across releases
❌ No turnkey evidence, which is what wins the security reviewer this plan targets

## Answered: E-EXPIRYWARN (D8 → add)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Token expiry required, max 365 d / 90 d in enterprise | approved (F-RECS I10) | in §5.4 | unchanged | unchanged | unchanged |
| `whoami` returns the token's expiry | approved scope (T1) | in T1 | unchanged | unchanged | unchanged |
| CLI warns on stderr when the saved `avm_` token expires within 7 d | pending | not in plan | added to T7 (expiry cached from `whoami` at login, refreshed at most daily) | TODOS.md | NOT in scope |
| CLI says "sign in again with `aerolvm login --sso`" when an SSO refresh fails | pending | not in plan | added to T7 | TODOS.md | NOT in scope |
| Server response headers | v1 soft-freeze | none | none added | none | none |
| Machine-readable output (`--json`, MCP) | existing contract | unchanged | warning on stderr only, never in stdout or JSON | — | — |
| Tests | pending | — | CLI tests: 6 d → warning, 8 d → none, `--json` stdout unchanged, refresh failure → hint | — | — |

Question: D8 — E-EXPIRYWARN: Should the CLI warn before a saved token expires, and say how to sign in again when SSO refresh fails?
Project/branch/task: plans/identity-and-access.md §5.6 (CLI), T7.
ELI10: Every service token now has an expiry date. That is good for security, but it means CI and people get surprised when a token dies on a Friday night. With this change, the CLI prints one line on the error stream when the saved token has less than a week left. When an SSO session can no longer refresh, it says exactly which command signs you back in. Nothing changes in the API or in JSON output.
Stakes if we pick wrong: Skip it, and the first sign of an expiring token is an outage. Add it, and the CLI gets a small check that must stay silent in machine-readable output.
Recommendation: A because required expiry (I10) creates this surprise, and a small CLI warning prevents it without touching the API.
Note: options differ in kind, not coverage — no completeness score.
Net: You are trading a small CLI check against expiring tokens causing surprise outages.
Header: Expiry warn
A) Add to this plan's scope (recommended)
Add to T7: a stderr warning when the saved `avm_` token expires within 7 days, and a sign-in hint when SSO refresh fails; never in stdout or JSON. Effort S, risk low, reuses `whoami` from T1; verified by CLI tests.
✅ People and CI scripts see a week's notice instead of discovering an expired token as an outage
✅ No API, header or SDK change, so the v1 soft-freeze and machine-readable output are untouched
❌ Only CLI users get the warning; SDK users must check expiry with `whoami` themselves
B) Defer to TODOS.md
Record it in TODOS.md with the trigger "first support ticket about an expired token". Effort S, risk low, zero implementation work now.
✅ T7 stays exactly as written
✅ The design (stderr only, cached expiry) is written down for later
❌ Expired tokens surface as failures until it ships
C) Skip
No warnings; people track expiry from `aerolvm token list`. Effort S, risk low, zero implementation work.
✅ Nothing new in the CLI to test or keep quiet in JSON mode
✅ Expiry stays visible in `token list` and `whoami`
❌ Required expiry with no warning turns every forgotten renewal into an outage

## Answered: E-DENYHINT (D9 → add)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Another team's sandbox → 404 with no hint (no probing) | approved scope (§5.3) | 404 | unchanged | unchanged | unchanged |
| Own team, missing verb → 403 naming the permission | approved scope (§5.3) | permission only | the message also names the caller's role and team, and the role that would allow it: "role viewer on team payments cannot sandbox.exec; ask an admin for role runner on team payments" | permission only | permission only |
| No binding matched → 403 | approved scope (§5.5) | "no role binding for ana@acme.com" | also names the issuer and the groups the token carried, all of them the caller's own claims | unchanged | unchanged |
| Information disclosed | security | the caller's permission | only the caller's own role, team and claims, which `whoami` already shows | — | — |
| Error body shape per surface | existing contracts | each surface's own error writer | hint in the message string; v1 also adds `required_permission` and `role` fields to the 403 body; facades keep their body shape | — | — |
| PAT and managed callers | approved (F-LOGIN L8) | never see these 403s | unchanged | unchanged | unchanged |
| Tests | pending | — | per-surface 403 body tests; a 404 carries no hint | — | — |

Question: D9 — E-DENYHINT: Should a 403 tell the caller which role would let them do it?
Project/branch/task: plans/identity-and-access.md §5.3 (status codes), T2 and T6.
ELI10: When someone with a read-only role tries to run a command, the plan returns "forbidden: sandbox.exec". That is correct but unhelpful: they don't know what to ask for. With this change the message says "your role is viewer on team payments; ask an admin for runner on team payments". When no binding matches at all, it also shows the groups their sign-in carried, so they can tell IT what is missing. It only ever shows the caller their own details, which `whoami` already shows.
Stakes if we pick wrong: Skip it, and every denied call becomes a support question to an admin. Add it, and error messages carry a little more text that must never leak anyone else's details.
Recommendation: A because roles are new to every user, and a message that names the fix turns a support ticket into a one-line request.
Note: options differ in kind, not coverage — no completeness score.
Net: You are trading slightly longer error messages against every denied call becoming a support question.
Header: Deny hints
A) Add to this plan's scope (recommended)
The 403 names the caller's role and team and the role that would allow the call; "no binding" also lists the caller's own groups; 404s stay bare. Effort S, risk low, reuses the T2 permission table; verified by per-surface error tests.
✅ People learn exactly what to ask their admin for, the first time they hit a role limit
✅ Discloses only the caller's own role, team and claims, which `whoami` already returns
❌ Error messages get longer, and each surface's error writer needs a test that the hint never leaks into a 404
B) Defer to TODOS.md
Ship 403s that name only the permission; record the hint in TODOS.md with the trigger "first support thread about a 403". Effort S, risk low, zero implementation work now.
✅ T2 error handling stays minimal
✅ The hint wording and disclosure rule are written down for later
❌ Every denied call sends the person to an admin to work out what is missing
C) Skip
403s name only the permission, permanently. Effort S, risk low, zero implementation work.
✅ Shortest, most uniform error messages
✅ Nothing extra to keep out of 404 responses
❌ Roles stay hard to self-diagnose for everyone who meets them

## Answered: E-MCPOAUTH (D10 → add, against recommendation)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Remote `/mcp` with bearer auth (`SB_MCP_ENABLED`) | shipped (MCP plan, CEO D2 2026-10-04) | bearer only | unchanged | unchanged | unchanged |
| MCP OAuth at Phase 4 behind a demand checkpoint | prior user decision (MCP CEO review D2) | deferred; no TODOS.md entry exists | reopened: built in this plan (new T13) | stays deferred; a new TODOS.md entry records the trigger and the lower cost | stays deferred, unchanged |
| RFC 9728 `/.well-known/oauth-protected-resource` naming the configured issuer, and `WWW-Authenticate` with `resource_metadata` on `/mcp` 401s | pending | not in plan | added | written into the deferred item | none |
| §5.5 accepts JWT access tokens (RFC 9068) whose `aud` is the `/mcp` resource, not only ID tokens | pending (Section 1 finding on accepted token types) | not specified | required | not required | not required |
| Client registration | per provider | — | admin pre-registers the MCP client at the provider; no dynamic registration, which enterprise providers rarely allow | — | — |
| Providers that issue only opaque access tokens (Google) | L2 rules out introspection | — | not supported for MCP OAuth | — | — |
| Proof it works with claude.ai or ChatGPT | none yet | — | a live connector test per provider (not offline) | — | — |
| Tests | pending | — | metadata and 401-header handler tests; access-token verify tests; a live connector UC | — | — |

Question: D10 — E-MCPOAUTH: Build OAuth for remote MCP now, so claude.ai and ChatGPT connectors can sign in with the company's SSO?
Project/branch/task: plans/identity-and-access.md §13; reopens the MCP plan's Phase 4 deferral (MCP CEO review D2, 2026-10-04) because an assumption changed.
ELI10: Today `/mcp` on sandboxd takes a bearer token, which Claude Code and Cursor can send. claude.ai and ChatGPT connectors can't: they only connect through OAuth. Earlier you decided to wait for demand, partly because OAuth was the expensive part. This plan makes sandboxd check sign-in tokens from the company's identity provider, so most of the work is now done. What's left: publish a small "where to sign in" document, accept the provider's access tokens for `/mcp`, and test against real connectors. Each company's admin must register the connector at their provider, and Google can't be used for this.
Stakes if we pick wrong: Build it now, and the stack grows with a part that can only be proven against live claude.ai and ChatGPT connectors. Defer it, and those connectors still can't reach AerolVM until someone asks.
Recommendation: B because your demand checkpoint still stands and the remaining risk is in live connector behavior, which this stack cannot prove offline; a TODO that records the much lower cost keeps it ready.
Note: options differ in kind, not coverage — no completeness score.
Net: You are trading stack size and unproven connector behavior against claude.ai and ChatGPT users reaching AerolVM sooner.
Header: MCP OAuth
A) Add to this plan's scope
New T13: RFC 9728 metadata, `WWW-Authenticate` on `/mcp` 401s, JWT access-token checks for the `/mcp` audience, per-provider docs, and a live connector test. Effort M, risk medium, reuses the §5.5 verifier and remote MCP handler; verified by handler tests plus live connector runs.
✅ claude.ai and ChatGPT users connect to AerolVM with their company SSO, no install and no shared token
✅ Most of the hard part (offline token checks, bindings, roles) is already in this plan
❌ Reopens your demand checkpoint, adds a task that needs live connector testing, and excludes Google-only shops
B) Defer to TODOS.md (recommended)
Keep the MCP plan's Phase 4 gate; add a TODOS.md entry (none exists today) with this design, the much lower cost, and the trigger "first customer asks for no-install MCP". Effort S, risk low, zero implementation work now.
✅ Respects the earlier demand-checkpoint decision while recording that the cost dropped sharply
✅ Keeps live-connector risk out of an already large stack
❌ claude.ai and ChatGPT connectors still cannot reach AerolVM until it ships
C) Skip
Leave §13 as written with no TODO update. Effort S, risk low, zero implementation work.
✅ No change at all to the MCP plan or TODOS.md
✅ Nothing new to track
❌ The lower cost goes unrecorded, so the next person re-derives it from scratch

### 0H. Spec review loop

Three adversarial reviews of this plan together with the CEO summary (`~/.gstack/projects/aerol-ai-microvm/ceo-plans/2026-10-16-identity-and-access.md`):

| Round | Score | Issues found | Result |
|---|---|---|---|
| 1 | 5/10 | 21 | fixed in the body |
| 2 | 6/10 | 15 | fixed in the body |
| 3 | 6/10 | 16 | **open**; listed under "Reviewer Concerns" in the CEO summary and carried into the Review Sections |

The 16 open items, briefly:
- **Infrastructure:** Caddy's L4 fallback hides the client IP (no PROXY protocol); `/ui` is not routed by Caddy, so the dashboard has no HTTPS origin.
- **Forwarding:** markers must ride on every forward path, not just `clusterroute`/`clustercreate`.
- **Missing pieces:** `--team` needs a wire mechanism; `Request` needs a target id; `cluster.internal` POSTs must be excluded from `api` records; monitoring goes blind once the mirror is stale; the rollout gate must cover `request` and the new kinds.
- **Consistency:** managed-role limits; one denial record kind; the §5.2 and §9.6 cluster call-outs; the coalescer still written as decided; the T10 row and the §9.4 wording.
- **Defaults and scope:** a `max_token_lifetime` default; whether the env-token expiry check fits D8.

**Document approval (D11, 2026-10-16):** "Approve and continue (recommended)". This accepts these document versions as the record of D1–D10. It does not approve the 16 open items or any implementation.

### 0I. Temporal interrogation

```
  HOUR 1 (foundations)    Access refactor (Fleet/Role/Principal/Via), one authenticate(), the route
                          registry, auditlog field order (append only, omitempty), fv gate pattern.
                          Must know: cmd/aerolvm cannot import server packages (pkg/ only), and v1
                          is soft-frozen (new routes fine, new 403s only for new principals).
  HOUR 2-3 (core)         Ambiguities they will hit: how --team travels with a stateless provider
                          token (open #5); which id an api record carries for non-sandbox routes
                          (#6); coalescer vs the existing audit budget (0G HOLD 1, #13); what a
                          managed Identity.Role may be (#10).
  HOUR 4-5 (integration)  Surprises: Caddy's L4 fallback hides the client IP (#1); /ui is not routed
                          by Caddy (#2); forwards happen in five places, not two (#3); the remote MCP
                          transport re-sends Authorization today; X-Cluster-* from a non-peer is a
                          403 in cluster mode, not a strip (#4); Caddy reloads close WebSockets
                          (learning caddy-reload-closes-websockets), so the public-socket switch is
                          install-time only.
  HOUR 6+ (polish/tests)  What they will wish they had: a test issuer in the harness on day one
                          (T12), the route-registry test before any route moves (T2), golden files
                          for audit records and the access report, and docs built with npm 10.
```

**Feasibility blockers.** None needs a founder decision before the review sections. All 16 open items are design gaps inside approved scope, and each is assigned to a review section:
- Section 1 (architecture): #1, #3, #5, #10, #13.
- Section 2 (errors): #8, #11.
- Section 3 (security): #2, #4.
- Section 6 (tests): #9, #14.
- Section 7 (data): #6, #7.
- Section 9 (deploy): #15.
- Section 1 scope check: #16.

**Effort** (whole stack T0–T13 plus T5b, 15 PRs): human team about 7–9 engineer-weeks; CC + gstack about 4–6 working sessions, plus 2 live integration runs (single-node and `cluster-3-mixed`) and manual claude.ai and ChatGPT connector checks.

## Review sections

### Section 1: Architecture review

**System architecture (new components marked `*`):**

```
                ┌─────────────── identity providers ─────────────────┐
                │ Okta · Entra · Google · Keycloak · GH Actions · EKS │
                │ discovery + JWKS (fetched at boot, hourly, ≤1/min    │
                │ on an unknown kid)                                  │
                └──────▲──────────────────────────────────▲───────────┘
   login: PKCE / device / GIS                              │ JWKS
   ┌───────────┐ ┌────────────┐ ┌────────────┐ ┌─────────┐ │
   │ aerolvm   │ │ dashboard* │ │ MCP client │ │ SDKs/CI │ │
   │ CLI*      │ │ /ui        │ │ (OAuth*)   │ │         │ │
   └─────┬─────┘ └─────┬──────┘ └─────┬──────┘ └────┬────┘ │
         │ bearer: PAT | avm_* | ID token | MCP access token*
         ▼             ▼              ▼             ▼      │
   ┌──────── Caddy :443 caddy-l4 SNI ──► :8443 HTTPS site (@api) ────────┐
   │ any scope : reverse_proxy 127.0.0.1:21212                          │
   │ host scope: reverse_proxy unix /run/sandboxd-public/api.sock*      │
   └──────────────────────────────┬─────────────────────────────────────┘
   remote SDK / Prometheus ───────┼──► :21212 (0.0.0.0 on domain installs)
                                  ▼
  ┌─────────────────────── sandboxd: receiving (edge) node ──────────────────────┐
  │ clusterControlHeaderGuard → authenticate()* ─┬─ PAT (const-time, scope rule*)  │
  │                                              ├─ avm_* → token mirror* (memory)│
  │                                              ├─ JWT  → OIDC verifier* + LRU*  │◄── identity file watcher*
  │                                              └─ provider Validator (managed)  │    (SB_IDENTITY_FILE)
  │ → authorize(perm, role, team)* → handler → api recorder* → per-node chain     │
  │ → forward paths (clusterroute, clustercreate, clusterlist, runloop, fan-outs) │
  │   + X-Cluster-PAT-Origin* / X-Cluster-Surface* over mTLS                       │
  └─────────┬────────────────────────────────────────────────┬────────────────────┘
            │ mTLS forward, original bearer                  │ mirror poll* 5 s (304)
            ▼                                                ▼
  ┌──── sandboxd: owner node ─────┐               ┌──── server tier (≤ 7, Raft) ────┐
  │ same authenticate() offline   │               │ FSM apiTokens* (ops 31/32),     │
  │ handler runs → api record*    │               │ change ring*, fv gate           │
  │ secret_open/egress + caller*  │               └─────────────────────────────────┘
  │ per-node chain → witness (S3 Object Lock) + export ──► aerolvm audit search* /   │
  └───────────────────────────────┘                        access review*            │
```

**Data flow: `authenticate()` (the one new hot path):**

```
  HAPPY  bearer ─► classify ─► PAT: const-time ─► scope rule ─► Access{operator|node}
                         ├─► avm_: checksum ─► mirror[id] ─► sha256 cmp ─► expiry ─► Access{token}
                         ├─► JWT: LRU hit? ─► sig/iss/aud/exp/nbf/lifetime ─► deny list ─► binding ─► Access{oidc}
                         └─► other ─► provider Validator ─► Access{controlplane, runner}
  NIL    no Authorization / no X-API-KEY ─► 401, auth_denied (rate-limited, metric)
  EMPTY  "Bearer " or whitespace ─► same as NIL (never reaches a validator)
  ERROR  mirror stale > 60 s ─► 503 for avm_ only │ JWKS never fetched or file invalid ─► 503 for JWT only
         provider Validator error ─► 401 (as today) │ no binding ─► 403 + D9 hint │ deny subject ─► 401
```

**Data flow: token mirror (worker and ingress nodes):**

```
  HAPPY  every 5 s ± jitter: GET internal/tokens?since=V ─► 304 (same V) │ 200 delta ─► apply by version
  NIL    first boot, V=0 ─► page-walk all tokens ─► cursor = V0 ─► synced
  EMPTY  zero tokens ─► empty map, synced; every avm_ token is a local miss (401)
  ERROR  server unreachable or 5xx ─► keep the map, age grows ─► > 60 s: refuse avm_ (503), metric
         cursor older than the change ring ─► resnapshot (page walk) ─► synced
```

**Data flow: `api` record:**

```
  HAPPY  d.Route ─► handler returns ─► build Event{caller, request} ─► buffered Emit ─► chain append
  NIL    no Access (internal or background) ─► caller system:<subsystem>, or not recorded for cluster.internal
  EMPTY  route has no sandbox ─► sandbox_id empty; request.target names the object (Section 7)
  ERROR  queue full ─► gap record with Dropped │ forwarded ─► edge skips, owner records │ forward fails ─► edge records 502
```

**State machines:**

```
  API token:   (absent) ──create──► LIVE ──expires_at──► EXPIRED ──sweep +30 d──► (absent)
                                     └──revoke (delete)──────────────────────────► (absent)
               Impossible: EXPIRED ──► LIVE (no update op exists; only create and delete).
                           Two LIVE with one (owner, name): the FSM apply checks uniqueness serially.

  Token mirror: UNSYNCED ──page walk──► SYNCED ──poll ok──► SYNCED
                SYNCED ──no sync 60 s──► STALE (refuse avm_) ──poll ok──► SYNCED
                SYNCED ──cursor too old──► UNSYNCED (resnapshot)

  Identity file: NONE ──valid load──► LOADED(h1) ──valid reload──► LOADED(h2)
                 NONE ──invalid at boot──► BOOT_ERROR (JWT 503) ──valid reload──► LOADED
                 LOADED ──invalid reload──► LOADED (last good kept, error metric)
```

**Coupling.** Each new coupling is justified by an approved requirement:
- `authenticate` → token mirror → server tier (L5).
- `auditlog.Event` → every reader. Hash-covered, so it is gated (§5.8).
- `remotemcp` → auth context (D10).
- Caddy and install.sh → PAT scope (D4).

The before and after dependency graph is the architecture diagram above, minus the `*` boxes.

**Scaling (what breaks first):**
- **10×, 20k nodes.** Mirror polls reach 4,000 req/s on ≤ 7 servers. That is still an in-memory 304, but it is the first number to watch. The change ring keeps deltas small.
- **100×.** The JWKS refetch storm after a provider key rotation: every node fetches within a minute, which can hit provider rate limits. Jitter the unknown-kid refetch; caching the JWKS honors `Cache-Control`.
- **`api` record volume** scales with call rate, not node count. Flood control is pending (Section 1, A5).

**Single points of failure:**

| Point | Effect |
|---|---|
| Server tier | Token writes stop; the mirror tolerates 60 s. |
| Identity provider | New logins stop; verification continues. |
| Caddy | The public API is down; host-local and `:21212` still work. |
| Identity-file distribution | Drift between nodes; the hash metric shows it. |

**Security architecture: new endpoints:**

| Endpoint | Who can call | Gets | Can change |
|---|---|---|---|
| `GET /v1/whoami` | any principal | own principal, role, team, expiry | nothing |
| `POST/GET/DELETE /v1/tokens` | admin (write); auditor or admin (read) | token metadata; the secret once on create | token set |
| `GET /.well-known/aerolvm-auth` | anyone | issuer URLs, client ids, display names (DR3), `ui_url` when `SB_DOMAIN` is set (DR9) | nothing |
| `GET /.well-known/oauth-protected-resource*` | anyone | resource URL, issuers | nothing |
| `GET /v1/cluster/internal/tokens` | `node:` principal over mTLS | hashes and metadata (never secrets) | nothing |
| public socket | Caddy only (`root:caddy 0750`) | same as the API | same as the API |

**Production failure scenarios:**
- **Provider key rotation.** Covered.
- **Raft leader change during token create.** Covered: 503, then revoke and recreate.
- **Caddy reload during the public-socket switch.** Covered: install-time only.
- **Export lag makes the access review incomplete.** Covered: it reports coverage.
- **Caddy hides the client IP.** Not covered (A1).

**Rollback posture:**
- Setting `SB_IDENTITY_ENABLED=false` and restarting returns a node to PAT-only in minutes.
- Old binaries silently skip unknown FSM ops (the precedent at `internal/cluster/fsm.go:1572`), so a server-tier rollback loses token state but keeps working.
- The audit fields carry the documented rollback floor (§5.8).
- `SB_PAT_SCOPE` back to `any` and the Caddy upstream back to TCP is an install-time revert, refused in enterprise mode.

**What makes it obvious to a new engineer:** two tables hold the whole model. One maps credential → authenticator → `Access`; the other maps route → permission. **Platform potential:** principal plus team is the basis for per-team quotas (#648), per-team policy and per-team usage.

**Fit of the accepted cherry-picks:**
- D4 and D10 add `X-Cluster-*` markers, so they depend on every forward path carrying them (finding 1.2).
- D7 depends on export coverage and a target id (Section 7).
- D6 depends on mirror staleness behavior (Section 2).
- No accepted pick needs revisiting. Each depends on a fix below.

**Findings:**

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1.1 | **CRITICAL GAP** | caddy-l4's SNI fallback dials `127.0.0.1:8443` with no PROXY protocol (`pkg/caddy/client.go:1203-1210`), so every public request reaches sandboxd from loopback. The per-IP `auth_denied` limit (§5.9), the "PAT used from outside" alert (§5.11) and source attribution all see 127.0.0.1. | **D12 → PROXY protocol** (applied) |
| 1.2 | WARNING | Forward markers (edge-record skip, `X-Cluster-PAT-Origin`, `X-Cluster-Surface`) were pinned to `clusterroute`/`clustercreate`. Requests are also forwarded by `clusterlist` (its own client), the runloop `forwardToNode`, `v1/js_bundle.go` and the `cluster_handler.go` fan-outs. | **correction** under D4 and D10's approved behavior: one helper, `cluster.StampForward(req, access)`, called on every forward path, plus a call-site test (§5.11, §5.14, T4, T10, T13) |
| 1.3 | WARNING | `--team` (I2: "multi-team users pick at login") has no wire mechanism: a provider ID token carries no session. | **D13 → team-selection header** (applied) |
| 1.4 | WARNING | `Identity.Role` from a managed provider could name a fleet role, or create new 403s for managed callers (L8). | **correction:** a managed provider may set only `viewer` or `runner`, never fleet scope. When it sets nothing, the caller is `runner`, exactly as today (§5.1). |
| 1.5 | WARNING | Two flood controls for audit records (0G HOLD 1): the planned one-second coalescer, and the existing per-sandbox budget in `secret_audit_quota.go`. | **D14 → all three modes, default budget; shared nodes always budget** (applied) |
| 1.6 | scope | The env-token expiry check (§5.6) goes beyond D8's "saved token" scope. | **D15 → keep the CI warning** (applied) |
| 1.7 | WARNING | `DESIGN.md` ("Actors and actions") describes "API client: the API token". This plan changes the actor model. | **correction:** T11 updates `DESIGN.md`'s actor and action tables (dependent doc) |
| 1.8 | WARNING | §5.2 says forward markers "only decide operator vs node", and §9.6 omits the new markers and the gossip scope that CLAUDE.md rule 6 requires as a cluster call-out. | **correction:** §5.2 and §9.6 updated |

## Answered: A1 (D12 → PROXY protocol)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Per-IP limit on `auth_denied` records (§5.9) | approved scope (plan) | breaks: every public request is 127.0.0.1 | works: real client IP | replaced by one per-node limit | broken |
| "PAT used from outside" alert (§5.11) | approved scope (plan) | cannot tell Caddy from host scripts | origin label from the real peer | keyed by listener; meaningful only under `host` | meaningless |
| `X-AerolVM-Client-IP` from `{remote_host}` (§5.9) | approved (spec-review fix) | always 127.0.0.1 | the real client | dropped | always 127.0.0.1 |
| caddy-l4 fallback route (`pkg/caddy/client.go:1203-1210`, `EnsureLayer4` — fragile per CLAUDE.md rule 5) | existing | plain TCP to `127.0.0.1:8443` | adds `"proxy_protocol": "v2"` behind `SB_L4_FALLBACK_PROXY_PROTOCOL` | unchanged | unchanged |
| 8443 site in install.sh and `packaging/Caddyfile.template` | existing | plain | `listener_wrappers { proxy_protocol { allow 127.0.0.1/32 } tls }`; default fallback policy accepts connections without a header, so the order of the two changes is safe | unchanged | unchanged |
| Rollout | pending | — | install.sh writes the Caddy wrapper and sets the env flag in one step; a binary-only upgrade leaves the flag off | — | — |
| Side effect | — | — | preview sites (`*.$DOMAIN:8443`) also see real client IPs | — | — |
| Tests | pending | — | regression test in `layer4_bootstrap_test.go` (route carries `proxy_protocol` only with the flag on); live UC: denied call from a remote host records its IP | per-node limit test | — |

Question: D12 — A1: Caddy hides every caller's real IP from sandboxd. Fix it with PROXY protocol, or design around it?
Project/branch/task: plans/identity-and-access.md §5.9, §5.11 (Section 1, finding 1.1); touches `EnsureLayer4`, which CLAUDE.md marks fragile.
ELI10: All public HTTPS traffic enters Caddy's port-443 router. That router forwards it to Caddy's HTTPS site on the same machine. The forward carries no note of who the real caller was, so sandboxd sees every request as coming from the server itself. Three planned features need the real address: the limit that stops a password-guessing flood from filling the audit log, the alert for "someone used the shared token from outside", and the IP on denied-access records. PROXY protocol is a standard one-line header that carries the real address across that internal hop.
Stakes if we pick wrong: Skip the fix, and the flood limit throttles everyone together, the outside-use alert can't work in the default setup, and denied records show 127.0.0.1. Fix it carelessly, and a mismatched upgrade breaks all HTTPS. That is why the plan turns it on only when install.sh changes both sides together.
Recommendation: A because auditors and the alerts need the real caller address, and gating the change on install.sh writing both sides at once keeps the fragile L4 path safe.
Completeness: A=9/10, B=6/10, C=3/10
Net: You are trading one careful change on a fragile Caddy path against features that would otherwise see every caller as 127.0.0.1.
Header: Client IP
A) PROXY protocol on the fallback (recommended)
The caddy-l4 fallback sends a PROXY v2 header and the 8443 site accepts it from 127.0.0.1, both written together by install.sh behind `SB_L4_FALLBACK_PROXY_PROTOCOL`. Effort M, risk medium, reuses `EnsureLayer4` and install.sh's Caddy block; verified by a `layer4_bootstrap_test.go` regression test plus a live UC.
✅ The flood limit, the outside-use alert and denied-access records all see the real caller address
✅ Preview sites get real client IPs too, and a binary-only upgrade can't break HTTPS because the flag stays off
❌ Changes `EnsureLayer4`, a path CLAUDE.md marks fragile, so it needs a regression test and a PR call-out
B) Design around it
Leave Caddy alone: one `auth_denied` limit per node instead of per IP, and an outside-use alert keyed by listener that only means something under `host` scope. Effort S, risk low, zero Caddy changes; verified by a per-node limit test.
✅ No change to the fragile L4 bootstrap path or to install.sh's Caddy block
✅ Still bounds the audit log during a token spray
❌ Denied records carry no real IP, and the outside-use alert cannot work in the default `any` scope
C) Do nothing
Ship the plan as written. Effort S, risk low, zero implementation work.
✅ No new work
✅ Nothing changes in Caddy
❌ Three planned features silently see every caller as 127.0.0.1

## Answered: A3 (D13 → team-selection header)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| One team per request (`ownerScope` single-valued) | approved (F-RECS I2) | yes | yes | yes |
| "Multi-team users pick at login" | approved (F-RECS I2, written recommendation) | no wire mechanism | `X-AerolVM-Team: <name>` request header | dropped: first matching binding always wins (changes I2's wording) |
| No identity header is trusted | approved (F-LOGIN L2) | — | holds: the header only picks among bindings the verified token already matches, and never grants. A team not among them → 403 with the D9 hint. Absent → first match. | holds |
| Cross-node | approved (L2) | — | an ordinary header; the forward keeps it and the owner re-applies the same selection offline | n/a |
| Clients | pending | — | CLI saves `--team` per login and sends it; dashboard team picker for multi-team users; `SB_TEAM` env / client option in all 5 SDKs (T9) | none |
| Audit | approved (§5.8) | caller only | `caller` also records the selected team | caller only |
| Tests | pending | — | selection, refusal of a non-matching team, forward keeps the header, per-SDK header tests | first-match order test |

Question: D13 — A3: How does a person in several teams choose which team a request acts for?
Project/branch/task: plans/identity-and-access.md §5.3 and §5.6 (Section 1, finding 1.3); settles how I2's "pick at login" works.
ELI10: Each request acts for exactly one team, so a person in both "payments" and "checkout" must say which. The plan says they pick at login. But the sign-in token comes from the company's identity provider and can't carry that choice, and AerolVM keeps no session. So the choice has to ride on each request as a small header naming the team. The header can only pick from teams the person's verified sign-in already allows; it can never add one. The other way is to drop the choice: the first matching rule in the config always wins.
Stakes if we pick wrong: Without a header, multi-team people always land in whichever team the config lists first, and must ask an admin to reorder rules to work elsewhere. With it, every client must learn one more header, including all five SDKs.
Recommendation: A because it delivers I2's "pick at login" as written, while the header narrows what the verified token already allows and never grants, so L2 holds.
Completeness: A=9/10, B=6/10
Net: You are trading one header across the CLI, dashboard and five SDKs against multi-team people being stuck in the config's first team.
Header: Team choice
A) Team-selection header (recommended)
Requests may send `X-AerolVM-Team`; it selects among the token's already-matching bindings, never grants, and is re-applied on the owner node; CLI, dashboard and all 5 SDKs send it. Effort M, risk low, reuses the bindings matcher and the D9 hint; verified by selection and refusal tests plus per-SDK header tests.
✅ People in several teams switch with `aerolvm login --team checkout` or a picker, exactly as I2 describes
✅ Can't widen access: a team the token doesn't already allow gets a 403 with a clear hint
❌ One more header for every client to send, including all five SDKs in T9
B) First matching binding wins
No selection: the first binding in the identity file that matches decides the team, for every request. Effort S, risk low, zero client work; verified by a binding-order test.
✅ Nothing for clients to send, and nothing for the SDKs to change
✅ The identity file alone decides, which is easy to audit
❌ Changes I2's "pick at login" to "the config decides", so multi-team people must ask an admin to work in another team

## Answered: A5 (D14 → custom: all three, default budget, shared nodes always budget)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Records never block the request path; overflow is a `gap` with a count | approved (§5.9) | yes | unchanged | unchanged | unchanged |
| Exec digest proves which command ran (I5) | approved (F-RECS I5) | per record | holds for every written record; over budget, a marker names the caller, the count and the routes, but not each command | holds only for identical repeats (they merge with a count); a flood of *different* commands is unbounded | holds per record, and repeats merge |
| Flood control mechanism | 0G HOLD 1 (pending) | new one-second coalescer keyed `(caller, route, sandbox, status, digest)` | extend the existing per-sandbox token bucket (`internal/service/secret_audit_quota.go`) with an `api` bucket keyed `(sandbox, caller)`; coalesced `rate_limited` marker naming the caller | keep the new coalescer only | coalescer first, then the budget |
| Bound under a flood of varying commands | Section 1 finding 1.5 | none | bounded (burst then rate) | **none** | bounded |
| Secret-open records and gap markers | existing rule (`secret_audit_quota.go:26-29`) | never budgeted | never budgeted | n/a | never budgeted |
| Records with no sandbox (token ops, cluster admin) | pending | — | not budgeted (rare, admin-only) | coalesced | not budgeted |
| New settings | pending | — | `SB_AUDIT_API_RATE` (20/s), `SB_AUDIT_API_BURST` (100) per sandbox and caller | none | both sets |
| Tests | pending | — | budget table: burst, refill, marker content, secret-open exempt, per-caller isolation | merge table | both |

Question: D14 — A5: How should a flood of API calls be kept from swamping the audit log?
Project/branch/task: plans/identity-and-access.md §5.9 (Section 1, finding 1.5; 0G HOLD check 1).
ELI10: An AI agent can call "run a command" hundreds of times a second. If each call wrote its own audit record, one busy sandbox could bury everyone else's evidence. The plan invented a new trick: merge identical calls made in the same second. But an agent running *different* commands defeats it completely. AerolVM already has a better tool for network records: a per-sandbox allowance. When it runs out, the extras are counted into one "rate limited" record. Reusing it bounds any flood, and the overflow record still says who and how many.
Stakes if we pick wrong: Keep the new trick, and a varied-command flood is unbounded and can push other tenants' records into gaps. Reuse the allowance, and over-budget calls show up as a count with the caller's name, not one record each.
Recommendation: A because it reuses the proven per-sandbox budget, bounds every flood, and keeps the loss visible with the caller named. That is DRY, and safer than a second flood control.
Completeness: A=9/10, B=6/10, C=8/10
Net: You are trading one record per call under extreme floods against a bounded log built on machinery that already exists.
Header: Flood control
A) Extend the existing audit budget (recommended)
Add an `api` bucket keyed `(sandbox, caller)` to `secret_audit_quota.go`; over budget, calls are counted into one `rate_limited` record naming the caller, the count and the routes; drop the new coalescer. Effort S, risk low, reuses the egress budget's writer funnel and marker; verified by a budget table test.
✅ Any flood is bounded, including varied commands, so one agent can't push other tenants' records into gaps
✅ No second flood-control mechanism; the overflow record still names who and how many
❌ Over budget, individual command digests for the extra calls are not recorded, only their count and routes
B) Keep the one-second coalescer
Ship §5.9 as written: identical calls within a second merge with a count; different commands are never merged. Effort S, risk medium, new code; verified by a merge table test.
✅ Every distinct command keeps its own record and digest
✅ Simple to explain: repeats merge, everything else is kept
❌ An agent running varied commands is never bounded, and the code duplicates a flood control that already exists
C) Both: coalesce, then budget
Merge identical repeats first, then apply the per-sandbox budget to what remains. Effort M, risk medium, two mechanisms; verified by both test tables.
✅ Keeps the most per-command detail while still bounding floods
✅ Repeated identical calls cost almost nothing
❌ Two flood controls to reason about, test and tune, for a small gain over A

## Answered: A6 (D15 → keep the CI warning)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| Stderr warning when the saved `avm_` token expires within 7 d | approved (D8) | in §5.6/T7 | unchanged | unchanged |
| Sign-in hint when an SSO refresh fails | approved (D8) | in §5.6/T7 | unchanged | unchanged |
| Same warning for an `avm_` token from `SB_PAT_TOKEN`/`SB_API_TOKEN` (CI), via `whoami` at most once a day per token id, cached under `$XDG_CACHE_HOME/aerolvm` | added by the spec review, **not approved** | in §5.6 | approved; T7 test added | removed from §5.6 |
| Extra request | — | — | one `whoami` per token per day; one per run on a fresh CI runner | none |
| Never in stdout, `--json` or MCP output | approved (D8) | yes | yes | yes |
| Tests | pending | — | env-token: no cache → one `whoami`; cached → none; warning on stderr only | — |

Question: D15 — A6: Should the CLI also warn about expiring tokens that come from environment variables, the CI case?
Project/branch/task: plans/identity-and-access.md §5.6 (CLI), T7; the spec review added this beyond D8's approved "saved token" scope.
ELI10: You approved a warning when the token saved by `aerolvm login` is about to expire. CI jobs don't log in. They pass the token in an environment variable, so as written they would never be warned, even though CI is exactly where a dead token causes a surprise outage. Covering them means the CLI asks the server about the token's expiry at most once a day per token. On a fresh CI machine, that is once per run.
Stakes if we pick wrong: Drop it, and CI pipelines get no warning before their token dies. Keep it, and CLI runs in CI make one small extra API call.
Recommendation: A because CI is where expiring tokens cause outages, D8's own reasoning named CI, and the cost is one small request per run.
Note: options differ in kind, not coverage — no completeness score.
Net: You are trading one small extra request per CI run against CI pipelines failing without warning.
Header: CI warning
A) Keep the CI warning (recommended)
Approve the env-token check: one `whoami` per token per day (once per run on a fresh runner), warning on stderr only, with a T7 test. Effort S, risk low, reuses `whoami` and the D8 warning path; verified by CLI tests.
✅ CI pipelines see a week's notice before their token expires, where an outage hurts most
✅ Same stderr-only rule as D8, so JSON and MCP output stay clean
❌ One extra API call per CLI run on a fresh CI runner
B) Saved token only
Remove the env-token check from §5.6; only the token saved by `aerolvm login` gets the warning, as D8 approved. Effort S, risk low, zero extra work.
✅ No extra request, and exactly D8's approved scope
✅ Simpler CLI startup path
❌ CI tokens expire without warning; the access review's "expiring within 30 d" flag is the only signal

**Section 1 decision gate:** complete. D12–D15 answered and applied; corrections 1.2, 1.4, 1.7 and 1.8 applied.

### Section 2: Error and rescue map

```
  METHOD / CODEPATH                         | WHAT CAN GO WRONG                          | ERROR
  ------------------------------------------|--------------------------------------------|-------------------------------
  api.authenticate (one function, §5.2)     | no bearer / empty bearer                   | errNoCredential
                                            | PAT mismatch, PAT refused by scope         | errUnauthorized, errPATScope
                                            | avm_ checksum bad                          | errMalformedToken
                                            | avm_ unknown or revoked                    | errTokenRejected (existing)
                                            | avm_ expired                               | errTokenExpired
                                            | token mirror stale > 60 s                  | ErrIdentityStale
                                            | JWT: bad sig / alg / iss / aud / exp / nbf | errInvalidJWT{reason}
                                            | JWT: JWKS never fetched, file invalid      | ErrIdentityUnavailable
                                            | JWT: deny-listed subject                   | errSubjectDenied
                                            | no binding / team header not bound         | ErrNoBinding, ErrTeamNotBound
                                            | Entra group overage, Entra v1 token        | ErrNoBinding{hint}, errInvalidJWT{hint}
                                            | mcp_audiences token off /mcp               | errAudienceSurface
                                            | provider Validator error (managed)         | controlplane.ErrTokenRejected
  identity.TokenMirror.sync                 | server unreachable / 5xx / timeout         | net/http errors
                                            | cursor older than the change ring          | errResnapshot
  identity.OIDC.refreshJWKS                 | provider down, 429, bad JSON, no keys      | net/http, json, errEmptyJWKS
  identity.File.load / reload               | YAML parse, unknown field, overlap, bad URL| errIdentityFile{field}
  service.CreateAPIToken                    | name taken in team                         | ErrTokenNameTaken
                                            | not every server supports ops 31/32        | cluster.ErrClusterVersion
                                            | Raft apply timeout / leader change         | raft.ErrLeadershipLost, timeout
                                            | TTL over max, role/team invalid            | errInvalidTokenRequest
  service.RevokeAPIToken                    | unknown id                                 | (none: 204, idempotent)
  audit api recorder (d.Route)              | writer queue full                          | (gap record, existing)
                                            | budget exhausted                           | errAuditRateLimited (existing)
                                            | forward failed (502)                       | (edge records the failure)
  cluster.StampForward                      | a forward path that forgets to call it     | caught by the call-site test
  PAT scope: public socket                  | dir/socket create or chown fails           | errPublicSocket → boot fails
  L4 fallback with PROXY v2 (D12)           | flag on, 8443 wrapper missing              | TLS handshake failure (Caddy)
  remotemcp Access hand-off                 | context key missing on an inner call       | errNoAccess → 500 (bug)
  cmd/aerolvm login --sso                   | loopback port busy / browser never returns | errCallbackTimeout (5 min)
                                            | device code expired / denied               | oauth2 errors
                                            | refresh fails                              | errRefresh
  cmd/aerolvm access review / audit search  | export batch missing / chain FAIL          | auditlog.ErrIncomplete / ErrChain
                                            | token list 403 (not auditor or admin)      | errForbidden
  dashboard GIS (D2)                        | popup blocked / nonce mismatch / expiry    | browser errors
```

```
  ERROR                         | RESCUED? | RESCUE ACTION                                   | USER SEES
  ------------------------------|----------|-------------------------------------------------|------------------------------------
  errNoCredential, errUnauthorized | Y     | 401; rate-limited auth_denied record; metric    | 401 "unauthorized" (unchanged for PAT)
  errPATScope                   | Y        | 401 with the SSO hint (§5.11)                   | "operator token works only on this host"
  errMalformedToken             | Y        | 401 before any lookup                           | 401 (generic; see S2b)
  errTokenRejected/Expired      | Y        | 401                                             | 401 (generic; see S2b)
  ErrIdentityStale              | Y        | 503 + Retry-After; metric                       | 503 "identity data is stale"
  errInvalidJWT{reason}         | Y        | 401                                             | 401 (generic; see S2b)
  ErrIdentityUnavailable        | Y        | 503; reason in /v1/whoami for PAT callers; metric| 503 "sign-in keys unavailable"
  errSubjectDenied              | Y        | 401; api record result=denied                    | 401
  ErrNoBinding / ErrTeamNotBound| Y        | 403 with D9 hint; api record result=denied       | "no role binding for … (groups: …)"
  errAudienceSurface            | Y        | 401                                             | 401
  mirror net errors             | Y        | keep map, retry with jittered backoff (5 s → 30 s)| none until stale
  errResnapshot                 | Y        | page-walk resync                                | none
  JWKS errors                   | Y        | keep cached keys; retry hourly / on kid ≤1/min  | none unless never fetched
  errIdentityFile at boot       | Y        | JWT → 503; tokens and PAT work; metric          | 503 for SSO users
  errIdentityFile on reload     | Y        | keep last good; metric                           | nothing
  ErrTokenNameTaken             | Y        | 409                                             | "token name already used in team"
  ErrClusterVersion             | Y        | 409 "upgrade every server first"                | clear 409
  Raft apply timeout            | Y        | 503; token may exist → list, then revoke by id  | 503 with the recovery hint
  errInvalidTokenRequest        | Y        | 400 naming the field                            | 400
  errAuditRateLimited           | Y        | counted into a rate_limited record (D14)        | nothing (evidence keeps the count)
  errPublicSocket               | Y        | boot fails with the path and mode               | daemon refuses to start
  TLS failure (PROXY mismatch)  | Y        | boot logs the flag; runbook says re-run install | HTTPS down until fixed
  errNoAccess (MCP hand-off)    | N ← BUG  | 500, never fall back to the bearer               | 500 (must never happen; test)
  errCallbackTimeout, oauth2    | Y        | CLI exits 1 with the next step                  | "login timed out; try --device"
  errRefresh                    | Y        | "sign in again with aerolvm login --sso" (D8)   | that hint
  ErrIncomplete / ErrChain      | Y        | exit 3 (INCOMPLETE) / FAIL, as `audit verify`   | named gap or broken batch
  GIS errors                    | Y        | inline message (allow popups / sign in again)   | inline message
```

**Gaps:**

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 2.1 | WARNING | **Monitoring goes dark on workers during a server-tier outage** (spec review #8). Under `host` scope the scrape uses an `avm_` token. After 60 s of mirror staleness, workers refuse it, so worker metrics stop exactly when an outage needs them. Server-tier nodes read their own FSM and keep answering, so Raft health stays visible. The default `any` scope uses the PAT and is unaffected. | **D16 → keep metrics flowing** (applied) |
| 2.2 | WARNING → **D17 applied** | Every SSO and `avm_` failure is a bare 401. A wrong audience, clock skew or an expired token looks the same as a forged one, and operators configuring an issuer get no signal. | **D17 → standard reason** (applied) |
| 2.3 | WARNING | A "no binding" denial was an `auth_denied` record in §5.5 but `api`/`denied` in §5.9 (spec review #11). | **correction:** a 403 is always an `api` record with `result: denied`; `auth_denied` is only for rate-limited 401s |
| 2.4 | OK | Raft apply timeout on token create → the token may exist without its secret. The recovery is list, find by name, revoke by id. The API revokes by id, not by name (spec review #14). | **correction:** §9.4 wording fixed |
| 2.5 | OK | `errNoAccess` on an MCP inner call is a programming error. It must return 500 and never fall back to reading the bearer, or a `/mcp`-audience token would be checked against `/v1` rules. | **correction:** T13 test asserts the 500 and no fallback |

## Answered: S2a (D16 → keep metrics flowing)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B |
|---|---|---|---|---|
| Mirror refuses `avm_` tokens after `SB_IDENTITY_MAX_STALE` (60 s) | approved (§5.4, L5) | all permissions | all permissions **except** requests whose route needs only `metrics.read` | unchanged |
| Revoked scrape token during an outage | — | refused after 60 s | can keep scraping workers until the mirror syncs again (read-only counters) | refused |
| Worker metrics during a server-tier outage under `host` scope | — | dark after 60 s | keep flowing | dark; documented as a limit |
| Server-tier and default (`any`, PAT) scrapes | — | unaffected | unaffected | unaffected |
| Evidence | — | — | each stale accept is counted (`aerolvm_identity_stale_accept_total`) and logged once a minute | — |
| Tests | pending | — | stale mirror: `metrics.read` accepted, `sandbox.read` refused; revoked-then-stale scrape token keeps working until resync | stale mirror refuses the scrape |

Question: D16 — S2a: Should worker nodes keep accepting the scrape token while their copy of the token list is stale?
Project/branch/task: plans/identity-and-access.md §5.4 and §5.11 (Section 2, finding 2.1).
ELI10: Worker nodes check service tokens against a copy of the token list, refreshed every few seconds from the cluster's core servers. If they can't refresh for a minute, they stop trusting the copy and refuse all service tokens. That is safe, but the Prometheus scrape uses a service token in strict mode. So during an outage of the core servers, every worker's metrics go dark, right when you need them. The fix is to keep accepting a token for the "read metrics" permission only, even when the copy is stale.
Stakes if we pick wrong: Refuse, and worker dashboards go blank during core-server outages. Accept, and a scrape token revoked during the outage keeps reading counters on workers until the copy refreshes.
Recommendation: A because outage visibility matters more than revoking a read-only metrics credential within the outage window, and the exception covers nothing but `metrics.read`.
Note: options differ in kind, not coverage — no completeness score.
Net: You are trading a few minutes' delay in revoking a read-only scrape token against metrics going dark during an outage.
Header: Stale mirror
A) Keep metrics flowing (recommended)
While the mirror is stale, workers still accept a token for routes that need only `metrics.read`; every other permission is refused as planned. Each stale accept is counted and logged. Effort S, risk low, reuses the T2 permission table; verified by stale-mirror tests.
✅ Worker metrics keep flowing during a server-tier outage, when they matter most
✅ The exception is one read-only permission; secrets, exec and writes still fail closed
❌ A scrape token revoked during the outage keeps reading counters on workers until the mirror syncs again
B) Fail closed for everything
Keep the 60 s rule for every permission and document that worker metrics pause during server-tier outages under `host` scope. Effort S, risk low, zero extra code.
✅ One simple rule: a stale mirror refuses every service token
✅ Revocation is never delayed beyond 60 s, even for metrics
❌ Worker dashboards go blank during exactly the outages you need to watch

## Answered: S2b (D17 → standard reason in the 401)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| PAT callers, managed callers and unclassified bearers | approved (F-LOGIN L8) | generic 401 "unauthorized" | unchanged | unchanged | unchanged |
| `avm_` and JWT failures, what the caller sees | pending | generic 401 | RFC 6750 `WWW-Authenticate: Bearer error="invalid_token", error_description="<reason>"` plus the same `reason` in the JSON body | generic 401 | generic 401 |
| Reasons | pending | — | `expired`, `not_yet_valid` (clock skew), `unknown_issuer`, `wrong_audience`, `too_long_lived`, `invalid_signature`, `malformed`, `unknown_or_revoked` (`avm_` can't tell those two apart) | logged only | — |
| Never disclosed | security | — | claim values, key ids, which check of a signature failed, whether an `avm_` id exists | — | — |
| Operator signal | pending | — | `aerolvm_auth_failures_total{kind,reason}` and a debug log with the issuer | same metric and log | none |
| Tests | pending | — | per-reason table; PAT 401 body byte-for-byte unchanged | metric/log table | — |

Question: D17 — S2b: When an SSO or service token is refused, should the 401 say why?
Project/branch/task: plans/identity-and-access.md §5.2 and §5.5 (Section 2, finding 2.2).
ELI10: Right now every refused sign-in token gets the same "unauthorized". An expired token, a laptop clock that is off by five minutes, and an issuer set up with the wrong audience all look identical to a forged token. The people setting up SSO, and the developers whose CI token just expired, have no clue what to fix. The standard OAuth way is a short reason in the 401, such as "expired" or "wrong audience". It never includes secret details or the token's contents. The shared operator token keeps today's plain 401.
Stakes if we pick wrong: Keep it generic, and every SSO setup mistake and expired token becomes a support thread. Add reasons, and an attacker learns slightly more, for example that a stolen token has expired.
Recommendation: A because these coarse, standard reasons make SSO setup and expired tokens self-diagnosing and reveal nothing secret, while PAT callers see no change (L8).
Completeness: A=9/10, B=7/10, C=4/10
Net: You are trading a little information for an attacker against SSO and token failures that explain themselves.
Header: 401 reason
A) Standard reason in the 401 (recommended)
For `avm_` and JWT failures, the 401 carries an RFC 6750 `error_description` and a `reason` field (expired, not_yet_valid, wrong_audience…); PAT and managed 401s stay byte-for-byte as today; a metric counts each reason. Effort S, risk low, reuses `authenticate`'s error types; verified by a per-reason table test.
✅ Clock skew, wrong audience and expired tokens explain themselves to the person who hit them
✅ Standard OAuth behavior that SDKs and tools already understand, with no secrets or token contents disclosed
❌ Tells a holder of a stolen token whether it has expired, which a generic 401 hides
B) Reasons for operators only
Keep the generic 401 for callers; record the reason in `aerolvm_auth_failures_total{reason}` and a debug log. Effort S, risk low, zero response change; verified by a metric/log test.
✅ Callers learn nothing extra, matching today's Kubernetes-style plain 401
✅ Operators can still diagnose SSO setup from metrics and logs
❌ Developers with an expired CI token or a skewed clock still have to ask an operator
C) Do nothing
Generic 401 everywhere and no reason metric. Effort S, risk low, zero work.
✅ No new response or metric to maintain
✅ Smallest change
❌ SSO setup errors and expired tokens are invisible to everyone

**Section 2 decision gate:** complete. D16 and D17 answered and applied; corrections 2.3, 2.4 and 2.5 applied.

### Section 3: Security and threat model

| # | Threat | Likelihood | Impact | Mitigated? |
|---|---|---|---|---|
| 3.1 | **The dashboard has no HTTPS origin.** `/ui` is not in Caddy's `@api` matcher (`scripts/install.sh:1289`), so people reach it at `http://<host>:21212/ui` or through an SSH tunnel. Entra and Google refuse non-localhost `http` redirect URIs and JS origins, and an ID token typed into a plain-HTTP page crosses the network in the clear. | High (every domain install) | High (L3's dashboard SSO can't be registered; tokens in clear) | **D18 applied** |
| 3.2 | **Token theft by script injection on `/ui`.** The page keeps the bearer (PAT today, SSO tokens next) in `sessionStorage`. It escapes API data (`escapeHTML`, `textContent`; no unescaped interpolation found), but it sends no Content-Security-Policy, and D2 adds a third-party script (`accounts.google.com/gsi/client`). | Low | High (an admin's token) | **D19 applied** |
| 3.3 | **No record of when someone gained a role.** Bindings live in the identity file (I4), and a reload changes who is admin, with no evidence of when. An auditor asking "when did Ana become admin?" gets no answer from the chain. | Med | Med (CC8 change-management evidence) | **D20 applied** |
| 3.4 | **Spoofed client IP.** `X-AerolVM-Client-IP` (D12) is trusted on Caddy's upstream, but `:21212` binds `0.0.0.0` on domain installs, so a remote caller could send the header directly. | Med | Low (it would poison per-IP limits and alert labels) | **correction:** trusted only on the public socket, or from a loopback TCP peer; from any other peer it is dropped and counted |
| 3.5 | **JWT key-substitution tricks.** `jku`, `x5u` or an embedded `jwk` header pointing at an attacker's key. | Low | High | **correction:** keys come only from the configured discovery or `jwks_file`; those headers are ignored. Algorithms = the issuer's advertised set ∩ {RS256, ES256, EdDSA}. Issuer URLs must be `https` (that test-only exception was later removed by finding 5.4). |
| 3.6 | **Input abuse.** Team names, token names, `X-AerolVM-Team`, and claim-derived display names reaching logs, 403 hints, the access-review Markdown/CSV, and the dashboard. | Med | Med | **correction:** team names `[a-z0-9-]{1,63}`; token names `[A-Za-z0-9._-]{1,64}`; a bad `X-AerolVM-Team` → 400. Display names are truncated to 256 characters with control characters stripped. The report escapes Markdown, and CSV prefixes `=+-@` cells with `'` (formula injection). The dashboard renders new fields with `textContent` only. |
| 3.7 | **Personal data in the evidence.** `caller.name` holds email addresses, which ride the hash chain into exports and the witness window. | High (by design) | Med (GDPR / CCPA disclosure) | **correction:** T11 docs (`audit-evidence.mdx`) disclose it. Retention and redaction (`chain.go:44-54`) bound it. The stable id (`oidc:<issuer>:<sub>`) is what links records. |
| 3.8 | **Dependency risk.** New direct deps: `github.com/coreos/go-oidc/v3`, `github.com/go-jose/go-jose/v4`, and `golang.org/x/oauth2` (already indirect at v0.36.0, `go.mod:84`). go-jose has had parsing denial-of-service fixes in past releases. | Low | Med | **correction:** pin the latest releases; the T6 PR lists them; govulncheck runs on the PR |
| 3.9 | **Reading another team's objects by id.** | Low | High | **OK:** `GET /v1/tokens` and `DELETE /v1/tokens/{id}` are fleet-only (auditor, admin). `whoami` returns only the caller. Sandbox and audit reads keep the 404-for-other-team rule. |
| 3.10 | **New secrets.** | — | — | **OK:** `SB_PAT_TOKEN_PREVIOUS` is env-only and rotation-scoped. No client secret sits on the server (D2, L1). `avm_` secrets are stored as SHA-256 of 256 random bits, so offline brute force is infeasible. |
| 3.11 | **Marker test expectation** (spec review #4). | — | — | **corrected** in finding 1.2: 403 in cluster mode, stripped on a single node |

## Answered: S3a (D18 → serve /ui through Caddy on HTTPS)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| People sign in to the dashboard with the provider (L3) | approved (F-LOGIN L3) | can't register: no HTTPS origin | `https://<api-domain>/ui` registered as the redirect URI and JS origin | `http://localhost:21212/ui` through an SSH tunnel | broken |
| Caddy `@api` matcher (`scripts/install.sh:1289`, `packaging/Caddyfile.template`) | existing | no `/ui` | adds `/ui /ui/*` | unchanged | unchanged |
| Where sign-in buttons appear | pending | — | only on HTTPS or a localhost origin; on plain `http` from another host the page says "open https://<domain>/ui to sign in" | localhost only | everywhere |
| Token-paste fallback over plain `http` | existing behavior (L8) | allowed | unchanged, with a warning line | unchanged | unchanged |
| Exposure | — | `/ui` on `:21212` (admin CIDRs) | the static page is also served on the public API domain; data still needs a token | unchanged | unchanged |
| Tests | pending | — | Caddyfile render test; page logic: buttons hidden on non-local `http`; a live UC: sign-in through `https://<domain>/ui` with the test issuer | docs only | — |

Question: D18 — S3a: Where should the dashboard live so people can sign in to it with SSO?
Project/branch/task: plans/identity-and-access.md §5.7 (Section 3, finding 3.1); `scripts/install.sh:1289` Caddy matcher.
ELI10: Today the dashboard is only at the server's raw address on port 21212 over plain HTTP. Caddy, which provides HTTPS, doesn't route `/ui`. Identity providers like Entra and Google won't let you register a plain-HTTP web address, unless it's `localhost`, as a place to send people back after sign-in. Plain HTTP would also send sign-in tokens unencrypted. So either Caddy serves the dashboard on the API's HTTPS address, or dashboard SSO works only through an SSH tunnel to localhost.
Stakes if we pick wrong: Leave it, and L3's dashboard SSO can't be set up on a domain install. Tunnel-only works, but every person needs SSH access to a server just to use the dashboard.
Recommendation: A because L3 promises dashboard SSO, and HTTPS on the API domain is the only address providers accept that doesn't require SSH. The page is static, and its data still needs a token.
Completeness: A=9/10, B=6/10, C=2/10
Net: You are trading one more path on Caddy's public site against dashboard SSO that only works through SSH tunnels.
Header: Dashboard URL
A) Serve /ui through Caddy on HTTPS (recommended)
Add `/ui /ui/*` to Caddy's `@api` matcher; register `https://<api-domain>/ui` with the provider; show sign-in buttons only on HTTPS or localhost, with a pointer otherwise. Effort S, risk low, reuses install.sh's Caddy block; verified by a Caddyfile render test, a page-logic test and a live UC.
✅ Dashboard SSO works on every domain install with a URL providers accept
✅ Sign-in tokens never cross the network in the clear, since the buttons stay hidden on non-local plain HTTP
❌ The static dashboard page becomes reachable on the public API domain, not only on port 21212
B) Tunnel-only dashboard SSO
Leave Caddy alone; document SSO for the dashboard through `ssh -L 21212:127.0.0.1:21212` and register `http://localhost:21212/ui`. Effort S, risk low, zero code.
✅ No change to what Caddy exposes publicly
✅ Providers accept localhost origins, so it can be registered today
❌ Every dashboard user needs SSH access to a server, which most people signing in with SSO won't have
C) Leave it
Ship §5.7 as written. Effort S, risk low, zero work.
✅ No new work
✅ No exposure change
❌ Dashboard SSO cannot be registered on domain installs, breaking L3

## Answered: S3b (D19 → add the CSP)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| `/ui` escapes API data (`escapeHTML`, `textContent`) | existing (`pkg/api/dashboard.html:352`) | yes | unchanged | unchanged | unchanged |
| Bearer kept in `sessionStorage` | existing (`dashboard.html:266`) | PAT today; SSO tokens after T8 | unchanged | unchanged | unchanged |
| Content-Security-Policy on `/ui` | pending (spec review round 1 dropped an implied one as unapproved) | none | `default-src 'none'; script-src 'sha256-<inline script>' https://accounts.google.com/gsi/client; style-src 'unsafe-inline'* (no hash: a hash would make browsers ignore `'unsafe-inline'` and block the page's `style=` attribute); connect-src 'self' <issuer token-endpoint origins>; frame-src https://accounts.google.com; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` | TODOS.md | NOT in scope |
| How the hashes stay right | pending | — | computed at boot from the embedded HTML, so they never drift from the page; `connect-src` rebuilt from the current identity file on each `/ui` request | — | — |
| Inline event handlers / `style=` attributes | existing page | 0 handlers; inline `style=` used | handlers stay banned; `style=` attributes need `'unsafe-inline'` for styles only (*), never for scripts | — | — |
| Tests | pending | — | header test (hash matches the served script); `/browse` check that the dashboard loads and signs in with the CSP on | — | — |

Question: D19 — S3b: Add a Content-Security-Policy to the dashboard now that it holds people's SSO tokens?
Project/branch/task: plans/identity-and-access.md §5.7 (Section 3, finding 3.2); `pkg/api/dashboard.go` serves `/ui`.
ELI10: The dashboard keeps whoever is signed in's token in the browser. If an attacker ever got a script to run on that page, through a missed escape or a bad third-party script, it could steal an admin's token. The page already escapes data carefully, but browsers offer a second lock: a Content-Security-Policy header. It tells the browser to run only the dashboard's own script and Google's sign-in script, and to send data only to AerolVM and the identity provider. The script fingerprint is computed when the server starts, so it can't go stale.
Stakes if we pick wrong: Skip it, and one future escaping bug means stolen admin tokens. Add it carelessly, and a too-strict policy breaks the dashboard. That's why it ships with a browser check.
Recommendation: A because admin SSO tokens now live in that page, and a boot-computed policy adds a strong second lock for very little code.
Completeness: A=9/10, B=6/10, C=4/10
Net: You are trading a small header and one browser test against a single escaping bug turning into stolen admin tokens.
Header: Dashboard CSP
A) Add the CSP (recommended)
`/ui` sends a CSP that allows only the page's own inline script (hash computed at boot), Google's sign-in script, and connections to AerolVM and the configured issuers; no framing, no forms, no base URI. Effort S, risk low, reuses the embedded page; verified by a header test and a `/browse` dashboard check.
✅ A future escaping bug can't run an injected script or send a token to an attacker's server
✅ Hashes come from the embedded page at boot, so they can never drift out of date
❌ Styles still need `'unsafe-inline'` because the page uses `style=` attributes, so style injection isn't blocked
B) Defer to TODOS.md
Record the CSP design with the trigger "before the first enterprise dashboard SSO rollout". Effort S, risk low, zero implementation work now.
✅ T8 stays smaller
✅ The policy is written down for later
❌ SSO tokens sit in a page with no second lock until it ships
C) Skip
Rely on the page's escaping alone. Effort S, risk low, zero work.
✅ Nothing to maintain
✅ No risk of a policy breaking the page
❌ One escaping mistake is enough to leak an admin's token

## Answered: S3c (D20 → record each change with a binding diff)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Bindings live in a per-node file (I4) | approved (F-LOGIN I4, L6) | yes | unchanged | unchanged | unchanged |
| Hash metric for drift between nodes | approved (§5.5) | yes | unchanged | unchanged | unchanged |
| Chain record when the effective file changes | pending | none | kind `identity_config`, caller `system:identity-file`: old → new hash, and a binding diff (added and removed `issuer + match → role/team` lines, deny-list changes), written at reload and at boot when the hash differs from the last record | old → new hash only | none |
| Who changed it | — | — | not knowable from the file. The record points at the hash, and the operator's config history (git, Ansible) names the author. Docs say so. | same | — |
| Volume | — | — | one record per node per change (2,000 nodes → 2,000 records per change; changes are rare) | same | none |
| Access review (D7) | approved | tokens and principals | adds a "binding changes in window" section from these records | hash changes only | — |
| Tests | pending | — | reload writes one record with the correct diff; an unchanged reload writes none; a boot with a changed file writes one | hash-only record test | — |

Question: D20 — S3c: Should changes to the role-binding file be written into the tamper-evident audit log?
Project/branch/task: plans/identity-and-access.md §5.5 (identity file) and §5.10 (access review); Section 3, finding 3.3.
ELI10: Who is an admin is decided by rules in a config file on each server, such as "Okta group platform-admins → admin". When someone edits that file and reloads it, people silently gain or lose power, and the audit log shows nothing. An auditor asking "when did Ana become an admin?" gets no answer. With this change, each server writes one record whenever the rules actually change. The record lists which rules were added or removed, and the access review shows those changes. It can't say which person edited the file; the company's own config history, such as git, holds that.
Stakes if we pick wrong: Skip it, and role changes, the most sensitive change there is, leave no trace in the evidence. Add it, and every server writes one small record per change.
Recommendation: A because a change in who holds admin is exactly what auditors trace, and a binding diff makes the record self-explanatory at almost no cost.
Completeness: A=9/10, B=7/10, C=4/10
Net: You are trading one small record per server per config change against role grants that leave no evidence.
Header: Binding log
A) Record each change with a binding diff (recommended)
Each node writes one `identity_config` chain record on every effective reload (and at boot when the file changed): old and new hash plus added and removed bindings; the access review lists them. Effort S, risk low, reuses the watcher's change hook and the chain writer; verified by reload tests.
✅ "When did Ana become admin?" is answerable from tamper-evident records, with the exact rule that changed
✅ The access review gains a binding-change section with no new store
❌ The record can't name the person who edited the file; that stays in the customer's own config history
B) Record the hash change only
Each node records old → new hash with no diff. Effort S, risk low, reuses the same hook; verified by a reload test.
✅ Smallest possible record, and still proves when a change happened
✅ No diff logic to maintain
❌ An auditor must find the matching file version elsewhere to learn what changed
C) Nothing
Rely on the customer's config history alone. Effort S, risk low, zero work.
✅ No new record kind
✅ Nothing to test
❌ Role grants and removals leave no trace in AerolVM's evidence

**Section 3 decision gate:** complete. D18–D20 answered and applied; corrections 3.4–3.8 applied; 3.9–3.11 OK.

### Section 4: Data flow and interaction edge cases

**Token create:**

```
  INPUT {name, role, team, expires_in} ─► VALIDATE ─► TRANSFORM ─► PERSIST ─► OUTPUT
    │ nil body / bad JSON ──► 400          │ name/team regex ─► 400  │ secret = 32 B rand  │ FSM apply (leader) │ 201 {id, token once}
    │ wrong type ──► 400                   │ role∉4 / team≠* for     │ hash = sha256       │ single-node: SQLite│
    │ name > 64 / unicode ──► 400          │   auditor|admin ─► 400  │ id = 12 base62      │                    │
    │                                      │ ttl > max ─► 400 (max)  │ crc6 checksum       │                    │
    shadow: conflict (same team+name) ─► FSM serial apply ─► 409  │  timeout/leader change ─► 503 (list → revoke by id → recreate)
            ErrClusterVersion ─► 409  │  rand failure ─► 500 (no token persisted)
```

**OIDC-authenticated request:**

```
  bearer JWT ─► parse (3 segments, ≤ 16 KB) ─► header alg ∈ allowed, kid ─► key (cache / ≤1/min refetch) ─► verify
    shadow: > 16 KB ─► 401 malformed │ alg none/HS* ─► 401 invalid_signature │ unknown kid + refetch fails ─► 503
  ─► claims iss/aud/exp/nbf/lifetime ─► deny list ─► bindings (+ X-AerolVM-Team) ─► Access ─► LRU (until exp)
    shadow: skew > 60 s ─► 401 not_yet_valid/expired │ no binding ─► 403 + hint │ bad team header ─► 400
            group overage ─► 403 + hint │ display name > 256 / control chars ─► truncated and stripped
```

**Identity file reload:**

```
  mtime change or SIGHUP ─► read ─► strict YAML ─► validate ─► atomic swap ─► identity_config record (D20) ─► metric
    shadow: empty file ─► invalid (unset SB_IDENTITY_FILE instead) │ unknown field / overlap ─► keep last good + metric
            unreadable (perms) ─► keep last good + metric │ same hash ─► no swap, no record
```

**Async ordering:**

1. **Revoke vs. use on another node.**
   - *Invariant:* a revoked token is refused on every node within ≤ 15 s (UC-271).
   - *Boundary:* the revoke's FSM index `I` on the server tier, and each mirror's next poll.
   ```
     server tier          mirror on node N             request R on N
     revoke@I applied
                          poll (cursor < I) … pending   R reads map → token present → ACCEPT (inside window)
                          poll returns delete@I → drop  R' reads map → miss → 401 unknown_or_revoked
   ```
   - Both orders are inside the window, and that is accepted by contract (§5.4).
   - *Resurrection is prevented:* every change carries a version, and deletes ride the change ring as tombstones. A resnapshot page walk that read the token before the delete can't re-add it, because the merge keeps the higher version and a delete at index ≥ the row's version removes it. This is the placement-feed rule (`internal/cluster/agent_placement_feed.go:19-24`).
   - *Proof:* a pause/release test: page walk paused after reading T, delete applied, walk resumed → T absent.

2. **Concurrent create with the same name on two nodes.** Both forward one hop to the leader. FSM apply is serial, so the first wins (201) and the second gets `ErrTokenNameTaken` (409). *Proof:* two goroutines released together against the FSM → exactly one 201.

3. **Identity reload during a request.**
   - `authenticate` loads one `atomic.Pointer` snapshot and uses it for the whole request. No request mixes two files.
   - A forwarded request may see a different snapshot on the owner during a rollout. Both nodes must accept it, so the stricter file wins (§11 drift row).
   - *Proof:* swap the pointer between authenticate and authorize → the original snapshot is used.

4. **JWKS rotation vs. verify.** The refresh is single-flight and swaps the key set atomically. A verify holds the set it started with. Providers publish the new key before signing with it, so an unknown kid triggers at most one refetch per minute.

5. **Records vs. a crash.**
   - `api` records use the buffered `Emit`, and the writer fsyncs on a ticker (`secretAuditSyncInterval`, `internal/service/secret_audit.go:709`). A crash can lose records not yet synced: the same window secret-open and egress records have today.
   - A torn tail is repaired and marked in the chain. A batch that never reached the file leaves no marker.
   - `SB_AUDIT_API_DURABLE=true` (on in enterprise mode) makes token create, token revoke and sandbox delete wait for fsync.
   - **Correction:** the docs claim "every mutating action is recorded, except calls in the last sync interval before an unclean crash, unless the call is durable".

**Interaction edge cases:**

| Interaction | Edge case | Handled? | How |
|---|---|---|---|
| `aerolvm token create` | double-run / retry | Y | same name → 409; the first secret was shown once |
| `aerolvm token revoke` | twice / unknown id | Y | 204 |
| `aerolvm login --sso` | browser never returns or tab closed | Y | 5 min timeout with the `--device` hint |
| `aerolvm login --sso` | two logins at once | Y | config is written temp + rename; last writer wins (`login.go:91-115`) |
| `aerolvm login --device` | slow polling / `slow_down` | Y | `x/oauth2` honors the interval |
| dashboard | token expires mid-session (Google about 1 h) | **N ← gap** | **correction:** on a 401 with `reason: expired`, the page re-runs sign-in silently once (GIS auto-select; SPA providers re-authorize with `prompt=none`). If that fails, it shows "sign in again" and keeps the current view. |
| dashboard | team switched while a list is open | Y | the list reloads under the new header |
| dashboard | two tabs | Y | `sessionStorage` is per tab, so each tab signs in; documented |
| access review | export empty or missing | Y | exit 3 INCOMPLETE "no export batches found" |
| access review | 100k principals | Y | streams rows; never holds the whole report in memory |
| token list | zero tokens | Y | empty list |
| identity file | zero issuers and bindings | Y | tokens-only mode (L7) |
| identity file | empty file | **N ← gap** | **correction:** an empty file is invalid; unset `SB_IDENTITY_FILE` for tokens-only |
| team header | team with zero sandboxes | Y | empty list, not 404 |

**Findings:** 4.1 crash-window claim wording, 4.2 dashboard re-sign-in on expiry, 4.3 empty identity file invalid, 4.4 tombstoned deletes in the change ring. All four are corrections that implement approved behavior (L3, §5.4, §5.5, §5.9). No new choices.

### Section 5: Code quality

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 5.1 | WARNING → **resolved by eng review D6** | **`authenticate()` branches well over 5 times** (PAT and scope, `avm_`, JWT with an unknown-kid refetch, provider, team header, surface rules), so a single function would be the plan's hardest code to review. | **pending: owner T1 / `/plan-eng-review`.** One option: one entry point over an ordered list of authenticators (`pat`, `apiToken`, `jwt`, `provider`), each returning `(Access, matched, error)`, with team selection and surface rules as separate steps after a match. It is non-blocking and behavior-neutral; it must keep the §5.1 invariant test green. |
| 5.2 | OK | **Reuse for the token mirror.** Worker-to-server calls already have a retrying, server-tier-aware helper (`Agent.doControlPlaneJSON`/`doControlPlaneBytes`, `internal/cluster/agent.go:1428-1471`). | **correction:** T3's mirror uses it instead of a new client |
| 5.3 | WARNING | **Package layout is unnamed**, and the CLI cannot import server packages (learning `aerolvm-cli-dep-guard`). | **correction:** see the layout below |
| 5.4 | WARNING | **`SB_IDENTITY_ALLOW_INSECURE_ISSUER` (added during review) is a test-only switch shipped in production config**, a footgun. | **correction:** remove it. Unit tests inject an `*http.Client` that trusts the `httptest` TLS cert. The harness installs its test CA into the node's trust store. Private-cloud issuers with an internal CA use the system trust store, as every other TLS client on the host does. |
| 5.5 | WARNING | **Unbounded inputs.** A mirror response, a JWT, the identity file, and a discovery or JWKS document from a misbehaving provider. | **correction:** caps of 12 MiB per mirror page (the FSM read budget, `fsm.go:3051`), 16 KB per JWT, 1 MiB for the identity file, and 1 MiB for discovery and JWKS documents; over the cap → refused, with a metric |
| 5.6 | OK | **New errors need HTTP statuses.** | **correction:** `apihttp.Classify` (`pkg/api/apihttp/apihttp.go:117-122`) maps `ErrTokenNameTaken` → 409, `ErrIdentityStale`/`ErrIdentityUnavailable` → 503 + Retry-After, `ErrNoBinding`/`ErrTeamNotBound` → 403, and `errInvalidTokenRequest` → 400, so handlers stay thin (CLAUDE.md convention) |
| 5.7 | OK | **Over-engineering check.** Three flood modes (D14, the founder's choice); the change ring with tombstones (required by 4.4); the verified-JWT LRU (saves ~50 µs × request rate; bounded at 10k). | No cut; each traces to an approved requirement |

**Package layout (correction 5.3):**

```
  pkg/identitywire/     avm_ format, checksum, parse; /.well-known/aerolvm-auth + RFC 9728
                        document types (shared: server + CLI; eng review D2 merged two packages)
  pkg/auditlog/         + Caller, Request, kind constants; search/review readers (shared)
  internal/identity/    token store interface, mirror, OIDC verifier, identity file + watcher, bindings
  internal/cluster/     + FSM ops 31/32, change ring, internal tokens route, StampForward
  pkg/api/              authenticate(), d.Route + permission table, whoami, tokens handlers
  pkg/api/remotemcp/    + Access hand-off, RFC 9728 challenge
  cmd/aerolvm/          login --sso / --device, auth token, whoami, token, access review
```

**Section 5 decision gate:** complete. 5.1 is left to `/plan-eng-review` (non-blocking, owner T1); corrections 5.2–5.6 applied; 5.7 OK.

### Section 6: Test review

**What the plan introduces, and how each is tested:**

```
  NEW THING                                   TYPE          HAPPY                 FAILURE                         EDGE
  authenticate() (5 credential kinds)         unit table    each kind → Access    each reason → 401/403/503       empty bearer, 16 KB JWT, skew ±60 s
  route permission table (T2)                 unit + regis. role × route matrix   unregistered route fails build  facades, MCP inner calls
  token store (SQLite, FSM 31/32)             unit + fsm    create/list/revoke    409 name, ErrClusterVersion     old snapshot restore
  token mirror                                unit + UC-271 delta apply           stale 60 s → 503 (not metrics)  resnapshot vs revoke race
  OIDC verifier + identity file               unit + UC-275 bound role            alg none/HS, aud, iss, kid      reload, overage, empty file
  team header (D13)                           unit + UC     select team           unbound team → 403              forward keeps header
  api / auth_denied / identity_config records unit + UC-273 one record per call   gap on full queue               3 flood modes, shared node
  caller fields + fv gate                     unit + UC-281 old chain verifies    mixed fv → no new fields        retention stub
  PAT scope + public socket + PROXY (D4/D12)  unit + UC-285/288  host-local ok    public PAT 401, socket perms    flag on, wrapper missing
  MCP OAuth + Access hand-off (D10)           unit + UC-286 tool call works       wrong aud, missing hand-off 500 cross-node forward
  CLI login --sso / --device / expiry (D8)    unit + UC-282 saved login works     timeout, refresh fail           env token, --json clean
  dashboard SSO + CSP (D2/D18/D19)            unit + /browse + UC-290  sign in    popup blocked, expiry           http non-local hides buttons
  access review (D7)                          golden files  report rows/flags     tampered batch FAIL             empty export, CSV injection
```

Every row's happy, failure and edge test is named in its task (§7). The assertion check:

| Behavior | Observable assertion | Wrong result it rejects |
|---|---|---|
| Revocation | refused on every node ≤ 15 s (UC-271) | accepted after 15 s |
| Attribution | exactly one `api` record per call, on the owner, with `via` (UC-273) | two records, or none |
| Rolling upgrade | zero verify failures and zero new fields or kinds before the last member upgrades (UC-281) | any new field written early |
| PAT and managed callers | 401/403 bodies byte for byte unchanged (T1, T2) | any new field or hint |

Corrections applied:
- **6.1:** the gate now covers `request` and every new record kind (spec review #9).
- **6.2:** the T10 row lists the Terraform files and the Caddy client-IP line (spec review #14).
- **6.3:** the Section 4 and 5 corrections now have named tests in T3, T6 and T8.

**Ambition checks:**
- **2 a.m. Friday test:** UC-271, UC-273, UC-281 and UC-285 on `cluster-3-mixed`: revocation, forwarded attribution, rolling upgrade, and PAT scope together.
- **Hostile QA:** a token spray; JWT algorithm confusion; `X-Cluster-*` from the public side; a forged `X-AerolVM-Client-IP` from a remote peer.
- **Chaos:** a partitioned worker; Raft leader loss during token creates; a provider key rotation under load.

The plan has the first two partly and the chaos runs not at all; see S6a.

**Flakiness.** Expiry, staleness, the refetch rate limit and the flood budget use an injected clock, never `time.Sleep`. The identity provider is the in-harness test issuer only. The claude.ai and ChatGPT connector checks are manual and never run in CI.

**Test pyramid.** Many unit tables, 23 live use cases (UC-268–UC-290), and two manual end-to-end connector runs. It is not inverted. After D21 there are 26 live use cases (UC-268–UC-293).

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 6.1 | **CRITICAL GAP** | The rollout gate covered only `caller`. `request` and the new kinds would break old readers' hashes mid-upgrade. | **correction** (UC-281's approved "no verify failure" requirement) |
| 6.2 | OK | T10 row incomplete | **correction** |
| 6.3 | OK | Corrections from Sections 4–5 lacked named tests | **correction** |
| 6.4 | WARNING | No load, fuzz or chaos verification for the hottest path (`authenticate`) or for the failure modes that matter most (partition, leader loss, key rotation) | **D21 applied** |

## Answered: S6a (D21 → benchmarks, fuzz, spray and chaos)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Unit tables and UC-268–UC-290 | approved scope (tasks, §8) | in plan | unchanged | unchanged | unchanged |
| Benchmarks with budgets | pending | none | `BenchmarkAuthenticate{PAT,Token,JWTCached,JWTCold}`, `BenchmarkAPIRecordEmit`; CI fails above p99 50 µs (cached paths) or 5 µs (emit) | same as A | none |
| Fuzz targets | pending | checksum fuzz only | `FuzzParseAPIToken`, `FuzzJWTHeader`, `FuzzIdentityFile` | same as A | none |
| Token-spray test | pending | none | 10k req/s of malformed and unknown tokens → zero server-tier calls (metric), `auth_denied` bounded | same as A | none |
| Chaos UCs on `cluster-3-mixed` | pending | none | UC-291: partition a worker 90 s (`avm_` 503, `metrics.read` ok per D16, OIDC and PAT ok). UC-292: kill the Raft leader during a 50-create burst (no duplicate names, no secret returned for an unapplied token). UC-293: rotate the test issuer's keys under 1k req/s (≤ 1 refetch per minute per node, no 5xx beyond the unknown-kid wait). | none | none |
| Cost | — | — | about 1 extra live-run hour plus unit-test time | unit-test time only | none |

Question: D21 — S6a: Add load, fuzz and chaos tests for the parts that run on every request and the failures that hurt most?
Project/branch/task: plans/identity-and-access.md §7 tasks and §8 use cases (Section 6, finding 6.4).
ELI10: The plan tests that each feature works and fails cleanly. It doesn't yet test three things a hostile tester would try first. First, is the sign-in check fast enough to sit on every request? Second, does junk input ever crash the token and config parsers? Third, does the system behave when the cluster's core servers lose their leader, a worker loses its network, or the identity provider swaps keys mid-traffic? Benchmarks and fuzzing are cheap unit tests. The three chaos runs need about one more hour on the live test cluster.
Stakes if we pick wrong: Skip them, and the first real leader loss or key rotation is the test. Add them, and each live run takes a little longer.
Recommendation: A because the sign-in check sits on every request and its failure modes are cluster events, which only a live chaos run proves.
Completeness: A=10/10, B=7/10, C=4/10
Net: You are trading one extra hour per live test run against learning about leader loss and key rotation in production.
Header: Load & chaos
A) Benchmarks, fuzz, spray and chaos (recommended)
Add benchmark budgets that fail CI, three fuzz targets, the token-spray test, and chaos UCs 291–293 on `cluster-3-mixed`. Effort M, risk low, reuses the harness and test issuer; verified by CI budgets plus a live run.
✅ Proves the sign-in check stays cheap on every request, with CI failing on regressions
✅ Leader loss, worker partitions and key rotation are exercised before a customer meets them
❌ About one more hour per live cluster run, and three more UCs to keep green
B) Unit-level only
Add the benchmarks, fuzz targets and spray test, but no chaos UCs. Effort S, risk low, unit-test time only; verified by CI.
✅ Catches performance regressions and parser crashes cheaply in CI
✅ No added live-run time
❌ Leader loss, partitions and key rotation are never exercised before production
C) Neither
Ship the planned unit tables and UCs only. Effort S, risk medium, zero extra work.
✅ No new tests to maintain
✅ Shortest test runs
❌ No proof the hot path stays fast, and the cluster failure modes stay untested

**Section 6 decision gate:** complete. D21 answered and applied; corrections 6.1–6.3 applied.

### Section 7: Performance review

**Memory, per node, worst case at G7 scale:**

| Structure | Bound | Size |
|---|---|---|
| Token mirror | 10k tokens × ~200 B | ~2 MB |
| Verified-JWT LRU | 10k entries and 16 MB (7.4) | ≤ 16 MB |
| JWKS sets | per issuer, 1 MiB cap | < 1 MB |
| Change ring (server tier only) | 10 min of mutations, 1,024–65,536 entries (7.3) | ≤ 13 MB |
| `api` flood buckets `(sandbox, caller)` | the existing bucket-map cap and idle sweep (`egressQuotaMaxEntries`, `secret_audit_quota.go`) | bounded like today's egress buckets |
| Identity file snapshot | 1 MiB cap | < 1 MB |

**Indexes.** SQLite `api_tokens`: primary key `id`, plus `UNIQUE(owner_ref, name)`, used by create's uniqueness check. The FSM `apiTokens` map is keyed by id, with a `(owner, name)` index for the same check. The per-sandbox `?caller=` audit filter scans only that sandbox's posting list (existing read index). `aerolvm audit search` and `access review` scan the export. That is deliberate; the SIEM is the indexed path (§5.10).

**Caching.** Already covered: the mirror, the verified-JWT LRU, and JWKS cached under `Cache-Control`. Nothing else on the request path is expensive.

**Background jobs:**

| Job | Payload | Runtime | Retry |
|---|---|---|---|
| Mirror poll | 304, or a delta ≤ 12 MiB | ms | jittered backoff, 5 s → 30 s |
| Token GC sweep (leader, daily) | expired + 30 d rows | ms | next day |
| JWKS refresh | ≤ 1 MiB | ms | hourly, plus ≤ 1/min on unknown kid |
| Identity-file poll | stat | µs | 10 s |

**Slowest new paths (p99 estimates):**
1. A request with an unknown `kid` right after a provider key rotation: ≤ 2 s (one refetch). Rare.
2. Token create or revoke: one hop plus a Raft apply, ~5–20 ms. Admin-only.
3. `aerolvm access review` over a large export: minutes to hours at G7 scale. Offline; the SIEM path is documented.

On every request: cached `authenticate` ≤ 50 µs (D21 budget). `CreateSandbox` gains ~5 µs (permission check plus enqueue).

**Connection pressure.** One keep-alive connection per worker to a server for the mirror (2,000 connections over ≤ 7 servers, about 285 each), and one HTTP client per issuer for JWKS. No new database connections: SQLite stays single-writer, and the hot path never touches it.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 7.1 | WARNING | `api` records had no target id, so a token revoke couldn't name the token, which breaks D7's "revoked in the window" (spec review #6) | **correction:** `request.target` from path params; token create records the new id, role and team |
| 7.2 | WARNING | `cluster.internal` POSTs (`internal/cluster/agent.go:30-72`) would each write an `api` record, multiplying records per create (spec review #7) | **correction:** added to the "Never" row |
| 7.3 | WARNING | A fixed 1,024-entry change ring: a burst of creates (e.g. 5,000 CI tokens) overflows it, and then all 2,000 mirrors page-walk at once (~4 GB from ≤ 7 servers) | **correction:** time-based ring (10 min, 1,024–65,536 entries) and resnapshots jittered over 30 s |
| 7.4 | OK | LRU bounded by count only; large JWTs (≤ 16 KB each) could reach 160 MB | **correction:** also bounded at 16 MB |

**Section 7 decision gate:** complete. Corrections 7.1–7.4 applied, with tests in T3 and T5.

### Section 8: Observability and debuggability

**What the plan already emits:**
- `aerolvm_auth_requests_total{kind,origin}` and `aerolvm_auth_failures_total{kind,reason}` (D17);
- `aerolvm_identity_stale_accept_total` (D16), `aerolvm_pat_scope_drift` (§5.11), `aerolvm_audit_api_flood_mode{configured,effective}` (D14);
- the identity-file hash metric, and counters for size-cap refusals and dropped `X-AerolVM-Client-IP` headers;
- two alerts: break-glass PAT use, and PAT-scope drift;
- the runbook file name (T10).

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 8.1 | WARNING | **Launch-scope observability is incomplete** (prime directive: dashboards, alerts and runbooks ship with the feature). Missing:<br>• **metrics:** mirror age per node; JWKS fetch health per issuer; identity-file load errors; `api` records written and rate-limited; live token count by role (server tier);<br>• **alerts:** mirror stale; JWKS failing; identity-file drift across nodes; identity-file load errors;<br>• **trace attributes** on the existing OTEL span (`pkg/api/middleware.go:198-210`): principal kind and id, team, permission, auth result;<br>• **structured logs:** token create and revoke, identity reload, mirror resnapshot, stale entry and exit;<br>• **a dashboard row**, and **a runbook entry per alert**.<br>Debuggability gap: "why am I viewer, not runner?" has no answer short of reading the identity file. | **D22 applied** (§5.15) |
| 8.2 | OK | **Three weeks post-ship, can we reconstruct a denial?** Yes, once 8.1 lands: the `api` record (caller, route, result, reason), the 401 reason metric, the trace span with principal and permission, and the identity-file hash at the time (an `identity_config` record, D20). | — |

## Answered: S8a (D22 → full pack plus whoami --explain)

Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Metrics already approved (auth requests/failures, stale accepts, scope drift, flood mode) | approved (D14, D16, D17, §5.11) | in plan | unchanged | unchanged | unchanged |
| New metrics | pending | — | `aerolvm_identity_mirror_age_seconds`, `aerolvm_identity_jwks_fetch_total{issuer,result}` + `…_last_success_timestamp`, `aerolvm_identity_file_load_errors_total`, `aerolvm_audit_api_records_total{result}`, `aerolvm_audit_api_rate_limited_total`, `aerolvm_api_tokens{role}` (server tier) | same | same |
| Alerts in `setup/prometheus/sandboxd-alerts.yml` | 2 approved | 2 | + mirror age > 30 s for 2 m (warning) and > 60 s (critical: tokens refused); JWKS failing 15 m per issuer; identity-file hash differs across nodes 10 m; identity-file load errors | same | none |
| Dashboard | pending | none | an "Identity and access" row in `setup/grafana/d9-security-isolation.json`, checked by `dashboard_metrics_test.go` | same | none |
| Runbook | T10 names the file | file only | one entry per alert in `setup/runbooks/identity-and-access.md` | same | none |
| Trace attributes and structured logs | pending | none | principal kind/id, team, permission, auth result on the existing span; info logs for token create/revoke, identity reload, resnapshot, stale entry and exit | same | none |
| `aerolvm whoami --explain` | pending | — | shows which binding matched and the caller's own claims considered (issuer, groups, roles), never anyone else's | not included | not included |
| Tests | pending | — | metric names exist (`dashboard_metrics_test.go`); alert rules lint; `--explain` golden output | same minus `--explain` | metric names only |

Question: D22 — S8a: Ship the full observability pack for identity and access, including `aerolvm whoami --explain`?
Project/branch/task: plans/identity-and-access.md (Section 8, finding 8.1); `setup/prometheus/sandboxd-alerts.yml`, `setup/grafana/d9-security-isolation.json`, `setup/runbooks/`.
ELI10: The plan emits some numbers and two alerts, but an operator can't yet see the things that break: a worker whose copy of the token list went stale, a provider whose signing keys can't be fetched, or servers running different role-binding files. This pack adds those numbers, alerts that fire before users notice, a dashboard row, and a runbook entry per alert. It also adds `aerolvm whoami --explain`, which answers "why am I a viewer and not a runner?" by showing which rule matched and which of your groups were seen.
Stakes if we pick wrong: Skip it, and the first sign of a stale mirror or broken key fetch is a user's failed request. Add it, and the stack carries a few more metrics, rules and one CLI flag.
Recommendation: A because dashboards, alerts and runbooks are launch scope for a feature this central, and `--explain` turns the most common SSO support question into a command.
Completeness: A=10/10, B=9/10, C=5/10
Net: You are trading a few more metrics, rules and one CLI flag against finding identity failures through user complaints.
Header: Observability
A) Full pack plus `whoami --explain` (recommended)
Add the six metrics, four alerts, the dashboard row, per-alert runbook entries, trace attributes and logs, and `aerolvm whoami --explain`. Effort M, risk low, reuses the existing alert file, dashboard and span; verified by the metric-name test, rule lint and a golden `--explain` output.
✅ Stale mirrors, failing key fetches and config drift page an operator before users notice
✅ "Why am I this role?" becomes `aerolvm whoami --explain` instead of a support thread
❌ More metrics, alert rules and one CLI flag to keep accurate across releases
B) Pack without `--explain`
Everything in A except the CLI flag. Effort M, risk low, same reuse; verified by the metric-name test and rule lint.
✅ Full operator visibility and alerting at launch
✅ No new CLI surface
❌ Role-binding questions still need someone to read the identity file
C) Metrics only
Add the metrics, but no alerts, dashboard row, runbook entries or flag. Effort S, risk medium, zero dashboard work.
✅ Smallest change
✅ The data exists for anyone who builds their own alerts
❌ Nothing tells an operator when identity breaks; users find out first

**Section 8 decision gate:** complete. D22 answered and applied (§5.15).

### Section 9: Deployment and rollout

**Migrations** (all additive, idempotent, no table locks beyond SQLite's single writer):
- `api_tokens` table: `CREATE TABLE IF NOT EXISTS` (T3).
- T0's tenant-to-digest ownership table for WASM modules.
- FSM ops 31/32 with snapshot `Restore` treating nil as empty.
- The audit fields and kinds, appended and `omitempty`, gated on `fv`.

**Feature flags** (all default to today's behavior): `SB_IDENTITY_ENABLED`, `SB_IDENTITY_FILE`, `SB_PAT_SCOPE`, `SB_L4_FALLBACK_PROXY_PROTOCOL`, `SB_AUDIT_API_RECORDS`, `SB_AUDIT_API_FLOOD_CONTROL`, `SB_MCP_ENABLED`.

**Rollout order (cluster):**

```
  1. Upgrade every node to this release, identity still off.     (fv gate closed: no new fields or ops yet)
  2. Last node upgraded → fv gate opens.                         (caller/request fields and api records start)
  3. Ship the identity file and SB_IDENTITY_ENABLED=true          (Terraform/Ansible; rolling restart)
     to every node.
  4. Mint admin and service tokens; move CI and people to SSO or tokens; check `aerolvm whoami`.
  5. Optional, single node or cluster: re-run install.sh to write the 8443 PROXY wrapper,
     set SB_L4_FALLBACK_PROXY_PROTOCOL, and move Caddy to the public socket.
  6. Optional: SB_PAT_SCOPE=host on every node (only after step 1 on all nodes: owners refuse a missing origin).
  Enterprise mode: steps 3 and 6 are required before the upgraded binary will boot, so set the env first.
```

**Rollback, step by step:**
1. `SB_PAT_SCOPE=any` (outside enterprise mode), then restart.
2. `SB_IDENTITY_ENABLED=false`, then restart. The node is PAT-only again; tokens stay stored but unused.
3. Downgrading the binary is safe for FSM ops (old builds skip unknown ops, `fsm.go:1572`) and for the Caddy flag (old builds ignore it). But **not below this release** once a node has written `caller` fields (§5.8 rollback floor): boot once with `SB_SECRET_AUDIT_BOOT_VERIFY=warn`, or stay at or above this release.
4. Undo PROXY protocol: set the flag false and restart **before** removing the 8443 wrapper. The wrapper accepts connections with or without a header, so this order never breaks HTTPS.

**Deploy-time risk window (old and new nodes together):**

| Old node does not know… | What happens | Guard |
|---|---|---|
| ops 31/32 | a token write would be skipped on it | `fv` gate: `ErrClusterVersion` until every server has upgraded |
| `caller`/`request`, new kinds | its readers would fail on new records | `fv` gate on every member (6.1) |
| `X-Cluster-PAT-Origin` | it forwards a PAT with no origin | `host` scope only after a full upgrade; owners refuse a missing origin |
| `X-AerolVM-Team` | it ignores the header, so the team could differ between edge and owner | turn identity on (step 3) only after step 1 |
| `X-Cluster-Surface` | an MCP cross-node call is refused | `SB_MCP_ENABLED` with OAuth only after a full upgrade (runbook) |

**Post-deploy checklist (runbook, D22):**
- **First 5 minutes:** `aerolvm whoami` with the PAT, an `avm_` token and an SSO login; `aerolvm audit verify`; `aerolvm_identity_mirror_age_seconds` < 10 s on every node; `aerolvm_identity_jwks_last_success_timestamp` set per issuer; one `identity_config` record per node.
- **First hour:** no spike in `aerolvm_auth_failures_total` by reason; `aerolvm_audit_api_records_total` tracks request volume; no `rate_limited` records outside known floods.

**Smoke tests:** UC-268, UC-271, UC-273 and UC-275 run as the post-deploy subset of the harness. No new tooling.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 9.1 | OK | `max_token_lifetime` had no default (spec review #15) | **correction:** `24h` default per issuer |
| 9.2 | OK | **T0 migration.** Existing WASM modules had no owner on record. | **Resolved by #724** (merged 2026-10-17): every pre-existing row was backfilled to `""`. Modules a managed tenant uploaded before #724 became operator-published: still usable by everyone, deletable only by the operator. |
| 9.3 | OK | Rollout and rollback order was implicit | **written above**, and copied into the T10 runbook |

**Section 9 decision gate:** complete. 9.1 and 9.3 applied; 9.2 was later resolved by #724 merging.

### Section 10: Long-term trajectory

- **Debt introduced:**
  - *Operational:* the identity file is per node, so drift is possible. It is mitigated by the hash metric and the drift alert, and fixed for good only if bindings move into Raft, which I4 ruled out for now.
  - *Code:* `authenticate` complexity (5.1).
  - *Testing:* the manual claude.ai and ChatGPT connector checks.
  - *Documentation:* provider-specific setup steps (Entra manifest, Google desktop secret, Keycloak mappers) that drift as providers change. The docs date-stamp what was verified (§5.14).
- **Path dependency:** four fixed roles (I1) and one team per request (I2) are cheap now and well contained. Custom roles later means a policy language behind the same permission table. Multi-team later means `ownerScope` returns a set (§13). Neither choice blocks the other.
- **Reversibility: 3/5.** Identity on/off, PAT scope and the PROXY flag are reversible (5). The audit fields are a one-way door below this release (2). FSM ops are reversible by skip (4). Overall it is a mix, with the one-way piece documented.
- **Knowledge concentration:** the plan, §5.0, the two model tables (credential → `Access`, route → permission), the runbook and the docs page. A new engineer can follow it in 12 months if `DESIGN.md` is updated (finding 1.7).
- **Ecosystem fit:** follows the repo's own patterns: the egress-profile dual backend, the operator-file watcher, the `fv` gate, the facade translation rule, and `pkg/` for CLI-shared code.
- **What comes next:**
  1. Per-team quotas (#648), which now have a team to count.
  2. Team-admin delegation (I8 revisited on demand).
  3. Custom roles.
  4. SCIM (I9 revisited).
  5. An OCSF-shaped export for SIEMs.
  6. Per-team default egress profiles bound in the identity file.

  The principal, team and permission table support all six.
- **Platform potential:** named principals and teams become the unit for usage reporting and billing in the managed build (`controlplane.Sample.OwnerRef` already exists). MCP OAuth (D10) makes AerolVM reachable from hosted agent products under the customer's own SSO.
- **Retrospective on the accepted picks:** all accepted picks hold. Three of them were load-bearing on later fixes:
  - D10 needed the forward-marker fix (1.2);
  - D7 needed `request.target` (7.1);
  - D4's alert needed D12's PROXY protocol.

  No skipped item turned out to be load-bearing, since nothing was skipped.

**Section 10 decision gate:** complete. No new choices.

### Section 11: Design and UX (dashboard scope only)

Scoped to the dashboard changes the plan approves (D2, D9, D13, D18, D19), per the learning that this user rejects UI scope beyond the feature.

**User flow:**

```
  /ui (HTTPS or localhost) ──► sign-in screen: [Sign in with Okta] [Sign in with Google] [use a token ▾]
        │ plain http, non-local host ──► "open https://<domain>/ui to sign in" (paste box only, with a warning)
        ▼
  provider (redirect or GIS popup) ──► back to /ui ──► whoami
        │ no binding ──► 403 screen with the D9 hint (issuer, the caller's groups) + [sign out]
        │ several teams ──► team picker ──► (choice saved per tab) ──┐
        ▼                                                          ▼
  overview (header: name · role · team ▾ · sign out) ── 401 expired ──► silent re-sign-in ──► same view
        │ role != admin ──► drain / uncordon / orphan buttons hidden (server enforces regardless)
        └── 403 on an action ──► inline D9 hint next to the action
```

> Superseded in part by design review DR1 and DR2 (2026-10-17): callers without the `admin` role get a signed-in screen, not the overview (§5.7). The dashboard has no team picker, so the "several teams" branch and the Team picker state row no longer apply.

**State coverage:**

| Feature | Loading | Empty | Error | Success | Partial |
|---|---|---|---|---|---|
| Sign-in | "redirecting to <issuer>…" | no issuers configured → paste box only | provider error / popup blocked → inline message | overview | — |
| Team picker | spinner while `whoami` loads | one team → picker hidden | team no longer bound → 403 hint, picker reopens | list reloads | — |
| Role-aware actions | — | viewer: no action buttons | 403 → inline hint | action done | — |
| Session expiry | silent re-sign-in in progress | — | re-sign-in failed → "sign in again" (view kept) | same view | — |

**Accessibility basics:** sign-in buttons are real `<button>` elements with the issuer name as their label, and keyboard focus lands on the first one. Errors and 403 hints go in an `aria-live="polite"` region. Contrast follows the existing dashboard palette.

**Responsive:** the sign-in screen and header use the dashboard's existing layout and reflow at phone width like the rest of `/ui`.

**`DESIGN.md` alignment:** `DESIGN.md` is the actor model, not a visual system. Its update is finding 1.7.

**Generic-UI risk:** low. The flow reuses the existing page, and the screens are the standard sign-in, picker and hint states.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 11.1 | OK | Loading, empty and error states for sign-in, the picker and expiry weren't written down | **correction:** the state table above goes into T8 as acceptance criteria |
| 11.2 | OK | Accessibility basics unstated | **correction:** the button, focus and `aria-live` rules go into T8 |

Not proposed: an expiry countdown in the header, and a "copy whoami" button. Both are optional extras outside the approved feature. `/plan-design-review` is optional for this scope: the UI change is a sign-in screen and a picker inside an existing page.

**Section 11 decision gate:** complete. No new choices.

## Closing

### Outside voice

Codex preflight: `CODEX_MODE: model_unusable`. The configured Codex model id is invalid (hint: set `GSTACK_CODEX_MODEL` or the `config.toml` model), so no Codex call was made. The native fallback needs `TaskOutput`, which this session does not have, so the outside voice is **unavailable**. This is missing coverage, not a clean review; it was logged as `unavailable`.

### TODO choices

No TODO proposals remain. Every expansion was accepted (D4–D10), and no item was deferred or skipped. TODOS.md changes only during implementation (T11 marks the metrics-token item resolved with its caveat, D6).

### Approval readiness

Each approved remedy is cited to its actual answer, and the plan applies only that answer's scope:
- F-LOGIN, F-RECS, F-NOCOMMIT (founder message 2026-10-16);
- R-EXCHANGE (D2), S-SSH (D3), E-PATCONF (D4), E-PATCONF-ENT (D5), E-METRICS (D6), E-ACCESSREVIEW (D7), E-EXPIRYWARN (D8), E-DENYHINT (D9), E-MCPOAUTH (D10), document approval (D11);
- A1 (D12), A3 (D13), A5 (D14, custom answer), A6 (D15), S2a (D16), S2b (D17), S3a (D18), S3b (D19), S3c (D20), S6a (D21), S8a (D22).

Corrections made without a question only implement approved behavior, or fix text that contradicted it: 1.2, 1.4, 1.7, 1.8, 2.3–2.5, 3.4–3.8, 4.1–4.4, 5.2–5.6, 6.1–6.3, 7.1–7.4, 9.1, 9.3, 11.1, 11.2 and the stale-diagram fix.

Unresolved and kept out of accepted work: 5.1 (`authenticate` structure), owned by `/plan-eng-review`. 9.2 (the T0 backfill rule) was resolved when #724 merged with a backfill to `""`.

**Approval readiness: PASS**

### NOT in scope

Nothing was deferred or rejected in this review. §13 stands as the NOT-in-scope list (8 items: custom roles and ACLs, multi-team sessions, SAML/SCIM, token last-used, CLI keychain, SSH key-to-person binding, per-team quotas, live fleet-wide audit query). MCP OAuth moved out of it into scope (D10).

### What already exists (and is reused)

| Existing code | Reused for |
|---|---|
| `controlplane.Validator` / `Access` (`pkg/controlplane/controlplane.go:42-60`) | the principal model; the managed path is unchanged |
| `ownerScope` / `enforceOwner` (`internal/service/owner_scope.go`) | team scoping |
| Egress-profile dual backend + `fv` gate (`internal/service/egress_profiles.go:59-78`, `fsm_egress_profiles.go`) | token store, both modes |
| Placement feed merge rule (`agent_placement_feed.go:11-26`) | mirror versioning and tombstones |
| `Agent.doControlPlaneJSON` (`internal/cluster/agent.go:1428-1471`) | mirror polling |
| Egress operator watcher (`internal/egress/operator/watch.go`) | the identity file |
| Secret-audit chain, witness, export, retention, read index | `caller`, `api` records |
| Per-sandbox audit budget (`internal/service/secret_audit_quota.go`) | `api` flood control (D14) |
| `auditlog.VerifyNode` (`pkg/auditlog/verify.go:139`) | `audit search` and `access review` |
| `clusterControlHeaderGuard` (`pkg/api/middleware.go:25-60`) | trust for the new `X-Cluster-*` markers |
| `EnsureLayer4` / `layer4_bootstrap_test.go` | the PROXY v2 fallback (D12) |
| Dashboard `escapeHTML` (`pkg/api/dashboard.html:352`) | new fields render safely |
| `apihttp.Classify` | status mapping for new errors |

### Dream state delta

```
  12-MONTH IDEAL                                  AFTER THIS PLAN
  named credentials enforced for people           DONE (D4, D5)
  no long-lived secrets anywhere                  MOSTLY: workload identity for CI; scoped expiring tokens elsewhere;
                                                  the PAT remains as the host/peer credential
  access-review evidence on demand                DONE (D7, D20)
  every action provably attributed                DONE, except the documented crash window and SSH-by-key
  MCP connectors under customer SSO               BUILT; ChatGPT pending a live check (D10)
  per-team quotas and policy                      NOT YET: unblocked (#648)
```

### Error and rescue registry

The Section 2 tables are the registry: 22 codepaths and 30 error classes, every one rescued. `errNoAccess` is a guarded programming error with a test. **0 critical gaps.**

### Failure modes registry

```
  CODEPATH              | FAILURE MODE                    | RESCUED? | TEST?            | USER SEES?               | LOGGED?
  ----------------------|---------------------------------|----------|------------------|--------------------------|---------------
  authenticate          | token mirror stale > 60 s       | Y        | T3, UC-291       | 503 "identity stale"     | metric + alert
  authenticate          | JWKS never fetched              | Y        | T6               | 503 "keys unavailable"   | metric + alert
  authenticate          | expired / clock skew            | Y        | T1 reason table  | 401 with reason (D17)    | metric
  authenticate          | no binding / unbound team       | Y        | T6               | 403 + hint (D9)          | api record
  token create          | Raft leader change              | Y        | UC-292           | 503 + recovery hint      | log
  token create          | name taken                      | Y        | T3               | 409                      | api record
  token mirror          | ring overflow → resnapshot      | Y        | T3 (7.3)         | none                     | log
  identity file         | invalid reload                  | Y        | T6               | none (last good kept)    | metric + alert
  identity file         | drift across nodes              | Y        | alert rule lint  | none                     | metric + alert
  api recorder          | queue full                      | Y        | existing         | none                     | gap record
  api recorder          | call flood                      | Y        | T5, UC-289       | none                     | rate_limited record
  caller fields         | mixed fv during upgrade         | Y        | UC-281           | none                     | —
  PAT scope             | public socket perms             | Y        | T10              | daemon refuses start     | boot log
  L4 PROXY (D12)        | flag on, wrapper missing        | Y        | T10 + runbook    | HTTPS down until fixed   | boot log
  forward paths         | marker not stamped              | Y        | call-site test   | (prevented)              | —
  remote MCP            | Access hand-off missing         | Y        | T13              | 500                      | log
  CLI login             | callback timeout                | Y        | T7               | hint to use --device     | —
  dashboard             | token expiry mid-session        | Y        | T8               | silent re-sign-in        | —
  access review         | tampered or missing batch       | Y        | T5b              | FAIL / exit 3            | —
  audit writer          | crash before the fsync tick     | Partial  | existing torn-tail | silent (documented)    | torn-tail marker
```

**0 CRITICAL GAPS.** No row is unrescued, untested and silent at once. The crash window is the existing audit behavior; it is documented (4.1), and durable mode covers token and delete records.

### Scope expansion decisions

From the CEO plan's 0G record:
- **Accepted:**
  - D4: `SB_PAT_SCOPE=host`;
  - D5: enterprise mode requires it;
  - D6: `metrics.read`;
  - D7: `aerolvm access review`;
  - D8: CLI expiry warnings;
  - D9: 403 hints;
  - D10: MCP OAuth.
- **Deferred:** none. **Skipped:** none.
- **Approach and scope items also settled:** D2 (Google Identity Services), D3 (SSH record kept).

### Diagrams produced

- System architecture (Section 1).
- Data flows with shadow paths: authenticate, mirror, `api` record, token create, OIDC request, identity reload (Sections 1 and 4).
- State machines: token, mirror, identity file (Section 1).
- Error flow: the Section 2 tables.
- Deployment sequence: Section 9.
- Dashboard user flow: Section 11.
- Rollback flowchart:

```
  problem after deploy
     │
     ├─ PAT callers locked out under host scope? ── yes ─► SSH to host, use 127.0.0.1:21212 ─► (not enterprise) SB_PAT_SCOPE=any, restart
     ├─ HTTPS down after install.sh?            ── yes ─► SB_L4_FALLBACK_PROXY_PROTOCOL=false, restart ─► then remove the 8443 wrapper
     ├─ SSO users failing?                      ── yes ─► check whoami (PAT) + JWKS metrics ─► fix the identity file / SIGHUP
     ├─ identity broken overall?                ── yes ─► SB_IDENTITY_ENABLED=false, restart (PAT-only, tokens kept)
     └─ need an older binary?                   ── yes ─► not below this release once caller fields exist;
                                                          else boot once with SB_SECRET_AUDIT_BOOT_VERIFY=warn
```

### Stale diagram audit

| File | Diagram | Still accurate after ship? |
|---|---|---|
| `docs/src/content/docs/enterprise/architecture.mdx` | 2 mermaid diagrams: "apps hold the API token", "API token" edge; credential tables at lines 50, 72, 150 | **No.** T11 redraws them with named credentials. |
| `docs/src/content/docs/engineering-trust-boundary.mdx` | toolbox-token diagram | Yes: it is about the in-sandbox token |
| `docs/src/content/docs/engineering-security-overview.mdx` | security overview | Check in T11 for "one API token" wording |
| `DESIGN.md` | actor and action tables (not a diagram) | **No.** T11 updates them (1.7). |
| `internal/cluster/agent_placement_feed.go` | feed state comment | Yes: reused unchanged |

## Implementation Tasks

Synthesized from this review's findings. Each task derives from a specific finding above and lands inside the §7 task named in brackets. Run with Claude Code or Codex; checkbox as you ship. Effort assumptions: features ~30×, tests ~50×, architecture ~5× human ÷ CC.

- [ ] **CR1 (P1, human: ~1 d / CC: ~1 h)** — caddy/L4 — PROXY v2 on the caddy-l4 fallback plus the 8443 listener wrapper, behind `SB_L4_FALLBACK_PROXY_PROTOCOL` [T10]
  - Surfaced by: Section 1, finding 1.1 (D12)
  - Files: `pkg/caddy/client.go`, `internal/service/layer4_bootstrap_test.go`, `scripts/install.sh`, `packaging/Caddyfile.template`
  - Verify: `go test -run TestEnsureLayer4 ./internal/service/...`; UC-288
- [ ] **CR2 (P1, human: ~1 d / CC: ~45 min)** — cluster — `cluster.StampForward` on every forward path, plus a call-site test [T4]
  - Surfaced by: Section 1, finding 1.2
  - Files: `internal/cluster/forward.go`, `pkg/api/clusterroute/forward.go`, `pkg/api/clustercreate/clustercreate.go`, `pkg/api/clusterlist/list.go`, `pkg/api/v1/js_bundle.go`, `pkg/api/v1/cluster_handler.go`, the runloop forward file (to be determined)
  - Verify: `go test ./internal/cluster/... ./pkg/api/...`; UC-273, UC-286
- [ ] **CR3 (P1, human: ~3 d / CC: ~2 h)** — auth — `X-AerolVM-Team` selection in the server, CLI, dashboard and all 5 SDKs [T6–T9]
  - Surfaced by: Section 1, finding 1.3 (D13)
  - Files: `pkg/api/` (authenticate), `internal/identity/` (bindings), `cmd/aerolvm/`, `pkg/api/dashboard.html`, `sdk/*` (to be determined)
  - Verify: T6 selection tests; per-SDK header tests
- [ ] **CR4 (P1, human: ~1.5 d / CC: ~1 h)** — audit — `SB_AUDIT_API_FLOOD_CONTROL` budget/coalesce/both, with the shared-node rule [T5]
  - Surfaced by: Section 1, finding 1.5 (D14)
  - Files: `internal/service/secret_audit_quota.go`, `internal/service/secret_audit.go`
  - Verify: the budget/coalesce/both tables; UC-289
- [ ] **CR5 (P2, human: ~3 h / CC: ~15 min)** — cli — expiry check for environment tokens [T7]
  - Surfaced by: Section 1, finding 1.6 (D15)
  - Files: `cmd/aerolvm/`
  - Verify: CLI tests (no cache → one `whoami`; `--json` clean)
- [ ] **CR6 (P1, human: ~3 h / CC: ~15 min)** — identity — a stale mirror still accepts `metrics.read`-only routes [T3]
  - Surfaced by: Section 2, finding 2.1 (D16)
  - Files: `internal/identity/` (to be determined)
  - Verify: stale-mirror tests; UC-291
- [ ] **CR7 (P1, human: ~4 h / CC: ~20 min)** — auth — RFC 6750 401 reasons for `avm_` and JWT failures [T1]
  - Surfaced by: Section 2, finding 2.2 (D17)
  - Files: `pkg/api/middleware.go`
  - Verify: per-reason table; PAT 401 body byte for byte unchanged
- [ ] **CR8 (P1, human: ~4 h / CC: ~20 min)** — caddy/dashboard — `/ui` in Caddy's `@api` matcher, sign-in only on HTTPS or localhost [T8]
  - Surfaced by: Section 3, finding 3.1 (D18)
  - Files: `scripts/install.sh`, `packaging/Caddyfile.template`, `pkg/api/dashboard.html`
  - Verify: Caddyfile render test; UC-290
- [ ] **CR9 (P1, human: ~4 h / CC: ~20 min)** — dashboard — CSP with a boot-computed script hash [T8]
  - Surfaced by: Section 3, finding 3.2 (D19)
  - Files: `pkg/api/dashboard.go`
  - Verify: header test; `/browse` dashboard check
- [ ] **CR10 (P1, human: ~6 h / CC: ~30 min)** — audit — `identity_config` records with a binding diff [T6]
  - Surfaced by: Section 3, finding 3.3 (D20)
  - Files: `internal/identity/`, `pkg/auditlog/event.go`
  - Verify: reload tests (diff; unchanged → none; changed boot → one)
- [ ] **CR11 (P1, human: ~3 d / CC: ~2 h)** — tests — benchmarks with CI budgets, fuzz targets, the token spray, chaos UCs 291–293 [T1, T3, T5, T6, T12]
  - Surfaced by: Section 6, finding 6.4 (D21)
  - Files: `pkg/identitywire/`, `internal/identity/`, `pkg/api/`, `integration-tests/suite/`
  - Verify: `go test -bench . ./pkg/api/...`; `go test -fuzz` targets; live `cluster-3-mixed` run
- [ ] **CR12 (P1, human: ~2 d / CC: ~1.5 h)** — obs — the §5.15 pack: metrics, six alerts, the Grafana row, runbook entries, trace attributes, logs, `whoami --explain` [T1, T7, T10]
  - Surfaced by: Section 8, finding 8.1 (D22)
  - Files: `setup/prometheus/sandboxd-alerts.yml`, `setup/grafana/d9-security-isolation.json`, `setup/runbooks/identity-and-access.md`, `pkg/api/middleware.go`, `cmd/aerolvm/`
  - Verify: `go test ./setup/grafana/...` (dashboard metrics); alert rule lint; golden `--explain`
- [ ] **CR13 (P1, human: ~4 h / CC: ~20 min)** — audit — the `fv` gate covers `request` and every new kind [T4]
  - Surfaced by: Section 6, finding 6.1 (critical, corrected)
  - Files: `internal/service/secret_audit.go`, `pkg/auditlog/event.go`
  - Verify: UC-281 extended; mixed-version gate test
- [ ] **CR14 (P1, human: ~4 h / CC: ~20 min)** — audit — `request.target` on non-sandbox routes; `cluster.internal` never recorded [T5]
  - Surfaced by: Section 7, findings 7.1 and 7.2
  - Files: `pkg/api/` (`d.Route`)
  - Verify: record-per-route table
- [ ] **CR15 (P2, human: ~6 h / CC: ~30 min)** — cluster — time-based change ring and jittered resnapshots [T3]
  - Surfaced by: Section 7, finding 7.3
  - Files: `internal/cluster/` (token ring, to be determined)
  - Verify: 5,000-create burst test; resnapshot spread ≥ 30 s
- [ ] **CR16 (P2, human: ~1 d / CC: ~45 min)** — security — input validation, `X-AerolVM-Client-IP` trust rule, JWT key rules, size caps [T3, T6, T10]
  - Surfaced by: Section 3, findings 3.4–3.6; Section 5, finding 5.5
  - Files: `pkg/api/`, `internal/identity/`, `pkg/identitywire/`
  - Verify: validation tables; fuzz targets
- [ ] **CR17 (P2, human: ~4 h / CC: ~30 min)** — docs — `DESIGN.md` actors, `architecture.mdx` diagrams, PII disclosure, crash-window wording [T11]
  - Surfaced by: Section 1, finding 1.7; Section 3, finding 3.7; Section 4, finding 4.1; the stale-diagram audit
  - Files: `DESIGN.md`, `docs/src/content/docs/enterprise/architecture.mdx`, `docs/src/content/docs/enterprise/audit-evidence.mdx`
  - Verify: `make docs-build` with npm 10
- [ ] **CR18 (P2, human: ~1 d / CC: ~45 min)** — identity — managed role limits, dashboard re-sign-in on expiry, empty identity file invalid, tombstoned deletes [T1, T3, T6, T8]
  - Surfaced by: Section 1, finding 1.4; Section 4, findings 4.2–4.4
  - Files: `pkg/controlplane/controlplane.go`, `internal/identity/`, `pkg/api/dashboard.html`
  - Verify: §5.1 invariant test; T8 expiry test; T6 empty-file test; T3 resurrection test
- [ ] **CR19 (P2, human: ~1 h / CC: ~10 min)** — plan — resolve the `authenticate` structure (5.1) [eng review]. 9.2 was resolved by #724.
  - Surfaced by: Section 5, finding 5.1; Section 9, finding 9.2
  - Files: `plans/identity-and-access.md`
  - Verify: `/plan-eng-review` records both decisions

### Completion summary

```
  +====================================================================+
  |            MEGA PLAN REVIEW — COMPLETION SUMMARY                   |
  +====================================================================+
  | Mode selected        | SELECTIVE EXPANSION                         |
  | System Audit         | DESIGN.md actor model; TODOS metrics-token  |
  |                      | item; 3 spec reviews (52 found, 36 fixed in  |
  |                      | the loop, 16 closed in the sections)         |
  | Step 0               | SELECTIVE (D1); D2–D11; login locked (§5.0)  |
  | Section 1  (Arch)    | 8 issues found                              |
  | Section 2  (Errors)  | 30 error paths mapped, 2 GAPS (resolved)    |
  | Section 3  (Security)| 11 issues found, 3 High severity (resolved) |
  | Section 4  (Data/UX) | 14 edge cases mapped, 2 unhandled (fixed)   |
  | Section 5  (Quality) | 7 issues found (1 left to eng review)       |
  | Section 6  (Tests)   | Diagram produced, 4 gaps (1 critical, fixed)|
  | Section 7  (Perf)    | 4 issues found                              |
  | Section 8  (Observ)  | 1 gap found (resolved by D22)               |
  | Section 9  (Deploy)  | 3 risks flagged (1 left to eng review)      |
  | Section 10 (Future)  | Reversibility: 3/5, debt items: 4           |
  | Section 11 (Design)  | 2 issues (dashboard scope only)             |
  +--------------------------------------------------------------------+
  | NOT in scope         | written (8 items, §13)                      |
  | What already exists  | written                                     |
  | Dream state delta    | written                                     |
  | Error/rescue registry| 30 rows, 0 CRITICAL GAPS                    |
  | Failure modes        | 20 total, 0 CRITICAL GAPS                   |
  | TODOS.md updates     | 0 items proposed                            |
  | Scope proposals      | 7 proposed, 7 accepted (SEL)                |
  | CEO plan             | written                                     |
  | Outside voice        | codex unavailable (model_unusable); native  |
  |                      | fallback unavailable (no TaskOutput)        |
  | Lake Score           | 2/2 recommendations chose complete option   |
  | Diagrams produced    | 14 (architecture, 6 data flows, 3 state,    |
  |                      | error tables, deploy, rollback, user flow)  |
  | Stale diagrams found | 1 file (architecture.mdx) + DESIGN.md table |
  | Unresolved decisions | 1 (5.1; 9.2 resolved by #724)               |
  +====================================================================+
```

### Unresolved decisions

- 5.1: how `authenticate` is structured. One function, or an ordered list of authenticators. Behavior-neutral; owner T1 / `/plan-eng-review`.
- ~~9.2~~: resolved by #724 (merged 2026-10-17): existing rows were backfilled to `""`.


---

# Eng review: `/plan-eng-review` 2026-10-17

**Target (fixed):** `plans/identity-and-access.md` (PR #734, branch `plans/identity-and-access`, rebased on `main` at `ed6d8814`). **Report file:** this plan. **Design reference:** `DESIGN.md`. **Settled inputs:** §5.0 L1–L8 (founder-locked), and CEO-review answers D1–D24 (ledger above). Neither is reopened here without new evidence.

## Eng Scope Challenge

### A. Assessment

- **What already solves each sub-problem.** The §5.13 reuse map and the CEO-review "What already exists" table still hold. Three things landed on `main` after the CEO review (the `xtenant` series, #719–#733) and bear on this plan:
  - `pkg/daemon/itest_identity.go` plus `pkg/daemon/daemon.go:100-114`: a test-only static validator, `SB_ITEST_IDENTITY_FILE` (finding E2).
  - `internal/service/owner_scope.go:70-90`: `snapshotResolvableForCreate`, which treats "unscoped" as "operator" (finding E1).
  - `pkg/api/remotemcp/handler.go`: `bearerToken` re-implements `extractBearerToken` and must "stay in lockstep" (finding E3). The b374ec3d guarantee also matters: an empty token never reaches `agenttools`, whose SDK client otherwise falls back to `SB_PAT_TOKEN` (finding E4).
- **FSM op numbers:** still free at 31/32 (`internal/cluster/fsm.go:57-58` ends at 30).
- **Minimum changes for the goal.** The founder's CEO review approved scope (D1–D24, recorded as an active decision). No cut is proposed: each piece maps to a questionnaire row, a locked rule, or an approved remedy.
- **Complexity:**
  - About 130 changed files (estimate).
  - New components: `internal/identity` (token store interface, mirror, OIDC verifier, identity-file watcher, bindings), `pkg/identitywire`, the `api` recorder on the existing budget, `cluster.StampForward`, and the access-review reader.
  - The gate trips (≥ 8 files, ≥ 2 new components).
- **Search check:** the OIDC resource-server model (KEP-3331), PROXY protocol and CSP were researched in the CEO review (sources there). The new check is how `go-oidc` `RemoteKeySet` refetches keys: its docs say keys are cached by `Cache-Control`. A minimum interval between unknown-kid refetches is **not confirmed**. T6 must verify it or wrap the key set with its own 1-per-minute limiter; T6 and UC-293 already test the requirement.
- **TODOS cross-reference:** "Metrics-scoped read-only token" is resolved by D6 (T11). Nothing in TODOS.md blocks this plan.
- **Distribution:** no new binary or artifact. CLI changes ship in the existing `aerolvm` release path; alerts and dashboards ship in `setup/`.
- **Retrospective:** the auth edge has needed repeated fixes (`d6b865d9` edge-auth gaps S6–S10, `b374ec3d` MCP operator fallback, and twelve `xtenant` PRs). The recurring cause is owner and capability checks scattered across about 30 `ownerScope` call sites. This is the architectural concern behind E1.

### B. Complexity selectors

No feature cuts proposed (scope approved in the CEO review). The structure question follows.

**Scope record:**
- **Feature answers:** none asked (no cuts proposed; the CEO-review scope D1–D24 stands).
- **Structure:** B, "Smaller arrangement (recommended)" (D2, 2026-10-17).
- **Accepted scope:** the CLI-shared token-format and discovery-document packages become one package, `pkg/identitywire`. Every reference in this plan is updated. Features, PR count (T1–T13 + T5b remaining), contracts and tests are unchanged.
- **Pending remedies:** E1, E2, E3, E4.

### C. Findings

The Scope Challenge's own findings are the structure item above (resolved by D2) and the search-check note on `go-oidc` (a verification already owned by T6 and UC-293; no new choice). Findings E1–E4 come from the `main` changes and are architecture and code-quality items, resolved in Sections 1 and 2.

**Scope Challenge result:** scope accepted as-is. The smaller arrangement preserves scope; it is not a reduction.

## Eng Section 1: Architecture

**Findings** (most severe first):
- `[P1] (confidence: 9/10) internal/service/service.go:1611` — **E1.** Operator-only capabilities are gated on "unscoped", and the plan makes non-admin principals unscoped.
  - Quoted: `if _, scoped := ownerScope(ctx); scoped && len(mounts) > 0 { return models.ErrMountOperatorOnly }`.
  - The same pattern: `isolate.go:94` (`scoped && jsbundle.IsFileRef(bundleRef)` → file:// bundles, an arbitrary host-file read); `custom_domains.go:469` and `dns_verify.go:37-39` (DNS TXT proof skipped when unscoped); `facade_state.go:159` (`if _, scoped := ownerScope(ctx); !scoped { return nil }`, which skips snapshot visibility).
  - The plan's §5.1 sets `Fleet` (unscoped) for any role bound to `*`, and §5.3 allows `runner` on `*`. A `runner@*` token would therefore get raw host-side mounts (pr-review §5: verbatim inputs run as the daemon user), host-file bundle reads, and custom domains without the DNS proof.
- `[P1] (confidence: 9/10) pkg/daemon/daemon.go:100-114` — **E2.** A test-only static validator ships in release binaries, gated only by an env var.
  - Quoted: `if path := strings.TrimSpace(os.Getenv("SB_ITEST_IDENTITY_FILE")); path != "" { … cp.Validator = itestStaticValidator{tokens: tokens} …`.
  - It maps plaintext tokens to owners from a file (`pkg/daemon/itest_identity.go`).
  - It collides with §5.2's boot rule: identity on plus a non-noop provider validator must refuse to boot. So the harness can't test identity while it uses this file.
  - Enterprise mode does not refuse it.
- `[P2] (confidence: 8/10) pkg/api/remotemcp/handler.go` (`serverFor`) — **E4.** Since b374ec3d, remote MCP refuses an empty token "rather than escalate", because the `agenttools` SDK client falls back to `SB_PAT_TOKEN` (the operator PAT) on an empty token. D10's in-process `Access` hand-off (§5.14) must keep that guarantee: inner calls act only as the caller, never as the SDK's default credential.

**Architecture checks** (beyond the CEO review's Section 1, which stands):
- **Boundaries:** unchanged.
- **New coupling from `main`:** about 30 `ownerScope` call sites now (the `xtenant` series added about 10). T1's `Operator → Fleet` rename touches all of them; sizing stays M.
- **Per-owner snapshot namespaces** (#731) give each team its own snapshot names for free. Fleet principals create in the operator namespace (`""`), as the PAT does.
- **Distribution:** none new.

## Eng review decision ledger

### E1: what fleet-scoped non-admin principals may do
Finding: E1, P1, confidence 9/10, `internal/service/service.go:1611`, `isolate.go:94`, `custom_domains.go:469`, `dns_verify.go:37-39` (and, as first written, `facade_state.go:159`), reviewer: Claude (eng review)
Plan baseline: D3 approved "Explicit operator predicate": keep runner@*; `hostCapable(ctx)` on **five** gates, including `facade_state.go:159`.
Runtime evidence (new, reason for reopening): `facade_state.go:156-165` `requireVisibleSnapshot` is a **visibility** check, not an operator power. It is skipped for unscoped callers because they see every owner's snapshots. Its caller, `UpsertSnapshotAlias` (`facade_state.go:92-112`), uses it so a *team-scoped* token cannot retarget another team's alias. A fleet runner already writes across every team by design, so gating this on `hostCapable` would wrongly limit fleet runners and viewers to operator-namespace (`""`) snapshots. The other four sites are real host or trust powers: raw host mounts, `file://` host reads, and skipping the DNS ownership proof (`custom_domains.go:456-468`: "Operator/PAT callers are trusted to control DNS").
Comparison grid:

| Choice | Current (D3 as approved) | A | B |
|---|---|---|---|
| Predicate approach and runner@* | `hostCapable`, runner@* kept (D3) | unchanged | unchanged |
| Gates switched to `hostCapable` | five: `service.go:1611`, `isolate.go:94`, `custom_domains.go:469`, `dns_verify.go:37-39`, `facade_state.go:159` | **four** (`facade_state.go:159` keeps following `Fleet` visibility) | five, as approved |
| Fleet runner/viewer and snapshot aliases | limited to operator-namespace snapshots | may alias and see any team's snapshots (consistent with cross-team writes) | limited to `""` snapshots |
| Tests | predicate table over five gates | over four gates, plus a row: runner@* may upsert an alias onto a team snapshot | over five gates |

Question D7:
D7 — E1 (reopened): One of the five "operator-only" spots I listed is actually a visibility check. Switch four of them, not five?
Project/branch/task: plans/identity-and-access.md §5.1 / T2 (PR #734); reopening D3's list only. The predicate and runner@* stay as you chose.
ELI10: You chose to make machine-level powers ask "are you an admin or the operator?". I listed five places in the code for that, but one is wrong. The snapshot-alias check at `facade_state.go:159` doesn't guard a machine power. It stops one team's token from taking over another team's snapshot nickname. A fleet-wide runner is allowed to work across every team anyway, so putting that check behind admin would block fleet runners from aliasing team snapshots for no security gain. The other four (raw host mounts, reading host files, skipping the domain-ownership proof) are real machine-level powers and stay behind the new check.
Stakes if we pick wrong: Keep five, and fleet-wide runners and viewers can only see and alias operator snapshots, which contradicts their cross-team role. Switch four, and nothing about host safety changes.
Recommendation: A because the alias check is about which team's data you can see, which fleet scope already answers, while the other four are the real host powers D3 was meant to protect.
Note: options differ in kind, not coverage — no completeness score.
Net: You are deciding whether a visibility check wrongly rides along with the host-power fix.
Header: Gate list
Options:
A) Four gates (recommended)
Switch `service.go:1611`, `isolate.go:94`, `custom_domains.go:469` and `dns_verify.go:37-39` to `hostCapable`; leave `facade_state.go:159` on fleet visibility; add a test row for a fleet runner aliasing a team snapshot. Effort S (human ~15 min / CC ~2 min of plan change), risk low, maintenance: none extra.
✅ Host powers stay admin-or-operator only, exactly as D3 intended
✅ Fleet runners and viewers keep consistent cross-team visibility for snapshots and aliases
❌ One more row in the predicate test to explain why that call site is deliberately excluded
B) Five gates, as approved
Keep D3's list unchanged, including `facade_state.go:159`. Effort S, risk low, zero change.
✅ No change to the recorded D3 scope
✅ Fleet runners get the narrowest snapshot-alias reach
❌ Fleet runners and viewers can't see or alias team snapshots, contradicting their cross-team role

State: approved
Actual answer: A) "Four gates (recommended)" (D7, 2026-10-17), refining D3's A) "Explicit operator predicate"
Accepted scope: keep `runner` on `*`; `hostCapable(ctx)` (operator/PAT, `node:`, no-Access internal, `admin`) on **four** gates (`service.go:1611`, `isolate.go:94`, `custom_domains.go:469`, `dns_verify.go:37-39`); `facade_state.go:159` keeps following `Fleet` visibility; the predicate table over four gates plus the fleet-runner alias row, and the `ownerScope` call-site test, in T2.
History: D3 (2026-10-17) approved A) "Explicit operator predicate" with five gates. Previous payload: the D3 question as recorded in this file's earlier save, the grid shown below, and the accepted scope "keep `runner` on `*`; add `hostCapable(ctx)` … switch the five gates … predicate table and the `ownerScope` call-site test in T2". Reopened 2026-10-17 because the `facade_state.go:156-165` evidence contradicts that one call site's classification.

<details><summary>Superseded D3 grid</summary>


| Choice | Current | A | B | C |
|---|---|---|---|---|
| `runner` on `*` | allowed (§5.3) | allowed | **refused** at binding/token creation (fleet scope only for viewer, auditor, admin) | **refused** |
| Operator-only capability gate | `!scoped` | new predicate `hostCapable(ctx)`: PAT/operator, `node:`, no-Access internal callers, `admin`; the five gates switch to it | unchanged `!scoped` (safe because the only unscoped writers left are operator, node, internal, admin) | `hostCapable(ctx)` on all five gates |
| Future capability checks | ad hoc | must use `hostCapable`; a test lists every `!scoped` use and fails on unreviewed new ones | rely on the binding rule | both |
| Platform automation creating sandboxes for every team | runner@* | runner@* | needs `admin` | needs `admin` |
| Tests | — | predicate table (each principal kind × each gate) + call-site test | binding validation test (runner@* refused at file load and token create) | both |
| Effort | — | human ~1 d / CC ~45 min | human ~2 h / CC ~15 min | human ~1.5 d / CC ~1 h |



Superseded D3 brief (as asked): "D3 — E1: Fleet-wide runner tokens would get operator-only powers. How should the plan close that?" Options:
- A) Explicit operator predicate: keep runner@*; add `hostCapable(ctx)` and switch the five gates to it, with a predicate table and a call-site test.
- B) No fleet-wide runners: refuse `runner` on `*`.
- C) Both (recommended): refuse runner@* and add `hostCapable(ctx)` on all five gates.

Answer: A) "Explicit operator predicate".
</details>

### E2: the test-only static validator (`SB_ITEST_IDENTITY_FILE`)
Finding: E2, P1, confidence 9/10, `pkg/daemon/daemon.go:100-114` and `pkg/daemon/itest_identity.go`, reviewer: Claude (eng review)
Plan baseline: not mentioned by the plan (landed on `main` after the CEO review in b4e152b1). §5.2 says the daemon refuses to boot when identity is on and a non-noop provider validator is present.
Runtime evidence: `if path := strings.TrimSpace(os.Getenv("SB_ITEST_IDENTITY_FILE")); path != "" { … cp.Validator = itestStaticValidator{tokens: tokens} …` in every release binary. Tokens are plaintext in the file. `git grep` finds no reference in `integration-tests/`, `scripts/`, `Terraform/` or `Ansible/`, so nothing in the tree drives it today. Enterprise mode does not refuse it.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| `SB_ITEST_IDENTITY_FILE` path in release binaries | honored | **removed** in T3 (daemon wiring, `itest_identity.go`, its test) | moved behind a build tag `itestidentity`; release builds ignore it | honored |
| How the harness gets scoped tokens | static file | real `avm_` tokens minted with the PAT at scenario setup (T3), OIDC via the T12 test issuer | the tagged static validator | static file |
| Interim (before T3 lands) | — | T1: identity on + this env → boot error; enterprise mode refuses the env | T1: same two guards | none |
| Collision with §5.2's boot rule | yes | gone | handled by the guard | yes |
| Tests | — | boot-guard table (T1); scenarios use `avm_` tokens (T12) | boot-guard table; build-tag test | — |
| Effort | — | human ~4 h / CC ~20 min | human ~3 h / CC ~15 min | none |

Question D4:
D4 — E2: A test-only "static token file" ships in every release binary. Retire it, hide it behind a build flag, or leave it?
Project/branch/task: plans/identity-and-access.md (PR #734); the code landed on `main` in b4e152b1 (`pkg/daemon/daemon.go:100-114`, `pkg/daemon/itest_identity.go`).
ELI10: Last night's cross-tenant fixes added a shortcut for testing. If one environment variable points at a file, the server accepts the plaintext tokens listed in it as logins. It's meant only for tests, but every release binary honors it. It also clashes with this plan: once real identity is on, the server must refuse a second identity source, so tests couldn't use both. This plan's own service tokens can do the same job for tests, properly hashed. So the shortcut can go, or at least be compiled out of release builds.
Stakes if we pick wrong: Leave it, and production servers keep a second, unhashed login path that enterprise mode doesn't block. Tests can't exercise the real identity feature through it either.
Recommendation: A because the plan's own `avm_` tokens replace it with the real, hashed path, nothing in the tree uses it yet, and one identity path is easier to secure than two.
Completeness: A=10/10, B=8/10, C=3/10
Net: You are trading a little harness work against keeping a second, plaintext login path in production binaries.
Header: Test tokens
Options:
A) Retire it (recommended)
Remove the env path, `itest_identity.go` and its test in T3; the harness mints real `avm_` tokens at setup and uses the T12 test issuer for OIDC; T1 adds an interim boot error (identity on + this env) and an enterprise-mode refusal. Effort S (human ~4 h / CC ~20 min), risk low, maintenance: none afterwards.
✅ One identity path: tests exercise the same hashed, expiring tokens customers use
✅ Production binaries lose a plaintext login shortcut that enterprise mode never blocked
❌ The cross-tenant itest has to mint tokens at setup instead of reading a static file
B) Build-tag it
Keep the static validator but compile it only with `-tags itestidentity`, so release binaries ignore the env; T1 adds the same interim guards. Effort S (human ~3 h / CC ~15 min), risk low, maintenance: a tagged test path to keep building.
✅ Release binaries can no longer honor it, with no harness change
✅ Keeps a dead-simple token source for tests that don't need the full feature
❌ Two identity paths to maintain, and tests built with the tag don't exercise the real feature
C) Leave it
Ship the plan as written; the env stays honored in release builds. Effort S, risk medium, zero work.
✅ No change to last night's test scaffolding
✅ Nothing to coordinate with the harness
❌ A plaintext token path stays in production binaries and collides with §5.2's boot rule

State: approved
Actual answer: A) "Retire it (recommended)" (D4, 2026-10-17)
Accepted scope: T1 adds the interim guards (identity on + `SB_ITEST_IDENTITY_FILE` → boot error; enterprise mode refuses the env var) with a boot-guard table. T3 deletes the env path, `pkg/daemon/itest_identity.go` and its test. T12's cross-tenant scenarios mint team `avm_` tokens at setup and use the test issuer for OIDC.
History: restored 2026-10-17 after an editing slip removed it from this file during the E1 reopen; content and answer are unchanged.

### Eng Section 1 dispositions

- **E1:** accepted. D3 answered "Explicit operator predicate" (runner@* kept). D7, reopened with new evidence, answered "Four gates": `facade_state.go:159` stays a fleet-visibility check.
- **E2:** accepted. D4 answered "Retire it": interim guards in T1, deletion in T3, harness on `avm_` tokens.
- **E4:** accepted as a correction under D10's approved behavior (inner calls act only as the caller). §5.14 and the T13 test updated; no new choice.


## Eng Section 2: Code quality

**Findings** (most severe first):
- `[P2] (confidence: 9/10) pkg/api/middleware.go:75-93` and `pkg/api/remotemcp/handler.go:237-253` — **E3.** Bearer extraction is implemented twice, and the copies have drifted.
  - Middleware: `const prefix = "Bearer "` … `if strings.HasPrefix(authorization, prefix)` (case-sensitive, untrimmed).
  - Remote MCP: `const prefix = "bearer "` … `strings.EqualFold(auth[:len(prefix)], prefix)` … `strings.TrimSpace(auth[len(prefix):])` (case-insensitive, trimmed).
  - The MCP copy's own comment says the two "must stay in lockstep", or the tools act as a different identity than the one that authenticated.
  - Today the stricter middleware fails first, so it is safe by accident. T1 rewrites the middleware, which is exactly when that accident can flip.
- `[P2] (confidence: 8/10)` plan §5.2 / CEO-review finding 5.1 — **E5.** How `authenticate()` is structured is still open (the only unresolved item handed over by the CEO review). It covers five credential kinds plus scope rules, surface rules, team selection and 401 reasons, well over 5 branches in one function.

**Other checks:**
- **Organization** matches the D2 layout (`pkg/identitywire`, `internal/identity`).
- **The `Operator → Fleet` rename** is a field rename, so the compiler forces every one of the ~30 sites to be revisited. Good.
- **Error handling** is mapped in the CEO review's Section 2 (no new gaps).
- **ASCII diagrams in touched files:** `internal/cluster/agent_placement_feed.go:11-26` is reused unchanged and still accurate. `pkg/api/middleware.go` has no diagram.

### E3: one bearer-extraction function
Finding: E3, P2, confidence 9/10, `pkg/api/middleware.go:75-93` and `pkg/api/remotemcp/handler.go:237-253`, reviewer: Claude (eng review)
Plan baseline: §5.2 "one authenticate()" (approved scope), silent on remote MCP's own copy.
Runtime evidence: two implementations with different scheme matching and trimming (quoted above).
Shared-code rubric:
- **Callers:** two verified first-party callers: `extractBearerToken` (`requireAuth`, `requireRunloopAuth`, `requireE2BAuth`) and `remotemcp.bearerToken` (`serverFor`).
- **Destination:** `pkg/api/apihttp.BearerToken(r *http.Request) string`; both import `apihttp` already.
- **Contract:** RFC 7235 makes the scheme case-insensitive, so `EqualFold` "bearer", then trim; then the `sandbox.bearer, <token>` subprotocol.
- **Lines:** about 19 removed, about 18 added (net about −1), plus a shared table test (~40). Total growth ~+40.
- **Value:** reliability, not size. The auth and the tools can no longer see different tokens.
- **Blast radius:** every authenticated request, so the table test covers case, whitespace, subprotocol, empty and an E2B `X-API-KEY` fallthrough.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| Implementations | 2 (drifted) | 1: `apihttp.BearerToken` | 2 | 2 |
| Scheme match | middleware case-sensitive; MCP case-insensitive | case-insensitive everywhere (RFC 7235) | unchanged | unchanged |
| Lockstep guarantee | comment only | by construction | an agreement test feeding both the same table | none |
| Behavior change for callers | — | `bearer tok` (lowercase) now authenticates in the middleware; today it gets 401 | none | none |
| Tests | — | shared table test; both callers' existing tests stay green | agreement table test | — |
| Effort | — | human ~2 h / CC ~10 min | human ~1 h / CC ~5 min | none |

Question D5:
D5 — E3: Two copies of "read the caller's token from the request" have drifted. Merge them into one?
Project/branch/task: plans/identity-and-access.md §5.2 / T1 (PR #734); `pkg/api/middleware.go:75-93` and `pkg/api/remotemcp/handler.go:237-253`.
ELI10: The server reads a caller's token in two places: once to check who they are, and again in the MCP tool runner to act as them. The copies differ: one ignores capital letters and extra spaces, the other doesn't. Its own comment says they must match, or the tools could act as someone other than the person who was checked. Today the stricter copy fails first, so nothing is wrong yet. But this plan rewrites the first copy, which is exactly when that luck can run out. One shared function removes the risk.
Stakes if we pick wrong: Keep two copies, and a future edit to either can make the MCP tools act as a different identity than the one that authenticated. Merge, and lowercase "bearer" starts working where it used to get 401.
Recommendation: A because a single function makes "the tools act as the authenticated caller" true by construction, at the exact moment T1 rewrites this code.
Completeness: A=10/10, B=8/10, C=4/10
Net: You are trading one tiny behavior change (lowercase "bearer" accepted, per the HTTP spec) against two copies that must be kept identical by hand.
Header: Token parse
Options:
A) One shared function (recommended)
Move extraction to `apihttp.BearerToken` (case-insensitive scheme per RFC 7235, trimmed, then the WebSocket subprotocol); the middleware and remote MCP both call it; a shared table test. Effort S (human ~2 h / CC ~10 min), risk low, maintenance: one function.
✅ The token that authenticated is always the token the MCP tools use, by construction
✅ Follows the HTTP spec: `bearer` and `Bearer` both work, and stray spaces are trimmed
❌ Lowercase `bearer` requests that get 401 today start authenticating
B) Keep two, test agreement
Leave both functions; add one table test that feeds both the same inputs and requires identical output. Effort S (human ~1 h / CC ~5 min), risk low, maintenance: two functions plus the test.
✅ No behavior change at all for current callers
✅ The agreement test catches drift in CI
❌ The copies already disagree, so this test first forces a choice of behavior anyway, and two copies remain
C) Do nothing
Keep both copies as they are. Effort S, risk medium, zero work.
✅ No change
✅ Safe today, because the stricter copy fails first
❌ T1's rewrite of the middleware can silently break the lockstep the comment depends on

State: approved
Actual answer: A) "One shared function (recommended)" (D5, 2026-10-17)
Accepted scope: `apihttp.BearerToken` (case-insensitive scheme, trimmed, then subprotocol) replaces `extractBearerToken` and `remotemcp.bearerToken`; both callers migrate; shared table test in T1. Lowercase `bearer` now authenticates (RFC 7235).
History: none


### E5: how `authenticate()` is structured (CEO-review open item 5.1)
Finding: E5, P2, confidence 8/10, plan §5.2 and CEO-review Section 5 finding 5.1, reviewer: Claude (eng review)
Plan baseline: §5.2 lists the classification order (PAT → `avm_` → JWT → provider). CEO-review 5.1 left the code structure to this review.
Runtime evidence: none yet (proposed code). Today's three wrappers are straight-line (`pkg/api/middleware.go:115-168`).
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| Shape | 3 copied wrappers | one entry point over an ordered list of authenticators (`pat`, `apiToken`, `jwt`, `provider`), each `Authenticate(r, bearer) (controlplane.Access, matched bool, err error)`; the first `matched` wins | one function with a `switch` on credential shape, calling a helper per kind |
| After a match | — | separate steps in order: surface rule (`mcp_audiences` only on `/mcp` or a marked forward), team selection (`X-AerolVM-Team`), 401/403 reason mapping (D9, D17) | the same logic inline in the switch arms |
| Adding a credential kind later | — | append one authenticator | add a switch arm and touch shared code |
| Tests | — | one table per authenticator plus one table for the post-match steps; the §5.1 invariant table runs through the entry point | one large table through the function |
| Behavior | — | identical (the §5.1 invariant test must stay green) | identical |
| Effort | — | human ~1 d / CC ~40 min | human ~1 d / CC ~40 min |

Question D6:
D6 — E5: How should the new sign-in check be organized in code?
Project/branch/task: plans/identity-and-access.md §5.2 / T1 (PR #734); the open item 5.1 the CEO review handed to this review.
ELI10: One function will decide who every request is. It handles five kinds of credential (the operator token, service tokens, sign-in tokens, managed logins, node-to-node calls). After that it applies the team choice, the MCP-only token rule and the error messages. Written as one big function, that's a lot of branches in the most security-critical spot in the server. The alternative is a short list of small checkers, one per credential kind, tried in order, with the shared rules applied afterwards. The behavior is identical either way.
Stakes if we pick wrong: One big function is harder to review and test, and every new credential type means editing the riskiest code. The list adds one small interface.
Recommendation: A because small per-credential checkers are each testable in isolation and keep the shared rules in one place, which matters most in the code every request passes through.
Note: options differ in kind, not coverage — no completeness score.
Net: You are trading one small interface against a single many-branch function on every request's path.
Header: Auth shape
Options:
A) Ordered list of checkers (recommended)
One entry point tries `pat`, `apiToken`, `jwt`, `provider` in order (each returns Access, matched, error); then surface rule, team selection and reason mapping run as separate steps. Effort M (human ~1 d / CC ~40 min), risk low, maintenance: one small interface.
✅ Each credential kind is a small unit with its own table test, easy to review
✅ A future credential type is one appended checker, not an edit to shared branching
❌ One more small interface and a list to keep in the right order
B) One function with a switch
A single `authenticate` with a switch on the credential's shape and a helper per kind; shared rules inline. Effort M (human ~1 d / CC ~40 min), risk low, maintenance: one larger function.
✅ Everything about sign-in reads top to bottom in one place
✅ No new interface or indirection
❌ Well over five branches in the riskiest function, and every new kind edits it

State: approved
Actual answer: A) "Ordered list of checkers (recommended)" (D6, 2026-10-17)
Accepted scope: one `authenticate` entry point over an ordered authenticator list (`pat`, `apiToken`, `jwt`, `provider`), each returning (Access, matched, error), with surface rule, team selection and reason mapping as separate post-match steps; per-authenticator tables plus a post-match table in T1; behavior identical (the §5.1 invariant test stays green).
History: none

### Eng Section 2 dispositions

- **E3:** accepted. D5 answered "One shared function": `apihttp.BearerToken`.
- **E5:** accepted. D6 answered "Ordered list of checkers". This closes CEO-review open item 5.1.


## Eng Section 3: Test review

**Framework.** Go (`go.mod`). `CLAUDE.md` "Build, test, format" is authoritative: `make test` (offline), per-package `go test`, a coverage bar of ~85% per touched package, tag-gated live tests in `integration-tests/` (`integration` tag), and table-driven style. The SDKs use their own runners (`npm test`, `unittest`, `cargo test`, `mvn test`). No LLM or prompt files are touched, so no eval scope applies.

**Existing tests touching changed code** (read in this review):
- `pkg/api/middleware_test.go`: `TestExtractBearerToken` (147).
- `pkg/api/auth_token_test.go`: `TestRequireAuthSecondTokenPath` (26), `TestRequireAuthNoopValidatorRejectsUserTokens` (88).
- `pkg/api/edge_auth_test.go`: `TestMetricsAreOperatorOnly` (16), `TestUserTokenWithoutAnAccountIsRefused` (36), `TestSingleNodeDropsClusterControlHeaders` (52).
- `pkg/api/runloop_auth_test.go`: `TestRequireRunloopAuth` (15).
- `pkg/api/remote_mcp_test.go`: `TestRemoteMCPSubprotocolTokenIsNotOperator` (146).
- `internal/service/owner_scope_test.go`: `TestOwnerScope`, `TestEnforceOwner`, `TestFilterByOwnerScope`, `TestOwnerRefForCreate`.
- The gates: `TestValidateCreateMounts_RawMountsAreOperatorOnly` (`mount_owner_policy_test.go:22`), `TestCreateIsolateSandboxScopedFileRefRejected` (`isolate_coverage_test.go:78`), `TestPersistCustomDomainsOnCreate_OwnerScopedRequiresTXT` (`custom_domains_create_owner_test.go:26`), and the `dns_verify_test.go` set.
- `requireVisibleSnapshot` has no direct test.

**Coverage diagram** (proposed paths are `[PLANNED]` with the task that owns the test; `[GAP]` was missing before this review):

```
CODE PATHS                                                   USER FLOWS
[+] authenticate() (T1, D6)                                  [+] People
  ├── apihttp.BearerToken  [★★★ PLANNED T1, D5]               ├── [★★★ PLANNED T7] aerolvm login --sso / --device → whoami
  ├── pat authenticator    [★★★ PLANNED T1] + existing        ├── [★★★ PLANNED T8, UC-290] dashboard sign-in (HTTPS) → overview
  │     TestRequireAuth*, TestExtractBearerToken (→ replaced) ├── [★★★ PLANNED T8] token expiry mid-session → silent re-sign-in
  ├── apiToken authent.    [★★★ PLANNED T3] mirror, stale,     ├── [★★★ PLANNED T6/T7] multi-team --team → X-AerolVM-Team
  │                          metrics.read exception (D16)     └── [GAP→FIXED E6] [→E2E] multi-team list across peers
  ├── jwt authenticator    [★★★ PLANNED T6] alg/iss/aud/      [+] Services and CI
  │                          kid/lifetime/overage/size caps    ├── [★★★ PLANNED T3, UC-268/271] token create → use → revoke
  │     └── LRU vs team    [GAP→FIXED E7] cached JWT, 2 teams ├── [★★★ PLANNED UC-275/284] GH Actions / k8s workload token
  ├── provider authent.    [★★★ existing TestRequireAuth*]     └── [★★★ PLANNED T7, D15] CI env token expiry warning
  └── post-match steps     [★★★ PLANNED T1/T6/T13]            [+] Operators and auditors
        surface, team, 401/403 reasons (D9, D17)                ├── [★★★ PLANNED T5b, UC-279] aerolvm access review
[+] hostCapable (T2, D3/D7)                                     ├── [★★★ PLANNED T10, UC-285] SB_PAT_SCOPE=host
  ├── raw mounts           [★★★ existing + PLANNED row]        └── [★★★ PLANNED UC-291..293] chaos (partition, leader, keys)
  ├── file:// bundles      [★★★ existing + PLANNED row]       [+] Error states
  ├── DNS proof skip       [★★★ existing + PLANNED row]        ├── [★★★ PLANNED T1] 401 reason per kind; PAT body unchanged
  └── alias visibility     [★★  PLANNED row D7] (no direct     ├── [★★★ PLANNED T2/T6] 403 hint; 404 bare
                             test today)                        └── [★★★ PLANNED T13] /mcp empty bearer → 400 (E4)
[+] runner@* create owner  [GAP→FIXED] owner "" + "" snapshots
[+] itest validator guard  [★★★ PLANNED T1, D4] → deleted T3
[+] StampForward + fan-out [★★★ PLANNED T4] + E6 header copy
[+] token store/mirror     [★★★ PLANNED T3] FSM, ring, tombstone, spray
[+] api records + floods   [★★★ PLANNED T5, D14] three modes, shared node
[+] caller fields + fv     [★★★ PLANNED T4, UC-281] mixed-version gate

COVERAGE (planned, value-weighted): 38/38 paths have a ★★/★★★ planned test after this review's three additions
QUALITY: ★★★ 37  ★★ 1 (alias visibility row)  |  GAPS found: 3 (E6, E7, runner@* create owner), all now planned
```

**Regression contracts carried forward** (no new answer needed):
- **L8 (founder-locked):** PAT and managed-provider behavior is unchanged. `TestRequireAuthNoopValidatorRejectsUserTokens`, `TestUserTokenWithoutAnAccountIsRefused`, `TestRequireRunloopAuth`, the owner-scope tests and the four gate tests must pass **unmodified** after the `Operator → Fleet` rename (T1) and the `hostCapable` switch (T2). Only the rows D3/D7 add are new.
- **D5 changes one behavior on purpose:** lowercase `bearer` now authenticates. `TestExtractBearerToken` is replaced by the `apihttp.BearerToken` table, not deleted.
- **D6:** `TestMetricsAreOperatorOnly` keeps its managed-caller and team-caller assertions (403). It gains the fleet-viewer row (200) and the `/debug/vars` row (403).

**Tests made obsolete by this plan** (proposal; retire with a card at implementation time):
- `pkg/daemon/itest_identity_test.go`, with the validator (D4, T3).
- `TestExtractBearerToken` (`pkg/api/middleware_test.go:147`), superseded by the `apihttp.BearerToken` table (D5).

**Value cards for this review's additions:**
- E6. Value: protects=a multi-team caller's cluster list shows one team on every peer; fails_when=a fan-out client drops X-AerolVM-Team; why_new=clusterlist builds fresh requests (list.go:591-606) outside the ReverseProxy path; seam=none
- E7. Value: protects=team selection is per request, never cached; fails_when=the JWT LRU stores the selected team with the claims; why_new=no test pairs the cache with D13's header; seam=none
- runner@* create. Value: protects=fleet runner creates land in the operator namespace and resolve only operator snapshots; fails_when=Fleet create stamps a team owner or resolves a tenant snapshot by name (#7); why_new=TestOwnerRefForCreate covers PAT and tenant only; seam=none

**Findings:**
- `[P1] (confidence: 9/10) pkg/api/clusterlist/list.go:601-606` — **E6.** The fan-out copies only `if opts.AuthHeader != "" { req.Header.Set("Authorization", …) }` and `X-API-KEY`, so D13's `X-AerolVM-Team` (and H3's correlation id) never reach peers. A multi-team caller's list is answered for the first-matching team on every peer. **Correction** under D13 ("an ordinary header, so a forward keeps it") and H3: `StampForward` copies both on fan-out clients; T4 test added.
- `[P2] (confidence: 8/10)` plan §5.5 verified-token LRU plus D13 — **E7.** The cache key is `SHA-256(jwt)`. If the selected team were cached with the claims, a second request with a different `X-AerolVM-Team` would reuse the first team. D6 already makes team selection a post-match step, so the required proof is one test; added to T6.
- `[P2] (confidence: 8/10) internal/service/owner_scope.go:70-90` — **runner@* create owner.** The §5.1 behavior (fleet creates stamp `""`) and #7's `snapshotResolvableForCreate` have no test for a fleet-scoped *non-operator* principal. Added to T2 as required proof of approved behavior.

**Dispositions:** E6 is a correction (D13, H3), applied. E7 and the runner@* create test are required proof of approved behavior (D13 + D6; §5.1), applied. No new test-depth choice was needed, because D21 already settled load, fuzz and chaos depth.


## Eng Section 4: Performance

On the per-request path:
- `apihttp.BearerToken` (D5): a string scan.
- The authenticator list (D6): the first match wins; PAT is a constant-time compare, `avm_` is a map lookup plus SHA-256 of 32 B, and a JWT is an LRU hit or an RS256 verify (~50 µs, first time only).
- `hostCapable` (D3/D7): field reads.
- `StampForward` header copies (E6): a few `Header.Set`s per forward.

None adds I/O, locks or a server-tier call, and `CreateSandbox` still gains only µs. Memory bounds are unchanged from the CEO review's Section 7 (mirror ~2 MB, LRU ≤ 16 MB, ring ≤ 13 MB on servers).

**Findings:**
- `[P3] (confidence: 6/10)` plan §5.5 bindings plus D13 — **E8.** Medium confidence; verify at implementation.
  - Team selection runs after the cached JWT match, so the bindings list is scanned on every request.
  - The identity file is capped at 1 MiB, which is roughly 10k bindings at worst. A linear scan per request (~10k comparisons) could break D21's p99 ≤ 50 µs budget for cached paths.
  - **Scale:** unknown until real identity files exist. Typical files have tens of bindings.
  - **Disposition:** no new choice. D21's budget (`BenchmarkAuthenticate{JWTCached}`) is the approved contract, and the implementation owner (T6) must meet it.
  - The natural way: cache the caller's *matched binding set* with the claims in the LRU, and run team selection over that short list. That keeps E7, because the selected team is never cached.

No other issues found: no N+1 or unbounded queries (tokens are in memory; SQLite is touched only on token writes), and no new caches beyond those already bounded.

**Dispositions:** E8 is covered by D21's approved budget, with an implementation note for T6. No question needed.


## Eng outside voice

Codex preflight: `CODEX_MODE: model_unusable` (the configured model id is invalid; fix with `GSTACK_CODEX_MODEL=<supported-model>` or the `config.toml` model). No Codex call was made. The native fallback needs `TaskOutput`, which this session lacks, so the outside voice is **unavailable**. That is missing coverage, not a clean review, and it was logged as `unavailable`.

## Eng TODO choices

### E9: TODO — per-owner WASM module ids (residual from #724)
Finding: E9, P2, confidence 9/10, `internal/service/wasm_module_api.go:176-188`, reviewer: Claude (eng review)
Plan baseline: T0 (shipped as #724) notes the residual as "not in this stack".
Runtime evidence: `id := explicitID; if id == "" { id = strings.TrimSpace(resolved.Digest) }` … `if existing, err := s.store.GetWasmModule(ctx, id); err == nil { if … wasmModuleWritable(ctx, existing) { … } return nil, store.ErrWasmModuleIDConflict }`.
TODO content:
- **What:** give WASM module catalogue ids a per-owner namespace (or ref-counted ownership like `jsbundle.TenantOwns`), so a second owner registering identical module bytes without an explicit id gets its own row instead of `ErrWasmModuleIDConflict`.
- **Why:**
  - Today the id defaults to the content digest, which is a global key. A team uploading a module another team (or the operator) already registered is refused.
  - The conflict also confirms that a module with that digest exists, a small cross-owner existence signal.
  - Teams (this plan) make same-module uploads common.
- **Pros:** teams can register the same standard modules independently, and the existence signal disappears.
- **Cons:** a store identity change (`(owner_ref, id)`, like #731 did for snapshots) with a migration and create-time resolution changes. It touches the resolver's catalogue lookup (`ResolveOwnedWasmModule`).
- **Context:** #724 added `wasm_modules.owner_ref` with backfill `""`. #731 is the precedent for per-owner name spaces. Start at `CreateWasmModule` (`wasm_module_api.go:127-200`) and `ResolveOwnedWasmModule` (`pkg/daemon/wasm_wiring.go`).
- **Effort:** human M / CC S. **Priority:** P2.
- **Depends on / blocked by:** nothing; independent of this stack.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| Residual tracked | only in T0's note | TODOS.md entry with the content above | not tracked | built in this stack as a new task (T0b) |
| Stack size | 14 PRs | unchanged | unchanged | +1 PR (M) |

Question D8:
D8 — E9: Track the "second team can't register the same WASM module" residual from #724 as a TODO?
Project/branch/task: plans/identity-and-access.md T0 (PR #734); the code is `internal/service/wasm_module_api.go:176-188` on `main`.
ELI10: Last night's fix gave WASM modules an owner. But a module's id is still its content fingerprint, and that id is shared by everyone. If team B uploads the exact same module team A already uploaded, B gets an "id conflict" error instead of its own copy. The error also tells B that someone already has that module. Teams make this more likely. The fix is to make ids per-owner, the way last night's snapshot fix did.
Stakes if we pick wrong: Skip it, and teams hit confusing conflicts uploading common modules. Build it now, and this already large stack grows by one more PR.
Recommendation: A because it's real but independent of identity and access, and the snapshot fix (#731) gives a clear template to do it separately.
Note: options differ in kind, not coverage — no completeness score.
Net: You are choosing where this residual lives: the backlog, nowhere, or this stack.
Header: WASM ids TODO
Options:
A) Add to TODOS.md (recommended)
Record the What/Why/Pros/Cons/Context above as a P2 entry; this stack is unchanged. Effort S (human ~10 min / CC ~2 min), risk low.
✅ The residual is written down with its root cause and the #731 template, ready for anyone
✅ This stack stays focused on identity and access
❌ Teams can still hit the conflict until someone picks it up
B) Skip — not valuable enough
Leave it only as T0's one-line note. Effort S, risk low, zero work.
✅ No new backlog item
✅ Nothing to maintain
❌ The root cause and fix direction are easy to lose; the next person re-derives them
C) Build it now in this stack
Add a task T0b (per-owner `(owner_ref, id)` with migration, like #731) to this stack. Effort M (human ~1–2 d / CC ~1 h), risk medium.
✅ Teams never hit the conflict when identity ships
✅ Removes the cross-owner existence signal at the same time
❌ Adds a store-identity migration to an already large stack

State: approved
Actual answer: C) "Build it now in this stack" (D8, 2026-10-17; the recommendation was A)
Accepted scope: new task T0b (per-owner `(owner_ref, id)` WASM module ids with an idempotent migration, own-then-`""` resolution, owner-keyed resolver and warm pool, delete within namespace) with its tests and UC-294; no TODOS.md entry.
History: none


### Eng approval readiness

Each accepted remedy is cited to its own answer:
- Structure: D2 (Smaller arrangement).
- E1: D3, reopened and refined by D7 (Four gates).
- E2: D4 (Retire it). E3: D5 (One shared function). E5: D6 (Ordered list of checkers). E9: D8 (Build it now, T0b).

Corrections without a new question implement already-approved behavior:
- E4, under D10 (inner MCP calls act only as the caller);
- E6, under D13 ("a forward keeps it") and H3 (correlation id);
- E7 and the runner@* create test: required proof of D13 + D6 and §5.1;
- E8: implementation note under D21's budget.

No setup, mode or navigation answer is used as approval.

Approval readiness: PASS. Checked: D2, E1 (D3, D7), E2 (D4), E3 (D5), E5 (D6), E9 (D8); corrections E4, E6, E7, E8 cited above.

## Eng review outputs

### NOT in scope

Nothing was deferred in this review. E9 was pulled into the stack as T0b (D8) instead of deferred. The plan's §13 list stands unchanged.

### What already exists

| Existing code | Reuse in this review's changes |
|---|---|
| `ownerScope` / `ownerRefForCreate` / `snapshotResolvableForCreate` (`internal/service/owner_scope.go`) | kept for visibility and stamping; `hostCapable` is a new sibling predicate, not a rebuild (D3/D7) |
| Gate tests (`mount_owner_policy_test.go:22`, `isolate_coverage_test.go:78`, `custom_domains_create_owner_test.go:26`, `dns_verify_test.go`) | the L8 regression suite, unmodified; D3/D7 rows are added beside them |
| `extractBearerToken` / `remotemcp.bearerToken` | collapsed into `apihttp.BearerToken` (D5); moved code is counted on both sides (≈ −19 / +18 lines) |
| `itestStaticValidator` (`pkg/daemon/itest_identity.go`) | retired; replaced by real `avm_` tokens (D4) |
| #731 per-owner snapshot namespace | the template for T0b's per-owner WASM ids (D8) |
| `clusterlist` fan-out client (`list.go:591-606`) | gains the team and correlation headers through `StampForward` (E6), not a new client |

### Diagrams

**`authenticate()` after D5/D6:**

```
  request ─► apihttp.BearerToken(r) ──► bearer ("" → 401, never the SDK's PAT fallback: E4)
                │
                ▼  ordered authenticators (first matched wins)
        ┌──── pat ──────┐  ┌── apiToken ───┐  ┌──── jwt ─────┐  ┌── provider ──┐
        │ const-time,   │  │ checksum →    │  │ LRU(sha256)→ │  │ managed      │
        │ scope rule,   │  │ mirror[id] →  │  │ sig/iss/aud/ │  │ Validator    │
        │ origin marker │  │ sha256, exp,  │  │ exp/lifetime │  │ (Noop in OSS)│
        └──────┬────────┘  │ stale rule    │  │ → matched    │  └──────┬───────┘
               │           └──────┬────────┘  │   bindings   │         │
               │                  │           └──────┬───────┘         │
               └──────────────────┴──────┬───────────┴─────────────────┘
                                         ▼  post-match steps (never cached: E7)
                        surface rule ─► team selection (X-AerolVM-Team) ─► reason mapping
                                         ▼
                        Access{Principal, Role, Fleet, Via} ─► route permission (d.Route)
                                         ▼
                        service: ownerScope (what you see)   hostCapable (host powers, D3/D7)
```

**Scope vs. power:**

```
                    Fleet (sees all owners)?     hostCapable (raw mounts, file://, DNS-proof skip)?
  PAT / operator    yes                          yes
  node:<id>         yes                          yes
  internal (no Access) yes                       yes
  admin             yes                          yes
  auditor           yes (read routes only)       no
  viewer@* / runner@* yes                        no   ← D3 closes the gap here
  viewer/runner@team no                          no
  managed identity  no                           no
```

### Failure modes (new paths in this review)

| Path | Realistic failure | Test / handling | User sees |
|---|---|---|---|
| `hostCapable` | a new capability check copies `!scoped` | `ownerScope` call-site test fails the build | (prevented) |
| `hostCapable` | a principal kind misclassified | predicate table over four gates | 403 `ErrMountOperatorOnly` / file-ref refusal |
| fan-out headers | a fan-out client drops `X-AerolVM-Team` | T4 multi-team list test (E6) | before the fix, the wrong team's sandboxes, silently; now covered |
| JWT LRU | team pinned in the cache | T6 two-team test (E7) | (prevented) |
| `SB_ITEST_IDENTITY_FILE` | set together with identity on | T1 boot guard | daemon refuses to start, naming the conflict |
| `BearerToken` | auth and MCP disagree | impossible by construction (D5) plus table | — |
| authenticator order | JWT tried before `avm_` on a token-shaped bearer | per-authenticator tables plus the order test | 401 with reason |
| T0b migration | warm upgrade with existing rows | idempotent migration test | boot proceeds; rows intact |

**Critical gaps: 0.** The only silent row (E6) is fixed and tested.

### Worktree parallelization strategy

| Step | Modules touched | Depends on |
|---|---|---|
| T0b WASM ids | `internal/store`, `internal/service` (wasm), `pkg/daemon` | — |
| T1 principal + authenticate | `pkg/controlplane`, `pkg/api`, `pkg/api/apihttp`, `pkg/api/remotemcp`, `internal/service` (owner_scope) | — |
| T2 permissions + hostCapable | `pkg/api` (routes, facades), `internal/service` (gates) | T1 |
| T3 tokens + mirror | `internal/store`, `internal/cluster`, `internal/identity`, `pkg/identitywire`, `pkg/api`, `cmd/aerolvm`, `pkg/daemon` | T1 |
| T4 caller fields + StampForward | `pkg/auditlog`, `internal/service` (audit), `internal/cluster`, `pkg/api/clusterroute`, `pkg/api/clusterlist` | T1 |
| T5 api records (+ T5b review) | `internal/service` (audit quota), `pkg/api`, `pkg/sshgateway`, `cmd/aerolvm`, `pkg/auditlog` | T2, T4 (T5b also T3) |
| T6 OIDC | `internal/identity`, `pkg/identitywire`, `pkg/api` | T1, T3 |
| T7 CLI SSO | `cmd/aerolvm` | T3, T6 |
| T8 dashboard | `pkg/api` (dashboard), `scripts/install.sh`, `packaging` | T6 |
| T9 SDKs | `sdk/*` | T1, T3, T6 |
| T10 PAT scope + PROXY + obs | `pkg/caddy`, `internal/service` (L4), `scripts/install.sh`, `packaging`, `Terraform`, `setup` | T1, T3 |
| T13 MCP OAuth | `pkg/api/remotemcp`, `internal/identity` | T4, T6 |
| T11 docs, T12 harness | `docs`, `DESIGN.md`, `integration-tests` | all |

**Parallel lanes** (develop in parallel worktrees; merge as one stack in order, per the no-partial-merge rule):
- **Lane A:** T0b (independent; can start now).
- **Lane B:** T1, then T2, then T5 (shared `pkg/api`; sequential).
- **Lane C:** T3, then T6, then (T7 ∥ T9 ∥ T13).
- **Lane D:** T4. It shares `pkg/api/cluster*` with lane B, so coordinate.
- **Lane E:** T10, after T1 and T3. It shares `scripts/install.sh` with T8, so sequence T8 after T10.

**Execution order:**
1. Launch A and B (T1).
2. Once T1 lands in the stack, launch B's T2, C's T3 and D's T4.
3. Then T5, T6, T10.
4. Then T7, T8, T9, T13, T5b.
5. Last, T11 and T12.

**Conflict flags:**
- `pkg/api/clusterroute` and `pkg/api/clusterlist` (T2 vs T4);
- `scripts/install.sh` (T8 vs T10);
- `internal/identity` (T3 vs T6 vs T13);
- `cmd/aerolvm` (T3, T5, T5b, T7).

### Unresolved decisions

None in this review. The CEO review's open items are closed: 5.1 by D6, 9.2 by #724.

## Eng implementation tasks

Synthesized from this review's findings. Each derives from a finding above. Run with Claude Code or Codex; checkbox as you ship. Effort assumes features ~30×, tests ~50×, architecture ~5× (human ÷ CC).

- [ ] **ET1 (P1, human: ~1.5 d / CC: ~1 h)** — store/wasm — Per-owner WASM module ids `(owner_ref, id)` with migration and own-then-`""` resolution (T0b)
  - Surfaced by: TODO choices, E9 (D8), `internal/service/wasm_module_api.go:176-188`
  - Files: `internal/store/store.go`, `internal/service/wasm_module_api.go`, `internal/service/wasm_module.go`, `pkg/daemon/wasm_wiring.go`
  - Verify: `go test -run Wasm ./internal/store/ ./internal/service/ ./pkg/daemon/`; UC-294
- [ ] **ET2 (P1, human: ~1 d / CC: ~45 min)** — service/auth — `hostCapable(ctx)` on the four operator-only gates, plus the `ownerScope` call-site test (T2)
  - Surfaced by: Section 1, E1 (D3, D7)
  - Files: `internal/service/service.go`, `internal/service/isolate.go`, `internal/service/custom_domains.go`, `internal/service/dns_verify.go`, `internal/service/owner_scope.go`
  - Verify: `go test ./internal/service/...` (predicate table, alias row, call-site test)
- [ ] **ET3 (P1, human: ~4 h / CC: ~20 min)** — daemon/harness — Retire `SB_ITEST_IDENTITY_FILE`: interim guards (T1), deletion (T3), harness on `avm_` tokens (T12)
  - Surfaced by: Section 1, E2 (D4)
  - Files: `pkg/daemon/daemon.go`, `pkg/daemon/itest_identity.go`, `pkg/daemon/itest_identity_test.go`, `internal/config/config.go`
  - Verify: boot-guard table; `go test ./pkg/daemon/...`
- [ ] **ET4 (P2, human: ~2 h / CC: ~10 min)** — api — `apihttp.BearerToken` shared by `authenticate` and `remotemcp.serverFor` (T1)
  - Surfaced by: Section 2, E3 (D5)
  - Files: `pkg/api/apihttp/apihttp.go`, `pkg/api/middleware.go`, `pkg/api/remotemcp/handler.go`
  - Verify: `BearerToken` table; `go test ./pkg/api/...`
- [ ] **ET5 (P2, human: ~1 d / CC: ~40 min)** — api — `authenticate` as an ordered authenticator list with post-match steps (T1)
  - Surfaced by: Section 2, E5 (D6)
  - Files: `pkg/api/middleware.go` (to be split into an auth file, to be determined)
  - Verify: per-authenticator tables; §5.1 invariant test unchanged
- [ ] **ET6 (P1, human: ~3 h / CC: ~15 min)** — cluster — `StampForward` copies `X-AerolVM-Team` and `X-Correlation-ID` on fan-out clients (T4)
  - Surfaced by: Section 3, E6
  - Files: `internal/cluster/forward.go`, `pkg/api/clusterlist/list.go`, `pkg/api/clusterlist/facade_list.go`
  - Verify: multi-team list fan-out test
- [ ] **ET7 (P2, human: ~1 h / CC: ~5 min)** — mcp — the hand-off never reaches the SDK's `SB_PAT_TOKEN` fallback (T13)
  - Surfaced by: Section 1, E4
  - Files: `pkg/api/remotemcp/handler.go`, `pkg/api/remotemcp/inprocess.go`
  - Verify: empty bearer → 400; inner-call identity test
- [ ] **ET8 (P2, human: ~3 h / CC: ~15 min)** — identity — JWT LRU caches the matched bindings, never the team; stays within D21's budget (T6)
  - Surfaced by: Section 3, E7; Section 4, E8
  - Files: `internal/identity/` (to be determined)
  - Verify: two-team cached-JWT test; `BenchmarkAuthenticateJWTCached` with a 10k-binding file
- [ ] **ET9 (P2, human: ~1 h / CC: ~5 min)** — service — test that a `runner@*` create stamps `""` and resolves only `""` snapshots (T2)
  - Surfaced by: Section 3, runner@* create gap
  - Files: `internal/service/owner_scope_test.go`
  - Verify: `go test -run OwnerRefForCreate ./internal/service/`
- [ ] **ET10 (P2, human: ~30 min / CC: ~5 min)** — layout — one CLI-shared package, `pkg/identitywire` (T3/T6)
  - Surfaced by: Scope Challenge structure (D2)
  - Files: `pkg/identitywire/` (new), `cmd/aerolvm/deps_test.go` (guard stays green)
  - Verify: `go test ./cmd/aerolvm/...` (dependency guard)

### Completion summary

- Step 0: Scope Challenge — scope accepted as-is (structure: smaller arrangement, D2).
- Architecture Review: 3 issues found (E1 P1, E2 P1, E4 P2).
- Code Quality Review: 2 issues found (E3, E5).
- Test Review: diagram produced, 3 gaps identified (E6, E7, runner@* create), all now planned.
- Performance Review: 1 issue found (E8, P3).
- NOT in scope: written (nothing deferred).
- What already exists: written.
- TODOS.md updates: 1 item proposed (E9), built in-stack as T0b instead.
- Failure modes: 0 critical gaps flagged.
- Unresolved decisions: 0 in this review.
- Outside voice: codex unavailable (`model_unusable`); native fallback unavailable (no `TaskOutput`).
- Parallelization: 5 lanes, 3 parallel at peak / 2 sequential chains.
- Lake Score: 2/3 (D4 and D5 chose the 10/10 option; D3 chose 8/10).


---

# Design review: `/plan-design-review` 2026-10-17

**Target:** `plans/identity-and-access.md` (PR #734). **UI scope:**
- `/ui` dashboard: SSO sign-in, Google Identity Services button, token fallback, HTTPS-only sign-in (D18), CSP (D19), identity header, team picker (D13), role-aware actions, the 403 "no binding" screen (D9), re-sign-in on expiry.
- Secondary: CLI output for `login --sso`, `whoami --explain` and the expiry warnings.

**Design system:** `DESIGN.md` exists but is the actor model, not a visual system. The de facto visual system is the dashboard's own CSS (`pkg/api/dashboard.html:10-28`):
- colors `--bg #0b0d11`, `--panel #14171d`, `--border #2a2f3a`, `--text #e4e7ee`, `--muted #8b95a7`, `--accent #7aa2ff`, `--ok/--warn/--bad`;
- a system font stack at 13 px;
- a 360 px login overlay (`:136-162`).

New UI is calibrated to those tokens. No prior design reviews exist. **Mockups:** none (the designer needs an OpenAI API key; 0 images saved).

**Step 0 rating: 5/10.** The flow, state table and accessibility basics exist (CEO-review Section 11). The hierarchy, copy, team-picker data, Google-button styling, non-admin experience and responsive behavior are unspecified. Focus: all 7 dimensions (D1).

## Design outside voices

Codex: unavailable (invalid model id; no call made). The Claude design subagent completed, so this pass is `[single-model]`.

```
DESIGN OUTSIDE VOICES — LITMUS SCORECARD:
═══════════════════════════════════════════════════════════════
  Check                                    Claude  Codex  Consensus
  ─────────────────────────────────────── ─────── ─────── ─────────
  1. Brand unmistakable in first screen?   NO      —      single-model (box says "sandboxd", header "AerolVM")
  2. One strong visual anchor?             NOT SPEC'D —   —
  3. Scannable by headlines only?          NOT SPEC'D —   —
  4. Each section has one job?             NO      —      single-model (admin panels error for non-admins)
  5. Cards actually necessary?             N/A     —      no cards proposed
  6. Motion improves hierarchy?            N/A     —      no motion proposed
  7. Premium without decorative shadows?   NOT SPEC'D —   —
  ─────────────────────────────────────── ─────── ─────── ─────────
  Hard rejections triggered:               none    —      —
═══════════════════════════════════════════════════════════════
```

The subagent's 11 findings are confirmed against code where they cite it (`dashboard.html:468-733` calls only `/health` and `fleet.admin` routes; `:754-764` uses `confirm()`/`alert()`) and are folded into the passes below.


**Prior learning applied:** `acebot-no-ui-scope-creep` (confidence 10/10, from 2026-09-20). Findings stay scoped to the screens this feature changes. The rest of the dashboard (KPI tiles, tables, 13 px base type, palette) is existing UI and out of scope unless the identity work breaks it.

## Design Pass 1: Information architecture

**Initial rating: 4/10.** The CEO-review flow (Section 11) says where a person goes after sign-in, but not what they see there.
- **The overview assumes an admin.** Health uses `/health`, which is public. Nodes, Placements and Metrics call `/v1/cluster/leader`, `/v1/cluster/members`, `/v1/cluster/sandbox-index` and `/debug/vars` (`dashboard.html:551,552,634,733`). §5.3 puts all four under `fleet.admin`. So only admin, PAT and operator callers can load them, and every other role gets 403s on three of the four panels.
- **Missing pieces:** the order of the sign-in screen, the issuer labels, where the identity sits in the header, and the team picker's data source.

A 10 here would define, for each role, what the first screen shows, which panels load, and the order of items in the sign-in box and the header.

## Design review decision ledger

### DR1: what a signed-in non-admin sees
Finding: subagent finding 1, CRITICAL, confidence 9/10, `pkg/api/dashboard.html:551,552,634,733` against §5.3 `fleet.admin`, reviewer: Claude design subagent (confirmed in code).
Plan baseline: §5.7 "Role-aware: the page calls `whoami` and hides drain, uncordon and orphan buttons unless the caller is an admin." The Section 11 flow sends every bound caller to "overview".
Gap: viewer, runner and auditor callers reach the overview and get 403s on Nodes, Placements and Metrics. Only Health renders. Team-bound viewers and runners, the only callers with a team, can never load a data panel. That leaves the D13 dashboard team picker with nobody to serve, which DR2 takes up next.

| Choice | Current | A | B | C |
|---|---|---|---|---|
| Non-admin after sign-in | overview with three 403 panels | one "signed in" screen: name, role, team, what the console needs, CLI pointer, sign out | overview; each admin panel replaced by one muted line "Needs the admin role" | overview with a new team-scoped "Sandboxes" panel (`GET /v1/sandboxes`, `sandbox.read`); admin panels hidden |
| Admin, PAT, operator | full overview | unchanged | unchanged | unchanged |
| New panels or routes | — | none | none | one panel; list route already exists |
| Dashboard team picker (D13) | planned | no audience; DR2 | no audience (no team data shown); DR2 | needed (selects whose sandboxes) |
| Effort | — | S (human ~2 h / CC ~10 min) | S (human ~3 h / CC ~15 min) | M (human ~1.5 d / CC ~45 min) |

State: approved
Actual answer: A) "Admin-only console (recommended)" (D3, 2026-10-17)
Accepted scope: §5.7 "Who the console is for". `admin` and PAT/operator callers get the overview. Every other role gets the signed-in screen: name, role, team, the console line, the CLI pointer and Sign out, with no panel requests. T8 adds a `/browse` check for a viewer token. The Section 11 flow carries a superseded note.
Consequence recorded: subagent finding 10 (role-aware hiding misses the placement Start, Stop and Delete buttons) no longer applies. Only callers with every permission see those buttons. The page's existing `alert()`/`confirm()` calls are existing UI and are listed under NOT in scope.

**Pass 1 re-rate after DR1: 6/10.** Every role now has a defined first screen. Still open: the team picker's audience (DR2), the issuer list and labels, the sign-in box order, and the header layout.

### DR2: the dashboard team picker
Finding: subagent finding 2, CRITICAL, confidence 9/10, §5.2 `whoami` (one resolved team), §5.3 D13, reviewer: Claude design subagent.
Plan baseline: D13 approved "Team-selection header". Its scope covers "the header, its selection rule, the CLI/dashboard/SDK senders, and the audit team field". T8 lists "a team picker for multi-team users".
New evidence (why D13's dashboard part is reopened): after DR1, only `admin` and PAT/operator callers see the console. §5.3 requires `admin` to be bound to `*`, so nobody who can use the console has a team to pick. `whoami` also returns only the single resolved team, so the picker has no list to show. One edge remains. A person can match both `admin` on `*` and a team binding listed above it. First match wins, so they resolve to the team binding and get the signed-in screen. Nothing in the plan lets a request select the fleet binding.

| Choice | Current | A | B |
|---|---|---|---|
| Dashboard team picker | planned, no data source | removed; the dashboard sends no `X-AerolVM-Team` | kept; a native `<select>` in the header, shown only when the token matches more than one binding |
| `whoami` | one resolved team | unchanged | adds `bindings[]`: each matching binding's role and team |
| Selecting the fleet binding | impossible | stays impossible; docs say "list admin bindings first", as the §5.5 example does | `X-AerolVM-Team: *` selects the matching fleet binding (§5.3, CLI `--team '*'`, SDKs) |
| D13 elsewhere (CLI, SDKs, audit) | approved | unchanged | unchanged, plus `*` |
| Effort | — | S, removes work (human ~1 h / CC ~5 min) | S–M (human ~1 d / CC ~30 min) |

State: approved
Actual answer: A) "Drop the dashboard picker (recommended)" (D4, 2026-10-17)
Accepted scope:
- The dashboard sends no `X-AerolVM-Team`, and T8 has no picker. §5.3 says so.
- The §5.5 `bindings[]` row tells operators to list fleet bindings above team bindings. T11's `access-control.mdx` repeats that rule.
- The Section 11 note and the test-coverage diagram are updated. D13's CLI, SDK and audit parts are unchanged, and the A3 ledger row records the amendment.
History: D13 (2026-10-16) approved "Team-selection header (recommended)", covering "the header, its selection rule, the CLI/dashboard/SDK senders, and the audit team field". Reopened for the dashboard sender only, because of the DR1 evidence above.

**Pass 1 re-rate after DR2: 7/10.** No control lacks a data source now. Still open: which issuers get a sign-in button and how they are labelled, the order inside the sign-in box, and the header identity layout.

### DR3: which issuers get a sign-in button, and what it says
Finding: subagent finding 3, HIGH, confidence 9/10, §5.7 "one 'Sign in with <issuer>' button per discovered issuer", §5.5 identity-file example, reviewer: Claude design subagent.
Plan baseline: one button per discovered issuer, labelled with the issuer.
Gap: the §5.5 example has four issuers. Two of them, `github-actions` and `eks-prod`, are workload issuers with no dashboard client id. Read literally, the plan shows "Sign in with github-actions" and "Sign in with eks-prod" buttons that can't start a browser sign-in. The label source is `issuers[].name`, a lowercase slug (`[a-z0-9-]`), so people would read "Sign in with okta".
Shared by every option: only issuers with `clients.dashboard` set get a button, because a browser sign-in can't start without that client id. Buttons follow identity-file order.

| Choice | Current | A | B |
|---|---|---|---|
| Buttons shown | every issuer | issuers with `clients.dashboard` | issuers with `clients.dashboard` |
| Label | "Sign in with <name>" | "Sign in with <display_name>"; new optional `issuers[].display_name` (1–40 chars, control characters stripped), falling back to `name` | "Sign in with <name>" (slug as written) |
| Discovery (`/.well-known/aerolvm-auth`) | issuer URLs, client ids | adds `display_name` | unchanged |
| Effort | — | S (human ~2 h / CC ~10 min) | S (human ~30 min / CC ~3 min) |

State: approved
Actual answer: A) "Optional display_name (recommended)" (D5, 2026-10-17)
Accepted scope:
- Buttons render only for issuers with `clients.dashboard`, in file order.
- New optional `issuers[].display_name` (schema row, §5.5 example), published in discovery.
- T6 validates and publishes the field. T8 checks the two-button render for the example file.

**Pass 1 re-rate after DR3: 8/10.** The sign-in screen now lists only real, readable choices. Still open: the order inside the sign-in box (brand, buttons, token fallback) and the header identity layout.

### DR4: the order inside the sign-in box
Finding: subagent finding 11, MEDIUM, confidence 8/10, `pkg/api/dashboard.html:151-162` (box heading "sandboxd", placeholder-only token field), header brand "AerolVM" (`:166-169`), §5.7, reviewer: Claude design subagent.
Plan baseline: Section 11 sketch `[Sign in with Okta] [Sign in with Google] [use a token ▾]`. Nothing fixes the heading, the order, or the relative weight of the buttons and the token box.
Gap:
- **Brand.** The first screen says "sandboxd" and the page header says "AerolVM", so the first screen names a process, not the product.
- **Order and weight.** No rule decides whether SSO or the token box comes first, or how much space each gets.
- **Token field label.** Its only label is the placeholder "Personal access token", which disappears once you type (a universal hard rule).
Shared by every option: the token field gets a visible `<label>` ("API token"), with the hint "An avm_ token or the server's PAT." Buttons are full width and stacked, in DR3 order.

| Choice | Current | A | B | C |
|---|---|---|---|---|
| Heading | "sandboxd" | "AerolVM", then the page's host in muted text | "sandboxd" | "AerolVM", then the host |
| Line under it | "Sign in with `SB_PAT_TOKEN` to view this node." | "Sign in with your company account." | same as A | same as A |
| SSO buttons | — | first, full width | first, full width | first, full width |
| Token box | the whole box | behind a "Use an API token instead" disclosure, after an "or" divider. Closed when any SSO button shows; open, and the only content, when none do. | as A | always visible under the buttons, equal weight |
| Effort | — | S (human ~2 h / CC ~10 min) | S | S |

State: approved
Actual answer: A) "AerolVM, SSO first (recommended)" (D6, 2026-10-17)
Accepted scope: the §5.7 "Sign-in box layout" bullet and its wireframe: the heading and host, the two line variants, SSO buttons first, the token disclosure rule, and the visible token label. T8 checks the disclosure state, the heading and the label.

**Pass 1 re-rate after DR4: 9/10.** The sign-in screen has a fixed order. Still open: the header identity treatment.

### DR5: who you are, in the header
Finding: subagent finding 9, MEDIUM, confidence 8/10, Section 11 sketch "header: name · role · team ▾ · sign out", `pkg/api/dashboard.html:164-175`, reviewer: Claude design subagent.
Plan baseline: the CEO review's Section 11 approved showing the name and role in the header. DR2 removed the team. There is no rule for where the identity goes, how long names behave, or what a PAT session shows.
Gap: after DR1, everyone who sees the header is an `admin` or a PAT/operator caller. The useful difference is between a named admin and a shared-token session, because shared-token actions are recorded as the server, not a person. Long OIDC emails and token names have no width rule.

| Choice | Current | A | B |
|---|---|---|---|
| Position | — | right side, before auto-refresh / Refresh / Sign out | right side, before the controls |
| Content | — | display name, plus a muted role pill (`admin`) | display name only |
| PAT/operator session | — | "Server token" with an `operator` pill in `--warn` text. Its `title` reads "Actions are recorded as the server, not a person." | "Server token" |
| Long names | — | `max-width: 200px`, ellipsis, full value in `title` | same |
| Effort | — | S (human ~1 h / CC ~5 min) | S (human ~45 min / CC ~4 min) |

State: approved
Actual answer: A) "Name + role pill (recommended)" (D7, 2026-10-17)
Accepted scope: the §5.7 "Header identity" bullet and its T8 check. L8 sets one constraint: the `--warn` color appears only with identity on. On a default install the pill is muted, because there is no SSO to steer toward and identity-off behavior stays as today.

**Pass 1 re-rate after DR5: 10/10.** Every role has a defined first screen. The sign-in box, the signed-in screen and the header each have a fixed order, wireframes for the two boxes, and no control without a data source.

## Design Pass 2: Interaction state coverage

**Initial rating: 5/10.** The CEO review's Section 11 state table covers sign-in, the team picker, role-aware actions and expiry. DR1 and DR2 retired two of those rows. Four gaps remain:
- **Expiry renewal.** It can't be built as written (DR6).
- **Sign-out.** It signs Google users straight back in (DR7). DR8's buttons depend on it, so it is asked first.
- **The "no binding" screen.** It has no content spec (DR8).
- **State wording.** Seven states have no words at all (DR9).

### DR6: renewing an expired sign-in
Finding: subagent finding 6, HIGH, confidence 8/10, §5.7 "Expiry mid-session", the §5.7 CSP (`frame-src https://accounts.google.com` only), reviewer: Claude design subagent.
Plan baseline: "on a 401 with `reason: expired`, the page re-runs sign-in silently once (GIS auto-select; SPA providers re-authorize with `prompt=none`). If that fails, it shows 'sign in again' and keeps the current view."
Gap:
- **Okta, Entra and Keycloak.** A silent `prompt=none` re-authorization runs in a hidden iframe or a full-page redirect.
  - The CSP blocks iframes to those providers, and Safari and Chrome now block the provider's cookie inside a third-party iframe, so the iframe route fails.
  - A redirect reloads the page, and nothing says how the view survives that.
- **Parallel 401s.** The page polls four panels. When the token expires, four 401s arrive at once, and nothing stops four renewals from starting.
- **Google.** GIS auto-select is unaffected (its frame is allowed).

| Choice | Current | A | B | C |
|---|---|---|---|---|
| When | on the first 401 `expired` | proactively at `exp − 120 s` while the tab is visible, and on any 401 `expired` | same as B | on a 401 `expired` |
| Okta, Entra, Keycloak | `prompt=none` (iframe, blocked) | a refresh-token grant from the browser. The sign-in asks for `offline_access`, and the provider's rotating refresh token sits in `sessionStorage` next to the ID token. Operators must enable SPA refresh tokens at the provider. | a full-page redirect with `prompt=none`. The view (open panel, filters, page) is saved in `sessionStorage` first and restored on return. If a request or a confirm prompt is in progress, the redirect waits for it. | none |
| Google | GIS auto-select | GIS auto-select | GIS auto-select | none |
| Concurrency | unspecified | one renewal at a time; auto-refresh pauses and API calls wait for it | same | — |
| On failure | "sign in again", view kept | a top banner, "Your sign-in expired. [Sign in again]" (`role="alert"`), view kept | same banner | same banner, every time a token expires (about hourly) |
| What the browser holds | ID token (about 1 h) | ID token, plus a refresh token living up to the provider's limit (Entra SPA: 24 h) | ID token only | ID token only |
| Effort | — | M (human ~1.5 d / CC ~40 min) | M (human ~1 d / CC ~30 min) | S (human ~2 h / CC ~10 min) |

State: approved
Actual answer: "Redirect, save the view (recommended)" (D8, 2026-10-17). This is grid column **B**. The question listed it first.
Accepted scope: the §5.7 "Expiry mid-session" rewrite: proactive plus on-401 timing, single-flight, the `prompt=none` full-page redirect with the view saved and restored, GIS auto-select for Google, and the failure banner. There is no browser refresh token, and the CSP is unchanged. T8 tests single-flight, the redirect, waiting for an in-flight action, and the banner.

### DR7: signing out, and switching accounts
Finding: subagent finding 5, HIGH, confidence 9/10, `pkg/api/dashboard.html` Sign out (clears `sessionStorage`), §5.7 Google path ("GIS auto-select re-issues it silently"), reviewer: Claude design subagent.
Plan baseline: Sign out clears the stored token and shows the sign-in box. There is no account-switch path.
Gap:
- **Google signs you straight back in.** GIS auto-select is on so renewal can be silent (DR6). After Sign out, the next page load or button click auto-selects the same Google account, so Sign out looks broken.
- **No way to switch accounts.** For every provider, clicking the button again silently reuses the provider's session. A person who signed in with the wrong account (personal vs work Google, a second Entra tenant) can't switch.

| Choice | Current | A | B | C |
|---|---|---|---|---|
| Local sign-out | clear the stored token | clear the token and the DR6 saved view; call `google.accounts.id.disableAutoSelect()` | same as A | same as A |
| After sign-out | sign-in box | the sign-in box with a muted "Signed out." line, focus on the first button | same as A | same as A |
| Switch account | none | a "Use a different account" link under the buttons: `prompt=select_account` where the issuer's discovery lists it, else `prompt=login`; for Google, GIS account chooser | same as A | none |
| Provider sign-out | none | none: the person stays signed in to their company account, as with other SSO apps | also redirect to the issuer's `end_session_endpoint`, signing them out at the provider | none |
| Effort | — | S (human ~3 h / CC ~15 min) | S–M (human ~5 h / CC ~20 min) | S (human ~1 h / CC ~5 min) |

State: approved
Actual answer: A) "Local sign-out + switch link (recommended)" (D9, 2026-10-17)
Accepted scope: the §5.7 "Sign out and switching accounts" bullet (local sign-out, `disableAutoSelect()`, the "Signed out." state and the switch link with the `prompt` rule) and its T8 checks. There is no provider sign-out.

### DR8: the "no binding" screen
Finding: subagent finding 7, HIGH, confidence 9/10, §5.5 "No binding matched" (403, message names the issuer and the caller's groups), Section 11 flow "403 screen with the D9 hint … + [sign out]", reviewer: Claude design subagent.
Plan baseline: a 403 screen showing the D9 hint and Sign out. The hint is one message string: "no role binding for ana@acme.com", plus the issuer and groups.
Gap:
- **No content spec.** The screen has no heading, no wording and no announcement.
- **Long group lists.** People commonly carry 20 to 150 groups, and the plan would print them inline as one string.
- **Overage and empty cases.** The Entra overage case ("group overage: bind on Entra app roles") and the no-groups case have no wording.
- **No structured data.** `whoami` itself returns this 403, so the screen must render from the 403 body, but the body has no structured fields to render from.

| Choice | Current | A | B |
|---|---|---|---|
| Heading | — | "You're signed in, but you don't have access here." | none: the hint text as the box body |
| Who and where | inside the hint string | "alice@acme.com · Acme Okta" (DR3 display name) | inside the hint string |
| Guidance | inside the hint string | "No access rule on this server matches your account. Ask your AerolVM admin to add one for a group you're in." | none |
| Groups | inline in the string | `<details>` "Groups your sign-in carried (N)", up to 50 shown, then "and N more". "Your sign-in carried no groups." when there are none. | inline in the string |
| Entra overage | "group overage: bind on Entra app roles" | "Your sign-in carried too many groups to list. Ask your admin to bind an Entra app role instead." (no list) | the hint string |
| Actions | Sign out | Use a different account (DR7) · Sign out | Sign out |
| Announcement | — | focus moves to the heading; the box has `role="alert"` | — |
| v1 403 body | message only | adds `reason` (`no_binding` or `group_overage`), `issuer`, `name` and `groups[]`, all the caller's own claims. The facades are unchanged. | unchanged |
| Effort | — | S (human ~4 h / CC ~20 min) | S (human ~1 h / CC ~5 min) |

State: approved
Actual answer: A) "Structured screen (recommended)" (D10, 2026-10-17)
Accepted scope:
- The §5.7 "No access screen" bullet and its wireframe.
- The four v1 403 body fields in §5.5. The facades are unchanged, and PAT and managed bodies are unchanged (L8).
- T6 body tests and T8 render tests.

### DR9: words for every sign-in state
Finding: subagent finding 8, MEDIUM, confidence 8/10, Section 11 state table, §5.7 HTTPS rule, §5.2 D17 reasons, `dashboard.html:330` ("Invalid or expired token. Sign in again."), reviewer: Claude design subagent.
Plan baseline: Section 11 gives wording for only two states ("redirecting to <issuer>…", "sign in again"). §5.7 says the plain-HTTP page shows "open https://<domain>/ui to sign in", but the page has no source for `<domain>`.
Gap: these states have no words, so each engineer would invent them:
- loading the sign-in options, and the discovery fetch failing;
- returning from the provider;
- a provider `?error=`, and a stale state or nonce;
- a blocked Google pop-up;
- the D17 401 reasons;
- a `whoami` 503;
- the HTTPS pointer, and the plain-HTTP token warning.

Proposed wording. All lines go in the approved `aria-live="polite"` region, and reason codes are shown in parentheses so support can match them:

| State | What the person sees |
|---|---|
| Loading sign-in options | muted "Loading sign-in options…" where the buttons go |
| Discovery fetch failed | "Couldn't load sign-in options. You can still use an API token." plus Retry; the token disclosure opens |
| Leaving for the provider | the clicked button reads "Opening Acme Okta…"; all buttons disabled |
| Back from the provider | only "Signing you in…" until `whoami` answers |
| Provider `?error=` | "Acme Okta didn't sign you in (access_denied). Try again, or use a different account." The URL is cleaned with `history.replaceState`. |
| Stale state or nonce | "That sign-in attempt expired. Please try again." |
| Google pop-up blocked | "Your browser blocked the Google sign-in window. Allow pop-ups for this site, then try again." |
| 401 `not_yet_valid` | "Your computer's clock is more than a minute off. Fix the clock, then sign in again." |
| 401 `wrong_audience`, `unknown_issuer`, `too_long_lived` | "This server doesn't accept sign-ins from that app (wrong_audience). Ask your AerolVM admin to check the dashboard client id." |
| 401 `invalid_signature`, `malformed`, `unknown_or_revoked` | "That sign-in couldn't be verified (invalid_signature). Try again. If it keeps failing, tell your AerolVM admin." |
| `whoami` 503 (identity file or keys unavailable) | "Sign-in is unavailable on this server right now. Try again in a minute, or use an API token." plus Retry; the token disclosure opens |
| Plain HTTP from another host | buttons replaced by "SSO sign-in needs a secure connection. Open https://api.acme.dev/ui". With no domain: "… Reach this page through an SSH tunnel to localhost:21212." |
| Token field on plain HTTP | a `--warn` line: "This connection isn't encrypted. Your token will cross the network in plain text." |
| PAT rejected | unchanged: "Invalid or expired token. Sign in again." (L8) |
| `avm_` token rejected | "That token has expired." or "That token isn't valid or was revoked." (D17 reason) |

| Choice | Current | A | B |
|---|---|---|---|
| Wording table above | none | adopted as T8 acceptance criteria | adopted |
| HTTPS pointer's domain | no source | discovery adds `ui_url` (`https://<SB_DOMAIN>/ui`, omitted when `SB_DOMAIN` is empty) | no domain: always "Open this page at https://<your API domain>/ui, or through an SSH tunnel to localhost:21212." |
| Effort | — | S (human ~4 h / CC ~20 min) | S (human ~3 h / CC ~15 min) |

State: approved
Actual answer: A) "Table + ui_url (recommended)" (D11, 2026-10-17)
Accepted scope: the wording table above as T8 acceptance criteria; discovery `ui_url` from `SB_DOMAIN` (T6 test); the §5.7 HTTPS bullet and "State wording" bullet.

### Pass 2 consolidated state table

This restates DR1 and DR6–DR9 in one place for T8. It replaces the CEO review's Section 11 table and adds no new decision.

| Feature | Loading | Empty | Error | Success | Partial |
|---|---|---|---|---|---|
| Sign-in options | "Loading sign-in options…" | no dashboard issuers, or identity off → token disclosure open, "Sign in with an API token." | discovery failed → message plus Retry, token disclosure open | buttons in DR3 order | plain HTTP → buttons replaced by the `ui_url` pointer; token field with the warning |
| SSO sign-in | "Opening Acme Okta…" then "Signing you in…" | — | provider `?error=`, stale state, pop-up blocked, the D17 401 reasons, `whoami` 503 → DR9 wording | admin or operator → overview; other roles → signed-in screen (DR1) | no binding → no-access screen (DR8) |
| Token sign-in | button disabled while checking | — | PAT → today's text; `avm_` → reason text | same routing as SSO | — |
| Session renewal | none visible (Google); the page reloads and restores the view (SPA providers) | — | "Your sign-in expired. [Sign in again]" banner, view kept | same view | auto-refresh paused during renewal |
| Sign out | — | — | — | "Signed out." in the sign-in box | — |

**Pass 2 re-rate: 10/10.** Every state the identity work adds has words, a place in the table and a T8 test. The overview's own `alert()`/`confirm()` prompts are existing UI that this plan doesn't change, so they are recorded under NOT in scope.

## Design Pass 3: User journey and emotional arc

**Initial rating: 6/10.** Section 11 drew the flow, but no persona was walked through it, and nothing said what each step should feel like. The storyboard below follows the decisions already approved (DR1–DR9) and adds no new treatment.

| Step | User does | User feels | Plan specifies? |
|---|---|---|---|
| **Admin, first SSO day** | | | |
| 1 | Opens `https://api.acme.dev/ui` | Oriented: "this is our AerolVM" | yes: "AerolVM" plus the host, one clear button (DR4) |
| 2 | Clicks "Sign in with Acme Okta" | Something is happening | yes: "Opening Acme Okta…", then "Signing you in…" (DR9) |
| 3 | Lands on the overview | Recognized and accountable | yes: name and `admin` pill in the header (DR5) |
| 4 | Keeps working past the hour | Doesn't notice | yes: one quick reload that restores the view, or none for Google (DR6) |
| 5 | Clicks Sign out | Done, and trusts it | yes: "Signed out.", no Google auto sign-back-in (DR7) |
| **New hire with no binding** | | | |
| 6 | Signs in | Blocked, but not broken | yes: plain heading, next step, groups behind a toggle (DR8) |
| 7 | Realizes it was the personal Google account | Relief: there's a way out | yes: "Use a different account" (DR7) |
| **Team viewer** | | | |
| 8 | Signs in | Clear about why there's no data | yes: the signed-in screen names role and team (DR1) |
| 9 | Follows the CLI pointer | Expects it to work | **partly**: the pointer says `aerolvm list`, but a fresh CLI isn't signed in, so the first command fails (DR10) |
| **Operator with the PAT, identity on** | | | |
| 10 | Opens the token disclosure and pastes the PAT | Reminded their clicks aren't tied to them | yes: "Server token" with a `--warn` `operator` pill (DR5) |
| **Visitor on plain HTTP** | | | |
| 11 | Opens `http://10.0.0.5:21212/ui` | Pointed somewhere useful, not stuck | yes: link to `ui_url` (DR9) |

**Time horizons:**
- **5 seconds.** The product name, the host and one prominent button.
- **5 minutes.** Sign in, see yourself in the header, work, and renewal never interrupts.
- **5 years.** Every audit record names a person, and the warning pill keeps shared-token use visible until teams retire the PAT (D4, D5).

### DR10: the signed-in screen's CLI pointer
Finding: Pass 3 storyboard step 9, MEDIUM, confidence 9/10, §5.7 signed-in screen (`aerolvm list`), §5.6 (`aerolvm login <url>` reads discovery and runs SSO), reviewer: Claude (design review).
Plan baseline: DR1 approved "a CLI pointer" and wrote it as `aerolvm list`.
New evidence: a person who just signed in to the dashboard usually has no CLI login on that machine, so `aerolvm list` fails first with "not logged in". The working path is two commands: `aerolvm login https://api.acme.dev` (SSO, §5.6), then `aerolvm list`.

| Choice | Current (DR1) | A | B |
|---|---|---|---|
| Pointer on the signed-in screen | `aerolvm list` | two lines: `aerolvm login https://<host>` then `aerolvm list`, the host filled from the page | `aerolvm list` (unchanged) |
| Effort | — | S (human ~15 min / CC ~2 min) | none |

State: approved
Actual answer: A) "Show login, then list (recommended)" (D12, 2026-10-17), refining D3's CLI pointer
Accepted scope: the signed-in screen shows `aerolvm login https://<host>` then `aerolvm list`, with the host taken from the page. The §5.7 text, the wireframe and the T8 check are updated.
History: D3 approved "a CLI pointer (aerolvm sandbox list)", recorded as `aerolvm list` after checking `cmd/aerolvm/help.go:93-95`. Reopened because of storyboard step 9.

**Pass 3 re-rate: 10/10.** Every persona's steps are specified, and no step leads to a dead end.

## Design Pass 4: AI slop risk

**Classifier: OPERATE (app UI).** The win is "signed in and acting as myself", so the App UI rules apply: calm surfaces, utility copy, few colors.

**Initial rating: 6/10.** DR4 already fixed the brand, so the new screens are one box each, with utility copy and no decoration. The one undecided visual is the Google button. Google renders it in its own iframe, so the plan doesn't control its look by default.

**Hard rejections:** none triggered by the new screens. The overview's KPI tile grid and stacked cards are existing UI that this plan doesn't change (NOT in scope).

**Litmus** (new screens, after DR1–DR10):

| Check | Answer | Evidence |
|---|---|---|
| 1. Brand unmistakable in the first screen? | YES | "AerolVM" plus the host heads every box (DR4) |
| 2. One strong visual anchor? | YES | the full-width SSO button stack (DR4) |
| 3. Scannable by headlines only? | YES | each box opens with one plain heading (DR1, DR8) |
| 4. Each section has one job? | YES | one screen per outcome: sign in, signed in without access, no binding (DR1, DR8) |
| 5. Cards actually necessary? | YES | the single box is the form itself |
| 6. Motion improves hierarchy? | N/A | none proposed |
| 7. Premium without decorative shadows? | YES | border-only box, as today |

**AI slop blacklist:** item 11 (system UI font as the primary face) matches the dashboard's existing `--sans` stack. That is existing UI and NOT in scope (prior learning `acebot-no-ui-scope-creep`). Nothing else matches.

### DR11: the Google button and the other SSO buttons
Finding: subagent finding 4, HIGH, confidence 8/10, §5.7 Google path (GIS renders its own button in an iframe), `dashboard.html:39-42` (button: `--panel2`, 1 px `--border`, radius 4 px), reviewer: Claude design subagent.
Plan baseline: nothing on button look. By default GIS draws a white, pill-ish button of its own width.
Gap:
- **It won't match.** On the dark box, the default Google button is a bright white block of a different height and width from the Okta button.
- **It can't be restyled.** Google's rendered button is the only supported way to get an ID token with no server secret (D2), so the other buttons have to match Google's geometry, not the other way round.

| Choice | Current | A | B |
|---|---|---|---|
| Google button | GIS defaults (white) | `renderButton` with `theme: "filled_black"`, `size: "large"` (40 px), `shape: "rectangular"`, `text: "signin_with"`, `logo_alignment: "left"`, `width: 312` (the box's inner width) | GIS defaults |
| Other SSO buttons | the page's default button (4 px × 10 px padding) | matched to Google: 40 px tall, full width (312 px), radius 4 px, the existing `button` look (`--panel2`, 1 px `--border`, hover `--accent`), 14 px text, no accent fill | the page's accent-colored primary button |
| Effect | mismatched stack | one even stack, Google indistinguishable in size and weight | a white Google block next to a blue Okta button |
| Effort | — | S (human ~1 h / CC ~5 min) | none |

State: approved
Actual answer: A) "Match Google's dark button (recommended)" (D13, 2026-10-17)
Accepted scope: the GIS `renderButton` options and the matched geometry for the other SSO buttons in §5.7 "Sign-in box layout", plus the T8 check.

**Pass 4 re-rate: 10/10.** The new screens use specific, intentional treatments: one box, utility copy, an even button stack and existing tokens. No hard rejection or slop pattern is introduced. The existing dashboard's font stack and card layout stay out of scope.

## Design Pass 5: Design system alignment

`DESIGN.md` is the actor model, not a visual system, so this pass rates the plan's explicit tokens against the dashboard's own CSS (`pkg/api/dashboard.html:10-147`).

**Initial rating: 7/10.** Earlier decisions mapped most new elements to existing styles. The pills (DR5), the banner (DR6), the "or" divider (DR4), the inline error lines (DR9) and the token warning (DR9) were approved as elements but had no token named.

**Token map.** Each row applies an existing class or token to an element an earlier decision already approved. No new visual choice is made, so no question was needed:

| Element (approved by) | Existing token or class |
|---|---|
| Sign-in, signed-in and no-access boxes (DR1, DR4, DR8) | `#login .box`: `--panel`, 1 px `--border`, radius 8 px, 24 px padding, 360 px |
| Heading "AerolVM" (DR4) | `#login h1` (18 px) |
| Host line, "Signed out.", loading lines (DR4, DR7, DR9) | `--muted`, `#login p` |
| SSO buttons (DR11, DR12, DR14) | `button` (`--panel2` fill, hover `--accent`) with a 1 px `--muted2` border, 40 px tall, as wide as the box |
| "or" divider (DR4) | 1 px `--border-soft` rules with `--muted` text, 12 px |
| Token disclosure, groups toggle (DR4, DR8) | `details > summary` (`--muted`, 12 px) |
| Role pill `admin` (DR5) | `.pill.muted` |
| `operator` pill with identity on (DR5) | `.pill.warn` |
| Inline error lines (DR9) | `.error` (`--bad`), `#login .error` (12 px) |
| Plain-HTTP token warning (DR9) | `--warn` text, 12 px |
| "Your sign-in expired" banner (DR6) | the `.pill.warn` palette (`#231e10` background, `#5a4a1c` border, `--warn` text) as a full-width bar under the header, 8 px × 16 px padding, with Sign in again as a standard `button` |

**New components:** none. Every element is built from the classes above.

**Pass 5 re-rate: 10/10.** Every new element names an existing token or class. Turning `DESIGN.md` into a visual system (`/design-consultation`) is out of this feature's scope and recorded under NOT in scope.

## Design Pass 6: Responsive and accessibility

**Initial rating: 4/10.**
- **Section 11's rules.** Real `<button>`s labelled with the issuer, focus on the first button, errors in `aria-live="polite"`, and "reflow at phone width like the rest of `/ui`".
- **Responsive gaps (DR12).** `dashboard.html` has no `@media` rule at all, so "like the rest" specifies nothing. DR11's 312 px Google button overflows a 320 px phone, because the box shrinks to 92vw.
- **Accessibility gaps.** Focus can't start on Google's button, which lives in an iframe (DR13). No focus ring is themed. The SSO button border is 1.34:1 against the box (DR14).

Already passing, measured from the tokens:
- **Text contrast:** `--muted` on `--panel` 5.94:1, `--text` 14.5:1, `--bad` 6.09:1, `--warn` on its pill 9.94:1.
- **Target size:** 40 px buttons meet WCAG 2.2 AA target size (24 px). Google's large button is fixed at 40 px, so 44 px (AAA) is not reachable for it.
- **Alerts:** `role="alert"` on the banner and the no-access box (DR6, DR8).

### DR12: narrow screens
Finding: subagent finding 9 (wrap below 720 px) and Pass 6 review, MEDIUM, confidence 8/10, `dashboard.html:68,142` (`max-width: 92vw`, no `@media`), §5.7 DR11 (`width: 312`), reviewer: Claude design subagent and Claude (design review).
Plan baseline: Section 11 says "reflow at phone width like the rest of `/ui`".
Gap: there is no reflow to copy.
- On a 375 px phone, the header holds the brand, node summary, name, pill, auto-refresh, Refresh and Sign out in one row and overflows.
- On a 320 px phone, the box is 294 px wide, and the fixed 312 px Google button overflows it.

| Choice | Current | A | B |
|---|---|---|---|
| Header below 720 px | overflows | wraps to two rows: brand and node summary, then identity and controls; the name's `max-width` drops to 140 px | unspecified (desktop target) |
| Boxes below 400 px | 92vw, 24 px padding | 92vw, 16 px padding | unchanged |
| Google button width | fixed 312 px | the box's measured inner width (GIS allows 200–400 px), re-rendered on resize; other SSO buttons `width: 100%` | fixed 312 px |
| Banner below 480 px | — | text wraps, and "Sign in again" drops below it | unspecified |
| Stated support | — | the new screens fit 320 px with no horizontal scroll; overview tables keep today's horizontal scroll (`.card .body`) | `/ui` targets ≥ 1024 px; phones unsupported |
| Effort | — | S (human ~2 h / CC ~10 min) | S (docs line only) |

State: approved
Actual answer: A) "Specify narrow behavior (recommended)" (D14, 2026-10-17)
Accepted scope: the §5.7 "Narrow screens" bullet, the DR11 width rule switched to the measured width, and the T8 viewport checks at 320 and 375 px.

### DR13: keyboard focus
Finding: subagent finding 4 (focus) and Pass 6 review, MEDIUM, confidence 8/10, Section 11 "keyboard focus lands on the first one", DR7 "focus on the first button", `dashboard.html` (no `:focus` or `:focus-visible` rule; `autofocus` on the token field at `:156`), reviewer: Claude design subagent and Claude (design review).
Plan baseline: focus starts on the first sign-in button, and the browser's default focus ring is used.
Gap:
- **Focus can't always start on the first button.** When Google is the first issuer, the first button is Google's iframe, which a script can't reliably focus. The rule fails, and keyboard users start nowhere.
- **The ring is unthemed.** The default ring on the dark box is a thin blue or black outline that varies by browser, often under 3:1 against `--panel`.
- **Stale autofocus.** The token field's `autofocus` would steal focus from the SSO buttons when the disclosure is closed.

| Choice | Current | A | B |
|---|---|---|---|
| Where focus starts | "first button" | the first focusable element in the box that isn't Google's iframe: an SSO button, else "Use a different account", else the token disclosure's summary, else the token field when it's the only content. On the no-access screen, the heading (DR8). | first button, whatever it is |
| Token field `autofocus` | always | removed; focus is set by the rule above | kept |
| Focus ring | browser default | `:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px }` on the new elements (`--accent` on `--panel` is 7.21:1) | browser default |
| Tab order | — | visual order; the overview is `hidden` while a box shows, so no focus trap is needed | — |
| Effort | — | S (human ~1 h / CC ~5 min) | none |

State: approved
Actual answer: A) "Focus rule + accent ring (recommended)" (D15, 2026-10-17)
Accepted scope:
- The §5.7 "Keyboard focus" bullet: the start rule, `autofocus` removed, the themed ring and tab order.
- DR7's "focus on the first button" now points to the DR13 rule. The Section 11 accessibility rule is superseded on this point.
- T8 checks the start rule with Google listed first and with Google as the only issuer.

### DR14: SSO button edges
Finding: Pass 6 review, MEDIUM, confidence 7/10, `dashboard.html:39-42` (`button` border `--border` #2a2f3a; background `--panel2`), the box `--panel` #14171d, Google's dark button style (fill #131314, 1 px stroke #8E918F, per Google's sign-in branding guidelines), reviewer: Claude (design review).
Plan baseline: DR11 gives the other SSO buttons the existing `button` look.
Gap:
- **Our button edges are nearly invisible.** The existing border is 1.34:1 against the box, and the button fill is barely lighter than the box.
- **Google's edge is not.** Its button carries a light gray stroke at 5.64:1.
- **The result.** The Okta button reads as text floating in the box, beside a clearly outlined Google button. DR11's even stack breaks. The labels identify the controls, so WCAG 1.4.11 is technically met, but the primary action loses its shape.

| Choice | Current (DR11) | A | B |
|---|---|---|---|
| SSO button border in the boxes | `--border` (1.34:1) | `--muted2` #6a7385 (3.76:1), close to Google's stroke; hover stays `--accent` | `--border` |
| Other buttons on the page | unchanged | unchanged | unchanged |
| Effort | — | S (human ~10 min / CC ~1 min) | none |

State: approved
Actual answer: A) "Visible border (recommended)" (D16, 2026-10-17)
Accepted scope: SSO buttons in the boxes use a 1 px `--muted2` border, with hover still `--accent`, in §5.7, the Pass 5 token map and the T8 check. Other buttons are unchanged.

**Pass 6 re-rate: 10/10.**
- **Narrow screens.** The new screens have explicit layouts down to 320 px (DR12).
- **Keyboard.** Focus starts somewhere usable, with a themed ring (DR13).
- **Contrast.** Control edges are 3:1 or better (DR14), text contrast is 5.5:1 or better, and the targets meet WCAG 2.2 AA.
- **Announcements.** Errors use the polite live region, and the expiry and no-access states use `role="alert"`.

## Design Pass 7: Unresolved design decisions

Earlier passes left no dashboard decision open: DR1–DR14 are approved. One in-scope surface is still unspecified: the CLI text that T7 adds. It is listed under the review's secondary scope.

| Decision needed | If deferred, what happens |
|---|---|
| CLI wording for SSO sign-in, `whoami`, the no-binding case, the refresh failure and the expiry warning (DR15) | T7's golden tests lock in whatever an engineer writes first, and the CLI's words drift from the dashboard's (DR8, DR9) |

### DR15: CLI words for the identity commands
Finding: Pass 7, MEDIUM, confidence 8/10, §5.6 (`aerolvm login <url>`, refresh, `whoami`, expiry warnings, the refresh hint "sign in again with `aerolvm login --sso`"), T7 golden tests, `cmd/aerolvm/login.go:316-319` (house style: `aerolvm:` notes on stderr, e.g. "aerolvm: logged in to %s (sandboxd %s). The token is saved in %s, readable only by you."), reviewer: Claude (design review).
Plan baseline: §5.6 names the commands and one hint string. There is no wording for the issuer choice, the browser and device prompts, success, no binding, the expiry warning, or the `whoami` layout.

Proposed wording (stderr notes in the existing `aerolvm:` style; `--json` output unchanged):

| Moment | Text |
|---|---|
| More than one issuer with a CLI client | `aerolvm: sign in with  [1] Acme Okta  [2] Google` then `Choose [1]: ` (DR3 display names) |
| Browser flow | `aerolvm: opening your browser to sign in with Acme Okta. If it doesn't open, visit: <url>` |
| Device flow (`--device`) | `aerolvm: to sign in, open https://acme.okta.com/activate and enter the code ABCD-EFGH. Waiting…` |
| Success | `aerolvm: logged in to https://api.acme.dev as alice@acme.com (role runner, team payments) through Acme Okta. The login is saved in <path>, readable only by you.` |
| No binding | `aerolvm: signed in as alice@acme.com through Acme Okta, but no access rule on https://api.acme.dev matches your account. Ask your AerolVM admin to add one for a group you're in. Your sign-in carried: <up to 10 groups> (and N more).` The Entra overage case uses DR8's wording. |
| Refresh failed | `aerolvm: your sign-in to https://api.acme.dev expired and couldn't be renewed. Sign in again: aerolvm login --sso https://api.acme.dev` |
| `avm_` token expiring (D8, D15) | `aerolvm: warning: the API token "ci-deploy" expires in 6 days (2026-10-23). Ask an admin for a new one before then.` |
| `aerolvm whoami` | first line: the name; then aligned `role`, `team` (or `all teams`), `via` (display name, or `API token "ci-deploy"`, or `server token`), `expires` (`in 54m (15:04 UTC)` or `never`) |

| Choice | Current | A | B |
|---|---|---|---|
| Wording | one hint string | the table above, as T7's golden-test fixtures | left to the T7 implementer; golden tests record what ships |
| Effort | — | S (human ~1 h / CC ~5 min) | none |

State: approved
Actual answer: A) "Adopt the CLI table (recommended)" (D17, 2026-10-17)
Accepted scope: the table above as T7's golden fixtures, the §5.6 "Wording" bullet, and the refresh-failure line rewritten in §5.6. `--json` output is unchanged.

**Pass 7 result:** 1 decision surfaced, 1 resolved, 0 deferred.

## Design review outputs

### NOT in scope

- **Restyling the existing overview** (KPI tiles, cards, tables). Existing UI that identity doesn't change (prior learning `acebot-no-ui-scope-creep`).
- **The dashboard's 13 px type scale and system font stack (`--sans`).** Below the 16 px body guideline and on the slop list, but existing. The new boxes follow them so the page stays consistent.
- **Replacing the overview's `alert()`/`confirm()` prompts** (`dashboard.html:754-764`). Existing, and after DR1 only admins and operators see them.
- **A phone layout for the overview's tables.** They keep today's horizontal scroll (DR12 covers only the new screens and the header).
- **A team-facing dashboard view.** DR1 option C, declined in D3. Team users get the CLI pointer.
- **Remembering the last-used issuer** (subagent finding 11). A convenience beyond the feature.
- **Signing out at the provider.** DR7 option B, declined in D9.
- **Browser refresh tokens.** DR6's refresh-token option, declined in D8.
- **A visual `DESIGN.md`** (`/design-consultation`). `DESIGN.md` stays the actor model, and this feature uses the dashboard's CSS as its system.
- **An expiry countdown and a "copy whoami" button.** Left out by the CEO review's Section 11, and still out.

### What already exists

- **`#login .box`** (`dashboard.html:136-147`). Reused for the sign-in, signed-in and no-access boxes (DR1, DR4, DR8).
- **Existing styles and tokens.** `button`, `.pill.muted`, `.pill.warn`, `.error`, `details > summary`; `--panel`, `--panel2`, `--muted`, `--muted2`, `--accent`, `--warn`, `--bad` (Pass 5 token map).
- **Bearer in `sessionStorage`** (`dashboard.html:266,300`). It keeps holding the bearer, now the ID token.
- **The CLI's house style.** `aerolvm:` notes (`cmd/aerolvm/login.go:316-319`) and `aerolvm list` (`cmd/aerolvm/help.go:93-95`) (DR10, DR15).
- **Google's rendered button** and its dark-theme options (DR11).
- **`/.well-known/aerolvm-auth`** (T6). Extended with `display_name` and `ui_url` (DR3, DR9).
- **The D9 403 hint and the D17 401 reasons.** The dashboard and CLI wording renders them, and the reason codes appear in parentheses.

### TODOS.md updates

None proposed. The NOT-in-scope items are existing UI choices or options you declined, not debt this feature creates.

### Implementation tasks (design review)

Synthesized from this review's findings. Each folds into the stack task named in brackets. Effort assumes features at ~30× and tests at ~50× (human ÷ CC).

- [ ] **DT1 (P1, human: ~3h / CC: ~15min)** — dashboard [T8] — Admin-only console, plus a signed-in screen with the two-line CLI pointer
  - Surfaced by: Pass 1 DR1, Pass 3 DR10
  - Files: `pkg/api/dashboard.html`
  - Verify: `/browse` with a viewer token. The signed-in screen shows, and no `/v1/cluster/*` or `/debug/vars` request is made.
- [ ] **DT2 (P1, human: ~4h / CC: ~20min)** — dashboard [T8] — The sign-in box:
  - Issuer filter and display names.
  - AerolVM heading, SSO first, token disclosure, visible label.
  - Google's dark button, matched buttons with a `--muted2` border.
  - Surfaced by: Pass 1 DR3, DR4; Pass 4 DR11; Pass 6 DR14
  - Files: `pkg/api/dashboard.html`
  - Verify: `/browse` with the §5.5 example file: two 40 px buttons, the disclosure closed, the label present.
- [ ] **DT3 (P1, human: ~3h / CC: ~15min)** — dashboard [T8] — Header identity pills; sign-out with `disableAutoSelect()`; "Use a different account"
  - Surfaced by: Pass 1 DR5, Pass 2 DR7
  - Files: `pkg/api/dashboard.html`
  - Verify: T8 checks. An SSO admin and the PAT render their pills. After Sign out, Google doesn't sign the person back in.
- [ ] **DT4 (P1, human: ~1d / CC: ~30min)** — dashboard [T8] — Renewal:
  - at `exp − 120 s` and on any 401, one at a time;
  - a `prompt=none` redirect that saves and restores the view;
  - GIS auto-select for Google;
  - the expiry banner.
  - Surfaced by: Pass 2 DR6
  - Files: `pkg/api/dashboard.html`
  - Verify: T8 tests. Four 401s start one renewal, the view is restored, the redirect waits for an in-flight action, the banner shows on failure.
- [ ] **DT5 (P1, human: ~5h / CC: ~25min)** — dashboard [T8] — No-access screen and the full state-wording table
  - Surfaced by: Pass 2 DR8, DR9
  - Files: `pkg/api/dashboard.html`
  - Verify: T8 render tests for every row of the DR9 table and the consolidated state table.
- [ ] **DT6 (P1, human: ~3h / CC: ~15min)** — dashboard [T8] — Narrow-screen rules and the keyboard focus rule with its accent ring
  - Surfaced by: Pass 6 DR12, DR13
  - Files: `pkg/api/dashboard.html`
  - Verify: `/browse` at 320 and 375 px shows no horizontal scroll. A keyboard Tab test runs with Google listed first and with Google as the only issuer.
- [ ] **DT7 (P1, human: ~4h / CC: ~20min)** — identity [T6] — `issuers[].display_name`; discovery `display_name` and `ui_url`; the v1 no-binding 403 fields (`reason`, `issuer`, `name`, `groups[]`)
  - Surfaced by: Pass 1 DR3, Pass 2 DR8, DR9
  - Files: `internal/identity/`, `pkg/identitywire/`, `pkg/api/`
  - Verify: `go test ./internal/identity/... ./pkg/identitywire/... ./pkg/api/...`
- [ ] **DT8 (P1, human: ~3h / CC: ~15min)** — cli [T7] — DR15 wording and golden fixtures
  - Surfaced by: Pass 7 DR15
  - Files: `cmd/aerolvm/login.go`, `cmd/aerolvm/testdata/`
  - Verify: `go test ./cmd/aerolvm/...`
- [ ] **DT9 (P2, human: ~1h / CC: ~5min)** — docs [T11] — The fleet-bindings-first rule; `display_name` and `ui_url`; the admin-only console in `dashboard.mdx`
  - Surfaced by: Pass 1 DR2, DR3; Pass 2 DR9; Pass 1 DR1
  - Files: `docs/src/content/docs/enterprise/access-control.mdx`, `docs/src/content/docs/dashboard.mdx`
  - Verify: `make docs-build` with npm 10

### Completion summary

```
  +====================================================================+
  |         DESIGN PLAN REVIEW — COMPLETION SUMMARY                    |
  +====================================================================+
  | System Audit         | DESIGN.md = actor model (no visual system);  |
  |                      | UI scope: /ui sign-in + console, CLI text    |
  | Step 0               | 5/10, all 7 dimensions (D1)                  |
  | Pass 1  (Info Arch)  | 4/10 → 10/10 after fixes                     |
  | Pass 2  (States)     | 5/10 → 10/10 after fixes                     |
  | Pass 3  (Journey)    | 6/10 → 10/10 after fixes                     |
  | Pass 4  (AI Slop)    | 6/10 → 10/10 after fixes                     |
  | Pass 5  (Design Sys) | 7/10 → 10/10 after fixes                     |
  | Pass 6  (Responsive) | 4/10 → 10/10 after fixes                     |
  | Pass 7  (Decisions)  | 1 resolved, 0 deferred                       |
  +--------------------------------------------------------------------+
  | NOT in scope         | written (10 items)                           |
  | What already exists  | written                                      |
  | TODOS.md updates     | 0 items proposed                             |
  | Approved Mockups     | 0 generated, 0 approved (no OpenAI key)      |
  | Decisions made       | 15 added to plan (DR1–DR15, asked D3–D17)    |
  | Decisions deferred   | 0                                            |
  | Overall design score | 4/10 → 10/10                                 |
  +====================================================================+
```

**Outside voice:** Codex unavailable (invalid model id). The Claude design subagent's 11 findings were all handled:
- 9 by their own decision: findings 1–9 map to DR1, DR2, DR3, DR11, DR7, DR6, DR8, DR9 and DR5/DR12.
- Finding 10 became moot under DR1.
- Finding 11 was split: the brand and order became DR4, and "remember the last issuer" is NOT in scope.

Plan is design-complete. Run `/design-review` after implementation for visual QA.

### Unresolved decisions (design review)

None. All 15 design findings were asked and answered (D3–D17).

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | ISSUES OPEN | 7 proposals, 7 accepted, 0 deferred |
| Outside Review | codex (outside voice in `/plan-ceo-review` and `/plan-eng-review`) | Independent 2nd opinion | 2 | unavailable | Codex `model_unusable` (invalid model id) both times; native fallback unavailable (no TaskOutput); no completed external review |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | ISSUES OPEN | 9 issues, 0 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 1 | CLEAR | score: 4/10 → 10/10, 15 decisions |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **OUTSIDE COVERAGE:**
  - **Codex, plan-review phase:** unavailable in both the CEO and the eng review.
  - **Codex, design phase:** unavailable. The in-host Claude design subagent completed with 11 findings, all resolved (DR1–DR15). It is native, so it is not outside coverage. No completed external review exists.
- **Staleness:**
  - The CEO review was recorded at `0d8e51f9`.
  - The eng and design reviews were recorded at `57a0f499`, plus uncommitted edits to this file (the eng-review and design-review records).
  - The design review adds server-visible fields that the eng review never saw:
    - `issuers[].display_name`;
    - discovery `display_name` and `ui_url`;
    - the v1 no-binding 403 fields `reason`, `issuer`, `name` and `groups[]`.
  - It also drops the dashboard's `X-AerolVM-Team` sender.
- **VERDICT:**
  - **DESIGN CLEARED.**
  - **Eng review: ISSUES OPEN.** It found 9 issues, all resolved into accepted changes and tasks, with 0 unresolved decisions and 0 critical gaps. Eng review required. A quick eng re-check of the new fields above is recommended.

**UNRESOLVED DECISIONS:**
- + 2 unresolved from prior reviews
