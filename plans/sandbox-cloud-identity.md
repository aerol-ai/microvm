# D1: a cloud identity per sandbox

Status: design approved by the owner for build (2026-11-06), under
`plans/agent-sandbox-feature-parity.md` row D1 ("needs its own design doc
and a security review"). The security review is section 7; the build PR
must answer each of its points.

## 1. What we want

Code inside a sandbox gets short-lived AWS, GCP or Azure credentials for a
role the customer chose, with no stored secret. This is how IRSA and
Workload Identity work: the platform signs a token, the cloud trusts the
platform's public keys, and the cloud swaps the token for its own
short-lived credentials.

```
 sandboxd (issuer)                     sandbox                       cloud STS
  signs JWT ──push──► toolboxd writes ──► /run/aerolvm/identity/token ──► AssumeRoleWithWebIdentity
  serves /.well-known/openid-configuration + JWKS  ◄────────── fetches keys (public, HTTPS)
```

## 2. Decisions

| # | Decision | Why |
|---|---|---|
| D1.1 | AerolVM is an OIDC issuer at `SB_IDENTITY_ISSUER_URL` (HTTPS, the API's public URL). Off when unset. It serves `GET /.well-known/openid-configuration` and `GET /.well-known/jwks.json` without auth. | The clouds fetch discovery and keys anonymously over public HTTPS. |
| D1.2 | RS256, RSA-2048 keys. | The one algorithm AWS, GCP and Azure all accept for federation. ES256 would let us derive the key from the server key, but Azure acceptance is not certain, so we do not bet on it. |
| D1.3 | The signing key is generated once per deployment, sealed with the existing secrets cipher (`pkg/secrets`), stored in the store, and in cluster mode replicated through the FSM the way named egress profiles are (`internal/cluster/fsm_egress_profiles.go`). Every node signs with the active key; the JWKS lists the active key and the previous one until every token it signed has expired. | A key derived on each node would need ES256 (D1.2). One generated key needs replication; the FSM pattern exists and is tested. |
| D1.4 | Claims: `iss`, `aud` (default `sts.amazonaws.com`; the sandbox may set its own), `sub` = `team:<team id>:role:<role tag>`, `sandbox` (id), `team`, `role`, `iat`, `nbf`, `exp` (1 hour), `jti`. | AWS can only use `sub` and `aud` in trust conditions for a generic OIDC provider, and Azure matches `sub` exactly. So `sub` must hold what customers trust on: the team and a role tag. The sandbox id is for audit, not trust. |
| D1.5 | Role tags are an allow list per team, managed by team admins (`/v1/identity/roles`, admin only): each tag names the minimum caller role (viewer, developer, admin) that may create a sandbox with it. A create asking for a tag not on the list, or by a caller below its role, gets 403. | Without it, any team member could create a sandbox claiming the most trusted role tag and assume the most privileged cloud role. |
| D1.6 | Create option `identity: {role_tag, audience?, aws_role_arn?, azure_client_id?, azure_tenant_id?}`. The sandbox gets `AEROLVM_IDENTITY_TOKEN_FILE`; with `aws_role_arn`, also `AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN` (the AWS SDKs pick these up); with the Azure ids, `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`. GCP is documented with a credential-config file pointing at the token file. | Each cloud SDK finds the token with no code change in the sandbox. |
| D1.7 | sandboxd pushes the token to toolboxd (`PUT /identity/token`, toolbox-token auth like every toolbox route), which writes the file atomically (temp file + rename, mode 0644 in a 0755 folder owned by root). A refresher pass, owner-local, runs every 5 minutes and re-pushes any token with less than 30 minutes left. | toolboxd cannot call sandboxd. Owner-local keeps the work sharded: 100k sandboxes refreshing every 30 min is about 55 pushes per second across the fleet. |
| D1.8 | The first token: pushed right after the sandbox's toolbox becomes reachable, off the create response path, and the env vars are set at create. A process that reads the file in its first moments may not find it; the docs say so, and the AWS/Azure SDKs retry credential loading. The build PR measures the gap and, if it is above 1 s at p99, moves the first push onto the create path and reports the latency (boot-path rule). | Keeps `CreateSandbox` free of a new synchronous call unless the gap proves too big. |
| D1.9 | Runtimes: Docker, containerd, gVisor, Firecracker. WASM and isolate refuse `identity` at create with 400. | They have no file the cloud SDKs could read. |
| D1.10 | Every token issue is an audit record (`identity.token_issued`: sandbox, team, role tag, kid, jti, exp; never the token). | A bank needs to see which sandbox held which role, when. |

## 3. API

- `PUT /v1/identity/roles/{tag}` `{min_role}`, `DELETE`, `GET /v1/identity/roles` (team admin). Idempotent.
- `identity` on create (and visible, without secrets, on the sandbox).
- No route to fetch a token: only the sandbox receives it.

## 4. Failure handling

- Issuer off: `identity` on create gives 400 "identity needs SB_IDENTITY_ISSUER_URL".
- Push fails (sandbox stopped, toolbox down): retried on the next refresher pass; a token that expires unrefreshed is logged and counted (`aerolvm_identity_refresh_failures_total`).
- Key rotation: `POST /v1/identity/keys/rotate` (operator); the new key signs at once, the old key stays in the JWKS for 2 hours.
- Stop/start: a started sandbox gets a fresh token on the next pass (and at once after start, like the first token).

## 5. Tests

Unit: claims, signature verifiable with the published JWKS, expiry, rotation
overlap, allow-list refusal, role check, refresher selection, atomic write
in toolboxd, the 400s. Cluster: a token signed on one node verifies with the
JWKS from another. Live (UC range given to the lane): the discovery and
JWKS endpoints are public; a sandbox sees the token file with the right
claims; it refreshes; a tag not on the list is refused. A live
AssumeRoleWithWebIdentity against real AWS needs an IAM OIDC provider for
the test domain: the lane adds it to the integration Terraform only if
that is a small, isolated change, and otherwise verifies the token with
the JWKS and says so.

## 6. Not in scope

Per-sandbox audience lists, token exchange inside AerolVM, SPIFFE ids,
binding tokens to a sandbox's network identity.

## 7. Security review (the build PR answers each)

1. The issuer key is sealed at rest, never logged, never returned by any API, and only sandboxd processes hold it in memory.
2. A token stolen from a sandbox gives the role that sandbox already had, for at most 1 hour; nothing more. Document it.
3. `sub` cannot be chosen freely: the role tag is checked against the team's allow list and the caller's role at create, and the team comes from the caller's credential, never from the request.
4. Discovery and JWKS are public and read-only; they reveal only public keys.
5. A forged push to toolboxd needs the toolbox token, which only sandboxd has.
6. Cross-team: a token for team A can never carry team B in `sub`.
7. Clock skew: `nbf` = issue time minus 60 s; `exp` 1 hour.
8. Revocation: destroying the sandbox stops refresh; an issued token stays valid until `exp` (document; the customer can tighten the cloud session duration).
