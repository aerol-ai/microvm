# Actors and actions

This is the design of a released AerolVM node: who acts, and what each actor can cause the system to do. The daemon is `sandboxd`. `toolboxd` is the agent inside a sandbox. Caddy terminates TLS and routes HTTP and TCP. A cluster is optional; with cluster mode off, peer actions do not run.

Identity is optional too. With `SB_IDENTITY_ENABLED=false` (the default), the only API credential is the operator token (PAT), and every caller who holds it acts as the operator. With identity on, callers hold named credentials: scoped API tokens (`avm_…`), ID tokens from the company's identity provider, or workload tokens. Each request then runs as a **principal** (who), with a **role** (`viewer`, `runner`, `auditor` or `admin`) on one team or on every team (`*`). A team is an owner (`team:<name>`), so another team's sandbox answers 404. `docs/src/content/docs/enterprise/access-control.mdx` is the user-facing page.

## Actors

| Actor | What it is | What it holds |
| :--- | :--- | :--- |
| Operator | The person who installs and configures the host. | Host access, the PAT, the daemon environment, and the identity file. The PAT is the break-glass and node-to-node credential: it always acts as the operator with every permission. With `SB_PAT_SCOPE=host` it works only from a loopback peer on the API listener and from cluster peers. |
| Person | Someone who signs in with the company's identity provider, through `aerolvm login` or the dashboard. | A short-lived ID token (about an hour) and, in the CLI, a refresh token. Never a password or a sandboxd session. The identity file's bindings map their groups, app roles or claims to a role and a team. |
| Service or CI job | A program that calls the API without a person. | A scoped API token (`avm_…`) with a role, a team and an expiry, minted by an admin. Or a workload token (GitHub Actions, a Kubernetes service account) that is checked like an ID token, so no secret is stored on AerolVM. |
| API client | An SDK or any HTTPS caller, acting for a person, a service or the operator. | One bearer: the PAT, an `avm_` token or an ID token. With identity on, it may also send `X-AerolVM-Team` to pick one of the teams its credential is already bound to. |
| MCP client | An AI agent's host (Claude Code, Cursor, VS Code, a hosted connector) speaking MCP to `aerolvm mcp` on its own machine or to `/mcp` on `sandboxd`. | Any API bearer, from the client's MCP configuration or the CLI login. Or an OAuth access token whose audience is one of the issuer's `mcp_audiences`; such a token is accepted only on `/mcp`. |
| Identity provider | Okta, Entra ID, Google, Keycloak, Authentik, Zitadel, GitHub Actions, or a Kubernetes service-account issuer, named in the identity file. | Its signing keys. It logs people in and signs their tokens. `sandboxd` fetches its public keys at start and hourly, and never calls it per request. |
| Sandbox guest | Code running inside one sandbox. | That sandbox's filesystem, network namespace, and resource limits. Not the host, an API credential, or another tenant's sandbox. |
| Preview or TCP client | A browser or TCP client that was given a published address. | The preview URL or the TLS address. No API credential. |
| SSH client | A client using the sandbox's Ed25519 key. | That one sandbox's key. Its session is recorded as `caller: sandbox_key`; the sandbox's create record names who made it. |
| Cluster peer | Another `sandboxd` process, only when cluster mode is on. | Raft membership, its mTLS certificate and the cluster forwarding credential. Its own calls are recorded as `node:<id>`. A request it forwards still carries the original caller's credential, which the owner node checks again. |
| External storage | An S3, NFS, SSHFS, or rclone service the operator attached. | The credentials the operator sealed into the mount. |

### What each role may do

| Role | Bound to | May |
| :--- | :--- | :--- |
| `viewer` | a team or `*` | Read sandboxes (no env) and their audit records. Bound to `*`, it may also scrape `/v1/metrics`. |
| `runner` | a team or `*` | Everything a viewer may, plus create, change, run commands in and delete sandboxes, and read their env. Never host-side powers: raw host mounts, `file://` bundles, or custom domains without the DNS proof. |
| `auditor` | `*` only | Read every team's sandboxes and audit records, list tokens, verify the audit chain, and scrape metrics. Never write, run or read env. |
| `admin` | `*` only | Everything, including minting and revoking tokens, templates, cluster and reconcile routes, and `/debug/vars`. |

The managed control-plane build maps its users to `runner` (or `viewer`) on their own account, so its behavior is unchanged.

## Actions

| Actor | Action | What carries it out |
| :--- | :--- | :--- |
| Operator | Install `sandboxd`, `toolboxd`, and Caddy. Configure TLS, runtimes, and cluster membership. | `install.sh`, `cluster-init.sh`, `cluster-join.sh`, and the daemon environment. |
| Operator | Turn identity on, name the identity providers, bind groups to roles, and block a person at once. | `SB_IDENTITY_ENABLED`, and the identity file (`SB_IDENTITY_FILE`): issuers, bindings and `deny_subjects`. Each node reloads it within one poll or on SIGHUP and writes one `identity_config` audit record per change. |
| Operator or admin | Mint, list and revoke scoped API tokens. Run fleet operations: reconcile drifted host state, build images, manage templates and cluster members. | `POST/GET/DELETE /v1/tokens` (`aerolvm token`), `POST /v1/admin/reconcile`, `POST /v1/images/build`, `/v1/cluster/*`. A revoke reaches every node within one token-mirror sync. |
| Person | Sign in, and see who the server thinks they are. | `aerolvm login` (browser or device flow against the provider), `aerolvm whoami`, and the dashboard at `/ui`. Only admins and the operator get the dashboard's console; every other role gets a signed-in screen with a CLI pointer. |
| API client | Create, list, start, stop, and destroy a sandbox. Set env, tags, and resource limits. | `POST/GET /v1/sandboxes` and the per-sandbox lifecycle routes, within the caller's role and team. The Daytona (`/daytona`), E2B (`/e2b`) and Runloop (`/runloop`) facades call the same service layer with the same permission checks. |
| API client | Run a command, open a PTY session, and read or write files. | The API forwards to `toolboxd` inside the sandbox. Needs `sandbox.exec` (`runner` or `admin`); a viewer cannot read files, since files can hold secrets. |
| API client | Publish an HTTP preview or a TCP/TLS port. Take and restore a snapshot. Attach external storage. | The service layer records the intent in SQLite and programs Caddy, the runtime, or the mount manager. |
| API client | Read capacity and the audit log. | `GET /v1/capacity`, `GET /v1/sandboxes/{id}/audit` (with a `caller` filter). `aerolvm audit search` and `aerolvm access review` read an exported, verified copy instead. |
| Auditor | Read every team's sandboxes and audit records, list tokens, and verify the audit chain. | The same read routes, fleet-wide, plus `GET /v1/tokens` and `POST /v1/audit/verify`. |
| MCP client | Create sandboxes, run commands, read and write files, and publish ports, through MCP tools. A pinned server reaches only its one sandbox. | `aerolvm mcp` calls the v1 API like any SDK. With `SB_MCP_ENABLED=true`, `/mcp` on `sandboxd` serves the same tools. It authenticates the caller once and hands the resolved access to each in-process API call, so each tool call is checked by its route's own permission and writes its own audit record. An OAuth connector discovers the issuer from `/.well-known/oauth-protected-resource`. No MCP tool reads or writes the client's machine. |
| Identity provider | Log people in and sign tokens. Publish signing keys. | The provider itself. Each node verifies every token offline against the provider's published keys; `sandboxd` hosts no login service and keeps no session. |
| Sandbox guest | Compute, open outbound connections, and use the files and mounts it was given. | The runtime: containerd (default), gVisor, Firecracker, WASM, or the V8 isolate. |
| Sandbox guest | Ask the host to run a process, touch the filesystem, or record session output. | `toolboxd`, which the daemon placed in that sandbox. The guest does not talk to Caddy's admin socket or to SQLite. |
| Preview or TCP client | Open the published HTTP or TCP service. | Caddy routes `<sandbox-id>.<domain>` (HTTP) or `<sandbox-id>-<port>.<domain>` (TCP) to the sandbox. |
| SSH client | Open a shell in one sandbox. | The SSH gateway checks the per-sandbox Ed25519 key and connects only to that sandbox. |
| Cluster peer | Replicate placement and API tokens, exchange membership and capacity, and forward an API call to the node that owns the sandbox. | Raft for placement and token state, SWIM for membership, and the cross-node HTTP proxy. Workers and ingress nodes keep an in-memory token mirror polled from the server tier. A node that is not the owner does not apply the mutation locally; the owner re-checks the caller's credential and records the call, with the edge node as `via`. |
| External storage | Serve the objects or files the mount names. | The host mount manager. The guest sees the mounted tree. The remote service never receives an API credential. |

Every API call that changes something, every toolbox call, and every refused call writes one hash-chained `api` (or `auth_denied`) record naming the caller, on the node that ran it. The daemon's own destructive work (lifecycle stops and deletes, the reconcile reap, the orphan delete) is recorded with `caller: system:<subsystem>`.

SQLite (WAL, one writer in the daemon) stores sandbox rows, exposed-port intents, the TCP host-port pool, sealed secrets, and, on a single node, the hashed API tokens. It is not an actor. No other process opens that database.
