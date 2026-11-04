# Runbook: Remote MCP

Use this when agents connected to sandboxd's remote MCP endpoint (`/mcp`)
report failures, when `SandboxdRemoteMCPErrorRate` fires, or when you set up
or re-check an OAuth connector (claude.ai, ChatGPT; see
[OAuth connectors](#oauth-connectors-claudeai-chatgpt)).

The endpoint is off unless `SB_MCP_ENABLED=true`. It is stateless: each
request names one sandbox in `?sandbox=` and authenticates once, with the
bearer in the `Authorization` header. Its tools then call the v1 API
in-process as that same caller: each call is authorized by its own route's
permission and writes its own audit record (surface `mcp`). So almost every
failure is an ordinary API failure seen through MCP. Design:
`plans/mcp-server-and-agent-cli.md` §5.7, and for OAuth
`plans/identity-and-access.md` §5.14.

## Alerts

- `SandboxdRemoteMCPErrorRate`: over 20% of tool calls ended in
  `api_error` for 10 minutes.

## Severity

| Severity | Criteria |
|---|---|
| SEV-2 | Most remote tool calls fail across tenants (platform failure). |
| SEV-3 | One tool, one tenant or one sandbox fails; others work. |

## First Checks

1. Open the "Remote MCP" row of the sandboxd SLOs dashboard. The outcome
   panel separates `ok`, `tool_error` (the model can fix it: not found,
   bad argument, edit conflict), `api_error` (the platform failed) and
   `unauthorized`.
2. Find the failing calls in the logs. Each tool call writes one line with
   the tool, sandbox, owner, outcome, error code and duration, never the
   arguments or output:

   ```bash
   sudo journalctl -u sandboxd --since "30 minutes ago" --no-pager \
     | grep '"mcp tool call"' | grep '"outcome":"api_error"'
   ```

3. Group by `code`:

| Code | Likely cause | Next step |
|---|---|---|
| `unavailable` | owner node unreachable, failover in progress, 503 from capacity | check cluster health; the same calls fail on `/v1` |
| `unreachable` | the API handler could not reach a peer | check cluster mTLS and membership |
| `timeout` | slow toolbox or a long `exec` | check `duration_ms`; `exec` defaults to 300 s |
| `internal` | toolbox or API 5xx | read the sandboxd error lines around the call |

4. Reproduce outside MCP with the same token. Remote tool calls are API
   calls, so the CLI shows the same failure with more detail:

   ```bash
   aerolvm get <sandbox> --debug
   aerolvm exec <sandbox> -- true
   ```

## Request-Level Refusals

`aerolvm_mcp_requests_total` counts requests refused before any tool ran:

| Key | Meaning |
|---|---|
| `bad_request` | a query parameter is invalid; the 400 body names it |
| `unauthorized` | missing or wrong token |
| `rate_limited` | the token passed `SB_MCP_RATE_LIMIT` (per token, burst 2x) |
| `forbidden_origin` | a browser page sent an `Origin` not in `SB_MCP_ALLOWED_ORIGINS` |
| `forbidden_host` | the `Host` is not in `SB_MCP_ALLOWED_HOSTS` |

A burst of `forbidden_origin` from one source is a DNS-rebinding or
cross-site attempt; the endpoint refuses it before authentication, so
nothing leaked.

With OAuth connectors configured, some `unauthorized` is normal: a
connector's first request carries no token, and that 401 is how it learns
where to sign in.

## OAuth connectors (claude.ai, ChatGPT)

Hosted agent products connect to remote MCP servers through OAuth, not with
a pasted token. With identity on, sandboxd accepts the access tokens your
company's identity provider issues for `/mcp`. sandboxd stays a resource
server: the provider does the sign-in, and every node checks each token
offline. sandboxd hosts no authorization or client-registration endpoint.

How a connector signs in:

1. Its first request to `/mcp` has no token. The 401 carries
   `WWW-Authenticate: Bearer resource_metadata="https://<domain>/.well-known/oauth-protected-resource/mcp"`
   (plus `scope="…"` when the identity file lists scopes).
2. It reads that RFC 9728 document: the `/mcp` resource URL, the identity
   providers that may sign people in (`authorization_servers`), and the
   scopes to ask for.
3. It signs the person in at the provider with the client you registered
   there, and gets a JWT access token whose `aud` is one of the issuer's
   `mcp_audiences`.
4. sandboxd verifies it like an ID token (signature, issuer, expiry,
   lifetime cap, deny list), then applies your bindings unchanged.

That access token works only on `/mcp`. On `/v1`, the dashboard and every
facade it gets `401` with reason `wrong_audience`, by design. Tool calls still
reach `/v1` routes, because `/mcp` hands its verified caller to them
in-process. A tool call on a sandbox another node owns is forwarded with the
caller's token and the `X-Cluster-Surface: mcp` marker, and the owner checks
the token itself.

### Before you start

- `SB_IDENTITY_ENABLED=true`, an identity file (`SB_IDENTITY_FILE`), and
  `SB_MCP_ENABLED=true` on every node.
- A domain install: Caddy forwards `/mcp` and
  `/.well-known/oauth-protected-resource*` to sandboxd (both are in the
  stock `@api` matcher).
- In a cluster, every node runs a build with OAuth for remote MCP before you
  add `mcp_audiences` or the `mcp:` section. A node without it refuses the
  forwarded access token (`wrong_audience`), so tool calls on sandboxes it
  owns fail.
- Google cannot be used: its access tokens are opaque, and checking one
  would need a call to Google per request. The identity file refuses
  `mcp: true` on a `kind: google` issuer.
- Authentik cannot be used yet. Its access tokens are JWTs, but each names
  only its own application's client id as `aud`, and each Authentik
  application is its own issuer. sandboxd tells an MCP-only access token
  from an ID token by audience alone, so the connector's tokens need an
  audience that the same issuer's ID tokens never carry, and Authentik has
  no setting for a custom access-token audience.

### The identity file

```yaml
version: 1
issuers:
  - name: okta
    url: https://acme.okta.com/oauth2/aus1mcp      # the authorization server's issuer
    audiences: [0oa1cli]                           # ID tokens (CLI, dashboard)
    claims: { username: email, groups: groups }
    mcp: true                                      # listed in the RFC 9728 document
    mcp_audiences: [api://aerolvm-mcp]             # access tokens, accepted only on /mcp
bindings:
  - { issuer: okta, group: payments-eng, role: runner, team: payments }
mcp:
  resource: https://api.acme.dev/mcp               # https://<SB_DOMAIN>/mcp; the path must be /mcp
  scopes: [api://aerolvm-mcp/mcp]                  # optional; Entra and Zitadel need one
```

- `mcp_audiences` must not overlap `audiences`; the load fails if they do.
  That is how an access token is told apart from an ID token.
- An issuer with `mcp_audiences` but no `mcp: true` still has its access
  tokens accepted on `/mcp`; `mcp: true` only lists it in the document.
- `mcp.scopes` goes into `scopes_supported` and the 401's `scope`. It does
  not change which tokens are accepted.
- Bindings match the access token's claims. Make sure the provider puts the
  claims your bindings use (groups, app roles) into access tokens, not only
  into ID tokens.

Check the result: open `https://<domain>/.well-known/oauth-protected-resource/mcp`
in a browser. It lists your resource URL, your `mcp: true` issuers and your
scopes. A 404 means no `mcp.resource` is in force (or identity or remote MCP
is off).

### Provider setup

Register the connector at your provider as an OAuth client. Copy the
redirect (callback) URL from the connector's own settings page, and record
it in the verification log below. These steps are what the live check
follows; the docs claim a provider and connector only after a run passes.

**Okta** (a custom authorization server; the org server issues opaque
access tokens):

1. Security → API → Authorization Servers: add one (or use `default`). Set
   its Audience to the value you put in `mcp_audiences` (for example
   `api://aerolvm-mcp`). Its Issuer URI is the issuer's `url`.
2. Add a scope (for example `mcp`) and an access policy with a rule that
   allows the authorization-code grant for the connector's client.
3. Claims: add a `groups` claim to the access token (filter to your AerolVM
   groups), so group bindings match.
4. Applications: create a web application for the connector with the
   authorization-code grant, PKCE, and the connector's redirect URL. Give
   its client id (and secret, if the connector asks for one) to the
   connector.

**Entra ID:**

1. App registrations: register an API app. In Expose an API, set the
   Application ID URI and add a scope (for example `mcp`). Put
   `<Application ID URI>/mcp` in `mcp.scopes`.
2. In the API app's manifest set `"accessTokenAcceptedVersion": 2`. Without
   it Entra issues v1 tokens (`iss` = `https://sts.windows.net/<tenant>/`),
   which sandboxd refuses with the hint "set accessTokenAcceptedVersion: 2
   on the API app".
3. `mcp_audiences` is the API app's Application (client) id: that is the
   `aud` of a v2 access token. The issuer's `url` is
   `https://login.microsoftonline.com/<tenant>/v2.0`.
4. Token configuration: add the groups claim for access tokens, or bind on
   app roles (`app_role:` bindings match the `roles` claim). Above 200
   groups Entra leaves the groups out, and sandboxd refuses with
   `group_overage`.
5. Register the connector as a second app (web platform, the connector's
   redirect URL, a client secret if the connector asks for one), add an API
   permission for the scope, and grant admin consent.
6. Connectors send the RFC 8707 `resource` parameter (the `/mcp` URL).
   Whether Entra accepts it next to the scope is one of the things the live
   check records; if it is refused, try setting the API app's Application
   ID URI to the `/mcp` URL.
7. Entra's `sub` is per application, so the same person has one principal
   id through the CLI app and another through the API app. The display name
   (and the binding) is the same.

**Keycloak:**

1. Create a client for the connector: standard flow, PKCE, the connector's
   redirect URL.
2. Add an Audience mapper (to a client scope the connector gets, or to the
   client) that puts your `mcp_audiences` value into access tokens: set
   "Included Custom Audience" to it, "Add to access token" on and "Add to
   ID token" off.
3. Add a Group Membership mapper with the claim name `groups`, "Add to
   access token" on and "Full group path" off, so group bindings match.
   Full group path is on by default and sends `/platform-admins`; then no
   `group: platform-admins` binding matches (or write the binding with the
   slash, `group: /platform-admins`). The connector's client needs this
   mapper too, not only the CLI and dashboard clients.
4. The issuer's `url` is `https://<keycloak>/realms/<realm>`. Set Keycloak's
   `hostname` option (`KC_HOSTNAME`) to that public address, so the `iss`
   in its tokens is the same for every node and for the connector.

**Zitadel** (not yet tested against a live tenant; these steps follow
Zitadel's documentation):

1. Create a project for the connector alone, for example `AerolVM MCP`.
   Do not add the connector to the project of the CLI and dashboard apps.
   Zitadel puts the client id of every app in a project into the `aud` of
   every token that project issues, so a connector token from the CLI's
   project would name the CLI app, and sandboxd would accept it on `/v1`
   too.
2. In that project, turn on Assert Roles on Authentication. Create the same
   role keys as in the CLI's project and grant them to the same people:
   Zitadel puts only a project's own roles into its tokens.
3. Add the connector as a Web app in that project: the code flow, the
   connector's redirect URL, and PKCE or a client secret, whichever the
   connector uses. Set its Auth Token Type to JWT. The default, Bearer, is
   an opaque token that sandboxd cannot check.
4. `mcp_audiences` is that project's id, which is in the `aud` of every
   token the project issues. The issuer's `url` is the same instance URL
   the CLI and dashboard use, so it is the same identity-file issuer.
5. Add the `groupsClaim` Action ("Zitadel roles as groups" in
   [SSO](../../docs/src/content/docs/enterprise/sso.mdx))
   to the Complement Token flow's Pre access token creation trigger too, so
   access tokens carry `groups`. Actions run from each person's own
   organization, whichever project the app is in.
6. Set `mcp.scopes: [openid]`. Zitadel refuses a sign-in request that names
   no scope, and a connector asks for the scopes the RFC 9728 document
   lists.
7. Zitadel's access tokens carry no name or email, so the display name of
   an MCP call is the person's Zitadel user id. Their principal id
   (`oidc:<issuer>:<sub>`) is the same as through the CLI.

### Live connector check

Run it once per provider and connector after setup, after a provider or
connector change, and before the docs claim a new combination. It needs a
real person's account at the provider, so it is manual.

1. Add the connector: the `/mcp` URL with a pinned sandbox, for example
   `https://api.acme.dev/mcp?sandbox=agent-scratch`, and the client from
   Provider setup.
2. Sign in when the connector asks. Expect the provider's own sign-in page.
3. The connector lists the tools (`exec`, `read_file`, …). Run `exec` with
   `echo hello`.
4. Check the evidence: the sandbox's audit records (or
   `aerolvm audit search --since 1h --caller oidc:<issuer>:<sub>` with your
   `--export` or `--export-dir`) show one `api` record for that call, naming
   the person, with `surface: mcp`. In a cluster, repeat with a sandbox
   another node owns: the record is on the owner, with `via` naming the edge.
5. Take the access token out of the picture: the same person's token sent to
   `/v1` is refused with `wrong_audience` (the connector never does this; it
   proves the token is MCP-only). Skip this if the connector does not let
   you see its token.
6. Record the run below, with the date, the provider, the connector, the
   redirect URL, and what failed if anything did.

| Date | Provider | Connector | Result | Notes |
|---|---|---|---|---|
| — | Okta | claude.ai | not yet run | |
| — | Okta | ChatGPT | not yet run | ChatGPT's support for a pre-registered client is unconfirmed |
| — | Entra ID | claude.ai | not yet run | |
| — | Entra ID | ChatGPT | not yet run | |
| — | Keycloak | claude.ai | not yet run | |
| — | Keycloak | ChatGPT | not yet run | |
| — | Zitadel | claude.ai | not yet run | |
| — | Zitadel | ChatGPT | not yet run | |

### OAuth troubleshooting

| What the connector or log shows | Likely cause | Next step |
|---|---|---|
| No sign-in prompt; the connector says the server needs no auth or can't find one | The 401 has no `resource_metadata`: identity off, no `mcp.resource`, or the file failed to load | Open the metadata URL; check `aerolvm_identity_file_load_errors_total` and the boot log |
| 401 `wrong_audience` on `/mcp` | The token's `aud` is not in `audiences` or `mcp_audiences` | Okta: the authorization server's Audience. Entra: the API app's client id. Keycloak: the Audience mapper. Zitadel: the connector project's id |
| 401 `unknown_issuer`, body "Entra issued a v1 access token…" | The API app still issues v1 tokens | Set `accessTokenAcceptedVersion: 2` in its manifest |
| 401 `unknown_issuer` | The token's `iss` is not an issuer `url`, byte for byte | Copy the issuer from the provider's discovery document |
| 401 with no reason | The token is not a JWT (opaque): Google, Okta's org authorization server, or a Zitadel app left on the Bearer token type | Okta: use a custom authorization server. Zitadel: set the connector app's Auth Token Type to JWT. Google is not supported |
| The provider refuses the sign-in because the scope is missing (Zitadel) | No `mcp.scopes`, so the connector asked for no scope | Set `mcp.scopes: [openid]` |
| 403 "no role binding … through issuer …" | The access token lacks the claims your bindings match | Add groups (or app roles) to access tokens at the provider |
| 401 `wrong_audience` on `/v1` | A connector token used outside `/mcp` | Expected; people use the CLI or dashboard sign-in for `/v1` |
| Tool calls on one node's sandboxes fail with `unauthorized`, others work | That node runs a build without OAuth for remote MCP | Upgrade it (see Before you start) |
| Every tool call fails with "a remote MCP tool call reached the API without its caller" (HTTP 500) | A sandboxd bug: the in-process hand-off was lost. `aerolvm_auth_failures_total{key="mcp_handoff"}` counts it | Turn off `SB_MCP_ENABLED` and report it; the API refuses rather than run the call as anyone else |

## Turning It Off

Set `SB_MCP_ENABLED=false` and restart sandboxd. `/mcp` then answers 404.
Nothing else depends on it, and sandboxes created through it keep their idle
lifecycle (stop after 30 minutes, destroy after 24 hours).
