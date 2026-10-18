# Runbook: Identity and access

Use this when a `SandboxdBreakGlassPATUse`, `SandboxdPATScopeDrift`,
`SandboxdIdentity*` alert fires, when people or CI get unexpected 401, 403 or
503 answers, or when you rotate the operator token (PAT), the Prometheus
scrape token, or turn on `SB_PAT_SCOPE=host`. Design:
`plans/identity-and-access.md`.

sandboxd knows four kinds of caller:

- **The operator token (PAT)**, `SB_PAT_TOKEN`. Full power. Nodes also use it
  to call each other. It is the break-glass credential.
- **API tokens** (`avm_…`), minted by an admin with `aerolvm token create`.
  Every node checks them against an in-memory copy of the token list. Worker
  and ingress nodes keep that copy (the "mirror") fresh by polling the Raft
  servers every 5 seconds.
- **SSO tokens** from the company's identity provider, checked on each node
  with the provider's published signing keys (the JWKS) and the role
  bindings in the identity file (`SB_IDENTITY_FILE`).
- **A managed control plane's tokens** (managed build only).

Nothing here runs a login service or keeps sessions. Every check is local to
the node that serves the request.

## Alerts

| Alert | Meaning |
|---|---|
| `SandboxdBreakGlassPATUse` | The PAT was used, or tried, from outside the host and the cluster. |
| `SandboxdPATScopeDrift` | Nodes disagree on `SB_PAT_SCOPE`. |
| `SandboxdIdentityMirrorStale` | A node's API token list is more than 30 seconds old. |
| `SandboxdIdentityMirrorRefusingTokens` | A node's token list is more than 60 seconds old, so it refuses API tokens. |
| `SandboxdIdentityJWKSFailing` | A provider's signing keys could not be fetched for 15 minutes. |
| `SandboxdIdentityFileDrift` | Nodes run different identity files. |
| `SandboxdIdentityFileLoadErrors` | An identity file did not load. |

## Severity

| Severity | Criteria |
|---|---|
| SEV-2 | `SandboxdIdentityMirrorRefusingTokens` on many nodes (CI and services are locked out), a leaked PAT, or a leaked provider signing key ([KeyCompromise](#keycompromise)). |
| SEV-3 | One node refuses tokens, JWKS failing for one issuer, or a scope or identity-file drift. |
| SEV-4 | A single break-glass use you can explain, or a rejected identity-file edit. |

## Metrics

Read them from `GET /v1/metrics` on the node (see the README's standard
evidence commands) or from the "Identity and access" row of the D9 Security
& Isolation dashboard (`setup/grafana/d9-security-isolation.json`). The maps
have positional labels: `key`, then `key2`.

| Metric | Meaning |
|---|---|
| `aerolvm_auth_requests_total{key=<kind>,key2=<origin>}` | Accepted credentials. kind: operator, node, token, oidc, controlplane. origin: host (loopback), peer (mTLS cluster peer), public. |
| `aerolvm_auth_failures_total{key=<kind>,key2=<reason>}` | Refused credentials. `pat_scope` and `pat_origin` are PATs refused by `SB_PAT_SCOPE=host`; `stale` is a stale token list (503). |
| `aerolvm_auth_client_ip_dropped_total` | `X-AerolVM-Client-IP` headers ignored because they did not come from Caddy. |
| `aerolvm_pat_scope_drift` | Live members whose `SB_PAT_SCOPE` differs from this node's. |
| `aerolvm_identity_mirror_age_seconds` | Age of this node's token list (0 on Raft servers and single nodes). |
| `aerolvm_identity_stale_accept_total` | Metrics scrapes accepted from a stale token list (by design). |
| `aerolvm_identity_jwks_fetch_total{key=<issuer>,key2=<result>}` | Signing-key fetches: ok, error, too_large. |
| `aerolvm_identity_jwks_last_success_timestamp{key=<issuer>}` | Unix time of the last good fetch. |
| `aerolvm_identity_file_info{key=<sha256>}` | The identity file in force; more than one hash across nodes is drift. |
| `aerolvm_identity_file_load_errors_total` | Identity files that did not validate. |
| `aerolvm_api_tokens{key=<role>}` | Unexpired API tokens by role (Raft servers and single nodes). |
| `aerolvm_audit_api_records_total{key=<result>}` | `api` audit records written. |

## BreakGlassPATUse

The PAT was accepted from a public origin (only possible under the default
`SB_PAT_SCOPE=any`), or refused because `SB_PAT_SCOPE=host` is on.

1. Find the caller. The `auth_denied` records (refused PATs) and the `api`
   records (accepted ones, `caller.kind: operator`) carry the source address:
   `aerolvm audit search --export s3://<bucket>/<prefix> --caller operator --since 1h`
   (or `--export-dir <dir>` for a local copy).
   Under scope `any`, the address is the real client only with
   `SB_L4_FALLBACK_PROXY_PROTOCOL=true`; otherwise Caddy's traffic shows as
   127.0.0.1 and counts as host, not public.
2. If it is a known tool (a remote script, a Prometheus scrape, the
   dashboard), move it to a named token or SSO. For the scrape, see
   [RotateScrapeToken](#rotatescrapetoken).
3. If you cannot explain it, treat the PAT as leaked: [RotatePAT](#rotatepat),
   then turn on [host scope](#turnonhostscope).

## PATScopeDrift

One or more nodes run a different `SB_PAT_SCOPE`. A node left on `any`
accepts the PAT from anywhere, and owners on `host` refuse the PAT calls it
forwards (`aerolvm_auth_failures_total{key="operator",key2="pat_origin"}`).

1. Find the odd node: the drift gauge is above 0 on every node, so compare
   `SB_PAT_SCOPE` in `/etc/sandboxd/sandboxd.env` across nodes.
2. Set the same value everywhere through Terraform or Ansible, and re-run
   install.sh with the same `--pat-scope` on the odd node (Caddy's upstream
   must match); the re-run restarts it. Read [Re-running install.sh](#re-running-installsh)
   first: the re-run rewrites the node's settings file.

## MirrorStale

A worker or ingress node could not sync its API token list from the Raft
servers. At 30 seconds it warns. At 60 seconds (`SB_IDENTITY_MAX_STALE`) it
answers every API token with `503 identity data is stale on this node`, except
metrics scrapes, which keep working. SSO and the PAT are not affected.

1. Check the server tier: `GET /v1/cluster/leader` and `/v1/cluster/members`.
   A server tier that is down already blocks creates; fix that first
   (`lost-quorum-recovery.md`).
2. Check this node can reach a server over mTLS (port 7002):
   `journalctl -u sandboxd | grep 'token mirror'` shows each failed sync
   with its error.
3. It recovers by itself within one poll once a server answers. A revoked
   token stays usable for metrics only until then.

## JWKSFailing

The node could not fetch an issuer's signing keys for 15 minutes. Tokens
signed with a key it already has still work. A token with a new key id
(after the provider rotates keys), or any token on a node that never got the
keys, gets `503` "sign-in with an identity provider is unavailable on this
server right now".

1. From the node, check the issuer's discovery URL and `jwks_uri` resolve and
   answer over HTTPS (proxy, firewall, DNS, an expired internal CA).
2. `key2="too_large"` means the key set is over the size cap: check you
   pointed the issuer at the right URL.
3. While it is down, people can use an API token. See
   [ProviderOutage](#provideroutage).

## KeyCompromise

A provider's signing key leaked, or the provider withdrew a key it no longer
trusts. Each node keeps the keys it fetched, so a key the provider removed
stays trusted on that node until the node fetches again: at the hourly
refresh, or when a token with a key id it doesn't know arrives (at most once
a minute per issuer). A `SIGHUP` or an identity-file reload does **not**
fetch keys again while the issuer's `url` and `jwks_file` stay the same.

1. Remove the key at the provider first, so it signs nothing new.
2. **Issuer read from discovery:** restart sandboxd on every node, one at a
   time (`systemctl restart sandboxd`). Each node fetches the provider's
   current keys as it starts.
3. **Issuer with `jwks_file`:** write the new key set to a **new** file, point
   `jwks_file` at it in the identity file, push the file to every node and
   wait one poll (or send `SIGHUP`). A changed `jwks_file` path is a new key
   source, which each node loads at once. Rewriting the old file in place is
   picked up only at the next hourly refresh.
4. Check each node: `aerolvm_identity_jwks_fetch_total{key=<issuer>,key2="ok"}`
   went up, and a token signed with the removed key gets `401` with reason
   `invalid_signature`.
5. People whose sign-in was signed with the removed key get `401` and sign
   in again; the CLI and the dashboard tell them how.

## IdentityFileDrift

Nodes run different identity files, so one person can get a different role
depending on which node serves the request.

1. Compare the `key` (file hash) of `aerolvm_identity_file_info` per node.
2. Ship one file to every node (Terraform or Ansible) and wait one poll, or
   send `SIGHUP` to sandboxd. Each change writes an `identity_config` audit
   record with the binding diff.

## IdentityFileLoadErrors

An identity file did not validate. A running node keeps its last good file.
A node that booted with a bad file answers SSO with 503 until it is fixed;
API tokens and the PAT still work.

1. `journalctl -u sandboxd | grep 'identity file'` shows the "identity file
   invalid" line with the error.
2. Fix the file, then wait one poll or send `SIGHUP`.

## RotatePAT

The PAT can be rotated without downtime. Nodes always send the current PAT
and accept both during the rollout.

0. **Pin the operator volume scope first.** Operator platform volumes live
   under a path derived from the PAT. Boot logs it as
   `operator volume scope scope=op-… pinned=false`. Set
   `SB_OPERATOR_VOLUME_SCOPE=<that value>` on every node and restart in
   turn. sandboxd refuses to boot with `SB_PAT_TOKEN_PREVIOUS` set and the
   scope unpinned while platform volumes are on, and prints the value to pin.
1. On every node set `SB_PAT_TOKEN=<new>` and `SB_PAT_TOKEN_PREVIOUS=<old>`,
   then restart one node at a time. Old and new both work everywhere.
2. Move every client (scripts, `config/secrets.yml` `cluster.pat_token`,
   CI secrets) to the new PAT.
3. Remove `SB_PAT_TOKEN_PREVIOUS` from every node and restart in turn. The old
   PAT stops working.

## RotateScrapeToken

The Prometheus scrape on the obs host uses `cluster.metrics_token` from
`config/secrets.yml` when it is set, and the PAT otherwise. Under
`SB_PAT_SCOPE=host` it must be set, because the PAT is refused from the obs
host. The token is a `viewer` bound to every team: it can read metrics and
nothing that changes anything.

1. On any node, with the PAT, on the host:

   ```bash
   SB_API_URL=http://127.0.0.1:21212 SB_PAT_TOKEN=<pat> \
     aerolvm token create --name prometheus-2 --role viewer --team '*' --expires-in 90d
   ```

2. Put the new `avm_…` value in `cluster.metrics_token` and re-apply
   Terraform. Check the D9 panels still fill.
3. Revoke the old one: `aerolvm token revoke <tok_id>`. `aerolvm token list`
   shows every token with its expiry; rotate before it expires, or the scrape
   gets 401 and the D9 panels go empty.

## FirstAdminToken

In enterprise mode with tokens only (identity on, no identity file) and
`SB_PAT_SCOPE=host`, the first `admin` token can only be minted with the PAT
from a node:

```bash
SB_API_URL=http://127.0.0.1:21212 SB_PAT_TOKEN=<pat> \
  aerolvm token create --name first-admin --role admin --team '*' --expires-in 30d
```

Give it to the admin, who then mints everyone else's tokens.

## ProviderOutage

The identity provider is down. Issued SSO tokens work until they expire
(about an hour); new sign-ins fail. API tokens and the PAT are not affected.

- People who need access now can use an API token an admin mints.
- If no admin token exists and the PAT is confined to the host: SSH to a
  node and use `http://127.0.0.1:21212` with the PAT (break-glass). Outside
  enterprise mode you may also set `SB_PAT_SCOPE=any` and restart, then set
  it back.

## ProxyProtocolMismatch

`SB_L4_FALLBACK_PROXY_PROTOCOL=true` makes caddy-l4 send a PROXY v2 header
to the HTTPS site on 127.0.0.1:8443. The site must run the `proxy_protocol`
listener wrapper that install.sh writes with `--l4-proxy-protocol`. With the
flag on and no wrapper (a hand-edited Caddyfile), every public HTTPS
handshake fails.

1. Boot logs the flag: `journalctl -u sandboxd | grep 'PROXY protocol v2'`.
2. Check `/etc/caddy/Caddyfile` has a `servers 127.0.0.1:8443` block with
   `listener_wrappers { proxy_protocol { allow 127.0.0.1/32 } tls }`.
3. Fix: re-run install.sh with `--l4-proxy-protocol` (see
   [Re-running install.sh](#re-running-installsh)), or set
   `SB_L4_FALLBACK_PROXY_PROTOCOL=false` and restart sandboxd.
4. To turn it off for good: set the flag false and restart sandboxd
   **before** removing the wrapper. The wrapper accepts connections with or
   without a header, so this order never breaks HTTPS.

## TurnOnHostScope

`SB_PAT_SCOPE=host` accepts the PAT only from a loopback peer on port 21212
and from cluster peers, so remote people must use SSO or a named token.
Enterprise mode requires it.

1. Upgrade every node to this release first. Owners on `host` refuse a
   forwarded PAT call that does not say where it came from, which older
   nodes never say.
2. Move remote PAT users to named tokens or SSO: the dashboard, remote MCP,
   remote SDK scripts, and the Prometheus scrape
   ([RotateScrapeToken](#rotatescrapetoken)).
3. On every node re-run install.sh with `--pat-scope host` (optionally with
   `--l4-proxy-protocol`), following [Re-running install.sh](#re-running-installsh):
   move the settings you added by hand (`SB_IDENTITY_ENABLED`,
   `SB_ENTERPRISE_MODE` and the rest) into `/etc/sandboxd/local.env` first,
   then pass every original flag and the current `--pat-token`. The re-run
   sets `SB_PAT_SCOPE=host`, restarts sandboxd, waits for the public socket
   `/run/sandboxd-public/api.sock`, and only then starts Caddy on it. Any
   other reverse proxy on the host must use that socket too.
4. Check: `stat /run/sandboxd-public /run/sandboxd-public/api.sock` shows
   `root:caddy`, `drwxr-x---` and `srw-rw----`. sandboxd refuses to boot if
   it cannot make them. A PAT through the public domain now gets 401 "the
   operator token works only on this host"; the setup scripts on the host
   keep working.

Rollback, step by step: set `SB_PAT_SCOPE=any` (refused in enterprise mode)
and re-run install.sh with `--pat-scope any` so Caddy goes back to
`127.0.0.1:21212` (the same [re-run rules](#re-running-installsh) apply);
then, if needed, `SB_IDENTITY_ENABLED=false` and restart.
Undo PROXY protocol as in [ProxyProtocolMismatch](#proxyprotocolmismatch),
step 4.

## Re-running install.sh

Several steps above re-run `scripts/install.sh` on a node that is already
installed. On Linux a re-run does three things that are easy to miss:

- **It rewrites `/etc/sandboxd/sandboxd.env` from scratch** (`write_environment`
  starts with `cat >`). Nothing from the old file is kept: the new file holds
  only the defaults and what this run's flags produce. Every setting you
  added by hand is gone, including `SB_IDENTITY_ENABLED`, `SB_IDENTITY_FILE`,
  `SB_ENTERPRISE_MODE`, `SB_NODE_ID`, the audit export and witness settings,
  `SB_OPERATOR_VOLUME_SCOPE` and `SB_PAT_TOKEN_PREVIOUS`. With
  `SB_ENTERPRISE_MODE` gone the node boots outside enterprise mode; with
  `SB_IDENTITY_ENABLED` gone it refuses every API token and SSO sign-in.
- **Without `--pat-token` it makes a new random PAT** (`openssl rand -hex 24`),
  and every client and peer still holding the old one is refused.
- **It restarts a running sandboxd when it changed the settings file or
  the unit** (`restart_sandboxd_if_reconfigured`), so the restart happens
  during the run, with whatever the new file holds. It runs before Caddy
  starts, and waits until sandboxd answers `/health` and, under
  `--pat-scope host`, has made `/run/sandboxd-public/api.sock`, so Caddy
  never proxies to a socket that is not there. A run that changes neither
  file leaves sandboxd running, even when it installed a new binary; restart
  it yourself after such an upgrade. A fresh install, or a stopped unit, is
  started as before.

So, on each node:

1. Keep the settings you added by hand out of the file the installer
   rewrites, once: put them in `/etc/sandboxd/local.env` and load it with a
   drop-in the installer never touches.

   ```bash
   sudo cp /etc/sandboxd/sandboxd.env /root/sandboxd.env.before
   # copy each line you added by hand (SB_IDENTITY_ENABLED, SB_ENTERPRISE_MODE, ...) into /etc/sandboxd/local.env
   sudo mkdir -p /etc/systemd/system/sandboxd.service.d
   printf '[Service]\nEnvironmentFile=/etc/sandboxd/local.env\n' | sudo tee /etc/systemd/system/sandboxd.service.d/local.conf
   sudo systemctl daemon-reload && sudo systemctl restart sandboxd
   ```

   A key in `local.env` wins over the same key in `sandboxd.env`.
2. Re-run install.sh with every flag the node was installed with, the
   current PAT (`--pat-token "$(sudo grep '^SB_PAT_TOKEN=' /root/sandboxd.env.before | cut -d= -f2-)"`),
   and the new flag (`--pat-scope host`, `--l4-proxy-protocol`, …). It
   restarts sandboxd if the settings changed and prints
   `sandboxd settings changed; restarting sandboxd before Caddy`.
3. Check `journalctl -u sandboxd` for a clean boot (enterprise mode names
   any rule that is missing). A warning that sandboxd is not answering
   means the restart did not come up within 60 s; the journal says why.

Clusters built with the project's Terraform set extra settings through its
`extra_sandboxd_env` variable (or a node's `sandboxd_env`); keep them there,
not only in the file on the node.

## Post-deploy checklist

First 5 minutes:

- `GET /v1/whoami` with the PAT, with an `avm_` token and with an SSO login:
  each names the principal and role you expect.
- `aerolvm audit verify`.
- `aerolvm_identity_mirror_age_seconds` under 10 on every node.
- `aerolvm_identity_jwks_last_success_timestamp` set for every issuer.
- One `identity_config` record per node.

First hour:

- No spike in `aerolvm_auth_failures_total` by reason.
- `aerolvm_audit_api_records_total` tracks request volume.
- No `rate_limited` records outside known floods.
