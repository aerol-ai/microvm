# Config defaults reference

Operator reference for every boolean feature flag in `internal/config/config.go`:
its default, and **why** it defaults the way it does. Use this when deciding
whether a flag is safe to flip on for a deployment, or when reviewing a proposal
to change a shipped default.

Snapshot as of 2026-08-11. When you change a default in `config.go`, update the
matching row here.

## The rule for flipping a default on

A `false` default becomes `true` only when it has **soaked** — proven in an
integration/bench run — and its blocker is gone. The canonical example is
`SB_NETRULES_BACKEND`, which stayed `exec` behind an explicit "default remains
exec until the netlink path soaks" note until it did, then flipped to `netlink`
(now the default). Nothing should be flipped blindly: the `false` flags below
are off for security, a hard external-config/hardware dependency, or because the
feature is still mid-rollout.

## Already on — no action
| Env var | Notes |
|---|---|
| `SB_AUTO_RECONCILE` | true |
| `SB_ENABLE_CADDY` | true |
| `SB_ENABLE_NETWORK_RULES` | true. Off (and on any non-Linux host) the docker, containerd and Firecracker runtimes have no firewall, so creates, starts and updates that ask for network policy are refused with `501 network_policy_unenforced`; WASM and isolate filter egress themselves and are unaffected. |
| `SB_NETRULES_BACKEND` | `netlink` (in-process nftables; `exec` = go-iptables fallback) |
| `SB_ENABLE_EVENT_MONITOR` | true. Also what ends a toolbox request (an exec, a file transfer, a session) the moment its container sandbox dies: the die/destroy event answers it 409 instead of leaving it to the connection timeout below. |
| `SB_TOOLBOX_DEAD_PEER_TIMEOUT` | `30s` — how long a toolbox connection (exec, file transfer, session, SSH-gateway shell) lives on once its sandbox stops answering without closing it, as a killed gVisor sandbox or Firecracker VM does. Keepalive probes start after 15s idle, every 5s, and the third unanswered one ends it; `TCP_USER_TIMEOUT` (Linux) 30s also bounds data the sandbox never acknowledges. A live sandbox's kernel answers the probes, so a command that runs for hours with no output is never cut. What it does cut is a sandbox that answers nothing for the whole bound while still existing: raise it if your sandboxes are paused (a gVisor or Firecracker snapshot) for longer. `0` = off (Go's default keepalive, about 2.5 minutes; about 15 minutes for unacknowledged data); otherwise at least `6s`, or the boot is refused. |
| `SB_ENABLE_SSH_GATEWAY` | true |
| `SB_LIVENESS_SOCKET` | `/run/sandboxd/live.sock` — the Unix socket (root `0600`) the install.sh watchdog (`sandboxd-healthcheck`) probes: `GET /livez` answers `200` with the phase (`booting`, `serving`, `stopping`) from its own listener, with no I/O and no lock, from the first moment of the boot. It is liveness only; `/health` stays the readiness check (store, engines, Caddy). The watchdog restarts sandboxd only after 3 failed liveness probes in a row of one daemon run over at least 90 s, never in the daemon's first 120 s and never while a start, stop or restart is under way. `off` closes the socket, and the watchdog then probes `/health` with the same rule. Must be absolute. |
| `SB_ENABLE_SERVERLESS` | true — wake path on out of the box |
| `SB_DOCKER_READY_SOCKET_ENABLED` | true |
| `SB_IMAGE_BUILD_GC_ENABLED` | true — both image janitors |
| `SB_WASM_MODULE_GC_ENABLED` | true |
| `SB_WASM_POOL_ENABLED` | true — warm-worker pool |
| `SB_FIRECRACKER_USE_JAILER` | true |
| `SB_FIRECRACKER_TEMPLATE_GC_ENABLED` | true |
| `SB_FIRECRACKER_SNAPSHOT_ENABLED` | true |
| `SB_FIRECRACKER_SNAPSHOT_VERIFY_ON_LOAD` | true |
| `SB_FIRECRACKER_OVERLAY_ENABLED` | true |
| `SB_SECRET_FANOUT_MIN_ACK_WAIT` | `2s` — sync wait on HA create for ≥1 peer ACK before return. Cluster mode requires a positive value; remaining peers stay async. |
| `SB_EGRESS_ATTRIBUTION_ENABLED` | true — host-mediated egress destinations (wasm + isolate) into audit JSONL; dial-path only, never create. Set false to disable. |
| `SB_EGRESS_FQDN_ENABLED` | true — hostname entries in `network_allow_out` (plans/egress-domain-filtering.md, CEO D25). Inert until a sandbox uses one: no per-sandbox state otherwise. Needs the `aerolvm-egress-gateway` unit for container runtimes; without it (or on a privileged node) hostname creates get 501. `false` refuses them everywhere. |
| `SB_EGRESS_PROCID_SOCKET` / `SB_EGRESS_GATEWAY_USER` | `/run/aerolvm/egress-procid.sock` / `aerolvm-egress` — sandboxd answers the gateway's executable lookups for per-binary rules on this socket, group-owned by and answering only the gateway's user (the gateway can't read sandbox `/proc` itself). The gateway reads the same `SB_EGRESS_PROCID_SOCKET`. Empty turns lookups off: covered flows are refused. |
| `SB_EGRESS_GATEWAY_SOCKET` | `/run/aerolvm/egress-gateway.sock` — sandboxd ↔ egress-gateway UDS, created root-owned 0600 by `aerolvm-egress-gateway.socket`. |
| `SB_EGRESS_DNS_PORT` / `SB_EGRESS_PROXY_PORT` (sandboxd) | 53054 / 15080 — the gateway's listener ports as sandboxd's node guard opens them to sandboxes. Set them in `sandboxd.env` too when `egress-gateway.env` changes them; until then the guard follows the ports the gateway reports it listens on (and logs the mismatch). 1-65535 and different, or the boot is refused. |
| `SB_TLS_ACME_CA` / `SB_TLS_ACME_CA_ROOT` | unset — ACME directory (https) and its root PEM for custom-domain certificates on a network with no route to Let's Encrypt (plans/egress-domain-filtering.md §5.10 PC-5). install.sh `--acme-ca` / `--acme-ca-root` set these and the Caddyfile's `acme_ca` / `acme_ca_root` for the wildcard certs. Re-read at every start; unset goes back to public ACME. |
| `SB_TLS_ISSUER` | `acme` — `internal` makes Caddy's own CA issue custom-domain certificates (labs); install.sh `--tls-issuer internal` also switches the wildcard sites to `tls internal`, with no DNS provider. |
| `SB_EGRESS_OPERATOR_FILE` | unset — the private-cloud operator file (default policy, ceiling, deny floor, internal zone, upstream proxy, control-port guard, org profiles, built-in profile switch); see `setup/runbooks/egress-gateway.md`. Unset keeps every default. An invalid file at boot refuses creates (503) until fixed. |
| `SB_EGRESS_PROFILE_APPLY_QPS` | 50 — sandboxes per second a node re-applies after an egress profile changes, so one profile edit can't flood the gateway and firewall (D21). |
| Egress gateway (`/etc/sandboxd/egress-gateway.env`) | `SB_EGRESS_DNS_PORT` 53054, `SB_EGRESS_PROXY_PORT` 15080, `SB_EGRESS_DNS_UPSTREAMS` (host resolver), `SB_EGRESS_DNS_QPS` 50 per sandbox, `SB_EGRESS_PROXY_MAX_CONNS` 16384 per node, `SB_EGRESS_PROXY_MAX_CONNS_PER_SANDBOX` 512, `SB_EGRESS_LEARNED_MAX` 512 per sandbox, `SB_EGRESS_AUDIT_BUFFER` 10000 events, `SB_EGRESS_INSPECT_MAX_BODY_BYTES` 268435456 (256 MiB, the largest request body to a host with an inspect rule; larger gets 413), `SB_EGRESS_STATE_DIR` `/var/lib/aerolvm-egress`, `SB_EGRESS_PEER_CGROUP` `sandboxd.service`. Sized for the 100k-sandbox fleet budget (plans/egress-domain-filtering.md §8.2). |

## 🔴 Must stay off — security / safety
| Env var | Why off is correct |
|---|---|
| `SB_ENTERPRISE_MODE` | Opt-in fail-fast profile; local development keeps its lightweight defaults. Production deployments should enable it. Requires an `SB_PAT_TOKEN` of at least 32 bytes, and named credentials for people (`plans/identity-and-access.md` §5.12): `SB_IDENTITY_ENABLED=true` (tokens-only is enough; an identity file is optional, so air-gapped installs work), `SB_PAT_SCOPE=host`, an `SB_TOKEN_MAX_TTL` of at most 90 days, `SB_AUDIT_API_RECORDS` not `off`, and `SB_AUDIT_API_DURABLE` not `false`. With an external `SB_SECRET_PROVIDER` it also requires `SB_SECRET_PROVIDER_STRICT_BOOT=true` and a hardware PKCS#11 slot, and `SB_CREDENTIAL_KEY_CUSTODY=wrapped` (plans/customer-key-custody.md §7, F2; the release before only warned). |
| `SB_CONTAINER_PRIVILEGED` | Privileged containers = sandbox escape. |
| `SB_CLUSTER_INSECURE_GOSSIP` | Disables gossip encryption. |
| `SB_CLUSTER_INSECURE_CREDENTIALS` | Disables credential protection. |
| `SB_RESOURCE_LIMITS_DISABLED` | *Disables* cgroup limits; `false` already = limits ON. |
| `SB_SANDBOX_PIDS_LIMIT` | Processes and threads per container sandbox; default `4096`, `0` = unlimited (refused in enterprise mode). A gVisor sandbox gets the cap inside gVisor, lowered to one per MiB of its memory (1024 for the default 1 GB), and a host cgroup limit of twice that plus 1024 for gVisor's own threads. |
| `SB_SANDBOX_INTERCONNECT` | `true` lets sandboxes on one server reach each other; default `false` (isolated, refused in enterprise mode). |
| `SB_SANDBOX_NODE_PORTS_ALLOW` | Extra ports of the server itself every sandbox on it may reach, such as `8080,5353/udp` (tcp when bare). Default empty: sandboxes are default-denied from their own server (the node guard, `AEROLVM-NODE` in INPUT), except the egress gateway's DNS and proxy ports (when the gateway runs), DNS on a server address the sandboxes' resolver names, and 80/443 on a server that serves ingress. No ranges. A control or host-service port (API, SSH gateway, Raft, gossip, cluster mTLS, host-port redirect, 22, 111) or the gateway's own port refuses the boot; any entry refuses it in enterprise mode. Logged at every boot. |
| `SB_DISK_LIMIT_CHECK_INTERVAL` | How often a container sandbox's writable layer is checked against its disk size; one past it is stopped. Default `15s`, `0` = off. |
| `SB_ALLOW_UNENFORCED_NETWORK_POLICY` | With the host firewall off, accepts network policy (block-all, address lists, hostname rules, byte caps) that nothing enforces: the sandbox runs unfiltered while GET shows the policy (with `egress_status: "unenforced"`). Local development only; boot logs a warning and every accepted sandbox logs one. Refused when `SB_ENTERPRISE_MODE=true`. `install.sh --local` does not set it. |

## Secret provider (SB_SECRET_PROVIDER)

| Env var | Default | Notes |
|---|---|---|
| `SB_SECRET_PROVIDER` | `local` | `local` \| `awskms` \| `vault` \| `pkcs11`. Off-state is `local` — never contacts a key store unless explicitly set. See `docs/.../cluster-secrets.mdx` and `docs/.../enterprise/key-custody.mdx`. |
| `SB_SECRET_AWS_KMS_KEY_ID` | (empty) | Required when `SB_SECRET_PROVIDER=awskms`. Set with another provider, the node still opens AWS KMS rows (step 1 of a provider switch). |
| `SB_SECRET_VAULT_ADDR` | (empty) | Vault or OpenBao URL. Required when `SB_SECRET_PROVIDER=vault`. `https`, or `http` only to loopback (a local `vault proxy`). Set with another provider, the node already opens vault rows. |
| `SB_SECRET_VAULT_KEY_NAME` | (empty) | Transit key name. Required with `SB_SECRET_VAULT_ADDR`. |
| `SB_SECRET_VAULT_TRANSIT_MOUNT` | `transit` | Transit mount path. |
| `SB_SECRET_VAULT_TOKEN_FILE` | (empty) | Token file written by Vault Agent auto-auth; re-read when it changes and once more after a 403. Empty means `SB_SECRET_VAULT_ADDR` is a local `vault proxy` that adds the token, so sandboxd holds none. `VAULT_TOKEN` is never read. The token may hold only `update` on the encrypt and decrypt paths: a token with `create`, `sudo` or `root` there stops the boot, because Transit would recreate a deleted key and undo a revoke. The hourly rewrap sweep also needs `read` on `<mount>/keys/<key>` to learn the latest version. |
| `SB_SECRET_VAULT_NAMESPACE` | (empty) | Vault Enterprise namespace (`X-Vault-Namespace`). |
| `SB_SECRET_VAULT_CACERT` | (empty) | PEM CA bundle for a private PKI. |
| `SB_SECRET_PKCS11_MODULE` | (empty) | Path to the HSM vendor's PKCS#11 `.so`. Required when `SB_SECRET_PROVIDER=pkcs11`. It loads only in the `sandboxd --pkcs11-helper` child process, never in sandboxd. Set with another provider, the node already opens p11 rows. |
| `SB_SECRET_PKCS11_TOKEN_LABEL` | (empty) | Token (partition) label; must match exactly one slot. |
| `SB_SECRET_PKCS11_PIN_FILE` | (empty) | User PIN file; refused if it has group or other permission bits (0400 or 0600 pass). |
| `SB_SECRET_PKCS11_KEY_LABEL` | (empty) | Label of the AES-256 key used for new wraps. |
| `SB_SECRET_PKCS11_DECRYPT_KEY_LABELS` | (empty) | Comma-separated older labels still allowed for unwrap during a rotation. |
| `SB_SECRET_PKCS11_GCM_IV` | `auto` | Who picks the AES-GCM IV: `auto` probes at helper start on a throwaway session key, `hsm` (the token writes it, e.g. AWS CloudHSM) or `caller` (sandboxd picks a random IV, e.g. SoftHSM2). An all-zero IV is always refused. |
| `SB_SECRET_PKCS11_RUN_DIR` | `/run/sandboxd/pkcs11` | Directory (made 0700) for the helper's 0600 Unix socket. |
| `SB_SECRET_PROVIDER_STRICT_BOOT` | `false` | Fail daemon start when the boot canary of any external provider fails. Default fail-open with a warning. Required for every external provider in enterprise mode. |
| `SB_SECRET_PROVIDER_MAX_INFLIGHT` | `8` | Foreground key-store calls in flight per node (1–256). One slot is kept for creates; background work has 2 more slots of its own. Lower it to fit an HSM partition's session limit or one Vault active node's capacity. Throttled calls back off inside the caller's deadline, then fail 503 `key_store_throttled`. |
| `SB_CREDENTIAL_KEY_CUSTODY` | `file` | `file` \| `wrapped`. `file` keeps the server key in the env or `SB_CREDENTIAL_ENCRYPTION_KEY_PATH` (today's behavior). `wrapped` keeps only a copy wrapped by the external provider at `SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH`, unwrapped at boot (one try, 10 s; systemd restarts on failure). Boot refuses if a plaintext key is set or its file exists; a fresh single node generates the key, cluster nodes never do (copy the seed's wrapped file). Manage it with `sandboxd key` (status, verify, wrap, rewrap, unwrap, ack-migration, rotate); `install.sh` and `cluster-init.sh` take `--key-custody wrapped`. Default stays `file`: wrapped custody needs a customer key store. |
| `SB_SECRET_PROVIDER_RECHECK_INTERVAL` | `5m` | With wrapped custody, how often each node unwraps its server-key file again (±10% jitter) to notice a revoke. Minimum 10s. One key-store call per node per interval, on the background budget. The same tick re-reads the server-key ring with either custody, so a `sandboxd key rotate` step reaches a node without a restart, and while a rotation is in progress it reseals rows onto the current key (local AES work, no key-store call). |
| `SB_SECRET_PROVIDER_REVOKE_AFTER` | `3` | Consecutive "key revoked" re-check results that stop the node: the server key leaves memory (every sealed read fails 503 `key_revoked`), the egress CA and injection secrets leave the gateway, SSH sessions and proxied toolbox streams end, health reports `key_custody: revoked`. A 403, an outage or a retired key version never count. The first good re-check brings the node back. 5m × 3 ≈ 15 minutes. |
| `SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH` | `/var/lib/sandboxd/credential_encryption.key.wrapped` | The wrapped server key used with `SB_CREDENTIAL_KEY_CUSTODY=wrapped`. In cluster mode it is what the shared-key check looks for instead of the plaintext key. After `sandboxd key rotate --stage` it holds the server-key ring (format 2), which older builds refuse to read. |
| `SB_CREDENTIAL_KEY_RING_PATH` | `SB_CREDENTIAL_ENCRYPTION_KEY_PATH` + `.ring` | With `SB_CREDENTIAL_KEY_CUSTODY=file`, the server-key ring that `sandboxd key rotate` writes (plaintext, 0600). Once it exists it holds every live server key; a key in `SB_CREDENTIAL_ENCRYPTION_KEY` or the key file must match its key 0 until key 0 is retired, after which it should be removed. In cluster mode it satisfies the shared-key check. Unused until the first rotation. |
| `SB_SECRET_RECIPIENT_BACKUP_COUNT` | `2` | Non-owner seal recipients for HA creates. |
| `SB_SECRET_FANOUT_MIN_ACK_WAIT` | `2s` | Bounded sync wait for ≥1 backup ACK on HA create. Cluster mode requires `>0`; zero ACKs retract the secret and fail the create. |
| `SB_SECRET_AUDIT_RETENTION_DAYS` | `30` | Local `{Dir(DBPath)}/audit/secrets.jsonl` and `sandbox_audit_acl` retention. Appends are fsynced at least once per second and at shutdown; pruned daily (and on sink start). **`0` means retain nothing beyond the crash buffer** — post-delete ACL rows go at the next sweep and the JSONL keeps one day for the export tailer. It never means forever. Removal is by record time anywhere in the file: the expired prefix is dropped; an expired record that landed behind a newer one (spill drain, worker ingest) becomes a hash-only `retention_redacted` stub so the chain still verifies (runbook: secrets-and-audit). |
| `SB_SECRET_AUDIT_STRICT_BOOT` | `true` | Refuse daemon startup when the local secret-audit writer cannot be opened or its hash chain fails verification. A torn final record from an unclean shutdown is not a failure: it is cut at open and recorded as a `reason=torn_tail` gap marker. |
| `SB_SECRET_AUDIT_BOOT_VERIFY` | `full` | How much of `secrets.jsonl` boot re-reads before the writer opens. `full`: every record, in **one** pass with O(1) memory (the witness check rides on the same pass, probing for the witnessed head instead of holding every hash in memory) — boot is O(retained volume). `checkpoint`: verify from the writer's last fsynced checkpoint (`secrets.verified`, written every sync) — O(bytes since the last sync) — then re-verify the whole chain in the background right after boot. A background failure withholds local audit reads (`503`), disables the read index, and fires `SandboxdAuditChainBroken`, instead of refusing to start. Trade-off: for the minutes the background pass takes, an in-place edit of the already-verified prefix is not yet detected; the tail, the checkpoint record, and everything appended after boot are verified synchronously. Recommended for large logs (multi-GB) where a full read at every restart is minutes of downtime; the default keeps the strict contract exactly as before. |
| `SB_SECRET_TOMB_RETENTION_DAYS` | `30` | Retain delete fences after all peer ACKs; `0` disables tombstone GC. Live/pending rows are never pruned. |
| `SB_SECRET_OUTBOX_STANDALONE_GRACE` | `1h` | Only matters with cluster mode **off** on a node that was a cluster member. Peer obligations it can never send (pending peer PUTs/DELETEs) and sealed rows for sandboxes it no longer has are retired once older than this; the grace keeps them across a brief cluster-off restart so a node that rejoins still owes them. `0` retires on the first sweep. Without this, a cluster→single-node downgrade leaked those rows forever. |
| `SB_EGRESS_ATTRIBUTION_ENABLED` | `true` | Wasm/isolate egress destination records in the same audit JSONL (`kind=egress`). Observational; off create path. |

### Audit rate limits (security parameters)

These bound amplification on `GET /v1/sandboxes/{id}/audit` (one client call → N peer reads). They are **security parameters**, not throughput knobs. On reject the API returns `429` with `Retry-After` — never silent truncation.

| Env var | Default | Notes |
|---|---|---|
| `SB_AUDIT_RATE_LIMIT_IDENTITY` | `10` | Per-`OwnerRef` token rate (req/s). Burst 20. |
| `SB_AUDIT_RATE_LIMIT_OPERATOR` | `50` | Operator PAT bucket (req/s). Burst 100 — generous for incident response. |
| `SB_AUDIT_RATE_LIMIT_NODE` | `50` | Global per-node ceiling (req/s). Burst 100. The only effective bound on OSS (single operator identity). |

The cluster-internal per-sandbox audit endpoint that ingress fan-out hits has its own per-node bucket at the same rate (`SB_AUDIT_RATE_LIMIT_NODE`), so a fleet-wide storm of peer reads cannot starve a node's own public audit traffic or the other way round. A node whose 8 local read slots stay busy for 50 ms answers `429` + `Retry-After: 1` (`aerolvm_audit_query_busy_total`) instead of queueing the request until its deadline turns into a 504.

### Audit read index

| Env var | Default | Notes |
|---|---|---|
| `SB_AUDIT_INDEX_ENABLED` | `true` | Keep a per-sandbox posting-list index (`secret_audit_index` in the SQLite store) over the local `secrets.jsonl` so a page of one sandbox's history is O(page) — the index names the records the page needs and only those are read and hash-checked. Derived data: rebuilt in the background from the file whenever they disagree, and reads scan the file meanwhile (`aerolvm_audit_index_ready`, `aerolvm_audit_query_scan_fallback_total`). Off means every page scans every retained record on the node, the pre-index behaviour; only useful to isolate a suspected index fault. Design: `plans/audit-read-index.md`. |

Whole-chain verification no longer runs on every page read. It runs at boot, before every retention sweep, incrementally as records are indexed (a break disables the index and withholds reads with `503` until an operator repairs the log), and on demand via `POST /v1/audit/verify` (operator PAT; O(file); one at a time per node; `aerolvm_audit_chain_verify_ok`).

`vault` is accepted as a known name but **fails boot** with a not-implemented error (no silent fallback to local).

## API overload protection (SB_API_LIST_*)

A cluster-wide sandbox list (`GET /v1/sandboxes`, and the Daytona, E2B and
Runloop lists) fans out: a placement-page read from the control plane and one
request per owner node. Each node runs only so many at once; past that a list
waits briefly for a slot and is otherwise answered `503` + `Retry-After: 1`
with code `overloaded`, instead of queueing until it takes 30 s and the node
falls over (bank flagship ramp, 2026-11-01: 1024 concurrent list clients gave
a 37 s p99 and 5,081 `502`s from a node the watchdog restarted). A single node
(cluster off) and a peer's forwarded list hop are never gated. Concurrent
identical placement-page reads on a node share one control-plane request, and
each still comes from a read that began after its caller asked.

| Env var | Default | Notes |
|---|---|---|
| `SB_API_LIST_MAX_INFLIGHT` | `16` | Cluster-wide lists this node runs at once. Matches the cluster transport's 16 pooled connections per peer, so list fan-out reuses mTLS connections rather than opening new ones. A healthy list holds its slot for milliseconds, so 16 slots serve thousands of lists a second and fill only when owners or the control plane slow down. Raise it on nodes with more CPU. `0` = no limit (the behaviour before this setting). Anything but a whole number refuses the boot. |
| `SB_API_LIST_QUEUE_WAIT` | `500ms` | How long a list waits for a free slot before it is shed. Short on purpose: inside every SDK's own retry backoff (they retry `503` up to 3 times, about 1-1.75 s in all). `0` = refuse at once. |

Metrics: `aerolvm_api_list_inflight`, `aerolvm_api_list_admitted_total`,
`aerolvm_api_list_shed_total` (alert `SandboxdAPIListShedding`).

## Audit export connectors (SB_AUDIT_EXPORT_BACKEND)

Modeled on kube-apiserver's audit backends (`plans/audit-export-connectors.md`):
the local hash-chained JSONL is the buffer, one cursor-tailer ships batches,
and the backend is pluggable. Raft never carries audit history. Delivery is
at-least-once — receivers dedupe on `Idempotency-Key` / `X-Aerol-Audit-Batch-ID`
(the S3 object key *is* the batch id, so a re-send overwrites, not duplicates).
A failing backend never drops evidence: the cursor lags, retention refuses to
rotate unexported bytes, and `aerolvm_audit_export_lag_bytes` grows visibly.

| Env var | Default | Notes |
|---|---|---|
| `SB_AUDIT_EXPORT_BACKEND` | `noop` (`webhook` when `SB_SECRET_AUDIT_EXPORT_URL` is set) | `noop` \| `stdout` \| `file` \| `webhook` \| `s3` \| `bus`. `noop` keeps evidence on local disk only and claims nothing more. Enterprise mode requires a non-noop backend or an injected `controlplane.AuditExporter`. |
| `SB_AUDIT_EXPORT_BATCH_MAX` | `4096` | Events per shipped batch (≤ 65536). |
| `SB_AUDIT_EXPORT_FLUSH_INTERVAL` | `1s` | Tailer tick (≥ 100ms). |
| `SB_AUDIT_EXPORT_MAX_BACKOFF` | `5m` | Retry cap after a failed export; exponential with full jitter from the flush interval. |
| `SB_AUDIT_QUEUE_MAX` | `1024` (`8192` enterprise) | Bounded in-memory emit queue in front of the JSONL. Emit never blocks a request. |
| `SB_AUDIT_OVERFLOW_POLICY` | `gap` (`spill` enterprise) | Full queue: `gap` drops and writes a counted `gap` marker; `spill` durable-appends to `secrets.spill.jsonl` (gap only if that fails). |
| `SB_AUDIT_EGRESS_SANDBOX_RATE` | `25` | Per-sandbox egress evidence budget, records per second, applied at the audit writer on every path (worker ingest, worker spill, in-process mediators) so a busy or compromised sandbox cannot grow the node-global evidence file or push other tenants' secret-open records into the overflow path. Records over budget are not written; they are counted and reported as one `egress` record per sandbox with `reason=rate_limited` and `dropped=n`, indexed under that sandbox only. `0` disables the budget (refused in enterprise mode). Workers get `429` for a refused record and do not spill it. |
| `SB_AUDIT_EGRESS_SANDBOX_BURST` | `250` | Burst for the budget above: a sandbox keeps full per-connection evidence for bursts up to this size, then `SB_AUDIT_EGRESS_SANDBOX_RATE` per second. |
| `SB_AUDIT_EXPORT_FILE_PATH` | (empty) | `file` backend target; `-` = stdout. A log backend for shippers, not durable storage. |
| `SB_AUDIT_EXPORT_WEBHOOK_URL` / `SB_AUDIT_EXPORT_WEBHOOK_BEARER_TOKEN` | (empty) | Aliases of `SB_SECRET_AUDIT_EXPORT_URL` / `..._BEARER_TOKEN`. Batched NDJSON POST; redirects are refused. |
| `SB_AUDIT_EXPORT_WEBHOOK_HMAC_KEY` | (empty) | Signs each body: `X-Aerol-Signature: sha256=<hex hmac>`. |
| `SB_AUDIT_EXPORT_WEBHOOK_CA_FILE` / `_CERT_FILE` / `_KEY_FILE` | (empty) | Receiver pinning and client-certificate (mTLS) auth. Enterprise webhooks must be `https` with at least one of bearer, HMAC, or client cert. |
| `SB_AUDIT_EXPORT_S3_BUCKET` / `_PREFIX` / `_ENDPOINT` / `_REGION` / `_PATH_STYLE` | (empty) | Any S3-compatible store; one object per batch at `<prefix>/node=<id>/<yyyy>/<mm>/<dd>/<batch>.jsonl`. Credentials come from the default AWS chain. Enterprise requires an `https` endpoint. |
| `SB_AUDIT_EXPORT_BUS_BROKERS` / `_TOPIC` | (empty) | Consumed by a registered `auditexport.BusPublisher` (Kafka/NATS client linked into the build). Without one, boot fails with `not implemented`. |
| `SB_AUDIT_DELETED_GRACE` | `1h` | How long the Raft FSM keeps a **routing stub** (owner_ref + evidence nodes) for a deleted sandbox so any ingress can still route a post-delete audit read. A grace window, never history: hard cap 24h; `0` disables it (pure Kubernetes mode — post-delete history is the backend's). |
| `SB_AUDIT_DELETED_INDEX_MAX` | `100000` | Hard cap on that stub index, oldest log index evicted first. Bounds FSM memory and snapshot size regardless of delete rate. Carried in each delete command so every replica evicts identically. |

Sandbox environment values are always encrypted in `sandbox_env`, and toolbox
bearer tokens are always encrypted in `sandboxes.toolbox_token_sealed`. There
are no plaintext storage columns or compatibility flags for either path. A
database containing the removed plaintext columns is rejected at boot; deploy
this schema as a coordinated, one-way change.

## API action records (SB_AUDIT_API_RECORDS)

Create, delete, exec, file, port, snapshot and token calls each write one
hash-chained `api` record naming the caller (`plans/identity-and-access.md`
§5.9): `ref` is the route pattern, `request` holds the method, status, the
exec body's SHA-256, and the object a non-sandbox route acts on. Only the node
that runs the handler records; a forwarded call is recorded by its owner with
the edge as `caller.via`. Refused calls are records too: a 403 is an `api`
record with `result: denied`; a refused credential (401) is an `auth_denied`
record, at most one per source address per minute: the first 401 is written at
once, and the 401s folded after it are written as one record when the minute
closes (within about 70 s of the first, even if the address goes quiet), its
`dropped` counting them. A graceful shutdown writes the counts still owed; a
crash loses the folded 401s of each address's open minute. SSH session opens and the daemon's own destructive work
(lifecycle auto-stop and auto-delete, the reconcile reap, the orphan delete)
write `api` records with `caller: sandbox_key` and `caller: system:<subsystem>`.
Records are buffered (no fsync on the request path) and, like every new
record field, written only once every cluster member runs the release. At
10k calls/s fleet-wide that is ~5 records/s per node, ~170 MB per node per day
before flood control, inside the existing retention and export.

| Env var | Default | Notes |
|---|---|---|
| `SB_AUDIT_API_RECORDS` | `mutations` | `mutations` records every non-GET call, every toolbox call (file reads too: files can hold secrets), token listing and every refused call. `all` adds plain GETs. `off` records none and costs nothing per request (refused in enterprise mode). `cluster.internal` traffic, `/health` and the outer `/mcp` request are never recorded; each MCP tool's inner call records itself with `request.surface: mcp`. |
| `SB_AUDIT_API_FLOOD_CONTROL` | `budget` | `budget`: a token bucket per (sandbox, caller); calls over it are counted into one `rate_limited` record naming the caller, the count (`dropped`) and the routes. `coalesce`: identical calls (same caller, route, sandbox, status, digest) within one second become one record with `request.count`; different commands never merge, and nothing is capped. `both`: coalesce, then budget. A node hosting sandboxes of more than one owner always budgets: `coalesce` runs as `both` there, and every change of the effective mode writes an `api_flood_mode` record. Gauge: `aerolvm_audit_api_flood_mode{key=<configured>,key2=<effective>}`. Records with no sandbox (token and cluster admin calls), durable records, secret opens and gap markers are never budgeted. |
| `SB_AUDIT_API_RATE` / `SB_AUDIT_API_BURST` | `20` / `100` | The budget above, per (sandbox, caller): a caller keeps one record per call for bursts up to the burst size, then this rate. `aerolvm_audit_api_rate_limited_total` counts the calls folded into `rate_limited` records. |
| `SB_AUDIT_EXEC_COMMAND` | `digest` | `digest` records the SHA-256 of an exec request body, hashed as it streams (never buffered): it proves which command ran without recording it, because commands carry secrets. `full` also records the argv (never the environment), read from the first 64 KiB of the body. |
| `SB_AUDIT_API_DURABLE` | `false` (`true` in enterprise mode, which refuses `false`) | Token create, token revoke and sandbox delete wait for their record to reach disk. Off by default to keep fsync off the request path. Without it, an unclean crash can lose the records of the last sync interval (1 s), the same window secret-open records have. |

## Audit witness (SB_AUDIT_WITNESS_BACKEND)

The witness keeps each node's audit hash-chain heads off the node, in an S3
bucket with Object Lock, so a node that is taken over later cannot rewrite the
history those heads vouch for (`plans/open-audit-witness.md`). A witness that a
provider supplies (the managed build) always wins over these settings. With a
witness in place the node ships its head every
`SB_SECRET_AUDIT_WITNESS_INTERVAL` (30s) and checks it at every boot;
`SB_SECRET_AUDIT_EXTERNAL_WITNESS=true`, which enterprise mode forces, also
refuses to boot without one. Bucket recipe, boot errors and recovery: runbook
secrets-and-audit, "S3 audit witness".

| Env var | Default | Notes |
|---|---|---|
| `SB_AUDIT_WITNESS_BACKEND` | (empty) | `s3`, or empty for none. Empty is off: zero S3 calls and the placeholder witness, exactly as before the setting existed. Off by default because it needs a bucket only the operator can create: Object Lock must be on from creation, and the lock mode (compliance or governance) and length decide whether anyone can ever delete what the bucket holds. That is not a choice a default should make. With `s3`, boot checks the bucket (versioning, Object Lock, a default retention of at least `SB_SECRET_AUDIT_RETENTION_DAYS`, a missing-key probe that needs `s3:ListBucket`, and a canary delete that must be refused) under a 30s deadline and refuses to start on any failure. Any other value is a config error. |
| `SB_AUDIT_WITNESS_S3_BUCKET` | (empty) | The Object Lock bucket. Required with `s3`. Use a bucket for the witness alone: the lock default applies to every object in it. |
| `SB_AUDIT_WITNESS_S3_PREFIX` | `witness/` | Key prefix; heads go to `<prefix>node=<id>/day=<UTC date>/head.json`. A fixed, non-empty default so the node-role IAM (`arn:aws:s3:::<bucket>/witness/*`) can be written before the first boot and never has to cover the whole bucket. A prefix without a trailing slash still works. Change it only together with the IAM. |
| `SB_AUDIT_WITNESS_S3_REGION` | (empty: AWS config) | Empty leaves the region to the standard AWS chain, the same as the S3 export. Terraform pins it, because a missing region shows up as an opaque timeout instead of a clear error. |
| `SB_AUDIT_WITNESS_S3_ENDPOINT` | (empty: AWS) | For S3-compatible stores. Only AWS is tested and documented in v1; a store without Object Lock fails the boot checks, so a wrong endpoint cannot pass silently. |
| `SB_AUDIT_WITNESS_S3_PATH_STYLE` | `false` | Path-style addressing, for S3-compatible stores that need it. AWS uses virtual-hosted addressing. |
| `SB_NODE_ID` (with a witness) | (empty: `standalone` on a single server) | **Required** once `SB_AUDIT_WITNESS_BACKEND` is set, and must not be `standalone`; config load fails and names `SB_NODE_ID` otherwise. Heads are filed under the node id, and every single server without one is `standalone`, so two servers sharing a bucket would overwrite each other's heads and refuse to restart. Must be unique among servers sharing the bucket. Cluster nodes already have one from `cluster-init.sh` / `cluster-join.sh`. Changing it later is a rebuild, not a config change (runbook: "Rebuild a node under a new SB_NODE_ID"). |

Credentials come from the standard AWS chain (instance role, environment,
profile), the same as the S3 export. The installer only documents these
settings (commented out in `sandboxd.env`) and never creates a bucket;
Terraform creates one with `audit_witness_enabled = true` (lock mode
`witness_lock_mode`, default `COMPLIANCE`; length `witness_lock_days`, default
30); Ansible passes the settings through from `sandboxd_audit_witness_*` and
`sandboxd_node_id`.

## 🟡 Opt-in — needs external config/hardware, would break or no-op if forced on
| Env var | Blocker |
|---|---|
| `SB_SECRET_PROVIDER=awskms` \| `vault` \| `pkcs11` | Needs a customer key store: an AWS KMS key + IAM, a Vault/OpenBao Transit key + Vault Agent or Proxy, or an HSM + its PKCS#11 library. Default remains `local`. |
| `SB_CREDENTIAL_KEY_CUSTODY=wrapped` | Needs an external `SB_SECRET_PROVIDER` to wrap the server key; cluster nodes need the seed's wrapped file. Default remains `file`. |
| `SB_ENABLE_FIRECRACKER` | Needs KVM/metal host; rejects create otherwise. |
| `SB_ENABLE_WASM` | Needs a provisioned wasm modules dir. |
| `SB_CONTAINER_ENGINE` | Code fallback is `docker` (empty/unknown → docker, so a bare host or the local `install.sh` stays dockerd). **Server deployments now default to `containerd`**: the shipped `config/cluster.yml`, Terraform, and Ansible all set `containerd` — set `container_engine: docker` there to keep a legacy dockerd host. This is the docker→containerd migration target; per-sandbox rows record their owning engine so a flip never strands existing sandboxes. containerd is live-validated on the t3 cluster topology (`cluster-3-mixed-containerd`); metal/arm64 provisioning is not yet live-proven (`plans/containerd-engine.md`). |
| `SB_DOCKER_TOOLBOX_LOOPBACK` | For hosts where sandboxd cannot dial container IPs — set by the macOS `install.sh --local` (Local Network privacy blocks a user process from the OrbStack / Docker Desktop VM's addresses). Each Docker sandbox publishes only its toolbox port, on `127.0.0.1` with a Docker-assigned host port, and sandboxd reads that port from the live container per toolbox request (it changes on every start). Startup rejects it with `SB_ENABLE_CLUSTER`, `SB_DOCKER_POOL_ENABLED`, `SB_DOCKER_NETNS_POOL_ENABLED` or `SB_DOCKER_NETWORK=host`. Sandboxes created before it was enabled must be recreated. |
| `SB_CONTAINERD_SOCKET` | containerd gRPC socket; default `/run/containerd/containerd.sock`. Used only when `SB_CONTAINER_ENGINE=containerd`. |
| `SB_CONTAINERD_NAMESPACE` | containerd namespace for aerolvm-managed workloads; default `aerolvm` (dockerd uses `moby`, so both engines coexist on one system containerd during migration). |
| `SB_CONTAINERD_RUN_DIR` | Host workdir for per-sandbox generated files (resolv.conf, hosts, hostname) and task logs; default `/var/lib/sandboxd/containerd`. |
| `SB_CONTAINERD_LOG_DIR` | Overrides per-task log file placement; defaults to `${SB_CONTAINERD_RUN_DIR}/logs`. Each task log is size-capped (containerd does not rotate task IO). |
| `SB_CONTAINERD_CNI_PLUGIN_DIR` | CNI plugin binaries dir; default `/opt/cni/bin`. Only consumed when the native netns pool is enabled. |
| `SB_CONTAINERD_CNI_CONF_PATH` | Bridge conflist path; default `/etc/cni/net.d/aerolvm.conflist`. Auto-generated at boot (bridge + host-local + `ipMasq`) if absent; an operator-provided file is never clobbered. |
| `SB_CONTAINERD_BUILDKIT_ADDR` | buildkitd control socket for image builds on the containerd engine; default `unix:///run/buildkit/buildkitd.sock`. The bootstrap installs buildkitd with a containerd worker pinned to the aerolvm namespace, so built images land where the driver can run them. Only used when `SB_CONTAINER_ENGINE=containerd`. |
| `SB_CONTAINERD_NETNS_POOL_DEPTH` | Number of netns slots the refiller keeps pre-realized (warm) for fast-hit creates; default `4`. This is the WARM target, NOT the concurrency ceiling — see `SB_CONTAINERD_NETNS_POOL_SIZE`. Only relevant when `SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED=true`. |
| `SB_CONTAINERD_NETNS_POOL_SIZE` | TOTAL netns slots seeded at boot = the ceiling on concurrent containerd sandboxes per node; default `256` (decoupled from the warm depth, exactly like `SB_FIRECRACKER_TAP_POOL_SIZE` is decoupled from the warm VMM depth). Cold creates reserve+realize any free slot up to this size; the refiller only pre-realizes `_DEPTH` of them. Floored to `_DEPTH` if set lower. Historically this was conflated with `_DEPTH`, which capped every node at 4 concurrent sandboxes. runc and gVisor share it; keep it at or below 1,023 (one bridge's port limit). Sizing per host: "Per-node slot limits" below. Only relevant when `SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED=true`. |
| `SB_CONTAINERD_NETNS_POOL_REFILL_INTERVAL` | netns pool refill ticker; default `2s`. |
| `SB_CONTAINERD_POOL_DEPTH` | Warm containers per image key; default `2`. Only relevant when `SB_CONTAINERD_POOL_ENABLED=true`. |
| `SB_CONTAINERD_POOL_IMAGES` | Comma-separated image allowlist to pre-warm; default empty. |
| `SB_CONTAINERD_POOL_MAX_IMAGES` | Cap on distinct warm image keys; default `8`. |
| `SB_CONTAINERD_POOL_IDLE_TTL` | Idle eviction TTL for warm slots; default `15m`. |
| `SB_CONTAINERD_POOL_REFILL_INTERVAL` | containerd warm-pool refill ticker; default `5s`. |
| `SB_ENABLE_CLUSTER` | Opt-in; cluster code must be a no-op when false. |
| `SB_CLUSTER_BOOTSTRAP` | Single-seed cluster bring-up only. |
| `SB_CLUSTER_SHARD_AWARE_INGRESS` | Declares that the router in front of the ingress tier resolves each sandbox's owners through `GET /v1/cluster/ingress-route/{id}`. Above 10 live ingress-capable nodes each ingress node holds only its share of the public route table (primary plus one replica per shard), so DNS round-robin, a cloud TCP LB, or a BGP VIP would black-hole most sandbox traffic. Without this flag the daemon fails closed at that size: enterprise boots refuse, open-source never marks ingress ready, `/health` reports `degraded`, `aerolvm_cluster_topology_ok` is 0. Flipping it with a plain LB in front silences the check and breaks traffic silently — the daemon cannot see what fronts it. Runbook: `setup/runbooks/cluster-ingress-topology.md`. |
| `SB_OTEL_METRICS_ENABLED` | Needs a collector; auto-enables when `SB_OTEL_METRICS_ENDPOINT` is set. |
| `SB_OTEL_TRACES_ENABLED` | Needs a collector; auto-enables when `SB_OTEL_TRACES_ENDPOINT` is set. |
| `SB_PLATFORM_VOLUMES_ENABLED` | Needs an S3/NFS backend config. |
| `SB_ENABLE_CUSTOM_DOMAINS` | Requires `SB_DOMAIN`; validator rejects in IP mode. |
| `SB_SNAPSHOT_PUSH_ENABLED` | Requires cluster ID + PAT path (validated at startup). |
| `SB_AUTO_IMPORT_ENABLED` | Needs registry/cluster import config. |
| `SB_FLEET_ENABLED` | Managed control-plane only; open-source build stays no-op. |
| `SB_IMAGE_BUILD_CONTEXT_ENABLED` | Context resolver not wired — returns 501 even when true. |

## 🟢 Complete & shipped — default-off is a deliberate operator opt-in
These work today and have soaked. Default-off is a host-resource/latency
tradeoff the operator makes (warm slots hold containers resident and enabling
the pool widens the ready-socket gate), **not** incompleteness. Clusters opt in
via Terraform/Ansible — do not flip the code default on.
| Env var | Status |
|---|---|
| `SB_DOCKER_POOL_ENABLED` | SHIPPED & VERIFIED v0.5.33 (2026-07-11): warm-hit p50 **43ms**, beats the ≤100ms gate. Holds pre-started containers resident; enabling also widens `DockerReadySocketEffective`. See `plans/docker-warm-pool.md` §12. |
| `SB_DOCKER_NETNS_POOL_ENABLED` | Companion pause-netns pool shipped/deployed (PR #300, v0.5.30–32). Terraform plumbs it per-node. With it off (or empty), a Docker create with network rules starts a pause container of its own so its rules are on before its workload runs (`docker_pause` stage); `SB_DOCKER_NETNS_POOL_PAUSE_IMAGE` (default `registry.k8s.io/pause:3.10`) is that container's image too, pulled in the background at boot, so an air-gapped node must point it at a mirror. |

## 🟠 Mid-rollout / not soaked — flip only with soak data
| Env var | Status |
|---|---|
| `SB_FIRECRACKER_VMM_POOL_ENABLED` | Fully wired: daemon runs the refill goroutine + `Driver.SetWarmPool`, and `Driver.Create.tryAcquireWarm` consumes warm VMMs. Kept default-off **ship-dark** — code-complete but no benchmark gate in `plans/firecracker-create-latency.md` re-measured yet. Do not flip until those gates pass. |
| `SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED` | Being canaried (`plans/warm-direct-route-bypass.md`). |
| `SB_L4_WAKE_DIRECT_BYPASS_ENABLED` | Ships only after HTTP has been default-on for two cycles. |
| `SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED` | Turns on Phase-2 CNI container networking for the containerd engine (netns pool + CNI ADD/DEL + `AEROLVM-USER` chain). Code-flag default is off (docker hosts), but **containerd deployments enable it** (`config/cluster.yml`, Terraform, Ansible all set it `true`) — and since server deployments now default to containerd, it is on by default there. The §8 exit gates (neighbor isolation, orphan=0, live bench) passed on the t3 containerd topology (`cluster-3-mixed-containerd`); still un-proven on metal/arm64, so validate those before relying on them. Requires `SB_CONTAINER_ENGINE=containerd` + CNI plugin binaries. |
| `SB_INGRESS_PROXY_ROUTING` | Routing without per-sandbox Caddy writes (`plans/ingress-proxy-routing.md`). Each per-sandbox write reloads Caddy's whole config and drops ~2.6% of new connections under churn. With the flag on, Caddy holds static routes and asks a loopback sandboxd DNS responder where each host goes. Raw TCP host ports move to kernel DNAT, so sessions survive sandboxd restarts. **Default off** because the flip has host prerequisites: the `~rt.internal` resolver routing domain on ingress nodes (`install.sh --ingress-proxy-routing`), iptables, and `SB_AUTO_RECONCILE` on workers. The flag refuses to engage without them and the node stays on Caddy routes. Engaging is one Caddy load. Turning the flag off is detected on the next boot through the `ingress_proxy_routing_last_enabled` marker and rolled back in one load. Per-node, no flag-day. Flip only after the churn repro gate shows 0 failures. `cluster-bank-flagship` runs it on (a reload drops new connections in two ways that no Caddy setting turns off; TODOS.md has the mechanism), and the default flips after that run is green and the A/B is in. |
| `SB_ROUTE_DNS_ADDR` | `127.0.0.1:53053`: the route responder's loopback address. The static owner route and the boot probes ask it directly; change both together. |
| `SB_ROUTE_DNS_LINK_ADDR` | Empty: a second responder listener, on the `aerolvm-rt` link's own address, which is where systemd-resolved sends `*.rt.internal`. `install.sh --ingress-proxy-routing` sets `169.254.53.53:53053` and points the link's DNS server at the same address. Not loopback, because resolved pins its socket for a link's DNS server to that link: a UDP query to `127.0.0.1` leaves through the dummy link and is dropped, and resolved then stalls lookups for about 20 s each time it re-probes UDP, failing new connections through the ingress with EOF (cluster-bank-flagship UC-171, 2026-11-01). The listener answers only this node (loopback, or its own address). An ingress engaging the flag without it logs a warning. |
| `SB_HOSTPORT_REDIRECT_PORT` | `21215`: the listener that REDIRECTed raw-TCP host ports reach, for targets the kernel can't DNAT to (a stopped serverless sandbox to wake, WASM/isolate loopback mediators). It must sit outside `SB_L4_PORT_RANGE_*`; config load refuses it otherwise. |
| `SB_MCP_ENABLED` | Mounts the remote MCP endpoint `/mcp` (`plans/mcp-server-and-agent-cli.md` §5.7): MCP clients reach a pinned sandbox over Streamable HTTP with an API token, no local install. **Default off** because it is a new public surface on the API listener; turn it on per deployment once the "Remote MCP" dashboard row and `SandboxdRemoteMCPErrorRate` alert are wired. Companion settings: `SB_MCP_ALLOWED_ORIGINS` (browser origins allowed; default none, so any request carrying an `Origin` is refused), `SB_MCP_ALLOWED_HOSTS` (optional `Host` allowlist), `SB_MCP_RATE_LIMIT` (per-token req/s, default 20, burst 2x; 0 disables). OAuth for claude.ai/ChatGPT connectors is a later phase; this is bearer-only. Runbook: `setup/runbooks/remote-mcp.md`. |
| `SB_IDENTITY_ENABLED` | Turns on sandboxd's own named credentials (`plans/identity-and-access.md`): scoped API tokens (`avm_…`, minted with `POST /v1/tokens` or `aerolvm token create`) and SSO through an identity provider when `SB_IDENTITY_FILE` names one. **Default off**: off is byte for byte the PAT-only server, which every existing install relies on; tokens can still be minted, listed and revoked, but no node accepts them, and no node loads or mirrors them. It cannot run next to a control-plane provider that validates tokens itself (boot refuses). The test-only `SB_ITEST_IDENTITY_FILE` is gone: the variable is ignored. Enterprise mode requires it (boot refuses `SB_ENTERPRISE_MODE=true` without it); tokens-only mode, with no `SB_IDENTITY_FILE`, satisfies that. Docs: `docs/src/content/docs/enterprise/sso.mdx`. |
| `SB_IDENTITY_SYNC_INTERVAL` | `5s`: how often a cluster node without Raft state (worker, ingress) polls the server tier for token changes. A poll that finds nothing new is a 304 from an in-memory compare, so 2,000 nodes cost the server tier ~400 req/s of next to nothing; a revoke reaches every node within one interval (target ≤ 15 s). |
| `SB_IDENTITY_MAX_STALE` | `60s`: a token mirror that has not synced for this long refuses API tokens with 503 (the PAT is unaffected), except on routes that need only `metrics.read`, so worker metrics keep flowing through a server-tier outage (CEO review D16). A server tier down for 60 s already blocks creates, so this adds no new outage class. Must be at least `SB_IDENTITY_SYNC_INTERVAL`. |
| `SB_TOKEN_MAX_TTL` | `8760h` (365 days); `2160h` (90 days) in enterprise mode, which refuses anything longer. Every API token must expire, and `expires_in` above this cap is a 400. Accepts days (`90d`) as well as Go durations; an unparsable value fails the boot rather than silently falling back. |
| `SB_IDENTITY_FILE` | The identity file (`plans/identity-and-access.md` §5.5): the OIDC issuers people and CI sign in with, the group / app-role / claim to role bindings, and the emergency `deny_subjects` list. **Default empty**: empty with `SB_IDENTITY_ENABLED=true` is tokens-only mode (no SSO), and config load refuses the file without `SB_IDENTITY_ENABLED=true`, so a deploy never believes SSO or the deny list is on when it is not. Strict YAML (an unknown key fails the load), 1 MiB cap, and an empty file is invalid. Polled every 10 s and reloaded on SIGHUP; an invalid reload keeps the last good file (`aerolvm_identity_file_load_errors_total`), and an invalid file at boot leaves OIDC sign-in at 503 while the PAT and API tokens keep working. Each node writes one `identity_config` audit record per effective change. Ship the same file to every node (Terraform, Ansible); distinct `aerolvm_identity_file_info` hashes across nodes show drift. |
| `SB_PAT_SCOPE` | `any`: where the operator token (PAT) works. `any` is today's behavior, everywhere the API answers. `host` accepts it only from a loopback TCP peer on the API listener (setup scripts, runbooks, the SSH gateway) and from mTLS cluster peers, so remote people must use SSO or a named `avm_` token; a refused PAT gets 401 "the operator token works only on this host; sign in with `aerolvm login --sso` or use a named token". **Default `any`** because every existing remote PAT user (dashboard, remote MCP, SDK scripts, the Prometheus scrape) would break; enterprise mode requires `host`. Under `host` Caddy must proxy to `SB_PUBLIC_API_SOCKET` (`install.sh --pat-scope host` writes both halves), because Caddy's own traffic also comes from loopback. A forwarded PAT carries `X-Cluster-PAT-Origin`, and an owner under `host` refuses a missing marker, so turn it on only after every node runs the release. Nodes gossip their scope; `aerolvm_pat_scope_drift` counts members that differ. `SB_API_HOST` is unchanged (`0.0.0.0` on domain installs): host scope works by the peer address, not by the bind, so remote SSO and `avm_` callers and a token-based scrape of `private_ip:21212` keep working. Runbook: `setup/runbooks/identity-and-access.md` (TurnOnHostScope). |
| `SB_PUBLIC_API_SOCKET` | `/run/sandboxd-public/api.sock`: the Unix socket Caddy proxies to under `SB_PAT_SCOPE=host`; every request on it is public, so the PAT is refused there. Unused under `any`. sandboxd creates the directory `root:caddy 0750` and the socket `root:caddy 0660` on every boot (`/run/sandboxd` is `0700`, which Caddy cannot enter). Must be absolute. Any other reverse proxy on the host must use this socket too. |
| `SB_PAT_TOKEN_PREVIOUS` | Empty: a second PAT accepted (in constant time) during a rotation, while nodes send only the current one. Empty outside a rotation, so an old PAT never lingers. At least 32 bytes in enterprise mode. With platform volumes on, boot refuses it unless `SB_OPERATOR_VOLUME_SCOPE` is pinned, because a new PAT would otherwise move every operator volume. Runbook: RotatePAT. |
| `SB_OPERATOR_VOLUME_SCOPE` | Empty (the legacy `op-<hash of the PAT>`): the operator's platform-volume namespace. Pin it to the value boot logs (`operator volume scope scope=op-… pinned=false`) before rotating the PAT, so volumes stay where they are. Empty keeps every existing install's volumes in place. Format: `op-` and up to 61 of `a-z 0-9 . _ -`. |
| `SB_L4_FALLBACK_PROXY_PROTOCOL` | `false`: the caddy-l4 TLS fallback sends a PROXY v2 header to the 8443 HTTPS site, so Caddy sees the real client and passes it to sandboxd as `X-AerolVM-Client-IP` (for `auth_denied` records, their per-address limit, and the `origin` label of the break-glass PAT alert). **Default off** because it needs the 8443 `proxy_protocol` listener wrapper: on without it, every public HTTPS handshake fails. Only `install.sh --l4-proxy-protocol` (domain mode) turns it on, writing the wrapper and the flag together. sandboxd trusts the header only from the public socket or a loopback peer; anything else is dropped and counted in `aerolvm_auth_client_ip_dropped_total`. To undo: set it `false` and restart **before** removing the wrapper. |
| `SB_CONTAINERD_POOL_ENABLED` | Turns on the Phase-3 containerd warm-container pool (rename-free park/adopt). Default-off **ship-dark**; also widens the ready-socket gate like `SB_DOCKER_POOL_ENABLED`. Requires `SB_CONTAINER_ENGINE=containerd` + `SB_DOCKER_READY_SOCKET_ENABLED=true`. Gated on the §8 warm-hit bench. |

## Per-node slot limits (capacity planning)

Besides CPU, memory and disk, every sandbox holds one network slot on its node
until it is destroyed (stopped sandboxes keep theirs, so their address
survives a restart). The pools are fixed at boot, so on a big host a pool, not
the CPU or memory budget, is often what fills first. The 2026-11-01 bank
flagship density ramp stopped every m5zn.metal worker (48 vCPU, 192 GiB) at
256 containerd + gVisor sandboxes and 256 Firecracker VMs, while the CPU
budget at the default ratios (48 × 0.9 × 10 = 432 vCPU) still had room for
1,728 sandboxes of 0.25 vCPU.

A full pool is a capacity refusal: the create answers 503 with `Retry-After`
(the pool's error wraps `capacity.ErrCapacityExceeded`), each worker reports
its pools and free slots as `slot_pools` on `/v1/capacity`, and cluster
placement skips a node whose pool for the request's runtime is full. When
every node that could run the request is full, the cluster answers 503 "at
capacity" (`docs/src/content/docs/engineering-placement-failover.mdx`, section
"Network slots").

| Pool | Setting | Default | Who draws on it | Hard ceiling and why | Cost per slot | Recommendation |
|---|---|---|---|---|---|---|
| containerd netns | `SB_CONTAINERD_NETNS_POOL_SIZE` | `256` | runc (`docker`) **and** gVisor creates on the containerd engine — one shared pool; also warm-parked containers (`SB_CONTAINERD_POOL_*`) and slots parked `releasing` after a failed teardown | **1,023**: every slot is a veth on the one `aerolvm0` bridge, and a Linux bridge numbers ports with 10 bits (`BR_MAX_PORTS` 1024, port 0 unused). Past it CNI ADD fails with "exchange full"; boot logs a warning when the size is set higher. Address space is not the limit (`10.88.0.0/16`, 65,534 addresses); the seed refuses more than 10,000. | a netns, a veth pair, a host-local lease, and the bridge plugin's `ipMasq` chain (3 nat rules, so `POSTROUTING` grows by one jump per slot). conntrack entries follow connections, not slots. | Keep `256` as the code default: on most hosts the CPU budget fills first (an m6i.xlarge's 36-vCPU budget holds 144 sandboxes of 0.25 vCPU). On a large host set it to the number of the smallest sandbox the CPU and memory budgets admit, capped at **1,000** (headroom under 1,023 for warm and prewarmed slots). For the m5zn.metal flagship workers: `1000`. |
| Firecracker TAP | `SB_FIRECRACKER_TAP_POOL_SIZE` (with `SB_FIRECRACKER_TAP_BASE_CIDR`) | `256` (in `172.16.0.0/20`) | Firecracker creates; warm VMMs (`SB_FIRECRACKER_VMM_POOL_*`) hold theirs | the base CIDR: one `/30` per slot, so the default `/20` holds **1,024**; boot refuses a size the CIDR cannot hold. TAPs are routed, not bridged, so there is no bridge-port wall. Each slot also takes a vsock CID and a `fctapN` name; the seed refuses more than 10,000. | a TAP device and a `/30` route; the isolation rules are per subnet, not per TAP. The VM's guest memory is the real cost, and the memory budget, live-memory floor and `SB_FIRECRACKER_RSS_WATERMARK_RATIO` already bound it. | Keep `256` as the code default. On a metal Firecracker host set it to what the memory budget admits for your smallest VM, up to `1024` within the default `/20`; beyond that widen `SB_FIRECRACKER_TAP_BASE_CIDR` (a `/19` holds 2,048) **before** the first boot, because a re-seed keeps the old layout. For the m5zn.metal flagship workers: `1024`. |
| isolate egress | `SB_ISOLATE_EGRESS_POOL_SIZE` | `64` | isolate sandboxes that may reach the network (block-all ones take no slot), **per tenant group per node**, not per node | none in practice: a slot is a Unix socket path, bound only while a sandbox holds it, and one declared service in that group's workerd config | one listener goroutine while held; the generated group config grows by one service per slot | Raise it when one tenant runs more than 64 egress-using isolates on one node. Because the pool is per group, it is not in `slot_pools`: a create that needs a slot in a full group is refused with the 503 capacity error (before, it started with egress silently denied), and the retry may land on another node. |
| WASM instances | `SB_WASM_MAX_INSTANCES` | `0` (no cap) | WASM creates | only what the operator sets; WASM networking is host-mediated, so there is no per-sandbox address | the module instance itself | Leave uncapped unless you need a hard per-host count; when set, it is advertised in `slot_pools` and placement honours it. |
| Docker engine | none (dockerd's own bridge) | — | runc and gVisor creates on the docker engine | **1,023** containers per bridge (the same `docker0` port limit), then dockerd fails the container start. Not a pool sandboxd counts, so it is not in `slot_pools`; the pause-netns pool (`SB_DOCKER_NETNS_POOL_*`) is a warm pool whose miss falls back, never a ceiling. | a veth on `docker0` | Keep a docker-engine host's CPU budget below ~1,000 of its smallest sandbox, or move dense hosts to containerd. |

## Client settings (the five SDKs and the aerolvm CLI)

Not sandboxd settings: every SDK and the CLI read these from the caller's
environment (`plans/identity-and-access.md` §10, T7 and T9). Both default to
empty so existing scripts keep the exact requests they send today.

| Env var | Default | Why this default |
|---|---|---|
| `SB_API_TOKEN` | empty | An alias of `SB_PAT_TOKEN` for any bearer: an `avm_` API token, an OIDC ID token (for example from `aerolvm auth token`), or the PAT. The old name stays the one that wins when both are set, so a shell that already exports `SB_PAT_TOKEN` keeps sending the same credential. |
| `SB_TEAM` | empty | The team a multi-team credential acts for, sent as `X-AerolVM-Team` (CEO review D13). Empty sends no header and the server uses the credential's first matching binding, so a single-team credential and the PAT see no change. The header only selects among bindings the credential already holds; it never grants. The CLI's `aerolvm login --team` saves the same choice per login, and `SB_TEAM` overrides it. The TypeScript SDK cannot send it on WebSocket streams. |

## ⚪ Boot-path tuning — intentionally off
| Env var | Why |
|---|---|
| `SB_FIRECRACKER_OVERLAY_MKFS` | Guest mkfs's its own overlay; enabling adds ~50ms/create (pr-review §2). |
