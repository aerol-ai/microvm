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
| `SB_ENABLE_NETWORK_RULES` | true |
| `SB_NETRULES_BACKEND` | `netlink` (in-process nftables; `exec` = go-iptables fallback) |
| `SB_ENABLE_EVENT_MONITOR` | true |
| `SB_ENABLE_SSH_GATEWAY` | true |
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

## 🔴 Must stay off — security / safety
| Env var | Why off is correct |
|---|---|
| `SB_ENTERPRISE_MODE` | Opt-in fail-fast profile; local development keeps its lightweight defaults. Production deployments should enable it. Requires an `SB_PAT_TOKEN` of at least 32 bytes. |
| `SB_CONTAINER_PRIVILEGED` | Privileged containers = sandbox escape. |
| `SB_CLUSTER_INSECURE_GOSSIP` | Disables gossip encryption. |
| `SB_CLUSTER_INSECURE_CREDENTIALS` | Disables credential protection. |
| `SB_RESOURCE_LIMITS_DISABLED` | *Disables* cgroup limits; `false` already = limits ON. |

## Secret provider (SB_SECRET_PROVIDER)

| Env var | Default | Notes |
|---|---|---|
| `SB_SECRET_PROVIDER` | `local` | `local` \| `awskms` \| `vault`. Off-state is `local` — never contacts AWS/Vault unless explicitly set. See `docs/.../cluster-secrets.mdx`. |
| `SB_SECRET_AWS_KMS_KEY_ID` | (empty) | Required when `SB_SECRET_PROVIDER=awskms`. |
| `SB_SECRET_PROVIDER_STRICT_BOOT` | `false` | Fail daemon start on awskms boot-canary failure. Default fail-open with a warning. |
| `SB_SECRET_RECIPIENT_BACKUP_COUNT` | `2` | Non-owner seal recipients for HA creates. |
| `SB_SECRET_FANOUT_MIN_ACK_WAIT` | `2s` | Bounded sync wait for ≥1 backup ACK on HA create. Cluster mode requires `>0`; zero ACKs retract the secret and fail the create. |
| `SB_SECRET_AUDIT_RETENTION_DAYS` | `30` | Local `{Dir(DBPath)}/audit/secrets.jsonl` and `sandbox_audit_acl` retention. Appends are fsynced at least once per second and at shutdown; pruned daily (and on sink start). **`0` means retain nothing beyond the crash buffer** — post-delete ACL rows go at the next sweep and the JSONL keeps one day for the export tailer. It never means forever. |
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

## 🟡 Opt-in — needs external config/hardware, would break or no-op if forced on
| Env var | Blocker |
|---|---|
| `SB_SECRET_PROVIDER=awskms` | Needs `SB_SECRET_AWS_KMS_KEY_ID` + AWS credentials / IAM. Default remains `local`. |
| `SB_ENABLE_FIRECRACKER` | Needs KVM/metal host; rejects create otherwise. |
| `SB_ENABLE_WASM` | Needs a provisioned wasm modules dir. |
| `SB_CONTAINER_ENGINE` | Code fallback is `docker` (empty/unknown → docker, so a bare host or the local `install.sh` stays dockerd). **Server deployments now default to `containerd`**: the shipped `config/cluster.yml`, Terraform, and Ansible all set `containerd` — set `container_engine: docker` there to keep a legacy dockerd host. This is the docker→containerd migration target; per-sandbox rows record their owning engine so a flip never strands existing sandboxes. containerd is live-validated on the t3 cluster topology (`cluster-3-mixed-containerd`); metal/arm64 provisioning is not yet live-proven (`plans/containerd-engine.md`). |
| `SB_CONTAINERD_SOCKET` | containerd gRPC socket; default `/run/containerd/containerd.sock`. Used only when `SB_CONTAINER_ENGINE=containerd`. |
| `SB_CONTAINERD_NAMESPACE` | containerd namespace for aerolvm-managed workloads; default `aerolvm` (dockerd uses `moby`, so both engines coexist on one system containerd during migration). |
| `SB_CONTAINERD_RUN_DIR` | Host workdir for per-sandbox generated files (resolv.conf, hosts, hostname) and task logs; default `/var/lib/sandboxd/containerd`. |
| `SB_CONTAINERD_LOG_DIR` | Overrides per-task log file placement; defaults to `${SB_CONTAINERD_RUN_DIR}/logs`. Each task log is size-capped (containerd does not rotate task IO). |
| `SB_CONTAINERD_CNI_PLUGIN_DIR` | CNI plugin binaries dir; default `/opt/cni/bin`. Only consumed when the native netns pool is enabled. |
| `SB_CONTAINERD_CNI_CONF_PATH` | Bridge conflist path; default `/etc/cni/net.d/aerolvm.conflist`. Auto-generated at boot (bridge + host-local + `ipMasq`) if absent; an operator-provided file is never clobbered. |
| `SB_CONTAINERD_BUILDKIT_ADDR` | buildkitd control socket for image builds on the containerd engine; default `unix:///run/buildkit/buildkitd.sock`. The bootstrap installs buildkitd with a containerd worker pinned to the aerolvm namespace, so built images land where the driver can run them. Only used when `SB_CONTAINER_ENGINE=containerd`. |
| `SB_CONTAINERD_NETNS_POOL_DEPTH` | Number of netns slots the refiller keeps pre-realized (warm) for fast-hit creates; default `4`. This is the WARM target, NOT the concurrency ceiling — see `SB_CONTAINERD_NETNS_POOL_SIZE`. Only relevant when `SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED=true`. |
| `SB_CONTAINERD_NETNS_POOL_SIZE` | TOTAL netns slots seeded at boot = the ceiling on concurrent containerd sandboxes per node; default `256` (decoupled from the warm depth, exactly like `SB_FIRECRACKER_TAP_POOL_SIZE` is decoupled from the warm VMM depth). Cold creates reserve+realize any free slot up to this size; the refiller only pre-realizes `_DEPTH` of them. Floored to `_DEPTH` if set lower. Historically this was conflated with `_DEPTH`, which capped every node at 4 concurrent sandboxes. Only relevant when `SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED=true`. |
| `SB_CONTAINERD_NETNS_POOL_REFILL_INTERVAL` | netns pool refill ticker; default `2s`. |
| `SB_CONTAINERD_POOL_DEPTH` | Warm containers per image key; default `2`. Only relevant when `SB_CONTAINERD_POOL_ENABLED=true`. |
| `SB_CONTAINERD_POOL_IMAGES` | Comma-separated image allowlist to pre-warm; default empty. |
| `SB_CONTAINERD_POOL_MAX_IMAGES` | Cap on distinct warm image keys; default `8`. |
| `SB_CONTAINERD_POOL_IDLE_TTL` | Idle eviction TTL for warm slots; default `15m`. |
| `SB_CONTAINERD_POOL_REFILL_INTERVAL` | containerd warm-pool refill ticker; default `5s`. |
| `SB_ENABLE_CLUSTER` | Opt-in; cluster code must be a no-op when false. |
| `SB_CLUSTER_BOOTSTRAP` | Single-seed cluster bring-up only. |
| `SB_CLUSTER_SHARD_AWARE_INGRESS` | Cluster ingress topology. |
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
| `SB_DOCKER_NETNS_POOL_ENABLED` | Companion pause-netns pool shipped/deployed (PR #300, v0.5.30–32). Terraform plumbs it per-node. |

## 🟠 Mid-rollout / not soaked — flip only with soak data
| Env var | Status |
|---|---|
| `SB_FIRECRACKER_VMM_POOL_ENABLED` | Fully wired: daemon runs the refill goroutine + `Driver.SetWarmPool`, and `Driver.Create.tryAcquireWarm` consumes warm VMMs. Kept default-off **ship-dark** — code-complete but no benchmark gate in `plans/firecracker-create-latency.md` re-measured yet. Do not flip until those gates pass. |
| `SB_HTTP_WAKE_DIRECT_BYPASS_ENABLED` | Being canaried (`plans/warm-direct-route-bypass.md`). |
| `SB_L4_WAKE_DIRECT_BYPASS_ENABLED` | Ships only after HTTP has been default-on for two cycles. |
| `SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED` | Turns on Phase-2 CNI container networking for the containerd engine (netns pool + CNI ADD/DEL + `AEROLVM-USER` chain). Code-flag default is off (docker hosts), but **containerd deployments enable it** (`config/cluster.yml`, Terraform, Ansible all set it `true`) — and since server deployments now default to containerd, it is on by default there. The §8 exit gates (neighbor isolation, orphan=0, live bench) passed on the t3 containerd topology (`cluster-3-mixed-containerd`); still un-proven on metal/arm64, so validate those before relying on them. Requires `SB_CONTAINER_ENGINE=containerd` + CNI plugin binaries. |
| `SB_CONTAINERD_POOL_ENABLED` | Turns on the Phase-3 containerd warm-container pool (rename-free park/adopt). Default-off **ship-dark**; also widens the ready-socket gate like `SB_DOCKER_POOL_ENABLED`. Requires `SB_CONTAINER_ENGINE=containerd` + `SB_DOCKER_READY_SOCKET_ENABLED=true`. Gated on the §8 warm-hit bench. |

## ⚪ Boot-path tuning — intentionally off
| Env var | Why |
|---|---|
| `SB_FIRECRACKER_OVERLAY_MKFS` | Guest mkfs's its own overlay; enabling adds ~50ms/create (pr-review §2). |
