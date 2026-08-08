# Config defaults reference

Operator reference for every boolean feature flag in `internal/config/config.go`:
its default, and **why** it defaults the way it does. Use this when deciding
whether a flag is safe to flip on for a deployment, or when reviewing a proposal
to change a shipped default.

Snapshot as of 2026-07-12. When you change a default in `config.go`, update the
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
| `SB_SECRET_RECIPIENT_FANOUT_ENABLED` | true — defect fix for cross-node failover open (recipient-set sealing + async peer fan-out). Set false only while diagnosing. |
| `SB_SECRET_FANOUT_MIN_ACK_WAIT` | `2s` — sync wait on HA create for ≥1 peer ACK before return (shrinks GAP-1). Remaining peers stay async. `0` = fully async. |
| `SB_EGRESS_ATTRIBUTION_ENABLED` | true — host-mediated egress destinations (wasm + isolate) into audit JSONL; dial-path only, never create. Set false to disable. |

## 🔴 Must stay off — security / safety
| Env var | Why off is correct |
|---|---|
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
| `SB_SECRET_FANOUT_MIN_ACK_WAIT` | `2s` | Bounded sync wait for ≥1 backup ACK on HA create; `0` disables (fully async). |
| `SB_SECRET_ENV_SEAL_ENABLED` | `false` | Sealed `sandbox_env` rows + Raft Env redaction (RefVersionEnv=2). Format change — enable only after every node can merge Env from the provider bag. Removal criterion: `aerolvm_env_plaintext_fallback_total` stays zero for a release and plaintext `env_json` is dropped. |
| `SB_SECRET_AUDIT_RETENTION_DAYS` | `30` | Local `{Dir(DBPath)}/audit/secrets.jsonl` retention. Pruned daily (and on sink start). `0` disables prune. |
| `SB_EGRESS_ATTRIBUTION_ENABLED` | `true` | Wasm/isolate egress destination records in the same audit JSONL (`kind=egress`). Observational; off create path. |

### Audit rate limits (security parameters)

These bound amplification on `GET /v1/sandboxes/{id}/audit` (one client call → N peer reads). They are **security parameters**, not throughput knobs. On reject the API returns `429` with `Retry-After` — never silent truncation.

| Env var | Default | Notes |
|---|---|---|
| `SB_AUDIT_RATE_LIMIT_IDENTITY` | `10` | Per-`OwnerRef` token rate (req/s). Burst 20. |
| `SB_AUDIT_RATE_LIMIT_OPERATOR` | `50` | Operator PAT bucket (req/s). Burst 100 — generous for incident response. |
| `SB_AUDIT_RATE_LIMIT_NODE` | `50` | Global per-node ceiling (req/s). Burst 100. The only effective bound on OSS (single operator identity). |

`vault` is accepted as a known name but **fails boot** with a not-implemented error (no silent fallback to local).

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
