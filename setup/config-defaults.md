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

## 🔴 Must stay off — security / safety
| Env var | Why off is correct |
|---|---|
| `SB_CONTAINER_PRIVILEGED` | Privileged containers = sandbox escape. |
| `SB_CLUSTER_INSECURE_GOSSIP` | Disables gossip encryption. |
| `SB_CLUSTER_INSECURE_CREDENTIALS` | Disables credential protection. |
| `SB_RESOURCE_LIMITS_DISABLED` | *Disables* cgroup limits; `false` already = limits ON. |

## 🟡 Opt-in — needs external config/hardware, would break or no-op if forced on
| Env var | Blocker |
|---|---|
| `SB_ENABLE_FIRECRACKER` | Needs KVM/metal host; rejects create otherwise. |
| `SB_ENABLE_WASM` | Needs a provisioned wasm modules dir. |
| `SB_CONTAINER_ENGINE` | `docker` (default) vs `containerd`. Empty/unknown → docker so pre-migration hosts are byte-identical. containerd is a host-level operator choice; per-sandbox rows record their owning engine so a flip never strands existing sandboxes. Phase 1 (dark): lifecycle + security envelope + seams; container networking is Phase 2 (`plans/containerd-engine.md`). |
| `SB_CONTAINERD_SOCKET` | containerd gRPC socket; default `/run/containerd/containerd.sock`. Used only when `SB_CONTAINER_ENGINE=containerd`. |
| `SB_CONTAINERD_NAMESPACE` | containerd namespace for aerolvm-managed workloads; default `aerolvm` (dockerd uses `moby`, so both engines coexist on one system containerd during migration). |
| `SB_CONTAINERD_RUN_DIR` | Host workdir for per-sandbox generated files (resolv.conf, hosts, hostname) and task logs; default `/var/lib/sandboxd/containerd`. |
| `SB_CONTAINERD_LOG_DIR` | Overrides per-task log file placement; defaults to `${SB_CONTAINERD_RUN_DIR}/logs`. Each task log is size-capped (containerd does not rotate task IO). |
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

## ⚪ Boot-path tuning — intentionally off
| Env var | Why |
|---|---|
| `SB_FIRECRACKER_OVERLAY_MKFS` | Guest mkfs's its own overlay; enabling adds ~50ms/create (pr-review §2). |
