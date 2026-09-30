# Kubernetes deployment — run AerolVM on, and manage it from, Kubernetes

**Status:** PROPOSED (2026-09-30). Not eng-reviewed. Nothing below is built.
**Related:** `plans/data-plane-load-balancer.md` (server/worker/ingress role
split this plan maps onto), `plans/containerd-engine.md` (the engine a
Kubernetes node already runs), `plans/integration-tests.md` (where the new
scenario lands), `docs/src/content/docs/engineering-runtime-layers.mdx`
(why we drive Firecracker directly instead of via Kata).

## 1. Why

Buyers trust Kubernetes. "Can I `helm install` it into my cluster?" and "can I
manage sandboxes with `kubectl` / GitOps?" come up before any benchmark does.
Today the only supported install paths are `scripts/install.sh`, Ansible
(`Ansible/playbooks/`) and Terraform (`Terraform/`) onto bare VMs with systemd
(`packaging/sandboxd.service`). There is no container image for `sandboxd`, no
chart, and no Kubernetes API integration.

There are two different asks hiding in "Kubernetes support", and this plan
keeps them separate:

| Ask | What the customer gets | Server risk |
|---|---|---|
| **A. Runs on Kubernetes** | One Helm chart installs AerolVM onto their existing cluster; they operate it with their existing tooling (Prometheus Operator, cert-manager, node pools). | Low — packaging + config only |
| **B. Managed through Kubernetes** | Sandboxes are Kubernetes objects: `kubectl get sandboxes`, RBAC, ArgoCD/Flux, status on the object. | Low (operator) → High (runtime driver) |

## 2. The constraint: sandboxd is a node agent, not a workload

`sandboxd` is its own scheduler (Raft placement + SWIM gossip in
`internal/cluster/`) and drives the host directly. Every host dependency
below is load-bearing — the chart must satisfy each one, or the feature it
backs is off.

| Host dependency | Code | Kubernetes answer |
|---|---|---|
| Container engine socket | `pkg/docker/`, `internal/runtime/containerd/` | hostPath-mount the node's containerd socket. We already use our own containerd namespace (`SB_CONTAINERD_NAMESPACE`, default `aerolvm`), disjoint from kubelet's `k8s.io`, so kubelet image GC does not touch our images and we do not touch its pods. |
| iptables chains, netns, TAP devices, host-port forwarder | `pkg/docker/netrules/`, `internal/network/{hostport,netns,tap,cni}/` | `privileged: true`, `hostNetwork: true`, `hostPID: true`. Coexistence with kube-proxy / the CNI's chains is the #1 risk (§7). |
| `/dev/kvm`, `/dev/net/tun`, Firecracker jailer | `internal/runtime/firecracker/`, `pkg/firecracker/` | hostPath device mounts; only on metal or nested-virt node pools. Firecracker is opt-in per node pool via `SB_HOST_RUNTIMES`. |
| FUSE / NFS / rclone mounts that must be visible to the engine | `pkg/mounts/`, `MountFlags=shared` in the systemd unit | `mountPropagation: Bidirectional` on `/var/lib/sandboxd/mounts`. |
| Local state: SQLite (`SB_DB_PATH`, single writer), Raft log (`SB_RAFT_DATA_DIR`), SSH host key, credential encryption key | `internal/store/`, `internal/cluster/`, `pkg/secrets/` | Node-pinned storage: hostPath `/var/lib/sandboxd` for workers (sandboxes are node-local anyway); a PVC per replica for servers. |
| Caddy admin API on `127.0.0.1:2019` (custom build with caddy-l4) | `pkg/caddy/` | Caddy as a sidecar in the same pod (shares the host network namespace). |
| Host capacity | `pkg/capacity/` | Already overridable: `SB_HOST_CPU_CORES`, `SB_HOST_MEMORY_MB`, `SB_HOST_DISK_GB`. The chart sets them to node allocatable minus a margin so we do not double-book what kubelet has handed out. **No code change needed.** |
| Cluster mTLS: `ca.crt`, `node.crt`, `node.key` in `SB_CLUSTER_TLS_DIR`; joiners sign CSRs via `scripts/cluster-sign-node.sh` | `internal/cluster/`, `internal/config/config.go` | cert-manager `Issuer` + `Certificate` per pod (§5.3). |
| Host binaries: `iptables`, `ip`, `mkfs.ext4`, `skopeo`, `umoci`, `runsc`, `firecracker`, `jailer`, `workerd` | `pkg/oci/builder.go`, `internal/runtime/*` | Baked into the new `sandboxd` image (§5.1). Kernel + rootfs templates stay on the node's hostPath. |

Consequence: **sandboxes are not pods.** Kubernetes schedules AerolVM;
AerolVM schedules sandboxes. That is the same contract as Longhorn, Cilium,
Falco or KubeVirt's `virt-handler` — a privileged DaemonSet on a dedicated,
tainted node pool — which platform teams already accept.

## 3. Options considered

| # | Option | Ask | Effort | Keeps sub-50ms create? | Verdict |
|---|---|---|---|---|---|
| 1 | **Helm chart** (servers = StatefulSet, workers = DaemonSet, ingress = Deployment) | A | S–M | Yes | **Do first (Phase 1)** |
| 2 | **Plugins on existing seams** (`pkg/controlplane`, secret provider, mount adapter, Gateway API) | A+B | S each | Yes | **Phase 2, pick by demand** |
| 3 | **Operator + CRDs** (`Sandbox`, `SandboxTemplate`, `SandboxPool`) over the Go SDK | B | M | Yes | **Phase 3** |
| 4 | **Kubernetes runtime driver** — `internal/runtime/kubernetes`, one Pod per sandbox via RuntimeClass (gVisor/Kata) | B (full) | L | No — pod scheduling is ~1–3s without a pre-created pod pool; `CreateSnapshot` has no clean equivalent | Deferred; only on enterprise demand |
| 5 | **containerd shim / RuntimeClass** exposing our Firecracker snapshot-boot as `runtimeClassName: aerolvm-fc` | B (full) | XL | Yes | Deferred; this is the strategic pivot `engineering-runtime-layers.mdx` warns about |

Also worth tracking before building 3–5: the upstream
`kubernetes-sigs/agent-sandbox` project defines a Sandbox CRD for exactly this
use case. Aligning our CRD shape with it (or implementing its API) may be
cheaper and more credible than inventing our own. **Open question Q1.**

## 4. Phases

| Phase | Deliverable | Server code touched | Exit gate |
|---|---|---|---|
| 0 | Decisions: Q1–Q5 answered in this doc | none | eng-review cleared |
| 1 | `sandboxd` image + Helm chart, single-node + 3-server cluster | none expected (config only); small fixes if the live run finds any | `k8s-single` and `k8s-cluster-3` integration scenarios green on EKS (§6) |
| 2 | Plugins (§5.5), one PR each | `pkg/controlplane`, `pkg/secrets`, `pkg/mounts/adapters` | each ships with tests at the 85% bar |
| 3 | Operator (§5.6) | none (SDK client only) | CRD round-trip scenario green; retries and duplicate creates proven idempotent |
| 4+ | Runtime driver / shim | `internal/runtime/` | separate plan, only if Phase 3 customers ask for sandboxes-as-pods |

Phase 1 ships as a stacked series
(image → chart → integration scenario → docs) and nothing merges until the
whole stack is green.

## 5. Design

### 5.1 Container image — `ghcr.io/aerol-ai/sandboxd`

- New `packaging/docker/Dockerfile`, multi-stage. Final stage is a slim
  Debian (not distroless) because we shell out to `iptables`, `ip`,
  `mkfs.ext4`, `skopeo`, `umoci`.
- Build variants by tag so the base image stays small:
  `:vX.Y.Z` (docker/containerd + gVisor), `:vX.Y.Z-firecracker` (+
  `firecracker`, `jailer`), `:vX.Y.Z-isolate` (+ `workerd`). Kernel images and
  rootfs templates are **not** baked in — they live on the node's hostPath
  and are fetched by an init container, same as `install.sh` does today.
- Caddy sidecar image: the same custom caddy-l4 build `install.sh` downloads,
  published as `ghcr.io/aerol-ai/caddy-l4`.
- `toolboxd` is bind-mounted into sandboxes from the host today
  (`pkg/docker/client.go`); the init container copies it from the image onto
  the node's hostPath so that path stays the same.
- Published by `release.yml` next to the existing binaries (multi-arch
  amd64/arm64).

### 5.2 Chart topology — `deploy/helm/aerolvm/`

Maps 1:1 onto the existing `SB_NODE_ROLE` split (`internal/config/config.go`):

```
                 LoadBalancer Service (80/443, L4 range)
                               │
                  ┌────────────▼────────────┐
                  │ ingress  (Deployment)   │  SB_NODE_ROLE=ingress
                  │ sandboxd + caddy sidecar│  unprivileged, no hostPath
                  └────────────┬────────────┘
                               │ mTLS :7002
      ┌────────────────────────┼────────────────────────┐
┌─────▼──────────────┐                        ┌─────────▼──────────────────┐
│ server (StatefulSet│  Raft :7000            │ worker (DaemonSet)         │
│ 3 or 5 replicas)   │◄──── SWIM :7001 ──────►│ nodeSelector aerolvm/worker│
│ PVC per replica    │                        │ privileged, hostNetwork    │
│ headless Service   │                        │ hostPath /var/lib/sandboxd │
│ unprivileged       │                        │ containerd sock, /dev/kvm  │
└────────────────────┘                        │ + caddy sidecar            │
                                              └────────────────────────────┘
```

- **server**: `SB_NODE_ROLE=server`, `SB_NODE_ID=$(POD_NAME)` (stable via
  StatefulSet), `SB_RAFT_ADVERTISE_ADDR` / `SB_GOSSIP_ADVERTISE_ADDR` =
  `$(POD_NAME).aerolvm-server.<ns>.svc`. Pod `-0` sets
  `SB_CLUSTER_BOOTSTRAP=true` on first start only; the others get
  `SB_BOOTSTRAP_PEERS` = the headless Service's DNS names. Replicas are pinned
  to 3 or 5 (voter count is fixed by design; `SB_CLUSTER_MAX_AUTO_VOTERS`).
  PodDisruptionBudget `maxUnavailable: 1`. Anti-affinity across zones.
- **worker**: DaemonSet on nodes labelled `aerolvm.io/worker=true` and
  tainted `aerolvm.io/worker:NoSchedule`, so ordinary pods never land on
  nodes that AerolVM has sized as its own. `SB_NODE_ID=$(NODE_NAME)` via the
  downward API — stable across pod restarts, which Raft placement needs
  because it records the owning node. `SB_HOST_CPU_CORES` /
  `SB_HOST_MEMORY_MB` come from chart values (default: node allocatable − a
  margin for the DaemonSet itself). `terminationGracePeriodSeconds` long
  enough to drain; a `preStop` hook drains the node the way `scripts/sandboxd-node-lifecycle.sh` does.
- **ingress**: Deployment, `SB_NODE_ROLE=ingress`, behind a LoadBalancer
  Service (or the customer's Gateway). Needs no host privileges.
- **Small clusters**: `mode: mixed` values preset runs one DaemonSet with
  `SB_NODE_ROLE=mixed` for ≤10 nodes, matching the topology rule in
  `config.go`. `mode: single` runs one privileged pod with
  `SB_ENABLE_CLUSTER=false` for evaluation.
- Monitoring: `ServiceMonitor` over the existing expvar/OTEL endpoints,
  `PrometheusRule` generated from `setup/prometheus/`, Grafana dashboards from
  `setup/grafana/` as ConfigMaps with the sidecar label. `/health` backs the
  liveness/readiness probes (already documented for this in
  `pkg/api/server.go`).
- Upgrades: DaemonSet `updateStrategy: OnDelete` by default. A rolling
  restart that bounces every SWIM member can split the cluster (seen live in
  the v0.7.10 WASM deploy — restarting the seed last orphaned the joiners),
  so upgrades go node by node through a documented runbook, not a blind
  rollout.

### 5.3 Cluster TLS via cert-manager

The daemon only needs `ca.crt`, `node.crt` and `node.key` in
`SB_CLUSTER_TLS_DIR`; it does not care how they got there. The chart ships a
cert-manager `Issuer` (CA-backed, CA key held in a Kubernetes Secret or an
external issuer such as Vault / AWS PCA) and one `Certificate` per server
pod and per worker node, with the `aerolvm-cluster-node` SAN that
`scripts/cluster-sign-node.sh` issues today. The CA private key never reaches
a node — the same invariant the enterprise mode enforces. No daemon change,
provided the daemon reloads rotated certs; **Q3 checks whether it does.**

### 5.4 What stays out of the chart

- Sandbox networking: sandboxes keep AerolVM's own bridge/CNI and iptables
  chains; they do **not** get pod IPs from the cluster CNI in Phases 1–3.
- Sandbox images: pulled into the `aerolvm` containerd namespace by sandboxd,
  as today. Registry mirror settings (`SB_MIRROR_UPSTREAMS`) are chart values.

### 5.5 Plugins on existing seams (Phase 2)

Each is independent and ships behind config, off by default:

| Plugin | Seam | Behaviour |
|---|---|---|
| ServiceAccount auth | `controlplane.Validator` | Validate a projected SA token via the TokenReview API, map `namespace/sa` to an AerolVM identity; in-cluster callers need no API key. |
| Namespace quotas | `controlplane.Admitter` | Admit a create only if the caller's namespace has headroom under an `aerolvm.io/*` ResourceQuota. Must stay off the boot path unless enabled, and cached when on (boot-latency rule). |
| Kubernetes secret provider | `SB_SECRET_PROVIDER=kubernetes` (next to `local`) | Credential-encryption key and sealed secrets backed by a Kubernetes Secret / KMS plugin instead of a node file. |
| PVC / CSI mount adapter | `pkg/mounts/adapters/` via `/add-mount-adapter` | Mount a pre-bound PVC's node path into a sandbox. Host-side threat model from `pr-review.md` §5 applies. |
| Gateway API routes | new, alongside `pkg/caddy` | Optionally publish exposed ports as `HTTPRoute` / `TLSRoute` so customers keep their own ingress + cert-manager. Caddy stays the default. |
| Usage + audit export | `controlplane.Reporter`, `AuditExporter` | Emit to the cluster's Prometheus / log pipeline. |

All `pkg/controlplane` defaults stay no-op; the open-source build must not
require a Kubernetes API server.

### 5.6 Operator (Phase 3) — `cmd/aerolvm-operator`

- controller-runtime, talks to AerolVM only through `sdk/go` (no internal
  imports), so it works against any AerolVM — in-cluster or external VMs.
- CRDs (group `aerolvm.io`, `v1alpha1`): `Sandbox` (spec ≈
  `models.CreateSandboxRequest`, status = state, URLs, owner node),
  `SandboxTemplate`, `SandboxPool` (maintain N warm sandboxes).
- **AerolVM remains the source of truth** (no parallel store, same rule as the
  Daytona/E2B facades). The CR is a declarative facade; the
  reconciler converges AerolVM to it and mirrors status back.
- Idempotency: sandbox ID derived from the CR's UID and created with
  `CreateSandboxWithID`, so a retry or duplicate reconcile returns the
  existing sandbox. A finalizer deletes the sandbox before the CR goes away;
  delete of an already-gone sandbox is success.
- Drift: a sandbox deleted out-of-band marks the CR `Lost`; it is not
  silently recreated (recreation would lose state the user expected to keep).

## 6. Testing

- **Offline (`make test`)**: `helm lint` + `helm template` golden tests in
  CI; `kubeconform` against the rendered manifests. Plugin and operator code
  gets unit tests at the 85% bar (envtest for the operator; fake
  clientset for TokenReview/ResourceQuota). No cluster needed.
- **kind smoke test** (CI job, tag-gated): `mode: single` on kind with the
  docker/containerd runtime — create, exec, expose_port, delete through each
  SDK. Proves the image, privileges and mounts; no Firecracker.
- **Live (`integration-tests/`)**: new `k8s-single` and `k8s-cluster-3`
  scenarios on EKS behind the `integration` tag, reusing the existing UC
  catalogue so results compare 1:1 with the VM scenarios. Must include:
  pod restart of a worker (sandbox survives), server-pod reschedule (Raft
  stays healthy), a node-by-node upgrade, and iptables coexistence with both
  kube-proxy (iptables mode) and Cilium.
- Firecracker on Kubernetes gets its own scenario on a metal node pool once
  the metal vCPU quota allows it (see `plans/arm64-firecracker-hosts.md`).

## 7. Risks

| Risk | Mitigation |
|---|---|
| Our iptables chains vs kube-proxy / CNI chains (ordering, flushes, nftables vs legacy backends — `pkg/docker/netrules/legacy_check.go` already detects the backend) | Dedicated tainted node pool; live test against kube-proxy and Cilium; document supported CNIs. |
| Worker pod restart while sandboxes run | Sandboxes are owned by containerd/VMM, not the pod, so they survive; reconcile on restart already exists. Needs an explicit live test. |
| Raft voters rescheduled with a new identity | StatefulSet stable names + PVCs; servers never on spot nodes (chart default affinity). |
| Capacity double-booked with kubelet | Taint the node pool; set `SB_HOST_*` from allocatable. |
| Rolling upgrade splits SWIM | `OnDelete` strategy + runbook (§5.2). |
| Customers expect sandboxes to be pods (NetworkPolicy, pod security) | Say so plainly in docs: Phases 1–3 do not do this; Phase 4 would. |
| Privileged DaemonSet rejected by Pod Security Admission `restricted` | Chart namespace carries `pod-security.kubernetes.io/enforce: privileged`; document it. |

## 8. Open questions

- **Q1.** Adopt `kubernetes-sigs/agent-sandbox`'s CRD shape for Phase 3, or
  ship our own `aerolvm.io` group?
- **Q2.** Chart location: `deploy/helm/aerolvm/` in this repo (versioned with
  the daemon) or a separate charts repo? Recommendation: this repo.
- **Q3.** Does the daemon hot-reload rotated certs in `SB_CLUSTER_TLS_DIR`,
  or does cert-manager rotation need a pod restart? (Read `internal/cluster`
  TLS loading before Phase 1 is locked.)
- **Q4.** Minimum Kubernetes version and supported managed offerings for v1:
  proposed EKS + GKE, 1.29+.
- **Q5.** Do workers share the node's containerd (hostPath socket, separate
  namespace) or run their own containerd inside the pod? Recommendation:
  share — no second engine per node, and the namespace split already
  isolates us.

## 9. NOT in scope

- Sandboxes as pods (Option 4) and the containerd shim (Option 5).
- A managed Kubernetes offering or marketplace listing.
- Replacing Raft placement with the Kubernetes scheduler.
- Windows or non-Linux nodes.
