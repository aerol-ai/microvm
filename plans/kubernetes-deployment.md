# Kubernetes deployment — run AerolVM on, and serve the Kubernetes Sandbox API from, Kubernetes

**Status:** CEO-REVIEWED (2026-09-30, SCOPE EXPANSION). Not eng-reviewed.
Nothing below is built. Decisions D2–D14 from the review are binding and listed
in §0; `/plan-eng-review` is the next required gate.
**Related:** `plans/data-plane-load-balancer.md` (server/worker/ingress role
split this plan maps onto), `plans/containerd-engine.md` (the engine a
Kubernetes node already runs), `plans/integration-tests.md` (where the new
scenarios land), `docs/src/content/docs/engineering-runtime-layers.mdx`
(why we drive Firecracker directly instead of via Kata),
`plans/sdk-compatibility/` (the Daytona/E2B facade model this plan reuses).

## 0. Decisions (CEO review, 2026-09-30)

| ID | Decision | Answer |
|---|---|---|
| D2 | Approach | **C** — Helm chart first, then implement the upstream `kubernetes-sigs/agent-sandbox` API (`agents.x-k8s.io`) backed by AerolVM. No `aerolvm.io` CRDs of our own. |
| D4.1 | Husk-pod mode (every sandbox is a real, unprivileged pod) | Added — Phase 4 |
| D4.2 | Daytona → AerolVM migration path | Added — Phase 1b |
| D4.3 | Signed supply chain (cosign, SBOM, SLSA provenance) | Added — Phase 1 |
| D4.4 | agent-sandbox conformance suite + upstream backend listing | Added — Phase 3 |
| D4.5 | `make k8s-dev` kind quickstart + `kubernetes.mdx` | Added — Phase 1 |
| D4.6 | EKS add-on + GKE Marketplace listing | Added — Phase 5 (gated by D9) |
| D5 | How we serve agent-sandbox | Our own `aerolvm-controller` reconciles the `agents.x-k8s.io` CRDs; the upstream controller is **not** installed and a pre-install check refuses to coexist with it. |
| D6 | Worker node certificates | Init container sends a CSR + projected SA token; the controller TokenReviews it and signs `node:<id>` **only if** `<id>` equals the bound pod's `spec.nodeName`. |
| D7 | Husk-pod placement authority | kube-scheduler places husk pods; claiming one writes a Raft placement **pinned** to that pod's node; husk capacity comes from pod requests, not `SB_HOST_*`. |
| D8 | Readiness | New cluster-aware `/ready` with an election grace window, in Phase 1. |
| D9 | Licensing | Single/mixed chart modes ship now; the server/worker/ingress cluster preset and Phase 5 are blocked until PR #223 is merged or closed. |
| D10 | Controller identity | Namespace = AerolVM owner (`OwnerRef k8s:<cluster-id>/<namespace>`), never the operator PAT. |
| D11 | CA key custody | External signer (cert-manager Issuer backed by Vault / AWS PCA / GCP CAS). A Secret-held CA only with `ca.mode: in-cluster` + loud warning; cluster mode refuses to start without an external issuer by default. |
| D12 | Scale contract for the CR path | Status writes coalesced; tested ceiling (target 10k live `Sandbox` objects per cluster) documented; high-churn ephemeral creates pointed at the SDK path. |
| D13 | Observability | Metrics + alerts + dashboard + runbook for controller, signer, husk pool and `/ready`, shipped in the chart. |
| D14 | Upstream coexistence | TODO: propose a `controllerName` class field upstream (TODOS.md). |

## 1. Why

Buyers trust Kubernetes. "Can I `helm install` it into my cluster?" and "can I
manage sandboxes with `kubectl` / GitOps?" come up before any benchmark does.
Today the only supported install paths are `scripts/install.sh`, Ansible
(`Ansible/playbooks/`) and Terraform (`Terraform/`) onto bare VMs with systemd
(`packaging/sandboxd.service`). There is no container image for `sandboxd`, no
chart, and no Kubernetes API integration.

### 1.1 Landscape (checked 2026-09-30)

- **kubernetes-sigs/agent-sandbox** (SIG Apps) is the Kubernetes-standard
  Sandbox API: v1.0.2, API `agents.x-k8s.io/v1beta1`, CRDs `Sandbox`,
  `SandboxTemplate`, `SandboxClaim`, `SandboxWarmPool`; gVisor or Kata via
  RuntimeClass; pause/resume; Go and Python SDKs.
  <https://github.com/kubernetes-sigs/agent-sandbox>,
  <https://kubernetes.io/blog/2026/03/20/running-agents-on-kubernetes-with-agent-sandbox>
- **GKE Agent Sandbox** claims 300 sandboxes/s per cluster, 90% of warm-pool
  allocations within 200ms, plus GKE-only Pod Snapshots.
  <https://cloud.google.com/blog/products/containers-kubernetes/bringing-you-agent-sandbox-on-gke-and-agent-substrate>
- **Mitos** (Apache-2.0, v0.3, pre-1.0) runs Firecracker snapshot restore on
  Kubernetes as "husk pods" (one unprivileged pod per VM, `/dev/kvm` from a
  device plugin), ~27ms p50 warm claim, and ships an agent-sandbox conformance
  facade. <https://pkg.go.dev/github.com/paperclipinc/mitos>
- **Daytona** reportedly took its codebase closed-source in June 2026; Helm
  self-hosters are left on v0.190.0. **E2B** self-hosts on Nomad only, AWS/GCP
  only. <https://www.morphllm.com/comparisons/e2b-vs-daytona>,
  <https://helix.ml/blog/self-hosted-agent-sandboxes> (Daytona claim to be
  re-verified before Phase 1b marketing — T9.)

**Position:** AerolVM is the backend that already speaks every sandbox API a
buyer uses (agent-sandbox, Daytona, E2B, our SDKs) across five runtimes
(containerd, gVisor, Firecracker, WASM, V8 isolates) — GKE has one, Mitos has
one.

## 2. The constraint: sandboxd is a node agent, not a workload

`sandboxd` is its own scheduler (Raft placement + SWIM gossip in
`internal/cluster/`) and drives the host directly. Every host dependency
below is load-bearing — the chart must satisfy each one, or the feature it
backs is off.

| Host dependency | Code | Kubernetes answer |
|---|---|---|
| Container engine socket | `pkg/docker/`, `internal/runtime/containerd/` | hostPath-mount the node's containerd socket. We already use our own containerd namespace (`SB_CONTAINERD_NAMESPACE`, default `aerolvm`), disjoint from kubelet's `k8s.io`, so kubelet image GC does not touch our images and we do not touch its pods. |
| iptables chains, netns, TAP devices, host-port forwarder | `pkg/docker/netrules/`, `internal/network/{hostport,netns,tap,cni}/` | `privileged: true`, `hostNetwork: true`, `hostPID: true`. Coexistence with kube-proxy / the CNI's chains is the #1 risk (§8). |
| `/dev/kvm`, `/dev/net/tun`, Firecracker jailer | `internal/runtime/firecracker/`, `pkg/firecracker/` | hostPath device mounts; only on metal or nested-virt node pools. Firecracker is opt-in per node pool via `SB_HOST_RUNTIMES`. Phase 4 moves this to a device plugin. |
| FUSE / NFS / rclone mounts that must be visible to the engine | `pkg/mounts/`, `MountFlags=shared` in the systemd unit | `mountPropagation: Bidirectional` on `/var/lib/sandboxd/mounts`. |
| Local state: SQLite (`SB_DB_PATH`, single writer), Raft log (`SB_RAFT_DATA_DIR`), SSH host key, credential encryption key | `internal/store/`, `internal/cluster/`, `pkg/secrets/` | Node-pinned storage: hostPath `/var/lib/sandboxd` for workers; a PVC per replica for servers. |
| Caddy admin API on `127.0.0.1:2019` (custom build with caddy-l4) | `pkg/caddy/` | Caddy as a sidecar in the same pod. |
| Host capacity | `pkg/capacity/` | Already overridable: `SB_HOST_CPU_CORES`, `SB_HOST_MEMORY_MB`, `SB_HOST_DISK_GB`. The chart sets them to node allocatable minus a margin. **No code change needed.** |
| Cluster mTLS: `ca.crt`, `node.crt`, `node.key` in `SB_CLUSTER_TLS_DIR`; certs must carry DNS/URI SAN `node:<SB_NODE_ID>` plus `aerolvm-cluster-node` | `internal/cluster/tls.go` (`nodeIDSANprefix`, `ExtractPeerNodeID`) | Per-node issuance by the controller signer (§5.3, D6/D11). Leaf/key files hot-reload per handshake (`tls.go` `certificateForHandshake`), so rotation needs no restart. |
| Host binaries: `iptables`, `ip`, `mkfs.ext4`, `skopeo`, `umoci`, `runsc`, `firecracker`, `jailer`, `workerd` | `pkg/oci/builder.go`, `internal/runtime/*` | Baked into the `sandboxd` image (§5.1). |

Consequence for Phases 1–3: **sandboxes are not pods.** Kubernetes schedules
AerolVM; AerolVM schedules sandboxes — the Longhorn / Cilium / KubeVirt
`virt-handler` pattern. Phase 4 (husk pods, D4.1) makes sandboxes real pods
for buyers who need Kubernetes quotas, NetworkPolicy and pod security to
apply per sandbox.

## 3. Options considered

| # | Option | Effort | Verdict |
|---|---|---|---|
| A | Helm chart only | S–M | Rejected as the whole plan (no `kubectl`/GitOps story); kept as Phase 1 |
| B | Helm + plugins + our own `aerolvm.io` operator/CRDs | M | Rejected (D2): competes with the Kubernetes-standard API |
| **C** | **Helm + agent-sandbox API facade + husk pods** | L | **Chosen (D2)** |
| — | containerd shim / RuntimeClass (`runtimeClassName: aerolvm-fc`) under the upstream controller | XL | Rejected for now (D5): the strategic pivot `engineering-runtime-layers.mdx` warns about; revisit only if D14's upstream class field never lands |

Correction to the pre-review draft: sandboxes-as-pods does **not** have to
lose sub-50ms creates. A warm pool of pre-created husk pods keeps the
Kubernetes scheduling cost off the request path (Mitos: ~27ms p50).

## 4. Phases

| Phase | Deliverable | Server code touched | Exit gate |
|---|---|---|---|
| 1 | `sandboxd` + `caddy-l4` images (signed, SBOM, provenance); Helm chart `single` + `mixed` modes; `/ready`; `make k8s-dev` + `kubernetes.mdx` | `pkg/api` (`/ready`) | kind smoke green in CI; `k8s-single` live scenario green on EKS; `cosign verify` documented and passing |
| 1b | Daytona migration: `daytona-compat` values preset, migration guide, Daytona SDK smoke against the chart | none (facade exists) | Daytona SDK smoke green against a Helm install; facade coverage vs v0.190 recorded in `plans/sdk-compatibility/` |
| 2 | `aerolvm-controller` part 1: node-cert signer (D6/D11) + cluster chart preset (server STS / worker DS / ingress Deployment) | `pkg/controlplane` (scoped controller identity, D10) | **Blocked by D9.** `k8s-cluster-3` live scenario green incl. chaos step (§7) |
| 3 | `aerolvm-controller` part 2: agent-sandbox facade; conformance CI; upstream listing PR; D12 scale bench; plugins (§5.6) | `pkg/controlplane` Validator/Admitter paths | Upstream agent-sandbox e2e/examples pass on kind; 10k-object bench recorded |
| 4 | Husk-pod mode: warm husk pool, `/dev/kvm` device plugin, pinned Raft placement, NetworkPolicy egress | `internal/cluster` (pinned placement — fragile area), `internal/pool`, new runtime mode | Warm claim p50 ≤ 50ms on kind+KVM and EKS metal; placement regression test next to `placement.go`; eviction → `Lost` test |
| 5 | EKS add-on + GKE Marketplace | none | **Blocked by D9.** Listing live; install-from-marketplace smoke green |

Phases ship as stacked PRs; nothing merges until its phase's whole stack is
green.

## 5. Design

### 5.1 Images and supply chain (Phase 1, D4.3)

- `packaging/docker/Dockerfile`, multi-stage, slim Debian final stage (we
  shell out to `iptables`, `ip`, `mkfs.ext4`, `skopeo`, `umoci`). Tags:
  `:vX.Y.Z`, `:vX.Y.Z-firecracker`, `:vX.Y.Z-isolate`. Kernel images and
  rootfs templates stay on the node's hostPath, fetched by an init container.
- `ghcr.io/aerol-ai/caddy-l4`: the same custom Caddy build `install.sh` uses.
- `toolboxd` is copied by the init container onto the node's hostPath so the
  bind-mount path used today (`pkg/docker/client.go`) stays the same.
- `release.yml`: multi-arch build; **cosign keyless** signatures on images and
  the OCI-hosted Helm chart; SBOM (syft) and SLSA provenance attached; docs
  show `cosign verify`; the chart ships an example Kyverno / Sigstore policy.

### 5.2 Chart topology — `deploy/helm/aerolvm/`

```
                 LoadBalancer Service (80/443, L4 range)
                               │
                  ┌────────────▼────────────┐
                  │ ingress  (Deployment)   │  SB_NODE_ROLE=ingress
                  │ sandboxd + caddy sidecar│  unprivileged
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

- **Modes:** `single` (one privileged pod, `SB_ENABLE_CLUSTER=false`,
  evaluation and kind), `mixed` (one DaemonSet, `SB_NODE_ROLE=mixed`, ≤10
  nodes per `config.go`'s topology rule), `cluster` (below; **D9-gated**).
- **server**: `SB_NODE_ROLE=server`, `SB_NODE_ID=$(POD_NAME)`, advertise addrs
  = `$(POD_NAME).aerolvm-server.<ns>.svc`; pod `-0` bootstraps on first start
  only, others use `SB_BOOTSTRAP_PEERS`. 3 or 5 replicas (voter count is fixed
  by design). PDB `maxUnavailable: 1`, zone anti-affinity, never on spot.
- **worker**: DaemonSet on nodes labelled `aerolvm.io/worker=true`, tainted
  `aerolvm.io/worker:NoSchedule`. `SB_NODE_ID=$(NODE_NAME)` — stable across
  pod restarts, which Raft placement needs. `SB_HOST_*` from values (node
  allocatable − margin). `preStop` drains the node.
- **ingress**: Deployment, `SB_NODE_ROLE=ingress`, LoadBalancer Service.
- **Probes:** liveness `/health`, readiness **`/ready`** (§5.4).
- **Monitoring (D13):** ServiceMonitor, PrometheusRule (existing
  `setup/prometheus/` rules + new ones in §9), Grafana dashboards as
  ConfigMaps.
- **Upgrades:** DaemonSet `updateStrategy: OnDelete`; node-by-node runbook
  (a rolling restart of every SWIM member split the cluster in the v0.7.10
  WASM deploy). The chart pins the agent-sandbox CRD version; `helm rollback`
  does **not** revert CRDs, so CRD bumps go through the conformance job.
- Namespace carries `pod-security.kubernetes.io/enforce: privileged`.

### 5.3 `aerolvm-controller` (Phases 2–4)

One binary, **three reconcilers with separate RBAC**, 2 replicas with
controller-runtime leader election. It talks to AerolVM only through `sdk/go`
(no `internal/` imports).

**(a) Node-cert signer (D6, D11).**

```
worker init container                  aerolvm-controller              external issuer
  │ gen node.key + CSR(node:<NODE_NAME>)       │                         (Vault/PCA/CAS)
  │ + projected SA token (audience=aerolvm) ──►│
  │                                            │ TokenReview ─► kube-apiserver
  │                                            │ pod = token.boundObjectRef
  │                                            │ require pod.spec.nodeName == CSR id
  │                                            │ require pod in aerolvm ns + worker SA
  │                                            │── sign(CSR, SANs) ────────►│
  │◄──────────────── node.crt ─────────────────│◄───────────────────────────│
  │ write SB_CLUSTER_TLS_DIR; sandboxd starts  │ deny → event + metric + ALERT
```

Servers and ingress (stable pod names) use the same path with
`id == pod name`. CA private key never enters the cluster unless
`ca.mode: in-cluster` (dev only, loud warning).

**(b) agent-sandbox facade (D2, D5, D10, D12).**
- Installs the pinned `agents.x-k8s.io` CRDs; pre-install hook fails if the
  upstream agent-sandbox controller Deployment exists.
- Calls AerolVM as `OwnerRef k8s:<cluster-id>/<namespace>` via a scoped
  identity the controlplane Validator mints for the controller's SA only;
  never the operator PAT. Cross-namespace lookups 404.
- Mapping: `SandboxTemplate` → `models.CreateSandboxRequest` template;
  `SandboxWarmPool` → AerolVM warm-pool target for that template;
  `SandboxClaim` → acquire from that pool; `Sandbox` → create/pause/resume/
  delete. Exact field table is an eng-review deliverable (T11).
- Sandbox ID = derived from the CR UID; created with `CreateSandboxWithID`, so
  retries and duplicate reconciles return the existing sandbox. Finalizer
  deletes; deleting an already-gone sandbox is success.
- Immutable spec fields are rejected by a validating webhook; resize fields
  call `Resize`.
- Status: conditions with named reasons (`BackendUnavailable`,
  `CreateRejected`, `Lost`, `Ready`); writes coalesced to phase changes, max
  one per object per interval (D12). Out-of-band deletion → `Lost`, never
  silent recreation.

**(c) Husk-pod manager (Phase 4, D4.1, D7).** See §5.5.

### 5.4 `/ready` (Phase 1, D8)

- `/health` stays liveness (process up).
- `/ready` returns 503 when, in cluster mode, the node is not a Raft member or
  has seen no leader for longer than a grace window (default 10s, above
  normal election time); single-node mode mirrors `/health`.
- Used by Kubernetes readiness, the VM installs and Caddy upstream health —
  it also closes the open TODO "A partitioned node keeps serving".

### 5.5 Husk-pod mode (Phase 4, D4.1, D7)

```
 SandboxWarmPool / AerolVM pool target
          │ desired N
          ▼
 husk manager ── creates N husk pods (unprivileged, /dev/kvm via device
          │       plugin, requests = template size, PriorityClass high, PDB)
          ▼
 kube-scheduler places each husk ──► node X
          │
 claim ──►│ pick Ready husk on any node
          │ Raft: placement PINNED to husk's node (no power-of-two choice)
          │ worker on node X adopts husk: loads snapshot / starts container
          ▼
 sandbox Running inside pod ──► NetworkPolicy governs egress
```

Husk state machine:

```
 Pending ──scheduled──► Warm ──claimed──► Bound ──sandbox up──► Running
    │                     │                 │                     │
    └─unschedulable──►Failed└──evicted──►(replaced)  evicted/node lost ──► Lost
                                                     (Raft placement released,
                                                      CR status Lost, metric)
 Invalid: Bound→Warm (never re-pooled after a claim), Running→Warm.
```

- Capacity for husk sandboxes comes from pod requests; `SB_HOST_*` accounting
  excludes husk capacity so nothing is counted twice.
- The pinned-placement path is new Raft FSM behaviour → regression test next
  to `placement.go` / `fsm_*_test.go` and a PR call-out (CLAUDE.md fragile
  area rule). Non-husk sandboxes keep today's placement unchanged.
- Separate design doc required before Phase 4 build: snapshot/restore into a
  husk, re-binding after a worker restart, NetworkPolicy vs our netrules.

### 5.6 Plugins on existing seams (Phase 3)

| Plugin | Seam | Behaviour |
|---|---|---|
| Controller namespace identity (D10) | `controlplane.Validator` | Mint `k8s:<cluster-id>/<ns>` owner identities, only for the controller SA |
| ServiceAccount auth for in-cluster SDK callers | `controlplane.Validator` | TokenReview a projected SA token → namespace owner |
| Namespace quotas | `controlplane.Admitter` | Admit against an `aerolvm.io/*` ResourceQuota; cached; off unless enabled |
| Kubernetes secret provider | `SB_SECRET_PROVIDER=kubernetes` | Credential key / sealed secrets via Secret + KMS plugin |
| PVC / CSI mount adapter | `pkg/mounts/adapters/` via `/add-mount-adapter` | Mount a pre-bound PVC's node path into a sandbox |
| Gateway API routes | new, alongside `pkg/caddy` | Optional `HTTPRoute`/`TLSRoute` for exposed ports |

All `pkg/controlplane` defaults stay no-op; the open-source build must not
require a Kubernetes API server.

### 5.7 Daytona migration (Phase 1b, D4.2)

`values-daytona-compat.yaml` enables `/daytona` routes and maps the Daytona
chart's common knobs (registry, resource defaults, domain) to ours; a
migration guide (5-language tabs) shows swapping charts while keeping Daytona
SDK code; a live scenario runs the Daytona SDK smoke against the Helm install.

### 5.8 Marketplace (Phase 5, D4.6, D9-gated)

EKS add-on and GKE Marketplace packaging of the Phase 1–3 chart. Needs the
license decision (PR #223), vendor onboarding and billing metering first.

## 6. What already exists (reuse map)

| Need | Existing code | Reused? |
|---|---|---|
| Role split for server/worker/ingress | `SB_NODE_ROLE` in `internal/config/config.go` | Yes, 1:1 |
| Capacity override | `SB_HOST_CPU_CORES/MEMORY_MB/DISK_GB` | Yes, no code change |
| Separate containerd namespace | `SB_CONTAINERD_NAMESPACE=aerolvm` | Yes |
| Cert hot-reload + node-id SAN check | `internal/cluster/tls.go` | Yes |
| Owner scoping | `controlplane.Identity.OwnerRef`, `Access` | Yes (D10) |
| Idempotent create by ID | `Service.CreateSandboxWithID` | Yes (facade) |
| Warm pools | `internal/pool/{vmm,wasm,isolate}`, docker/containerd warm pools | Yes (SandboxWarmPool, husks) |
| Translate-don't-duplicate facades | `pkg/api/daytona`, planned `/e2b` | Pattern reused |
| Alerts / dashboards | `setup/prometheus/`, `setup/grafana/` | Extended |
| Live AWS harness | `integration-tests/` | New `k8s-*` scenarios |

## 7. Testing

- **Offline (`make test`):** `helm lint` + `helm template` golden tests;
  `kubeconform`. Controller: envtest. Tests that must exist:
  - signer: node-name mismatch → denied; token for another pod → denied;
    wrong audience → denied; external issuer down → retried, no cert written.
  - facade: namespace A cannot get/exec/delete namespace B's sandbox (404);
    duplicate reconcile returns the same sandbox; CR deleted mid-create leaks
    nothing; immutable-field edit rejected; status write coalescing.
  - `/ready`: election within grace stays ready; partition past grace → 503;
    single-node mirrors `/health`.
  - husk (Phase 4): pinned-placement regression next to `placement.go`;
    eviction → `Lost` + placement released; Bound never returns to Warm.
- **kind (CI, tag-gated):** `make k8s-dev` path — single mode, create/exec/
  delete through each SDK; upstream agent-sandbox e2e/examples against the
  facade (conformance, D4.4).
- **Live (`integration-tests/`, `integration` tag):** `k8s-single`,
  `k8s-cluster-3` on EKS reusing the UC catalogue. Must include worker pod
  restart (sandbox survives), server-pod reschedule, node-by-node upgrade,
  iptables coexistence with kube-proxy (iptables mode) and Cilium, and the
  **chaos step**: delete the leader server pod and one worker pod during 50
  concurrent claims → zero duplicate sandboxes, zero lost claims.
- **Scale (D12):** 10k live `Sandbox` objects; record API-server write QPS
  and etcd size; publish the ceiling.
- Firecracker on Kubernetes: own scenario on a metal node pool once the metal
  vCPU quota allows it (`plans/arm64-firecracker-hosts.md`).

## 8. Risks

| Risk | Mitigation |
|---|---|
| Our iptables chains vs kube-proxy / CNI chains | Dedicated tainted pool; live test vs kube-proxy and Cilium; supported-CNI list |
| Worker pod restart while sandboxes run | Sandboxes owned by containerd/VMM, not the pod; reconcile on restart; live test |
| Forged node identity | D6 TokenReview + node match; D11 external CA; denial alert |
| Cross-namespace access through CRs | D10 namespace owners; isolation test |
| Customer etcd/API-server load | D12 coalescing + published ceiling |
| Two controllers for one CRD | D5 pre-install refusal; D14 upstream class field |
| Upstream v1beta1 API drift | Pinned CRDs; conformance job per bump |
| Rolling upgrade splits SWIM | `OnDelete` + runbook |
| Husk vs Raft placement disagreement | D7 single authority + regression test |
| Privileged DaemonSet rejected by PSA / security review | Privileged namespace label documented; signed images + SBOM (D4.3); minimal worker RBAC |
| Licensing ambiguity | D9 gate |

## 9. Observability (D13)

- **Metrics:** reconcile latency and errors by reason; facade drift (CR vs
  AerolVM mismatch count); signer approvals/denials by reason; husk pool
  depth, hit, miss, evictions; `/ready` transitions.
- **Alerts:** any signer denial (possible impersonation); reconcile error
  rate; husk pool empty for > N min; `/ready` flapping.
- **Dashboard:** one "AerolVM on Kubernetes" Grafana board.
- **Runbook:** `setup/runbooks/kubernetes.md` — one response per alert.

## 10. Open questions (for eng review)

- **Q2.** Chart location: `deploy/helm/aerolvm/` in this repo (recommended).
- **Q4.** Minimum Kubernetes version / managed offerings for v1: proposed
  EKS + GKE, 1.29+ (check bound SA token node claims on the minimum).
- **Q5.** Workers share the node's containerd (recommended) or run their own.
- **Q6.** `cluster-id` source for D10 owner refs (kube-system namespace UID
  proposed).
- Q1 (answered by D2/D5) and Q3 (answered: per-handshake reload in
  `internal/cluster/tls.go`) are closed.

## 11. NOT in scope

- containerd shim / RuntimeClass backend under the upstream controller —
  rejected for now (D5); revisit if D14 fails.
- Replacing Raft placement with the Kubernetes scheduler for non-husk
  sandboxes — D7 applies to husk pods only.
- Windows or non-Linux nodes.
- Upgrade/backup of in-cluster AerolVM state beyond what the VM installs
  already support.

## 12. Dream state delta

```
 TODAY                        THIS PLAN (Phases 1-5)                12-MONTH IDEAL
 VM installs only;     ──►    signed chart on EKS/GKE; /ready;  ──► AerolVM listed as an
 no image, no chart,          agent-sandbox API served by           agent-sandbox backend;
 no k8s API                   AerolVM; husk pods; Daytona           husk pods default for
                              migration; marketplace (gated)        strict tenants; upstream
                                                                    controller-class field (D14)
```

Remaining gap after this plan: coexistence with other agent-sandbox backends
depends on upstream accepting D14.

## 13. Error & rescue registry (capability level)

| Capability | Failure | Rescue | User sees | Verify owner |
|---|---|---|---|---|
| Facade reconcile | AerolVM unreachable / 5xx | Backoff retry | `Ready=False, BackendUnavailable` | Phase 3 envtest |
| Facade reconcile | Create rejected (quota, image) | No retry | `CreateRejected` + message | Phase 3 envtest |
| Facade reconcile | CR deleted mid-create | Finalizer + UID-derived ID | Nothing leaks | Phase 3 envtest |
| Facade reconcile | Sandbox deleted out of band | Mark `Lost` | `Lost` condition | Phase 3 envtest |
| Signer | Token invalid / node mismatch | Deny | Init CrashLoop + event; alert fires | Phase 2 unit |
| Signer | External issuer down | Retry; existing certs keep working | New nodes wait | Phase 2 unit |
| `/ready` | No leader past grace | 503 | Traffic shifts to healthy pods | Phase 1 unit + live |
| Husk pool | Husk evicted while Running | Mark `Lost`, release placement | `Lost` + metric | Phase 4 |
| Husk pool | Pool empty | Cold husk (1–3s) | Slower create + alert | Phase 4 |
| Chart install | Upstream controller present | Pre-install hook fails | Clear install error | Phase 3 kind |

## 14. Failure modes registry

```
 CODEPATH              | FAILURE MODE                 | RESCUED? | TEST?     | USER SEES?           | LOGGED?
 ----------------------|------------------------------|----------|-----------|----------------------|--------
 facade reconcile      | backend 5xx                  | Y        | planned   | status condition     | Y
 facade reconcile      | cross-namespace lookup       | Y (404)  | planned   | not found            | Y
 cert signer           | forged node id               | Y (deny) | planned   | CrashLoop + alert    | Y
 cert signer           | issuer outage                | Y        | planned   | join delayed         | Y
 /ready                | partition                    | Y        | planned   | 503 on that pod      | Y
 husk manager          | eviction of Running husk     | Y        | planned   | Lost                 | Y
 husk manager          | Raft/scheduler disagreement  | Y (D7)   | planned   | n/a (prevented)      | Y
 worker DaemonSet      | pod restart                  | Y        | live      | none                 | Y
 chart upgrade         | CRD not rolled back          | partial  | conformance| version pin error   | Y
```

No CRITICAL GAPs: every row is rescued and has a planned test and a visible
signal.

## 15. Deployment sequence and rollback

```
 Deploy:  CRDs (pinned) ─► controller (2 replicas, leader election)
          ─► server STS (bootstrap -0, then -1,-2) ─► ingress Deployment
          ─► worker DS (OnDelete; node-by-node) ─► flip facade/husk toggles
 Rollback: toggles off ─► helm rollback (workloads) ─► CRDs stay (pinned;
          conformance-checked) ─► workers node-by-node; running sandboxes
          survive (owned by containerd/VMM)
```

## 16. Stale diagram audit

Only this file's diagrams are touched; all were rewritten in this revision.
No code-comment diagrams change.

## 17. Implementation Tasks

- [ ] **T1 (P1, human: ~3d / CC: ~3h)** — pkg/api — Add cluster-aware `/ready` with election grace
  - Surfaced by: System audit / D8 — `/health` cluster-blind (TODOS.md)
  - Files: `pkg/api/server.go`, `internal/service` health, tests
  - Verify: `go test ./pkg/api/... ./internal/service/...` incl. grace and partition cases
- [ ] **T2 (P1, human: ~3d / CC: ~3h)** — packaging — `sandboxd` + `caddy-l4` images with cosign, SBOM, provenance
  - Surfaced by: D4.3
  - Files: `packaging/docker/Dockerfile`, `.github/workflows/release.yml`
  - Verify: `cosign verify` on a release candidate tag
- [ ] **T3 (P1, human: ~1w / CC: ~1d)** — deploy — Helm chart `single` + `mixed` modes, probes, ServiceMonitor
  - Surfaced by: §5.2
  - Files: `deploy/helm/aerolvm/` (new)
  - Verify: `helm lint`, golden tests, kind smoke
- [ ] **T4 (P1, human: ~3d / CC: ~3h)** — Makefile/docs — `make k8s-dev` + `kubernetes.mdx` (5-lang tabs, sidebar)
  - Surfaced by: D4.5
  - Files: `Makefile`, `docs/src/content/docs/kubernetes.mdx`, `docs/src/content.config.ts`
  - Verify: fresh laptop run < 5 min to first sandbox; `make docs-build`
- [ ] **T5 (P1, human: ~1w / CC: ~1d)** — integration-tests — `k8s-single` EKS scenario
  - Surfaced by: §7
  - Files: `integration-tests/suite/` (new scenario)
  - Verify: live run green
- [ ] **T6 (P2, human: ~1-2w / CC: ~1-2d)** — deploy/docs — Daytona migration preset + guide + SDK smoke
  - Surfaced by: D4.2
  - Files: `deploy/helm/aerolvm/values-daytona-compat.yaml`, docs page, `plans/sdk-compatibility/`
  - Verify: Daytona SDK smoke green against a Helm install
- [ ] **T7 (P1, human: ~1-2w / CC: ~1-2d)** — controller — Node-cert signer (TokenReview + node match + external issuer)
  - Surfaced by: D6, D11
  - Files: `cmd/aerolvm-controller/` (new), chart
  - Verify: signer unit tests (mismatch, foreign token, audience, issuer down)
- [ ] **T8 (P1, human: ~1w / CC: ~1d)** — pkg/controlplane — Scoped controller identity (namespace owners)
  - Surfaced by: D10
  - Files: `pkg/controlplane/`, `pkg/api` auth
  - Verify: cross-namespace 404 test
- [ ] **T9 (P2, human: ~2h / CC: ~15min)** — research — Re-verify Daytona closed-source report before Phase 1b marketing
  - Surfaced by: §1.1 landscape
  - Files: none
  - Verify: primary source (Daytona announcement/repo) linked in §1.1
- [ ] **T10 (P1, human: ~1w / CC: ~1d)** — integration-tests — `k8s-cluster-3` with chaos step (D9-gated)
  - Surfaced by: §7
  - Files: `integration-tests/suite/`
  - Verify: zero duplicate / zero lost claims under chaos
- [ ] **T11 (P1, human: ~3-4w / CC: ~4-5d)** — controller — agent-sandbox facade (field mapping, finalizers, webhook, coalesced status)
  - Surfaced by: D2, D5, D12
  - Files: `cmd/aerolvm-controller/`, chart CRDs
  - Verify: envtest suite + upstream e2e on kind
- [ ] **T12 (P2, human: ~1w / CC: ~1d)** — CI — Conformance job + upstream listing PR
  - Surfaced by: D4.4
  - Files: `.github/workflows/`, `plans/sdk-compatibility/`
  - Verify: job green on pinned upstream version
- [ ] **T13 (P2, human: ~3d / CC: ~3h)** — bench — 10k-object scale bench, publish ceiling
  - Surfaced by: D12
  - Files: `integration-tests/`
  - Verify: numbers recorded in docs
- [ ] **T14 (P2, human: ~4d / CC: ~4h)** — observability — Metrics, alerts, dashboard, runbook
  - Surfaced by: D13
  - Files: `setup/prometheus/`, `setup/grafana/`, `setup/runbooks/kubernetes.md`, chart
  - Verify: alerts fire in kind on injected signer denial and empty pool
- [ ] **T15 (P2, human: ~1d / CC: ~1h)** — design — Husk-pod design doc (snapshot into husk, re-bind, NetworkPolicy vs netrules)
  - Surfaced by: D4.1, D7
  - Files: `plans/kubernetes-husk-pods.md` (new)
  - Verify: `/plan-eng-review` on it before Phase 4 code
- [ ] **T16 (P3, human: ~6-8w / CC: ~1-2w)** — husk pods — Phase 4 build incl. pinned-placement regression test
  - Surfaced by: D4.1, D7
  - Files: `internal/cluster/placement.go` + tests, `internal/pool/`, controller
  - Verify: warm claim p50 ≤ 50ms; placement + eviction tests
- [ ] **T17 (P3, human: ~4-6w incl. non-eng / CC: ~2-3d)** — marketplace — EKS add-on + GKE Marketplace (D9-gated)
  - Surfaced by: D4.6
  - Files: packaging TBD
  - Verify: install-from-marketplace smoke

## 18. Completion summary

```
  +====================================================================+
  |            MEGA PLAN REVIEW — COMPLETION SUMMARY                   |
  +====================================================================+
  | Mode selected        | SCOPE EXPANSION                             |
  | System Audit         | /health cluster-blind, no /ready; Q3 already|
  |                      | answered (hot reload); node:<id> SAN missing|
  |                      | from draft; license PR #223 open; PR #515   |
  |                      | merged before review                        |
  | Step 0               | Approach C (agent-sandbox facade); 6        |
  |                      | expansions accepted; D5-D9 design calls     |
  | Section 1  (Arch)    | 3 issues found (tenant identity, controller |
  |                      | HA, CA custody)                             |
  | Section 2  (Errors)  | 10 error paths mapped, 1 GAP (husk evict)   |
  | Section 3  (Security)| 4 issues found, 3 High severity             |
  | Section 4  (Data/UX) | 5 edge cases mapped, 0 unhandled            |
  | Section 5  (Quality) | 2 issues found                              |
  | Section 6  (Tests)   | Diagram produced, 0 gaps                    |
  | Section 7  (Perf)    | 1 issue found (CR scale)                    |
  | Section 8  (Observ)  | 1 gap found (new components unobserved)     |
  | Section 9  (Deploy)  | 2 risks flagged (CRD rollback, SWIM upgrade)|
  | Section 10 (Future)  | Reversibility: 3/5, debt items: 2           |
  | Section 11 (Design)  | SKIPPED (no UI scope)                       |
  +--------------------------------------------------------------------+
  | NOT in scope         | written (4 items)                           |
  | What already exists  | written                                     |
  | Dream state delta    | written                                     |
  | Error/rescue registry| 10 rows, 0 CRITICAL GAPS                    |
  | Failure modes        | 9 total, 0 CRITICAL GAPS                    |
  | TODOS.md updates     | 1 item proposed (D14, accepted)             |
  | Scope proposals      | 6 proposed, 6 accepted                      |
  | CEO plan             | written                                     |
  | Outside voice        | codex: unavailable (CLI cannot parse model  |
  |                      | list); native fallback unavailable          |
  | Lake Score           | 9/9 recommendations chose complete option   |
  | Diagrams produced    | 6 (arch, cert flow, husk data flow, husk    |
  |                      | state machine, deploy/rollback, dream delta)|
  | Stale diagrams found | 0                                           |
  | Unresolved decisions | 0                                           |
  +====================================================================+
```

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | CLEAR | 6 proposals, 6 accepted, 0 deferred |
| Outside Review | `codex exec` (plan-review) | Independent 2nd opinion | 1 | unavailable | Codex CLI could not parse the model list (upgrade: `npm install -g @openai/codex`); native fallback needs TaskOutput, not available — no completed external review |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 0 | — | — |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **OUTSIDE COVERAGE:** codex, plan-review, unavailable (CLI model-list parse error `unknown variant 'max'`); no native fallback ran. No completed external review.
- **VERDICT:** CEO CLEARED — eng review required.

NO UNRESOLVED DECISIONS
