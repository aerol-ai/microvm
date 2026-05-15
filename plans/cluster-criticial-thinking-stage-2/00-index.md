# Cluster Critical Thinking - Stage 2

This folder critiques the first-stage plan in
`plans/cluster-criticial-thinking/` against a stricter release bar:

> Cluster mode should be robust enough to run roughly 200 runners with 50
> sandboxes per runner, while preserving the product's non-HA sandbox semantics.

Non-HA sandbox semantics means the cluster does not need to preserve a running
container, open sessions, local filesystem state, or old host ports after the
owner dies. It does mean the control plane, API routing, placement decisions,
and public network ingress must remain coherent under failures.

## Stage-2 verdict

The first-stage plan is directionally right, but too generous to the current
branch. It correctly identifies the two big architectural problems:

- every node becomes a Raft voter;
- public sandbox URL traffic has no real owner-aware load balancer.

However, it misses or underweights several release blockers:

- `POST /v1/sandboxes` is not reliably routable today because the forwarded
  target re-runs placement instead of creating locally.
- The plan treats per-node URLs as an acceptable P0, but the requested product
  needs a real load-balancer story for HTTP/TLS, and probably for raw TCP.
- The control-plane plan does not decide whether the product should keep the
  embedded HashiCorp Raft FSM or move to an etcd-style API with watches, leases,
  compaction, and backup/restore.
- The placement model ignores resources and constraints that already exist in
  the API, including disk, GPU, cluster-wide names, and global L4 port
  allocation.
- The release plan lacks measurable gates: scale tests, chaos tests, route-miss
  SLOs, Raft latency SLOs, and operator runbooks.

## Reading order

| File | Purpose |
|---|---|
| [`01-review-of-stage-1-plan.md`](./01-review-of-stage-1-plan.md) | Positive and negative criticism of the first-stage plan itself. |
| [`02-release-blockers-in-current-pr.md`](./02-release-blockers-in-current-pr.md) | Concrete blockers found by comparing the plan to the PR #58 implementation. |
| [`03-control-plane-decision.md`](./03-control-plane-decision.md) | HashiCorp Raft vs etcd-style control plane; what Kubernetes-grade robustness actually requires. |
| [`04-data-plane-load-balancer.md`](./04-data-plane-load-balancer.md) | Required load-balancer design for HTTP, TLS/SNI, raw TCP, and future UDP. |
| [`05-placement-correctness.md`](./05-placement-correctness.md) | Scheduler, resource model, idempotency, and cluster-wide uniqueness gaps. |
| [`06-release-gates.md`](./06-release-gates.md) | Release criteria, tests, observability, and runbooks needed before calling cluster mode production-ready. |
| [`07-diff-map.md`](./07-diff-map.md) | File-level implementation deltas implied by this critique. |

## External references used

- Kubernetes components: <https://kubernetes.io/docs/concepts/overview/components/>
- etcd FAQ: <https://etcd.io/docs/v3.7/faq/>
- MetalLB overview: <https://metallb.io/index.html>
- MetalLB concepts: <https://metallb.io/concepts/>
- Envoy dynamic configuration / xDS: <https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/dynamic_configuration>

