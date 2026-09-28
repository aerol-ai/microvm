# Runbook: Cluster ingress topology (`SandboxdClusterTopologyViolation`)

`aerolvm_cluster_topology_ok` is 0 on a node whose live membership violates
the production topology contract. In practice this means one of two things:

1. **More than 10 live nodes with a `mixed` or hybrid role, or a missing
   dedicated tier.** Placement and local creates fail with `503`. See
   [Cluster Ingress](../../docs/src/content/docs/cluster-ingress.mdx) for the
   role split.
2. **More than 10 live ingress-capable nodes without
   `SB_CLUSTER_SHARD_AWARE_INGRESS=true`.** This page.

## Why the daemon stops at 10 ingress nodes

Through 10 ingress-capable nodes every ingress node keeps the full public
route table, so any router that picks any ingress node works: DNS round-robin,
a cloud TCP load balancer, a BGP VIP. Above 10, each ingress node subscribes
only to its rendezvous-hashed share of the route table (the primary owner plus
one failover replica per shard). A router that still picks any ingress node
for any sandbox now sends most connections to a node that does not hold the
route. The daemon cannot see what is in front of it, so it fails closed until
an operator declares the router shard-aware:

| Mode | Behaviour above 10 ingress nodes without the flag |
|---|---|
| Enterprise (`SB_ENTERPRISE_MODE=true`) | Boot refuses; the error names the flag and the route endpoint. |
| Open-source | Boot logs `cluster topology violation; refusing to mark ingress ready`, the ingress reconciler never starts, `/health` reports `degraded` with the reason, a warning repeats every reconcile cycle, this alert fires. |

Creates are not refused by this rule; sandboxes keep running. Public traffic
through the ingress tier is what is at stake.

## What a shard-aware router must do

Before forwarding a connection for a sandbox (by id or by the hostname derived
from it), the router calls `GET /v1/cluster/ingress-route/{id}` on the control
plane with an operator PAT and forwards to one of the returned `owners[]`
(`data_plane_host`, or `api_url` / `internal_url` for API traffic). The first
owner is the primary for the sandbox's shard, the second its failover replica.
Cache the answer with a short TTL. On a miss, `404` or `503`, fail closed —
never fall back to spraying every ingress node.

Only when that path is in place, set `SB_CLUSTER_SHARD_AWARE_INGRESS=true` on
every node (Terraform: `shard_aware_ingress = true`) and restart. The gauge
returns to 1 and the ingress reconciler starts on the next boot.

## Do not

- **Do not set the flag to silence the alert while a plain LB fronts the
  tier.** The check goes quiet and most public sandbox traffic black-holes,
  with nothing daemon-side left to notice.
- Do not shrink the tier by killing ingress nodes under load to get back under
  10; drain them (`Ansible/playbooks/prepare-role-change.yml`) or convert some
  to `worker`.

## Verify

1. `GET /health` on an ingress node: `cluster_topology` is `ok`.
2. `aerolvm_cluster_topology_ok == 1` on every node.
3. Create a sandbox with a public port and reach it through the advertised
   endpoint several times; every attempt must land.
4. `GET /v1/cluster/ingress-route/{id}` for that sandbox returns two owners
   whose `data_plane_host` values are among your ingress nodes.
