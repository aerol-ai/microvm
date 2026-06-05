# Changing a node's role consistently

When a node's role needs to change (e.g. `mixed` → `ingress`, or
`worker,ingress` → `worker`), the question that always comes up is: *who is
allowed to write the role - Terraform, Ansible, or both?* This document
states the rule, explains why, and gives you the implementation.

## The rule

**Terraform is the sole writer of node role. Role changes happen by
recreating the instance, never by editing it in place.**

Ansible never touches `SB_NODE_ROLE` or `/etc/sandboxd/sandboxd.env`. There
is no `change-role.yml` playbook - and there shouldn't be.

## Why

Three pieces of state describe a node's role:

1. **EC2 `Role` tag** - owned by Terraform's `nodes.tf`.
2. **`SB_NODE_ROLE` in `/etc/sandboxd/sandboxd.env`** - written by
   `cluster-init.sh` / `cluster-join.sh` during the user_data bootstrap.
3. **Cloudflare A records** - created by Terraform's `dns.tf` for any node
   whose role contains `ingress`.

If two systems can write any of those, they will drift. The dangerous one is
the third: if Ansible removes a node's ingress role but Terraform still
believes it's ingress-bearing, Cloudflare keeps routing public traffic to a
node that no longer serves it → 502s. Inversely, if Ansible adds ingress
without Terraform knowing, the new capability is invisible from outside.

The cheapest way to guarantee consistency is to ensure only one system ever
writes the field. We pick Terraform because it already owns the other two
related pieces (the EC2 tag and DNS), and because the alternative -
"cluster owns role, Terraform launches every node as mixed, role assigned
via API" - is a multi-day feature, not a config change.

## How (the one-time Terraform setup)

In `Terraform/nodes.tf`, on both `aws_instance.seed` and
`aws_instance.joiner`, add:

```hcl
user_data_replace_on_change = true

lifecycle {
  ignore_changes        = [ami]   # keep your existing line
  create_before_destroy = true    # only for ingress-bearing nodes if you want zero-downtime
}
```

With `user_data_replace_on_change = true`, any change to `var.nodes[*].role`
forces Terraform to recreate that instance because the rendered user_data
script changes. The new instance boots, runs `cluster-join.sh --role <new>`,
joins fresh. EC2 tag, env file, and DNS records all reconcile in the same
apply because they were written by the same operation. Drift becomes
impossible.

## How (the day-to-day workflow)

Changing a role becomes a normal Terraform change:

```bash
# edit Terraform/terraform.tfvars - flip wrk1's role from "worker" to "worker,ingress"
terraform -chdir=Terraform plan -target='aws_instance.joiner["wrk1"]'
terraform -chdir=Terraform apply -target='aws_instance.joiner["wrk1"]'
```

Use `-target` so you change one node at a time. Terraform will show you the
destroy + recreate plan before doing anything.

What happens during the apply:

1. The instance is destroyed (Raft handles the voter loss if it was a server;
   workloads on the node are lost - see "Caveats" below).
2. A new instance comes up with the new role baked into user_data.
3. The cluster-join.sh script joins it in its new role.
4. DNS records reconcile: if the node gained ingress, an A record is added;
   if it lost ingress, the record is dropped.

Total time: 5–10 minutes per node.

## Caveats and mitigations

| Concern | Mitigation |
|---|---|
| Workloads on a worker node are lost when it's recreated | Run `ansible-playbook Ansible/playbooks/prepare-role-change.yml --limit <node>` before the Terraform apply. It marks the node drained and waits until the cluster placement index shows zero owned placements. |
| Brief capacity dip while the new instance comes up | Use `create_before_destroy = true` in the lifecycle block, especially for ingress nodes. New node + DNS record exist before old one disappears → zero public-traffic downtime. |
| Losing a Raft voter momentarily | The cluster tolerates `(N-1)/2` voter losses. Change one server-role node at a time and you stay in quorum. After terminating a stale server-role node, call `DELETE /v1/cluster/members/<node-id>` from a survivor to remove it from raft explicitly. |
| "But 5–10 minutes is slow for me!" | If role changes are frequent enough that this hurts, the right fix is the long-term option below, not a faster patch. Role changes in real deployments are rare. |

Pre-drain command:

```bash
cd Ansible
ansible-playbook playbooks/prepare-role-change.yml --limit <inventory-host>
```

The playbook deploys `sandboxd-node-lifecycle.sh`, calls the node-local API to
drain its own `SB_NODE_ID`, and waits up to
`sandboxd_role_change_drain_timeout_s` seconds. A timeout is a hard stop: the
Terraform apply should wait or the operator should intentionally destroy the
remaining sandboxes first.

## What Ansible *does* own

This rule narrows what Ansible is for, but it doesn't remove it. Ansible
still owns everything that isn't declared state:

| Operation | Tool |
|---|---|
| Add / remove / resize / change role | Terraform |
| Pre-drain before role change | Ansible (`playbooks/prepare-role-change.yml`) |
| Push a new `sandboxd` binary | Ansible (`playbooks/update-sandboxd.yml`) |
| Restart services, rotate PATs, tail logs | Ansible |
| Run one-off shell commands across many nodes | Ansible |

The split: **declared state in Terraform, ephemeral operations in Ansible.**
Role belongs to declared state because it's part of the cluster's identity.
Binary versions belong to ephemeral operations because Terraform doesn't need
to know what version is running - it's not part of the topology.

## The long-term version (only when you outgrow the above)

If role changes start happening often enough that the recreate cost is real
operational pain, the answer is **not** "let Ansible write role too." The
answer is to move role out of Terraform entirely:

- Terraform launches every node as `mixed` (or some neutral default).
- The cluster exposes `POST /v1/cluster/nodes/<id>/role`.
- Role state lives in the Raft-backed store, reconciled into
  `/etc/sandboxd/sandboxd.env` by a per-node reconciler that restarts
  sandboxd when role changes.
- DNS becomes a function of cluster state, not of `var.nodes` - either via a
  cluster-managed DNS controller, or by Terraform reading cluster state at
  plan-time.

This makes drift impossible because Terraform never declares role in the
first place. It's a real feature (API + persistence + reconciler + DNS
rework), not a config change. Don't build it until the pain is concrete.

## TL;DR

- One writer for role: Terraform.
- Add `user_data_replace_on_change = true` to your EC2 instances.
- Change roles by editing `var.nodes` and running `terraform apply -target=...`.
- Never write a `change-role.yml` Ansible playbook.
- If recreate cost becomes painful, move role to cluster state - don't add a
  second writer.
