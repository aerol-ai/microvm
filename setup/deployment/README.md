# Deployment guidelines

How to keep an AerolVM cluster in a consistent state across the tools that
operate it: **Terraform** (declared infra + topology), the **`aerolvm`
CLI** (upgrades, drains, node removal, join tokens) and **Ansible**
(host ops settings, service restarts, log tails).

The unifying principle: **for any field that describes the cluster, exactly
one tool is allowed to write it.** Two writers always drift. Pick one,
document it, enforce it.

## Tool boundary

| Operation | Tool |
|---|---|
| Provision / destroy nodes | Terraform |
| Resize a node (instance type, volume) | Terraform |
| Change a node's role | Terraform (see [`role-changes.md`](./role-changes.md)) |
| Add or remove ingress capacity, DNS | Terraform |
| Security group / VPC / IAM changes | Terraform |
| Upgrade `sandboxd`, `toolboxd` and `caddy` | `aerolvm upgrade apply <version>` (see [`../runbooks/cluster-upgrades.md`](../runbooks/cluster-upgrades.md)) |
| Push a dev `toolboxd` build | `aerolvm upgrade apply --from` (see [`toolboxd-updates.md`](./toolboxd-updates.md)) |
| Drain, cordon or remove a node | `aerolvm drain`, `aerolvm cordon`, `aerolvm delete node` |
| Add a node by hand | `aerolvm join-command`, then the printed line on the new machine |
| Restart services, rotate PATs | Ansible |
| Tail logs across nodes | Ansible (`Ansible/playbooks/tail-logs.yml`) |
| Run one-off shell commands | Ansible |

**Declared state** (topology, role, DNS, capacity) lives in Terraform.
**Ephemeral operations** live outside it: binary versions in the cluster
itself (`aerolvm upgrade` keeps the rollout in Raft), service lifecycle and
ad-hoc commands in Ansible. Terraform doesn't need to know what binary
version is running; Ansible doesn't need to know how many nodes exist (the
dynamic inventory asks AWS).

## Guidelines

- [**role-changes.md**](./role-changes.md) - Changing a node's role
  consistently. Why role lives in Terraform only, the `user_data_replace_on_change`
  setting that makes it work, and why there is no `change-role.yml`
  playbook.
- [**toolboxd-updates.md**](./toolboxd-updates.md) - Rolling a new
  `toolboxd` binary across the fleet. Local-build vs release-asset paths,
  the atomic file swap, and why existing sandboxes have to be recreated to
  pick up the new code.

(More guidelines land here as drift-prone operations show up. The pattern is
always the same: identify the field, pick the writer, document the rule.)

## Why this matters

The cluster has three places role information lives:

1. EC2 `Role` tag (Terraform writes this).
2. `SB_NODE_ROLE` in `/etc/sandboxd/cluster.env` (`sandboxd init` /
   `sandboxd join` write this at boot).
3. Cloudflare A records (Terraform writes this).

If Ansible can also write (2), the three can diverge. The most dangerous
case: Ansible removes a node's ingress role but Terraform still believes
it's ingress-bearing → Cloudflare keeps routing public traffic to a node
that no longer serves it → 502s with no obvious cause.

The rule "one writer per field" eliminates this class of bug at the cost of
some operations being slower (e.g. role changes recreate the instance
instead of editing it in place). For a small self-hosted cluster, that
trade is correct. For a fleet where role changes are frequent, the right
answer isn't "let two systems write" - it's to remove the field from
Terraform entirely and own it in cluster state. See the long-term-version
section in `role-changes.md`.
