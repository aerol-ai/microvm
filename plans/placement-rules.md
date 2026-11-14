# P1: placement rules (zone and node labels)

Status: design approved by the owner for build (2026-11-06), under
`plans/agent-sandbox-feature-parity.md` row P1 ("needs its own design doc";
cluster code: regression tests and a cluster-correctness call-out).

## 1. What we want

A caller can say "run this sandbox in zone X" or "on a node labelled
`gpu=a10`, `tier=pci`". A bank uses it to keep regulated work on approved
hosts, and to spread work across availability zones.

## 2. Decisions

| # | Decision | Why |
|---|---|---|
| P1.1 | A node declares `SB_NODE_ZONE` and `SB_NODE_LABELS=k=v,k=v` (validated at boot: keys and values follow the Kubernetes label syntax, at most 16 labels, 63 chars each). Zone is a label with the reserved key `zone`. | Operator-set, simple, testable. Auto-reading the cloud zone from instance metadata is a later convenience. |
| P1.2 | Labels travel in the **authenticated capacity heartbeat** (`capacity.Snapshot` → `capacityLeaseCache`), not in gossip `nodeMeta`. | `nodeMeta` has a hard 512-byte memberlist limit; overflowing it once stripped Raft addresses and broke voter auto-join (`internal/cluster/gossip.go`). Placement already requires a fresh heartbeat per worker, so the labels are there when placement runs. |
| P1.3 | Create takes `placement: {zone?: string, labels?: {k: v}}`: every given key must match exactly (AND). No operators (In, NotIn, Exists) in this version. | Covers the bank cases; operators can be added without breaking callers. |
| P1.4 | Placement filters candidates on labels **before** power-of-two-choices (`SelectPlacementWithCandidates` in `internal/cluster/placement.go`). No match gives 409 `placement_unsatisfiable` naming the rule, never a silent fallback to another node. | A rule that is quietly ignored is worse than a refusal for regulated work. |
| P1.5 | The rule is stored with the sandbox spec (it is part of `CreateSandboxRequest`), so the replicated recovery spec carries it; failover and recreate pick a target that matches. If none matches, the sandbox is not failed over (it stays recoverable when a matching node returns) and an audit record and a counter say why. | Placement rules must hold across failover, or failover breaks the guarantee. |
| P1.6 | Single-node mode: a rule the node's own labels do not satisfy gives the same 409. No FSM is involved. | Same answer everywhere; cluster code stays a no-op when cluster mode is off. |
| P1.7 | `GET /v1/cluster/members` shows each node's zone and labels (from the heartbeat). | Operators need to see what they can target. |

## 3. Cluster correctness (the build PR repeats this with test names)

- **No new FSM op.** The owner chosen at create is recorded as today; the rule rides in the spec bytes the FSM already replicates. Replay of old log entries is unaffected (an entry without a rule has none).
- **Leader change:** placement runs on the node handling the create, from its heartbeat cache, exactly as capacity does today; no leader-only state is added.
- **Split brain:** unchanged; placement still needs the quorum-backed reservation it takes today.
- **Mixed versions:** a node too old to send labels in its heartbeat has no labels, so it never matches a rule; a create with a rule fails closed (409) rather than landing on an unlabelled node. A sandbox without a rule places as today.
- **Single node:** no change in behaviour without a rule.

## 4. Tests

Unit: label parsing and limits, matching, filter-before-p2c, 409 with no
match, heartbeat carries labels, members view, recovery target selection
respects the rule, mixed-version (no labels) fails closed. Regression tests
live next to `placement.go` / `placement_test.go` and the heartbeat code.
Live (UC range given to the lane): on a 3-node cluster with distinct
zones/labels, a create with a zone lands there, a create with an unknown
label gets 409, the members view shows the labels. The lane adds the labels
to a cluster scenario's tfvars through the existing per-node env path only
if that is a small change; otherwise it tests with the labels the harness
can set, and says so.

## 5. Not in scope

Anti-affinity, spread constraints, label operators, taints and
tolerations, automatic zone from instance metadata.
