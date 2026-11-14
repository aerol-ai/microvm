# AerolVM on Kubernetes: alerts and failures

This runbook is for AerolVM installed with the Helm chart
(`charts/aerolvm`). It has two parts:

1. [When things break](#when-things-break): what fails, what the operator
   does about it, and what a person must do.
2. One entry for each alert the chart ships. Each entry says what the alert
   means, how to check it, and how to fix it.

The alerts come with the chart when you set `monitoring.enabled=true`. The
rules are in `charts/aerolvm/monitoring/rules.yaml`
(plans/kubernetes-v2-architecture.md, P6 and P9).

**Single mode and cluster mode.** Single mode is one worker pod and no
operator. Cluster mode has server, gateway and worker pods and an operator
that manages them. Alerts marked *cluster mode* read the operator's
numbers, so they never fire in single mode.

## Before you start

Find the pods. Each AerolVM pod has the labels `app.kubernetes.io/name=aerolvm`
and `app.kubernetes.io/component` (`server`, `gateway`, `worker` or
`operator`). In cluster mode the workers run in their own namespace
(`aerolvm-workers` by default) and the rest in the release namespace
(`aerolvm-system` by default).

```bash
kubectl get pods -A -l app.kubernetes.io/name=aerolvm -L app.kubernetes.io/component
```

Useful commands:

- `kubectl -n <namespace> logs <pod> -c agent --since=30m`: the AerolVM
  server's log on a worker. Servers and gateways have one container.
- `kubectl get aerolnodes` and `kubectl describe aerolnode <name>`
  (cluster mode): each node's state, conditions and recent events. The
  operator writes the reason for most problems here.
- `aerolvm health`, `aerolvm get nodes`, `aerolvm top nodes` and
  `aerolvm upgrade status`: what AerolVM itself sees, through its API.

The Grafana dashboards **AerolVM on Kubernetes** and **AerolVM usage per
team** come with the chart (`monitoring.grafanaDashboards`). Every alert
below has a panel there.

Alert labels: `aerolvm_cluster` is the cluster's name (the Helm release in
single mode), `aerolvm_component` is the kind of pod, and `namespace` and
`pod` name one pod.

## When things break

| What breaks | What the operator does | What AerolVM does | What a person does | Alerts |
|---|---|---|---|---|
| A gateway pod | Starts a new gateway pod. | The load balancer drops the old one. Clients retry and connect through another gateway. | Nothing, unless it keeps happening. | [AerolVMPodNotReady](#aerolvmpodnotready) |
| A server pod | Starts a new server pod in the same zone, with the same disk. | Raft keeps working with the other servers. | Nothing. If the disk is lost too, see the next row. | [AerolVMNodeLost](#aerolvmnodelost), [AerolVMPodNotReady](#aerolvmpodnotready) |
| Two of three servers | Starts new pods where the disks still exist. It replaces no lost server while any server is in maintenance mode. | No new sandboxes can be placed until a majority is back. Running sandboxes keep running, and their links keep working. | If two disks are lost, recover the cluster from the last server: see [Recover from lost servers](#recover-from-lost-servers). | [AerolVMNodeLost](#aerolvmnodelost) |
| A worker's `agent` container | Nothing. The node shows as Restarting for a short time. | The kubelet restarts the container. It finds its sandboxes again; they never stopped. | Nothing, unless it does not come back. | [AerolVMPodNotReady](#aerolvmpodnotready) |
| A worker's `runtime` container | Nothing. | Every sandbox on that worker ends. Failover does not apply: the worker is still alive. | Find out why. This should never happen. | [AerolVMRuntimeContainerRestarted](#aerolvmruntimecontainerrestarted) |
| A worker machine | Marks the node Suspect, then Dead. Starts a new worker if headroom needs one. | Gossip notices. After the grace period, failover rebuilds the sandboxes with `failover.policy=recreate` on other workers. That machine's other sandboxes are lost. | Nothing, unless many machines go. | [AerolVMNodeLost](#aerolvmnodelost), [AerolVMHeadroomLow](#aerolvmheadroomlow) |
| A whole zone | Starts workers in the other zones, up to the headroom target. | Gateways and servers in the other zones carry on. Failover rebuilds in the other zones. | Watch headroom. | [AerolVMNodeLost](#aerolvmnodelost), [AerolVMHeadroomLow](#aerolvmheadroomlow) |
| The Kubernetes API or etcd | Waits. It can scale, upgrade or hand out certificates only when the API is back. | Nothing changes for sandboxes. Creates through the SDKs, exec and links keep working. | Fix the Kubernetes API. AerolVM needs nothing. | [AerolVMOperatorReconcileErrors](#aerolvmoperatorreconcileerrors) |
| A person deletes a worker pod | Its webhook refuses the delete, unless the pod was decommissioned or has `aerolvm.io/force-delete=true`. | If the delete goes through, every sandbox on that pod ends. | Decommission a worker instead of deleting it. | [AerolVMWorkerPodLost](#aerolvmworkerpodlost) |
| The bank's certificate issuer (external-CA mode only) | Retries. | Running nodes keep their certificates and keep working. New machines wait to join. | Fix the issuer. | [AerolVMNodeCertificateFailing](#aerolvmnodecertificatefailing) |
| The cloud has no machines of that type | Keeps the new pods Pending and waits. | Headroom covers new sandboxes for a while. Then creates get "no room" (503 with Retry-After). | Pick another machine type, or raise the cloud quota. | [AerolVMNodePending](#aerolvmnodepending), [AerolVMHeadroomLow](#aerolvmheadroomlow), [AerolVMCreatesRefusedNoRoom](#aerolvmcreatesrefusednoroom) |
| Object storage | Nothing. | Snapshots and audit export wait and retry. | Fix the storage or its permissions. | Not in the chart yet: see `SandboxdAuditExportLagging` in `setup/prometheus/sandboxd-alerts.yml`. |

### Recover from lost servers

Use this only when a majority of the servers and their disks are gone for
good. With the disks still there, the operator brings the servers back by
itself.

1. Put **every** server that is left into maintenance mode. `sandboxd
   recover-quorum` refuses to run while sandboxd runs on any server:

   ```bash
   kubectl annotate aerolnode <server> aerolvm.io/maintenance=true
   ```

   The operator restarts that server's pod with its disk but without
   sandboxd.
2. In one server pod, run the recovery. Follow
   [lost-quorum-recovery.md](lost-quorum-recovery.md) for which server to
   pick and what the command does:

   ```bash
   kubectl -n <namespace> exec -it <server pod> -- sandboxd recover-quorum
   ```

3. Take every server out of maintenance mode:

   ```bash
   kubectl annotate aerolnode <server> aerolvm.io/maintenance-
   ```

4. Check that a leader is back with `aerolvm cluster-info`. The operator
   then starts new servers in place of the lost ones.

## AerolVMMetricsDown

**What it means.** Prometheus has not been able to read one AerolVM pod's
metrics for 10 minutes. The pod's process is down, or it refuses the token
Prometheus sends. While this lasts, that pod's other alerts cannot fire.

**Check.**

- Is the pod running? `kubectl -n <namespace> get pod <pod>`.
- Look at the target on Prometheus's Targets page. "401" or "403" means the
  token is wrong. "connection refused" means the process is down.

**Fix.**

- A 401 or 403: the Secret in `monitoring.scrapeToken.existingSecret` (or
  the API token Secret) holds a token AerolVM does not accept. An expired
  read-only token is the usual cause. Make a new one with `aerolvm token
  create --name prometheus-2 --role viewer --team '*' --expires-in 90d`, put
  it in the Secret, and wait one scrape. Then revoke the old one with
  `aerolvm token revoke <token-id>`.
- A process that is down: see [AerolVMPodNotReady](#aerolvmpodnotready).

## AerolVMPodNotReady

**What it means.** An AerolVM pod has not been ready for 10 minutes. A
worker that is not ready takes no new sandboxes, and the cluster cannot
reach its sandboxes through it. A server or gateway that is not ready gets
no traffic. This alert reads pod status from kube-state-metrics.

**Check.**

- `kubectl -n <namespace> describe pod <pod>`: look at the events at the
  bottom and at each container's state.
- In cluster mode, `kubectl describe aerolnode <name>`: the condition says
  why the operator thinks it is not ready.
- The agent's log: `kubectl -n <namespace> logs <pod> -c agent --since=30m`.
  A worker reports not ready when it cannot reach the servers, or when it is
  still pulling its pool's images.

**Fix.**

- A new worker still pulling images: wait, or see
  [AerolVMNodeJoinSlow](#aerolvmnodejoinslow).
- A worker that cannot reach the servers: check the network between the
  worker and server namespaces, and the NetworkPolicies there.
- An agent that keeps crashing: the log names the reason. A bad setting in
  `worker.extraEnv` is a common one.
- If the pod cannot recover, decommission the worker. Do not delete the pod:
  that ends its sandboxes.

## AerolVMRuntimeContainerRestarted

**What it means.** A worker's `runtime` container restarted. It holds
containerd and every sandbox on that worker, so every sandbox there ended.
It has no liveness probe on purpose, so Kubernetes never restarts it by
choice. This should never happen. This alert reads pod status from
kube-state-metrics.

**Check.**

- Why did it stop?
  `kubectl -n <namespace> get pod <pod> -o jsonpath='{.status.containerStatuses[?(@.name=="runtime")].lastState}'`.
  `OOMKilled` means the container ran out of memory.
- Its log from before the restart:
  `kubectl -n <namespace> logs <pod> -c runtime --previous`.

**Fix.**

- `OOMKilled`: the sandboxes and containerd used more than
  `worker.runtime.resources`. Give the pod more memory, or keep requests
  equal to limits so the pod is never the first one evicted.
- A crash in containerd or the supervisor: keep the log and open an issue.
- Check whether other workers restarted too. Several at once point to the
  machines (a kernel or node image change), not to one pod.

## AerolVMPodImagePullStuck

**What it means.** An AerolVM pod has waited more than 10 minutes to pull
the image of one of its containers. A new worker cannot serve until it has
all its images. This alert reads pod status from kube-state-metrics.

**Check.**

- `kubectl -n <namespace> describe pod <pod>`: the events show the image
  name and the pull error.
- Can the node reach the registry or your mirror?

**Fix.**

- A wrong tag: fix `image.tag` (or the image the operator sets) and let the
  pod start again.
- A private registry: check the pull secret and the
  `networkPolicy.extraEgressCIDRs` entry for the registry.
- A registry outage: wait, or point `image.registry` at your mirror.

## AerolVMWorkerPodLost

*Cluster mode.*

**What it means.** A worker pod went away without a decommission. Someone
forced the delete with `aerolvm.io/force-delete=true`, or the operator's
delete webhook was down. Every sandbox on that pod ended. Failover rebuilds
only the ones with `failover.policy=recreate`.

**Check.**

- The audit log names who forced the delete.
- `kubectl get events -A --field-selector reason=Killing` around the alert's
  time shows which pod went.
- Was the operator's webhook running? A webhook that is down lets deletes
  through, so it never blocks repairs.

**Fix.**

- Tell the owners whose sandboxes ended.
- To remove a worker, decommission it: cordon its machine, and the operator
  moves or finishes its sandboxes first.
- Keep `aerolvm.io/force-delete` for a worker that is already broken.

## AerolVMDecommissionStuck

*Cluster mode.*

**What it means.** A worker has been decommissioning for over an hour, and
no decommission finished in that hour. That is past the deadline (the drain
window plus the time to move sandboxes). The machine cannot be returned
until it ends, and a cloud upgrade may stop waiting and take the machine
anyway.

**Check.**

- `kubectl get aerolnodes` shows which node is Decommissioning.
  `kubectl describe aerolnode <name>` shows its progress events.
- Are moves failing? See
  [AerolVMDecommissionMovesFailing](#aerolvmdecommissionmovesfailing).
- `aerolvm describe node <name>` lists the sandboxes still on it.

**Fix.**

- Moves that fail because no other worker has room: add room, or lower the
  headroom target for a while.
- Sandboxes that cannot move stop at the deadline by design. If the deadline
  passed and they still run, check the operator's log for errors.
- On an EKS managed node group, the cloud waits 15 minutes per machine. Use
  the operator's "prepare pool" action before a node group upgrade, so
  workers drain before the upgrade starts.

## AerolVMNodePending

*Cluster mode.*

**What it means.** The operator made a pod for a new node 15 minutes ago,
and no machine took it. Karpenter, Node Auto Provisioning or the node group
cannot start a machine of that type. Headroom covers new sandboxes until it
runs out.

**Check.**

- `kubectl -n <namespace> describe pod <pod>`: the scheduler's event says
  why the pod fits nowhere.
- Karpenter: `kubectl get nodeclaims` and the Karpenter log. Look for
  "insufficient capacity" or a quota error.
- Is the pool's machine type available in that zone?

**Fix.**

- Allow more machine types or zones in the pool, or ask the cloud for a
  higher quota.
- Check that the pool's node selector and taints match the machines the
  provisioner makes.

## AerolVMNodeJoinSlow

*Cluster mode.*

**What it means.** A node has been joining for over 10 minutes. Joining
covers four steps: getting its certificate, joining gossip, pulling its
pool's images, and passing its ready check. Image pulls are the usual slow
step.

**Check.**

- `kubectl describe aerolnode <name>`: the condition names the step it waits
  on, and the image when it is a pull.
- For an image: can the worker reach the registry? Is the image large?
- For a certificate: see [AerolVMJoinTokenErrors](#aerolvmjointokenerrors)
  and [AerolVMNodeCertificateFailing](#aerolvmnodecertificatefailing).

**Fix.**

- Use a registry mirror close to the cluster, or smaller pool images.
- Fix the registry's network path or pull secret.

## AerolVMNodeLost

*Cluster mode.*

**What it means.** Gossip has not heard from these nodes. A node is
Suspect first, then Dead after the grace period.

- A lost worker: failover rebuilds its `failover.policy=recreate` sandboxes
  on other workers. Its other sandboxes are lost.
- Lost servers: Raft needs a majority of servers to place new sandboxes.
  With one of three lost, nothing changes. With two of three lost, no new
  sandboxes can be placed.

**Check.**

- `kubectl get aerolnodes` and `kubectl get nodes`: is the machine gone, or
  only the pod?
- `aerolvm get nodes` shows what AerolVM sees.

**Fix.**

- A machine that died: nothing. The operator replaces it if headroom needs
  it.
- Many nodes at once: look for a network split, a zone outage or a broken
  node image.
- Two of three servers lost with their disks: see
  [Recover from lost servers](#recover-from-lost-servers).

## AerolVMOperatorReconcileErrors

*Cluster mode.*

**What it means.** One of the operator's controllers has returned errors for
15 minutes. It retries with a growing wait, so nothing it manages moves
forward: scaling, upgrades and decommissions all wait.

**Check.**

- The operator's log: each error names the object and the reason.
- Can the operator reach the Kubernetes API, and the AerolVM servers' API?
  An operator pod that restarts again and again on its liveness probe, with
  nothing in its log, cannot reach the API at all.
- Did someone change its RBAC, or the AerolCluster, just before?

**Fix.**

- A Kubernetes API outage: nothing to do in AerolVM. It catches up when the
  API is back.
- On EKS with network policies on: a pod that started while an egress
  NetworkPolicy selected it can keep that policy's block after the policy
  is deleted (seen with aws-network-policy-agent v1.4.0-eksbuild.4). Delete
  the operator pods. The new ones start without the old block.
- A refused AerolVM API call: check the admin credential Secret the operator
  uses.
- An invalid AerolCluster change: undo it. `kubectl describe aerolcluster`
  shows the reason.

## AerolVMServerMaintenanceTooLong

*Cluster mode.*

**What it means.** A server has been in maintenance mode for over an hour.
A server in maintenance runs no sandboxd, and the operator replaces no lost
server while any server is in maintenance.

**Check.**

- `kubectl get aerolnodes -o custom-columns=NAME:.metadata.name,MAINTENANCE:.metadata.annotations.aerolvm\.io/maintenance`
- Is someone still running a backup, restore or `recover-quorum` there?

**Fix.**

- When the work is done, remove the annotation:
  `kubectl annotate aerolnode <server> aerolvm.io/maintenance-`.

## AerolVMHeadroomLow

**What it means.** In one zone (or the whole install, when pods carry no
zone label), less than 15% of the workers' CPU or memory is free, for 10
minutes. 15% is the AerolCluster's default `headroomPercent`. New workers
are not arriving fast enough. When the room runs out, creates get 503 "no
room".

**Check.**

- `aerolvm top nodes`: free CPU and memory per worker.
- The "CPU reserved, by zone" panel on the AerolVM on Kubernetes dashboard.
- Is the operator adding workers? See
  [AerolVMNodePending](#aerolvmnodepending).

**Fix.**

- In cluster mode: raise the pool's `maxWorkers`, or let it use more machine
  types.
- In single mode: give the worker pod more CPU and memory
  (`worker.runtime.resources`), or move it to a bigger node.
- Your pools use another headroom target? Turn this alert off with
  `monitoring.prometheusRule.disabledAlerts` and copy it from
  `charts/aerolvm/monitoring/rules.yaml` with your number.

## AerolVMCreatesRefusedNoRoom

**What it means.** New sandboxes have been refused for lack of room for 10
minutes. Clients get 503 with Retry-After, and the SDKs retry.

**Check.**

- `aerolvm top nodes`: are all workers full, or only the ones a create can
  use (its zone, runtime or pool)?
- Is the operator adding workers? See
  [AerolVMNodePending](#aerolvmnodepending).

**Fix.**

- Add room, as for [AerolVMHeadroomLow](#aerolvmheadroomlow).
- Ask the teams with idle sandboxes to stop them. The "AerolVM usage per
  team" dashboard shows who reserves the most.

## AerolVMWorkerDiskHigh

**What it means.** A worker has used over 70% of the disk that holds images
and sandboxes. Below `worker.diskFloorRatio` free (20% by default), it
refuses new sandboxes with 503. Sandboxes already running keep writing past
that, up to their own disk size. If the disk is the machine's root disk (the
default `emptyDir`), kubelet evicts pods below its own line (10% free on
EKS), and the worker pod uses the most of it.

**Check.**

- `aerolvm top nodes` and the "Sandbox disk used, per worker" panel.
- Is one sandbox writing a lot? `aerolvm list` and each sandbox's disk use.

**Fix.**

- Delete sandboxes that are no longer needed.
- Put `worker.containerdVolume` on a bigger local disk.
- To cap each sandbox's disk, put the volume on XFS with project quotas
  (`prjquota`) and set `SB_CONTAINERD_DISK_QUOTA` in `worker.extraEnv`
  (see `worker.containerdVolume` in the chart's `values.yaml`).

## AerolVMDecommissionMovesFailing

*Cluster mode.*

**What it means.** While a worker is decommissioned, AerolVM moves each
`failover.policy=recreate` sandbox to another worker. Moves have failed
again and again for 15 minutes. A failed move is tried again, but if it
still fails at the deadline, the sandbox is stopped instead of moved.

**Check.**

- The servers' logs: each failed move names the sandbox and the reason.
- Do other workers have room? Can they pull the sandbox's image?

**Fix.**

- No room: add room (see [AerolVMHeadroomLow](#aerolvmheadroomlow)).
- An image that cannot be pulled: fix the registry or the image.

## AerolVMCertSignerDenied

**What it means.** The servers refused a node's request to join, for a
reason that can mean someone else has a node's credentials: a join token
used twice (`token_used`), a node name already in use (`node_id_in_use`), a
key already in use or revoked (`key_in_use`, `key_revoked`), or a token for
another role (`role_mismatch`). Treat it as a security event until you know
why.

**Check.**

- The audit log names the caller's address and the token's ID for each
  refusal.
- Did the operator retry a join on its own (for example after a restart)?
  Its log shows each join it started.
- Who can read the join token Secrets in the worker namespace?

**Fix.**

- A known retry: nothing. If it happens often, open an issue.
- An unknown caller: find the pod or machine at that address, remove it, and
  tighten who can read Secrets in the worker namespace. Revoke the node's
  key if it may have leaked.

## AerolVMJoinTokenErrors

*Cluster mode.*

**What it means.** For over 10 minutes, the operator kept refusing new pods
their join tokens, or could not make them. A new pod shows the operator a
token Kubernetes made for it; the operator checks it with TokenReview, then
checks the pod is the AerolVM node it says and runs on the machine the token
names. A pod that fails a check gets no token. A token the servers could not
make (no Raft leader) counts too. New nodes wait in Joining, their `setup`
container failing.

**Check.**

- `kubectl describe aerolnode <name>`: the condition `IdentityDenied` says
  why the operator refused that node's pod.
- The operator's log: each refusal, with the caller and the reason. A
  refusal with no pod named means a token Kubernetes did not vouch for:
  something other than an AerolVM pod is asking.
- `aerolvm_operator_join_requests_total` by `result`: `issued`, `refused`
  or `retry`.

**Fix.**

- "the token names no machine": the cluster runs Kubernetes older than 1.30.
  Upgrade it.
- "wrong machine" or "another pod's": a pod is showing a token that is not
  its own. Treat it as a security event: find the pod by the caller address
  in the operator's log.
- "the servers made no join token": the servers have no leader. See
  [lost-quorum-recovery.md](lost-quorum-recovery.md).
- The pod cannot reach the operator: its `setup` log says "the operator did
  not answer". Check the operator pods and the NetworkPolicies on port 9443.

## AerolVMNodeCertificateFailing

*Cluster mode.*

**What it means.** A node's certificate has waited for the issuer for
over 10 minutes. In external-CA mode, the bank's issuer signs every node's
certificate through cert-manager, and the operator makes a node's pod only
once its certificate is ready. Running nodes keep working until their
certificates expire. New nodes cannot join.

**Check.**

- `kubectl describe aerolnode <name>`: the condition `CertificatePending`
  says what the node waits for.
- `kubectl describe certificate <name>-cert` in the node's namespace (the
  worker namespace for a worker): what does cert-manager say?
- `kubectl get certificaterequests -A`: is the request denied, or waiting?
- Is the issuer healthy? `kubectl describe clusterissuer <name>`.
- Does the issuer return its CA? The certificate's Secret needs `ca.crt`
  beside `tls.crt` and `tls.key`.

**Fix.**

- Fix the issuer or its approval policy. The operator retries by itself.

## AerolVMRolloutFailed

**What it means.** An AerolVM upgrade stopped at its first failed node. It
starts no other node. The failed node runs its old version again.

**Check.**

- `aerolvm upgrade status` names the failed node and its error.
- In cluster mode, also see
  [AerolVMUpgradeStepFailing](#aerolvmupgradestepfailing).

**Fix.**

- Fix the cause, then run `aerolvm upgrade apply <same version>` to go on.
- Or put every node back: `aerolvm upgrade rollback`.
- More detail: [cluster-upgrades.md](cluster-upgrades.md).

## AerolVMRolloutStuck

**What it means.** An upgrade has stayed in one state for over an hour. On
Kubernetes the operator changes each node's agent image in turn. A step
that never finishes, or a pause that nobody resumed, holds the upgrade
still.

**Check.**

- `aerolvm upgrade status`: the state and the node it waits for. On
  Kubernetes a node's turn shows as `upgrading` until its new pod reports
  the target version.
- `kubectl describe aerolnode <name>` for that node.

**Fix.**

- `paused`: check the first upgraded nodes, then `aerolvm upgrade resume`.
- A node that does not come back: see
  [AerolVMPodNotReady](#aerolvmpodnotready). Then `aerolvm upgrade apply`
  with the same version, or `aerolvm upgrade rollback`.

## AerolVMUpgradeStepFailing

*Cluster mode.*

**What it means.** The operator could not finish an upgrade step on a node.
Usually the new agent image could not be pulled, or the node did not become
ready in time. The operator put the old image back, and the upgrade
stopped.

**Check.**

- `kubectl describe aerolnode <name>`: the events say which image and why.
- `aerolvm upgrade status`.

**Fix.**

- A pull error: see [AerolVMPodImagePullStuck](#aerolvmpodimagepullstuck).
- A node that did not get ready: read its agent log.
- Then go on with `aerolvm upgrade apply <same version>`, or roll back.

## AerolVMFinalizePending

**What it means.** An upgrade has waited over a day to be finalized. Either
it finished and is held (`--hold`) without a finalize, or a node that missed
its turn has waited a day, and finalize waits for it. Until then, the new
version's new features stay off, and rollback stays possible.

**Check.**

- `aerolvm upgrade status`: the state, and any node marked `skipped` or
  `manual`.

**Fix.**

- Happy with the new version: `aerolvm upgrade finalize`. After that there is
  no rollback.
- A skipped node: bring it back, or delete it with `aerolvm delete node
  <name>`.

## AerolVMUsageExporterStale

**What it means.** A worker's per-team usage counters have not moved for over
10 minutes. The per-team charge misses that worker while this lasts. The
counters only leave the worker when Prometheus reads them, so nothing is
lost once they move again, except the time they were stuck.

**Check.**

- The agent's log on that worker: look for `usage metrics:`. Each skipped
  sample says why.
- Is the worker's database healthy? A sample is skipped when the sandbox
  list cannot be read.

**Fix.**

- A database error: see [AerolVMPodNotReady](#aerolvmpodnotready).
- Still stuck with a healthy database: restart only the agent container.
  Its sandboxes keep running, and it starts new counters:
  `kubectl -n <namespace> exec <pod> -c agent -- /bin/bash -c 'kill 1'`.
  Never delete the worker pod for this: that ends every sandbox on it.
- You do not want usage per team: set `worker.usageMetrics.enabled=false`.
  The counters and this alert go away.

## AerolVMSandboxEgressToClusterRanges

**What it means.** Sandboxes tried to reach the cluster's own addresses at
more than three times the usual rate (and at least 20 times in 15
minutes). Every try was blocked. The `key` label says which kind:

- `deny_floor`: addresses no sandbox may ever reach, such as the Kubernetes
  API server (`worker.egressDenyFloor`).
- `private`: private ranges and the cluster's pod, Service and node ranges
  (`worker.egressPrivateRanges`).

One sandbox scanning the network looks like this, so find out which
sandboxes they were. The count covers sandboxes whose traffic AerolVM's
egress gateway or the V8-isolate proxy handles. Other sandboxes are blocked
by the worker's firewall, which does not count.

**Check.**

- Each refusal is in the audit log with the sandbox's ID (kind `egress`,
  unless `SB_EGRESS_ATTRIBUTION_ENABLED=false`). Search it:
  `aerolvm audit search --since 1h --kind egress --export-dir <dir>`, or in
  your log store where the audit export lands.
- Which team owns those sandboxes? `aerolvm get <sandbox>`.

**Fix.**

- A sandbox that should reach an internal service: open that one range on
  purpose, with an egress profile in AerolVM and the same range in
  `networkPolicy.extraEgressCIDRs`.
- A sandbox that should not: stop it, and tell its owner.

## Alerts still to come

The plan lists these alerts too. They wait on a metric or on a later phase:

- **Raft leader changes above normal.** sandboxd has no leader-change
  counter yet. Until then, [AerolVMNodeLost](#aerolvmnodelost) and the Raft
  panels on the dashboard show server trouble.
- **Checkpoint-move refusals by reason** (C21) and **`adopt` finding fewer
  hosts than expected after an `agent` restart** (C14): Phase 5.
- **`AerolVMAPIServiceUnavailable`**: Phase 6, with the agent-sandbox API.
