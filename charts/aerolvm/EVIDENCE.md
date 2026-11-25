# AerolVM on Kubernetes: security evidence pack

This pack is for a bank's security and platform teams. It says what AerolVM
runs on your cluster, what rights each part has and why, what it can and
cannot reach, and how you check all of it yourself. It ships inside the Helm
chart, so the pack you read always matches the chart you install.

Everything here describes **cluster mode** (`mode: cluster`), the layout for
a bank. Single mode (one pod, for laptops and small installs) is noted where
it differs.

Each promise below that a machine can check is checked by one command,
`aerolvm k8s verify`. It exits 1 on any miss. The list of what it checks is
in [What `aerolvm k8s verify` checks](#what-aerolvm-k8s-verify-checks), and a
test in the AerolVM repository fails if that list and the command ever
differ.

## 1. What runs where

| Namespace | Pod Security level | Pods |
|---|---|---|
| Your release namespace (for example `aerolvm-system`) | `restricted`, which you set | The operator (2), servers (3 or 5, one per zone), gateways (at least one per zone); during a `helm upgrade` only, one CRD upgrade Job |
| The worker namespace (`aerolvm-workers`, made by the chart) | `privileged`, set by the chart | One worker pod per worker machine |

- **Servers** keep the list of sandboxes and where each runs. They agree using
  Raft. Each has its own disk in its own zone.
- **Gateways** take every request (the API, sandbox links, SSH) and pass it to
  the worker that runs the sandbox.
- **Workers** run the sandboxes. One worker pod fills one machine.
- **The operator** makes and watches all of the above. It is the only
  long-running part with rights on the Kubernetes API.
- **The CRD upgrade Job** runs before each `helm upgrade` and updates
  AerolVM's two CRDs, which Helm installs only once. It is removed when it
  is done.

Worker machines should be a node pool of their own, with a taint that only
worker pods tolerate. Then the privileged pods run on machines that run
nothing else.

## 2. Each pod's rights

### Pods with no special rights

| Pod | Runs as | Rights | Kubernetes API |
|---|---|---|---|
| Server | user 65532, not root | No capabilities, no privilege escalation, read-only root disk, `RuntimeDefault` seccomp | None: no service account token for the API is mounted. Its `setup` container alone gets a 10-minute token for the operator's audience, which the API refuses (section 3) |
| Gateway | user 65532, not root | Same as a server. With the edge on, its Caddy container is also user 65532 with no capabilities; port 443 opens through the namespaced `ip_unprivileged_port_start` sysctl, which `restricted` allows | None |
| Operator | user 65532, not root | No capabilities, no privilege escalation, read-only root disk, `RuntimeDefault` seccomp | See below |
| CRD upgrade Job (during a `helm upgrade` only) | user 65532, not root | Same as the operator | Get and update two CustomResourceDefinitions, by name: `aerolclusters.aerolvm.io` and `aerolnodes.aerolvm.io`. Nothing else, and it cannot create one. Its ClusterRole, binding and service account are Helm hooks, deleted when it succeeds (`templates/crd-upgrade.yaml`). Off with `cluster.operator.upgradeCRDs: false` |

The operator's Kubernetes rights, all named in the chart's
`templates/operator.yaml`:

- **In its own namespace and the worker namespace only:** pods, Secrets,
  Services, ConfigMaps and volume claims (to make and replace AerolVM's pods,
  mark which pod got a join token, and keep each server's disk); Events;
  leader election leases; its own `AerolCluster` and `AerolNode` objects.
- **Across the cluster:** read Nodes; list ServiceCIDRs; read Karpenter
  NodeClaims, and delete one to give back a machine it has emptied; create
  TokenReviews, to check which pod, on which machine, asks for a join token.
- **In `default`:** read the `kubernetes` Service and its EndpointSlice, by
  name, to keep sandboxes away from the API server.
- **In enterprise mode only:** open a port-forward to a pod in its own
  namespace (`pods/portforward`), to make its own admin API token on a
  server: there a server takes the admin token only from inside its pod.
- **Not:** `pods/exec`, any other namespace, cluster roles, or anything in
  cert-manager.

The operator can make pods in the worker namespace, where privileged pods are
allowed. That is its job, and it is why its rights stop at those two
namespaces.

### The worker pod: the one exception

| Container | Runs as | Rights | Why |
|---|---|---|---|
| `preflight` (runs first) | user 65532 | None; read-only root disk | Checks the machine: cgroup v2, kernel 5.10 or later, `br_netfilter` |
| `setup` (runs second) | root | None: not privileged, all capabilities dropped, read-only root disk; mounts only the node's settings and state folders, and its token for the operator | Gets the node's one-time join token from the operator and writes the node's cluster files with it |
| `runtime` | root | **privileged** | Runs AerolVM's own containerd and gVisor, which build sandboxes |
| `agent` | root; in `split`, user 65531 | **privileged**; in `split`, none ([below](#privilege-mode-split-an-agent-with-no-rights)) | Runs `sandboxd`, which reads every API request. In `single` it also makes each sandbox's network and cgroup |
| `egress` | starts as root, drops to user 65532 | `NET_ADMIN` and `NET_BIND_SERVICE` only (it gets `SETUID`, `SETGID` and `SETPCAP` just to hand itself over); read-only root disk | The hostname-filtering egress gateway for sandboxes |
| `edge` (with the edge on) | user 65532 | None; read-only root disk | Caddy, for HTTPS sandbox links |

What the worker pod does **not** have: host network, host PID, host IPC, any
folder from the machine (`hostPath`), the machine's containerd socket, a
service account token the Kubernetes API accepts, or any Kubernetes API
right. It copies nothing onto
the machine. A bad firewall rule breaks that worker's sandboxes, not the
machine's networking.

**Why privileged.** Projects that run one Kubernetes pod per sandbox need no
privileged pod, because the kubelet and the machine's containerd (which run
as root) do the root work. AerolVM does that work itself, inside its pod, so
that a sandbox starts in milliseconds without a Kubernetes API call:

| Work done for every sandbox | Needs |
|---|---|
| Run containerd and mount each sandbox's filesystem | `CAP_SYS_ADMIN` |
| A network namespace per sandbox, its link, firewall rules and address translation | `CAP_NET_ADMIN` |
| Each sandbox's CPU and memory box inside the pod's cgroup | A writable `/sys/fs/cgroup` (normal pods get it read-only) |
| Network namespaces shared between `agent` and `runtime` | Two-way mount propagation, which Kubernetes allows only in privileged containers |
| External storage through FUSE (off by default: `worker.externalStorage.enabled`, off in `values-bank-eks.yaml`) | `/dev/fuse` and `CAP_SYS_ADMIN`, and two-way mount propagation of the pod's own `mounts` folder (an `emptyDir`), so a mount the `agent` makes reaches the `runtime` that builds the sandbox. The helpers run in the pod's cgroup, and every mount is removed when the pod ends. It also needs one process namespace for the pod (`shareProcessNamespace`), so the helpers outlive an `agent` restart; that lets every container, the internet-facing `edge` among them, read every process's command line (not its memory or environment, which stay root's), so it stays off unless turned on. Off, `sandboxd` refuses every mount (`501 mounts_unavailable`), never writing to the worker's disk instead; mount credentials go to files, and options that carry one are refused |

We measured the alternatives on Amazon Linux 2023 and Bottlerocket:

- **A named list of rights instead of `privileged: true`** works for a
  one-container worker, with 14 capabilities and seccomp and AppArmor off.
  It is still close to root. It does not work for the two-container worker,
  because of the two-way mount above.
- **A Kubernetes user namespace** (`hostUsers: false`) fails: the worker can
  no longer give each sandbox its own CPU and memory limit.

So `privileged: true` stays, limited to these two containers, in this one
namespace, on machines that run nothing else. With `privilegeMode: split`,
only `runtime` is privileged (below).

**Inside the privileged pod, every sandbox is fenced again.** Each sandbox
runs under gVisor by default (a second kernel between its code and the
machine; the bank preset allows nothing else). Every container sandbox also
gets containerd's own envelope: the default seccomp profile, a trimmed set
of capabilities, masked and read-only kernel paths, and no new privileges.
The chart never turns on `SB_CONTAINER_PRIVILEGED`, which would remove that
envelope.

### Privilege mode split: an `agent` with no rights

`privilegeMode: split` (default `single`) takes the rights away from the
container that reads every API request. The root work moves to a small root
helper, `aerolvm-rootd`, in the `runtime` container, which is privileged in
both modes. The `agent` asks it over one Unix socket. The helper lets in only
the agent's uid, and checks every request against fixed rules before it acts.
That includes containerd writes: the `agent` reaches containerd only through
the helper.

| Container | `single` | `split` |
|---|---|---|
| `agent` | root, **privileged**; mounts containerd's root and socket, `/run/netns` two-way | user 65531; no capabilities; no privilege escalation; read-only root disk; `RuntimeDefault` seccomp; no containerd root or socket; no `/run/netns` |
| `runtime` | root, privileged | root, privileged; also runs the root helper, only from a copy whose signature a release key built into the `aerolvm-runtime` image checks |
| Pod | two-way mounts; one process namespace with external storage, WASM, V8 or Firecracker | no shared process namespace; no two-way mount, except, with V8 isolates on, the jails' folder from `runtime` (below); with WASM on, the `agent` is in the WASM workers' group (61000) |
| Folders from the machine | none | `/sys/fs/cgroup`, read only, in `agent` alone: it reads its sandboxes' memory and CPU there, and cannot write a cgroup file |
| External storage | off by default | on by default: the helper runs the mount tools as their own user, in the `runtime` container |
| Folders root writes | n/a | none the `agent` can write: see below |
| `split-folders` (first) | absent | root with `CAP_CHOWN` only; sets five folders' owners (six with V8 isolates), then exits |
| `workerd` (first, V8 isolates only) | absent | root with no capability; copies `workerd` from the `aerolvm` image into a volume of its own, then exits |

**Folders shared with the `agent` in split.** No root process writes in a
folder the `agent` can write. Three containers start as root: `runtime`,
`egress` (until it drops to user 65532) and `split-folders`; with V8
isolates on, a fourth, `workerd`. A test in the
AerolVM repository renders the pod and fails if any of them writes a
volume the `agent` writes, other than the two named below, or if another
container starts as root.

| Volume | `agent` | Root containers | What they do there |
|---|---|---|---|
| `state` (sandboxd's data) | writes | `split-folders` writes; `runtime` and `egress`: not mounted | `split-folders` gives the volume's top folder to the agent, before the agent starts |
| `run-aerolvm` (`/run/aerolvm`) | writes (ownership lease, its own sockets) | `runtime` and `egress`: read only | the supervisor reads the lease: no link followed, regular files only, size bound; the gateway dials sandboxd's lookup socket |
| `run-runtime` (`/run/aerolvm-runtime`) | read only | `runtime` writes | the supervisor writes the cgroup parent; temporary file by `O_EXCL`, then rename |
| `run-egress` (`/run/aerolvm-egress`) | read only | `split-folders` and `egress` write | `split-folders` gives the folder to the gateway's user (65532, 0755); the gateway makes its control socket there, and refuses a folder another user can write |
| `toolbox` | writes `toolboxd` | `runtime`: read only | the helper copies it: no link followed, a regular file the agent owns, size bound |
| `rootd-stage` | writes the helper and its signature | `runtime`: read only | the supervisor copies them into a folder of its own, then checks the copy's signature |
| `rootd-shared` (`/run/aerolvm-rootd/shared`) | writes only in its own folder, `agent/` | `split-folders` and `runtime` write | `split-folders` makes the top root's (0750, the agent's group), then makes `agent/`; the helper makes its socket, ready sockets, task output and the WASM hosts' sockets (`wasm/`) in folders of its own there, and links ready sockets from `agent/` by handle. With WASM on, the agent's compile cache is in `agent/`: the helper opens it, following no link, and hands it to each WASM host |
| `tmp`, `run-sandboxd` | writes | not mounted | none |
| `cni-state` | not mounted | `split-folders` and `runtime` write | `split-folders` closes it to other users (0755); the CNI plugins' address records |
| `run-containerd` | not mounted | `runtime` writes | containerd's socket |
| `egress-state` | not mounted | `egress` writes | the gateway's rule snapshot and each sandbox's learn-mode record |
| containerd's volume | one empty folder, read only | `split-folders` and `runtime` write | containerd's images and layers; in a folder of its own, `aerolvm-rootd-moves`, the helper's gVisor move checkpoints: `split-folders` makes it root's alone (0700) |
| `host-cgroup` (machine) | read only | not mounted | none |
| `isolate-jail` (V8 isolates, `/srv/isolate-jail`) | read only, mounts taken in (`HostToContainer`) | `split-folders` and `runtime` write | `split-folders` makes the top root's (0755); the helper links each group's jail, mounts its `run` and `tmp` folders (a `tmpfs` each) and runs `workerd` there. Each `run` folder is the agent's (it writes `workerd`'s settings there), so the folder is two-way from `runtime` alone; the supervisor unmounts the jails when the pod ends |
| `workerd` (V8 isolates) | not mounted | the `workerd` init container writes; `runtime`: read only | the helper reads `workerd`'s libraries and copies it into the jails' base |

What split does not run yet, refused by name at `helm install`:
Firecracker. On VM installs `sandboxd` runs Firecracker in split, its VM
pool included. The chart refuses it because it does not wire Firecracker
into a split pod yet, and no live run has proven it there.

WASM and V8-isolate sandboxes run in split. The helper starts their hosts
in the `runtime` container, WASM workers as their own user (61000) and
`workerd` in its jail, so they outlive an `agent` restart with no process
namespace shared. With WASM on, the deny floor (the Kubernetes API
server's addresses) reaches the `runtime` container too, where the helper
keeps the WASM workers' network fence. Split also runs the
container warm pool, the kubectl API's warm pools and gVisor moves with
memory (`worker.gvisor.checkpointMoves` stays off by default in split). A
gVisor sandbox moves only between workers of one privilege mode.

What is proven so far, and how:

- **The chart.** `single` renders byte for byte what the chart rendered
  before (a diff over 15 value sets). Tests in the AerolVM repository check
  that each refused value matches a refusal `sandboxd` itself makes at
  start, that a new refusal in `sandboxd` fails the build until the chart
  refuses it too, that a split worker renders a pod `sandboxd` starts in,
  and that the helper reads the same settings the agent does.
- **The helper and the gate.** Tests in the repository send the helper
  and the containerd gate the requests a broken agent could send, and
  check each is refused. They are listed by name in
  [Requests the helper and the gate refuse](#requests-the-helper-and-the-gate-refuse).
- **On kind** (`integration-tests/k8s/split.sh`, on Docker Desktop, kernel
  5.10, 2026-11-23): the `agent` runs as uid 65531 with no capability and
  cannot write its root disk; it has no containerd root, socket or
  `/run/netns`; the pod has no two-way mount and no shared process
  namespace; the helper runs from the supervisor's verified copy. runc and
  gVisor sandboxes run commands and take files in and out, and cannot
  reach the worker's ports or the Kubernetes API. No-network, address and
  hostname allow lists hold. An rclone mount of a MinIO bucket reaches its
  gVisor sandbox, with rclone running as the mount tools' own user in the
  `runtime` container. After an `agent` restart and then a helper restart,
  every sandbox still answers, new ones start, and the mount keeps writing.
  `aerolvm k8s verify` passes and reports the worker in split. Deleting the
  pod with sandboxes running took 7 seconds and left nothing on the
  machine. With `privilegeMode: auto`, an upgrade kept each mode, a new
  install rendered split, and a running pod kept its mode until it was made
  again. With the edge on, the smoke test passed in split (HTTPS API,
  sandbox link, certificate renewal with no restart), and a raw TCP port
  answered from another pod. Single mode's smoke test passed on the same
  images. Docker Desktop's kernel (5.10) cannot show memory pressure
  or real create latency; those were left to the EKS run (below). Again on
  2026-11-24, with the egress gateway's socket in a folder of its own:
  the `agent` saw the socket there and could not write the folder, the
  `egress` container could not write `/run/aerolvm`, hostname allow lists
  through the gateway held, and every other check above passed again.
- **WASM and V8 isolates in split, on kind** (2026-11-24, `split.sh` with
  both on): a WASM sandbox and a V8 sandbox answered. Their processes ran
  in the `runtime` container, WASM's as uid 61000 and `workerd` as the
  jail's uid 1000, and the `agent` could not see either. The `agent`
  could not write the jails' folder, only each jail's `run` folder. After
  an `agent` restart the processes that held them still ran, both
  sandboxes answered, and the new `agent` took both over. Both deleted. Every other
  split check above passed with them on, and deleting the pod took 1
  second and left none of the jails' mounts on the machine.
- **Cluster mode on kind** (2026-11-24, after the first EKS drill found a
  split worker that could not read its join token): three servers, a
  gateway and one split worker pool. The worker's `setup` (uid 65531)
  read its token, the worker joined, runc and gVisor sandboxes ran on it,
  and `aerolvm k8s verify` reported `general: split 1`. In a split worker
  the token is mode 0444 (and an external-CA certificate 0404): the pod has
  no fsGroup and its containers run as different users, so Kubernetes
  makes these files root's, and only their readers mount them.
- **On EKS** (24 November 2026, the kit in `integration-tests/k8s/m1/`):
  cluster mode on three `m7i.xlarge` workers with Amazon Linux 2023
  (Linux 6.18). Each worker switched from `single` to `split` in turn,
  by decommission, and `aerolvm k8s verify` passed at every stage: all
  single, one split, two split, all split. What passed:
  - the split pod's shape: the `agent` as uid 65531, with no
    capabilities, not privileged, with no containerd, running the signed
    helper; and the same image user in split as in single;
  - an upgrade that swapped every `agent` in place kept every sandbox
    running, and the newer signed helper took over;
  - an rclone mount reached its sandbox and kept writing across that
    upgrade and across a helper restart;
  - a restarted helper ran alone in its cgroup;
  - a helper signed by another key, and an older helper, were refused,
    and the running helper stayed. An image with an unsigned helper was
    refused by the `agent`'s start, before the supervisor saw it. So the
    supervisor's own check for that case is proven by unit tests only;
  - a gVisor sandbox moved from one split worker to another with its
    memory, and a move from a single worker to a split one was refused
    before anything was saved, with the sandbox still running;
  - deleting a split worker pod with sandboxes running left nothing on
    its machine;
  - five gVisor sandboxes, each holding 3 GB on a 16 GB machine, under
    memory pressure: the kernel stopped whole sandboxes only, never the
    worker's own processes.

  The memory test and the cross-mode move call were run by hand, because
  the drill's own scripts had bugs; those are fixed. The run also found
  two bugs in replacing a worker, both fixed since: a decommission that
  never ended at its deadline, and a sandbox on a removed node that could
  not be deleted.
- **Not yet proven:**
  - Firecracker in a split worker pod. The chart refuses it.
  - A warm create inside its +1 ms budget on EKS (below).
  - In that run, a gVisor move between two single workers. Its test
    sandbox came from the warm pool, which moves only by recreate.

  The chart's default stays `single` until the release workflow signs the
  helper and the warm create is measured again.

#### Create speed in split

The time the worker reports for each create, split against single, in
that EKS run. The budget is on the p50 (the median).

| Create | `single` p50 | `split` p50 | p50 gap | Paired median difference (95% range) | Budget |
|---|---|---|---|---|---|
| Cold, no warm pool | 152.0 ms | 143.3 ms | -8.7 ms | -0.15 ms (-36.00 to +20.70) | +3 ms |
| Warm, from the container warm pool | 16.7 ms | 18.0 ms | **+1.3 ms** | +0.80 ms (+0.40 to +1.60) | +1 ms |

- **The warm p50 gap is over its budget.** 50 of the 120 warm rounds
  were pool misses and were left out. A warm claim in split makes two
  trips through the helper: one through the gate to label the
  container with its new sandbox, and one to put the sandbox's network
  rules in place. A change since makes both at the same time. On two test machines it
  closed part of the gap in one run and none of it in another. The next
  EKS run measures it.
- **20 creates at once:** split p50 976 ms, single p50 2,210 ms. The run
  set no budget for bursts and did not look into why split was faster.
- **The first create after a split helper started** took 17.7 ms.
- **WASM and V8 isolates** were timed in an earlier run, on one VM
  (`m7i.xlarge`, Ubuntu 24.04), in single and split in turn. The budget
  is +1 ms. The paired median differences were:
  - a warm WASM create: +0.05 ms (95% range -0.05 to +0.20);
  - a busy WASM mix: +0.15 ms (-2.75 to +0.40);
  - a warm V8 create: -0.10 ms (-0.15 to -0.05).

  All three meet the budget.

#### Requests the helper and the gate refuse

The `agent` only sends requests its own code built. The tests below act
as a broken agent. They send the helper and the containerd gate requests
the agent's code never builds. Each must be refused before anything
changes.

| The request | Refused by | Test |
|---|---|---|
| A container with an extra capability, no seccomp profile, or `NoNewPrivileges` off | The gate | `TestBrokenAgentWrites` in `internal/rootd/gate/gate_test.go` |
| A bind mount of `/`, `/proc` or another folder outside AerolVM's own | The gate | `TestBrokenAgentWrites` |
| An OCI hook, or a device | The gate | `TestBrokenAgentWrites` |
| A runtime binary such as `BinaryName=/bin/sh`, a shim binary, or a runsc config file that is not the helper's own | The gate | `TestBrokenAgentWrites` |
| The gVisor annotation `dev.gvisor.flag.network=host` | The gate | `TestBrokenAgentWrites` |
| A network namespace path with `../`, or a namespace name that is not a sandbox's | The gate; the helper | `TestBrokenAgentWrites`; `TestNetworkCallsRefuse` in `internal/rootd/network_test.go` |
| A cgroup outside the sandboxes' parent | The gate; the helper | `TestBrokenAgentWrites`; `TestCgroupPartBrokenAgent` in `internal/rootd/cgroup_test.go` |
| A root filesystem, or a layer unpack (`Diff.Apply`), that writes into a host folder | The gate | `TestBrokenAgentWrites` |
| A containerd call off the gate's list of 41, such as `Tasks.Exec` or `Tasks.Checkpoint`, or another containerd namespace | The gate | `TestUnlistedMethodsRefused`, `TestNamespaceIsPinned` in `internal/rootd/gate/gate_test.go`; `TestBrokenAgentSubscribeSeesOnlyItsNamespace` in `internal/rootd/gate/events_test.go` |
| A request field the gate was not written for | The gate at run time; the build, after a containerd upgrade | `TestBrokenAgentWrites`; `TestFieldPins` in `internal/rootd/gate/fields_test.go` |
| A mount option or tool argument off the allow list, a credential in an argument, rclone's `local` backend, or a mount target outside the sandbox's own | The helper | `TestMountExternalBrokenAgent` in `internal/rootd/mounts_test.go` |
| A host process of a kind the helper does not know, an ID that is a path or an option, or limits above the node's | The helper | `TestHostsRefuseHostileRequests` in `internal/rootd/hosts_test.go` |
| A Firecracker disk staged for a VM that is a name the agent may not stage, a link, a file with a second name, a folder, or a file the agent does not own | The helper | `TestFirecrackerPrepareRefusals` in `internal/rootd/hosts_firecracker_test.go` |
| An image user or disk quota for a snapshot that is not the container's own | The helper | `TestImageUserBrokenAgent`, `TestDiskQuotaBrokenAgent` in `internal/rootd/imageuser_test.go` |
| A move bundle the helper must not stage, or a move call for an ID that is a path | The helper | `TestMoveBrokenAgentImports`, `TestMoveBrokenAgentCalls` in `internal/rootd/moves_test.go` |
| A host port outside the node's range, or for an address that is not a sandbox's | The helper | `TestHostPortRefusals` in `internal/rootd/hostports_test.go` |
| A caller that is not the agent's user, or, on a VM, not in its service's cgroup | The helper's socket | `TestPeerCheckUID`, `TestPeerCheckCgroup` in `internal/rootd/peer_linux_test.go`; `TestPeerRefusedNeverReachesAHandler` in `internal/rootd/server_test.go` |
| A staged helper that is unsigned, signed by another key, cut short, changed after the check, or older than the one running | The supervisor; the installer | `TestInstallRefuses`, `TestReplacedAfterTheCheckChangesNothing` in `internal/rootswap/install_test.go`; `TestVerifyRefuses`, `TestCheckNewer` in `internal/rootswap/rootswap_test.go` |

The other side is tested too. Every container shape the agent builds
passes the gate (`TestBuilderOutputPassesRootPolicy` in
`internal/runtime/containerd/rootpolicy_conformance_test.go`), and the
shared rules are fuzzed (`internal/rootpolicy/fuzz_test.go`). The
`TestE2EBrokenAgent` tests in `internal/rootd` send the same kinds of
requests to a live helper with real containerd, on a Linux test machine
(`AEROL_E2E_HELPER_SOCKET`).

**Every refusal is recorded.** The call fails with `500`
(`TestRefusalsAre500AndRecordedOnce` in
`internal/rootclient/refusal_api_test.go`). The agent writes a
`rootd_refusal` audit record (`TestRecordRootRefusal` in
`internal/service/rootd_refusal_audit_test.go`). It counts the refusal
in `aerolvm_rootd_refusals_total`, and the `SandboxdRootHelperRefusal`
alert fires within 5 minutes (`TestRootHelperRefusalAlertRule` and
`TestRootHelperRefusalAlertFires`, in `setup/prometheus/alerts_test.go`;
CI's go-tests job runs the second with `promtool`). The chart's own rules
(`monitoring/rules.yaml`) carry the same alert, copied from
`setup/prometheus/sandboxd-alerts.yml`, so `monitoring.enabled=true`
installs it. `TestChartCarriesSetupAlertsAsIs` fails if the copy differs
from the setup rule, and `TestRootHelperRefusalAlertFires` runs promtool's
tests on both.
The helper also logs each refusal itself, as root, in the `runtime`
container's log, where the agent cannot change it. The runbook is
`setup/runbooks/secrets-and-audit.md`, "Root helper refusal".

#### What split does not cover

- The helper, containerd, runc, gVisor's `runsc` and the Firecracker
  jailer still run as root, and `runtime` stays privileged. A bug in them
  is a root bug, in both modes.
- The `agent` still holds, for its machine, each sandbox's toolbox token,
  the key that opens their environment variables, and the node's cluster
  certificate. So a bug in the `agent` still matters for the sandboxes on
  that machine and their secrets. Split keeps it inside the `agent`
  container: no root, no folder from the machine but the read-only cgroup
  tree, and no Kubernetes API credential.
- Escapes from a sandbox are the runtime's job (gVisor, Firecracker), not
  split's.
- The Docker engine has no gate in front of its socket, so a Docker node
  (local mode) runs in `single` only.

## 3. Identity

- **A new pod proves who it is before it gets a join token.** Kubernetes
  gives the pod's `setup` container a token that names the pod and its
  machine, for the operator's audience alone (the Kubernetes API refuses
  it), good for 10 minutes. The pod shows it to the operator, which checks
  it with TokenReview: the pod exists with that UID, belongs to an AerolVM
  node, runs on the machine the token names, and has not joined. Only then
  does the operator ask the servers for a join token for it. That token
  works once, lasts 10 minutes, and is never stored in a Secret. The
  operator marks the pod, so it gets one token, or a fresh one only after
  the first ran out unused. A refused pod's AerolNode says why
  (`IdentityDenied`).
- **Nodes talk to each other with mutual TLS.** Each node has its own
  certificate, signed by the cluster's certificate authority, which renews
  itself. The CA key lives on the servers.
- **Gossip** (who is alive) is encrypted with the cluster's gossip key.
- **Workers hold no admin token.** They know only its fingerprint, to check
  callers. Only servers hold it, from a Secret the operator makes in the
  release namespace.
- **In enterprise mode the admin token never works from outside a pod.**
  Every node takes it only from inside its own pod and from the cluster's
  own nodes; the edge reaches AerolVM on a socket where it is refused. A
  person uses it through `kubectl port-forward` to a server. The operator
  makes an admin API token for itself that way, keeps it in a Secret in the
  release namespace, and replaces it before a third of its life (30 days at
  most) is left.
- **Callers** use AerolVM's own API tokens, SSO and roles, as on any install.
  `identity.enabled` turns tokens on for servers, gateways and workers
  alike; it gives no node the admin token.
- **Prometheus reads metrics with a token you make.** In cluster mode the
  chart has no default scrape token: you name its Secret
  (`monitoring.scrapeToken`). The bank preset uses a viewer token for every
  team. On every node it may read metrics, sandbox details (never their
  env) and audit logs. It cannot create, change, stop or run anything,
  read secrets, or make tokens, and it expires.

**Or, with your own CA** (`cluster.externalCA.issuerRef`, external-CA mode):

- **No CA key is in the cluster.** Your issuer signs every node's
  certificate through cert-manager. The operator asks for one certificate
  per node and makes the node's pod only once it is ready.
- **The certificate is the credential.** It names the node and its one role.
  The node joins with it over mutual TLS: no join token is made. The cluster
  keeps the node's key and refuses any other key for that node.
- **cert-manager renews it,** with the same key, and the node reads the new
  certificate on its next connection.
- **The mode is set at install** and cannot be turned on or off after the
  cluster starts.

## 4. Network walls

| From | To | Allowed | Enforced by |
|---|---|---|---|
| Clients | Gateways | The client ports only (the API, SSH, and 443 with the edge; no port 80), through the gateways' load balancer or your own Gateway API Gateway | Your load balancer; NetworkPolicy `<release>-gateway-ingress` |
| Anything but AerolVM's pods | Gateways' cluster ports, servers | Nothing (Prometheus may read the servers' metrics) | NetworkPolicies `<release>-gateway-ingress`, `<release>-server-ingress` |
| The API server | The operator | Its webhook port only | NetworkPolicy `<release>-operator-ingress` |
| Gateways | Workers | Forwarded requests, over mutual TLS | NetworkPolicy `<release>-worker-ingress`; mTLS |
| Servers, other workers | Workers | Raft, gossip and the internal port | Same |
| Prometheus | Workers | The metrics port only, from the namespace you name | Same |
| Anything else | Workers | Nothing | Same |
| Workers | AerolVM pods, cluster DNS, the internet | Only these, never a private range | NetworkPolicy `<release>-worker-egress` |
| Sandboxes | Your network, other pods, the Kubernetes API, the worker's own ports | Nothing, unless a create opens one internal range on purpose. The API server can never be opened: the operator puts its addresses on every new worker's deny floor, and the cluster's pod and Service ranges in its closed-by-default list | AerolVM's own firewall in each worker, then the egress NetworkPolicy around the whole pod |
| Sandboxes | The cloud metadata service | Never | AerolVM's firewall, the egress NetworkPolicy, and the machine's IMDS hop limit of 1 |

NetworkPolicies need a network plugin that enforces them (on EKS: the VPC CNI
with network policy turned on, or Calico or Cilium).

**Known gaps, said plainly:**

- Without the edge, clients reach the gateways' API over plain HTTP inside
  the cluster. Turn the edge on for HTTPS (the bank preset does).
- The operator reaches the servers' API over plain HTTP inside the cluster,
  with the admin token. Only AerolVM's own pods can reach that port.
- A NetworkPolicy sees a sandbox's traffic as its worker pod's, and worker
  pods may reach the servers and each other. So a sandbox whose create
  opens the cluster's pod range (`network_allow_out`) can reach those ports.
  It still cannot use them: Raft and the internal port take only the
  cluster's node certificates (mutual TLS), gossip only the cluster's
  gossip key, and the API a token. Leave the pod range closed (it is by
  default; no sandbox needs it). The create policy cannot refuse it yet.
- `networkPolicy.extraIngressFrom` adds callers to the workers' wall only.
  The servers, the gateways' cluster ports and the operator take no extra
  callers: nothing outside AerolVM needs them.

## 5. Data flows

- **Create.** A client calls a gateway. The gateway checks the token and the
  create policy, asks the servers which worker should run it, and forwards
  the request to that worker over mTLS. The worker checks the create policy
  again and starts the sandbox. The servers record where it runs (Raft).
- **Secrets.** Environment secrets and mount credentials are sealed with the
  cluster's AEAD key before they are stored or copied to another node.
- **Commands, files, sandbox links, SSH.** Client to gateway, gateway to the
  owning worker over mTLS, worker to the sandbox inside the pod.
- **A machine goes away on purpose** (cordon, Karpenter drift, scale-down,
  age). The operator drains the worker, then moves each sandbox that asked
  for it (`failover.policy: recreate`) to a worker in another zone: the new
  worker pulls the image, the old copy stops, and the new one starts with the
  same ID. Owners of other sandboxes get a notice in the sandbox's audit log.
- **A machine dies.** Sandboxes that asked for it start again on a worker in
  another zone, from their stored create request. Nothing from the dead
  machine's disk is copied.
- **Audit.** Every create, delete, command, file access, port change,
  snapshot and token call, every refused call, and every secret opened is
  written to a hash-chained audit log, which can be shipped to your SIEM and
  witnessed in an S3 bucket with Object Lock (docs: Audit evidence). In
  enterprise mode both are required, and every node writes to them
  (`audit.witness`, `audit.export`), signing in to S3 through IRSA: the IAM
  role of a service account the chart makes, with no Kubernetes rights
  (a gateway serving the agent-sandbox API keeps its own account, which
  has that API's two rights), reaching each pod's agent container only.

## 6. Threat model

| Threat | What stops it |
|---|---|
| Code in a sandbox escapes the sandbox | gVisor by default (a second kernel); containerd's seccomp, capability and path envelope; the create policy can allow only gVisor |
| Something escapes to the privileged worker container | Worker machines run nothing else (taint); no host folders, network or PID; no Kubernetes API right; the machine's cloud identity is unreachable (IMDS hop limit 1) |
| A bug in the code that reads API requests (`sandboxd`, in the `agent` container) | With `privilegeMode: split`, the `agent` has no rights. Root work goes through the signed root helper, which checks each request. containerd is reached only through its gate. Every refusal is recorded ([above](#requests-the-helper-and-the-gate-refuse)). With `single`, the `agent` is privileged |
| A sandbox reaches your network or the cluster | AerolVM's firewall refuses private ranges, the cluster's ranges, the API server and the worker's own ports; the egress NetworkPolicy refuses the same around the whole pod; `aerolvm k8s verify` probes it from a real sandbox |
| Another pod in the cluster reaches a worker | The worker ingress NetworkPolicy; mTLS on every node port |
| A rogue pod joins the cluster | A join token only for a pod that TokenReview proves is that AerolVM node, on its machine; single use, 10 minutes, never stored in a Secret; mTLS certificates per node |
| A tampered or unsigned image | Signed images with SBOMs and provenance; the example admission policy refuses any AerolVM pod whose image the release workflow did not sign |
| Someone deletes or drains a worker pod by mistake | The operator's delete guard refuses it, also mid-move, unless every sandbox has moved or the pod is marked `aerolvm.io/force-delete=true`; the guard fails open, so a down operator never blocks repairs. A PodDisruptionBudget holds drains and node group updates until the operator has moved the sandboxes |
| The Kubernetes API is down | Sandboxes keep running and the API keeps answering: AerolVM's control plane is its own. Only changes to the layout wait |
| Too many sandboxes for a machine | Every sandbox is capped inside the worker pod's own CPU and memory limit; one out-of-memory event ends one sandbox, never the worker |

### What each option protects against

Two settings decide how sandboxes are walled off, and they guard different
things. The runtime is the wall around each sandbox; a create picks it, and
the create policy can limit the choice. The privilege mode is the wall
around AerolVM's own code on the worker; the chart value `privilegeMode`
picks it.

| Option | Picked for | The wall | What it does not cover |
|---|---|---|---|
| Container (`docker`, runc) | Each sandbox | Linux namespaces, cgroups, containerd's default seccomp profile and a trimmed list of capabilities | A bug in the machine's kernel: the sandbox shares it |
| gVisor (`gvisor`) | Each sandbox | A container, plus gVisor's own kernel in user space, so few system calls reach the machine's kernel | A bug in gVisor, or in the few calls it passes on |
| Firecracker (`firecracker`) | Each sandbox | A virtual machine with its own kernel, kept apart by the CPU (KVM); Firecracker runs under the jailer as an ordinary user. Not in a split worker pod yet | A bug in KVM or Firecracker; a breakout lands in the jailed Firecracker process |
| WebAssembly (`wasm`) | Each sandbox | The WebAssembly runtime: the module makes no system calls of its own; its worker runs as its own user (61000) with a system call filter | A bug in the runtime; there is no virtual machine or container around the worker |
| V8 isolate (`isolate`) | Each sandbox | A V8 isolate in a jailed `workerd` process, one process per tenant | A bug in V8 or `workerd`; the jail is what is left around them |
| `privilegeMode: single` | Each worker | None: the `agent` is privileged | A bug in `sandboxd` has the `agent`'s rights |
| `privilegeMode: split` | Each worker | The `agent` has no rights; the root helper checks each request; containerd only through the gate | A bug in the helper, containerd, runc, `runsc` or the jailer; the `agent`'s own reach ([above](#what-split-does-not-cover)) |

## 7. Verify the images yourself

Every image (`aerolvm`, `aerolvm-runtime`, `aerolvm-edge`, `aerolvm-operator`)
is signed by AerolVM's release workflow, keyless, with an SBOM and build
provenance. `RELEASE-VERIFICATION.md` in the repository shows the `cosign
verify` and `gh attestation verify` commands and the exact identity to
expect. Run images by digest, not tag.

## 8. Admission policy, and its one named exception

**Pod Security.** Label the release namespace `restricted`. The chart labels
the worker namespace `privileged`. That is the one exception, and it is
narrow: only the worker pods' `runtime` and `agent` containers are privileged,
and with `privilegeMode: split` only `runtime`. `aerolvm k8s verify` checks
both labels and fails on any other privileged container.

If you also run your own pod-security policies (Kyverno, Gatekeeper), exempt
pods labelled `app.kubernetes.io/name=aerolvm`,
`app.kubernetes.io/component=worker`, in the worker namespace, and only these
containers: `runtime` and `agent` for `privileged`; `egress` for running as
root and adding `NET_ADMIN`, `SETUID`, `SETGID` and `SETPCAP` (it starts as
root only to drop to user 65532 with `NET_ADMIN` and `NET_BIND_SERVICE`);
the `setup` init container for running as root (all capabilities dropped);
and, with `privilegeMode: split`, the `split-folders` init container for
running as root and adding `CHOWN`, and with V8 isolates on, the `workerd`
init container for running as root (all capabilities dropped). A split
`agent` needs no exception.

**Signed images.** `examples/kyverno-signed-images.yaml` in this chart is a
Kyverno policy that refuses any pod in the two AerolVM namespaces whose image
the release workflow did not sign, and runs each image by the digest it
checked. It was tested with Kyverno 1.15: a release image was admitted and
pinned to its digest; an image missing from the registry and a signed image
checked against another signer were refused.

## 9. What a sandbox may be: the create policy

Write the policy in the chart's values (`cluster.createPolicy`). The chart
puts it in a ConfigMap, and the operator puts it on every node. The node a
create reaches checks it, and the worker that runs the sandbox checks it
again. A create that breaks a rule is refused with 403 and the rule's name.
If the policy is named but missing, every create is refused until it is
there. Every pod mounts the policy, so turning it on, changing it or
turning it off reaches every running node within about a minute. It can limit images and registries, runtimes, size, root images and
GPUs. The bank preset allows only gVisor and your own registry.

## 10. Cloud credentials without stored keys

A sandbox that needs a cloud API gets a short-lived credential through
AerolVM's workload identity (docs: Sandbox cloud identity): the server signs
a token for that one sandbox, and the cloud trades it for temporary
credentials. No long-lived key is stored in the sandbox, its image, or
AerolVM. The machine's own cloud identity stays unreachable from sandboxes.

## 11. Start from the bank preset

`values-bank-eks.yaml` in this chart turns all of this on: cluster mode over
three zones, gVisor only, NetworkPolicies, HTTPS, the create policy,
monitoring, machine replacement every 30 days, and enterprise mode with the
audit witness and an S3 export. Its header lists what you set outside the
chart: the namespace label, the worker NodePool, the EC2NodeClass's
metadata settings, `br_netfilter` on worker machines, cert-manager,
Prometheus, and the two audit buckets with the nodes' IAM role.

## What `aerolvm k8s verify` checks

Run `aerolvm k8s verify --namespace <release namespace> --worker-namespace
aerolvm-workers --release <Helm release> --cluster <AerolCluster name>`. It
exits 1 on any failed rule. Rules about the cluster layout (the release
namespace's label, the worker and server ingress policies) run in cluster
mode only; the
Gateway rules run when the chart made Gateway API routes
(`cluster.gateways.gatewayRef`); the probe runs once per runtime.

<!-- verify-rules:start -->
- AerolVM pods found
- images signed by the AerolVM release workflow
- no folders mounted from the machine, except a split agent's read-only cgroup tree
- no Kubernetes API credential in the pods
- no DNS provider token in the pods
- privileged containers only in the worker pods' runtime and agent
- each worker pool's privilege mode
- the worker namespace's Pod Security label is privileged
- the release namespace enforces restricted Pod Security
- a NetworkPolicy limits the worker pods' egress
- a NetworkPolicy limits who reaches the worker pods
- a NetworkPolicy limits who reaches the servers
- worker machines allow IMDSv2 only, with a hop limit of 1
- the Gateway accepted every AerolVM route
- the sandbox-link listener passes TLS through
- a &lt;runtime&gt; sandbox cannot reach the worker, another pod or the Kubernetes API
<!-- verify-rules:end -->
