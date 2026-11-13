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
| Your release namespace (for example `aerolvm-system`) | `restricted`, which you set | The operator (2), servers (3 or 5, one per zone), gateways (at least one per zone) |
| The worker namespace (`aerolvm-workers`, made by the chart) | `privileged`, set by the chart | One worker pod per worker machine |

- **Servers** keep the list of sandboxes and where each runs. They agree using
  Raft. Each has its own disk in its own zone.
- **Gateways** take every request (the API, sandbox links, SSH) and pass it to
  the worker that runs the sandbox.
- **Workers** run the sandboxes. One worker pod fills one machine.
- **The operator** makes and watches all of the above. It is the only part
  with rights on the Kubernetes API.

Worker machines should be a node pool of their own, with a taint that only
worker pods tolerate. Then the privileged pods run on machines that run
nothing else.

## 2. Each pod's rights

### Pods with no special rights

| Pod | Runs as | Rights | Kubernetes API |
|---|---|---|---|
| Server | user 65532, not root | No capabilities, no privilege escalation, read-only root disk, `RuntimeDefault` seccomp | None: no service account token is mounted |
| Gateway | user 65532, not root | Same as a server. With the edge on, its Caddy container is also user 65532 with no capabilities; ports 80 and 443 open through the namespaced `ip_unprivileged_port_start` sysctl, which `restricted` allows | None |
| Operator | user 65532, not root | No capabilities, no privilege escalation, read-only root disk, `RuntimeDefault` seccomp | See below |

The operator's Kubernetes rights, all named in the chart's
`templates/operator.yaml`:

- **In its own namespace and the worker namespace only:** pods, Secrets,
  Services, ConfigMaps and volume claims (to make and replace AerolVM's pods,
  hand each pod its join token, and keep each server's disk); Events; leader
  election leases; its own `AerolCluster` and `AerolNode` objects.
- **Across the cluster:** read Nodes; list ServiceCIDRs; read Karpenter
  NodeClaims, and delete one to give back a machine it has emptied.
- **In `default`:** read the `kubernetes` Service and its EndpointSlice, by
  name, to keep sandboxes away from the API server.
- **Not:** `pods/exec`, any other namespace, cluster roles, TokenReview, or
  anything in cert-manager.

The operator can make pods in the worker namespace, where privileged pods are
allowed. That is its job, and it is why its rights stop at those two
namespaces.

### The worker pod: the one exception

| Container | Runs as | Rights | Why |
|---|---|---|---|
| `preflight` (runs first) | user 65532 | None; read-only root disk | Checks the machine: cgroup v2, kernel 5.10 or later, `br_netfilter` |
| `setup` (runs second) | root | None: not privileged, all capabilities dropped, read-only root disk; mounts only the node's settings and state folders | Writes the node's cluster files with its one-time join token |
| `runtime` | root | **privileged** | Runs AerolVM's own containerd and gVisor, which build sandboxes |
| `agent` | root | **privileged** | Runs `sandboxd`, which makes each sandbox's network and cgroup |
| `egress` | starts as root, drops to user 65532 | `NET_ADMIN` and `NET_BIND_SERVICE` only (it gets `SETUID`, `SETGID` and `SETPCAP` just to hand itself over); read-only root disk | The hostname-filtering egress gateway for sandboxes |
| `edge` (with the edge on) | user 65532 | None; read-only root disk | Caddy, for HTTPS sandbox links |

What the worker pod does **not** have: host network, host PID, host IPC, any
folder from the machine (`hostPath`), the machine's containerd socket, a
service account token, or any Kubernetes API right. It copies nothing onto
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
| External storage through FUSE | `/dev/fuse` and `CAP_SYS_ADMIN` |

We measured the alternatives on Amazon Linux 2023 and Bottlerocket:

- **A named list of rights instead of `privileged: true`** works for a
  one-container worker, with 14 capabilities and seccomp and AppArmor off.
  It is still close to root. It does not work for the two-container worker,
  because of the two-way mount above.
- **A Kubernetes user namespace** (`hostUsers: false`) fails: the worker can
  no longer give each sandbox its own CPU and memory limit.

So `privileged: true` stays, limited to these two containers, in this one
namespace, on machines that run nothing else.

**Inside the privileged pod, every sandbox is fenced again.** Each sandbox
runs under gVisor by default (a second kernel between its code and the
machine; the bank preset allows nothing else). Every container sandbox also
gets containerd's own envelope: the default seccomp profile, a trimmed set
of capabilities, masked and read-only kernel paths, and no new privileges.
The chart never turns on `SB_CONTAINER_PRIVILEGED`, which would remove that
envelope.

## 3. Identity

- **A new pod proves who it is with a one-time join token.** The operator asks
  the servers for a token for that one pod, stores it in a Secret that only
  that pod mounts (read-only, mode 0400), and deletes the Secret once the pod
  has joined. The token is spent on first use.
- **Nodes talk to each other with mutual TLS.** Each node has its own
  certificate, signed by the cluster's certificate authority, which renews
  itself. The CA key lives on the servers.
- **Gossip** (who is alive) is encrypted with the cluster's gossip key.
- **Workers hold no admin token.** They know only its fingerprint, to check
  callers. Only servers hold it, from a Secret the operator makes in the
  release namespace.
- **Callers** use AerolVM's own API tokens, SSO and roles, as on any install.

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
| Clients | Gateways | The client ports only (the API, SSH, and 443 and 80 with the edge), through the gateways' load balancer or your own Gateway API Gateway | Your load balancer; NetworkPolicy `<release>-gateway-ingress` |
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
  witnessed in an S3 bucket with Object Lock (docs: Audit evidence).

## 6. Threat model

| Threat | What stops it |
|---|---|
| Code in a sandbox escapes the sandbox | gVisor by default (a second kernel); containerd's seccomp, capability and path envelope; the create policy can allow only gVisor |
| Something escapes to the privileged worker container | Worker machines run nothing else (taint); no host folders, network or PID; no Kubernetes API right; the machine's cloud identity is unreachable (IMDS hop limit 1) |
| A sandbox reaches your network or the cluster | AerolVM's firewall refuses private ranges, the cluster's ranges, the API server and the worker's own ports; the egress NetworkPolicy refuses the same around the whole pod; `aerolvm k8s verify` probes it from a real sandbox |
| Another pod in the cluster reaches a worker | The worker ingress NetworkPolicy; mTLS on every node port |
| A rogue pod joins the cluster | One-time join tokens, mounted only into the pod they are for and deleted after use; mTLS certificates per node |
| A tampered or unsigned image | Signed images with SBOMs and provenance; the example admission policy refuses any AerolVM pod whose image the release workflow did not sign |
| Someone deletes a worker pod by mistake | The operator's delete guard refuses it unless the pod is marked `aerolvm.io/force-delete=true`; the guard fails open, so a down operator never blocks repairs |
| The Kubernetes API is down | Sandboxes keep running and the API keeps answering: AerolVM's control plane is its own. Only changes to the layout wait |
| Too many sandboxes for a machine | Every sandbox is capped inside the worker pod's own CPU and memory limit; one out-of-memory event ends one sandbox, never the worker |

## 7. Verify the images yourself

Every image (`aerolvm`, `aerolvm-runtime`, `aerolvm-edge`, `aerolvm-operator`)
is signed by AerolVM's release workflow, keyless, with an SBOM and build
provenance. `RELEASE-VERIFICATION.md` in the repository shows the `cosign
verify` and `gh attestation verify` commands and the exact identity to
expect. Run images by digest, not tag.

## 8. Admission policy, and its one named exception

**Pod Security.** Label the release namespace `restricted`. The chart labels
the worker namespace `privileged`. That is the one exception, and it is
narrow: only the worker pods' `runtime` and `agent` containers are privileged.
`aerolvm k8s verify` checks both labels and fails on any other privileged
container.

If you also run your own pod-security policies (Kyverno, Gatekeeper), exempt
exactly this: pods labelled `app.kubernetes.io/name=aerolvm`,
`app.kubernetes.io/component=worker`, in the worker namespace, containers
`runtime` and `agent`, for `privileged`.

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
monitoring and machine replacement every 30 days. Its header lists what you
set outside the chart: the namespace label, the worker NodePool, the
EC2NodeClass's metadata settings, `br_netfilter` on worker machines,
cert-manager and Prometheus.

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
- no folders mounted from the machine
- no Kubernetes API credential in the pods
- no DNS provider token in the pods
- privileged containers only in the worker pods' runtime and agent
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
