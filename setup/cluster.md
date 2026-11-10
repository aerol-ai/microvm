# Cluster Setup

Run AerolVM across multiple hosts behind one logical API. Clients call any
node, raft coordinates placement, and traffic is transparently forwarded to
whichever node owns each sandbox. **Sandboxes themselves are not highly
available** - if the owner node dies, the sandbox is gone (see
[Failover semantics](#failover-semantics)). What survives a node failure is
the cluster: the control plane stays available, other sandboxes keep running,
and new placements continue to land on healthy nodes.

When to pick this over [`single-node.md`](./single-node.md):

- You need more concurrent sandboxes than fits on one host.
- You need per-node failure isolation.
- You're spreading load across availability zones.

If a single host is enough today, run [`single-node.md`](./single-node.md).
You can convert it into the seed of a cluster later without losing state:
run `sudo sandboxd init` on it.

> **This is the most operationally complex deployment.** Read the
> [Architecture](#architecture) and [How data flows](#how-data-flows)
> sections before running any commands.

---

## Architecture

A cluster is a fixed set of `sandboxd` daemons, each on its own host, that
share three coordination layers and one set of cluster-wide secrets.

```
                          ┌────────────────────────────────────────────┐
                          │                  CLUSTER                   │
                          │                                            │
   client ──► any node ───┤  ┌────────┐    ┌────────┐    ┌────────┐   │
                          │  │ node A │◄──►│ node B │◄──►│ node C │   │
                          │  │ leader │    │follower│    │follower│   │
                          │  └────┬───┘    └────┬───┘    └────┬───┘   │
                          │       │             │             │       │
                          │       ▼             ▼             ▼       │
                          │   sqlite        sqlite         sqlite     │
                          │   (owned        (owned         (owned     │
                          │    sandboxes)    sandboxes)     sandboxes)│
                          └────────────────────────────────────────────┘
```

Three coordination layers between nodes:

| Layer | Port (default) | Role |
|---|---|---|
| **Raft** (TCP) | `7000` | Replicates the placement map (`sandbox_id → owner`) and per-sandbox specs. Strong consistency via leader election + log replication. |
| **Gossip** (SWIM, TCP+UDP) | `7001` | Membership, liveness, capacity heartbeats. Eventually consistent. |
| **Internal RPC** (HTTPS+mTLS) | `7002` | Leader-forwarded raft applies and any future cluster-internal RPC. Cert-pinned. |

One set of cluster-wide secrets, distributed once on first install:

| Secret | Purpose |
|---|---|
| `SB_PAT_TOKEN` | Public API auth. Internal cluster routes additionally require node-bound mTLS. |
| `SB_GOSSIP_SECRET_KEY` | AES-encrypts gossip payloads; gates raft voter auto-promotion. |
| Cluster TLS trust (`ca.crt`) | Cluster-internal mTLS trust anchor. `ca.key` lives on every server (in the CA store); a joiner sends a CSR to the join port and gets `node.crt` signed by a server. Certs renew themselves at 2/3 of their life. |
| Join tokens | `<id>.<secret>`, stored hashed in Raft; one makes one node of its role. `aerolvm join-command` makes them. |
| Credential bundle (`credential_encryption.key`) | Decrypts sealed registry passwords + per-mount creds. Ships separately from the CA trust tarball. |

---

## How data flows

This is the part that's easy to get wrong if you skip it. Each row below
traces one request type from client to action.

### 1. Client creates a sandbox

```
client ──► any API node
                    │
                    ▼
                 [pick best owner from gossip capacity table]
                    │
                    ▼
                 [if owner != API node: forward create to owner]
                    │
                    ▼  (owner is pinned; target re-checks the pin)
                 [owner creates the sandbox locally]
                    │
                    ▼
                 [seal registry/mount secrets with shared key]
                    │
                    ▼
                 [opPlace via raft: replicate placement+spec+sealed]
                    │
                    ▼
                 returns sandbox handle to client
```

Key invariants:
- The first API node selects placement exactly once. A forwarded create carries
  the selected owner ID, and a node rejects the request if it is not that owner.
- Only the **leader** can apply raft entries. Followers forward writes.
- Every node ends up with the same **redacted spec** + **sealed secrets**
  in its in-memory FSM. SealedSecrets are bytes - only the owner with the
  shared key can read them as plaintext.
- The owner's local SQLite is the source of truth for runtime state
  (container ID, port allocations, sessions). Raft only carries placement
  + intent.
- Placement is committed after local runtime creation. If the raft commit fails,
  the owner attempts to destroy the just-created sandbox so the cluster does
  not keep an untracked runtime.

### 2. Client makes a hot-path call (exec, file copy, port-forward)

```
client ──► any node
            │
            ▼
        [look up owner from FSM placement map]
            │
            ▼
        [if owner == this node: serve locally]
        [else: reverse-proxy to owner's API URL with PAT]
            │
            ▼
        owner runs the toolboxd / docker action
            │
            ▼
        response streams back through the proxy
```

Hot-path traffic does NOT go through raft - it would be far too slow.
Membership info from gossip is enough to find the owner.

### 3. A node dies

```
node B dies (kernel panic, host reboot, network partition)
        │
        ▼
gossip on surviving nodes marks B "suspect" then "dead"
        │
        ▼
        ──► Wait SB_DEAD_OWNER_GRACE (default 30s)
        │     to absorb transient flap (GC pause, blip)
        │
        ▼
leader runs the dead-owner reconciler:
  - for each default placement owned by B: set owner = "" (orphan)
  - for each placement with failover.policy="recreate": reassign to a live worker
  - RemoveServer B from the raft configuration
        │
        ▼
default sandboxes return 410 Gone; opted-in sandboxes are recreated
        │
        ▼
clients (or operators) issue a fresh create - placement picks
a new owner from the live, healthy nodes
```

**Sandbox auto-recreate is opt-in.** Spec, sealed credentials, and exposed-port
metadata replicated via raft are retained in the FSM for every sandbox, but
the default product policy is "a killed sandbox stays gone." A create request
with `failover.policy="recreate"` tells the dead-owner reconciler to reassign
that placement to a live worker and let the owner watcher call
`service.RecreateSandbox`.

### 4. A node joins for the first time

```
new node runs sandboxd join (the line aerolvm join-command prints)
        │
        ▼
a server on :7003 checks the token, signs its cert, hands it the keys
        │
        ▼
joins gossip ring (authenticated by SB_GOSSIP_SECRET_KEY)
        │
        ▼
seed's leader adds it to raft
        │
        ├─ as voter until SB_CLUSTER_MAX_AUTO_VOTERS is reached
        │
        └─ as non-voter after the cap
        │
        ▼
raft replays the FSM log: this node now has the full placement map
        │
        ▼
no sandboxes are migrated automatically - the new node has 0 owned
sandboxes and can accept new placements based on its capacity
```

---

## Failover semantics

**The default product policy is non-HA sandboxes.** When an owner node dies,
default sandboxes on it are gone. Sandboxes created with
`failover.policy="recreate"` are best-effort recreated on another worker from
their replicated spec. The cluster keeps running either way.

| State | Survives node failure | Why |
|---|---|---|
| Sandbox spec, sealed creds, port intents | **Retained in the FSM** | Replicated by raft for orphan inspection, manual recovery, and opt-in failover recreation. |
| Sandbox runtime (container, filesystem, sessions, host ports, SSH) | **No** | Lives only on the dead host. There is no automatic replacement. |
| Sandbox URL (`<id>.<domain>`) | Default: **No**. Opt-in recreate: **Best effort** | Default placement is orphaned and API returns 410 Gone. Opted-in sandboxes keep the ID while ingress repoints to the new owner. |
| Sessions / recordings on disk | **No (without external storage)** | Live in the dead host's `/var/lib/`. Use external mounts if you need to retrieve them later. |
| Cluster control plane (raft, placement of *other* sandboxes) | **Yes** | Quorum stays available as long as you keep `(N-1)/2` voters alive. Other sandboxes on healthy nodes continue to run. |
| New placements after the failure | **Yes** | Capacity from the dead node leaves the gossip pool; new creates pick from the remaining healthy candidates. |

This is by design: a sandbox is treated as a session, not a service. To make a
workload *survive* node failure, structure it on top of AerolVM rather than
inside one sandbox:

1. Keep durable state on external mounts (S3, NFS, sshfs) so a *new* sandbox
   created by your application code can pick it up.
2. Have your client code recreate the sandbox on `410 Gone` (the SDK exposes
   this as a clear error class).
3. Do not assume the sandbox URL, container ID, or host ports persist across
   the owner's death.

If a workload can tolerate writable-layer loss but should keep its sandbox ID,
create it with `failover.policy="recreate"`. Local-only images are rejected
for this policy because another worker cannot pull them.

See [Durability and Failover](https://microvm.aerol.ai/durability) for the
production runbook.

---

## Quorum and node count

Raft requires a majority of voters. With `N` voters, the cluster tolerates
the loss of `(N-1)/2` voters before writes stop.

| Voters | Failures tolerated | Notes |
|---|---|---|
| 1 | 0 | Single-node cluster. Any restart blocks writes briefly. |
| 2 | 0 | **Worst case.** Quorum is 2; losing either halts writes. **Avoid.** |
| 3 | 1 | **Minimum recommended for production.** |
| 5 | 2 | Recommended for clusters spanning availability zones. |
| 7 | 3 | Diminishing returns; replication latency grows. |

**Rules:**

- Always run an **odd number** of voters. Even counts only raise the quorum
  threshold without raising fault tolerance.
- A 2-node cluster is a single point of failure with extra steps.
- `SB_CLUSTER_MAX_AUTO_VOTERS` defaults to `5`. Once that many voters exist,
  a newly discovered **server-role** node is added as a raft **non-voter**: it
  still receives the full placement log and FSM, and can forward writes to the
  leader, but it does not enlarge quorum.
- **The voter cap bounds voting, not replication.** A non-voter holds the whole
  placement map — roughly 72 MB of state at 100k sandboxes, plus a dedicated
  replication stream from the leader. Scale-out belongs in the worker and
  ingress tiers, which run the Agent client, hold no FSM, and never join raft
  in any suffrage. The live **server tier is therefore capped at 7 nodes**
  (`MaxServerTierNodes`): the default 5 voters plus two slots so a rolling
  replacement can overlap. Above 10 live nodes a cluster with more than 7 live
  server-role nodes fails admission with `ErrInvalidTopology` — re-role the
  surplus nodes to `worker` or `ingress`. The cap is a constant, not an env
  knob, for the same reason the mixed-role gate is.
- `SB_NODE_ID` must be **stable** across restarts. A node returning with a
  new ID joins as a brand-new raft server while the old server sits in the
  configuration as dead.

---

## Prerequisites

Same per-node requirements as a single-node install (Linux apt-based,
`sudo`), plus:

- A **private network** the operator controls (VPC, WireGuard mesh,
  dedicated subnet). Cluster-internal traffic must not be reachable from
  the public internet.
- Cluster-internal ports open between nodes only:
  - `7000/TCP` - raft replication, between servers
  - `7001/TCP+UDP` - gossip, between all nodes
  - `7002/TCP` - required internal mTLS RPC, between all nodes
  - `7003/TCP` - joins, from every node to the servers
- Public ports open as in single-node: `443/TCP`, `2220/TCP`, optionally
  `22000-23000/TCP`.
- The `aerolvm` CLI on your laptop (`curl -fsSL https://aerolvm.aerol.ai |
  bash -s -- --cli-only`).

You need no copy of this repository. The admin PAT (`SB_PAT_TOKEN`) must
be the same on every node; the join hands it to each new node, so you give
it only to the first one.

---

## Step-by-step: bringing up a 3-node cluster

This is the recommended starting topology. Three small VPS hosts behind one
domain. Every step is one command; nothing is copied between nodes by hand.

### Step 1 - Open cluster-internal ports

On each node's firewall (cloud security group or `ufw`):

```
ALLOW 7000/TCP       from <other-cluster-node-IPs>   # raft
ALLOW 7001/TCP,UDP   from <other-cluster-node-IPs>   # gossip
ALLOW 7002/TCP       from <other-cluster-node-IPs>   # required internal mTLS
ALLOW 7003/TCP       from <other-cluster-node-IPs>   # joins (servers only listen)
```

**Never open these to the public internet.** Gossip carries auth tokens;
raft carries the full FSM.

### Step 2 - Start the cluster on the seed (node A)

Pick one node to start the cluster. From now on it's "the seed". On
`node-a`, install AerolVM and run `sandboxd init` in one command:

```bash
curl -fsSL https://aerolvm.aerol.ai \
  | sudo bash -s -- \
      --domain sandbox.example.com \
      --pat-token shared-pat-token \
      --dns-provider cloudflare \
      --dns-api-token <cloudflare-token> \
      init --role mixed --node-id node-a
```

Everything before `init` goes to `install.sh`; everything after it goes to
`sandboxd init` (`sudo sandboxd init --help` lists its flags). `init`:

1. Runs the local preflight checks (disk, ports free, cgroup v2, KVM when
   Firecracker is on) and stops before changing anything if one fails.
2. Makes the cluster CA (ECDSA P-256, 10 years) into the CA store, the
   32-byte gossip key, and the credential encryption key (or wraps it, with
   `--key-custody wrapped`).
3. Signs this node's certificate (`DNS:node:<id>`, `DNS:role:<role>`).
4. Writes `/etc/sandboxd/cluster.env` and the systemd drop-in, and
   restarts `sandboxd` in cluster mode.
5. Waits until this node leads, then registers the join tokens: the ones
   given with `--token <role>=<id.secret>[:<ttl>]`, or a 2h worker token.
6. Writes `/etc/sandboxd/admin-context.json` (0600) and prints a join
   command per token and the login line.

`init` is safe to run again. The advertise address defaults to the source
address of the default route; set `--advertise <ip>` when that is wrong.

On your laptop, take the admin login:

```bash
ssh node-a sudo cat /etc/sandboxd/admin-context.json > admin-context.json
aerolvm config import admin-context.json --use
aerolvm get nodes      # node-a  ...  Ready,Leader
```

### Step 3 - Join the rest (node B, node C)

On your laptop, make a join command per node:

```bash
aerolvm join-command --role mixed
```

It prints one line. With a domain, the line carries the seed's `--domain`
and DNS options before the word `join`, and `--role mixed` at the end
(`mixed` takes a server token):

```
curl -fsSL https://aerolvm.aerol.ai | sudo bash -s -- --domain sandbox.example.com --dns-provider cloudflare --dns-api-token "$CLOUDFLARE_API_TOKEN" join https://10.0.0.5:7003 --token <id.secret> --ca-cert-hash sha256:<hex> --role mixed
```

The line reads the Cloudflare token from the new machine, so it never holds
it. On `node-b`, set it, then run the line as printed. Add `--node-id node-b`
at the end to pick the node ID (the default is the short host name):

```bash
export CLOUDFLARE_API_TOKEN=<cloudflare-token>
curl -fsSL https://aerolvm.aerol.ai | sudo bash -s -- ... --role mixed --node-id node-b
```

`sandboxd join`:

1. Fetches the cluster's `ca.crt` from the join port (7003, server cert,
   no client cert) and checks it: against `--ca-cert-hash` when given, else
   against an HMAC that only a holder of the token's secret can make.
2. Runs preflight, including a dial-back: the join server opens a
   connection back to this node's ports.
3. Makes a P-256 key and CSR and posts the join. One Raft op uses up the
   token and reserves the node ID for this key; the server signs the
   certificate with the token's role. The answer carries the gossip key,
   the bootstrap peers, the credential key (or only its wrapped form), the
   shared PAT, and, for a server, the CA key.
4. Writes the certs and `cluster.env`, restarts `sandboxd`, and waits until
   the node is a member.

A join that failed part way can be run again: the same key gets the same
answer. Do `node-c` the same way. The token decides the role (`--role`
sets the full role when it is more than the token's, for example `mixed`
or `server,worker`).

After both joins land, check the seed's log:

```bash
sudo journalctl -u sandboxd -f
```

You want to see lines like:

```
cluster: auto-promoted member to raft voter node_id=node-b
cluster: added member as raft non-voter because voter cap is reached node_id=node-f
cluster gossip joined peers ...
```

The leader auto-promotes new **server-role** joiners to raft voters until
`SB_CLUSTER_MAX_AUTO_VOTERS` is reached, using the role the cert was signed
with, not the role a node gossips. Additional server joiners are added as
raft non-voters: they still receive the whole placement log, they just do
not increase quorum. That is why the live server tier is capped at 7 nodes
— see "Rules" above. Worker and ingress nodes never appear in these lines
at all; they run the Agent client, advertise no raft address, and hold no
FSM.

Check a machine before it joins with `sudo sandboxd preflight --join
https://10.0.0.5:7003 --token <id.secret>`: it prints a fix for each
failing check and changes nothing.

### Step 4 - Verify the cluster

From your laptop:

```bash
aerolvm get nodes -o wide
aerolvm cluster-info
```

Expect three nodes `Ready`, one of them `Ready,Leader`, and the leader in
`cluster-info`.

Create a sandbox via the SDK against any node - the cluster picks the owner
based on capacity, and subsequent calls are transparently forwarded.

### Join tokens are secrets

A join token can make a node, and a node gets the admin PAT, the gossip
key, the credential key (unless custody is wrapped) and, for a server, the
CA key. Treat join tokens like the PAT:

- The default token works once and lasts 2h. Server tokens last at most
  24h.
- `--reusable --ttl 0` (never expires) is only for worker and ingress
  tokens, such as an autoscaler's. Enterprise mode refuses it unless key
  custody is wrapped.
- `aerolvm get jointokens` lists them; `aerolvm delete jointoken <id>`
  revokes one. Every join, and every refused one, is audited.

---

## DNS and ingress for clusters

A cluster has **two distinct kinds of public traffic**, and they route
differently. This is the most common source of confusion when standing up a
cluster - read this section before configuring DNS.

### Path 1 - API traffic (`sandbox.example.com/v1/...`)

Lands on any node. For sandbox-scoped requests, the application looks up the
placement record and reverse-proxies the HTTP request to the owner
(`internal/cluster.ForwardHTTP`). Create requests are the special case: the
receiving API node chooses the owner once, then forwards a target-pinned
create to that owner.

**Internal channel.** Every cluster node requires `SB_CLUSTER_TLS_DIR`; the
proxy rides the cluster-internal mTLS channel on `:7002`. The receiving node's
mTLS listener serves the
same `/v1/...` mux as its public port, so handlers run identically but the
hop is cert-pinned end-to-end. The PAT bearer header is still forwarded
(belt-and-braces), but possession of the PAT alone is no longer sufficient
to forge a cross-node API hop. There is no plaintext or PAT-only downgrade
after a TLS configuration or handshake failure.

**You can put any LB or DNS scheme in front of the API path**, but every
node's advertised API URL must still be reachable by clients. The `:7002`
mTLS port must be reachable between cluster members.

### Path 2 - Sandbox URLs (`<id>.sandbox.example.com`, `<id>-<port>.sandbox.example.com`)

Each sandbox container lives on exactly **one** owner node, but every node runs
an ingress reconciler. Non-owner nodes install Caddy/caddy-l4 routes from the
cluster placement map and forward public traffic to the owner:

- domain-mode HTTP sandbox URLs use caddy-l4 SNI pass-through to the owner;
- IP/path-mode HTTP routes reverse-proxy to the owner's Caddy `:80`;
- raw TCP routes bind the same `host_port` on each node and proxy to the
  owner's `host_port`;
- TLS-SNI port routes pass through to the owner's `:443` mux.

The owner target for this data-plane forwarding is `SB_DATA_PLANE_ADVERTISE_HOST`.
Do not rely on `SB_API_ADVERTISE_URL` unless it is also the host peers should
dial on Caddy/L4 ports. If the API advertise URL is an API-only DNS name, a
shared load balancer, or an address that can loop back through the public LB,
set `SB_DATA_PLANE_ADVERTISE_HOST` to the node's peer-reachable data-plane IP
or DNS name.

That means the public LB no longer needs to know the owner for each sandbox.
It only needs to send traffic to a healthy sandboxd node.

### Address you give to clients

Always one hostname:

```
https://sandbox.example.com         # API
https://<sandbox-id>.sandbox.example.com   # sandbox URL
```

No matter how many nodes you have, the SDK uses one `baseURL`. The DNS
records below decide which physical node the connection actually reaches.

### Topology A - SNI-aware L4 LB (recommended; works for both paths) - **2 DNS records**

```
A   sandbox.example.com    →  <LB-public-IP>
A   *.sandbox.example.com  →  <LB-public-IP>
```

The LB does **TLS pass-through** (TCP-mode listener on `:443`, no cert at the
LB), preserving SNI. Each backend node terminates TLS with its own copy of
the wildcard cert.

For the **API path**, this works trivially - any backend forwards the call.

For the **sandbox URL path**, this also works: if the LB lands on a non-owner,
that node's ingress route forwards the connection to the owner. Route
convergence is controlled by the sandboxd cluster-ingress reconcile loop, so a
fresh expose or failover can briefly return 404/502 until the next reconcile.

### Topology B - Per-sandbox DNS (not recommended unless you need direct owner routing)

On each sandbox create, write a per-sandbox A record pointing at the owner:

```
A   <sandbox-id>.sandbox.example.com  →  <owner-node-IP>
```

On failover, update the record to point at the new owner. This bypasses the
any-node ingress layer, but it adds Cloudflare TTL lag during failover
(typically ≥60s), Cloudflare API rate limits at high create churn, and one DNS
record per sandbox. Prefer Topology A unless your environment forbids
node-to-node ingress forwarding.

### Topology C - DNS round-robin (NOT RECOMMENDED) - **6 records**

```
A   sandbox.example.com    →  <node-a-IP>
A   sandbox.example.com    →  <node-b-IP>
A   sandbox.example.com    →  <node-c-IP>
A   *.sandbox.example.com  →  <node-a-IP>
A   *.sandbox.example.com  →  <node-b-IP>
A   *.sandbox.example.com  →  <node-c-IP>
```

DNS round-robin now works functionally because any live node can route to the
owner, but it has no health checking: dead nodes still answer DNS until clients
retry another A record. Use only for testing or tiny private deployments.

### Practical recommendation

| Your usage | Use this |
|---|---|
| Production cluster with public URLs | Topology A: health-checked TCP/TLS pass-through LB in front of all nodes. |
| Small private test cluster | Topology C is acceptable if client retries tolerate dead DNS answers. |
| Environment that forbids node-to-node ingress forwarding | Topology B, with the operational cost of per-sandbox DNS updates. |

### Ingress tier size limit

Every topology on this page picks *any* live ingress-capable node for *any*
sandbox, which is only correct while each of them holds the full public route
table - guaranteed through **10 live ingress-capable nodes**. Above 10, each
ingress node holds only its rendezvous-hashed share (primary plus one failover
replica per shard) and a plain LB sends most connections to a node without the
route. The daemon fails closed there: enterprise boots refuse, open-source
never marks ingress ready and reports `degraded` on `/health`
(`aerolvm_cluster_topology_ok = 0`, alert `SandboxdClusterTopologyViolation`).
Running more than 10 ingress nodes needs a router that resolves owners through
`GET /v1/cluster/ingress-route/{id}` before forwarding, and then
`SB_CLUSTER_SHARD_AWARE_INGRESS=true` on every node (Terraform:
`shard_aware_ingress = true`). Setting the flag with a plain LB in front
silences the check and breaks traffic silently. Runbook:
`setup/runbooks/cluster-ingress-topology.md`.

---

## Concrete deployment: AWS + Cloudflare (3 nodes)

This is the path most operators take. Every step, no skipped pieces. Total
time: ~45 minutes if you already have an AWS account and a Cloudflare zone.

### What you'll build

```
            Cloudflare DNS                (sandbox.example.com → NLB)
                  │
                  ▼
         AWS Network Load Balancer       (TCP :443, TLS pass-through)
                  │
        ┌─────────┼─────────┐
        ▼         ▼         ▼
     node-a    node-b    node-c           (EC2, one per AZ, EIP each)
        │         │         │
        └─────────┴─────────┘             (raft :7000, gossip :7001, mTLS :7002)
              private subnet
```

**Important caveat upfront**: this gives you a working API and a working
sandbox-URL plane that lands on the owner ~1/3 of the time (round-robin
across 3 nodes). For a workload where public sandbox URLs are the primary
use case, see "After the cluster is up" at the end.

### Prerequisites checklist

- [ ] AWS account, IAM user with EC2 + VPC + ELB permissions.
- [ ] AWS CLI configured (`aws sts get-caller-identity` works).
- [ ] Cloudflare account with the zone for `example.com` already added.
- [ ] Cloudflare API token: scope **Zone → Zone → Read** + **Zone → DNS →
      Edit** on the `example.com` zone. Save it; you'll need it twice.
- [ ] An SSH keypair imported in the AWS region you'll deploy to.
- [ ] A subdomain you control under the Cloudflare zone, e.g.
      `sandbox.example.com`. The wildcard `*.sandbox.example.com` will be
      yours too.

### Step 1 - Create the VPC and subnets

```bash
# Region: pick one with ≥3 AZs. Example: us-east-1.
export AWS_REGION=us-east-1
aws configure set region $AWS_REGION

# Create a VPC.
VPC_ID=$(aws ec2 create-vpc --cidr-block 10.0.0.0/16 \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=aerolvm-vpc}]' \
  --query 'Vpc.VpcId' --output text)
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames

# Internet gateway and attach.
IGW_ID=$(aws ec2 create-internet-gateway --query 'InternetGateway.InternetGatewayId' --output text)
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID

# 3 public subnets, one per AZ.
SUBNET_A=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.1.0/24 \
  --availability-zone ${AWS_REGION}a --query 'Subnet.SubnetId' --output text)
SUBNET_B=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.2.0/24 \
  --availability-zone ${AWS_REGION}b --query 'Subnet.SubnetId' --output text)
SUBNET_C=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.3.0/24 \
  --availability-zone ${AWS_REGION}c --query 'Subnet.SubnetId' --output text)

for s in $SUBNET_A $SUBNET_B $SUBNET_C; do
  aws ec2 modify-subnet-attribute --subnet-id $s --map-public-ip-on-launch
done

# Route table → IGW.
RT_ID=$(aws ec2 create-route-table --vpc-id $VPC_ID --query 'RouteTable.RouteTableId' --output text)
aws ec2 create-route --route-table-id $RT_ID --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW_ID
for s in $SUBNET_A $SUBNET_B $SUBNET_C; do
  aws ec2 associate-route-table --route-table-id $RT_ID --subnet-id $s
done

echo "VPC=$VPC_ID  subnets=$SUBNET_A,$SUBNET_B,$SUBNET_C"
```

### Step 2 - Security groups

Three groups: public-edge, cluster-internal, management.

```bash
# Public ingress (only what the world reaches).
SG_PUBLIC=$(aws ec2 create-security-group --vpc-id $VPC_ID \
  --group-name aerolvm-public --description "Public ingress" \
  --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id $SG_PUBLIC \
  --ip-permissions IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges='[{CidrIp=0.0.0.0/0}]'
# Optional: SSH gateway
aws ec2 authorize-security-group-ingress --group-id $SG_PUBLIC \
  --ip-permissions IpProtocol=tcp,FromPort=2220,ToPort=2220,IpRanges='[{CidrIp=0.0.0.0/0}]'

# Cluster-internal (raft, gossip, mTLS, joins on 7003) - only from the SG itself.
SG_CLUSTER=$(aws ec2 create-security-group --vpc-id $VPC_ID \
  --group-name aerolvm-cluster --description "Cluster-internal" \
  --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id $SG_CLUSTER \
  --source-group $SG_CLUSTER --protocol tcp --port 7000-7003
aws ec2 authorize-security-group-ingress --group-id $SG_CLUSTER \
  --source-group $SG_CLUSTER --protocol udp --port 7001

# Management (SSH from your IP only).
MY_IP=$(curl -s https://api.ipify.org)
SG_MGMT=$(aws ec2 create-security-group --vpc-id $VPC_ID \
  --group-name aerolvm-mgmt --description "Operator SSH" \
  --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id $SG_MGMT \
  --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges="[{CidrIp=$MY_IP/32}]"

echo "SGs: public=$SG_PUBLIC cluster=$SG_CLUSTER mgmt=$SG_MGMT"
```

### Step 3 - Launch 3 EC2 instances

```bash
# Ubuntu 22.04 LTS AMI for your region (this is us-east-1 as of 2026; use SSM
# for portability if you prefer):
AMI=$(aws ssm get-parameters --names \
  /aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id \
  --query 'Parameters[0].Value' --output text)

KEY_NAME=your-keypair-name           # imported in this region
INSTANCE_TYPE=t3.medium              # bump for real workloads

declare -A NODES=( [node-a]=$SUBNET_A [node-b]=$SUBNET_B [node-c]=$SUBNET_C )
declare -A INSTANCE_IDS

for name in "${!NODES[@]}"; do
  id=$(aws ec2 run-instances \
    --image-id $AMI --instance-type $INSTANCE_TYPE \
    --key-name $KEY_NAME --subnet-id ${NODES[$name]} \
    --security-group-ids $SG_PUBLIC $SG_CLUSTER $SG_MGMT \
    --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=50,VolumeType=gp3}' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$name}]" \
    --query 'Instances[0].InstanceId' --output text)
  INSTANCE_IDS[$name]=$id
  echo "$name → $id"
done

# Wait for them all to be running.
aws ec2 wait instance-running --instance-ids ${INSTANCE_IDS[@]}

# Allocate and attach an Elastic IP to each (so node IPs are stable).
for name in "${!NODES[@]}"; do
  alloc=$(aws ec2 allocate-address --domain vpc --query 'AllocationId' --output text)
  aws ec2 associate-address --instance-id ${INSTANCE_IDS[$name]} --allocation-id $alloc
done
```

Get each node's **private** IP (the join commands use `node-a`'s):

```bash
for name in "${!NODES[@]}"; do
  ip=$(aws ec2 describe-instances --instance-ids ${INSTANCE_IDS[$name]} \
    --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)
  echo "$name private-ip=$ip"
done
```

### Step 4 - Network Load Balancer with TLS pass-through

```bash
# Create the NLB across all 3 subnets.
NLB_ARN=$(aws elbv2 create-load-balancer --name aerolvm-nlb \
  --type network --scheme internet-facing \
  --subnets $SUBNET_A $SUBNET_B $SUBNET_C \
  --query 'LoadBalancers[0].LoadBalancerArn' --output text)

# Target group: TCP/:443. TLS pass-through means we DO NOT terminate at NLB.
TG_ARN=$(aws elbv2 create-target-group --name aerolvm-tg-443 \
  --protocol TCP --port 443 --vpc-id $VPC_ID \
  --health-check-protocol TCP --health-check-port 443 \
  --target-type instance \
  --query 'TargetGroups[0].TargetGroupArn' --output text)

# Register all three instances.
aws elbv2 register-targets --target-group-arn $TG_ARN \
  --targets Id=${INSTANCE_IDS[node-a]} Id=${INSTANCE_IDS[node-b]} Id=${INSTANCE_IDS[node-c]}

# Listener on :443 → forward TCP to the target group.
aws elbv2 create-listener --load-balancer-arn $NLB_ARN \
  --protocol TCP --port 443 \
  --default-actions Type=forward,TargetGroupArn=$TG_ARN

# (Optional) :2220 listener for the SSH gateway:
TG2220=$(aws elbv2 create-target-group --name aerolvm-tg-2220 \
  --protocol TCP --port 2220 --vpc-id $VPC_ID \
  --health-check-protocol TCP --health-check-port 2220 \
  --target-type instance --query 'TargetGroups[0].TargetGroupArn' --output text)
aws elbv2 register-targets --target-group-arn $TG2220 \
  --targets Id=${INSTANCE_IDS[node-a]} Id=${INSTANCE_IDS[node-b]} Id=${INSTANCE_IDS[node-c]}
aws elbv2 create-listener --load-balancer-arn $NLB_ARN \
  --protocol TCP --port 2220 \
  --default-actions Type=forward,TargetGroupArn=$TG2220

NLB_DNS=$(aws elbv2 describe-load-balancers --load-balancer-arns $NLB_ARN \
  --query 'LoadBalancers[0].DNSName' --output text)
echo "NLB DNS: $NLB_DNS"
```

The key choice here is **TCP listener, not TLS**. TLS pass-through preserves
the encrypted handshake to the backend, where each node's Caddy terminates
TLS using its own copy of the wildcard cert (issued via DNS-01 - see Step 6).

### Step 5 - Cloudflare DNS

In the Cloudflare dashboard, add **two CNAME records** under your zone:

| Type | Name | Target | Proxy status |
|---|---|---|---|
| CNAME | `sandbox` | `<NLB_DNS>` | **DNS only** (gray cloud) |
| CNAME | `*.sandbox` | `<NLB_DNS>` | **DNS only** (gray cloud) |

Or via the Cloudflare API:

```bash
ZONE_ID=<your-zone-id>
CF_TOKEN=<cloudflare-api-token>

curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json" \
  -d "{\"type\":\"CNAME\",\"name\":\"sandbox\",\"content\":\"$NLB_DNS\",\"proxied\":false}"

curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json" \
  -d "{\"type\":\"CNAME\",\"name\":\"*.sandbox\",\"content\":\"$NLB_DNS\",\"proxied\":false}"
```

**Why DNS-only (gray cloud), not proxied?** Cloudflare's proxy terminates
TLS itself and won't pass through your wildcard cert to the backend. With
DNS-only, the SDK/browser connects directly through the NLB to the backend,
preserving the SNI-based TLS handshake that DNS-01 issued certs depend on.

Wait for propagation:

```bash
dig +short sandbox.example.com
dig +short test.sandbox.example.com
```

Both should return the NLB's IP(s) (Amazon-assigned, may be multiple).

### Step 6 - Install and start the cluster on `node-a`

SSH to `node-a` (the EIPs you allocated earlier are the SSH targets) and
install AerolVM with `init` at the end:

```bash
ssh ubuntu@<node-a-EIP>
curl -fsSL https://aerolvm.aerol.ai \
  | sudo bash -s -- \
      --domain sandbox.example.com \
      --pat-token shared-pat-token-pick-something-strong \
      --dns-provider cloudflare \
      --dns-api-token <cloudflare-token> \
      init --role mixed --node-id node-a --ingress-advertise-host sandbox.example.com
```

Caddy solves a DNS-01 challenge against Cloudflare (writes a transient
`_acme-challenge.sandbox.example.com` TXT record, waits for LE to verify,
deletes the record). Allow 30-90 seconds for first issuance.

On your laptop, import the admin login `init` wrote:

```bash
ssh ubuntu@<node-a-EIP> sudo cat /etc/sandboxd/admin-context.json > admin-context.json
aerolvm config import admin-context.json --use
```

### Step 7 - Join `node-b` and `node-c`

For each, make a join command on your laptop:

```bash
aerolvm join-command --role server
```

and run it on the node with the same domain options before `join`:

```bash
ssh ubuntu@<node-b-EIP>
curl -fsSL https://aerolvm.aerol.ai \
  | sudo bash -s -- \
      --domain sandbox.example.com \
      --dns-provider cloudflare \
      --dns-api-token <cloudflare-token> \
      join https://<node-a-private-ip>:7003 --token <id.secret> --ca-cert-hash sha256:<hex> \
      --role mixed --node-id node-b --ingress-advertise-host sandbox.example.com
```

The join brings the shared PAT, so `--pat-token` is not needed here. See
[Step 3 of the 3-node walkthrough](#step-3---join-the-rest-node-b-node-c)
for what the join does.

### Step 8 - Verify

```bash
aerolvm get nodes
aerolvm cluster-info
```

You should see all three nodes `Ready`, and one leader. From the SDK:

```ts
import { Sandbox } from "@aerol-ai/sdk";
const sb = new Sandbox({
  baseURL: "https://sandbox.example.com",
  apiKey: process.env.SB_PAT_TOKEN,
});
const sandbox = await sb.create({ image: "node:20" });
console.log(sandbox.id);   // confirm a sandbox actually got placed
```

The cluster picks the owner via power-of-two-choices over the gossip
capacity table; subsequent SDK calls reach the right node automatically
through API forwarding.

### After the cluster is up - what works, what doesn't

| Path | Status with this setup |
|---|---|
| SDK calls (`/v1/sandboxes/...`, exec, file copy, port-forward) | **Fully working.** Land on any node, internally forwarded to owner. |
| Public sandbox URLs (`<id>.sandbox.example.com`) | **Working.** NLB can land on any live node; non-owners SNI-pass-through to the owner. |
| Raw TCP exposures (`tcp://sandbox.example.com:<host-port>`) | **Working after route convergence.** Each node binds the replicated host port and proxies to the owner. |
| Failover (kill an EC2) | **Working.** After `SB_DEAD_OWNER_GRACE`, sandboxes reassign; new owner unseals creds with the shared key from the bundle. |
| TLS issuance/renewal | **Working per node.** Three independent DNS-01 renewal loops, well under LE quota. |

The important operational check is route convergence. On each node, sandboxd
reconciles cluster ingress routes every few seconds from the raft placement
snapshot. During failover or immediately after exposing a port, expect a short
window where a non-owner backend can return 404/502 before it refreshes.

#### Convergence-window response contract

While the cluster's placement view and the node's installed routes are
catching up, the daemon returns documented HTTP codes rather than letting the
caller fall into a generic timeout. Treat these as the wire contract - SDKs
and load-balancer health checks key off them:

| Surface | Situation | Response |
|---|---|---|
| API control plane (`/v1/sandboxes/...`) | Placement still resolving on this node, owner's URL not yet gossiped | **503 Service Unavailable** with owner node-id in body; bumps `aerolvm_ingress_route_misses_total`. Retry. |
| API control plane | Owner died and grace expired; placement orphaned | **410 Gone**. Stop retrying; issue a fresh `Create`. |
| API control plane | Request forwarded to wrong node (stale placement view at sender) | **421 Misdirected Request**. Caller should re-resolve owner. |
| Data plane HTTP/TLS (Caddy) | Route in flux on this node (placement seen, route not yet installed) | **503** with `Retry-After: 2` and body `Sandbox placement in flux. Retry in a moment.` |
| Data plane raw TCP | Route in flux on this node | Connection refused. (No in-flux mirror - raw TCP has no hostname to match on, so the port simply isn't bound until the reconciler installs it.) |
| Internal raft apply (`/v1/cluster/_apply`) | This node is not the leader | **503**, treat as retry signal. |

Convergence is event-driven, not periodic: every committed FSM mutation wakes
the local ingress reconciler via a cap=1 buffered channel
(`cluster.SubscribePlacement`), so the in-flux window is typically sub-second
under steady-state gossip and is bounded by the 5s reconcile-on-tick safety
net.

#### Per-sandbox convergence status

For pinpoint debugging of "is this sandbox's route installed on this node yet",
query `GET /v1/cluster/placements/<sandbox-id>` from the node in question:

```json
{
  "owner": {"node_id": "node-b", "api_url": "http://node-b:21212", "is_self": false},
  "orphaned": false,
  "exposed_ports": {
    "5432": {"protocol": "tcp", "host_port": 40123, "public_url": "tcp://lb.example.com:40123"}
  },
  "placement_version": 42,
  "node_installed_version": 41,
  "converged": false
}
```

- `converged: true` - owner is this node (synchronous install) OR the
  reconciler has applied routes for an FSM version ≥ `placement_version`.
  Client traffic via this node will hit the route.
- `converged: false` - the reconciler is still catching up; raw TCP dials may
  see connection refused and HTTP/TLS sees the 503-with-Retry-After in-flux
  response above. Recheck after the next 5s reconcile tick. If
  `node_installed_version` does not catch up after multiple ticks, scrape
  `/debug/vars` for `aerolvm_ingress_reconcile_errors_total` to find the
  Caddy-side failure.

For node-wide convergence (rather than per-sandbox), the gauges
`aerolvm_ingress_route_lag_versions` and `aerolvm_ingress_route_misses_total`
on each node's `/debug/vars` are the operator signals.

#### Preferred host-port replay during failover-recreate

When a placement re-lands on a new owner via the opt-in failover-recreate path,
the FSM carries the original TCP `host_port` so the new owner can re-bind it
and preserve the public endpoint. If that host port is already reserved on the
new owner (taken by an unrelated TCP exposure, or in use locally), the replay
**parks** the exposure rather than silently allocating a different host port:

- The FSM record (with the original `host_port`) stays intact.
- The local re-bind fails with `ErrPreferredHostPortUnavailable`; the
  per-sandbox convergence status above reports `converged: false`.
- The allocator does **not** fall through to the random/linear pool walk -
  silently switching `host:40123` → `host:55555` would break every client
  that memorized the original endpoint, which is the whole point of the
  cluster-stable TCP route map.

Operator remediation: drain the conflicting exposure on the new owner, or
restart the placement on a different node via an explicit re-create.

---

## Operating the cluster

Every command below runs from your laptop with the `aerolvm` CLI and an
admin login, unless it says `sudo` (then it runs on the node). No copy of
this repository is needed.

### Per-node files (cluster overlay)

`sandboxd init` and `sandboxd join` write the same two files:

- `/etc/sandboxd/cluster.env` (mode 0600) - cluster env vars.
- `/etc/systemd/system/sandboxd.service.d/cluster.conf` - drop-in adding
  `EnvironmentFile=/etc/sandboxd/cluster.env`.

The base `/etc/sandboxd/sandboxd.env` from `install.sh` is only changed to
carry the shared PAT a join hands over. Re-running `install.sh` later does
not overwrite the cluster overlay.

### Adding a 4th (or 5th, …) node

```bash
aerolvm join-command --role server     # or worker, or ingress
```

Run the printed line on the new host, with the cluster's domain options
before the word `join` ([Step 3](#step-3---join-the-rest-node-b-node-c)).
The leader adds a server as a voter until `SB_CLUSTER_MAX_AUTO_VOTERS` is
reached; after that, it is added as a non-voter. Workers and ingress nodes
never join Raft.

> **Tip:** keep voter count odd. Add nodes in pairs: 3 → 5 → 7. A 4-node
> cluster has the same fault tolerance as a 3-node one but a higher quorum
> threshold.

### Removing a node

```bash
aerolvm drain <node-id> --timeout 30m      # cordon, then wait until it runs no sandboxes
aerolvm delete node <node-id>
```

`drain` reads the node's own counts, so it never pages the fleet's sandbox
index. `--delete-sandboxes` destroys what is left; `--migrate` first moves
WASM sandboxes to another worker. `delete node` works for every role:

- a Raft server leaves the Raft configuration (it refuses to remove the
  last voter);
- a worker or ingress node is cordoned and its placements are handed to
  other workers when they asked for failover, or else orphaned (`410 Gone`);
- the node ID and its cert key get a deny record in Raft: every other node
  refuses its internal calls, its gossip and its cert renewal, until the
  machine joins again with a new token and a new key.

Deleting a live node that still owns sandboxes needs `--force`. A second
call answers "already gone". Then, on the machine, `sudo sandboxd reset
--yes` takes it out of cluster mode (below).

### Rolling restart

Restart nodes one at a time, waiting for each to rejoin before the next:

```bash
sudo systemctl restart sandboxd
aerolvm get nodes      # wait until it is Ready again, then move to the next node
```

Quorum is preserved as long as you don't exceed `(N-1)/2` simultaneous
restarts. For a 3-node cluster: never restart two at once.

### Upgrading

```bash
aerolvm upgrade plan v0.7.0
aerolvm upgrade apply v0.7.0 --wait
```

`apply` stores a rollout in Raft and the leader drives it, so it goes on
after the CLI exits and across a leader change. Every node stages and
checks the files first; then servers go one at a time with the leader last
(after a leadership hand-off), then ingress nodes one at a time, then
workers in batches (`--batch`, default 10%, at least 1), cordoned before
they restart. Each node runs `sandboxd upgrade node` in its own systemd
unit: hashes checked, database backed up with `VACUUM INTO`, old files
kept as `*.prev`, and put back if the new build does not come up. See
[`runbooks/cluster-upgrades.md`](runbooks/cluster-upgrades.md) for
`status`, `stop`, `resume`, `finalize`, `rollback` and the alerts.

While `sandboxd` restarts on a node: containers (docker, containerd,
gVisor) and Firecracker VMs keep running and are adopted again; mount
helpers keep serving. **WASM and V8-isolate sandboxes do not survive the
restart today**: a WASM sandbox comes back `stopped` with its state gone,
and an isolate sandbox is gone. Drain those nodes first, or recreate those
sandboxes after.

Offline sites: `aerolvm release pull v0.7.0 -o aerolvm-v0.7.0.tgz` on a
machine with internet, then `aerolvm upgrade apply v0.7.0 --from
aerolvm-v0.7.0.tgz`. A node with `SB_REMOTE_UPGRADE=false` (the default in
enterprise mode) is marked `manual`; `aerolvm upgrade status` prints the
`sudo sandboxd upgrade node ...` line to run on it.

**The first hop from a release without `aerolvm upgrade`** (v0.6.11 and
older) uses the installer once per node, one at a time, servers first and
the leader (`aerolvm cluster-info`) last:

```bash
curl -fsSL https://aerolvm.aerol.ai | sudo bash
```

It keeps the node's settings (`/etc/sandboxd/node.json`) and the PAT every
peer shares, restarts `sandboxd` onto the new binary, and never touches the
cluster overlay. Wait until `aerolvm get nodes` shows the node `Ready`
before the next one. Check a node with `sudo sandboxd version`. A cluster
first built with `cluster-init.sh` then needs `sandboxd adopt` once (next
section).

### Bringing a cluster built with cluster-init.sh onto one-line joins

`cluster-init.sh` kept `ca.key` on the seed only, and admitted nobody in
Raft, so new joins and cert renewal have nothing to work with. After the
first hop above:

1. On the seed: `sudo sandboxd adopt`. It imports
   `/etc/sandboxd/cluster-ca/ca.key` into the CA store and records every
   live member's node ID and cert key as admitted (one Raft op).
2. On every other server: `sudo sandboxd adopt`. Each fetches the CA key
   from the seed over the internal mTLS channel, authenticated by its
   existing node cert.
3. Workers and ingress nodes need nothing.

`adopt` is safe to run again ("admitted now: none"). If the seed is gone,
run `sudo sandboxd adopt --ca-key <file>` on a server with a saved copy of
its `ca.key` (a `sandboxd backup` archive of the seed has one). Without
any copy the cluster can't sign new certs; the way out is a new CA, which
is out of scope here.

From then on `aerolvm join-command` works and node certs renew themselves.

Go one node at a time, as in a rolling restart, but finish every server node
in the same session. Do not leave old and new servers running side by side
for hours. When a release changes how the Raft state machine applies entries,
an old and a new server can disagree on rare edge cases while both run. Such
a release says "upgrade every server in one window" in its release notes.

### Taking a node out of cluster mode

```bash
sudo sandboxd reset --yes
```

It asks the cluster to delete this node (when it can reach it), stops
`sandboxd`, and removes `cluster.env`, the certs and keys, the CA store
and the Raft data. The local SQLite database, the server key and
`sandboxd.env` stay. Then join again with a new token, or start
`sandboxd` as a single node.

---

## Cluster-mode environment variables

These are written by `sandboxd init` and `sandboxd join`. Operators who prefer to manage the env
file themselves can set them directly in `/etc/sandboxd/cluster.env`.

| Variable | Required | Description |
|---|---|---|
| `SB_ENABLE_CLUSTER` | yes | `true` to enable cluster mode. |
| `SB_NODE_ID` | yes | Stable identity. Default: hostname. |
| `SB_API_ADVERTISE_URL` | yes | URL other nodes use to forward writes back to this node. |
| `SB_DATA_PLANE_ADVERTISE_HOST` | yes | Host/IP other nodes use for sandbox data-plane forwarding to this node's Caddy/L4 listeners. Defaults to the host in `SB_API_ADVERTISE_URL`; set explicitly when API traffic uses a shared LB or API-only hostname. |
| `SB_RAFT_BIND_ADDR` | yes | Raft listen. Default `0.0.0.0:7000`. |
| `SB_RAFT_ADVERTISE_ADDR` | yes | Raft address peers connect to. Cannot be `0.0.0.0`. |
| `SB_RAFT_DATA_DIR` | yes | On-disk raft state. Default `/var/lib/sandboxd/raft`. |
| `SB_GOSSIP_BIND_ADDR` | yes | Gossip listen. Default `0.0.0.0:7001`. |
| `SB_GOSSIP_ADVERTISE_ADDR` | yes | Gossip address peers connect to. Cannot be `0.0.0.0`. |
| `SB_GOSSIP_SECRET_KEY` | yes | Base64 16/24/32-byte AES key. Same on every node. |
| `SB_CLUSTER_INSECURE_GOSSIP` | no | Opt out of gossip-key requirement. **Only safe on a fully isolated network.** |
| `SB_CREDENTIAL_ENCRYPTION_KEY` | yes | Base64 32-byte key for sealed registry/mount creds. Same on every node. |
| `SB_CREDENTIAL_ENCRYPTION_KEY_PATH` | no | Fallback file if env unset. Default `/var/lib/sandboxd/credential_encryption.key`. |
| `SB_CLUSTER_INSECURE_CREDENTIALS` | no | Opt out of shared-key requirement. **Recovered sandboxes lose private-registry/mount creds without it.** |
| `SB_CLUSTER_TLS_DIR` | yes | Cluster CA trust certificate + this node's keypair. |
| `SB_CLUSTER_INTERNAL_LISTEN` | no | mTLS listen. Default `0.0.0.0:7002`. |
| `SB_CLUSTER_INTERNAL_ADVERTISE` | no | HTTPS URL peers dial. Auto-derived. |
| `SB_CLUSTER_OWNER_CACHE` | no | Worker and ingress nodes remember which node owns a sandbox, so they forward without asking the server tier first, and an owner serves a forward from its ownership-lease reading when the forward's owner epoch matches it. Default `false`. Turn it on only after every node runs a build that has it. See `setup/config-defaults.md`. |
| `SB_BOOTSTRAP_PEERS` | join only | Comma-separated gossip-advertise addresses. Empty on the seed. |
| `SB_CLUSTER_BOOTSTRAP` | yes | `true` only on the seed; `false` on joiners. |
| `SB_CLUSTER_MAX_AUTO_VOTERS` | no | Max gossip-discovered **server-role** nodes auto-promoted as raft voters. Default `5`; additional server nodes become non-voters that still replicate the full FSM. Set `0` for unlimited. Does not bound replica count — the live server tier is separately capped at 7 nodes. |
| `SB_DEAD_OWNER_GRACE` | no | Wait before reassigning a dead node's placements. Default `30s`. Workers also pause their `failover.policy=recreate` sandboxes after half this long without an answer from the leader, so set it the same on every node. |
| `SB_OTEL_METRICS_ENDPOINT` | no | OTLP/HTTP metrics endpoint, for example `http://otel-collector:4318/v1/metrics`. Setting it enables OTEL metrics. |
| `SB_OTEL_METRICS_ENABLED` | no | Enables OTEL metrics without an explicit endpoint; the OTEL exporter env defaults apply. |
| `SB_OTEL_METRICS_INTERVAL` | no | OTEL export interval. Default `30s`. |
| `SB_OTEL_TRACES_ENDPOINT` | no | OTLP/HTTP traces endpoint, for example `http://otel-collector:4318/v1/traces`. Setting it enables OTEL traces. |
| `SB_OTEL_TRACES_ENABLED` | no | Enables OTEL traces without an explicit endpoint; the OTEL exporter env defaults apply. |
| `SB_OTEL_TRACES_SAMPLE_RATIO` | no | Parent-based trace sample ratio. Default `0.05`; use `1` for all root traces or `0` to disable local root sampling. |
| `SB_IMAGE_PULL_MAX_CONCURRENT` | no | Per-worker cap on concurrent Docker image pulls. Default `4`; set `0` to disable the cap. |
| `SB_IMAGE_PULL_FAILURE_BACKOFF` | no | Per-image/auth retry suppression after a failed pull. Default `30s`; set `0s` to disable. |

The daemon **refuses to boot** in cluster mode if either gossip or
credential keys are missing (and the matching `INSECURE_*` flag isn't set).
This is deliberate - silent divergence breaks failover.

---

## What's on disk per node

Same as a single-node install, plus:

| Path | Purpose |
|---|---|
| `/etc/sandboxd/cluster.env` | Cluster env vars (mode 0600). |
| `/etc/systemd/system/sandboxd.service.d/cluster.conf` | systemd drop-in. |
| `/etc/sandboxd/tls/ca.crt` | Cluster CA. |
| `/etc/sandboxd/cluster-ca/ca.key` | The CA store (`SB_CLUSTER_CA_DIR`): the cluster CA's signing key. Every server holds it, so any server can sign a joining node's cert; workers and ingress nodes never do. |
| `/etc/sandboxd/cluster-ca/ca.crt` | The CA certificate paired with `ca.key`. |
| `/etc/sandboxd/tls/node.crt` | This node's cert, signed by the cluster CA (`DNS:node:<id>`, `DNS:role:<role>`). Renewed by itself at 2/3 of its life. |
| `/etc/sandboxd/tls/node.key` | This node's private key. Mode 0600. |
| `/etc/sandboxd/admin-context.json` | The seed only: the admin login `sandboxd init` wrote for `aerolvm config import`. Mode 0600. Holds the PAT; delete it once you have copied it. |
| `/var/lib/sandboxd/raft/` | Raft log + snapshots. |
| `/var/lib/sandboxd/credential_encryption.key` | Cluster-wide AES key (also exported into env). |

Servers hold the CA key because they all sign joins (the same exposure as
the credential key every node already holds). An external-CA mode, with the
key off the servers, is not built yet.

---

## Backups in cluster mode

Raft replication is NOT a backup. A buggy `opPlace` or an operator mistake
gets replicated to every node within milliseconds. Take periodic backups.

Per-node, back up:

1. `/var/lib/sandboxd/state.db` - local SQLite (sandboxes this node owns).
2. `/var/lib/sandboxd/raft/` - local raft log + snapshots.
3. `/etc/sandboxd/` - config, the node cert and CA, and on servers the CA
   store.
4. `/var/lib/sandboxd/credential_encryption.key` - required to decrypt
   sealed credentials in the FSM.

`sandboxd backup` packages all of it into one archive, mode 0600. The
database is copied with `VACUUM INTO`, so a backup taken while `sandboxd`
runs is consistent:

```bash
sudo sandboxd backup --output /secure/backups/sandboxd-$(hostname)-$(date +%F).tar.gz
```

With wrapped key custody the archive carries only the wrapped key;
otherwise it carries the plain key, so store it as a secret. To restore onto
a stopped replacement node:

```bash
sudo systemctl stop sandboxd
sudo sandboxd restore --input /secure/backups/sandboxd-node-a-2026-05-20.tar.gz --force --start
```

`restore` checks the whole archive first and moves what it replaces aside
as `<name>.pre-restore-<time>`. See
[`runbooks/backup-restore.md`](runbooks/backup-restore.md).

---

## Lost-quorum recovery

If you lose more than `(N-1)/2` voters at once, surviving nodes cannot
elect a leader and writes stop. Reads from already-replicated state still
work; new placements do not.

Confirm the diagnosis on a survivor:

```bash
sudo journalctl -u sandboxd --since "10 minutes ago" | grep -iE 'leader|election'
aerolvm cluster-info      # no leader
```

A persistent empty leader with repeated election timeouts is the
signature.

### Option A - wait for the lost nodes to come back

If their raft state on disk is intact, restarting them rejoins the existing
configuration. **Try this first** - non-destructive.

### Option B - manual quorum recovery (last resort, destructive)

If the lost voters are gone for good (disk loss, hardware destroyed),
follow [`runbooks/lost-quorum-recovery.md`](runbooks/lost-quorum-recovery.md).
In short:

1. Stop `sandboxd` on every survivor.
2. On the survivor you chose (the one with the highest raft `LastIndex`):

   ```bash
   sudo sandboxd recover-quorum --start
   ```

   It backs the node up, writes `peers.json` that makes this server the
   only voter, starts `sandboxd`, and waits until it leads.
3. On each other surviving server, once the survivor leads:

   ```bash
   sudo sandboxd recover-quorum --rejoin --start
   ```

   It moves the stale Raft directory aside so the server rejoins as a new
   voter.
4. Delete the servers that are gone for good (`aerolvm delete node <id>`)
   and add new ones with `aerolvm join-command --role server`.

This is **destructive to durability guarantees** - any committed entry the
surviving node never replicated is lost. Rehearse the runbook before you
need it.

---

## Verifying cluster health

A healthy cluster reports:

- `aerolvm get nodes`: every expected node `Ready`, one `Ready,Leader`
  (the API: `GET /v1/cluster/members` with `alive: true`, and a non-empty
  `GET /v1/cluster/leader`).
- No repeated `cluster: AssertOwnership skipped, no leader yet` warnings.
- `cluster: auto-promoted member to raft voter` or `cluster: added member as
  raft non-voter because voter cap is reached` log lines when joiners come
  online - silence here means the raft membership loop isn't seeing the
  joiner.

Set up monitoring on `GET /v1/cluster/leader` returning empty for more than
30 seconds - that's the earliest signal of a brewing quorum problem.

For metric scraping, use the PAT-gated Prometheus endpoint on every node:

```bash
curl -H "Authorization: Bearer $SB_PAT_TOKEN" http://<node>:8080/v1/metrics
```

Scrape servers, workers, and ingress nodes separately. The endpoint exports
only `aerolvm_*` metrics and includes the operational signals needed for the
large-cluster SLOs: Raft apply/snapshot health, route lag, create queue depth,
worker lease freshness, host pressure, image-pull pressure, and Caddy/admin
errors.

For OTEL, set:

```bash
SB_OTEL_METRICS_ENDPOINT=http://otel-collector:4318/v1/metrics
SB_OTEL_METRICS_INTERVAL=30s
SB_OTEL_TRACES_ENDPOINT=http://otel-collector:4318/v1/traces
SB_OTEL_TRACES_SAMPLE_RATIO=0.05
OTEL_SERVICE_NAME=sandboxd
```

The OTEL bridge exports the same `aerolvm_*` expvars under
`aerolvm.expvar.int64` and `aerolvm.expvar.float64`, with the original expvar
name in the `metric` attribute. The trace exporter emits server spans for API
requests, preserves incoming W3C trace context, and attaches the matched
`http.route`, response status, node ID, node role, service name, and version.
A starter Grafana dashboard is available at
`setup/grafana/sandboxd-slo-dashboard.json`.

Prometheus alert rules are available at `setup/prometheus/sandboxd-alerts.yml`.
They cover Raft apply/snapshot health, worker lease freshness, create backlog,
capacity pressure, ingress route lag, Caddy/admin failures, owner-forward
errors, image-pull storms, and secret decrypt failures. An Alertmanager
route/receiver example is available at
`setup/alertmanager/sandboxd-alertmanager-example.yml`.

Full incident runbooks are available under `setup/runbooks/`:

- `backup-restore.md`
- `lost-quorum-recovery.md`
- `image-pull-storm.md`
- `slo-breach.md`

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Joiner stuck, gossip never lands | Wrong `--gossip-key`, or `:7001` blocked | Compare gossip key char-for-char; check security group |
| Joiner gossiped but no voter promotion | Raft `:7000` blocked | Open `:7000` between nodes |
| Daemon refuses to start: `SB_GOSSIP_SECRET_KEY is required` | Cluster env file missing or empty | Re-run `sandboxd init` (seed) or the join line from `aerolvm join-command` (other nodes); both are safe to repeat |
| Daemon refuses to start: `SB_CREDENTIAL_ENCRYPTION_KEY is required` | Same - credential key not in `cluster.env` and no key file on disk | Re-run cluster scripts (they now distribute the key); or copy `/var/lib/sandboxd/credential_encryption.key` from another node |
| Failed-over sandbox can't pull image | Different credential keys across nodes | Verify `sha256sum /var/lib/sandboxd/credential_encryption.key` matches everywhere |
| `502` from any node for a sandbox URL | Owner node down and grace not yet elapsed | Wait up to `SB_DEAD_OWNER_GRACE`; then dead-owner reconciler reassigns |
| Quorum lost (no leader for >30s) | Too many simultaneous failures | See [Lost-quorum recovery](#lost-quorum-recovery) |
| New sandbox creation hangs | No leader, OR no capacity on any node | Check `/v1/cluster/leader`; check capacity in `/v1/cluster/members` |

The single highest-leverage check during any cluster issue:

```bash
sudo journalctl -u sandboxd -n 200 --no-pager | grep -iE 'cluster|raft|gossip|leader'
```
