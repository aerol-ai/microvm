# Cluster Setup

Run AerolVM across multiple hosts behind one logical API. Clients call any
node, raft coordinates placement, and traffic is transparently forwarded to
whichever node owns each sandbox. **Sandboxes themselves are not highly
available** — if the owner node dies, the sandbox is gone (see
[Failover semantics](#failover-semantics)). What survives a node failure is
the cluster: the control plane stays available, other sandboxes keep running,
and new placements continue to land on healthy nodes.

When to pick this over [`single-node.md`](./single-node.md):

- You need more concurrent sandboxes than fits on one host.
- You need per-node failure isolation.
- You're spreading load across availability zones.

If a single host is enough today, run [`single-node.md`](./single-node.md).
You can convert it into the seed of a cluster later without losing state.

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
| `SB_PAT_TOKEN` | API auth. Cluster-internal forwarding rides this when mTLS is off. |
| `SB_GOSSIP_SECRET_KEY` | AES-encrypts gossip payloads; gates raft voter auto-promotion. |
| Cluster TLS bundle (`ca.crt` + `ca.key`) | Cluster-internal mTLS. Joiners mint a per-node cert from the CA. |
| `SB_CREDENTIAL_ENCRYPTION_KEY` | Decrypts sealed registry passwords + per-mount creds replicated via raft. **Required for failover to work for sandboxes that use these.** |

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
  in its in-memory FSM. SealedSecrets are bytes — only the owner with the
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

Hot-path traffic does NOT go through raft — it would be far too slow.
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
  - for each placement owned by B: set owner = "" (orphan)
  - RemoveServer B from the raft configuration
        │
        ▼
subsequent API calls for any of B's sandboxes return 410 Gone
        │
        ▼
clients (or operators) issue a fresh create — placement picks
a new owner from the live, healthy nodes
```

**Sandboxes do not auto-recreate.** Spec, sealed credentials, and exposed-port
metadata replicated via raft are *retained in the FSM* (and a future opt-in
lifecycle policy may rematerialize them), but the current product policy is
"a killed sandbox stays gone." The reassign + recreate code paths exist in
`internal/cluster/{dead_owner,owner_watcher}.go` and `service.RecreateSandbox`
but are gated off behind `clusterRecreateOnFailoverEnabled = false`.

### 4. A node joins for the first time

```
new node runs cluster-join.sh
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
no sandboxes are migrated automatically — the new node has 0 owned
sandboxes and can accept new placements based on its capacity
```

---

## Failover semantics

**The product policy is non-HA sandboxes.** When an owner node dies, every
sandbox on it is gone. The cluster keeps running; the sandboxes do not.

| State | Survives node failure | Why |
|---|---|---|
| Sandbox spec, sealed creds, port intents | **Retained in the FSM, not auto-recreated** | Replicated by raft so a future opt-in failover policy could rematerialize the sandbox. The current default does not. |
| Sandbox runtime (container, filesystem, sessions, host ports, SSH) | **No** | Lives only on the dead host. There is no automatic replacement. |
| Sandbox URL (`<id>.<domain>`) | **No** | The ID is gone from the live cluster — API returns 410 Gone. Clients should create a fresh sandbox and get a fresh ID. |
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

The reassign + recreate code paths exist behind a gate
(`clusterRecreateOnFailoverEnabled` in `internal/cluster/dead_owner.go`). They
are preserved for a future opt-in lifecycle policy and are not active in this
release.

See [Durability and Failover](https://docs.aerol.ai/durability) for the
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
  newly discovered nodes are added as raft **non-voters**: they receive the
  placement log, can own sandboxes, and can forward writes to the leader, but
  they do not enlarge quorum. This is the default safety guard for large runner
  pools.
- `SB_NODE_ID` must be **stable** across restarts. A node returning with a
  new ID joins as a brand-new raft server while the old server sits in the
  configuration as dead.

---

## Prerequisites

Same per-node requirements as a single-node install (Linux apt-based, Docker
prereqs, `sudo`), plus:

- A **private network** the operator controls (VPC, WireGuard mesh,
  dedicated subnet). Cluster-internal traffic must not be reachable from
  the public internet.
- Same `SB_PAT_TOKEN` on every node. The simplest way is to pass the same
  `--pat-token` to each `install.sh`.
- `openssl` available (cluster-init generates the gossip key, the TLS CA,
  and the credential encryption key with it).
- Cluster-internal ports open between nodes only:
  - `7000/TCP` — raft replication
  - `7001/TCP+UDP` — gossip
  - `7002/TCP` — internal mTLS RPC (only when TLS is enabled)
- Public ports open as in single-node: `443/TCP`, `2220/TCP`, optionally
  `22000-23000/TCP`.

---

## Step-by-step: bringing up a 3-node cluster

This is the recommended starting topology. Three small VPS hosts behind one
domain.

### Step 1 — Run install.sh on EVERY node

This is the same single-node install. The cluster scripts assume `sandboxd`
is already installed and managed by systemd. Use the **same PAT token** on
every node.

On `node-a`, `node-b`, `node-c`:

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh \
  | sudo bash -s -- \
      --domain sandbox.example.com \
      --pat-token shared-pat-token \
      --dns-provider cloudflare \
      --dns-api-token <cloudflare-token>
```

Verify on each:

```bash
curl https://sandbox.example.com/health
```

> The `--domain` value can be the same across nodes — they're behind the
> same DNS records. Or different: each node may resolve a different
> sub-domain depending on your load-balancer setup. Most operators use a
> single shared domain plus a load balancer in front. See [DNS for
> clusters](#dns-for-clusters) below.

### Step 2 — Open cluster-internal ports

On each node's firewall (cloud security group or `ufw`):

```
ALLOW 7000/TCP       from <other-cluster-node-IPs>   # raft
ALLOW 7001/TCP,UDP   from <other-cluster-node-IPs>   # gossip
ALLOW 7002/TCP       from <other-cluster-node-IPs>   # internal mTLS (TLS mode only)
```

**Never open these to the public internet.** Gossip carries auth tokens;
raft carries the full FSM.

### Step 3 — Bootstrap the seed (node A)

Pick one node to bootstrap. From now on it's "the seed". On `node-a`:

```bash
sudo curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/cluster-init.sh \
  -o /usr/local/bin/cluster-init.sh
sudo chmod +x /usr/local/bin/cluster-init.sh
sudo /usr/local/bin/cluster-init.sh \
    --node-id node-a \
    --api-advertise-url http://10.0.0.5:21212
```

Replace `10.0.0.5` with `node-a`'s private IP. The script:

1. Auto-generates a 32-byte gossip secret key (override with `--gossip-key`).
2. Generates a self-signed cluster CA + this node's keypair.
3. Reads or generates the credential encryption key.
4. Bundles `ca.crt`, `ca.key`, and `credential_encryption.key` into
   `aerolvm-tls-bundle.tar.gz` in the current directory.
5. Writes `/etc/sandboxd/cluster.env` and a systemd drop-in.
6. Restarts `sandboxd`.
7. Prints the gossip key and the exact `cluster-join.sh` command for
   the other nodes.

**Save the printed gossip key and copy the printed bundle path.** The script
prints a ready-to-run join command — paste it for steps 4 and 5.

Verify the seed came up clean:

```bash
sudo journalctl -u sandboxd -n 50
```

Look for `cluster: leader elected` and absence of any
`SB_CREDENTIAL_ENCRYPTION_KEY is required` or `SB_GOSSIP_SECRET_KEY is
required` errors.

### Step 4 — Securely transfer the TLS bundle

The bundle contains the CA private key and the credential encryption key.
Anyone who gets it can mint a node cert AND decrypt every sealed credential
in the cluster. Treat it like an SSH private key.

```bash
# from your laptop or a jump host:
scp node-a:/path/to/aerolvm-tls-bundle.tar.gz /tmp/
scp /tmp/aerolvm-tls-bundle.tar.gz node-b:/tmp/
scp /tmp/aerolvm-tls-bundle.tar.gz node-c:/tmp/

# or pull directly between nodes if they have SSH between them.
```

Wipe local copies after distribution:

```bash
shred -u /tmp/aerolvm-tls-bundle.tar.gz
```

### Step 5 — Join the rest (node B, node C)

On each joining node:

```bash
sudo curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/cluster-join.sh \
  -o /usr/local/bin/cluster-join.sh
sudo chmod +x /usr/local/bin/cluster-join.sh
sudo /usr/local/bin/cluster-join.sh \
    --node-id node-b \
    --gossip-key '<key-from-cluster-init-output>' \
    --peers 10.0.0.5:7001 \
    --tls-bundle /tmp/aerolvm-tls-bundle.tar.gz
```

The script:

1. Validates the gossip key length.
2. Extracts CA + cred-key from the bundle.
3. Mints a fresh per-node cert signed by the bundled CA.
4. Installs the credential key at `/var/lib/sandboxd/credential_encryption.key`.
5. Writes `/etc/sandboxd/cluster.env` with `SB_BOOTSTRAP_PEERS`,
   `SB_GOSSIP_SECRET_KEY`, `SB_CREDENTIAL_ENCRYPTION_KEY`, and the TLS dir.
6. Restarts `sandboxd`.

`--peers` accepts a comma-separated list — one reachable peer is enough; the
new node discovers the rest through gossip.

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

The seed leader auto-promotes new joiners to raft voters until
`SB_CLUSTER_MAX_AUTO_VOTERS` is reached. Additional joiners are added as raft
non-voters so they receive the placement log without increasing quorum.

### Step 6 — Verify the cluster

From any node:

```bash
curl -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/members
```

Expect three entries with `alive: true` and a recent capacity snapshot.

```bash
curl -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://127.0.0.1:21212/v1/cluster/leader
```

Expect a non-empty leader ID matching one of the three nodes.

Create a sandbox via the SDK against any node — the cluster picks the owner
based on capacity, and subsequent calls are transparently forwarded.

---

## DNS and ingress for clusters

A cluster has **two distinct kinds of public traffic**, and they route
differently. This is the most common source of confusion when standing up a
cluster — read this section before configuring DNS.

### Path 1 — API traffic (`sandbox.example.com/v1/...`)

Lands on any node. For sandbox-scoped requests, the application looks up the
placement record and reverse-proxies the HTTP request to the owner
(`internal/cluster.ForwardHTTP`). Create requests are the special case: the
receiving API node chooses the owner once, then forwards a target-pinned
create to that owner.

**Channel selection.** When both this node and the owner have TLS material
(`SB_CLUSTER_TLS_DIR` set on both), the proxy rides the cluster-internal
mTLS channel on `:7002` — the receiving node's mTLS listener serves the
same `/v1/...` mux as its public port, so handlers run identically but the
hop is cert-pinned end-to-end. The PAT bearer header is still forwarded
(belt-and-braces), but possession of the PAT alone is no longer sufficient
to forge a cross-node API hop. When either side has no TLS material, the
proxy falls back to the public `SB_API_ADVERTISE_URL` with PAT-only auth so
mixed rollouts (some nodes with TLS, some without) keep working.

**You can put any LB or DNS scheme in front of the API path**, but every
node's advertised API URL must still be reachable by its peers as the
mixed-rollout fallback. The `:7002` mTLS port must be reachable between
cluster members for the cert-pinned path to be used at all.

### Path 2 — Sandbox URLs (`<id>.sandbox.example.com`, `<id>-<port>.sandbox.example.com`)

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

### Topology A — SNI-aware L4 LB (recommended; works for both paths) — **2 DNS records**

```
A   sandbox.example.com    →  <LB-public-IP>
A   *.sandbox.example.com  →  <LB-public-IP>
```

The LB does **TLS pass-through** (TCP-mode listener on `:443`, no cert at the
LB), preserving SNI. Each backend node terminates TLS with its own copy of
the wildcard cert.

For the **API path**, this works trivially — any backend forwards the call.

For the **sandbox URL path**, this also works: if the LB lands on a non-owner,
that node's ingress route forwards the connection to the owner. Route
convergence is controlled by the sandboxd cluster-ingress reconcile loop, so a
fresh expose or failover can briefly return 404/502 until the next reconcile.

### Topology B — Per-sandbox DNS (not recommended unless you need direct owner routing)

On each sandbox create, write a per-sandbox A record pointing at the owner:

```
A   <sandbox-id>.sandbox.example.com  →  <owner-node-IP>
```

On failover, update the record to point at the new owner. This bypasses the
any-node ingress layer, but it adds Cloudflare TTL lag during failover
(typically ≥60s), Cloudflare API rate limits at high create churn, and one DNS
record per sandbox. Prefer Topology A unless your environment forbids
node-to-node ingress forwarding.

### Topology C — DNS round-robin (NOT RECOMMENDED) — **6 records**

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

### Step 1 — Create the VPC and subnets

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

### Step 2 — Security groups

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

# Cluster-internal (raft, gossip, mTLS) — only from the SG itself.
SG_CLUSTER=$(aws ec2 create-security-group --vpc-id $VPC_ID \
  --group-name aerolvm-cluster --description "Cluster-internal" \
  --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id $SG_CLUSTER \
  --source-group $SG_CLUSTER --protocol tcp --port 7000-7002
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

### Step 3 — Launch 3 EC2 instances

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

Get each node's **private** IP (you'll need these for `cluster-init.sh` and
`cluster-join.sh`):

```bash
for name in "${!NODES[@]}"; do
  ip=$(aws ec2 describe-instances --instance-ids ${INSTANCE_IDS[$name]} \
    --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)
  echo "$name private-ip=$ip"
done
```

### Step 4 — Network Load Balancer with TLS pass-through

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
TLS using its own copy of the wildcard cert (issued via DNS-01 — see Step 6).

### Step 5 — Cloudflare DNS

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

### Step 6 — Run `install.sh` on each EC2 instance

SSH to each instance (the EIPs you allocated earlier are the SSH targets):

```bash
ssh ubuntu@<node-a-EIP>
sudo curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh \
  | sudo bash -s -- \
      --domain sandbox.example.com \
      --pat-token shared-pat-token-pick-something-strong \
      --dns-provider cloudflare \
      --dns-api-token <cloudflare-token>
```

Repeat on `node-b` and `node-c`. **Use the same `--pat-token` and the same
`--dns-api-token` on all three.**

Each node's Caddy will independently solve a DNS-01 challenge against
Cloudflare (writes a transient `_acme-challenge.sandbox.example.com` TXT
record, waits for LE to verify, deletes the record). Allow 30-90 seconds
per node for first issuance.

Verify on each node:

```bash
sudo journalctl -u sandboxd -n 30 --no-pager | grep -iE 'health|caddy|cert'
curl http://127.0.0.1:21212/health    # local
curl https://sandbox.example.com/health   # via NLB → some backend
```

### Step 7 — Bootstrap the cluster on `node-a`

```bash
# On node-a:
NODE_A_PRIVATE_IP=10.0.1.X    # from Step 3 output

sudo curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/cluster-init.sh \
  -o /usr/local/bin/cluster-init.sh
sudo chmod +x /usr/local/bin/cluster-init.sh

sudo /usr/local/bin/cluster-init.sh \
    --node-id node-a \
    --api-advertise-url http://$NODE_A_PRIVATE_IP:21212
```

Save the printed gossip key and bundle path. The bundle is at
`./aerolvm-tls-bundle.tar.gz` by default (the script prints the exact path).

### Step 8 — Distribute the TLS bundle to `node-b` and `node-c`

From your laptop:

```bash
scp ubuntu@<node-a-EIP>:aerolvm-tls-bundle.tar.gz /tmp/
scp /tmp/aerolvm-tls-bundle.tar.gz ubuntu@<node-b-EIP>:/tmp/
scp /tmp/aerolvm-tls-bundle.tar.gz ubuntu@<node-c-EIP>:/tmp/
shred -u /tmp/aerolvm-tls-bundle.tar.gz
```

### Step 9 — Join `node-b` and `node-c`

On each joiner:

```bash
# On node-b (and node-c, with --node-id node-c):
NODE_A_PRIVATE_IP=10.0.1.X
GOSSIP_KEY='<key-from-step-7>'

sudo curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/cluster-join.sh \
  -o /usr/local/bin/cluster-join.sh
sudo chmod +x /usr/local/bin/cluster-join.sh

sudo /usr/local/bin/cluster-join.sh \
    --node-id node-b \
    --gossip-key "$GOSSIP_KEY" \
    --peers $NODE_A_PRIVATE_IP:7001 \
    --tls-bundle /tmp/aerolvm-tls-bundle.tar.gz
```

### Step 10 — Verify

```bash
PAT=shared-pat-token-pick-something-strong

# From your laptop, hitting the NLB:
curl -H "Authorization: Bearer $PAT" https://sandbox.example.com/v1/cluster/members
curl -H "Authorization: Bearer $PAT" https://sandbox.example.com/v1/cluster/leader
```

You should see all three nodes alive, and a non-empty leader. From the
SDK:

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

### After the cluster is up — what works, what doesn't

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
caller fall into a generic timeout. Treat these as the wire contract — SDKs
and load-balancer health checks key off them:

| Surface | Situation | Response |
|---|---|---|
| API control plane (`/v1/sandboxes/...`) | Placement still resolving on this node, owner's URL not yet gossiped | **503 Service Unavailable** with owner node-id in body; bumps `aerolvm_ingress_route_misses_total`. Retry. |
| API control plane | Owner died and grace expired; placement orphaned | **410 Gone**. Stop retrying; issue a fresh `Create`. |
| API control plane | Request forwarded to wrong node (stale placement view at sender) | **421 Misdirected Request**. Caller should re-resolve owner. |
| Data plane HTTP/TLS (Caddy) | Route in flux on this node (placement seen, route not yet installed) | **503** with `Retry-After: 2` and body `Sandbox placement in flux. Retry in a moment.` |
| Data plane raw TCP | Route in flux on this node | Connection refused. (No in-flux mirror — raw TCP has no hostname to match on, so the port simply isn't bound until the reconciler installs it.) |
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

- `converged: true` — owner is this node (synchronous install) OR the
  reconciler has applied routes for an FSM version ≥ `placement_version`.
  Client traffic via this node will hit the route.
- `converged: false` — the reconciler is still catching up; raw TCP dials may
  see connection refused and HTTP/TLS sees the 503-with-Retry-After in-flux
  response above. Recheck after the next 5s reconcile tick. If
  `node_installed_version` does not catch up after multiple ticks, scrape
  `/debug/vars` for `aerolvm_ingress_reconcile_errors_total` to find the
  Caddy-side failure.

For node-wide convergence (rather than per-sandbox), the gauges
`aerolvm_ingress_route_lag_versions` and `aerolvm_ingress_route_misses_total`
on each node's `/debug/vars` are the operator signals.

#### Preferred host-port replay during failover-recreate

When a placement re-lands on a new owner via the failover-recreate path (gated
off by default — sandboxes are not HA under current product policy), the FSM
carries the original TCP `host_port` so the new owner can re-bind it and
preserve the public endpoint. If that host port is already reserved on the
new owner (taken by an unrelated TCP exposure, or in use locally), the
replay **parks** the exposure rather than silently allocating a different
host port:

- The FSM record (with the original `host_port`) stays intact.
- The local re-bind fails with `ErrPreferredHostPortUnavailable`; the
  per-sandbox convergence status above reports `converged: false`.
- The allocator does **not** fall through to the random/linear pool walk —
  silently switching `host:40123` → `host:55555` would break every client
  that memorized the original endpoint, which is the whole point of the
  cluster-stable TCP route map.

Operator remediation: drain the conflicting exposure on the new owner, or
restart the placement on a different node via an explicit re-create.

---

## Operating the cluster

### Per-node files (cluster overlay)

Both `cluster-init.sh` and `cluster-join.sh` write the same two files:

- `/etc/sandboxd/cluster.env` (mode 0600) — cluster env vars.
- `/etc/systemd/system/sandboxd.service.d/cluster.conf` — drop-in adding
  `EnvironmentFile=/etc/sandboxd/cluster.env`.

The base `/etc/sandboxd/sandboxd.env` from `install.sh` is never modified.
Re-running `install.sh` later does not overwrite the cluster overlay.

### Adding a 4th (or 5th, …) node

Run `cluster-join.sh` on the new host with any reachable peer. The script
takes the same gossip key + TLS bundle as the original joiners. The leader
adds it as a voter until `SB_CLUSTER_MAX_AUTO_VOTERS` is reached; after that,
it is added as a non-voter.

> **Tip:** keep voter count odd. Add nodes in pairs: 3 → 5 → 7. A 4-node
> cluster has the same fault tolerance as a 3-node one but a higher quorum
> threshold.

### Removing a node

For worker or ingress-only nodes, drain admission first, wait until the node
owns no placements, then replace or terminate the instance:

```bash
export SB_PAT_TOKEN=<redacted>
curl -fsS -X POST -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://<any-node>:21212/v1/cluster/nodes/<node-id>/drain
curl -fsS -H "Authorization: Bearer $SB_PAT_TOKEN" \
  'http://<any-node>:21212/v1/cluster/sandbox-index?limit=5000'
```

The packaged helper does the same check and fails if long-lived placements are
still present:

```bash
sudo /usr/local/sbin/sandboxd-node-lifecycle.sh pre-role-change <node-id>
```

For server-role raft members, stop the daemon or terminate the instance, then
remove the stale raft member explicitly from any surviving node:

```bash
curl -fsS -X DELETE -H "Authorization: Bearer $SB_PAT_TOKEN" \
  http://<any-survivor>:21212/v1/cluster/members/<node-id>
```

`DELETE /v1/cluster/members/<node-id>` persists a drain mark, orphans any
placements owned by that node (`OwnerNodeID = ""`; subsequent API calls return
`410 Gone` under the current non-HA policy), and calls raft `RemoveServer`.
It refuses to remove a member that is still gossiped alive unless
`?force=true` is supplied, and it refuses to remove the last raft voter.
Any sandboxes that were on the removed node are gone for good under the current
non-HA policy; clients should create fresh sandboxes.

### Rolling restart

Restart nodes one at a time, waiting for each to rejoin before the next:

```bash
sudo systemctl restart sandboxd
sudo journalctl -u sandboxd -f   # wait for "cluster: leader elected" or peer log
# then move to next node
```

Quorum is preserved as long as you don't exceed `(N-1)/2` simultaneous
restarts. For a 3-node cluster: never restart two at once.

### Updating binaries

Re-run `install.sh` on each node in turn (rolling). The cluster overlay is
preserved.

### Taking a node out of cluster mode

```bash
sudo systemctl stop sandboxd
sudo rm /etc/sandboxd/cluster.env /etc/systemd/system/sandboxd.service.d/cluster.conf
sudo systemctl daemon-reload
sudo systemctl start sandboxd
```

The node's local SQLite + sandboxes remain. Only the cluster wiring is
removed. The remaining cluster eventually reconciles its absence.

---

## Cluster-mode environment variables

These are managed by the scripts. Operators who prefer to manage the env
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
| `SB_CLUSTER_TLS_DIR` | recommended | Cluster CA + this node's keypair. |
| `SB_CLUSTER_INTERNAL_LISTEN` | no | mTLS listen. Default `0.0.0.0:7002`. |
| `SB_CLUSTER_INTERNAL_ADVERTISE` | no | HTTPS URL peers dial. Auto-derived. |
| `SB_BOOTSTRAP_PEERS` | join only | Comma-separated gossip-advertise addresses. Empty on the seed. |
| `SB_CLUSTER_BOOTSTRAP` | yes | `true` only on the seed; `false` on joiners. |
| `SB_CLUSTER_MAX_AUTO_VOTERS` | no | Max gossip-discovered nodes auto-promoted as raft voters. Default `5`; additional nodes become non-voters. Set `0` for unlimited. |
| `SB_DEAD_OWNER_GRACE` | no | Wait before reassigning a dead node's placements. Default `30s`. |
| `SB_OTEL_METRICS_ENDPOINT` | no | OTLP/HTTP metrics endpoint, for example `http://otel-collector:4318/v1/metrics`. Setting it enables OTEL metrics. |
| `SB_OTEL_METRICS_ENABLED` | no | Enables OTEL metrics without an explicit endpoint; the OTEL exporter env defaults apply. |
| `SB_OTEL_METRICS_INTERVAL` | no | OTEL export interval. Default `30s`. |
| `SB_IMAGE_PULL_MAX_CONCURRENT` | no | Per-worker cap on concurrent Docker image pulls. Default `4`; set `0` to disable the cap. |
| `SB_IMAGE_PULL_FAILURE_BACKOFF` | no | Per-image/auth retry suppression after a failed pull. Default `30s`; set `0s` to disable. |

The daemon **refuses to boot** in cluster mode if either gossip or
credential keys are missing (and the matching `INSECURE_*` flag isn't set).
This is deliberate — silent divergence breaks failover.

---

## What's on disk per node

Same as a single-node install, plus:

| Path | Purpose |
|---|---|
| `/etc/sandboxd/cluster.env` | Cluster env vars (mode 0600). |
| `/etc/systemd/system/sandboxd.service.d/cluster.conf` | systemd drop-in. |
| `/etc/sandboxd/tls/ca.crt` | Cluster CA. |
| `/etc/sandboxd/tls/ca.key` | Cluster CA private key (seed and joiners both keep it for re-mints). Mode 0600. |
| `/etc/sandboxd/tls/node.crt` | This node's cert, signed by the cluster CA. |
| `/etc/sandboxd/tls/node.key` | This node's private key. Mode 0600. |
| `/var/lib/sandboxd/raft/` | Raft log + snapshots. |
| `/var/lib/sandboxd/credential_encryption.key` | Cluster-wide AES key (also exported into env). |

The cluster TLS bundle (`aerolvm-tls-bundle.tar.gz`) is generated by
`cluster-init.sh` for distribution and should be deleted from any host that
isn't actively joining a node.

---

## Backups in cluster mode

Raft replication is NOT a backup. A buggy `opPlace` or an operator mistake
gets replicated to every node within milliseconds. Take periodic backups.

Per-node, back up:

1. `/var/lib/sandboxd/state.db` — local SQLite (sandboxes this node owns).
2. `/var/lib/sandboxd/raft/` — local raft log + snapshots.
3. `/etc/sandboxd/cluster.env`, `/etc/sandboxd/sandboxd.env` — config.
4. `/etc/sandboxd/tls/` — node cert and CA.
5. `/var/lib/sandboxd/credential_encryption.key` — required to decrypt
   sealed credentials in the FSM.

For a full cluster recovery from total destruction, you also need the
cluster TLS bundle (CA + CA key) and the gossip key. Store these in your
secrets manager.

The repo includes a backup helper that packages the local SQLite DB, Raft
state, and `/etc/sandboxd` config tree into one restricted archive:

```bash
sudo scripts/sandboxd-backup.sh --output /secure/backups/sandboxd-$(hostname)-$(date +%F).tar.gz
```

To restore onto a stopped replacement node:

```bash
sudo systemctl stop sandboxd
sudo scripts/sandboxd-restore.sh --input /secure/backups/sandboxd-node-a-2026-05-20.tar.gz --target-root / --force
sudo systemctl start sandboxd
```

---

## Lost-quorum recovery

If you lose more than `(N-1)/2` voters at once, surviving nodes cannot
elect a leader and writes stop. Reads from already-replicated state still
work; new placements do not.

Confirm the diagnosis on a survivor:

```bash
sudo journalctl -u sandboxd --since "10 minutes ago" | grep -iE 'leader|election'
curl -s -H "Authorization: Bearer $SB_PAT_TOKEN" http://127.0.0.1:21212/v1/cluster/leader
```

A persistent empty `Leader` field with repeated election timeouts is the
signature.

### Option A — wait for the lost nodes to come back

If their raft state on disk is intact, restarting them rejoins the existing
configuration. **Try this first** — non-destructive.

### Option B — manual quorum recovery (last resort, destructive)

If the lost voters are gone for good (disk loss, hardware destroyed):

1. Stop `sandboxd` on every survivor.
2. On the node with the highest raft `LastIndex` (check `journalctl`),
   create `/var/lib/sandboxd/raft/peers.json` directly or with the helper:

   ```bash
   sudo scripts/raft-lost-quorum-recover.sh \
     --raft-dir /var/lib/sandboxd/raft \
     --node-id this-node-id \
     --raft-address 10.0.0.5:7000
   ```

3. Start `sandboxd` on that node only. It detects `peers.json`, runs
   HashiCorp Raft's recovery path, rewrites the raft configuration to the
   supplied peers, and renames the file to `peers.json.applied.<unix>` after
   success.
4. Once it elects itself leader, re-add the other survivors:

   ```bash
   sudo rm -rf /var/lib/sandboxd/raft   # on each rejoining node
   sudo cluster-join.sh --gossip-key '<key>' \
                        --peers <recovered-node>:7001 \
                        --tls-bundle <bundle> \
                        --force
   ```

5. Inspect placements via `GET /v1/cluster/members`. Any sandboxes owned by
   permanently-lost nodes are reassigned (or orphaned if no capacity) by
   the dead-owner reconciler.

This is **destructive to durability guarantees** — any committed entry the
surviving node never replicated is lost. Document this procedure in your
runbook before you need it.

---

## Verifying cluster health

A healthy cluster reports:

- A non-empty `Leader` from `GET /v1/cluster/leader`.
- All expected node IDs in `GET /v1/cluster/members` with `alive: true`.
- No repeated `cluster: AssertOwnership skipped, no leader yet` warnings.
- `cluster: auto-promoted member to raft voter` or `cluster: added member as
  raft non-voter because voter cap is reached` log lines when joiners come
  online — silence here means the raft membership loop isn't seeing the
  joiner.

Set up monitoring on `GET /v1/cluster/leader` returning empty for more than
30 seconds — that's the earliest signal of a brewing quorum problem.

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
OTEL_SERVICE_NAME=sandboxd
```

The OTEL bridge exports the same `aerolvm_*` expvars under
`aerolvm.expvar.int64` and `aerolvm.expvar.float64`, with the original expvar
name in the `metric` attribute. A starter Grafana dashboard is available at
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
| Daemon refuses to start: `SB_GOSSIP_SECRET_KEY is required` | Cluster env file missing or empty | Re-run `cluster-init.sh` / `cluster-join.sh` |
| Daemon refuses to start: `SB_CREDENTIAL_ENCRYPTION_KEY is required` | Same — credential key not in `cluster.env` and no key file on disk | Re-run cluster scripts (they now distribute the key); or copy `/var/lib/sandboxd/credential_encryption.key` from another node |
| Failed-over sandbox can't pull image | Different credential keys across nodes | Verify `sha256sum /var/lib/sandboxd/credential_encryption.key` matches everywhere |
| `502` from any node for a sandbox URL | Owner node down and grace not yet elapsed | Wait up to `SB_DEAD_OWNER_GRACE`; then dead-owner reconciler reassigns |
| Quorum lost (no leader for >30s) | Too many simultaneous failures | See [Lost-quorum recovery](#lost-quorum-recovery) |
| New sandbox creation hangs | No leader, OR no capacity on any node | Check `/v1/cluster/leader`; check capacity in `/v1/cluster/members` |

The single highest-leverage check during any cluster issue:

```bash
sudo journalctl -u sandboxd -n 200 --no-pager | grep -iE 'cluster|raft|gossip|leader'
```
