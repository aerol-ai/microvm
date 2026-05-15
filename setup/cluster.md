# Cluster Setup

Run AerolVM across multiple hosts behind one logical API. Clients call any
node, raft coordinates placement, and traffic is transparently forwarded to
whichever node owns each sandbox. Sandboxes survive node failure (with
caveats — see [Failover semantics](#failover-semantics)).

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
  - for each placement owned by B: try to reassign to a live node with capacity
  - if no capacity anywhere: orphan it (placement deleted)
        │
        ▼
new owner pulls the spec from its FSM
        │
        ▼
new owner unseals registry/mount creds with the shared key
        │   (THIS is why every node must hold the same key)
        ▼
new owner docker-runs the sandbox image
        │
        ▼
sandbox is back on a different host with the same spec
```

### 4. A node joins for the first time

```
new node runs cluster-join.sh
        │
        ▼
joins gossip ring (authenticated by SB_GOSSIP_SECRET_KEY)
        │
        ▼
seed's leader auto-promotes it to a raft voter
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

What does and does not survive a node failure.

| State | Survives failover | Why |
|---|---|---|
| Sandbox spec (image, env, mounts, runtime, registry config) | **Yes** | Replicated via raft. New owner recreates the container. |
| Sealed registry/mount credentials | **Yes (only with shared key)** | Replicated as encrypted blobs. Decrypted by new owner using `SB_CREDENTIAL_ENCRYPTION_KEY`. |
| Container filesystem | **No** | Lives only on the dead host. New owner starts a fresh container from the same image. |
| Active exec sessions, port-forwards, SSH connections | **No** | Bound to the old container. Clients reconnect after failover. |
| Sessions / recordings on disk | **No (without external storage)** | Live in the dead host's `/var/lib/`. Use external mounts to persist. |
| TCP-port allocations | **Re-allocated** | New owner picks fresh host ports from its pool. URLs that include the port number change. |
| Subdomain URL (`<id>.<domain>`) | **Yes** | The sandbox keeps its ID. DNS continues to resolve. |

Make workloads truly stateless across failover by:
1. Keeping ephemeral state in the container only.
2. Mounting durable state from external storage (S3, NFS, sshfs).
3. Reconnecting sessions on disconnect (the SDK does this automatically for
   exec and file streams).

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
cluster: voter promoted node_id=node-b
cluster: voter promoted node_id=node-c
cluster gossip joined peers ...
```

The seed leader auto-promotes new joiners to raft voters once gossip
membership is confirmed (typically within seconds).

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
placement record and forwards the HTTP request to the owner's advertised API
URL (`internal/cluster.ForwardHTTP`). Create requests are the special case:
the receiving API node chooses the owner once, then forwards a target-pinned
create to that owner.

The mTLS listener on `:7002` is for cluster-internal control-plane traffic
such as leader-forwarded raft applies. It is not the data path for API
owner-forwarding. **You can put any LB or DNS scheme in front of the API path,
but every node's advertised API URL must be reachable by its peers.**

### Path 2 — Sandbox URLs (`<id>.sandbox.example.com`, `<id>-<port>.sandbox.example.com`)

Each sandbox container lives on exactly **one** node. Only that node's Caddy
holds a route for `<id>.sandbox.example.com` → local container IP. **The
cluster does not proxy sandbox-URL traffic between nodes today.** If the TCP
connection lands on a node that isn't the owner, Caddy on that node has no
matching route and returns a 404 / unmatched-SNI fallback.

Your DNS / LB layer has to put each sandbox-URL connection on the right node.

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

For the **sandbox URL path**, this works **only when the LB happens to land
the connection on the owner**. With pure round-robin across N nodes, ~1/N of
sandbox-URL requests reach the right node and the rest 404. To make it
reliable you need one of:

- An LB that can dynamically steer per SNI to the owner backend (Envoy with
  an SDS feed from the cluster's owner endpoint, or a custom HAProxy
  config-rewriter). Not built into AerolVM today.
- A small router process in front (e.g. another `sandboxd` running with
  `SB_ENABLE_CADDY=true` but no sandboxes — it would still 404 because no
  cross-node sandbox routes exist; this option is not viable today).
- One of the alternate topologies below.

### Topology B — Per-sandbox DNS (works for sandbox URLs but operational overhead)

On each sandbox create, write a per-sandbox A record pointing at the owner:

```
A   <sandbox-id>.sandbox.example.com  →  <owner-node-IP>
```

On failover, update the record to point at the new owner. Pros: every
request reaches the owner directly. Cons: Cloudflare TTL lag during failover
(typically ≥60s of downtime), Cloudflare API rate limits at high create
churn, one DNS record per sandbox. **Not implemented in `sandboxd` today** —
you'd have to wire it up via a webhook on placement changes.

### Topology C — DNS round-robin (NOT RECOMMENDED) — **6 records**

```
A   sandbox.example.com    →  <node-a-IP>
A   sandbox.example.com    →  <node-b-IP>
A   sandbox.example.com    →  <node-c-IP>
A   *.sandbox.example.com  →  <node-a-IP>
A   *.sandbox.example.com  →  <node-b-IP>
A   *.sandbox.example.com  →  <node-c-IP>
```

Same hit-the-wrong-owner problem as Topology A, plus no health checking
(dead nodes still answer DNS). **API works** (every backend can forward).
**Sandbox URLs partially work** (1/N hit rate). Use only for testing.

### Practical recommendation

| Your usage | Use this |
|---|---|
| Mostly SDK calls (exec, file, port-forward) — sandbox URLs rare or none | Topology A. Sandbox URL hit-rate is acceptable; SDK path is perfect. |
| Public sandbox URLs are core to the product | Single-node today, OR build Topology B integration. |
| Mixed | Topology A + accept retries on sandbox URL failures, OR build B. |

The "any-node can serve any sandbox URL" property does **not** exist today
for the public HTTPS data plane. It exists for the API only. Plan
accordingly.

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
| Public sandbox URLs (`<id>.sandbox.example.com`) | **Round-robin: ~1/3 hit rate on a 3-node NLB.** Connection lands on a non-owner → 404. |
| Failover (kill an EC2) | **Working.** After `SB_DEAD_OWNER_GRACE`, sandboxes reassign; new owner unseals creds with the shared key from the bundle. |
| TLS issuance/renewal | **Working per node.** Three independent DNS-01 renewal loops, well under LE quota. |

If your product depends on `<id>.sandbox.example.com` URLs being reliably
reachable (not just SDK calls), you have three choices today:

1. **Stay single-node** until you implement smarter ingress.
2. **Per-sandbox DNS** (Topology B): write a record per sandbox pointing at
   the owner; update on failover. Requires custom integration.
3. **Build SNI-aware ingress**: replace the NLB with Envoy or HAProxy
   driven by a control loop that polls `/v1/cluster/members` + placements
   and rewrites the SNI→backend map. This is the "real" fix and is on the
   roadmap.

This isn't documented elsewhere because it's the architectural seam most
operators don't notice until they ship public sandbox URLs in production.

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
auto-promotes it to a voter.

> **Tip:** keep voter count odd. Add nodes in pairs: 3 → 5 → 7. A 4-node
> cluster has the same fault tolerance as a 3-node one but a higher quorum
> threshold.

### Removing a node

Stop the daemon on the node. The dead-owner reconciler runs after
`SB_DEAD_OWNER_GRACE` (default 30s) and reassigns or orphans its
placements. There is not currently a public API endpoint for explicit raft
membership removal; do not rely on `DELETE /v1/cluster/members/<node-id>`.
For now, treat permanent node removal as an operator action that must be
validated against the current raft membership before the node's data directory
is reused or discarded.

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
   create `/var/lib/sandboxd/raft/peers.json`:

   ```json
   [
     { "id": "this-node-id", "address": "10.0.0.5:7000", "non_voter": false, "suffrage": "Voter" }
   ]
   ```

3. Start `sandboxd` on that node only. It detects `peers.json` and rewrites
   the raft configuration to itself — bootstraps a fresh single-node cluster
   from its existing log.
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
- `cluster: voter promoted` log lines when joiners come online — silence
  here means the auto-voter loop isn't seeing the joiner.

Set up monitoring on `GET /v1/cluster/leader` returning empty for more than
30 seconds — that's the earliest signal of a brewing quorum problem.

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
