---
title: Cluster Setup
description: Deploy a multi-node AerolVM cluster on AWS using Terraform.
---

A cluster is a group of AerolVM servers that work together as one system. Instead of running all sandboxes on a single machine, a cluster spreads work across multiple nodes - so you can run more sandboxes in parallel and stay online even if one server goes down.

A **single-node setup** works well for development and low-traffic production. You need a cluster when:
- One server can't handle all your sandboxes at the same time
- You need the system to keep running when a server fails
- You want to separate sandbox execution from public traffic routing

This guide walks through deploying a cluster on AWS using Terraform. Terraform handles provisioning, installation, and wiring automatically - you edit three config files, run one command, and the cluster comes up.

## Before you start

You'll need:

- **Terraform 1.5 or newer** - [download here](https://developer.hashicorp.com/terraform/install)
- **An AWS account** with permissions to create EC2 instances, VPCs, IAM roles, S3 buckets, and security groups
- **AWS credentials** configured locally (environment variables, `~/.aws/credentials`, or an IAM instance role)
- **A Cloudflare account** with a domain you control and an API token with `Zone:DNS:Edit` permission
- **An SSH key pair** at `~/.ssh/id_rsa.pub` (or any path you specify)

If you don't have a domain yet, the cluster will work without HTTPS - sandbox URLs will use IP addresses instead. You can add a domain later.

## Step 1 - Copy the config files

From the root of the repository:

```bash
cp config/terraform.tfvars.example config/terraform.tfvars
cp config/secrets.example.yml      config/secrets.yml
```

You'll edit three files total. Here's what each one controls:

| File | What goes here |
|---|---|
| `config/secrets.yml` | API keys and tokens - never commit this file |
| `config/cluster.yml` | Cluster behavior: domain name, email, image settings |
| `config/terraform.tfvars` | Which servers to create and their sizes |

## Step 2 - Add your secrets

Open `config/secrets.yml` and fill in these two values:

```yaml
cluster:
  pat_token: ""     # Generate with: openssl rand -hex 32 | sed 's/^/avm_/'

cloudflare:
  api_token: ""     # Cloudflare API token with Zone:DNS:Edit permission
```

The **PAT token** is the shared password every node and SDK client uses for authentication. Every node in the cluster must share the same value - if they differ, nodes will reject requests from each other. Generate a token and store it somewhere secure.

The **Cloudflare API token** lets Terraform create DNS records for your cluster domain and lets AerolVM automatically obtain HTTPS certificates from Let's Encrypt.

## Step 3 - Set your domain

Open `config/cluster.yml` and update the `ingress` section:

```yaml
ingress:
  domain_name: "cluster.example.com"   # Your domain
  acme_email:  "you@example.com"        # Your email (for HTTPS cert expiry alerts)
```

AerolVM uses this domain to route traffic to sandboxes. Each sandbox gets a unique subdomain - for example, `abc123.cluster.example.com`. Terraform creates the DNS records automatically.

Leave `domain_name` empty to skip HTTPS and use IP-based routing instead.

## Step 4 - Choose your servers

Open `config/terraform.tfvars` and define your nodes. Each entry in the `nodes` block is one server.

**The simplest production-ready setup - three mixed nodes:**

```hcl
aws_region = "us-east-1"

nodes = {
  node1 = { role = "mixed", seed = true }
  node2 = { role = "mixed" }
  node3 = { role = "mixed" }
}
```

A `mixed` node does everything: it participates in cluster consensus, runs sandboxes, and handles public traffic. Three `mixed` nodes means you can lose one and the cluster keeps running.

Exactly one node must have `seed = true`. The seed starts the cluster; all others join it.

### Node roles

As you scale up, you may want specialized nodes for different responsibilities:

| Role | Votes in consensus | Runs sandboxes | Handles traffic |
|---|---|---|---|
| `mixed` | Yes | Yes | Yes |
| `server` | Yes | No | No |
| `worker` | No | Yes | No |
| `ingress` | No | No | Yes |
| `server,worker` | Yes | Yes | No |
| `worker,ingress` | No | Yes | Yes |

**Consensus (Raft)** is how all nodes agree on where each sandbox lives. Nodes that vote ("server" or "mixed") must have a majority online to make decisions - with 3 voters, you can lose 1; with 5, you can lose 2. Always use an odd number of voting nodes (3, 5, or 7). See [Cluster Glossary](/cluster-glossary) for a full quorum reference.

A larger split-role cluster:

```hcl
nodes = {
  srv1 = { role = "server", seed = true, instance_type = "t3.small" }
  srv2 = { role = "server",              instance_type = "t3.small" }
  srv3 = { role = "server",              instance_type = "t3.small" }
  wrk1 = { role = "worker",              instance_type = "t3.large", volume_size_gb = 200 }
  wrk2 = { role = "worker",              instance_type = "t3.large", volume_size_gb = 200 }
  ing1 = { role = "ingress",             instance_type = "t3.medium" }
  ing2 = { role = "ingress",             instance_type = "t3.medium" }
}
```

Sizing guidelines:
- **Server nodes** are lightweight - `t3.small` or `t3.medium` is sufficient.
- **Worker nodes** run sandboxes and need more memory and disk. Size to your workload.
- **Ingress nodes** handle network traffic - `t3.medium` is a good starting point.

## Step 5 - Enable gVisor (optional)

gVisor is a runtime that adds an extra layer of isolation to Docker containers. It runs a user-space kernel between each sandbox and the host - so if a sandbox tries to exploit a host kernel vulnerability, gVisor intercepts the call instead of the real kernel.

gVisor works on any standard EC2 instance type. There are no special hardware requirements.

To enable gVisor on a worker node, add `with_gvisor = true`:

```hcl
nodes = {
  srv1 = { role = "server", seed = true, instance_type = "t3.small" }
  wrk1 = { role = "worker", with_gvisor = true, instance_type = "t3.large" }
  wrk2 = { role = "worker", with_gvisor = true, instance_type = "t3.large" }
  ing1 = { role = "ingress",                    instance_type = "t3.medium" }
}
```

After deployment, create sandboxes with `runtime: "gvisor"` to use gVisor isolation. Nodes without `with_gvisor = true` continue to use the default Docker runtime.

## Step 6 - Enable Firecracker (optional)

Firecracker is a virtual machine runtime for sandboxes. Instead of Docker containers, each sandbox runs inside its own microVM that boots in under 100ms. This provides the strongest isolation - each sandbox has its own kernel, so a vulnerability in one cannot affect the host or other sandboxes.

:::caution[Firecracker requires bare-metal AWS instances]
Firecracker needs direct access to the hardware virtualization unit (`/dev/kvm`). Standard EC2 instance types (`t3`, `c6i`, `m5`, `r5`, etc.) are themselves virtual machines and don't expose `/dev/kvm`. You must use **bare-metal instance types** - the `*.metal` SKUs. Common options:

- Compute: `c5.metal`, `c5n.metal`, `c6i.metal`, `c7g.metal`
- General purpose: `m5.metal`, `m5zn.metal`, `m6i.metal`
- Storage / memory: `i3.metal`, `r5.metal`

Bare-metal instances are more expensive. Use them only on the worker nodes where Firecracker is enabled.
:::

To enable Firecracker, set `with_firecracker = true` on worker nodes and choose a bare-metal `instance_type`:

```hcl
nodes = {
  srv1 = { role = "server", seed = true, instance_type = "t3.small" }
  wrk1 = { role = "worker", with_firecracker = true, instance_type = "c5.metal" }
  wrk2 = { role = "worker", with_firecracker = true, instance_type = "c5.metal" }
  ing1 = { role = "ingress",                         instance_type = "t3.medium" }
}
```

Also add a `firecracker` block pointing to where the binaries and kernel should come from:

```hcl
firecracker = {
  binary_url  = "https://example.com/firecracker"
  jailer_url  = "https://example.com/jailer"
  kernel_url  = "https://example.com/vmlinux"
  kernel_path = "/var/lib/sandboxd/firecracker/vmlinux"
}
```

Set the `*_url` fields to download locations for the binaries. Leave them empty if your server image already has the files installed at those paths - Terraform will skip the download step.

After deployment, you register container images as Firecracker templates and then create sandboxes using the `firecracker` runtime. See [Firecracker Templates](/firecracker-templates) for the step-by-step workflow.

## Step 7 - Enable GPU support (optional)

AerolVM can pass through physical GPUs to sandboxes. NVIDIA and AMD GPUs are both supported. GPU-enabled worker nodes run alongside regular workers - the cluster placement engine automatically routes GPU sandbox requests to nodes that have the right hardware.

### NVIDIA GPUs

Set `with_nvidia_gpu = true` on worker nodes that have an NVIDIA GPU. This installs the NVIDIA Container Toolkit and configures Docker to expose the GPU to containers.

Common NVIDIA GPU instance types on AWS:

| Instance | GPU |
|---|---|
| `g4dn.xlarge` | NVIDIA T4 |
| `g5.xlarge` | NVIDIA A10G |
| `p3.2xlarge` | NVIDIA V100 |

```hcl
nodes = {
  srv1 = { role = "server", seed = true,  instance_type = "t3.small" }
  wrk1 = { role = "worker",               instance_type = "t3.large" }
  wrk2 = { role = "worker", with_nvidia_gpu = true, instance_type = "g5.xlarge",
            volume_size_gb = 500, tags = { gpu = "nvidia-a10g" } }
  ing1 = { role = "ingress",              instance_type = "t3.medium" }
}
```

The optional `tags` field is useful if you have multiple GPU types in the cluster - SDK clients can target a specific GPU model by tag.

### AMD GPUs

Set `with_amd_gpu = true` on worker nodes with AMD (ROCm-compatible) hardware. Only supported on `x86_64` instances.

```hcl
wrk3 = { role = "worker", with_amd_gpu = true, instance_type = "g4ad.xlarge",
          volume_size_gb = 300 }
```

:::note
GPU passthrough is not compatible with gVisor. A sandbox can use either a GPU or gVisor isolation - not both at the same time. You can mix GPU nodes and gVisor nodes in the same cluster; they simply accept different sandbox requests.
:::

After deployment, see [GPU Sandboxes](/gpu-sandboxes) for the full sandbox creation flow.

## Step 8 - Deploy

Initialize the Terraform providers (only needed once per machine):

```bash
scripts/terraform.sh init
```

Then deploy the cluster:

```bash
scripts/terraform.sh apply
```

Terraform shows a plan of everything it will create. Review it and type `yes` to confirm. Provisioning typically takes 3–5 minutes.

:::tip
Always run `scripts/terraform.sh`, not `terraform` directly. The script passes your `config/` files to Terraform automatically. Running `terraform` from inside the `Terraform/` directory will not find those files.
:::

After `apply` finishes, Terraform prints the public IP of each node. Watch the bootstrap log on the seed to know when the cluster is ready:

```bash
ssh ubuntu@<seed-ip> sudo tail -f /var/log/aerolvm-bootstrap.log
```

Wait until you see `[bootstrap] complete`. The seed takes a few minutes to start the cluster; other nodes join after the seed finishes and uploads its configuration to S3.

## Step 9 - Verify

Once bootstrap is complete, check that all nodes joined:

```bash
curl -s -H "Authorization: Bearer <your-pat-token>" \
  http://127.0.0.1:21212/v1/cluster/members | jq .
```

A healthy cluster shows every node with `"alive": true`. If a node shows `"alive": false`, SSH into it and check `/var/log/aerolvm-bootstrap.log`.

## Tear down

To delete the entire cluster and all AWS resources:

```bash
scripts/terraform.sh destroy
```

:::caution
This permanently deletes all EC2 instances, VPCs, S3 buckets, and any running sandboxes. There is no undo.
:::

---

For a full reference of the environment variables configured on each node, see the [Cluster Glossary](/cluster-glossary).
