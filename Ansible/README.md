# AerolVM cluster — Ansible

Day-N operations against the cluster that `../Terraform` provisions. Terraform
owns infra (VPC, EC2, SG, DNS); Ansible owns "push a new binary, restart a
service, tail logs across all nodes."

## Prereqs

- Ansible ≥ 2.15 (`pipx install ansible-core` or `brew install ansible`)
- `boto3` + `botocore` reachable from **Ansible's Python** (see install note below)
- AWS credentials in the default chain (env, profile, instance role) with
  `ec2:DescribeInstances` — that's all the inventory plugin needs
- The same SSH private key Terraform installed on the nodes (default:
  `~/.ssh/id_rsa`; change in `ansible.cfg` if you use a different one)

### One-time install

```bash
cd Ansible

# Install Ansible collections this repo depends on.
ansible-galaxy collection install -r requirements.yml

# Install boto3 / botocore for the dynamic EC2 inventory. The right command
# depends on how Ansible itself was installed:
#
#   - pipx (recommended):    pipx inject ansible-core boto3 botocore
#   - brew install ansible:  brew installs them as part of the formula — skip
#   - system pip / venv:     pip install boto3 botocore  (into the SAME env
#                            that owns the `ansible` binary)
#
# If you `pip install boto3` into your base/conda env while Ansible lives in
# a pipx venv, Ansible won't see it and `ansible-inventory --graph` will fail
# with "Failed to import the required Python library (botocore and boto3)".
pipx inject ansible-core boto3 botocore

# Load your SSH key into the agent (per session, no config edit needed).
ssh-add ~/.ssh/your-aws-key.pem

# Point at your cluster (defaults: cluster=aerolvm, region=us-east-1).
export AEROLVM_CLUSTER=aerolvm
export AEROLVM_REGION=us-east-1
export AWS_PROFILE=default            # if you use named profiles
```

Smoke test:

```bash
ansible-inventory --graph        # should list your EC2 nodes grouped by tag
ansible-playbook playbooks/ping.yml
```

## Inventory

`inventory/aws_ec2.yml` is a dynamic inventory plugin — it queries EC2 every
time you run a playbook. It filters by the `Cluster` tag (default `aerolvm`,
matches `var.cluster_name` in Terraform) in `us-east-1`. Override either via
environment variables:

```bash
export AEROLVM_CLUSTER=prod
export AEROLVM_REGION=us-west-2
ansible-inventory --graph
```

You'll get groups for free, derived from the tags Terraform sets:

```
@all:
  |--@aerolvm_role_server:        # Role=server
  |--@aerolvm_role_worker:        # Role=worker
  |--@aerolvm_role_ingress:       # Role=ingress
  |--@aerolvm_role_worker_ingress # Role=worker,ingress (comma → underscore)
  |--@aerolvm_role_mixed:         # Role=mixed
  |--@aerolvm_true:               # Seed=true (exactly one node)
  |--@aerolvm_false:              # Seed=false
```

Target any group with `--limit`:

```bash
ansible-playbook playbooks/update-sandboxd.yml --limit aerolvm_role_worker -e ...
```

## Common playbooks

```bash
# Reachability check (run this first to verify SSH + sudo work):
ansible-playbook playbooks/ping.yml

# Push the LATEST released sandboxd binary across the fleet (most common):
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_remote_url=https://github.com/aerol-ai/microvm/releases/latest/download/sandboxd_linux_amd64

# arm64 / Graviton nodes:
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_remote_url=https://github.com/aerol-ai/microvm/releases/latest/download/sandboxd_linux_arm64

# Pin to a specific release instead of "latest":
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_remote_url=https://github.com/aerol-ai/microvm/releases/download/v0.2.2/sandboxd_linux_amd64

# Push a locally-built binary (dev loop):
make -C .. build-sandboxd
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_local_binary=../bin/sandboxd

# Tail recent sandboxd logs from every node:
ansible-playbook playbooks/tail-logs.yml -e lines=200

# Configure OTEL/image-pull hardening and deploy backup/recovery,
# Grafana, Prometheus, Alertmanager, and runbook artifacts:
ansible-playbook playbooks/configure-ops.yml \
  -e sandboxd_otel_metrics_endpoint=http://otel-collector:4318/v1/metrics \
  -e sandboxd_backup_enabled=true
```

`update-sandboxd.yml` runs `serial: 1` — one host at a time, with
`any_errors_fatal: true` — so a failed health check on node 1 stops the
rollout before it touches the Raft quorum. Limit to a single non-seed test
node first (use a hostname from `ansible-inventory --graph`, e.g. one that
shows up under `@aerolvm_false`):

```bash
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_remote_url=https://github.com/aerol-ai/microvm/releases/latest/download/sandboxd_linux_amd64 \
  --limit aerolvm-node3
```

Release asset names come from `.github/workflows/release.yml` and follow
`sandboxd_<goos>_<goarch>` — `linux_amd64`, `linux_arm64`, `linux_armv7`,
`linux_armv6`, `linux_386`, `freebsd_amd64`, `darwin_arm64`, etc.

## Per-machine config

`ansible.cfg` is committed — your SSH key path, AWS profile, region, and
cluster name are per-machine and don't belong in it. Use:

- `ssh-add ~/.ssh/<your-key>.pem` for the key (persist on macOS with
  `ssh-add --apple-use-keychain`). Once loaded, `ansible-playbook` picks it
  up via the agent — no `--private-key` flag, no config edit.
- `AEROLVM_CLUSTER`, `AEROLVM_REGION`, `AWS_PROFILE` env vars for cluster
  selection (the dynamic inventory reads these directly).
- `Ansible/ansible.local.cfg` (gitignored) + `ANSIBLE_CONFIG=$PWD/Ansible/ansible.local.cfg`
  if you genuinely need to override `ansible.cfg` settings locally.

## Layout

```
ansible.cfg            # forks, ssh args, default inventory + remote_user
requirements.yml       # collections to install
inventory/
  aws_ec2.yml          # dynamic inventory (EC2 → hosts/groups via tags)
  group_vars/all.yml   # binary path, service name, health URL defaults
                       # (must live next to the inventory; Ansible auto-loads
                       # group_vars only from inventory/ or playbooks/, not
                       # from the repo root)
playbooks/
  ping.yml             # connectivity smoke test
  update-sandboxd.yml  # rolling binary push + restart + healthcheck
  configure-ops.yml    # OTEL env, image-pull knobs, ops alert/dashboard/runbook files
  tail-logs.yml        # journalctl across the fleet
```

## When to use this vs. Terraform

| You want to...                                  | Use         |
|-------------------------------------------------|-------------|
| Add / remove / resize nodes                     | Terraform   |
| Change SG rules, DNS, AMI                       | Terraform   |
| Push a new `sandboxd` binary                    | Ansible     |
| Change OTEL/image-pull env on running nodes     | Ansible     |
| Deploy backup/recovery helpers or backup cron   | Ansible     |
| Deploy Grafana/Prometheus/Alertmanager artifacts | Ansible     |
| Deploy operational runbooks                     | Ansible     |
| Restart a service, rotate a PAT, tail logs      | Ansible     |
| Run one-off shell commands across many nodes    | Ansible     |

Terraform's `user_data` only runs at instance launch — it can't update an
already-running node. That's what this folder exists for.
