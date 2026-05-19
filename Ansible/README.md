# AerolVM cluster — Ansible

Day-N operations against the cluster that `../Terraform` provisions. Terraform
owns infra (VPC, EC2, SG, DNS); Ansible owns "push a new binary, restart a
service, tail logs across all nodes."

## Prereqs

- Ansible ≥ 2.15 (`pipx install ansible-core` or `brew install ansible`)
- Python 3 with `boto3` + `botocore` on the control machine (`pip install boto3 botocore`)
- AWS credentials in the default chain (env, profile, instance role) with
  `ec2:DescribeInstances` — that's all the inventory plugin needs
- The same SSH private key Terraform installed on the nodes (default:
  `~/.ssh/id_rsa`; change in `ansible.cfg` if you use a different one)

Install Ansible collections once:

```bash
cd Ansible
ansible-galaxy collection install -r requirements.yml
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

# Push a locally-built sandboxd binary cluster-wide, one node at a time,
# verifying /healthz between restarts:
make -C .. build-sandboxd
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_local_binary=../bin/sandboxd

# Or pull a released binary from GitHub:
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_remote_url=https://github.com/aerol-ai/microvm/releases/download/v0.2.2/sandboxd_linux_amd64

# Tail recent sandboxd logs from every node:
ansible-playbook playbooks/tail-logs.yml -e lines=200
```

`update-sandboxd.yml` runs `serial: 1` — one host at a time, with
`any_errors_fatal: true` — so a failed health check on node 1 stops the
rollout before it touches the Raft quorum. Limit to a single test node first:

```bash
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_local_binary=../bin/sandboxd \
  --limit aerolvm-srv1
```

## Development practices

**Load your SSH key into the agent once per session** instead of editing
`ansible.cfg` with your key path (the config is committed; your key path is
per-machine and shouldn't be):

```bash
ssh-add ~/.ssh/suman-saurabh-aws.pem
# On macOS, persist across reboots via the Keychain:
# ssh-add --apple-use-keychain ~/.ssh/suman-saurabh-aws.pem
```

Once the agent has the key, `ssh`, `scp`, `git`, and `ansible-playbook` all
pick it up automatically — no `--private-key` flag, no config edit.

Anything else that varies between contributors' machines (AWS profile, region,
cluster name) belongs in your shell env — never in a tracked file:

```bash
export AEROLVM_CLUSTER=aerolvm        # matches var.cluster_name in Terraform
export AEROLVM_REGION=us-east-1
export AWS_PROFILE=default            # if you use named profiles
```

If you really need a local config override, create
`Ansible/ansible.local.cfg` (gitignored) and run with
`ANSIBLE_CONFIG=$PWD/Ansible/ansible.local.cfg ansible-playbook ...`.

## Layout

```
ansible.cfg            # forks, ssh args, default inventory + remote_user
requirements.yml       # collections to install
inventory/aws_ec2.yml  # dynamic inventory (EC2 → hosts/groups via tags)
group_vars/all.yml     # binary path, service name, health URL defaults
playbooks/
  ping.yml             # connectivity smoke test
  update-sandboxd.yml  # rolling binary push + restart + healthcheck
  tail-logs.yml        # journalctl across the fleet
```

## When to use this vs. Terraform

| You want to...                                  | Use         |
|-------------------------------------------------|-------------|
| Add / remove / resize nodes                     | Terraform   |
| Change SG rules, DNS, AMI                       | Terraform   |
| Push a new `sandboxd` binary                    | Ansible     |
| Restart a service, rotate a PAT, tail logs      | Ansible     |
| Run one-off shell commands across many nodes    | Ansible     |

Terraform's `user_data` only runs at instance launch — it can't update an
already-running node. That's what this folder exists for.
