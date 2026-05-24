# AOCR Private VPC Routing: Exact AWS Implementation

## Status

Draft - implementation-ready runbook.

## Scope

This file turns the higher-level design in `plans/aocr-vpc-private-routing.md` into an exact AWS implementation plan.

It is written for the current setup visible in this repo:

- AerolVM region: `us-east-1`
- AerolVM AOCR endpoints in `Terraform/terraform.tfvars`:
  - `mirror_host = "mirror.aocr.aerol.ai"`
  - `hooks_url = "https://aocr.aerol.ai"`
- AerolVM Terraform defaults to a single VPC with tag `aerolvm-vpc` and one node security group named `aerolvm-node` when `cluster_name` is left at default.
- AOCR is deployed separately via `aocr.sh` onto k3s with Traefik ingress and TLS enabled.

The goal is not to redesign AOCR. The goal is to keep the current hostnames and make AerolVM reach them privately inside AWS.

## Executive decision

Implement this exact topology first:

1. Keep using `aocr.aerol.ai` and `mirror.aocr.aerol.ai`.
2. Keep HTTPS on both names.
3. Add a Route53 Private Hosted Zone for `aocr.aerol.ai` and associate it with the AerolVM VPC.
4. Add private Route53 records:
  - `aocr.aerol.ai` -> AOCR VM private IP
  - `mirror.aocr.aerol.ai` -> AOCR VM private IP
5. Restrict AOCR inbound `443` to the AerolVM VPC CIDR or AerolVM node security group.
6. Add an S3 Gateway VPC Endpoint in the AOCR VPC so AOCR-to-S3 stays private.
7. Do not change the AerolVM `aocr` block for phase 1.

This gives you private AerolVM-to-AOCR traffic with no AerolVM code change.

No AWS load balancer is required for this phase-1 setup.

## Why this exact approach is correct for this repo

Current AerolVM behavior:

- `Terraform/templates/bootstrap.sh.tftpl` writes Docker Hub mirror config as `https://<mirror_host>`.
- `pkg/docker/mirror_rewrite.go` rewrites supported public registries onto `SB_MIRROR_HOST`.
- `internal/service/auto_import.go` POSTs imports to `SB_AUTO_IMPORT_HOOKS_URL`.

That means:

- the hostnames are already configuration-driven
- the transport already expects HTTPS
- nothing in AerolVM requires the AOCR hostnames to be public

The cleanest implementation is therefore private DNS plus private AWS routing, not a rewrite of AerolVM logic.

## Assumptions

This runbook assumes the recommended phase-1 topology:

- AOCR runs on EC2 in AWS.
- AOCR is reachable on its EC2 private IP inside either:
  - the same VPC as AerolVM, or
  - a peered VPC.
- AOCR continues to serve valid TLS certs for `aocr.aerol.ai` and `mirror.aocr.aerol.ai`.
- Public Cloudflare DNS for those names may remain in place for operator access and certificate issuance.

If AOCR is not on EC2, or not in AWS, use this file as the reference architecture but substitute the private target for your platform.

## Current AWS objects on the AerolVM side

From the Terraform in this repo:

- VPC tag: `${cluster_name}-vpc` -> default `aerolvm-vpc`
- subnet tag: `${cluster_name}-public` -> default `aerolvm-public`
- node security group: `${cluster_name}-node` -> default `aerolvm-node`
- default VPC CIDR when not overridden: `10.42.0.0/16`
- default subnet CIDR when not overridden: `10.42.1.0/24`

Your current `terraform.tfvars` does not override `vpc_cidr` or `subnet_cidr`, so unless the state was created with different values earlier, the working assumption is:

- AerolVM VPC CIDR: `10.42.0.0/16`

## Phase 0 - Gather exact live values

Run these before changing anything.

### AerolVM VPC and SG

```bash
aws ec2 describe-vpcs \
  --region us-east-1 \
  --filters Name=tag:Name,Values=aerolvm-vpc \
  --query 'Vpcs[0].{VpcId:VpcId,Cidr:CidrBlock}'

aws ec2 describe-security-groups \
  --region us-east-1 \
  --filters Name=group-name,Values=aerolvm-node \
  --query 'SecurityGroups[0].{GroupId:GroupId,VpcId:VpcId}'
```

### AerolVM route table for the public subnet

```bash
aws ec2 describe-route-tables \
  --region us-east-1 \
  --filters Name=tag:Name,Values=aerolvm-public \
  --query 'RouteTables[].{RouteTableId:RouteTableId,VpcId:VpcId}'
```

### AOCR instance private IP

Collect this:

1. AOCR EC2 private IP if Traefik on the AOCR VM terminates TLS directly.

You will use that value as the Route53 private target.

An internal NLB is not part of this runbook. If you ever add one later, treat that as an optional phase-2 hardening step.

### AOCR VPC and AOCR subnet route tables

If AOCR is in AWS, gather:

```bash
aws ec2 describe-instances \
  --region us-east-1 \
  --instance-ids <AOCR_INSTANCE_ID> \
  --query 'Reservations[0].Instances[0].{PrivateIp:PrivateIpAddress,VpcId:VpcId,SubnetId:SubnetId,SecurityGroups:SecurityGroups}'

aws ec2 describe-route-tables \
  --region us-east-1 \
  --filters Name=association.subnet-id,Values=<AOCR_SUBNET_ID> \
  --query 'RouteTables[].RouteTableId'
```

## Phase 1 - Same-VPC implementation

This is the preferred implementation if AOCR and AerolVM are already in the same VPC.

## Step 1 - Create a Route53 Private Hosted Zone for `aocr.aerol.ai`

Create a separate AWS infra stack for this. Do not put it in the AerolVM Terraform unless you want AOCR-private routing to become part of cluster lifecycle.

Use this Terraform as the baseline:

```hcl
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = "us-east-1"
  profile = "aerolvm-provisoner"
}

data "aws_vpc" "aerolvm" {
  filter {
    name   = "tag:Name"
    values = ["aerolvm-vpc"]
  }
}

resource "aws_route53_zone" "aocr_private" {
  name = "aocr.aerol.ai"

  vpc {
    vpc_id = data.aws_vpc.aerolvm.id
  }
}
```

Why the zone name is `aocr.aerol.ai` instead of `aerol.ai`:

- you only need to override the AOCR surfaces
- it avoids accidentally shadowing unrelated names under `aerol.ai`
- it keeps the split-horizon footprint narrow

## Step 2 - Add private DNS records

Use A records to the AOCR VM private IP:

```hcl
variable "aocr_private_ip" {
  type = string
}

resource "aws_route53_record" "aocr_apex" {
  zone_id = aws_route53_zone.aocr_private.zone_id
  name    = "aocr.aerol.ai"
  type    = "A"
  ttl     = 60
  records = [var.aocr_private_ip]
}

resource "aws_route53_record" "aocr_mirror" {
  zone_id = aws_route53_zone.aocr_private.zone_id
  name    = "mirror.aocr.aerol.ai"
  type    = "A"
  ttl     = 60
  records = [var.aocr_private_ip]
}
```

## Step 3 - Lock down AOCR ingress security group

At minimum, AOCR needs private HTTPS from AerolVM.

Recommended inbound rules on the AOCR security group:

1. `443/tcp` from AerolVM VPC CIDR `10.42.0.0/16`.
2. `80/tcp` only if your current cert-manager flow still depends on HTTP-01.
3. Public `443/tcp` only if you still want public/operator access.

Exact Terraform baseline:

```hcl
variable "aocr_security_group_id" {
  type = string
}

variable "aerolvm_vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

resource "aws_security_group_rule" "aocr_https_from_aerolvm" {
  type              = "ingress"
  security_group_id = var.aocr_security_group_id
  protocol          = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_blocks       = [var.aerolvm_vpc_cidr]
  description       = "Private HTTPS from AerolVM nodes"
}
```

If AOCR is in the same VPC and you want tighter control, replace the CIDR rule with a source security-group rule referencing the AerolVM node SG.

## Step 4 - Add an S3 Gateway Endpoint in the AOCR VPC

This is required if you want AOCR-to-S3 traffic to stay on the AWS private path.

If AOCR is in the same VPC as AerolVM, add the endpoint to that VPC. If AOCR is in a different VPC, add it there instead.

```hcl
variable "aocr_vpc_id" {
  type = string
}

variable "aocr_route_table_ids" {
  type = list(string)
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = var.aocr_vpc_id
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.aocr_route_table_ids

  tags = {
    Name = "aocr-s3-endpoint"
  }
}
```

Attach the endpoint to the route tables that serve the AOCR subnets, not just the AerolVM subnet.

## Step 5 - Leave the AerolVM `aocr` block unchanged

Do not change these phase-1 values:

```hcl
aocr = {
  enabled             = true
  mirror_host         = "mirror.aocr.aerol.ai"
  auto_import_enabled = true
  hooks_url           = "https://aocr.aerol.ai"
}
```

Reason:

- once Route53 private DNS is in place, AerolVM instances in the VPC will resolve these names privately automatically
- Docker and sandboxd will continue using the same hostnames
- public DNS stays available outside the VPC if you keep it

## Phase 2 - Different-VPC implementation

Use this if AOCR is in a separate VPC.

## Step 1 - Add VPC peering

Terraform baseline:

```hcl
resource "aws_vpc_peering_connection" "aerolvm_to_aocr" {
  vpc_id      = var.aerolvm_vpc_id
  peer_vpc_id = var.aocr_vpc_id
  auto_accept = true

  tags = {
    Name = "aerolvm-aocr-peering"
  }
}
```

## Step 2 - Add routes on both sides

```hcl
resource "aws_route" "aerolvm_to_aocr" {
  for_each                  = toset(var.aerolvm_route_table_ids)
  route_table_id            = each.value
  destination_cidr_block    = var.aocr_vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.aerolvm_to_aocr.id
}

resource "aws_route" "aocr_to_aerolvm" {
  for_each                  = toset(var.aocr_route_table_ids)
  route_table_id            = each.value
  destination_cidr_block    = var.aerolvm_vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.aerolvm_to_aocr.id
}
```

## Step 3 - Associate the Route53 private hosted zone with the AerolVM VPC

Keep the zone associated with the AerolVM VPC because that is where the private DNS override is needed. If the zone lives in the AOCR account and the VPC lives in a different account, use `aws_route53_vpc_association_authorization` plus `aws_route53_zone_association`.

## Step 4 - Open AOCR security group only to AerolVM VPC CIDR

Because security-group-to-security-group referencing does not work across peering the same way it does within a single VPC, use CIDR-based rules across the peering boundary.

## Phase 3 - TLS handling

## Recommended implementation

Keep the existing public certs on `aocr.aerol.ai` and `mirror.aocr.aerol.ai`.

That means:

- AerolVM nodes keep trusting the mirror with no CA changes
- the AOCR cert works on both the public and private path
- Docker does not need `insecure-registries`

## Important check before tightening public access

Find out whether the current cert-manager issuer behind `letsencrypt-prod` uses:

1. HTTP-01
2. DNS-01

If it uses HTTP-01:

- keep public `80/443` and public Cloudflare records until cert issuance is migrated

If it uses DNS-01:

- AOCR can become private-only later without breaking cert issuance

## Do not do this in phase 1

Do not switch to a private CA in phase 1.

Why:

- the AerolVM bootstrap does not currently install an AOCR-specific CA into the node trust store
- Docker mirror trust would break until that bootstrap work exists

## Validation checklist

Run these from an AerolVM node after private DNS is in place.

### DNS resolution

```bash
dig +short aocr.aerol.ai
dig +short mirror.aocr.aerol.ai
```

Expected:

- both return the AOCR private IP, not public IPs

### TLS and registry challenge

```bash
curl -I https://aocr.aerol.ai/v2/
curl -I https://mirror.aocr.aerol.ai/v2/
```

Expected:

- `401 Unauthorized` is healthy for the registry challenge path

### Docker Hub path

```bash
sudo cat /etc/docker/daemon.json
docker pull alpine:3.20
```

Expected:

- `registry-mirrors` still points at `https://mirror.aocr.aerol.ai`
- the pull succeeds

### Non-Hub mirror path

Trigger a sandbox or manual pull that goes through the AerolVM mirror rewrite path for `ghcr.io`, `gcr.io`, `quay.io`, or `registry.k8s.io`.

### Auto-import path

Verify AOCR still receives:

- `POST https://aocr.aerol.ai/v1/internal/imports`

and that the call completes successfully.

### AWS network validation

1. Use VPC Flow Logs to confirm AerolVM-to-AOCR traffic stays private.
2. Use Reachability Analyzer if security groups or route tables are unclear.
3. Confirm AOCR route tables now contain the S3 endpoint target.

## Exact rollout order

1. Gather AerolVM VPC ID, SG ID, and AOCR private IP.
2. Create the Route53 private hosted zone for `aocr.aerol.ai`.
3. Create private records for `aocr.aerol.ai` and `mirror.aocr.aerol.ai`.
4. Add or tighten AOCR security-group rules for private `443`.
5. Add the S3 Gateway Endpoint in the AOCR VPC.
6. Validate DNS from one AerolVM node.
7. Validate HTTPS and registry challenge.
8. Validate `docker pull alpine`.
9. Validate one rewritten non-Hub pull.
10. Validate auto-import.
11. Only then decide whether to reduce or remove public AOCR exposure.

## Rollback plan

If anything fails:

1. Delete or disassociate the Route53 private hosted zone.
2. Revert any tightened AOCR security-group rules.
3. Leave the AerolVM `aocr` block unchanged; it already points to the public names.

Because the private routing is DNS-overlay based, rollback is fast and does not require AerolVM node replacement.

## Optional phase-2 hardening

After phase 1 is stable, you can harden further:

1. Move AOCR behind an internal NLB instead of a single VM private IP if budget and HA requirements later justify it.
2. Migrate cert-manager to DNS-01 if it is still on HTTP-01.
3. Remove public `443` from AOCR if operator access can be moved to VPN, SSM, or bastion.
4. Narrow AOCR mirror allow-lists from `0.0.0.0/0` to only the AerolVM VPC CIDR or known VPC ranges.

## Final recommendation

For your current setup, the exact AWS move is:

1. Add a private Route53 zone for `aocr.aerol.ai`.
2. Point `aocr.aerol.ai` and `mirror.aocr.aerol.ai` to AOCR's private address.
3. Restrict AOCR `443` to the AerolVM network.
4. Add an S3 Gateway Endpoint in the AOCR VPC.
5. Keep the current AerolVM AOCR config unchanged.

That is the smallest-change, lowest-risk path to making AOCR traffic private over AWS VPC networking.