# AOCR Private VPC Routing AWS Checklist

## Status

Ready to execute.

## Goal

Make `aocr.aerol.ai` and `mirror.aocr.aerol.ai` resolve to the AOCR VM's private IP from inside the AerolVM VPC, without changing AerolVM code and without adding an AWS load balancer.

This checklist assumes the cheap phase-1 design:

- AOCR is on one EC2 VM
- Traefik on that VM already terminates TLS for `aocr.aerol.ai` and `mirror.aocr.aerol.ai`
- AerolVM should keep using the same hostnames it already has in `Terraform/terraform.tfvars`

## What does not change

Do not change the AerolVM AOCR config for phase 1:

```hcl
aocr = {
  enabled             = true
  mirror_host         = "mirror.aocr.aerol.ai"
  auto_import_enabled = true
  hooks_url           = "https://aocr.aerol.ai"
}
```

The only change is AWS networking and private DNS.

## Before you start

You need:

1. AWS CLI authenticated with permission to manage VPC, Route53, security groups, and VPC endpoints.
2. The AOCR EC2 instance ID.
3. The AerolVM VPC already deployed from this repo.
4. Public AOCR DNS and TLS already working.

Set this shell environment first:

```bash
set -euo pipefail

export AWS_PROFILE="aerolvm-provisoner"
export AWS_REGION="us-east-1"
```

## Step 1 - Gather live AerolVM values

Run these from the `Terraform/` directory of this repo if the state is present locally:

```bash
cd /Users/sumansaurabh/Documents/startup-3/sandbox-library/Terraform

terraform output nodes
terraform output ssh_command_seed
```

Now gather the live AWS object IDs.

### AerolVM VPC ID and CIDR

```bash
export AEROLVM_VPC_ID=$(aws ec2 describe-vpcs \
  --region "$AWS_REGION" \
  --filters Name=tag:Name,Values=aerolvm-vpc \
  --query 'Vpcs[0].VpcId' \
  --output text)

export AEROLVM_VPC_CIDR=$(aws ec2 describe-vpcs \
  --region "$AWS_REGION" \
  --vpc-ids "$AEROLVM_VPC_ID" \
  --query 'Vpcs[0].CidrBlock' \
  --output text)

echo "$AEROLVM_VPC_ID"
echo "$AEROLVM_VPC_CIDR"
```

### AerolVM node security group

```bash
export AEROLVM_NODE_SG_ID=$(aws ec2 describe-security-groups \
  --region "$AWS_REGION" \
  --filters Name=group-name,Values=aerolvm-node \
  --query 'SecurityGroups[0].GroupId' \
  --output text)

echo "$AEROLVM_NODE_SG_ID"
```

## Step 2 - Gather live AOCR values

Set the AOCR instance ID manually, then resolve the rest from AWS.

```bash
export AOCR_INSTANCE_ID="i-REPLACE_ME"
```

```bash
export AOCR_PRIVATE_IP=$(aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --instance-ids "$AOCR_INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PrivateIpAddress' \
  --output text)

export AOCR_VPC_ID=$(aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --instance-ids "$AOCR_INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].VpcId' \
  --output text)

export AOCR_SUBNET_ID=$(aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --instance-ids "$AOCR_INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].SubnetId' \
  --output text)

export AOCR_SG_ID=$(aws ec2 describe-instances \
  --region "$AWS_REGION" \
  --instance-ids "$AOCR_INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' \
  --output text)

echo "$AOCR_PRIVATE_IP"
echo "$AOCR_VPC_ID"
echo "$AOCR_SUBNET_ID"
echo "$AOCR_SG_ID"
```

## Step 3 - Check whether AOCR is in the same VPC

```bash
echo "AerolVM VPC: $AEROLVM_VPC_ID"
echo "AOCR VPC:    $AOCR_VPC_ID"
```

If the VPC IDs match, continue to Step 4.

If they do not match, do Step 3A first.

## Step 3A - If AOCR is in a different VPC, add VPC peering first

Gather the route table IDs you need on both sides.

```bash
export AEROLVM_ROUTE_TABLE_ID=$(aws ec2 describe-route-tables \
  --region "$AWS_REGION" \
  --filters Name=tag:Name,Values=aerolvm-public \
  --query 'RouteTables[0].RouteTableId' \
  --output text)

export AOCR_ROUTE_TABLE_ID=$(aws ec2 describe-route-tables \
  --region "$AWS_REGION" \
  --filters Name=association.subnet-id,Values="$AOCR_SUBNET_ID" \
  --query 'RouteTables[0].RouteTableId' \
  --output text)

echo "$AEROLVM_ROUTE_TABLE_ID"
echo "$AOCR_ROUTE_TABLE_ID"
```

Create and accept peering:

```bash
export PEERING_ID=$(aws ec2 create-vpc-peering-connection \
  --region "$AWS_REGION" \
  --vpc-id "$AEROLVM_VPC_ID" \
  --peer-vpc-id "$AOCR_VPC_ID" \
  --tag-specifications 'ResourceType=vpc-peering-connection,Tags=[{Key=Name,Value=aerolvm-aocr-peering}]' \
  --query 'VpcPeeringConnection.VpcPeeringConnectionId' \
  --output text)

aws ec2 accept-vpc-peering-connection \
  --region "$AWS_REGION" \
  --vpc-peering-connection-id "$PEERING_ID"

echo "$PEERING_ID"
```

Add routes both ways:

```bash
export AOCR_VPC_CIDR=$(aws ec2 describe-vpcs \
  --region "$AWS_REGION" \
  --vpc-ids "$AOCR_VPC_ID" \
  --query 'Vpcs[0].CidrBlock' \
  --output text)

aws ec2 create-route \
  --region "$AWS_REGION" \
  --route-table-id "$AEROLVM_ROUTE_TABLE_ID" \
  --destination-cidr-block "$AOCR_VPC_CIDR" \
  --vpc-peering-connection-id "$PEERING_ID"

aws ec2 create-route \
  --region "$AWS_REGION" \
  --route-table-id "$AOCR_ROUTE_TABLE_ID" \
  --destination-cidr-block "$AEROLVM_VPC_CIDR" \
  --vpc-peering-connection-id "$PEERING_ID"
```

After this, continue to Step 4.

## Step 4 - Verify current public AOCR still works

Run this before introducing private DNS so you know the baseline is healthy.

```bash
curl -I https://aocr.aerol.ai/v2/
curl -I https://mirror.aocr.aerol.ai/v2/
```

Expected:

- both return `401 Unauthorized`

That is a healthy registry challenge response.

## Step 5 - Check certificate issuance mode on AOCR

SSH to the AOCR VM and inspect the issuer.

```bash
ssh ubuntu@<AOCR_PUBLIC_IP_OR_BASTION_PATH> \
  'sudo kubectl get clusterissuer letsencrypt-prod -o yaml'
```

Interpretation:

- if you see `http01`, do not shut off public `80` yet
- if you see `dns01`, public `80` is not needed for future cert issuance

This step is only about future hardening. It does not block private DNS.

## Step 6 - Create the Route53 private hosted zone

Create a private zone only for `aocr.aerol.ai`. Do not create a private zone for the entire `aerol.ai` parent unless you intentionally want to shadow every record under that domain.

```bash
export AOCR_PRIVATE_ZONE_ID=$(aws route53 create-hosted-zone \
  --profile "$AWS_PROFILE" \
  --name aocr.aerol.ai \
  --caller-reference "aocr-private-$(date +%s)" \
  --hosted-zone-config Comment="Private AOCR routing for AerolVM",PrivateZone=true \
  --vpc VPCRegion="$AWS_REGION",VPCId="$AEROLVM_VPC_ID" \
  --query 'HostedZone.Id' \
  --output text | awk -F/ '{print $NF}')

echo "$AOCR_PRIVATE_ZONE_ID"
```

If the private zone already exists, use this instead:

```bash
export AOCR_PRIVATE_ZONE_ID=$(aws route53 list-hosted-zones-by-name \
  --profile "$AWS_PROFILE" \
  --dns-name aocr.aerol.ai \
  --query 'HostedZones[?Config.PrivateZone==`true` && Name==`aocr.aerol.ai.`][0].Id' \
  --output text | awk -F/ '{print $NF}')

echo "$AOCR_PRIVATE_ZONE_ID"
```

## Step 7 - Add private Route53 records

Create a temporary change batch:

```bash
cat > /tmp/aocr-private-records.json <<EOF
{
  "Comment": "Private AOCR records for AerolVM",
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "aocr.aerol.ai.",
        "Type": "A",
        "TTL": 60,
        "ResourceRecords": [{"Value": "$AOCR_PRIVATE_IP"}]
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "mirror.aocr.aerol.ai.",
        "Type": "A",
        "TTL": 60,
        "ResourceRecords": [{"Value": "$AOCR_PRIVATE_IP"}]
      }
    }
  ]
}
EOF
```

Apply it:

```bash
aws route53 change-resource-record-sets \
  --profile "$AWS_PROFILE" \
  --hosted-zone-id "$AOCR_PRIVATE_ZONE_ID" \
  --change-batch file:///tmp/aocr-private-records.json
```

## Step 8 - Open AOCR inbound `443` for AerolVM private traffic

If AOCR is in the same VPC, prefer a source security-group rule.

### Same-VPC preferred rule

```bash
aws ec2 authorize-security-group-ingress \
  --region "$AWS_REGION" \
  --group-id "$AOCR_SG_ID" \
  --ip-permissions "IpProtocol=tcp,FromPort=443,ToPort=443,UserIdGroupPairs=[{GroupId=$AEROLVM_NODE_SG_ID}]"
```

### Different-VPC or if SG referencing is not possible

```bash
aws ec2 authorize-security-group-ingress \
  --region "$AWS_REGION" \
  --group-id "$AOCR_SG_ID" \
  --protocol tcp \
  --port 443 \
  --cidr "$AEROLVM_VPC_CIDR"
```

Do not revoke public `443` or public `80` yet. First prove the private path works.

## Step 9 - Add an S3 Gateway Endpoint in the AOCR VPC

Gather the AOCR subnet route table if you have not already:

```bash
export AOCR_ROUTE_TABLE_ID=$(aws ec2 describe-route-tables \
  --region "$AWS_REGION" \
  --filters Name=association.subnet-id,Values="$AOCR_SUBNET_ID" \
  --query 'RouteTables[0].RouteTableId' \
  --output text)

echo "$AOCR_ROUTE_TABLE_ID"
```

Create the S3 Gateway Endpoint:

```bash
aws ec2 create-vpc-endpoint \
  --region "$AWS_REGION" \
  --vpc-id "$AOCR_VPC_ID" \
  --service-name "com.amazonaws.$AWS_REGION.s3" \
  --vpc-endpoint-type Gateway \
  --route-table-ids "$AOCR_ROUTE_TABLE_ID" \
  --tag-specifications 'ResourceType=vpc-endpoint,Tags=[{Key=Name,Value=aocr-s3-endpoint}]'
```

Verify it exists:

```bash
aws ec2 describe-vpc-endpoints \
  --region "$AWS_REGION" \
  --filters Name=vpc-id,Values="$AOCR_VPC_ID" Name=service-name,Values="com.amazonaws.$AWS_REGION.s3" \
  --query 'VpcEndpoints[].{VpcEndpointId:VpcEndpointId,State:State,VpcId:VpcId}'
```

## Step 10 - Validate from an AerolVM node

SSH to the seed or any worker node.

If you have local Terraform state for the cluster, get the seed SSH command with:

```bash
cd /Users/sumansaurabh/Documents/startup-3/sandbox-library/Terraform
terraform output -raw ssh_command_seed
```

On the AerolVM node, run:

```bash
getent hosts aocr.aerol.ai
getent hosts mirror.aocr.aerol.ai

curl -I https://aocr.aerol.ai/v2/
curl -I https://mirror.aocr.aerol.ai/v2/

sudo cat /etc/docker/daemon.json
sudo grep -E '^SB_(MIRROR|AUTO_IMPORT)_' /etc/sandboxd/cluster.env

docker pull alpine:3.20
```

Expected:

1. `getent hosts` returns the AOCR private IP
2. both `curl -I` calls return `401 Unauthorized`
3. Docker daemon.json still points at `https://mirror.aocr.aerol.ai`
4. the `alpine` pull succeeds

## Step 11 - Validate a non-Docker-Hub pull and auto-import

Trigger a pull that uses the AerolVM mirror rewrite path, for example via a sandbox using one of:

- `ghcr.io/...`
- `gcr.io/...`
- `quay.io/...`
- `registry.k8s.io/...`

Then confirm AOCR still receives auto-import traffic for private pulls.

At minimum, verify on the AerolVM node that:

```bash
sudo grep -E '^SB_AUTO_IMPORT_HOOKS_URL=' /etc/sandboxd/cluster.env
```

Expected:

- it still points at `https://aocr.aerol.ai`
- the name now resolves privately inside the VPC

## Step 12 - Only after success, optionally reduce public exposure

After all private-path validation passes, you can decide whether to tighten the public side.

Safe sequence:

1. narrow AOCR mirror ingress allow-lists from `0.0.0.0/0`
2. keep public `80` if cert issuance still uses HTTP-01
3. only remove public `443` if operator access has another path and cert issuance is not relying on public ingress

## Rollback

If anything fails, revert in this order:

1. delete the two private Route53 records from the private hosted zone
2. or disassociate/delete the private hosted zone entirely
3. remove the new AOCR SG ingress rule if needed
4. leave the AerolVM `aocr` block untouched

Because AerolVM still points at the same public hostnames, removing the private DNS overlay returns it to the old public path.

## End state

When this checklist is complete:

1. AerolVM nodes still use `mirror.aocr.aerol.ai` and `aocr.aerol.ai`
2. inside the VPC, those names resolve to the AOCR private IP
3. Docker and sandboxd continue to work without code changes
4. AOCR-to-S3 traffic uses an AWS private path
5. no AWS load balancer is involved