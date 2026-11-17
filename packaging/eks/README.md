# One-click EKS stack

`aerolvm-eks.yaml` is a CloudFormation template that makes a new EKS cluster
and installs AerolVM in cluster mode on it. The customer docs are
`docs/src/content/docs/kubernetes/eks.mdx` (the "One-click EKS" page).

## What it makes

| Part | Made by | Notes |
|---|---|---|
| VPC, 3 public + 3 private subnets, 1 NAT gateway | CloudFormation | One NAT keeps it cheap; its zone is a single point for outbound traffic. |
| IAM roles: cluster, node, Karpenter, EBS CSI, installer, helper | CloudFormation | Karpenter's role is its reference policy, limited to this cluster's tags; the installer's delete rights are limited the same way. |
| EKS cluster, 3 system machines (managed node group), add-ons, access entries | CloudFormation | IMDSv2 with hop limit 1 everywhere. VPC CNI with network policy on. |
| cert-manager, Karpenter, the worker NodePool, the AerolVM chart | The installer (CodeBuild) | Same steps as `docs/.../kubernetes/production.mdx`. |
| A first gVisor sandbox, then `aerolvm k8s verify` | The installer | The verify result is the `InstallCheck` output. It does not fail the stack. |

## How the installer runs

CloudFormation cannot run helm or kubectl. The `Install` custom resource calls
the `Helper` Lambda, which starts the `<stack>-installer` CodeBuild build and
returns. The build answers CloudFormation itself (`respond` in the script),
because an install takes longer than a Lambda may run. A failed step answers
`FAILED` with the step's name, and prints the cluster's state to the log.

- **Create and Update** run the install path. It is safe to run again:
  everything is `apply` or `helm upgrade --install`. An upgrade is a stack
  update with a new `AerolvmVersion`.
- **Delete** removes AerolVM, then Karpenter's NodePools, then whatever
  Karpenter left: machines, launch templates and instance profiles. None of
  them belong to CloudFormation, and a machine holds its subnet, and an
  instance profile holds the node role.
- **NetworkCleanup** is a second custom resource on the same Lambda. Its
  delete runs after the cluster is gone and before the subnets are. It
  deletes network interfaces left `available` (from the VPC CNI or CodeBuild)
  and EKS's cluster security group if EKS kept it. Either one stops the VPC
  delete. The `DependsOn` lines set that order.

The installer runs in the private subnets and reaches the cluster's private
endpoint. So narrowing `ApiAccessCidr` never locks it out.

## Changing it

- `integration-tests/safety/eks_stack_test.go` checks it offline. It runs
  `bash -n` and shellcheck on the script, and checks that every variable the
  script reads is set somewhere. It also checks that the Karpenter and
  cert-manager pins match the live harness (`integration-tests/k8s`), and
  that the values it writes name real chart settings.
- Also run `cfn-lint packaging/eks/aerolvm-eks.yaml`.
- The template is over CloudFormation's 51,200-byte limit for an inline
  body, so test it from S3 (below).

## Testing it live

It makes real AWS resources: about $1.40 an hour with the defaults in
us-east-1. A create takes about 22 minutes (6 of them the installer), and a delete about 25.

```bash
aws s3 cp packaging/eks/aerolvm-eks.yaml s3://<a bucket you own>/aerolvm-eks.yaml
aws cloudformation create-stack --stack-name aerolvm-test \
  --template-url https://<bucket>.s3.<region>.amazonaws.com/aerolvm-eks.yaml \
  --capabilities CAPABILITY_IAM \
  --parameters ParameterKey=Zones,ParameterValue='us-east-1a\,us-east-1b\,us-east-1c' \
  --tags Key=aerol:purpose,Value=eks-launch-stack Key=aerol:owner,Value=itest \
    Key=aerol:ttl,Value="$(date -u -v+6H +%Y-%m-%dT%H:%M:%SZ)"
aws cloudformation wait stack-create-complete --stack-name aerolvm-test
aws cloudformation describe-stacks --stack-name aerolvm-test --query 'Stacks[0].Outputs'
aws cloudformation delete-stack --stack-name aerolvm-test
```

The installer's log is in CloudWatch, log group `/aerolvm/<stack>/installer`.

## How it ships

`release.yml` copies the template into `dist/` with `AerolvmVersion`'s
default set to the release (the line that ends in `# release-version`). So it
ships as a release file and goes to the download mirror at
`aerolvm/<tag>/aerolvm-eks.yaml`. When the release is GitHub's latest, the
mirror job also writes `aerolvm/latest/aerolvm-eks.yaml`. That is the S3 URL
the docs' "Launch Stack" link uses. CloudFormation reads a template only from
S3, never from a GitHub URL.
