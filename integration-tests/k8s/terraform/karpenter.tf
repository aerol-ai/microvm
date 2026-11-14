# Spike S5 (plans/kubernetes-v2-phase0.md): what Karpenter needs from AWS.
# Only with var.karpenter; cluster.sh installs the chart and the spike
# applies its own EC2NodeClass and NodePool.
#
# Karpenter's nodes use the same node role as the node groups, so the access
# entry EKS made for that role already lets them join. Its controller gets a
# role through EKS Pod Identity. The policy is the spike's: wide on EC2
# within this throwaway account use, narrow on IAM (instance profiles and
# passing the node role only). No interruption queue: S5 does not test spot.

# Also the cell's EBS CSI controller (main.tf): with an IMDS hop limit of 1
# no pod reaches the node role, so it gets a role of its own too.
resource "aws_eks_addon" "pod_identity" {
  count        = var.karpenter || var.ebs_csi ? 1 : 0
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "eks-pod-identity-agent"
}

data "aws_iam_policy_document" "karpenter_assume" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "karpenter" {
  count              = var.karpenter ? 1 : 0
  name               = "${var.name}-karpenter"
  assume_role_policy = data.aws_iam_policy_document.karpenter_assume.json
}

data "aws_iam_policy_document" "karpenter" {
  statement {
    sid = "EC2"
    actions = [
      "ec2:CreateFleet", "ec2:RunInstances", "ec2:CreateLaunchTemplate", "ec2:DeleteLaunchTemplate",
      "ec2:CreateTags", "ec2:TerminateInstances", "ec2:DescribeAvailabilityZones", "ec2:DescribeImages",
      "ec2:DescribeInstances", "ec2:DescribeInstanceTypeOfferings", "ec2:DescribeInstanceTypes",
      "ec2:DescribeLaunchTemplates", "ec2:DescribeSecurityGroups", "ec2:DescribeSpotPriceHistory",
      "ec2:DescribeSubnets", "ec2:DescribeCapacityReservations", "ec2:DescribePlacementGroups",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "PassNodeRole"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.node.arn]
  }
  statement {
    sid = "InstanceProfiles"
    actions = [
      "iam:CreateInstanceProfile", "iam:TagInstanceProfile", "iam:AddRoleToInstanceProfile",
      "iam:RemoveRoleFromInstanceProfile", "iam:DeleteInstanceProfile", "iam:GetInstanceProfile",
      "iam:ListInstanceProfiles",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "Lookups"
    actions   = ["ssm:GetParameter", "pricing:GetProducts", "eks:DescribeCluster"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "karpenter" {
  count  = var.karpenter ? 1 : 0
  name   = "karpenter-controller"
  role   = aws_iam_role.karpenter[0].id
  policy = data.aws_iam_policy_document.karpenter.json
}

resource "aws_eks_pod_identity_association" "karpenter" {
  count           = var.karpenter ? 1 : 0
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "kube-system"
  service_account = "karpenter"
  role_arn        = aws_iam_role.karpenter[0].arn
  depends_on      = [aws_eks_addon.pod_identity]
}
