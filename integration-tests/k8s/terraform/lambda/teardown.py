"""The run's teardown timer (../teardown.tf): AWS calls this at the run's
TTL, so a dead laptop or session cannot leave the cluster's machines
running. EventBridge Scheduler invokes it with {"phase": ...}:

  scale-cap  the 60-worker step's time box ran out (eks-bank.sh scale makes
             this schedule): Karpenter loses its EC2 rights, and every
             machine it made for this run is terminated.
  compute    the run's TTL: scale-cap, then every node group deleted and
             every load balancer the AWS Load Balancer Controller made for
             this cluster deleted. Compute and load balancers are nearly all
             of the cost.
  cluster    30 minutes later: compute again (idempotent), then the EKS
             cluster itself once its node groups are gone, and the
             unattached volumes the run's claims left (tagged aerol:run).

Karpenter may still be launching a machine when it loses its rights: the
machines are ended twice, SECOND_SWEEP_DELAY (60) seconds apart.

Machines, load balancers and volumes must carry this run's TTL (the TTL
environment variable) as well as its name: an older run's leftovers of the
same name are reap.sh's to judge, by their own TTL, not this run's.

What is left (the VPC, subnets, IAM, the audit buckets) costs nothing; reap.sh
and `cluster.sh down <name>` remove it. Every call is idempotent, and each
failure is logged and the next step still runs: a partial teardown is better
than none.
"""
import json
import os
import time

import boto3

CLUSTER = os.environ["CLUSTER"]
KARPENTER_ROLE = os.environ.get("KARPENTER_ROLE", "")
SECOND_SWEEP_DELAY = float(os.environ.get("SECOND_SWEEP_DELAY", "60"))
TTL = os.environ.get("TTL", "")


def ours():
    """EC2 filters for this run's things: its name, and its TTL when known."""
    f = [{"Name": "tag:aerol:run", "Values": [CLUSTER]}]
    if TTL:
        f.append({"Name": "tag:aerol:ttl", "Values": [TTL]})
    return f


def _log(**kw):
    print(json.dumps(kw, default=str), flush=True)


def stop_karpenter(iam, ec2):
    """No new machines, then none of Karpenter's for this run."""
    if KARPENTER_ROLE:
        try:
            for name in iam.list_role_policies(RoleName=KARPENTER_ROLE)["PolicyNames"]:
                iam.delete_role_policy(RoleName=KARPENTER_ROLE, PolicyName=name)
                _log(step="karpenter-rights-removed", role=KARPENTER_ROLE, policy=name)
        except iam.exceptions.NoSuchEntityException:
            pass
        except Exception as e:  # noqa: BLE001
            _log(step="karpenter-rights", error=str(e))
    nodepool = [{"Name": "tag-key", "Values": ["karpenter.sh/nodepool"]}]
    terminate(ec2, nodepool)
    # A launch Karpenter started before it lost its rights lands after the
    # first sweep: a second one ends it.
    time.sleep(SECOND_SWEEP_DELAY)
    terminate(ec2, nodepool)


def terminate(ec2, extra_filters):
    filters = ours() + [
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
    ] + extra_filters
    ids = []
    for page in ec2.get_paginator("describe_instances").paginate(Filters=filters):
        for r in page["Reservations"]:
            ids += [i["InstanceId"] for i in r["Instances"]]
    for i in range(0, len(ids), 500):
        try:
            ec2.terminate_instances(InstanceIds=ids[i:i + 500])
        except Exception as e:  # noqa: BLE001
            _log(step="terminate", error=str(e))
    _log(step="terminated", count=len(ids))
    return ids


def delete_nodegroups(eks):
    try:
        groups = eks.list_nodegroups(clusterName=CLUSTER)["nodegroups"]
    except eks.exceptions.ResourceNotFoundException:
        return []
    for ng in groups:
        try:
            eks.delete_nodegroup(clusterName=CLUSTER, nodegroupName=ng)
            _log(step="nodegroup-delete", nodegroup=ng)
        except Exception as e:  # noqa: BLE001
            _log(step="nodegroup-delete", nodegroup=ng, error=str(e))
    return groups


def delete_load_balancers(elb):
    arns = []
    for page in elb.get_paginator("describe_load_balancers").paginate():
        arns += [lb["LoadBalancerArn"] for lb in page["LoadBalancers"]]
    for i in range(0, len(arns), 20):
        for d in elb.describe_tags(ResourceArns=arns[i:i + 20])["TagDescriptions"]:
            tags = {t["Key"]: t["Value"] for t in d["Tags"]}
            mine = tags.get("elbv2.k8s.aws/cluster") == CLUSTER or tags.get("aerol:run") == CLUSTER
            if mine and (not TTL or tags.get("aerol:ttl") == TTL):
                try:
                    elb.delete_load_balancer(LoadBalancerArn=d["ResourceArn"])
                    _log(step="load-balancer-delete", arn=d["ResourceArn"])
                except Exception as e:  # noqa: BLE001
                    _log(step="load-balancer-delete", arn=d["ResourceArn"], error=str(e))


def delete_volumes(ec2):
    """Unattached volumes tagged with the run (the run's volume claims)."""
    ids = []
    filters = ours() + [{"Name": "status", "Values": ["available"]}]
    for page in ec2.get_paginator("describe_volumes").paginate(Filters=filters):
        ids += [v["VolumeId"] for v in page["Volumes"]]
    for vid in ids:
        try:
            ec2.delete_volume(VolumeId=vid)
            _log(step="volume-delete", volume=vid)
        except Exception as e:  # noqa: BLE001
            _log(step="volume-delete", volume=vid, error=str(e))
    return ids


def handler(event, _context):
    phase = (event or {}).get("phase", "compute")
    _log(start=phase, cluster=CLUSTER)
    iam, ec2 = boto3.client("iam"), boto3.client("ec2")
    stop_karpenter(iam, ec2)
    if phase == "scale-cap":
        return {"phase": phase}
    eks, elb = boto3.client("eks"), boto3.client("elbv2")
    left = delete_nodegroups(eks)
    delete_load_balancers(elb)
    if phase == "cluster":
        if left:
            _log(step="cluster-delete", skipped="node groups still deleting", nodegroups=left)
        else:
            try:
                eks.delete_cluster(name=CLUSTER)
                _log(step="cluster-delete", cluster=CLUSTER)
            except eks.exceptions.ResourceNotFoundException:
                pass
            except Exception as e:  # noqa: BLE001
                _log(step="cluster-delete", error=str(e))
        delete_volumes(ec2)
    return {"phase": phase}
