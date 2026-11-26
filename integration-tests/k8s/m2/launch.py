#!/usr/bin/env python3
"""launch.py: the two AWS calls the M2 spikes make through boto3, because
the AWS CLI 2.27 cannot send CpuOptions.NestedVirtualization.

    launch.py check                                   boto3 can ask for nested virtualization?
    launch.py run --name N --type T --ami-param P --userdata F --sg SG
                  --root-dev D --disk-gb G [--nested] [--enclave] --tag k=v ...
    launch.py presign-put --bucket B --key K          a link the machine PUTs its results to

With --dry-run, run and presign-put import nothing from boto3 and make no
call: they print what they would send and a placeholder answer. Every
instance, volume and network interface carries the --tag tags. The user
data is gzipped (EC2 takes 16 KB; cloud-init unpacks it). A machine powers
off at its own deadline (the user data's shutdown), and powering off
terminates it.
"""
import argparse
import gzip
import json
import sys

REGION = "us-east-1"


def tags_of(pairs):
    out = []
    for p in pairs:
        k, sep, v = p.partition("=")
        if not sep or not k:
            raise SystemExit("launch.py: tag %r is not key=value" % p)
        out.append({"Key": k, "Value": v})
    return out


def run_kwargs(a, ami, userdata):
    tags = tags_of(a.tag)
    kw = {
        "ImageId": ami, "InstanceType": a.type, "MinCount": 1, "MaxCount": 1,
        "InstanceInitiatedShutdownBehavior": "terminate",
        "SecurityGroupIds": [a.sg],
        "UserData": userdata,
        "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
        "BlockDeviceMappings": [{"DeviceName": a.root_dev, "Ebs": {
            "VolumeSize": a.disk_gb, "VolumeType": "gp3", "DeleteOnTermination": True}}],
        "TagSpecifications": [{"ResourceType": rt, "Tags": tags}
                              for rt in ("instance", "volume", "network-interface")],
    }
    if a.nested:
        kw["CpuOptions"] = {"NestedVirtualization": "enabled"}
    if a.enclave:
        kw["EnclaveOptions"] = {"Enabled": True}
    return kw


def cmd_run(a):
    raw = open(a.userdata, "rb").read()
    if a.dry_run:
        kw = run_kwargs(a, "<ssm:%s>" % a.ami_param, "<gzip of %s: %d bytes>" % (a.userdata, len(gzip.compress(raw))))
        print("dry-run: ssm.get_parameter(Name=%r)" % a.ami_param, file=sys.stderr)
        print("dry-run: ec2.run_instances(%s)" % json.dumps(kw, sort_keys=True), file=sys.stderr)
        print("i-dry-%s" % a.name)
        return 0
    import boto3
    ssm = boto3.client("ssm", region_name=REGION)
    ec2 = boto3.client("ec2", region_name=REGION)
    ami = ssm.get_parameter(Name=a.ami_param)["Parameter"]["Value"]
    r = ec2.run_instances(**run_kwargs(a, ami, gzip.compress(raw)))
    print(r["Instances"][0]["InstanceId"])
    return 0


def cmd_presign_put(a):
    if a.dry_run:
        print("dry-run: s3.generate_presigned_url(put_object, Bucket=%s, Key=%s, ExpiresIn=%d)"
              % (a.bucket, a.key, a.expires), file=sys.stderr)
        print("https://%s.s3.amazonaws.com/%s?X-Amz-Signature=dry" % (a.bucket, a.key))
        return 0
    import boto3
    s3 = boto3.client("s3", region_name=REGION)
    print(s3.generate_presigned_url("put_object", Params={"Bucket": a.bucket, "Key": a.key}, ExpiresIn=a.expires))
    return 0


def cmd_check(_a):
    try:
        import botocore.session
    except ImportError:
        print("launch.py: no boto3 here; set AEROL_PYTHON to a python that has a new boto3", file=sys.stderr)
        return 2
    m = botocore.session.get_session().get_service_model("ec2")
    if "NestedVirtualization" not in m.shape_for("CpuOptionsRequest").members:
        print("launch.py: this boto3 cannot ask for nested virtualization; update it", file=sys.stderr)
        return 2
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--name", required=True)
    r.add_argument("--type", required=True)
    r.add_argument("--ami-param", required=True)
    r.add_argument("--userdata", required=True)
    r.add_argument("--sg", required=True)
    r.add_argument("--root-dev", required=True)
    r.add_argument("--disk-gb", type=int, required=True)
    r.add_argument("--nested", action="store_true")
    r.add_argument("--enclave", action="store_true")
    r.add_argument("--tag", action="append", default=[])
    r.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("presign-put")
    p.add_argument("--bucket", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--expires", type=int, default=14400)
    p.add_argument("--dry-run", action="store_true")
    sub.add_parser("check")
    a = ap.parse_args(argv)
    return {"run": cmd_run, "presign-put": cmd_presign_put, "check": cmd_check}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
