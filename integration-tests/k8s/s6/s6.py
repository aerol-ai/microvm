#!/usr/bin/env python3
"""s6.py: spike S6 (plans/kubernetes-v2-phase0.md). /dev/kvm and Firecracker
boot time on one EC2 instance with nested virtualization.

    s6.py [instance type]     # default m8i.large; prints the S6 lines

Needs boto3 new enough to send CpuOptions.NestedVirtualization (older SDKs
drop it without a word; check with the venv the Phase 0 goal names). The
instance is tagged like every Phase 0 resource and terminated at the end,
pass or fail.
"""
import base64, datetime, os, sys, time
import boto3

itype = sys.argv[1] if len(sys.argv) > 1 else "m8i.large"
region = os.environ.get("AWS_REGION", "us-east-1")
ec2 = boto3.client("ec2", region_name=region)
ssm = boto3.client("ssm", region_name=region)

vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
if not vpcs:
    sys.exit("s6: no default VPC in this region")
offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
    LocationType="availability-zone", Filters=[{"Name": "instance-type", "Values": [itype]}])["InstanceTypeOfferings"]}
subnets = [s for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}])["Subnets"]
           if s["AvailabilityZone"] in offered and s.get("MapPublicIpOnLaunch")]
if not subnets:
    sys.exit(f"s6: no public default subnet offers {itype}")
ami = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]
ttl = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
here = os.path.dirname(os.path.abspath(__file__))
userdata = open(os.path.join(here, "userdata.sh")).read()

resp = ec2.run_instances(
    ImageId=ami, InstanceType=itype, MinCount=1, MaxCount=1,
    SubnetId=subnets[0]["SubnetId"],
    CpuOptions={"NestedVirtualization": "enabled"},
    InstanceInitiatedShutdownBehavior="terminate",
    UserData=userdata,
    TagSpecifications=[{"ResourceType": "instance", "Tags": [
        {"Key": "Name", "Value": "p0-s6"}, {"Key": "aerol:purpose", "Value": "k8s-phase0"},
        {"Key": "aerol:owner", "Value": "itest"}, {"Key": "aerol:ttl", "Value": ttl},
        {"Key": "aerol:run", "Value": "p0-s6"}]}])
iid = resp["Instances"][0]["InstanceId"]
print(f"s6: launched {iid} ({itype}, {subnets[0]['AvailabilityZone']}, nested virtualization requested)", flush=True)
started = time.time()
try:
    desc = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    print(f"s6: CpuOptions as AWS reports them: {desc.get('CpuOptions')}", flush=True)
    seen = set()
    while time.time() - started < 1500:
        time.sleep(30)
        out = ec2.get_console_output(InstanceId=iid, Latest=True).get("Output", "")
        if out:
            # boto3 may hand back the console text decoded or still base64.
            try:
                text = base64.b64decode(out, validate=True).decode("utf-8", "replace")
            except Exception:
                text = out
            for line in text.splitlines():
                if "S6" in line and line not in seen:
                    seen.add(line)
                    line = line.strip()
                    print(line[line.find("S6"):], flush=True)
            if "S6-DONE" in text:
                break
    else:
        print("s6: no S6-DONE within 25 minutes", flush=True)
finally:
    ec2.terminate_instances(InstanceIds=[iid])
    mins = (time.time() - started) / 60
    print(f"s6: terminated {iid} after {mins:.0f} minutes", flush=True)
