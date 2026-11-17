// Offline test for k8s/reap.sh against a fake `aws` that holds a small
// account. Nothing reaches AWS.
//
// Runs in the normal `go test ./...` / `make test` flow (no build tag).
package safety

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAWSAccount answers the reads reap.sh makes from FAKE_WORLD (things by
// kind, each with its own tags), applies an EC2 tag filter the way EC2 does,
// logs every call to FAKE_LOG, and fails the calls the world lists in
// "fail".
const fakeAWSAccount = `#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
open(os.environ["FAKE_LOG"], "a").write(" ".join(args) + "\n")
W = json.load(open(os.environ["FAKE_WORLD"]))
opts, pos, i = {}, [], 0
while i < len(args):
    a = args[i]
    if a.startswith("--"):
        vals, i = [], i + 1
        many = a in ("--filters", "--resource-arns", "--instance-ids", "--vpc-endpoint-ids")
        while i < len(args) and not args[i].startswith("--") and (many or not vals):
            vals.append(args[i]); i += 1
        opts[a] = vals
    else:
        pos.append(a); i += 1
svc, op = (pos + ["", ""])[:2]
def one(k): return (opts.get(k) or [""])[0]
filt = {}
for f in opts.get("--filters", []):
    name, _, vals = f.partition(",Values=")
    filt[name.replace("Name=", "")] = vals.split(",")
def kv(tags): return [{"Key": k, "Value": v} for k, v in tags.items()]
def text(xs): print("\t".join(xs))
def fail(code): sys.stderr.write("An error occurred (%s)\n" % code); sys.exit(254)
for f in W.get("fail", []):
    if f in " ".join(args) and op != "wait": fail("ResourceInUseException")
def tagged(things):
    out = []
    for t in things:
        ok = all(t["tags"].get(k[4:]) in v for k, v in filt.items() if k.startswith("tag:"))
        if ok: out.append(t)
    return out
G = lambda k: W.get(k, [])
if svc == "configure": print("us-east-1")
elif (svc, op) == ("ec2", "describe-instances"): print(json.dumps([{"id": t["id"], "tags": kv(t["tags"])} for t in tagged(G("instances"))]))
elif (svc, op) == ("ec2", "describe-volumes"): print(json.dumps([{"id": t["id"], "tags": kv(t["tags"])} for t in tagged(G("volumes"))]))
elif (svc, op) == ("ec2", "describe-vpcs"): print(json.dumps([{"id": t["id"], "tags": kv(t["tags"])} for t in tagged(G("vpcs"))]))
elif (svc, op) == ("ec2", "describe-vpc-endpoints"):
    v = filt["vpc-id"][0]
    text(["vpce-" + v for t in G("vpcs") if t["id"] == v and t.get("endpoint")])
elif (svc, op) == ("ec2", "describe-internet-gateways"): text(["igw-" + filt["attachment.vpc-id"][0]])
elif (svc, op) == ("ec2", "describe-subnets"): text(["subnet-" + filt["vpc-id"][0]])
elif (svc, op) == ("ec2", "describe-route-tables"): text(["rtb-" + filt["vpc-id"][0]])
elif (svc, op) == ("ec2", "describe-security-groups"):
    if "--group-ids" in opts: print("[]")
    else: text(["sg-" + filt["vpc-id"][0]])
elif (svc, op) == ("ec2", "describe-network-interfaces"): text([])
elif (svc, op) == ("elbv2", "describe-load-balancers"): text([t["arn"] for t in G("lbs")])
elif (svc, op) == ("elbv2", "describe-tags"): print(json.dumps([{"ResourceArn": t["arn"], "Tags": kv(t["tags"])} for t in G("lbs") if t["arn"] in opts["--resource-arns"]]))
elif (svc, op) == ("eks", "list-clusters"): text([c["name"] for c in G("clusters")])
elif (svc, op) == ("eks", "describe-cluster"):
    c = [c for c in G("clusters") if c["name"] == one("--name")]
    if not c: fail("ResourceNotFoundException")
    print(json.dumps({"tags": c[0]["tags"], "vpc": c[0]["vpc"]}))
elif (svc, op) == ("eks", "list-nodegroups"): text([n["name"] for c in G("clusters") if c["name"] == one("--cluster-name") for n in c["nodegroups"]])
elif (svc, op) == ("eks", "describe-nodegroup"): print(json.dumps([n["tags"] for c in G("clusters") if c["name"] == one("--cluster-name") for n in c["nodegroups"] if n["name"] == one("--nodegroup-name")][0]))
elif (svc, op) == ("eks", "wait"):
    if any(f.startswith("delete-nodegroup") for f in W.get("fail", [])): sys.exit(255)
elif (svc, op) == ("lambda", "list-functions"): text(["arn:aws:lambda:us-east-1:1:function:" + t["name"] for t in G("lambdas")])
elif (svc, op) == ("lambda", "list-tags"): print(json.dumps([t["tags"] for t in G("lambdas") if one("--resource").endswith(":" + t["name"])][0]))
elif (svc, op) == ("logs", "describe-log-groups"): text([t["name"] for t in G("loggroups")])
elif (svc, op) == ("logs", "list-tags-log-group"): print(json.dumps([t["tags"] for t in G("loggroups") if t["name"] == one("--log-group-name")][0]))
elif (svc, op) == ("ecr", "describe-repositories"): text(["arn:aws:ecr:us-east-1:1:repository/" + t["name"] for t in G("repos")])
elif (svc, op) == ("ecr", "list-tags-for-resource"): print(json.dumps([kv(t["tags"]) for t in G("repos") if one("--resource-arn").endswith("/" + t["name"])][0]))
elif (svc, op) == ("iam", "list-open-id-connect-providers"): text([t["arn"] for t in G("oidc")])
elif (svc, op) == ("iam", "list-open-id-connect-provider-tags"): print(json.dumps([kv(t["tags"]) for t in G("oidc") if t["arn"] == one("--open-id-connect-provider-arn")][0]))
elif (svc, op) == ("iam", "list-roles"): text([t["name"] for t in G("roles")])
elif (svc, op) == ("iam", "list-role-tags"): print(json.dumps([kv(t["tags"]) for t in G("roles") if t["name"] == one("--role-name")][0]))
elif (svc, op) == ("iam", "list-attached-role-policies"): text(["arn:policy/managed"])
elif (svc, op) == ("iam", "list-role-policies"): text(["inline"])
elif (svc, op) == ("iam", "list-instance-profiles-for-role"): text(["profile-" + one("--role-name")])
elif (svc, op) == ("s3api", "list-buckets"): text([t["name"] for t in G("buckets")])
elif (svc, op) == ("s3api", "get-bucket-tagging"): print(json.dumps([kv(t["tags"]) for t in G("buckets") if t["name"] == one("--bucket")][0]))
elif (svc, op) == ("s3api", "get-bucket-location"): print("None")
elif (svc, op) == ("s3api", "list-object-versions"): print(json.dumps({"Versions": [], "DeleteMarkers": []}))
elif (svc, op) == ("scheduler", "list-schedules"): text([t["name"] for t in G("schedules")])
elif (svc, op) == ("scheduler", "get-schedule"):
    t = [t for t in G("schedules") if t["name"] == one("--name")][0]
    print(json.dumps({"at": "at(%s)" % t["at"], "target": t.get("target", "arn:aws:lambda:us-east-1:111122223333:function:" + t["name"].rsplit("-teardown", 1)[0].rsplit("-scale-cap", 1)[0] + "-teardown")}))
elif op.startswith("describe") or op.startswith("list") or op.startswith("get"):
    sys.stderr.write("fake aws: no answer for %s %s\n" % (svc, op)); sys.exit(2)
`

func harnessTags(run, ttl string) map[string]string {
	t := map[string]string{"aerol:purpose": "k8s-phase0", "aerol:run": run}
	if ttl != "" {
		t["aerol:ttl"] = ttl
	}
	return t
}

// reap.sh judges every thing on its own tags. The review's case: a live run
// whose name an older run used, with that older run's VPC left past its
// TTL; only that VPC goes. Beside it: a run past its TTL whose cluster is
// still up, one whose cluster is already gone, a thing of this harness with
// no TTL, another harness's thing past its TTL, and teardown schedules
// spent and not.
func TestReapJudgesEveryThingOnItsOwnTags(t *testing.T) {
	needTools(t, "python3", "jq")
	const past, future = "2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z"
	live, old, dead, gone := harnessTags("bank-1", future), harnessTags("bank-1", "2026-11-01T00:00:00Z"), harnessTags("dead", past), harnessTags("gone", past)
	other := map[string]string{"aerol:purpose": "another-harness", "aerol:run": "dead", "aerol:ttl": past}
	type thing = map[string]any
	world := map[string]any{
		"fail": []string{"delete-nodegroup --cluster-name dead"},
		"instances": []thing{{"id": "i-live", "tags": live}, {"id": "i-dead", "tags": dead}, {"id": "i-gone", "tags": gone},
			{"id": "i-other", "tags": other}},
		"lbs": []thing{{"arn": "arn:lb/live", "tags": live}, {"arn": "arn:lb/gone", "tags": gone}, {"arn": "arn:lb/other", "tags": other}},
		"clusters": []thing{
			{"name": "bank-1", "vpc": "vpc-live", "tags": live, "nodegroups": []thing{{"name": "system", "tags": live}}},
			{"name": "dead", "vpc": "vpc-dead", "tags": dead, "nodegroups": []thing{{"name": "ng1", "tags": dead}}},
			// A live cluster with nothing in it yet: its own tags keep it.
			{"name": "fresh", "vpc": "vpc-fresh", "tags": harnessTags("fresh", future), "nodegroups": []thing{}},
			// A cluster past its TTL holding a node group whose own TTL has
			// not passed: the node group stays, so the cluster does too.
			{"name": "mixed", "vpc": "vpc-mixed", "tags": harnessTags("mixed", past), "nodegroups": []thing{{"name": "ng-live", "tags": harnessTags("mixed", future)}}},
		},
		"lambdas":   []thing{{"name": "bank-1-teardown", "tags": live}, {"name": "dead-teardown", "tags": dead}},
		"loggroups": []thing{{"name": "/aws/lambda/bank-1-teardown", "tags": live}, {"name": "/aws/lambda/dead-teardown", "tags": dead}},
		"repos":     []thing{{"name": "bank-1/aerolvm", "tags": live}, {"name": "dead/drill", "tags": dead}},
		"oidc":      []thing{{"arn": "arn:oidc/bank-1", "tags": live}, {"arn": "arn:oidc/dead", "tags": dead}},
		"roles":     []thing{{"name": "bank-1-node", "tags": live}, {"name": "dead-node", "tags": dead}, {"name": "dead-audit", "tags": other}},
		"volumes": []thing{{"id": "vol-live", "tags": live}, {"id": "vol-dead", "tags": dead}, {"id": "vol-gone", "tags": gone},
			{"id": "vol-nottl", "tags": harnessTags("dead", "")}},
		"buckets": []thing{{"name": "bank-1-witness-111122223333", "tags": live}, {"name": "dead-witness-111122223333", "tags": dead}},
		"schedules": []thing{{"name": "bank-1-teardown-compute", "at": "2099-01-01T00:00:00"},
			{"name": "dead-teardown-compute", "at": "2020-01-01T00:00:00"}, {"name": "unrelated-job", "at": "2020-01-01T00:00:00"},
			// Another project's spent schedule with a name like ours: its
			// target is not this harness's teardown Lambda.
			{"name": "billing-teardown-cluster", "at": "2020-01-01T00:00:00", "target": "arn:aws:lambda:us-east-1:111122223333:function:billing-cleanup"}},
		"vpcs": []thing{{"id": "vpc-live", "tags": live}, {"id": "vpc-old", "tags": old, "endpoint": true},
			{"id": "vpc-dead", "tags": dead}, {"id": "vpc-gone", "tags": gone}},
	}
	dir := t.TempDir()
	raw, _ := json.Marshal(world)
	worldFile, log := filepath.Join(dir, "world.json"), filepath.Join(dir, "calls.log")
	if err := os.WriteFile(worldFile, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "aws"), []byte(fakeAWSAccount), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(extra ...string) (string, string) {
		_ = os.Remove(log)
		cmd := exec.Command("bash", k8sFile(t, "reap.sh"))
		cmd.Env = append(append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"FAKE_WORLD="+worldFile, "FAKE_LOG="+log, "AWS_REGION=us-east-1"), extra...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("reap.sh: %v\n%s", err, out)
		}
		return string(out), readLog(t, log)
	}
	out, calls := run()
	for _, want := range []string{
		// The older run's VPC, its endpoint first: and nothing else of bank-1.
		"ec2 delete-vpc-endpoints --vpc-endpoint-ids vpce-vpc-old",
		"ec2 delete-vpc --vpc-id vpc-old",
		// The run past its TTL whose cluster is up.
		"ec2 terminate-instances --instance-ids i-dead i-gone",
		"eks delete-nodegroup --cluster-name dead --nodegroup-name ng1",
		"lambda delete-function --function-name dead-teardown",
		"logs delete-log-group --log-group-name /aws/lambda/dead-teardown",
		"ecr delete-repository --repository-name dead/drill --force",
		"iam delete-open-id-connect-provider --open-id-connect-provider-arn arn:oidc/dead",
		"iam detach-role-policy --role-name dead-node --policy-arn arn:policy/managed",
		"iam delete-role-policy --role-name dead-node --policy-name inline",
		"iam remove-role-from-instance-profile --instance-profile-name profile-dead-node --role-name dead-node",
		"iam delete-instance-profile --instance-profile-name profile-dead-node",
		"iam delete-role --role-name dead-node",
		"ec2 delete-volume --volume-id vol-dead",
		"s3api delete-bucket --bucket dead-witness-111122223333",
		"scheduler delete-schedule --name dead-teardown-compute",
		// The run whose cluster is gone: found by its things' own tags.
		"elbv2 delete-load-balancer --load-balancer-arn arn:lb/gone",
		"ec2 delete-volume --volume-id vol-gone",
		"ec2 detach-internet-gateway --internet-gateway-id igw-vpc-gone --vpc-id vpc-gone",
		"ec2 delete-subnet --subnet-id subnet-vpc-gone",
		"ec2 delete-route-table --route-table-id rtb-vpc-gone",
		"ec2 delete-security-group --group-id sg-vpc-gone",
		"ec2 delete-vpc --vpc-id vpc-gone",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("reap.sh did not call %q", want)
		}
	}
	mutating := func(l string) bool {
		for _, w := range strings.Fields(l) {
			if strings.HasPrefix(w, "delete-") || w == "terminate-instances" || strings.HasPrefix(w, "detach-") || strings.HasPrefix(w, "remove-") {
				return true
			}
		}
		return false
	}
	for _, never := range []string{
		// The live run, all of it.
		"i-live", "arn:lb/live", "--cluster-name bank-1", "--name bank-1", "bank-1-teardown", "bank-1/aerolvm", "arn:oidc/bank-1",
		"bank-1-node", "vol-live", "bank-1-witness", "vpc-live",
		// Another harness's things, a thing with no TTL, a schedule not a
		// teardown's, the expired cluster whose node group would not go,
		// and the VPC that cluster is in.
		"i-other", "arn:lb/other", "dead-audit", "vol-nottl", "unrelated-job", "delete-cluster --name dead", "vpc-dead",
		"--name fresh", "--cluster-name mixed", "--name mixed", "billing-teardown-cluster",
	} {
		for _, l := range strings.Split(calls, "\n") {
			if strings.Contains(l, never) && mutating(l) {
				t.Errorf("reap.sh removed %q: %s", never, l)
			}
		}
	}
	for _, want := range []string{"keep volume vol-nottl of run dead: it has no aerol:ttl", "keep cluster dead until its node groups are gone",
		"keep VPC vpc-dead until the cluster in it is deleted", "keep schedule bank-1-teardown-compute: fires 2099-01-01T00:00:00 UTC",
		"could not remove node group dead/ng1", "keep machine i-live of run bank-1: ttl " + future,
		"keep cluster fresh of run fresh: ttl " + future, "keep schedule billing-teardown-cluster: its target is not the teardown Lambda billing-teardown", "keep node group mixed/ng-live of run mixed", "keep cluster mixed until its node groups are gone"} {
		if !strings.Contains(out, want) {
			t.Errorf("reap.sh did not say %q:\n%s", want, out)
		}
	}

	// A dry run says what would go and changes nothing.
	out, calls = run("DRY_RUN=1")
	for _, l := range strings.Split(calls, "\n") {
		if mutating(l) {
			t.Errorf("a dry run called %s", l)
		}
	}
	if !strings.Contains(out, "would remove machines i-dead i-gone") || !strings.Contains(out, "would remove VPC vpc-old") {
		t.Errorf("a dry run did not say what would go:\n%s", out)
	}
}
