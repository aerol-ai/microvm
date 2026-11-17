// Offline tests for the bank run on EKS (k8s/eks-bank.sh, k8s/drills-eks.sh
// and the bank-drills Terraform): the gate, the cost guards, the dry run and
// the teardown Lambda. Every AWS, kubectl and Helm call is a logging stub;
// nothing reaches AWS or a cluster.
//
// Runs in the normal `go test ./...` / `make test` flow (no build tag).
package safety

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// eksStubs puts logging stand-ins for kubectl, aws, terraform, helm, curl,
// kind and docker on PATH. kubectl answers only `config current-context`,
// from the kubeconfig file it is pointed at. aws answers only the reads the
// gate and up's account check make: the caller's account (STUB_ACCOUNT,
// default 111122223333), Inspector's ECR scanning (STUB_INSPECTOR,
// DISABLED), AWS Config recorders on (STUB_CONFIG, 0), GuardDuty detectors
// (STUB_GD, none; reading one fails), whether a cluster of the name exists
// (STUB_CLUSTER_EXISTS). Everything else fails.
func eksStubs(t *testing.T) ([]string, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	stubs := map[string]string{
		"kubectl": `echo "kubectl $*" >> "$STUB_LOG"
[ "$1 $2" = "config current-context" ] && { sed -n 's/^current-context: *//p' "$KUBECONFIG"; exit 0; }
exit 1`,
	}
	stubs["aws"] = `echo "aws $*" >> "$STUB_LOG"
case "$*" in
  *"sts get-caller-identity"*) echo "${STUB_ACCOUNT:-111122223333}"; exit 0 ;;
  *"inspector2 batch-get-account-status"*) echo "${STUB_INSPECTOR:-DISABLED}"; exit 0 ;;
  *"configservice describe-configuration-recorder-status"*) echo "${STUB_CONFIG:-0}"; exit 0 ;;
  *"guardduty list-detectors"*) echo "${STUB_GD:-None}"; exit 0 ;;
  *"eks describe-cluster"*) [ -n "${STUB_CLUSTER_EXISTS:-}" ] && { echo '{}'; exit 0; }; exit 254 ;;
esac
exit 1`
	for _, name := range []string{"terraform", "helm", "curl", "kind", "docker"} {
		stubs[name] = `echo "` + name + ` $*" >> "$STUB_LOG"; exit 1`
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "STUB_LOG="+log, "HELM=helm")
	return env, log
}

// bankRun copies the two gated scripts into a fresh k8s/ folder with a
// cluster.sh-style state folder for name: a kubeconfig naming ctx, and the
// run's saved inputs. An empty ctx leaves the state folder out.
func bankRun(t *testing.T, name, ctx string, bank bool) string {
	t.Helper()
	k8s := filepath.Join(t.TempDir(), "k8s")
	if err := os.MkdirAll(k8s, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"drills-eks.sh", "eks-bank.sh", "terraform/lb-controller-iam-policy.json"} {
		raw, err := os.ReadFile(filepath.Join(integrationDir(t), "k8s", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(k8s, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(k8s, f), raw, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if ctx != "" {
		state := filepath.Join(k8s, ".state", name)
		if err := os.MkdirAll(state, 0o755); err != nil {
			t.Fatal(err)
		}
		writeKubeconfig(t, filepath.Join(state, "kubeconfig"), ctx)
		inputs, _ := json.Marshal(map[string]any{"name": name, "bank_drills": bank})
		if err := os.WriteFile(filepath.Join(state, "run.tfvars.json"), inputs, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return k8s
}

func writeKubeconfig(t *testing.T, path, ctx string) {
	t.Helper()
	body := "apiVersion: v1\nkind: Config\ncurrent-context: " + ctx + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Every step after up deletes pods, fills workers, breaks a gateway or
// buys machines. Both scripts talk only to the kubeconfig cluster.sh wrote
// for the run they are named, and only if it names that EKS cluster and the
// run was made with --bank-drills; never KUBECONFIG or KUBECTL_CONTEXT, and
// never a kind cluster. A refusal comes before any other call.
func TestEKSBankGateRefusesEveryOtherContext(t *testing.T) {
	const name = "bank-1"
	const good = "arn:aws:eks:us-east-1:111122223333:cluster/bank-1"
	elsewhere := filepath.Join(t.TempDir(), "kubeconfig")
	writeKubeconfig(t, elsewhere, good)
	kindConfig := filepath.Join(t.TempDir(), "kubeconfig")
	writeKubeconfig(t, kindConfig, "kind-aerolvm-ent")
	for _, tc := range []struct {
		desc, name, ctx string
		bank            bool
		env             []string
		ok              bool
	}{
		{desc: "a kind cluster", name: name, ctx: "kind-aerolvm-ent", bank: true},
		{desc: "another EKS cluster", name: name, ctx: "arn:aws:eks:us-east-1:111122223333:cluster/bank-prod", bank: true},
		{desc: "this cluster's name as a suffix", name: name, ctx: "arn:aws:eks:us-east-1:111122223333:cluster/xbank-1", bank: true},
		{desc: "a plain context name", name: name, ctx: "bank-1", bank: true},
		{desc: "a run made without --bank-drills", name: name, ctx: good, bank: false},
		{desc: "no cluster.sh state", name: name, ctx: "", bank: true},
		{desc: "not a cluster.sh name", name: "Bank_1", ctx: good, bank: true},
		// The environment points at the right cluster; the run's own
		// kubeconfig does not. The environment is never read.
		{desc: "KUBECONFIG names the cluster, the run's kubeconfig a kind one", name: name, ctx: "kind-aerolvm-ent", bank: true,
			env: []string{"KUBECONFIG=" + elsewhere, "KUBECTL_CONTEXT=" + good}},
		// And the other way round: the run's kubeconfig wins.
		{desc: "the run's own EKS cluster, with KUBECONFIG on kind", name: name, ctx: good, bank: true,
			env: []string{"KUBECONFIG=" + kindConfig, "KUBECTL_CONTEXT=kind-aerolvm-ent"}, ok: true},
		{desc: "the run's own EKS cluster", name: name, ctx: good, bank: true, ok: true},
		// The right cluster, but this machine's credentials are another
		// account's: every aws call would land there.
		{desc: "AWS credentials for another account", name: name, ctx: good, bank: true, env: []string{"STUB_ACCOUNT=999999999999"}},
	} {
		for _, script := range []string{"drills-eks.sh", "eks-bank.sh"} {
			env, log := eksStubs(t)
			k8s := bankRun(t, name, tc.ctx, tc.bank)
			args := []string{filepath.Join(k8s, script), tc.name}
			if script == "drills-eks.sh" {
				args = append(args, t.TempDir())
			}
			cmd := exec.Command("bash", append(args, "gate")...)
			cmd.Env = append(env, tc.env...)
			out, _ := cmd.CombinedOutput()
			code := cmd.ProcessState.ExitCode()
			if tc.ok {
				if code != 0 || !strings.Contains(string(out), "gate: ok") {
					t.Errorf("%s, %s: refused (exit %d): %s", script, tc.desc, code, out)
				}
				continue
			}
			if code != 2 || !strings.Contains(string(out), "refusing to run") {
				t.Errorf("%s, %s: exit %d, want a refusal: %s", script, tc.desc, code, out)
			}
			for _, line := range strings.Split(strings.TrimSpace(readLog(t, log)), "\n") {
				if line != "" && line != "kubectl config current-context" && line != "aws sts get-caller-identity --query Account --output text" {
					t.Errorf("%s, %s: called %q before refusing", script, tc.desc, line)
				}
			}
		}
	}
}

// mutating drops the calls a dry run may make, which read and change
// nothing: `helm template`, the enterprise guard's local render.
func mutating(calls string) string {
	var out []string
	for _, l := range strings.Split(calls, "\n") {
		if l != "" && !strings.HasPrefix(l, "helm template ") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// The cost guards before anything is made: up prints the estimate and
// refuses past the ceiling (default $45) or when the plan outlasts the
// teardown timer, before cluster.sh, Terraform or AWS is called; and up
// always asks for the teardown timer.
func TestEKSBankEstimateGuardsUp(t *testing.T) {
	needTools(t, "python3")
	run := func(extra ...string) (string, int, string) {
		env, log := eksStubs(t)
		k8s := bankRun(t, "bank-1", "", true)
		cmd := exec.Command("bash", filepath.Join(k8s, "eks-bank.sh"), "bank-1", "up")
		cmd.Env = append(env, extra...)
		out, _ := cmd.CombinedOutput()
		return string(out), cmd.ProcessState.ExitCode(), readLog(t, log)
	}
	for _, tc := range []struct {
		desc string
		env  []string
		want string
	}{
		{"a ceiling below the worst case", []string{"EKS_BANK_CEILING=20"}, "passes the ceiling $20.00"},
		{"a teardown timer before the plan ends", []string{"EKS_BANK_TTL=3h"}, "past the 3 h teardown timer"},
		{"more workers than the budget", []string{"EKS_BANK_PEAK_WORKERS=200"}, "passes the ceiling $45.00"},
	} {
		out, code, calls := run(tc.env...)
		if code != 3 || !strings.Contains(out, "REFUSED") || !strings.Contains(out, tc.want) {
			t.Errorf("%s: exit %d, want 3 and %q:\n%s", tc.desc, code, tc.want, out)
		}
		if strings.TrimSpace(calls) != "" || strings.Contains(out, "cluster.sh up") {
			t.Errorf("%s: something ran before the refusal:\n%s%s", tc.desc, calls, out)
		}
	}

	// The default run fits the budget: a dry run gets as far as cluster.sh,
	// with the teardown timer and the bank-drills Terraform.
	out, code, calls := run("DRY_RUN=1", "EKS_BANK_DRY_DIR="+t.TempDir())
	if code != 0 || strings.TrimSpace(mutating(calls)) != "" {
		t.Fatalf("dry run: exit %d, calls %q:\n%s", code, calls, out)
	}
	m := regexp.MustCompile(`planned: \$([0-9.]+) .* worst case \(teardown timer at 6 h\): \$([0-9.]+); ceiling \$45\.00`).FindStringSubmatch(out)
	if m != nil && (m[1] != "30.98" || m[2] != "40.05") {
		t.Errorf("the estimate moved: planned $%s, worst $%s (update the report and this test together)", m[1], m[2])
	}
	if m == nil {
		t.Fatalf("no estimate line:\n%s", out)
	}
	if !regexp.MustCompile(`dry-run: \S+/cluster\.sh up bank-1 --ttl 6h .*--workers 0 .*--karpenter .*--bank-drills --teardown`).MatchString(out) {
		t.Errorf("up does not ask cluster.sh for the bank Terraform and the teardown timer:\n%s", out)
	}
}

// A dry run of every step prints the plan and calls nothing: no AWS,
// Terraform, kubectl or Helm. It shows each guard of the scale step.
func TestEKSBankDryRunCallsNothing(t *testing.T) {
	needTools(t, "python3", "jq", "git")
	env, log := eksStubs(t)
	cmd := exec.Command("bash", filepath.Join(integrationDir(t), "k8s", "eks-bank.sh"), "bank-1", "all")
	cmd.Env = append(env, "DRY_RUN=1", "EKS_BANK_DRY_DIR="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry run failed: %v\n%s", err, out)
	}
	if calls := strings.TrimSpace(mutating(readLog(t, log))); calls != "" {
		t.Fatalf("a dry run called tools:\n%s", calls)
	}
	for _, want := range []string{
		"cluster.sh up bank-1",
		"cell.sh bank-1 build",
		"upgrade --install aws-load-balancer-controller",
		"upgrade --install aerolvm",
		"drills-eks.sh bank-1",
		"aws scheduler create-schedule",
		"--name bank-1-scale-cap",
		// The floor to the peak, then back to the base (the closing brace
		// keeps 6 from matching 60).
		"minWorkers\\\"\\,\\ \\\"value\\\":\\ 60\\}",
		"minWorkers\\\"\\,\\ \\\"value\\\":\\ 6\\}",
		"cell.sh bank-1 down",
		"read Inspector's ECR scanning, AWS Config recording and GuardDuty",
		"--probe-image public.ecr.aws/docker/library/alpine:3.20",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the dry run's plan has no %q", want)
		}
	}
	// The scale-cap schedule calls the teardown Lambda's scale-cap phase,
	// and deletes itself once it has run.
	sched := regexp.MustCompile(`(?m)^dry-run: aws scheduler create-schedule .*$`).FindString(string(out))
	if !strings.Contains(sched, `phase\\\":\ \\\"scale-cap`) || !strings.Contains(sched, "--action-after-completion DELETE") {
		t.Errorf("the scale-cap schedule: %s", sched)
	}
	if strings.Contains(string(out), "PASS") || strings.Contains(string(out), "FAIL") {
		t.Errorf("a dry run reported a result:\n%s", out)
	}
}

// The Terraform the bank run adds: a GOVERNANCE-locked witness (so the
// teardown can empty it with the bypass, which the node role is denied),
// a role only the two node service accounts may assume, a teardown Lambda
// that AWS calls at the TTL and may end only this run's machines, and the
// load balancer controller's published policy.
func TestEKSBankTerraformGuards(t *testing.T) {
	read := func(parts ...string) string {
		raw, err := os.ReadFile(filepath.Join(append([]string{integrationDir(t), "k8s"}, parts...)...))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	bank := read("terraform", "bank.tf")
	for _, want := range []string{
		"object_lock_enabled = true",
		`mode = "GOVERNANCE"`,
		`"system:serviceaccount:${ns}:aerolvm-node"`,
		`for ns in ["aerolvm-system", "aerolvm-workers"]`,
		`variable = "${local.oidc_host}:sub"`,
		`variable = "${local.oidc_host}:aud"`,
	} {
		if !strings.Contains(bank, want) {
			t.Errorf("bank.tf has no %q", want)
		}
	}
	if regexp.MustCompile(`(?m)^\s*mode\s*=\s*"COMPLIANCE"`).MatchString(bank) {
		t.Error("bank.tf locks the witness in COMPLIANCE mode: no teardown could delete it for the lock's 30 days")
	}
	deny := regexp.MustCompile(`(?s)sid\s*=\s*"WitnessDenyErase"\s*effect\s*=\s*"Deny"\s*actions\s*=\s*\[([^\]]*)\]`).FindStringSubmatch(bank)
	if deny == nil || !strings.Contains(deny[1], `"s3:BypassGovernanceRetention"`) || !strings.Contains(deny[1], `"s3:DeleteObjectVersion"`) {
		t.Errorf("the node role is not denied the governance bypass and version deletes: %v", deny)
	}

	main := read("terraform", "main.tf") + read("terraform", "variables.tf")
	for _, want := range []string{
		// Any other account's credentials are refused, a destroy too.
		`allowed_account_ids = var.aws_account == "" ? null : [var.aws_account]`,
		// us-east-1 only, and the cluster outlives nothing of its timer.
		`condition     = var.region == "us-east-1"`,
		`depends_on = [aws_iam_role_policy_attachment.cluster, aws_scheduler_schedule.teardown, aws_iam_role_policy.teardown]`,
	} {
		if !strings.Contains(main, want) {
			t.Errorf("the Terraform has no %q", want)
		}
	}
	cl := read("cluster.sh")
	for _, want := range []string{`aws_account: $account, region: "us-east-1",`, "same_account \"$sd/run.tfvars.json\"", "region_only"} {
		if !strings.Contains(cl, want) {
			t.Errorf("cluster.sh has no %q", want)
		}
	}
	td := read("terraform", "teardown.tf")
	for _, want := range []string{
		`variable = "aws:ResourceTag/aerol:run"`,
		`variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"`,
		`compute   = { at = local.teardown_t, phase = "compute" }`,
		`phase = "cluster" }`,
		`resource "aws_scheduler_schedule" "teardown"`,
		// Its log group carries the run's tags (reap.sh judges it on them).
		`resource "aws_cloudwatch_log_group" "teardown"`,
		"TTL = var.ttl",
	} {
		if !strings.Contains(td, want) {
			t.Errorf("teardown.tf has no %q", want)
		}
	}
	if regexp.MustCompile(`(?s)"ec2:TerminateInstances"\]\s*resources\s*=\s*\["\*"\]\s*\}`).MatchString(td) {
		t.Error("the teardown role may terminate any instance, not only this run's")
	}

	sum := sha256.Sum256([]byte(read("terraform", "lb-controller-iam-policy.json")))
	if m := regexp.MustCompile(`LBC_POLICY_SHA256=([0-9a-f]{64})`).FindStringSubmatch(read("eks-bank.sh")); m == nil || m[1] != hex.EncodeToString(sum[:]) {
		t.Errorf("lb-controller-iam-policy.json is sha256 %x; eks-bank.sh pins %v", sum, m)
	}

	karp := read("drills-eks", "karpenter.yaml")
	for _, want := range []string{"aerol:run: \"@@NAME@@\"", "aerol:ttl: \"@@TTL@@\"", "httpPutResponseHopLimit: 1",
		"httpTokens: required", "expireAfter: Never", `limits: { cpu: "@@LIMIT_CPU@@" }`, "consolidationPolicy: WhenEmpty"} {
		if !strings.Contains(karp, want) {
			t.Errorf("drills-eks/karpenter.yaml has no %q", want)
		}
	}
}

// fakeBoto3 is a stand-in for boto3 that records every call the teardown
// Lambda makes, with the instances, node groups and load balancers given in
// FAKE_STATE.
const fakeBoto3 = `import json, os
LOG = os.environ["FAKE_LOG"]
STATE = json.loads(os.environ.get("FAKE_STATE", "{}"))
def rec(*a):
    with open(LOG, "a") as f:
        f.write(json.dumps(a) + "\n")
class _Exc:
    class NoSuchEntityException(Exception): pass
    class ResourceNotFoundException(Exception): pass
class _Pages:
    def __init__(self, name): self.name = name
    def paginate(self, **kw):
        rec("paginate", self.name, kw)
        if self.name == "describe_instances":
            return [{"Reservations": [{"Instances": [{"InstanceId": i} for i in STATE.get("instances", [])]}]}]
        if self.name == "describe_volumes":
            return [{"Volumes": [{"VolumeId": v} for v in STATE.get("volumes", [])]}]
        return [{"LoadBalancers": [{"LoadBalancerArn": a} for a in STATE.get("lbs", {})]}]
class _Client:
    exceptions = _Exc
    def get_paginator(self, name): return _Pages(name)
    def list_role_policies(self, RoleName): rec("list_role_policies", RoleName); return {"PolicyNames": ["karpenter"]}
    def delete_role_policy(self, **kw): rec("delete_role_policy", kw)
    def terminate_instances(self, InstanceIds): rec("terminate_instances", InstanceIds)
    def list_nodegroups(self, clusterName): rec("list_nodegroups", clusterName); return {"nodegroups": STATE.get("nodegroups", [])}
    def delete_nodegroup(self, **kw): rec("delete_nodegroup", kw)
    def delete_volume(self, VolumeId): rec("delete_volume", VolumeId)
    def describe_tags(self, ResourceArns):
        return {"TagDescriptions": [{"ResourceArn": a, "Tags": [{"Key": k, "Value": v} for k, v in STATE["lbs"][a].items()]} for a in ResourceArns]}
    def delete_load_balancer(self, LoadBalancerArn): rec("delete_load_balancer", LoadBalancerArn)
    def delete_cluster(self, name): rec("delete_cluster", name)
def client(service): return _Client()
`

// The teardown Lambda, each phase AWS calls it with: scale-cap takes
// Karpenter's rights and ends this run's Karpenter machines and nothing
// else; compute also deletes the node groups and this cluster's load
// balancers (not another cluster's); cluster deletes the cluster only once
// no node group is left.
func TestEKSBankTeardownLambdaPhases(t *testing.T) {
	needTools(t, "python3")
	fake := t.TempDir()
	if err := os.WriteFile(filepath.Join(fake, "boto3.py"), []byte(fakeBoto3), 0o644); err != nil {
		t.Fatal(err)
	}
	lambdaDir := filepath.Join(integrationDir(t), "k8s", "terraform", "lambda")
	state := map[string]any{
		"instances":  []string{"i-1", "i-2"},
		"volumes":    []string{"vol-1"},
		"nodegroups": []string{"system"},
		"lbs": map[string]map[string]string{
			"arn:lb/ours": {"elbv2.k8s.aws/cluster": "bank-1", "aerol:ttl": "2026-11-18T00:00:00Z"},
			// An older run of the same name: reap.sh's to judge, not this run's.
			"arn:lb/older":  {"elbv2.k8s.aws/cluster": "bank-1", "aerol:ttl": "2026-01-01T00:00:00Z"},
			"arn:lb/theirs": {"elbv2.k8s.aws/cluster": "bank-prod"},
		},
	}
	call := func(phase string, st map[string]any) string {
		t.Helper()
		log := filepath.Join(t.TempDir(), "calls.jsonl")
		raw, _ := json.Marshal(st)
		cmd := exec.Command("python3", "-I", "-c",
			"import sys; sys.path[:0] = sys.argv[1:3]; import teardown; print(teardown.handler({'phase': sys.argv[3]}, None))",
			fake, lambdaDir, phase)
		cmd.Env = append(os.Environ(), "CLUSTER=bank-1", "KARPENTER_ROLE=bank-1-karpenter", "FAKE_LOG="+log, "FAKE_STATE="+string(raw),
			"SECOND_SWEEP_DELAY=0", "TTL=2026-11-18T00:00:00Z")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", phase, err, out)
		}
		return readLog(t, log)
	}
	// This run's name and its TTL: an older run's leftovers of the same name
	// are reap.sh's to judge.
	ownsOnly := `"Name": "tag:aerol:run", "Values": ["bank-1"]}, {"Name": "tag:aerol:ttl", "Values": ["2026-11-18T00:00:00Z"]`
	capCalls := call("scale-cap", state)
	for _, want := range []string{`"delete_role_policy", {"RoleName": "bank-1-karpenter", "PolicyName": "karpenter"}`,
		ownsOnly, `"Name": "tag-key", "Values": ["karpenter.sh/nodepool"]`, `["terminate_instances", ["i-1", "i-2"]]`} {
		if !strings.Contains(capCalls, want) {
			t.Errorf("scale-cap: no %s in\n%s", want, capCalls)
		}
	}
	// Karpenter may still be launching one when it loses its rights: the
	// machines are ended a second time.
	if n := strings.Count(capCalls, `["terminate_instances", ["i-1", "i-2"]]`); n != 2 {
		t.Errorf("scale-cap ended the machines %d times, want 2 (a sweep after the rights are gone)", n)
	}
	for _, not := range []string{"delete_nodegroup", "delete_load_balancer", "delete_cluster", "delete_volume"} {
		if strings.Contains(capCalls, not) {
			t.Errorf("scale-cap went past Karpenter's machines: %s", not)
		}
	}

	compute := call("compute", state)
	for _, want := range []string{ownsOnly, `"delete_nodegroup", {"clusterName": "bank-1", "nodegroupName": "system"}`, `["delete_load_balancer", "arn:lb/ours"]`} {
		if !strings.Contains(compute, want) {
			t.Errorf("compute: no %s in\n%s", want, compute)
		}
	}
	if strings.Contains(compute, "arn:lb/theirs") || strings.Contains(compute, "arn:lb/older") || strings.Contains(compute, "delete_cluster") || strings.Contains(compute, "delete_volume") {
		t.Errorf("compute deleted another cluster's load balancer or the cluster:\n%s", compute)
	}

	if c := call("cluster", state); strings.Contains(c, "delete_cluster") {
		t.Errorf("cluster deleted the cluster while a node group was left:\n%s", c)
	}
	empty := map[string]any{"instances": []string{}, "volumes": []string{"vol-1"}, "nodegroups": []string{}, "lbs": map[string]map[string]string{}}
	if c := call("cluster", empty); !strings.Contains(c, `["delete_cluster", "bank-1"]`) || !strings.Contains(c, `["delete_volume", "vol-1"]`) {
		t.Errorf("cluster did not delete the cluster once its node groups were gone, and the run's unattached volumes:\n%s", c)
	}
}
