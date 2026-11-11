package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const k8sIMDSCheck = "worker machines allow IMDSv2 only, with a hop limit of 1"

func k8sIMDSAnswer(id, tokens string, hops int, endpoint string) string {
	return fmt.Sprintf(`{"Reservations":[{"Instances":[{"InstanceId":%q,"MetadataOptions":{"HttpTokens":%q,"HttpPutResponseHopLimit":%d,"HttpEndpoint":%q}}]}]}`, id, tokens, hops, endpoint)
}

// Each seeded IMDS setting fails, the service turned off passes, and with
// no aws CLI, no credentials or no EC2 machine the check is skipped.
func TestK8sIMDS(t *testing.T) {
	with := func(edit func(*fakeK8s)) *fakeK8s {
		f := goodK8s()
		edit(f)
		return f
	}
	for _, tc := range []struct {
		name, want string
		f          *fakeK8s
		noAWS      bool // the aws CLI must not be called
	}{
		{name: "IMDSv1 on", want: "fail: ip-10-0-1-5.ec2.internal (i-0abc): IMDSv1 is on (HttpTokens optional, want required)",
			f: with(func(f *fakeK8s) { f.awsOut = k8sIMDSAnswer("i-0abc", "optional", 1, "enabled") })},
		{name: "hop limit 2", want: "fail: ip-10-0-1-5.ec2.internal (i-0abc): hop limit 2, want 1",
			f: with(func(f *fakeK8s) { f.awsOut = k8sIMDSAnswer("i-0abc", "required", 2, "enabled") })},
		{name: "both", want: "fail: ip-10-0-1-5.ec2.internal (i-0abc): IMDSv1 is on (HttpTokens optional, want required), hop limit 2, want 1",
			f: with(func(f *fakeK8s) { f.awsOut = k8sIMDSAnswer("i-0abc", "optional", 2, "enabled") })},
		{name: "the service turned off", want: "pass: 1 EC2 instance(s)",
			f: with(func(f *fakeK8s) { f.awsOut = k8sIMDSAnswer("i-0abc", "optional", 2, "disabled") })},
		{name: "no metadata options", want: "fail: ip-10-0-1-5.ec2.internal (i-0abc): no metadata options in the answer",
			f: with(func(f *fakeK8s) { f.awsOut = `{"Reservations":[{"Instances":[{"InstanceId":"i-0abc"}]}]}` })},
		{name: "the instance not in the answer", want: "fail: ip-10-0-1-5.ec2.internal (i-0abc): not in the answer",
			f: with(func(f *fakeK8s) { f.awsOut = `{"Reservations":[]}` })},
		{name: "the credentials refused", want: "fail: aws ec2 describe-instances: exit status 254: An error occurred (UnauthorizedOperation)",
			f: with(func(f *fakeK8s) { f.awsErr = errors.New("exit status 254: An error occurred (UnauthorizedOperation)") })},
		{name: "aws output not JSON", want: "fail: aws output",
			f: with(func(f *fakeK8s) { f.awsOut = "nope" })},
		{name: "the nodes unreadable", want: "fail: reading the nodes: forbidden", noAWS: true,
			f: with(func(f *fakeK8s) { f.nodes = "" })},

		{name: "no aws CLI", want: "skip: no aws CLI on PATH; the IMDS settings of ip-10-0-1-5.ec2.internal were not read",
			f: with(func(f *fakeK8s) { f.awsErr = errK8sNoAWSCLI })},
		{name: "no AWS credentials", want: "skip: no AWS credentials: Unable to locate credentials",
			f: with(func(f *fakeK8s) { f.awsErr = fmt.Errorf("%w: Unable to locate credentials", errK8sNoAWSCredentials) })},
		{name: "a kind machine", want: `skip: not EC2 instances, so not read: ip-10-0-1-5.ec2.internal (providerID "kind://docker/aerolvm/x"); 0 EC2 instance(s) passed`, noAWS: true,
			f: with(func(f *fakeK8s) { f.nodes = "ip-10-0-1-5.ec2.internal\tkind://docker/aerolvm/x\n" })},
		{name: "a machine with no providerID", want: `skip: not EC2 instances, so not read: ip-10-0-1-5.ec2.internal (providerID "")`, noAWS: true,
			f: with(func(f *fakeK8s) { f.nodes = "other\taws:///us-east-1a/i-9\n" })},
		{name: "the worker not on a machine yet", want: "skip: no worker pod is on a machine yet", noAWS: true,
			f: with(func(f *fakeK8s) {
				f.pods = strings.Replace(k8sGoodPods, `"nodeName":"ip-10-0-1-5.ec2.internal",`, ``, 1)
			})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := k8sResults(k8sVerify(context.Background(), tc.f.env(), k8sOpts))[k8sIMDSCheck]
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if tc.noAWS && len(tc.f.awsCalls) != 0 {
				t.Fatalf("aws was called: %q", tc.f.awsCalls)
			}
		})
	}
}

// Machines are read per region, a hundred at a time, and a machine that is
// not on EC2 next to ones that pass leaves the check skipped, not passed.
func TestK8sIMDSBatches(t *testing.T) {
	var pods []k8sPod
	var nodes strings.Builder
	add := func(node, providerID string) {
		var p k8sPod
		p.Metadata.Labels = map[string]string{k8sComponent: "worker"}
		p.Spec.NodeName = node
		pods = append(pods, p)
		fmt.Fprintf(&nodes, "%s\t%s\n", node, providerID)
	}
	for i := range 205 {
		add(fmt.Sprintf("n%03d", i), fmt.Sprintf("aws:///us-east-1%c/i-%03d", 'a'+i%3, i))
	}
	add("eu", "aws:///eu-west-1a/i-eu")
	var calls [][]string
	env := k8sEnv{
		kubectl: func(context.Context, ...string) ([]byte, error) { return []byte(nodes.String()), nil },
		aws: func(_ context.Context, args ...string) ([]byte, error) {
			calls = append(calls, args)
			var answer strings.Builder
			answer.WriteString(`{"Reservations":[{"Instances":[`)
			for i, id := range args[7:] {
				if i > 0 {
					answer.WriteString(",")
				}
				fmt.Fprintf(&answer, `{"InstanceId":%q,"MetadataOptions":{"HttpTokens":"required","HttpPutResponseHopLimit":1}}`, id)
			}
			answer.WriteString(`]}]}`)
			return []byte(answer.String()), nil
		},
	}
	got := k8sIMDS(context.Background(), env, pods)
	if got.Result != k8sPass || got.Detail != "206 EC2 instance(s)" {
		t.Fatalf("%+v", got)
	}
	var shape []string
	for _, c := range calls {
		shape = append(shape, fmt.Sprintf("%s:%d", c[3], len(c)-7))
	}
	if strings.Join(shape, " ") != "eu-west-1:1 us-east-1:100 us-east-1:100 us-east-1:5" {
		t.Fatalf("calls %v", shape)
	}

	add("kind-0", "kind://docker/aerolvm/kind-0")
	got = k8sIMDS(context.Background(), env, pods)
	if got.Result != k8sSkip || !strings.HasSuffix(got.Detail, "; 206 EC2 instance(s) passed") {
		t.Fatalf("%+v", got)
	}
}

func TestK8sAWSInstance(t *testing.T) {
	for providerID, want := range map[string]string{
		"aws:///us-east-1a/i-0abc":                "us-east-1 i-0abc",
		"aws:///eu-central-1b/i-5":                "eu-central-1 i-5",
		"aws:///us-west-2-lax-1a/i-1":             "us-west-2 i-1",
		"aws:///us-east-1-wl1-bos-wlz-1/i-2":      "us-east-1 i-2",
		"aws:///us-gov-west-1a/i-3":               "us-gov-west-1 i-3",
		"aws:///us-isob-east-1a/i-4":              "us-isob-east-1 i-4",
		"aws:///us-east-1a/abc123/fargate-ip-1-2": "",
		"aws://us-east-1a/i-0abc":                 "",
		"aws:///i-0abc":                           "",
		"aws:///nozone/i-0abc":                    "",
		"kind://docker/aerolvm/x":                 "",
		"azure:///subscriptions/x/vm-0":           "",
		"":                                        "",
	} {
		region, id, ok := k8sAWSInstance(providerID)
		got := ""
		if ok {
			got = region + " " + id
		}
		if got != want {
			t.Errorf("%q = %q, want %q", providerID, got, want)
		}
	}
}

// Missing credentials skip; credentials that were given but refused fail.
func TestAWSFailure(t *testing.T) {
	for _, tc := range []struct {
		code    int
		stderr  string
		noCreds bool
		want    string
	}{
		{253, "\nUnable to locate credentials. You can configure credentials by running \"aws configure\".\n", true, "Unable to locate credentials"},
		{255, "Unable to locate credentials\n", true, "Unable to locate credentials"},
		{253, "", true, "no AWS credentials: "},
		{254, "\nAn error occurred (UnauthorizedOperation) when calling the DescribeInstances operation: You are not authorized\n", false, "exit status 254: An error occurred (UnauthorizedOperation)"},
		{255, "Error when retrieving token from sso: Token has expired and refresh failed\n", false, "exit status 255: Error when retrieving token from sso"},
	} {
		err := awsFailure(tc.code, []byte(tc.stderr))
		if errors.Is(err, errK8sNoAWSCredentials) != tc.noCreds || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("awsFailure(%d, %q) = %v", tc.code, tc.stderr, err)
		}
	}
}

// The real aws call, with a stand-in script on PATH: the pager is off,
// missing credentials and a missing CLI are told apart from a refusal.
func TestK8sRealAWS(t *testing.T) {
	if runtimeGOOS() == "windows" {
		t.Skip("shell stand-ins")
	}
	dir := t.TempDir()
	script := `case "$*" in
*i-nocreds*) echo "Unable to locate credentials. You can configure credentials by running \"aws configure\"." >&2; exit 253;;
*i-refused*) echo "An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation" >&2; exit 254;;
esac
echo "pager=[$AWS_PAGER] $*"`
	if err := os.WriteFile(filepath.Join(dir, "aws"), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("AWS_PAGER", "less")
	env := k8sEnvFor(&app{}, &commonFlags{}, "")
	out, err := env.aws(context.Background(), "ec2", "describe-instances", "--instance-ids", "i-1")
	if err != nil || strings.TrimSpace(string(out)) != "pager=[] ec2 describe-instances --instance-ids i-1" {
		t.Fatalf("aws = %q, %v", out, err)
	}
	if _, err := env.aws(context.Background(), "ec2", "describe-instances", "--instance-ids", "i-nocreds"); !errors.Is(err, errK8sNoAWSCredentials) {
		t.Fatalf("no credentials: %v", err)
	}
	if _, err := env.aws(context.Background(), "ec2", "describe-instances", "--instance-ids", "i-refused"); err == nil || errors.Is(err, errK8sNoAWSCredentials) || !strings.Contains(err.Error(), "UnauthorizedOperation") {
		t.Fatalf("refused: %v", err)
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := env.aws(context.Background(), "ec2", "describe-instances"); !errors.Is(err, errK8sNoAWSCLI) {
		t.Fatalf("no aws CLI: %v", err)
	}
}
