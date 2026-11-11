package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runtimeGOOS() string { return runtime.GOOS }

// A worker pod as the chart makes it: no token, emptyDirs, the API port,
// a sandbox range set by C3, the API token from its Secret, and the edge
// certificate mounted by key (C25).
const k8sGoodPods = `{"items":[{
  "metadata":{"name":"aerolvm-0","labels":{"app.kubernetes.io/name":"aerolvm","app.kubernetes.io/instance":"aerolvm","app.kubernetes.io/component":"worker"}},
  "spec":{
    "automountServiceAccountToken":false,
    "volumes":[{"name":"containerd","emptyDir":{}},{"name":"netns","emptyDir":{}},
      {"name":"edge-tls","secret":{"secretName":"aerolvm-edge-tls","items":[{"key":"tls.crt","path":"tls.crt"},{"key":"tls.key","path":"tls.key"}]}}],
    "containers":[
      {"name":"runtime","image":"ghcr.io/aerol-ai/aerolvm-runtime:v1"},
      {"name":"agent","image":"ghcr.io/aerol-ai/aerolvm:v1","ports":[{"containerPort":21212}],
       "env":[{"name":"SB_CONTAINERD_BRIDGE_SUBNET","value":"10.200.0.0/16"},
         {"name":"SB_PAT_TOKEN","valueFrom":{"secretKeyRef":{"name":"aerolvm-api-token","key":"SB_PAT_TOKEN"}}},
         {"name":"SB_ROUTE_DNS_ADDR","value":"127.0.0.1:53053"}]},
      {"name":"egress","image":"ghcr.io/aerol-ai/aerolvm:v1"}]},
  "status":{"podIP":"10.244.0.12"}}]}`

// The chart's egress NetworkPolicy as the API server returns it (C24),
// with the range a bank opened on purpose, and another app's policy that
// does not select the worker.
const k8sGoodPolicies = `{"items":[{
  "metadata":{"name":"aerolvm-worker-egress"},
  "spec":{
    "podSelector":{"matchLabels":{"app.kubernetes.io/name":"aerolvm","app.kubernetes.io/instance":"aerolvm","app.kubernetes.io/component":"worker"}},
    "policyTypes":["Egress"],
    "egress":[
      {"to":[{"podSelector":{"matchLabels":{"app.kubernetes.io/name":"aerolvm","app.kubernetes.io/instance":"aerolvm"}}}]},
      {"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}},"podSelector":{"matchLabels":{"k8s-app":"kube-dns"}}}],
       "ports":[{"protocol":"UDP","port":53},{"protocol":"TCP","port":53}]},
      {"to":[{"ipBlock":{"cidr":"0.0.0.0/0","except":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","100.64.0.0/10","169.254.0.0/16","10.96.0.1/32"]}}]},
      {"to":[{"ipBlock":{"cidr":"10.50.0.0/16"}},{"ipBlock":{"cidr":"not-a-cidr"}}]}]}},
  {"metadata":{"name":"other-app"},"spec":{"podSelector":{"matchLabels":{"app":"other"}},"policyTypes":["Egress"],"egress":[{}]}}]}`

// The cluster DNS pods, and the API server behind its Service.
const (
	k8sDNSPods      = `{"items":[{"metadata":{"name":"coredns-a"},"status":{"podIP":"10.244.0.3"}},{"metadata":{"name":"coredns-b"},"status":{"podIP":"fd00::3"}},{"metadata":{"name":"coredns-c"},"status":{"podIP":""}}]}`
	k8sAPIEndpoints = `{"items":[{"endpoints":[{"addresses":["172.18.0.2"]},{"addresses":["fd00::2"]}],"ports":[{"port":6443}]}]}`
)

type fakeK8s struct {
	pods         string
	podsErr      error
	apiIP        string
	policies     string
	policiesErr  error
	dnsPods      string
	apiEndpoints string
	cosignErr    map[string]error
	probeOut     map[string]string
	probeErr     error
	commands     []string
	signed       []string
}

// goodK8s is a clean install: every check passes.
func goodK8s() *fakeK8s {
	return &fakeK8s{pods: k8sGoodPods, apiIP: "10.96.0.1", policies: k8sGoodPolicies, dnsPods: k8sDNSPods, apiEndpoints: k8sAPIEndpoints}
}

func (f *fakeK8s) env() k8sEnv {
	// An empty fixture answers like a kubectl without the right to read it.
	answer := func(fixture string) ([]byte, error) {
		if fixture == "" {
			return nil, errors.New("forbidden")
		}
		return []byte(fixture), nil
	}
	return k8sEnv{
		kubectl: func(_ context.Context, args ...string) ([]byte, error) {
			switch {
			case args[0] == "get" && args[1] == "pods" && args[3] == "kube-system":
				return answer(f.dnsPods)
			case args[0] == "get" && args[1] == "pods":
				return []byte(f.pods), f.podsErr
			case args[0] == "get" && args[1] == "svc":
				return []byte(f.apiIP), nil
			case args[0] == "get" && args[1] == "networkpolicies":
				return []byte(f.policies), f.policiesErr
			case args[0] == "get" && args[1] == "endpointslices":
				return answer(f.apiEndpoints)
			}
			return nil, errors.New("unexpected kubectl " + strings.Join(args, " "))
		},
		cosign: func(_ context.Context, image string) error {
			f.signed = append(f.signed, image)
			return f.cosignErr[image]
		},
		probe: func(_ context.Context, image, runtime, command string) (string, error) {
			f.commands = append(f.commands, runtime+" "+image+" "+command)
			return f.probeOut[runtime], f.probeErr
		},
	}
}

func k8sResults(checks []k8sCheck) map[string]string {
	out := map[string]string{}
	for _, c := range checks {
		out[c.Name] = c.Result + ": " + c.Detail
	}
	return out
}

var k8sOpts = k8sVerifyOptions{namespace: "aerolvm", release: "aerolvm", probeImage: "alpine:3.20", probeRuntimes: []string{"docker", "gvisor"}}

func TestK8sVerifyPasses(t *testing.T) {
	f := goodK8s()
	checks := k8sVerify(context.Background(), f.env(), k8sOpts)
	for _, c := range checks {
		if c.Result != k8sPass {
			t.Fatalf("%s: %s %s", c.Name, c.Result, c.Detail)
		}
	}
	if len(checks) != 8 {
		t.Fatalf("%d checks, want 8: %+v", len(checks), checks)
	}
	if strings.Join(f.signed, ",") != "ghcr.io/aerol-ai/aerolvm-runtime:v1,ghcr.io/aerol-ai/aerolvm:v1" {
		t.Fatalf("signatures checked for %v, want each image once", f.signed)
	}
	if len(f.commands) != 2 || !strings.HasPrefix(f.commands[0], "docker alpine:3.20 ") || !strings.HasPrefix(f.commands[1], "gvisor alpine:3.20 ") {
		t.Fatalf("probes %v", f.commands)
	}
	// The worker's ports, the API server at its Service address and at its
	// own address, and a DNS pod's address.
	for _, target := range []string{"10.244.0.12:2220", "10.244.0.12:21212", "10.200.0.1:2220", "10.200.0.1:21212", "10.96.0.1:443", "172.18.0.2:6443", "10.244.0.3:53"} {
		if !strings.Contains(f.commands[0], target+" ") && !strings.Contains(f.commands[0], target+";") {
			t.Errorf("the probe does not try %s: %s", target, f.commands[0])
		}
	}
	if strings.Contains(f.commands[0], "10.88.0.1") {
		t.Error("the default range was probed although the pod sets its own")
	}
	// No sandbox has IPv6, and a pod with no address yet has nothing to try.
	if strings.Contains(f.commands[0], "fd00::") || strings.Contains(f.commands[0], " :53") {
		t.Errorf("an IPv6 or empty address was probed: %s", f.commands[0])
	}
}

const k8sPolicyCheck = "a NetworkPolicy limits the worker pods' egress"

func TestK8sVerifyFailures(t *testing.T) {
	podsWith := func(edit func(string) string) string { return edit(k8sGoodPods) }
	// with is a clean install with one thing changed.
	with := func(edit func(*fakeK8s)) *fakeK8s {
		f := goodK8s()
		edit(f)
		return f
	}
	policiesWith := func(old, repl string) *fakeK8s {
		return with(func(f *fakeK8s) { f.policies = strings.Replace(k8sGoodPolicies, old, repl, 1) })
	}
	for _, tc := range []struct {
		name  string
		f     *fakeK8s
		check string
		want  string
	}{
		{name: "kubectl cannot list", f: &fakeK8s{podsErr: errors.New("forbidden")}, check: "AerolVM pods found", want: "fail: forbidden"},
		{name: "no pods", f: &fakeK8s{pods: `{"items":[]}`}, check: "AerolVM pods found", want: "fail: no pods labelled"},
		{name: "not JSON", f: &fakeK8s{pods: `nope`}, check: "AerolVM pods found", want: "fail: kubectl output"},
		{name: "a host folder", f: &fakeK8s{pods: podsWith(func(s string) string {
			return strings.Replace(s, `{"name":"netns","emptyDir":{}}`, `{"name":"netns","hostPath":{"path":"/run/netns"}}`, 1)
		})}, check: "no folders mounted from the machine", want: "fail: aerolvm-0: netns (/run/netns)"},
		{name: "the token mounted", f: &fakeK8s{pods: podsWith(func(s string) string {
			return strings.Replace(s, `"automountServiceAccountToken":false,`, ``, 1)
		})}, check: "no Kubernetes API credential in the pods", want: "fail: aerolvm-0: automountServiceAccountToken is not false"},
		{name: "a projected token", f: &fakeK8s{pods: podsWith(func(s string) string {
			return strings.Replace(s, `{"name":"containerd","emptyDir":{}}`, `{"name":"kube-api-access","projected":{"sources":[{"serviceAccountToken":{"path":"token"}}]}}`, 1)
		})}, check: "no Kubernetes API credential in the pods", want: "fail: aerolvm-0: volume kube-api-access holds a service account token"},
		{name: "a Secret volume with every key", f: &fakeK8s{pods: podsWith(func(s string) string {
			return strings.Replace(s, `,"items":[{"key":"tls.crt","path":"tls.crt"},{"key":"tls.key","path":"tls.key"}]`, ``, 1)
		})}, check: "no DNS provider token in the pods", want: "fail: aerolvm-0: volume edge-tls mounts every key of Secret aerolvm-edge-tls"},
		{name: "a Secret volume with another key", f: &fakeK8s{pods: podsWith(func(s string) string {
			return strings.Replace(s, `{"key":"tls.key","path":"tls.key"}`, `{"key":"api-token","path":"token"}`, 1)
		})}, check: "no DNS provider token in the pods", want: "fail: aerolvm-0: volume edge-tls mounts key api-token of Secret aerolvm-edge-tls"},
		{name: "a projected Secret", f: &fakeK8s{pods: podsWith(func(s string) string {
			return strings.Replace(s, `{"name":"containerd","emptyDir":{}}`, `{"name":"creds","projected":{"sources":[{"secret":{"name":"route53","items":[{"key":"secret-access-key"}]}}]}}`, 1)
		})}, check: "no DNS provider token in the pods", want: "fail: aerolvm-0: volume creds mounts key secret-access-key of Secret route53"},
		{name: "a provider token in the environment", f: &fakeK8s{pods: podsWith(func(s string) string {
			return strings.Replace(s, `{"name":"SB_ROUTE_DNS_ADDR"`, `{"name":"CLOUDFLARE_API_TOKEN","value":"x"},{"name":"SB_ROUTE_DNS_ADDR"`, 1)
		})}, check: "no DNS provider token in the pods", want: "fail: aerolvm-0/agent: environment variable CLOUDFLARE_API_TOKEN"},
		{name: "Caddy's DNS token in an init container", f: &fakeK8s{pods: podsWith(func(s string) string {
			return strings.Replace(s, `"containers":[`, `"initContainers":[{"name":"setup","image":"ghcr.io/aerol-ai/aerolvm:v1","env":[{"name":"SB_DNS_API_TOKEN","value":"x"}]}],"containers":[`, 1)
		})}, check: "no DNS provider token in the pods", want: "fail: aerolvm-0/setup: environment variable SB_DNS_API_TOKEN"},
		{name: "a Secret loaded whole", f: &fakeK8s{pods: podsWith(func(s string) string {
			return strings.Replace(s, `{"name":"egress","image":"ghcr.io/aerol-ai/aerolvm:v1"}`, `{"name":"egress","image":"ghcr.io/aerol-ai/aerolvm:v1","envFrom":[{"configMapRef":{"name":"settings"}},{"secretRef":{"name":"dns"}}]}`, 1)
		})}, check: "no DNS provider token in the pods", want: "fail: aerolvm-0/egress: Secret dns loaded whole into the environment"},
		{name: "an unsigned init container image", f: &fakeK8s{pods: podsWith(func(s string) string {
			return strings.Replace(s, `"containers":[`, `"initContainers":[{"name":"setup","image":"ghcr.io/x/setup:v1"}],"containers":[`, 1)
		}), cosignErr: map[string]error{"ghcr.io/x/setup:v1": errors.New("no signatures found")}}, check: "images signed by the AerolVM release workflow", want: "fail: ghcr.io/x/setup:v1 (no signatures found)"},
		{name: "an unsigned image", f: &fakeK8s{pods: k8sGoodPods, cosignErr: map[string]error{"ghcr.io/aerol-ai/aerolvm:v1": errors.New("no signatures found")}}, check: "images signed by the AerolVM release workflow", want: "fail: ghcr.io/aerol-ai/aerolvm:v1 (no signatures found)"},
		{name: "a sandbox reaches the API", f: with(func(f *fakeK8s) { f.probeOut = map[string]string{"gvisor": "10.244.0.12:21212\n10.96.0.1:443\n"} }), check: "a gvisor sandbox cannot reach the worker, another pod or the Kubernetes API", want: "fail: reached 10.244.0.12:21212, 10.96.0.1:443"},
		{name: "a sandbox reaches a pod", f: with(func(f *fakeK8s) { f.probeOut = map[string]string{"docker": "10.244.0.3:53\n"} }), check: "a docker sandbox cannot reach the worker, another pod or the Kubernetes API", want: "fail: reached 10.244.0.3:53"},
		{name: "the probe cannot run", f: with(func(f *fakeK8s) { f.probeErr = errors.New("not logged in") }), check: "a docker sandbox cannot reach the worker, another pod or the Kubernetes API", want: "fail: probe: not logged in"},
		{name: "no DNS pod to probe", f: with(func(f *fakeK8s) { f.dnsPods = "" }), check: "another pod's address to probe", want: "skip: no cluster DNS pod"},
		{name: "DNS pods not JSON", f: with(func(f *fakeK8s) { f.dnsPods = "nope" }), check: "another pod's address to probe", want: "skip: no cluster DNS pod"},

		// C24: the worker pod's egress NetworkPolicy.
		{name: "policies cannot be listed", f: with(func(f *fakeK8s) { f.policiesErr = errors.New("forbidden") }), check: k8sPolicyCheck, want: "fail: forbidden"},
		{name: "policies not JSON", f: with(func(f *fakeK8s) { f.policies = "nope" }), check: k8sPolicyCheck, want: "fail: kubectl output"},
		{name: "no policy", f: with(func(f *fakeK8s) { f.policies = `{"items":[]}` }), check: k8sPolicyCheck, want: "fail: aerolvm-0: no NetworkPolicy limits its egress"},
		{name: "a policy for other pods", f: policiesWith(`"app.kubernetes.io/component":"worker"}},`, `"app.kubernetes.io/component":"gateway"}},`), check: k8sPolicyCheck, want: "fail: aerolvm-0: no NetworkPolicy limits its egress"},
		{name: "an ingress-only policy", f: policiesWith(`"policyTypes":["Egress"],`, `"policyTypes":["Ingress"],`), check: k8sPolicyCheck, want: "fail: aerolvm-0: no NetworkPolicy limits its egress"},
		{name: "a rule open to every address", f: policiesWith(`{"to":[{"ipBlock":{"cidr":"10.50.0.0/16"}},`, `{"ports":[{"port":443}]},{"to":[`), check: k8sPolicyCheck, want: "fail: aerolvm-0: NetworkPolicy aerolvm-worker-egress lets the pod reach every address"},
		{name: "the internet rule with no except", f: policiesWith(`,"except":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","100.64.0.0/10","169.254.0.0/16","10.96.0.1/32"]`, ``), check: k8sPolicyCheck, want: "fail: aerolvm-0: NetworkPolicy aerolvm-worker-egress lets the pod reach 10.0.0.0/8 (ipBlock 0.0.0.0/0)"},
		{name: "the internet rule keeps a pod range open", f: policiesWith(`"100.64.0.0/10",`, ``), check: k8sPolicyCheck, want: "fail: aerolvm-0: NetworkPolicy aerolvm-worker-egress lets the pod reach 100.64.0.0/10 (ipBlock 0.0.0.0/0)"},
		{name: "a whole private range opened", f: policiesWith(`"cidr":"10.50.0.0/16"`, `"cidr":"172.16.0.0/12"`), check: k8sPolicyCheck, want: "fail: aerolvm-0: NetworkPolicy aerolvm-worker-egress lets the pod reach 172.16.0.0/12 (ipBlock 172.16.0.0/12)"},
		{name: "IPv6 opened with its private range", f: policiesWith(`"cidr":"10.50.0.0/16"`, `"cidr":"::/0"`), check: k8sPolicyCheck, want: "fail: aerolvm-0: NetworkPolicy aerolvm-worker-egress lets the pod reach fc00::/7 (ipBlock ::/0)"},
		{name: "every pod in the cluster", f: policiesWith(`{"ipBlock":{"cidr":"10.50.0.0/16"}}`, `{"namespaceSelector":{}}`), check: k8sPolicyCheck, want: "fail: aerolvm-0: NetworkPolicy aerolvm-worker-egress lets the pod reach every pod in the cluster"},
		{name: "no worker pod", f: with(func(f *fakeK8s) {
			f.pods = strings.Replace(k8sGoodPods, `,"app.kubernetes.io/component":"worker"`, ``, 1)
		}), check: k8sPolicyCheck, want: "fail: no worker pod"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := k8sResults(k8sVerify(context.Background(), tc.f.env(), k8sOpts))[tc.check]
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("%s = %q, want %q", tc.check, got, tc.want)
			}
		})
	}
}

func TestK8sVerifySkipsSignatures(t *testing.T) {
	f := &fakeK8s{pods: k8sGoodPods}
	o := k8sOpts
	o.skipSignatures = true
	got := k8sResults(k8sVerify(context.Background(), f.env(), o))["images signed by the AerolVM release workflow"]
	if !strings.HasPrefix(got, "skip: --skip-signatures") || len(f.signed) != 0 {
		t.Fatalf("got %q, signed %v", got, f.signed)
	}
}

// The command end to end, with the cluster faked and the probe going
// through the CLI's real API path to the fake AerolVM server.
func TestK8sVerifyCommand(t *testing.T) {
	h := newHarness(t)
	f := goodK8s()
	orig := k8sEnvFor
	t.Cleanup(func() { k8sEnvFor = orig })
	var realProbe func(context.Context, string, string, string) (string, error)
	k8sEnvFor = func(a *app, c *commonFlags, kubeContext string) k8sEnv {
		if kubeContext != "kind-x" {
			t.Errorf("kube context %q, want kind-x", kubeContext)
		}
		env := f.env()
		realProbe = orig(a, c, kubeContext).probe
		return env
	}

	if code := h.run("k8s", "verify", "--kube-context", "kind-x", "--json"); code != exitOK {
		t.Fatalf("exit %d: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	var out struct {
		OK     bool       `json:"ok"`
		Checks []k8sCheck `json:"checks"`
	}
	h.jsonOut(&out)
	if !out.OK || len(out.Checks) != 8 {
		t.Fatalf("%+v", out)
	}

	f.probeOut = map[string]string{"docker": "10.96.0.1:443"}
	if code := h.run("k8s", "verify", "--kube-context", "kind-x", "--probe-runtimes", "docker"); code != exitError {
		t.Fatalf("a reachable API exited %d, want 1", code)
	}
	if !strings.Contains(h.stdout.String(), "FAIL") || !strings.Contains(h.stderr.String(), "1 check(s) failed") {
		t.Fatalf("stdout %q stderr %q", h.stdout.String(), h.stderr.String())
	}

	// The real probe: create, run, destroy through the API.
	out2, err := realProbe(context.Background(), "alpine:3.20", "", "echo probed")
	if err != nil || !strings.Contains(out2, "probed") {
		t.Fatalf("probe = %q, %v", out2, err)
	}
	var listed []map[string]any
	if code := h.run("list", "--json"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	_ = json.Unmarshal([]byte(h.stdout.String()), &listed)
	if len(listed) != 0 {
		t.Fatalf("the probe sandbox was left behind: %v", listed)
	}

	for _, args := range [][]string{{"k8s"}, {"k8s", "status"}, {"k8s", "verify", "extra"}, {"k8s", "verify", "--nope"}} {
		if code := h.run(args...); code != exitUsage {
			t.Errorf("%v exited %d, want %d", args, code, exitUsage)
		}
	}
}

// The real kubectl and cosign calls, with stand-in scripts on PATH.
func TestK8sRealCommands(t *testing.T) {
	if runtimeGOOS() == "windows" {
		t.Skip("shell stand-ins")
	}
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("kubectl", `case "$*" in *fail*) echo "error: forbidden" >&2; exit 1;; esac; echo "args: $*"`)
	write("cosign", `case "$2" in *unsigned*) echo "Error: no signatures found" >&2; exit 1;; esac; exit 0`)
	t.Setenv("PATH", dir)
	env := k8sEnvFor(&app{}, &commonFlags{}, "kind-x")

	out, err := env.kubectl(context.Background(), "get", "pods")
	if err != nil || strings.TrimSpace(string(out)) != "args: --context kind-x get pods" {
		t.Fatalf("kubectl = %q, %v", out, err)
	}
	if _, err := env.kubectl(context.Background(), "get", "fail"); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("a failing kubectl: %v", err)
	}
	if out, err := k8sEnvFor(&app{}, &commonFlags{}, "").kubectl(context.Background(), "version"); err != nil || strings.TrimSpace(string(out)) != "args: version" {
		t.Fatalf("no context: %q, %v", out, err)
	}
	if err := env.cosign(context.Background(), "ghcr.io/aerol-ai/aerolvm:v1"); err != nil {
		t.Fatalf("a signed image: %v", err)
	}
	if err := env.cosign(context.Background(), "ghcr.io/x/unsigned:v1"); err == nil || !strings.Contains(err.Error(), "no signatures found") {
		t.Fatalf("an unsigned image: %v", err)
	}
}

// A pod not yet given an address is probed on the bridge gateway only, and
// a probe without an AerolVM login fails with the reason.
func TestK8sProbeEdges(t *testing.T) {
	f := &fakeK8s{pods: strings.Replace(k8sGoodPods, `"podIP":"10.244.0.12"`, `"podIP":""`, 1)}
	k8sVerify(context.Background(), f.env(), k8sOpts)
	if strings.Contains(f.commands[0], ":21212 :") || strings.Contains(f.commands[0], " :2220") {
		t.Fatalf("an empty address was probed: %s", f.commands[0])
	}
	if !strings.Contains(f.commands[0], "10.200.0.1:21212") {
		t.Fatalf("the bridge gateway was not probed: %s", f.commands[0])
	}
	// The API server's own addresses unreadable or not JSON: the probe
	// still tries its Service address.
	for _, endpoints := range []string{"", "nope"} {
		f := goodK8s()
		f.apiEndpoints = endpoints
		k8sVerify(context.Background(), f.env(), k8sOpts)
		if strings.Contains(f.commands[0], ":6443") || !strings.Contains(f.commands[0], "10.96.0.1:443") {
			t.Fatalf("endpoints %q: %s", endpoints, f.commands[0])
		}
	}

	h := newHarness(t)
	delete(h.env, "SB_API_URL")
	delete(h.env, "SB_PAT_TOKEN")
	t.Setenv("HOME", t.TempDir())
	if _, err := k8sEnvFor(h.app, &commonFlags{}, "").probe(context.Background(), "alpine:3.20", "", "true"); err == nil {
		t.Fatal("a probe ran without an AerolVM login")
	}
}

// TestK8sPolicySelection: a policy selects the worker pod the way
// Kubernetes does (labels and expressions), and with no policyTypes it
// limits egress only when it has egress rules.
func TestK8sPolicySelection(t *testing.T) {
	worker := map[string]string{"app": "aerolvm", "tier": "worker"}
	sel := func(raw string) k8sLabelSelector {
		var s k8sLabelSelector
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	for raw, want := range map[string]bool{
		`{}`:                                true,
		`{"matchLabels":{"app":"aerolvm"}}`: true,
		`{"matchLabels":{"app":"other"}}`:   false,
		`{"matchLabels":{"zone":""}}`:       false, // a missing label is not an empty one
		`{"matchExpressions":[{"key":"tier","operator":"In","values":["worker","gateway"]}]}`: true,
		`{"matchExpressions":[{"key":"tier","operator":"In","values":["gateway"]}]}`:          false,
		`{"matchExpressions":[{"key":"tier","operator":"NotIn","values":["gateway"]}]}`:       true,
		`{"matchExpressions":[{"key":"tier","operator":"NotIn","values":["worker"]}]}`:        false,
		`{"matchExpressions":[{"key":"app","operator":"Exists"}]}`:                            true,
		`{"matchExpressions":[{"key":"zone","operator":"Exists"}]}`:                           false,
		`{"matchExpressions":[{"key":"zone","operator":"DoesNotExist"}]}`:                     true,
		`{"matchExpressions":[{"key":"app","operator":"DoesNotExist"}]}`:                      false,
		`{"matchExpressions":[{"key":"app","operator":"Gt","values":["1"]}]}`:                 false,
	} {
		if got := sel(raw).matches(worker); got != want {
			t.Errorf("%s matches = %v, want %v", raw, got, want)
		}
	}
	var np k8sNetworkPolicy
	if np.limitsEgress() {
		t.Fatal("no types and no egress rules limits nothing")
	}
	if err := json.Unmarshal([]byte(`{"spec":{"egress":[{"to":[{"ipBlock":{"cidr":"10.50.0.0/16"}}]}]}}`), &np); err != nil || !np.limitsEgress() || np.opens() != "" {
		t.Fatalf("egress rules with no types limit egress: %v %q", err, np.opens())
	}
}

// An older cosign finds no signature on a signed release image: the failure
// says which cosign to use.
func TestCosignFailure(t *testing.T) {
	err := cosignFailure(errors.New("exit status 1"), []byte("Error: no signatures found\nmain.go:69: error during command execution: no signatures found\n"))
	if !strings.Contains(err.Error(), "cosign v3 or later") {
		t.Fatalf("err = %v, want the cosign v3 hint", err)
	}
	err = cosignFailure(errors.New("exit status 1"), []byte("Error: none of the expected identities matched\n"))
	if strings.Contains(err.Error(), "cosign v3") || !strings.Contains(err.Error(), "none of the expected identities matched") {
		t.Fatalf("err = %v, want the last line only", err)
	}
}
