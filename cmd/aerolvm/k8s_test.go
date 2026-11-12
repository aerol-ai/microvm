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
// a sandbox range set by C3, the API token from its Secret, the edge
// certificate mounted by key (C25), runtime and agent privileged, and an
// EC2 machine under it. Another app's pod in the namespace is not checked.
const k8sGoodPods = `{"items":[{
  "metadata":{"name":"aerolvm-0","labels":{"app.kubernetes.io/name":"aerolvm","app.kubernetes.io/instance":"aerolvm","app.kubernetes.io/component":"worker"}},
  "spec":{
    "nodeName":"ip-10-0-1-5.ec2.internal",
    "automountServiceAccountToken":false,
    "volumes":[{"name":"containerd","emptyDir":{}},{"name":"netns","emptyDir":{}},
      {"name":"edge-tls","secret":{"secretName":"aerolvm-edge-tls","items":[{"key":"tls.crt","path":"tls.crt"},{"key":"tls.key","path":"tls.key"}]}}],
    "containers":[
      {"name":"runtime","image":"ghcr.io/aerol-ai/aerolvm-runtime:v1","securityContext":{"privileged":true}},
      {"name":"agent","image":"ghcr.io/aerol-ai/aerolvm:v1","ports":[{"containerPort":21212}],"securityContext":{"privileged":true},
       "env":[{"name":"SB_CONTAINERD_BRIDGE_SUBNET","value":"10.200.0.0/16"},
         {"name":"SB_PAT_TOKEN","valueFrom":{"secretKeyRef":{"name":"aerolvm-api-token","key":"SB_PAT_TOKEN"}}},
         {"name":"SB_ROUTE_DNS_ADDR","value":"127.0.0.1:53053"}]},
      {"name":"egress","image":"ghcr.io/aerol-ai/aerolvm:v1","securityContext":{"privileged":false}}]},
  "status":{"podIP":"10.244.0.12"}},
  {"metadata":{"name":"other-install-0","labels":{"app.kubernetes.io/name":"aerolvm","app.kubernetes.io/instance":"other","app.kubernetes.io/component":"worker"}},
   "spec":{"containers":[{"name":"runtime","image":"ghcr.io/x/unsigned:v1","securityContext":{"privileged":true}}],"volumes":[{"name":"h","hostPath":{"path":"/"}}]}}]}`

// The machine under the worker pod, and its IMDS settings as the aws CLI
// prints them.
const (
	k8sGoodNodes = "ip-10-0-1-5.ec2.internal\taws:///us-east-1a/i-0abc\nkind-node\tkind://docker/aerolvm/kind-node\n"
	k8sGoodIMDS  = `{"Reservations":[{"Instances":[{"InstanceId":"i-0abc","MetadataOptions":{"HttpTokens":"required","HttpPutResponseHopLimit":1,"HttpEndpoint":"enabled"}}]}]}`
)

// k8sNamespaceLabelled is a namespace whose Pod Security enforce label is level.
func k8sNamespaceLabelled(level string) string {
	return `{"metadata":{"labels":{"kubernetes.io/metadata.name":"x","pod-security.kubernetes.io/enforce":"` + level + `"}}}`
}

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

// The worker namespace in the cluster-mode fixtures.
const k8sWorkerNS = "aerolvm-workers"

type fakeK8s struct {
	pods         string
	workerPods   string // pods in k8sWorkerNS
	podsErr      error
	apiIP        string
	policies     string
	policiesErr  error
	workerPolicy string // NetworkPolicies in k8sWorkerNS
	dnsPods      string
	apiEndpoints string
	namespaces   map[string]string
	nodes        string
	// routes are the Gateway API route lists by resource; a resource that
	// is not a key answers as a CRD that is not installed.
	routes    map[string]string
	routesErr map[string]error
	gateways  map[string]string // "namespace/name" → Gateway
	awsOut    string
	awsErr    error
	awsCalls  []string
	cosignErr map[string]error
	probeOut  map[string]string
	probeErr  error
	probeErrs map[string]error // by runtime
	commands  []string
	signed    []string
}

// goodK8s is a clean single-mode install: every check passes.
func goodK8s() *fakeK8s {
	return &fakeK8s{pods: k8sGoodPods, apiIP: "10.96.0.1", policies: k8sGoodPolicies, dnsPods: k8sDNSPods, apiEndpoints: k8sAPIEndpoints,
		namespaces: map[string]string{"aerolvm": k8sNamespaceLabelled("privileged")}, nodes: k8sGoodNodes, awsOut: k8sGoodIMDS}
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
			case args[0] == "get" && args[1] == "pods" && args[3] == k8sWorkerNS:
				return answer(f.workerPods)
			case args[0] == "get" && args[1] == "pods":
				return []byte(f.pods), f.podsErr
			case args[0] == "get" && args[1] == "svc":
				return []byte(f.apiIP), nil
			case args[0] == "get" && args[1] == "networkpolicies" && args[3] == k8sWorkerNS:
				return answer(f.workerPolicy)
			case args[0] == "get" && args[1] == "networkpolicies":
				return []byte(f.policies), f.policiesErr
			case args[0] == "get" && args[1] == "endpointslices":
				return answer(f.apiEndpoints)
			case args[0] == "get" && args[1] == "namespace":
				return answer(f.namespaces[args[2]])
			case args[0] == "get" && args[1] == "nodes":
				return answer(f.nodes)
			case args[0] == "get" && args[1] == "gateways.gateway.networking.k8s.io":
				return answer(f.gateways[args[4]+"/"+args[2]])
			case args[0] == "get" && strings.HasSuffix(args[1], "routes.gateway.networking.k8s.io"):
				if err := f.routesErr[args[1]]; err != nil {
					return nil, err
				}
				list, ok := f.routes[args[1]]
				if !ok {
					return nil, errors.New(`kubectl get: error: the server doesn't have a resource type "` + strings.Split(args[1], ".")[0] + `"`)
				}
				return []byte(list), nil
			}
			return nil, errors.New("unexpected kubectl " + strings.Join(args, " "))
		},
		aws: func(_ context.Context, args ...string) ([]byte, error) {
			f.awsCalls = append(f.awsCalls, strings.Join(args, " "))
			return []byte(f.awsOut), f.awsErr
		},
		cosign: func(_ context.Context, image string) error {
			f.signed = append(f.signed, image)
			return f.cosignErr[image]
		},
		probe: func(_ context.Context, image, runtime, command string) (string, error) {
			f.commands = append(f.commands, runtime+" "+image+" "+command)
			if err := f.probeErrs[runtime]; err != nil {
				return "", err
			}
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
	// No Gateway API in this cluster, so no route checks; one namespace, so
	// no release namespace check.
	if len(checks) != 11 {
		t.Fatalf("%d checks, want 11: %+v", len(checks), checks)
	}
	if strings.Join(f.signed, ",") != "ghcr.io/aerol-ai/aerolvm-runtime:v1,ghcr.io/aerol-ai/aerolvm:v1" {
		t.Fatalf("signatures checked for %v, want each image once", f.signed)
	}
	// Only the worker's machine is read, in its own region.
	if len(f.awsCalls) != 1 || f.awsCalls[0] != "ec2 describe-instances --region us-east-1 --output json --instance-ids i-0abc" {
		t.Fatalf("aws calls %q", f.awsCalls)
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

const (
	k8sPolicyCheck     = k8sRuleEgress
	k8sPrivilegedCheck = k8sRulePrivileged
	k8sWorkerNSCheck   = k8sRuleWorkerNS
	k8sReleaseNSCheck  = k8sRuleReleaseNS
	k8sAPICheck        = k8sRuleNoAPI
)

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
			return strings.Replace(s, `{"name":"egress","image":"ghcr.io/aerol-ai/aerolvm:v1",`, `{"name":"egress","image":"ghcr.io/aerol-ai/aerolvm:v1","envFrom":[{"configMapRef":{"name":"settings"}},{"secretRef":{"name":"dns"}}],`, 1)
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

		// P8 Phase 2: privilege only where the plan puts it.
		{name: "a privileged egress container", f: with(func(f *fakeK8s) {
			f.pods = strings.Replace(k8sGoodPods, `"securityContext":{"privileged":false}`, `"securityContext":{"privileged":true}`, 1)
		}), check: k8sPrivilegedCheck, want: "fail: aerolvm/aerolvm-0/egress is privileged; only runtime and agent may be"},
		{name: "a privileged init container in the worker", f: with(func(f *fakeK8s) {
			f.pods = strings.Replace(k8sGoodPods, `"containers":[`, `"initContainers":[{"name":"runtime","image":"ghcr.io/aerol-ai/aerolvm:v1","securityContext":{"privileged":true}}],"containers":[`, 1)
		}), check: k8sPrivilegedCheck, want: "fail: aerolvm/aerolvm-0/runtime is privileged; only runtime and agent may be"},
		{name: "a privileged pod that is not a worker", f: with(func(f *fakeK8s) {
			f.pods = strings.Replace(k8sGoodPods, `"app.kubernetes.io/component":"worker"}},
  "spec":{`, `"app.kubernetes.io/component":"gateway"}},
  "spec":{`, 1)
		}), check: k8sPrivilegedCheck, want: "fail: aerolvm/aerolvm-0/runtime is privileged in a pod that is not a worker"},
		{name: "the namespace has no Pod Security label", f: with(func(f *fakeK8s) { f.namespaces["aerolvm"] = `{"metadata":{}}` }),
			check: k8sWorkerNSCheck, want: "fail: namespace aerolvm has no pod-security.kubernetes.io/enforce label; set it to privileged"},
		{name: "the namespace enforces baseline", f: with(func(f *fakeK8s) { f.namespaces["aerolvm"] = k8sNamespaceLabelled("baseline") }),
			check: k8sWorkerNSCheck, want: "fail: namespace aerolvm enforces baseline, not privileged"},
		{name: "the namespace cannot be read", f: with(func(f *fakeK8s) { f.namespaces = nil }), check: k8sWorkerNSCheck, want: "fail: forbidden"},
		{name: "the namespace not JSON", f: with(func(f *fakeK8s) { f.namespaces["aerolvm"] = "nope" }), check: k8sWorkerNSCheck, want: "fail: kubectl output"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := k8sResults(k8sVerify(context.Background(), tc.f.env(), k8sOpts))[tc.check]
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("%s = %q, want %q", tc.check, got, tc.want)
			}
		})
	}
}

// A cluster-mode install (§7): the chart's operator and the operator's
// server and gateway in the release namespace, and a worker in its own
// namespace. The chart labels its pods with the release, the operator with
// the AerolCluster's name. Only the operator holds a Kubernetes API token.
const (
	k8sClusterPods = `{"items":[
 {"metadata":{"name":"aerolvm-operator-7d9","labels":{"app.kubernetes.io/name":"aerolvm","app.kubernetes.io/instance":"aerolvm","app.kubernetes.io/component":"operator"}},
  "spec":{"containers":[{"name":"operator","image":"ghcr.io/aerol-ai/aerolvm-operator:v1"}]},"status":{"podIP":"10.244.1.2"}},
 {"metadata":{"name":"prod-server-0","labels":{"app.kubernetes.io/name":"aerolvm","aerolvm.io/cluster":"prod","app.kubernetes.io/component":"server"}},
  "spec":{"automountServiceAccountToken":false,"containers":[{"name":"server","image":"ghcr.io/aerol-ai/aerolvm:v1","ports":[{"containerPort":7946}],"securityContext":{"privileged":false}}]},"status":{"podIP":"10.244.1.3"}},
 {"metadata":{"name":"prod-gateway-abc","labels":{"app.kubernetes.io/name":"aerolvm","aerolvm.io/cluster":"prod","app.kubernetes.io/component":"gateway"}},
  "spec":{"automountServiceAccountToken":false,"containers":[{"name":"gateway","image":"ghcr.io/aerol-ai/aerolvm:v1","ports":[{"containerPort":21212}]}]},"status":{"podIP":"10.244.1.4"}}]}`
	k8sClusterWorkers = `{"items":[
 {"metadata":{"name":"prod-worker-a","labels":{"app.kubernetes.io/name":"aerolvm","aerolvm.io/cluster":"prod","app.kubernetes.io/component":"worker"}},
  "spec":{"nodeName":"ip-10-0-2-7.eu-west-1.compute.internal","automountServiceAccountToken":false,
    "volumes":[{"name":"join","secret":{"secretName":"prod-worker-a-join","items":[{"key":"join_url","path":"join_url"},{"key":"token","path":"token"},{"key":"ca_cert_hash","path":"ca_cert_hash"}]}}],
    "containers":[
    {"name":"runtime","image":"ghcr.io/aerol-ai/aerolvm-runtime:v1","securityContext":{"privileged":true}},
    {"name":"agent","image":"ghcr.io/aerol-ai/aerolvm:v1","ports":[{"containerPort":21212}],"securityContext":{"privileged":true}},
    {"name":"edge","image":"ghcr.io/aerol-ai/aerolvm-edge:v1"}]},
  "status":{"podIP":"10.244.2.9"}}]}`
	k8sClusterWorkerPolicy = `{"items":[{"metadata":{"name":"prod-worker-egress"},"spec":{
  "podSelector":{"matchLabels":{"aerolvm.io/cluster":"prod","app.kubernetes.io/component":"worker"}},
  "policyTypes":["Egress"],
  "egress":[{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"aerolvm-system"}},"podSelector":{"matchLabels":{"aerolvm.io/cluster":"prod"}}}]},
    {"to":[{"ipBlock":{"cidr":"0.0.0.0/0","except":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","100.64.0.0/10","169.254.0.0/16"]}}]}]}},
 {"metadata":{"name":"prod-worker-ingress"},"spec":{
  "podSelector":{"matchLabels":{"aerolvm.io/cluster":"prod","app.kubernetes.io/component":"worker"}},
  "policyTypes":["Ingress"],
  "ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"aerolvm-system"}},"podSelector":{"matchLabels":{"aerolvm.io/cluster":"prod"}}},
      {"podSelector":{"matchLabels":{"aerolvm.io/cluster":"prod","app.kubernetes.io/component":"worker"}}}]},
    {"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"monitoring"}}},{"ipBlock":{"cidr":"10.50.0.0/16"}},{"ipBlock":{"cidr":"nope"}}],"ports":[{"port":21212}]}]}}]}`
	// The release namespace's policies: the servers' ingress wall.
	k8sClusterReleasePolicy = `{"items":[{"metadata":{"name":"prod-server-ingress"},"spec":{
  "podSelector":{"matchLabels":{"aerolvm.io/cluster":"prod","app.kubernetes.io/component":"server"}},
  "policyTypes":["Ingress"],
  "ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"aerolvm-system"}},"podSelector":{"matchLabels":{"aerolvm.io/cluster":"prod"}}}]}]}}]}`
	k8sClusterIMDS = `{"Reservations":[{"Instances":[{"InstanceId":"i-0w1","MetadataOptions":{"HttpTokens":"required","HttpPutResponseHopLimit":1,"HttpEndpoint":"enabled"}}]}]}`
)

// The bank's Gateway in front (§7.1): the API host ends TLS, sandbox links
// pass through, another app's TLS listener ends TLS, and SSH is plain TCP.
const (
	k8sBankGateway = `{"spec":{"listeners":[
  {"name":"https","hostname":"api.example.com","port":443,"protocol":"HTTPS","tls":{"mode":"Terminate"}},
  {"name":"links","hostname":"*.sbx.example.com","port":443,"protocol":"TLS","tls":{"mode":"Passthrough"}},
  {"name":"other-app","hostname":"*.other.example.com","port":443,"protocol":"TLS"},
  {"name":"ssh","port":22,"protocol":"TCP"}]}}`
	k8sAccepted = `{"type":"Accepted","status":"True","reason":"Accepted"},{"type":"ResolvedRefs","status":"True","reason":"ResolvedRefs"}`

	k8sHTTPRoutes = "httproutes.gateway.networking.k8s.io"
	k8sTLSRoutes  = "tlsroutes.gateway.networking.k8s.io"
	k8sTCPRoutes  = "tcproutes.gateway.networking.k8s.io"
)

// k8sRouteJSON is a route list with one route on one parent, as kubectl
// prints it, with the given status conditions for that parent.
func k8sRouteJSON(name, parent, hostnames, conditions string) string {
	return `{"items":[{"metadata":{"name":"` + name + `","namespace":"aerolvm-system"},"spec":{"parentRefs":[` + parent + `],"hostnames":[` + hostnames + `]},` +
		`"status":{"parents":[{"parentRef":` + parent + `,"controllerName":"example.com/gw","conditions":[` + conditions + `]}]}}]}`
}

// clusterK8s is a clean cluster-mode install behind the bank's Gateway.
func clusterK8s() *fakeK8s {
	f := goodK8s()
	f.pods, f.workerPods, f.workerPolicy = k8sClusterPods, k8sClusterWorkers, k8sClusterWorkerPolicy
	f.policies = k8sClusterReleasePolicy
	f.namespaces = map[string]string{"aerolvm-system": k8sNamespaceLabelled("restricted"), k8sWorkerNS: k8sNamespaceLabelled("privileged")}
	f.nodes = "ip-10-0-2-7.eu-west-1.compute.internal\taws:///eu-west-1b/i-0w1\n"
	f.awsOut = k8sClusterIMDS
	f.routes = map[string]string{
		k8sHTTPRoutes: k8sRouteJSON("prod-api", `{"name":"bank-gw","namespace":"infra","sectionName":"https"}`, `"api.example.com"`, k8sAccepted),
		k8sTLSRoutes:  k8sRouteJSON("prod-links", `{"name":"bank-gw","namespace":"infra"}`, `"*.sbx.example.com"`, k8sAccepted),
		k8sTCPRoutes:  k8sRouteJSON("prod-ssh", `{"name":"bank-gw","namespace":"infra","sectionName":"ssh"}`, ``, k8sAccepted),
	}
	f.gateways = map[string]string{"infra/bank-gw": k8sBankGateway}
	return f
}

var k8sClusterOpts = k8sVerifyOptions{namespace: "aerolvm-system", workerNamespace: k8sWorkerNS, release: "aerolvm", cluster: "prod",
	probeImage: "alpine:3.20", probeRuntimes: []string{"docker", "gvisor"}}

func TestK8sVerifyClusterModePasses(t *testing.T) {
	f := clusterK8s()
	checks := k8sVerify(context.Background(), f.env(), k8sClusterOpts)
	for _, c := range checks {
		if c.Result != k8sPass {
			t.Errorf("%s: %s %s", c.Name, c.Result, c.Detail)
		}
	}
	got := k8sResults(checks)
	if len(checks) != 16 || got[k8sReleaseNSCheck] == "" || got[k8sRoutesAccepted] == "" || got[k8sLinksPassthrough] == "" {
		t.Fatalf("%d checks: %+v", len(checks), checks)
	}
	for check, want := range map[string]string{
		"AerolVM pods found": "pass: 4 pod(s)",
		k8sAPICheck:          "pass: the 1 operator pod(s) hold one by design",
		k8sPrivilegedCheck:   "pass: 1 worker pod(s) in namespace aerolvm-workers",
		k8sPolicyCheck:       "pass: prod-worker-a (prod-worker-egress)",
		k8sRuleIngress:       "pass: prod-worker-a (prod-worker-ingress)",
		k8sRuleServerIngress: "pass: prod-server-0 (prod-server-ingress)",
		k8sIMDSCheck:         "pass: 1 EC2 instance(s)",
		k8sRoutesAccepted:    "pass: HTTPRoute prod-api, TLSRoute prod-links, TCPRoute prod-ssh",
		k8sLinksPassthrough:  "pass: Gateway infra/bank-gw listener links",
		"images signed by the AerolVM release workflow": "pass: ghcr.io/aerol-ai/aerolvm-edge:v1, ghcr.io/aerol-ai/aerolvm-operator:v1",
	} {
		if !strings.HasPrefix(got[check], want) {
			t.Errorf("%s = %q, want %q", check, got[check], want)
		}
	}
	// Every AerolVM pod's ports are probed; the sandbox bridge only once.
	probe := f.commands[0]
	for _, target := range []string{"10.244.1.3:7946", "10.244.1.4:21212", "10.244.2.9:21212", "10.88.0.1:21212"} {
		if !strings.Contains(probe, target) {
			t.Errorf("the probe does not try %s: %s", target, probe)
		}
	}
	if strings.Count(probe, "10.88.0.1:2220") != 1 || strings.Contains(probe, "10.88.0.1:7946") {
		t.Errorf("the bridge is probed per pod: %s", probe)
	}
}

func TestK8sVerifyClusterModeFailures(t *testing.T) {
	with := func(edit func(*fakeK8s)) *fakeK8s {
		f := clusterK8s()
		edit(f)
		return f
	}
	for _, tc := range []struct {
		name, check, want string
		f                 *fakeK8s
	}{
		{name: "a privileged server", check: k8sPrivilegedCheck, want: "fail: aerolvm-system/prod-server-0/server is privileged outside the worker namespace aerolvm-workers",
			f: with(func(f *fakeK8s) {
				f.pods = strings.Replace(k8sClusterPods, `"privileged":false`, `"privileged":true`, 1)
			})},
		{name: "a server with a token", check: k8sAPICheck, want: "fail: prod-server-0: automountServiceAccountToken is not false",
			f: with(func(f *fakeK8s) {
				f.pods = strings.Replace(k8sClusterPods, `"automountServiceAccountToken":false,`, ``, 1)
			})},
		{name: "an operator pod outside the release namespace", check: k8sAPICheck, want: "fail: prod-worker-a: automountServiceAccountToken is not false",
			f: with(func(f *fakeK8s) {
				f.workerPods = strings.Replace(strings.Replace(k8sClusterWorkers, `"automountServiceAccountToken":false,`, ``, 1),
					`"app.kubernetes.io/component":"worker"`, `"app.kubernetes.io/component":"operator"`, 1)
			})},
		{name: "the release namespace unlabelled", check: k8sReleaseNSCheck, want: "fail: namespace aerolvm-system has no pod-security.kubernetes.io/enforce label; set it to restricted",
			f: with(func(f *fakeK8s) { f.namespaces["aerolvm-system"] = `{"metadata":{}}` })},
		{name: "the release namespace enforces baseline", check: k8sReleaseNSCheck, want: "fail: namespace aerolvm-system enforces baseline, not restricted",
			f: with(func(f *fakeK8s) { f.namespaces["aerolvm-system"] = k8sNamespaceLabelled("baseline") })},
		{name: "the release namespace allows privileged pods", check: k8sReleaseNSCheck, want: "fail: namespace aerolvm-system enforces privileged, not restricted",
			f: with(func(f *fakeK8s) { f.namespaces["aerolvm-system"] = k8sNamespaceLabelled("privileged") })},
		{name: "a join Secret mounted whole", check: k8sRuleNoDNSToken, want: "fail: prod-worker-a: volume join mounts every key of Secret prod-worker-a-join",
			f: with(func(f *fakeK8s) {
				f.workerPods = strings.Replace(k8sClusterWorkers, `,"items":[{"key":"join_url","path":"join_url"},{"key":"token","path":"token"},{"key":"ca_cert_hash","path":"ca_cert_hash"}]`, ``, 1)
			})},
		{name: "another key in a join Secret", check: k8sRuleNoDNSToken, want: "fail: prod-worker-a: volume join mounts key dns-token of Secret prod-worker-a-join",
			f: with(func(f *fakeK8s) {
				f.workerPods = strings.Replace(k8sClusterWorkers, `{"key":"token","path":"token"}`, `{"key":"dns-token","path":"token"}`, 1)
			})},
		{name: "a token key in a Secret that is not a join Secret", check: k8sRuleNoDNSToken, want: "fail: prod-worker-a: volume join mounts key join_url of Secret dns-creds; prod-worker-a: volume join mounts key token of Secret dns-creds",
			f: with(func(f *fakeK8s) {
				f.workerPods = strings.Replace(k8sClusterWorkers, `"secretName":"prod-worker-a-join"`, `"secretName":"dns-creds"`, 1)
			})},
		{name: "the worker namespace enforces restricted", check: k8sWorkerNSCheck, want: "fail: namespace aerolvm-workers enforces restricted, not privileged",
			f: with(func(f *fakeK8s) { f.namespaces[k8sWorkerNS] = k8sNamespaceLabelled("restricted") })},
		{name: "no policy in the worker namespace", check: k8sPolicyCheck, want: "fail: prod-worker-a: no NetworkPolicy limits its egress",
			f: with(func(f *fakeK8s) { f.workerPolicy = `{"items":[]}` })},
		{name: "no policy limits who reaches the servers", check: k8sRuleServerIngress, want: "fail: prod-server-0: no NetworkPolicy limits who reaches it",
			f: with(func(f *fakeK8s) { f.policies = `{"items":[]}` })},
		{name: "a server policy that lets in every pod", check: k8sRuleServerIngress, want: "fail: prod-server-0: NetworkPolicy prod-server-ingress lets every pod in the cluster reach the pod",
			f: with(func(f *fakeK8s) {
				f.policies = strings.Replace(k8sClusterReleasePolicy, `"ingress":[`, `"ingress":[{"from":[{"namespaceSelector":{},"podSelector":{}}]},`, 1)
			})},
		{name: "no policy limits who reaches the worker", check: k8sRuleIngress, want: "fail: prod-worker-a: no NetworkPolicy limits who reaches it",
			f: with(func(f *fakeK8s) {
				f.workerPolicy = strings.Replace(k8sClusterWorkerPolicy, `"policyTypes":["Ingress"]`, `"policyTypes":["Egress"]`, 1)
			})},
		{name: "an ingress rule with no source", check: k8sRuleIngress, want: "fail: prod-worker-a: NetworkPolicy prod-worker-ingress lets every address reach the pod",
			f: with(func(f *fakeK8s) {
				f.workerPolicy = strings.Replace(k8sClusterWorkerPolicy, `"ingress":[`, `"ingress":[{},`, 1)
			})},
		{name: "an ingress rule from every pod", check: k8sRuleIngress, want: "fail: prod-worker-a: NetworkPolicy prod-worker-ingress lets every pod in the cluster reach the pod",
			f: with(func(f *fakeK8s) {
				f.workerPolicy = strings.Replace(k8sClusterWorkerPolicy, `"ingress":[`, `"ingress":[{"from":[{"namespaceSelector":{}}]},`, 1)
			})},
		{name: "an ingress rule from every address", check: k8sRuleIngress, want: "fail: prod-worker-a: NetworkPolicy prod-worker-ingress lets every address reach the pod (ipBlock 0.0.0.0/0)",
			f: with(func(f *fakeK8s) {
				f.workerPolicy = strings.Replace(k8sClusterWorkerPolicy, `{"ipBlock":{"cidr":"10.50.0.0/16"}}`, `{"ipBlock":{"cidr":"0.0.0.0/0"}}`, 1)
			})},
		{name: "a policy with no policyTypes counts for ingress", check: k8sRuleIngress, want: "pass: prod-worker-a (prod-worker-ingress)",
			f: with(func(f *fakeK8s) {
				f.workerPolicy = strings.Replace(k8sClusterWorkerPolicy, `"policyTypes":["Ingress"],`, ``, 1)
			})},
		{name: "the worker namespace's policies unreadable", check: k8sPolicyCheck, want: "fail: forbidden",
			f: with(func(f *fakeK8s) { f.workerPolicy = "" })},
		{name: "the worker pods unreadable", check: "AerolVM pods found", want: "fail: forbidden",
			f: with(func(f *fakeK8s) { f.workerPods = "" })},
		{name: "no pods in either namespace", check: "AerolVM pods found", want: "fail: no pods labelled app.kubernetes.io/name=aerolvm and app.kubernetes.io/instance=aerolvm or aerolvm.io/cluster=prod in namespace aerolvm-system or aerolvm-workers",
			f: with(func(f *fakeK8s) { f.pods, f.workerPods = `{"items":[]}`, `{"items":[]}` })},
		{name: "the IMDS hop limit of 2", check: k8sIMDSCheck, want: "fail: ip-10-0-2-7.eu-west-1.compute.internal (i-0w1): hop limit 2, want 1",
			f: with(func(f *fakeK8s) {
				f.awsOut = strings.Replace(k8sClusterIMDS, `"HttpPutResponseHopLimit":1`, `"HttpPutResponseHopLimit":2`, 1)
			})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := k8sResults(k8sVerify(context.Background(), tc.f.env(), k8sClusterOpts))[tc.check]
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("%s = %q, want %q", tc.check, got, tc.want)
			}
		})
	}
}

// The command passes --worker-namespace and --cluster through, and both
// default to single mode's values.
func TestK8sVerifyClusterFlags(t *testing.T) {
	h := newHarness(t)
	f := clusterK8s()
	orig := k8sEnvFor
	t.Cleanup(func() { k8sEnvFor = orig })
	k8sEnvFor = func(*app, *commonFlags, string) k8sEnv { return f.env() }
	if code := h.run("k8s", "verify", "--namespace", "aerolvm-system", "--worker-namespace", k8sWorkerNS, "--cluster", "prod"); code != exitOK {
		t.Fatalf("exit %d: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	// With neither flag, verify looks for a single-mode install in the
	// release namespace and finds only the chart's operator pod.
	if code := h.run("k8s", "verify", "--namespace", "aerolvm-system", "--json"); code != exitError {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(h.stdout.String(), `"detail": "1 pod(s)"`) {
		t.Fatalf("%s", h.stdout.String())
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
	if !out.OK || len(out.Checks) != 11 || strings.Contains(h.stderr.String(), "warning") {
		t.Fatalf("%+v %s", out, h.stderr.String())
	}

	// No AWS credentials here: the IMDS check is skipped with a warning
	// naming why, and the run still passes (the plan's error table).
	f.awsErr = errK8sNoAWSCredentials
	if code := h.run("k8s", "verify", "--kube-context", "kind-x"); code != exitOK {
		t.Fatalf("a skipped IMDS check exited %d: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "SKIP") ||
		!strings.Contains(h.stderr.String(), "aerolvm: warning: not checked: worker machines allow IMDSv2 only, with a hop limit of 1: no AWS credentials") {
		t.Fatalf("stdout %q stderr %q", h.stdout.String(), h.stderr.String())
	}
	f.awsErr = nil

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

// A runtime the install's create policy refuses (the bank preset: gVisor
// only) is skipped, not failed: its walls are moot. If every runtime is
// refused, nothing was probed, and that fails.
func TestK8sProbeSkipsRuntimesThePolicyRefuses(t *testing.T) {
	refused := errors.New(`api 403: create refused by policy rule "runtimes": runtime "docker" is not allowed on this server`)
	f := goodK8s()
	f.probeErrs = map[string]error{"docker": refused}
	got := k8sResults(k8sVerify(context.Background(), f.env(), k8sOpts))
	if !strings.HasPrefix(got["a docker sandbox cannot reach the worker, another pod or the Kubernetes API"], "skip: the create policy allows no docker sandbox") ||
		!strings.HasPrefix(got["a gvisor sandbox cannot reach the worker, another pod or the Kubernetes API"], "pass:") {
		t.Fatalf("results = %v", got)
	}
	f = goodK8s()
	f.probeErrs = map[string]error{"docker": refused, "gvisor": refused}
	got = k8sResults(k8sVerify(context.Background(), f.env(), k8sOpts))
	if !strings.HasPrefix(got["a docker or gvisor sandbox cannot reach the worker, another pod or the Kubernetes API"], "fail: no probe sandbox could be made") {
		t.Fatalf("results = %v", got)
	}
	// Any other refusal is still a failure.
	f = goodK8s()
	f.probeErrs = map[string]error{"docker": errors.New("cluster: no worker placement target available")}
	if got := k8sResults(k8sVerify(context.Background(), f.env(), k8sOpts)); !strings.HasPrefix(got["a docker sandbox cannot reach the worker, another pod or the Kubernetes API"], "fail: probe:") {
		t.Fatalf("results = %v", got)
	}
}
