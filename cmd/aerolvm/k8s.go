package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/agenttools"
)

// aerolvm k8s verify (plans/kubernetes-v2-architecture.md P8, CEO review
// CE2): checks a live Kubernetes install against the rules the security
// evidence pack (P7) states, and exits 1 on any miss, so a bank can run it
// instead of reading YAML. Phase 1 covers single mode: the images are
// signed, the worker pod mounts nothing from the machine and holds no
// Kubernetes API credential or DNS provider token (C25), a NetworkPolicy
// limits the worker pod's egress, and a probe sandbox cannot reach the
// worker's own ports, another pod or the Kubernetes API (C24). Phase 2
// adds the cluster layout: privileged containers only in the worker
// namespace, each namespace's Pod Security label, the worker machines' IMDS
// hop limit, and, behind the bank's own Gateway, that the Gateway accepted
// the routes and passes sandbox links through still encrypted.
//
// It reads the cluster with the kubectl, cosign and aws already on this
// machine (so the CLI carries no Kubernetes or AWS client, and holds no
// credential of its own), and probes through the AerolVM API the CLI is
// logged in to.

const (
	k8sPass = "pass"
	k8sFail = "fail"
	k8sSkip = "skip"

	// The release workflow's keyless signing identity (RELEASE-VERIFICATION.md).
	k8sSignerIdentity = `^https://github.com/aerol-ai/microvm/.github/workflows/release.yml@refs/tags/v`
	k8sSignerIssuer   = "https://token.actions.githubusercontent.com"

	// sandboxd's SSH gateway port: open on the worker, never to sandboxes.
	k8sSSHGatewayPort = 2220
	// The containerd sandbox range when SB_CONTAINERD_BRIDGE_SUBNET is unset.
	k8sDefaultBridge = "10.88.0.0/16"

	k8sComponent = "app.kubernetes.io/component"
	// The Pod Security admission label that decides what a namespace admits.
	k8sPodSecurityEnforce = "pod-security.kubernetes.io/enforce"
)

// The rules verify checks, each by the name its check reports. The bank
// evidence pack (P7, charts/aerolvm/EVIDENCE.md) lists exactly these, and
// TestEvidencePackListsVerifyRules fails when the two differ, so what the
// pack promises is what verify checks. k8sRuleProbe runs once per runtime,
// with <runtime> filled in.
const (
	k8sRuleFound         = "AerolVM pods found"
	k8sRuleSigned        = "images signed by the AerolVM release workflow"
	k8sRuleNoHostMounts  = "no folders mounted from the machine"
	k8sRuleNoAPI         = "no Kubernetes API credential in the pods"
	k8sRuleNoDNSToken    = "no DNS provider token in the pods"
	k8sRulePrivileged    = "privileged containers only in the worker pods' runtime and agent"
	k8sRuleWorkerNS      = "the worker namespace's Pod Security label is privileged"
	k8sRuleReleaseNS     = "the release namespace enforces restricted Pod Security"
	k8sRuleEgress        = "a NetworkPolicy limits the worker pods' egress"
	k8sRuleIngress       = "a NetworkPolicy limits who reaches the worker pods"
	k8sRuleServerIngress = "a NetworkPolicy limits who reaches the servers"
	k8sRuleIMDS          = "worker machines allow IMDSv2 only, with a hop limit of 1"
	k8sRoutesAccepted    = "the Gateway accepted every AerolVM route"
	k8sLinksPassthrough  = "the sandbox-link listener passes TLS through"
	k8sRuleProbe         = "a <runtime> sandbox cannot reach the worker, another pod or the Kubernetes API"
)

// k8sVerifyRules is every rule, in the order verify reports them.
var k8sVerifyRules = []string{
	k8sRuleFound, k8sRuleSigned, k8sRuleNoHostMounts, k8sRuleNoAPI, k8sRuleNoDNSToken, k8sRulePrivileged,
	k8sRuleWorkerNS, k8sRuleReleaseNS, k8sRuleEgress, k8sRuleIngress, k8sRuleServerIngress, k8sRuleIMDS, k8sRoutesAccepted,
	k8sLinksPassthrough, k8sRuleProbe,
}

// k8sPrivilegedContainers are the worker pod's containers that run
// privileged (§8.7): runtime builds sandboxes and agent makes their network
// namespaces. edge and egress never need it.
var k8sPrivilegedContainers = map[string]bool{"runtime": true, "agent": true}

// k8sTLSKeys are the only Secret keys a worker pod may mount (C25): the
// edge certificate and key cert-manager writes, and its CA.
var k8sTLSKeys = map[string]bool{"tls.crt": true, "tls.key": true, "ca.crt": true}

// k8sJoinKeys are the keys of a node's join-token Secret (cluster mode),
// mounted by name into that one pod.
var k8sJoinKeys = map[string]bool{"join_url": true, "token": true, "ca_cert_hash": true}

// k8sDNSTokenEnv matches the environment names DNS provider credentials go
// by: Caddy's DNS token on a VM install (SB_DNS_API_TOKEN) and the
// providers' own (Cloudflare, Route 53, DigitalOcean).
var k8sDNSTokenEnv = regexp.MustCompile(`(?i)(^|_)DNS_.*(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)|^(CLOUDFLARE|CF_API|CF_DNS|CF_ZONE|ROUTE53|DIGITALOCEAN)|^DO_AUTH_TOKEN$`)

type k8sCheck struct {
	Name   string `json:"name"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}

// k8sEnv is everything verify does outside this process, so it can be
// tested without a cluster.
type k8sEnv struct {
	// kubectl runs kubectl with args (the context flag already added).
	kubectl func(ctx context.Context, args ...string) ([]byte, error)
	// cosign checks image's keyless signature against the release identity.
	cosign func(ctx context.Context, image string) error
	// probe creates a sandbox of runtime from image, runs command in it,
	// destroys it, and returns the command's stdout.
	probe func(ctx context.Context, image, runtime, command string) (string, error)
	// aws runs the aws CLI with args. It fails with errK8sNoAWSCLI or
	// errK8sNoAWSCredentials when either is missing.
	aws func(ctx context.Context, args ...string) ([]byte, error)
}

type k8sVerifyOptions struct {
	// namespace is the release namespace; workerNamespace is where the
	// worker pods run, the same namespace in single mode.
	namespace, workerNamespace string
	// release is the Helm release and cluster the AerolCluster's name: the
	// chart labels the pods it makes with the first, the operator the pods
	// it makes with the second.
	release, cluster string
	probeImage       string
	probeRuntimes    []string
	skipSignatures   bool
}

// k8sPodList is the part of `kubectl get pods -o json` verify reads.
type k8sPodList struct {
	Items []k8sPod `json:"items"`
}

type k8sPod struct {
	Metadata struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		NodeName                     string `json:"nodeName"`
		AutomountServiceAccountToken *bool  `json:"automountServiceAccountToken"`
		Volumes                      []struct {
			Name     string `json:"name"`
			HostPath *struct {
				Path string `json:"path"`
			} `json:"hostPath"`
			Secret    *k8sSecretSource `json:"secret"`
			Projected *struct {
				Sources []struct {
					ServiceAccountToken *json.RawMessage `json:"serviceAccountToken"`
					Secret              *k8sSecretSource `json:"secret"`
				} `json:"sources"`
			} `json:"projected"`
		} `json:"volumes"`
		InitContainers []k8sContainer `json:"initContainers"`
		Containers     []k8sContainer `json:"containers"`
	} `json:"spec"`
	Status struct {
		PodIP string `json:"podIP"`
	} `json:"status"`
}

type k8sContainer struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	Ports []struct {
		ContainerPort int `json:"containerPort"`
	} `json:"ports"`
	Env []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"env"`
	EnvFrom []struct {
		SecretRef *struct {
			Name string `json:"name"`
		} `json:"secretRef"`
	} `json:"envFrom"`
	SecurityContext *struct {
		Privileged *bool `json:"privileged"`
	} `json:"securityContext"`
}

func (c k8sContainer) privileged() bool {
	return c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged
}

// k8sNetworkPolicyList is the part of `kubectl get networkpolicies -o json`
// verify reads.
type k8sNetworkPolicyList struct {
	Items []k8sNetworkPolicy `json:"items"`
}

type k8sNetworkPolicy struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		PodSelector k8sLabelSelector `json:"podSelector"`
		PolicyTypes []string         `json:"policyTypes"`
		Ingress     []struct {
			From []k8sPolicyPeer `json:"from"`
		} `json:"ingress"`
		Egress []struct {
			To []struct {
				PodSelector       *k8sLabelSelector `json:"podSelector"`
				NamespaceSelector *k8sLabelSelector `json:"namespaceSelector"`
				IPBlock           *struct {
					CIDR   string   `json:"cidr"`
					Except []string `json:"except"`
				} `json:"ipBlock"`
			} `json:"to"`
		} `json:"egress"`
	} `json:"spec"`
}

type k8sLabelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values"`
	} `json:"matchExpressions"`
}

// empty reports a selector that selects everything.
func (s *k8sLabelSelector) empty() bool {
	return s != nil && len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0
}

// matches applies the selector to a pod's labels, as Kubernetes does.
func (s k8sLabelSelector) matches(labels map[string]string) bool {
	for k, v := range s.MatchLabels {
		if got, ok := labels[k]; !ok || got != v {
			return false
		}
	}
	for _, e := range s.MatchExpressions {
		v, ok := labels[e.Key]
		switch e.Operator {
		case "In":
			if !ok || !slices.Contains(e.Values, v) {
				return false
			}
		case "NotIn":
			if ok && slices.Contains(e.Values, v) {
				return false
			}
		case "Exists":
			if !ok {
				return false
			}
		case "DoesNotExist":
			if ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// k8sPolicyPeer is one ingress source of a NetworkPolicy.
type k8sPolicyPeer struct {
	PodSelector       *k8sLabelSelector `json:"podSelector"`
	NamespaceSelector *k8sLabelSelector `json:"namespaceSelector"`
	IPBlock           *struct {
		CIDR string `json:"cidr"`
	} `json:"ipBlock"`
}

// limitsIngress reports a policy that limits who reaches the pods it
// selects. Kubernetes counts every policy as an ingress policy unless its
// policyTypes leave Ingress out.
func (np k8sNetworkPolicy) limitsIngress() bool {
	return len(np.Spec.PolicyTypes) == 0 || slices.Contains(np.Spec.PolicyTypes, "Ingress")
}

// admitsAnyone names an ingress rule of the policy that lets every pod or
// every address reach the pods it selects, or "" when none does.
// NetworkPolicies add up, so one such rule undoes the wall.
func (np k8sNetworkPolicy) admitsAnyone() string {
	for _, rule := range np.Spec.Ingress {
		if len(rule.From) == 0 {
			return "lets every address reach the pod"
		}
		for _, peer := range rule.From {
			if peer.NamespaceSelector.empty() && (peer.PodSelector == nil || peer.PodSelector.empty()) {
				return "lets every pod in the cluster reach the pod"
			}
			if peer.IPBlock == nil {
				continue
			}
			if block, err := netip.ParsePrefix(peer.IPBlock.CIDR); err == nil && block.Bits() == 0 {
				return fmt.Sprintf("lets every address reach the pod (ipBlock %s)", block)
			}
		}
	}
	return ""
}

// limitsEgress reports a policy that limits the egress of the pods it
// selects. With no policyTypes, Kubernetes infers Egress from egress rules.
func (np k8sNetworkPolicy) limitsEgress() bool {
	if len(np.Spec.PolicyTypes) == 0 {
		return len(np.Spec.Egress) > 0
	}
	return slices.Contains(np.Spec.PolicyTypes, "Egress")
}

// k8sBankRanges are the ranges a worker pod's egress must not open whole
// (C24): the private ranges, where a bank's own network lives, and the
// shared and link-local ranges, which clouds use for pods and their own
// services. One range opened on purpose (a /16 inside 10.0.0.0/8) is fine.
var k8sBankRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// opens names what one of the policy's rules lets every selected pod reach
// that the wall is there to shut, or "" when nothing. NetworkPolicies add
// up, so a single rule like that undoes every other policy on the pod.
func (np k8sNetworkPolicy) opens() string {
	for _, rule := range np.Spec.Egress {
		if len(rule.To) == 0 {
			return "lets the pod reach every address"
		}
		for _, peer := range rule.To {
			if peer.NamespaceSelector.empty() && (peer.PodSelector == nil || peer.PodSelector.empty()) {
				return "lets the pod reach every pod in the cluster"
			}
			if peer.IPBlock == nil {
				continue
			}
			block, err := netip.ParsePrefix(peer.IPBlock.CIDR)
			if err != nil {
				continue // the API server refuses it; nothing to judge
			}
			for _, r := range k8sBankRanges {
				if r.Addr().BitLen() != block.Addr().BitLen() || block.Bits() > r.Bits() || !block.Contains(r.Addr()) {
					continue // the block does not hold this whole range
				}
				excepted := slices.ContainsFunc(peer.IPBlock.Except, func(e string) bool {
					ep, err := netip.ParsePrefix(e)
					return err == nil && ep.Bits() <= r.Bits() && ep.Contains(r.Addr())
				})
				if !excepted {
					return fmt.Sprintf("lets the pod reach %s (ipBlock %s)", r, block)
				}
			}
		}
	}
	return ""
}

// k8sSecretSource is a Secret volume, or a Secret in a projected volume:
// SecretName is set on the first, Name on the second.
type k8sSecretSource struct {
	SecretName string `json:"secretName"`
	Name       string `json:"name"`
	Items      []struct {
		Key string `json:"key"`
	} `json:"items"`
}

// all is every container in the pod, init containers first: an image or a
// token in an init container is in the pod as much as one in the others.
func (p k8sPod) all() []k8sContainer {
	return append(append([]k8sContainer(nil), p.Spec.InitContainers...), p.Spec.Containers...)
}

// k8sVerify runs every check and returns them in order.
func k8sVerify(ctx context.Context, env k8sEnv, o k8sVerifyOptions) []k8sCheck {
	o.workerNamespace = cmp.Or(o.workerNamespace, o.namespace)
	o.cluster = cmp.Or(o.cluster, o.release)
	const found = k8sRuleFound
	pods, err := k8sPods(ctx, env, o)
	if err != nil {
		return []k8sCheck{{Name: found, Result: k8sFail, Detail: err.Error()}}
	}
	checks := []k8sCheck{{Name: found, Result: k8sPass, Detail: strconv.Itoa(len(pods)) + " pod(s)"}}
	checks = append(checks, k8sImagesSigned(ctx, env, pods, o.skipSignatures))
	checks = append(checks, k8sNoHostMounts(pods), k8sNoAPIRights(pods, o.namespace), k8sNoDNSToken(pods))
	checks = append(checks, k8sPrivileged(pods, o.workerNamespace))
	checks = append(checks, k8sPodSecurity(ctx, env, o)...)
	checks = append(checks, k8sEgressPolicy(ctx, env, pods))
	if o.workerNamespace != o.namespace {
		checks = append(checks, k8sIngressPolicy(ctx, env, pods, "worker", k8sRuleIngress),
			k8sIngressPolicy(ctx, env, pods, "server", k8sRuleServerIngress))
	}
	checks = append(checks, k8sIMDS(ctx, env, pods))
	checks = append(checks, k8sGatewayRoutes(ctx, env, o)...)
	checks = append(checks, k8sProbe(ctx, env, pods, o)...)
	return checks
}

// k8sPods lists the install's pods in the release namespace and, in cluster
// mode, the worker namespace. A pod is the install's when it carries the
// release's label (the chart made it) or the AerolCluster's (the operator
// did): the operator's pods carry only the second, so a label selector,
// which cannot say "or", would miss one kind or the other.
func k8sPods(ctx context.Context, env k8sEnv, o k8sVerifyOptions) ([]k8sPod, error) {
	namespaces := []string{o.namespace}
	if o.workerNamespace != o.namespace {
		namespaces = append(namespaces, o.workerNamespace)
	}
	var pods []k8sPod
	for _, ns := range namespaces {
		raw, err := env.kubectl(ctx, "get", "pods", "-n", ns, "-l", "app.kubernetes.io/name=aerolvm", "-o", "json")
		if err != nil {
			return nil, err
		}
		var list k8sPodList
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("kubectl output: %w", err)
		}
		for _, p := range list.Items {
			if p.Metadata.Labels["app.kubernetes.io/instance"] != o.release && p.Metadata.Labels["aerolvm.io/cluster"] != o.cluster {
				continue
			}
			p.Metadata.Namespace = ns
			pods = append(pods, p)
		}
	}
	if len(pods) == 0 {
		return nil, fmt.Errorf("no pods labelled app.kubernetes.io/name=aerolvm and app.kubernetes.io/instance=%s or aerolvm.io/cluster=%s in namespace %s",
			o.release, o.cluster, strings.Join(namespaces, " or "))
	}
	return pods, nil
}

func k8sImagesSigned(ctx context.Context, env k8sEnv, pods []k8sPod, skip bool) k8sCheck {
	const name = k8sRuleSigned
	images := map[string]bool{}
	for _, p := range pods {
		for _, c := range p.all() {
			images[c.Image] = true
		}
	}
	list := make([]string, 0, len(images))
	for img := range images {
		list = append(list, img)
	}
	sort.Strings(list)
	if skip {
		return k8sCheck{Name: name, Result: k8sSkip, Detail: "--skip-signatures: " + strings.Join(list, ", ")}
	}
	var bad []string
	for _, img := range list {
		if err := env.cosign(ctx, img); err != nil {
			bad = append(bad, fmt.Sprintf("%s (%v)", img, err))
		}
	}
	if len(bad) > 0 {
		return k8sCheck{Name: name, Result: k8sFail, Detail: strings.Join(bad, "; ")}
	}
	return k8sCheck{Name: name, Result: k8sPass, Detail: strings.Join(list, ", ")}
}

func k8sNoHostMounts(pods []k8sPod) k8sCheck {
	const name = k8sRuleNoHostMounts
	var found []string
	for _, p := range pods {
		for _, v := range p.Spec.Volumes {
			if v.HostPath != nil {
				found = append(found, fmt.Sprintf("%s: %s (%s)", p.Metadata.Name, v.Name, v.HostPath.Path))
			}
		}
	}
	if len(found) > 0 {
		return k8sCheck{Name: name, Result: k8sFail, Detail: strings.Join(found, "; ")}
	}
	return k8sCheck{Name: name, Result: k8sPass}
}

// k8sNoAPIRights checks no pod holds a Kubernetes API credential, except
// the operator in the release namespace: it is the one part that writes to
// the Kubernetes API (§7.4, §15.1).
func k8sNoAPIRights(pods []k8sPod, releaseNamespace string) k8sCheck {
	const name = k8sRuleNoAPI
	var found []string
	operators := 0
	for _, p := range pods {
		if p.Metadata.Labels[k8sComponent] == "operator" && p.Metadata.Namespace == releaseNamespace {
			operators++
			continue
		}
		if a := p.Spec.AutomountServiceAccountToken; a == nil || *a {
			found = append(found, p.Metadata.Name+": automountServiceAccountToken is not false")
		}
		for _, v := range p.Spec.Volumes {
			if v.Projected == nil {
				continue
			}
			for _, s := range v.Projected.Sources {
				if s.ServiceAccountToken != nil && !k8sJoinIdentityToken(*s.ServiceAccountToken) {
					found = append(found, fmt.Sprintf("%s: volume %s holds a service account token", p.Metadata.Name, v.Name))
				}
			}
		}
	}
	if len(found) > 0 {
		return k8sCheck{Name: name, Result: k8sFail, Detail: strings.Join(found, "; ")}
	}
	if operators > 0 {
		return k8sCheck{Name: name, Result: k8sPass, Detail: fmt.Sprintf("the %d operator pod(s) hold one by design", operators)}
	}
	return k8sCheck{Name: name, Result: k8sPass}
}

// k8sJoinAudience is the audience of the token a joining pod shows the
// operator (plans/kubernetes-v2-architecture.md §15.2).
const k8sJoinAudience = "aerolvm.io/join"

// k8sJoinIdentityToken says whether a projected token is a joining pod's
// proof of who it is: made for the operator's audience alone, which the API
// server refuses, so it opens nothing in the Kubernetes API.
func k8sJoinIdentityToken(raw json.RawMessage) bool {
	var sat struct {
		Audience string `json:"audience"`
	}
	return json.Unmarshal(raw, &sat) == nil && sat.Audience == k8sJoinAudience
}

// k8sPrivileged checks privilege stays where §7 and §15.1 put it: in the
// worker pods' runtime and agent containers, in the worker namespace, the
// one namespace the bank approves for privileged pods. The gateways face
// the internet and the servers hold the placement table, so one of them
// privileged would hand its machine to whoever broke into it. Init
// containers are held to it too: the worker pod needs none privileged.
func k8sPrivileged(pods []k8sPod, workerNamespace string) k8sCheck {
	const name = k8sRulePrivileged
	var bad []string
	workers := 0
	for _, p := range pods {
		worker := p.Metadata.Labels[k8sComponent] == "worker"
		if worker && p.Metadata.Namespace == workerNamespace {
			workers++
		}
		check := func(c k8sContainer, init bool) {
			if !c.privileged() {
				return
			}
			where := p.Metadata.Namespace + "/" + p.Metadata.Name + "/" + c.Name
			switch {
			case p.Metadata.Namespace != workerNamespace:
				bad = append(bad, where+" is privileged outside the worker namespace "+workerNamespace)
			case !worker:
				bad = append(bad, where+" is privileged in a pod that is not a worker")
			case init || !k8sPrivilegedContainers[c.Name]:
				bad = append(bad, where+" is privileged; only runtime and agent may be")
			}
		}
		for _, c := range p.Spec.InitContainers {
			check(c, true)
		}
		for _, c := range p.Spec.Containers {
			check(c, false)
		}
	}
	if len(bad) > 0 {
		return k8sCheck{Name: name, Result: k8sFail, Detail: strings.Join(bad, "; ")}
	}
	return k8sCheck{Name: name, Result: k8sPass, Detail: fmt.Sprintf("%d worker pod(s) in namespace %s", workers, workerNamespace)}
}

// k8sNamespace is the part of `kubectl get namespace -o json` verify reads.
type k8sNamespace struct {
	Metadata struct {
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
}

// k8sPodSecurity checks each namespace's Pod Security label, which decides
// what Kubernetes admits there from now on, not only what runs today. The
// worker namespace must say privileged, so the bank's approval names exactly
// one namespace, and a namespace that says less refuses the worker pods
// when they next start. In cluster mode the release namespace must enforce
// restricted (§15.1). A missing label there fails rather than warns: with
// no label nothing stops a privileged gateway or server after a bad upgrade
// or a hand edit, and that refusal is what a bank's reviewer asks for.
func k8sPodSecurity(ctx context.Context, env k8sEnv, o k8sVerifyOptions) []k8sCheck {
	label := func(ns string) (string, error) {
		raw, err := env.kubectl(ctx, "get", "namespace", ns, "-o", "json")
		if err != nil {
			return "", err
		}
		var n k8sNamespace
		if err := json.Unmarshal(raw, &n); err != nil {
			return "", fmt.Errorf("kubectl output: %w", err)
		}
		return n.Metadata.Labels[k8sPodSecurityEnforce], nil
	}
	want := func(name, ns, level, why string) k8sCheck {
		got, err := label(ns)
		switch {
		case err != nil:
			return k8sCheck{Name: name, Result: k8sFail, Detail: err.Error()}
		case got == "":
			return k8sCheck{Name: name, Result: k8sFail, Detail: fmt.Sprintf("namespace %s has no %s label; set it to %s (%s)", ns, k8sPodSecurityEnforce, level, why)}
		case got != level:
			return k8sCheck{Name: name, Result: k8sFail, Detail: fmt.Sprintf("namespace %s enforces %s, not %s (%s)", ns, got, level, why)}
		}
		return k8sCheck{Name: name, Result: k8sPass, Detail: fmt.Sprintf("namespace %s: %s=%s", ns, k8sPodSecurityEnforce, level)}
	}
	checks := []k8sCheck{want(k8sRuleWorkerNS, o.workerNamespace, "privileged",
		"the one namespace for privileged pods")}
	if o.workerNamespace != o.namespace {
		checks = append(checks, want(k8sRuleReleaseNS, o.namespace, "restricted",
			"gateways, servers and the operator need no rights"))
	}
	return checks
}

// k8sNoDNSToken checks no worker pod holds a DNS provider token (C25):
// cert-manager keeps it in its own namespace and hands the pods only the
// certificate. It reads the pod spec alone, so it needs no right to read
// Secrets: a token can reach a pod as an environment variable, as a whole
// Secret loaded into the environment, or as a Secret volume, so it fails
// on a credential-named variable, on any Secret loaded whole (its names
// cannot be seen), and on a Secret volume that mounts any key but a TLS
// certificate's or does not name its keys.
func k8sNoDNSToken(pods []k8sPod) k8sCheck {
	const name = k8sRuleNoDNSToken
	var found []string
	secret := func(pod, volume string, s *k8sSecretSource) {
		ref := s.SecretName + s.Name
		if len(s.Items) == 0 {
			found = append(found, fmt.Sprintf("%s: volume %s mounts every key of Secret %s (name its keys: tls.crt, tls.key)", pod, volume, ref))
			return
		}
		for _, it := range s.Items {
			// A node's one-time join token (the operator's <pod>-join
			// Secret) is no DNS token: its three keys are allowed there.
			if strings.HasSuffix(ref, "-join") && k8sJoinKeys[it.Key] {
				continue
			}
			if !k8sTLSKeys[it.Key] {
				found = append(found, fmt.Sprintf("%s: volume %s mounts key %s of Secret %s", pod, volume, it.Key, ref))
			}
		}
	}
	for _, p := range pods {
		for _, v := range p.Spec.Volumes {
			if v.Secret != nil {
				secret(p.Metadata.Name, v.Name, v.Secret)
			}
			if v.Projected != nil {
				for _, src := range v.Projected.Sources {
					if src.Secret != nil {
						secret(p.Metadata.Name, v.Name, src.Secret)
					}
				}
			}
		}
		for _, c := range p.all() {
			for _, e := range c.Env {
				if k8sDNSTokenEnv.MatchString(e.Name) {
					found = append(found, fmt.Sprintf("%s/%s: environment variable %s", p.Metadata.Name, c.Name, e.Name))
				}
			}
			for _, ef := range c.EnvFrom {
				if ef.SecretRef != nil {
					found = append(found, fmt.Sprintf("%s/%s: Secret %s loaded whole into the environment", p.Metadata.Name, c.Name, ef.SecretRef.Name))
				}
			}
		}
	}
	if len(found) > 0 {
		return k8sCheck{Name: name, Result: k8sFail, Detail: strings.Join(found, "; ")}
	}
	return k8sCheck{Name: name, Result: k8sPass}
}

// k8sEgressPolicy checks that a NetworkPolicy limits each worker pod's
// egress (C24). Sandbox traffic leaves with the pod's address, so this is
// the wall the bank's cluster sees, around AerolVM's own firewall in the
// pod. A policy that selects the pod but opens a whole private range, every
// address or every pod fails the check: policies add up, so one such rule
// undoes the rest. Only worker pods are held to it; they are the ones that
// carry sandbox traffic. A NetworkPolicy selects pods in its own namespace
// only, so each worker is read against its own namespace's policies.
func k8sEgressPolicy(ctx context.Context, env k8sEnv, pods []k8sPod) k8sCheck {
	const name = k8sRuleEgress
	policies := map[string][]k8sNetworkPolicy{}
	var bad, ok []string
	for _, p := range pods {
		if p.Metadata.Labels[k8sComponent] != "worker" {
			continue
		}
		ns := p.Metadata.Namespace
		if _, read := policies[ns]; !read {
			raw, err := env.kubectl(ctx, "get", "networkpolicies", "-n", ns, "-o", "json")
			if err != nil {
				return k8sCheck{Name: name, Result: k8sFail, Detail: err.Error()}
			}
			var list k8sNetworkPolicyList
			if err := json.Unmarshal(raw, &list); err != nil {
				return k8sCheck{Name: name, Result: k8sFail, Detail: "kubectl output: " + err.Error()}
			}
			policies[ns] = list.Items
		}
		var by []string
		for _, np := range policies[ns] {
			if !np.limitsEgress() || !np.Spec.PodSelector.matches(p.Metadata.Labels) {
				continue
			}
			by = append(by, np.Metadata.Name)
			if open := np.opens(); open != "" {
				bad = append(bad, fmt.Sprintf("%s: NetworkPolicy %s %s", p.Metadata.Name, np.Metadata.Name, open))
			}
		}
		if len(by) == 0 {
			bad = append(bad, p.Metadata.Name+": no NetworkPolicy limits its egress (networkPolicy.enabled in the chart)")
			continue
		}
		ok = append(ok, fmt.Sprintf("%s (%s)", p.Metadata.Name, strings.Join(by, ", ")))
	}
	switch {
	case len(bad) > 0:
		return k8sCheck{Name: name, Result: k8sFail, Detail: strings.Join(bad, "; ")}
	case len(ok) == 0:
		return k8sCheck{Name: name, Result: k8sFail, Detail: "no worker pod (label app.kubernetes.io/component=worker) to check"}
	}
	return k8sCheck{Name: name, Result: k8sPass, Detail: strings.Join(ok, "; ")}
}

// k8sIngressPolicy checks, in cluster mode, that a NetworkPolicy limits who
// reaches each pod of a role: the workers (§8.7, wall 3) and the servers,
// which hold the cluster's state and its admin token (§15.3). The chart's
// let in only this install's pods and Prometheus. A policy whose rule lets
// in every pod or every address fails the check, as for egress. Gateways
// are left out: anyone may reach their client ports by design.
func k8sIngressPolicy(ctx context.Context, env k8sEnv, pods []k8sPod, role, name string) k8sCheck {
	policies := map[string][]k8sNetworkPolicy{}
	var bad, ok []string
	for _, p := range pods {
		if p.Metadata.Labels[k8sComponent] != role {
			continue
		}
		ns := p.Metadata.Namespace
		if _, read := policies[ns]; !read {
			raw, err := env.kubectl(ctx, "get", "networkpolicies", "-n", ns, "-o", "json")
			if err != nil {
				return k8sCheck{Name: name, Result: k8sFail, Detail: err.Error()}
			}
			var list k8sNetworkPolicyList
			if err := json.Unmarshal(raw, &list); err != nil {
				return k8sCheck{Name: name, Result: k8sFail, Detail: "kubectl output: " + err.Error()}
			}
			policies[ns] = list.Items
		}
		var by []string
		for _, np := range policies[ns] {
			if !np.limitsIngress() || !np.Spec.PodSelector.matches(p.Metadata.Labels) {
				continue
			}
			by = append(by, np.Metadata.Name)
			if open := np.admitsAnyone(); open != "" {
				bad = append(bad, fmt.Sprintf("%s: NetworkPolicy %s %s", p.Metadata.Name, np.Metadata.Name, open))
			}
		}
		if len(by) == 0 {
			bad = append(bad, p.Metadata.Name+": no NetworkPolicy limits who reaches it (networkPolicy.enabled in the chart)")
			continue
		}
		ok = append(ok, fmt.Sprintf("%s (%s)", p.Metadata.Name, strings.Join(by, ", ")))
	}
	switch {
	case len(bad) > 0:
		return k8sCheck{Name: name, Result: k8sFail, Detail: strings.Join(bad, "; ")}
	case len(ok) == 0:
		return k8sCheck{Name: name, Result: k8sFail, Detail: fmt.Sprintf("no %s pod (label app.kubernetes.io/component=%s) to check", role, role)}
	}
	return k8sCheck{Name: name, Result: k8sPass, Detail: strings.Join(ok, "; ")}
}

// k8sEndpointSliceList is the part of `kubectl get endpointslices -o json`
// verify reads: the addresses and ports behind a Service.
type k8sEndpointSliceList struct {
	Items []struct {
		Endpoints []struct {
			Addresses []string `json:"addresses"`
		} `json:"endpoints"`
		Ports []struct {
			Port int `json:"port"`
		} `json:"ports"`
	} `json:"items"`
}

// k8sAPIServerTargets are the Kubernetes API server's own addresses, behind
// its Service: a sandbox that cannot reach the Service address may still
// try these directly, so the operator puts them on the deny floor too.
func k8sAPIServerTargets(ctx context.Context, env k8sEnv) []string {
	raw, err := env.kubectl(ctx, "get", "endpointslices", "-n", "default", "-l", "kubernetes.io/service-name=kubernetes", "-o", "json")
	if err != nil {
		return nil
	}
	var list k8sEndpointSliceList
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	var out []string
	for _, s := range list.Items {
		for _, ep := range s.Endpoints {
			for _, a := range ep.Addresses {
				if !k8sIPv4(a) {
					continue
				}
				for _, p := range s.Ports {
					out = append(out, fmt.Sprintf("%s:%d", a, p.Port))
				}
			}
		}
	}
	return out
}

// k8sIPv4 reports an IPv4 address: the only kind a probe tries, since
// container sandboxes have no IPv6 at all.
func k8sIPv4(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

// k8sOtherPodTargets are the cluster DNS pods' own addresses at port 53:
// pods every cluster runs, outside AerolVM, and listening. A sandbox reaches
// DNS through the DNS Service address, which its default leaves open, so
// reaching a DNS pod directly means it can reach the pod network.
func k8sOtherPodTargets(ctx context.Context, env k8sEnv) []string {
	raw, err := env.kubectl(ctx, "get", "pods", "-n", "kube-system", "-l", "k8s-app=kube-dns", "-o", "json")
	if err != nil {
		return nil
	}
	var list k8sPodList
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	var out []string
	for _, p := range list.Items {
		if k8sIPv4(p.Status.PodIP) {
			out = append(out, p.Status.PodIP+":53")
		}
	}
	return out
}

// k8sProbe runs a sandbox of each runtime and has it try every address it
// must not reach: the worker pod's ports on the pod's address and on the
// sandbox bridge's gateway, another pod's address, and the Kubernetes API
// at its Service address and its own addresses. Any that answers fails. In
// cluster mode that is every AerolVM pod's ports; only workers have a
// sandbox bridge, and every worker's is at the same address, so each target
// is tried once.
func k8sProbe(ctx context.Context, env k8sEnv, pods []k8sPod, o k8sVerifyOptions) []k8sCheck {
	var targets []string
	seen := map[string]bool{}
	for _, p := range pods {
		ports := map[int]bool{k8sSSHGatewayPort: true}
		bridge := k8sDefaultBridge
		for _, c := range p.Spec.Containers {
			for _, port := range c.Ports {
				ports[port.ContainerPort] = true
			}
			for _, e := range c.Env {
				if e.Name == "SB_CONTAINERD_BRIDGE_SUBNET" && e.Value != "" {
					bridge = e.Value
				}
			}
		}
		addrs := []string{p.Status.PodIP}
		if prefix, err := netip.ParsePrefix(bridge); err == nil && p.Metadata.Labels[k8sComponent] == "worker" {
			addrs = append(addrs, prefix.Masked().Addr().Next().String())
		}
		sorted := make([]int, 0, len(ports))
		for port := range ports {
			sorted = append(sorted, port)
		}
		sort.Ints(sorted)
		for _, addr := range addrs {
			if addr == "" {
				continue
			}
			for _, port := range sorted {
				if t := fmt.Sprintf("%s:%d", addr, port); !seen[t] {
					seen[t] = true
					targets = append(targets, t)
				}
			}
		}
	}
	if raw, err := env.kubectl(ctx, "get", "svc", "kubernetes", "-n", "default", "-o", "jsonpath={.spec.clusterIP}"); err == nil && strings.TrimSpace(string(raw)) != "" {
		targets = append(targets, strings.TrimSpace(string(raw))+":443")
	}
	targets = append(targets, k8sAPIServerTargets(ctx, env)...)
	var checks []k8sCheck
	other := k8sOtherPodTargets(ctx, env)
	if len(other) == 0 {
		// The probe still runs; say plainly that one wall went untested.
		checks = append(checks, k8sCheck{Name: "another pod's address to probe", Result: k8sSkip, Detail: "no cluster DNS pod (kube-system, k8s-app=kube-dns) with an address"})
	}
	targets = append(targets, other...)
	command := "for t in " + strings.Join(targets, " ") + `; do nc -z -w 3 "${t%:*}" "${t#*:}" 2>/dev/null && echo "$t"; done; true`
	probed := false
	for _, rt := range o.probeRuntimes {
		name := strings.Replace(k8sRuleProbe, "<runtime>", rt, 1)
		out, err := env.probe(ctx, o.probeImage, rt, command)
		switch {
		case err != nil && strings.Contains(err.Error(), `policy rule "runtimes"`):
			// The install's create policy runs no such sandbox (the bank
			// preset allows gVisor only): its walls are moot, not broken.
			checks = append(checks, k8sCheck{Name: name, Result: k8sSkip, Detail: "the create policy allows no " + rt + " sandbox: " + err.Error()})
			continue
		case err != nil:
			checks = append(checks, k8sCheck{Name: name, Result: k8sFail, Detail: "probe: " + err.Error()})
		case strings.TrimSpace(out) != "":
			checks = append(checks, k8sCheck{Name: name, Result: k8sFail, Detail: "reached " + strings.Join(strings.Fields(out), ", ")})
		default:
			checks = append(checks, k8sCheck{Name: name, Result: k8sPass, Detail: fmt.Sprintf("%d addresses refused", len(targets))})
		}
		probed = true
	}
	if !probed && len(o.probeRuntimes) > 0 {
		// Every runtime refused: nothing was probed, and that is no pass.
		checks = append(checks, k8sCheck{Name: strings.Replace(k8sRuleProbe, "<runtime>", strings.Join(o.probeRuntimes, " or "), 1),
			Result: k8sFail, Detail: "no probe sandbox could be made: set --probe-runtimes to a runtime this install allows"})
	}
	return checks
}

// cosignFailure is a failed `cosign verify`: its last line, and a hint when
// the cosign here is too old for the release's signatures. The release signs
// with cosign v3, in its newer bundle format, which cosign v2 cannot find:
// it reports "no signatures found" for an image that is signed.
func cosignFailure(err error, out []byte) error {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	last := lines[len(lines)-1]
	if strings.Contains(string(out), "no signatures found") {
		last += " (the release signs with cosign v3; check with cosign v3 or later)"
	}
	return fmt.Errorf("%v: %s", err, last)
}

// k8sEnvFor builds the real environment; tests replace it.
var k8sEnvFor = func(a *app, c *commonFlags, kubeContext string) k8sEnv {
	return k8sEnv{
		kubectl: func(ctx context.Context, args ...string) ([]byte, error) {
			if kubeContext != "" {
				args = append([]string{"--context", kubeContext}, args...)
			}
			out, err := exec.CommandContext(ctx, "kubectl", args...).Output()
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return nil, fmt.Errorf("kubectl %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
			}
			return out, err
		},
		cosign: func(ctx context.Context, image string) error {
			cmd := exec.CommandContext(ctx, "cosign", "verify", image,
				"--certificate-identity-regexp", k8sSignerIdentity,
				"--certificate-oidc-issuer", k8sSignerIssuer)
			if out, err := cmd.CombinedOutput(); err != nil {
				return cosignFailure(err, out)
			}
			return nil
		},
		probe: func(ctx context.Context, image, runtime, command string) (string, error) {
			tools, err := a.tools(ctx, c)
			if err != nil {
				return "", err
			}
			res, err := tools.GetOrCreate(ctx, agenttools.CreateSpec{Image: image, Runtime: runtime})
			if err != nil {
				return "", err
			}
			defer func() { _ = tools.Client().Destroy(context.WithoutCancel(ctx), res.Sandbox.ID) }()
			out, err := tools.Exec(ctx, res.Sandbox, agenttools.ExecRequest{Command: command})
			if err != nil {
				return "", err
			}
			return out.Stdout, nil
		},
		// The aws CLI reads the caller's own credentials (environment,
		// profile, SSO) as it always does; verify neither asks for nor keeps
		// them.
		aws: func(ctx context.Context, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, "aws", args...)
			// The output is read here, not by a person: no pager.
			cmd.Env = append(os.Environ(), "AWS_PAGER=")
			out, err := cmd.Output()
			var ee *exec.ExitError
			switch {
			case errors.Is(err, exec.ErrNotFound):
				return nil, errK8sNoAWSCLI
			case errors.As(err, &ee):
				return nil, awsFailure(ee.ExitCode(), ee.Stderr)
			}
			return out, err
		},
	}
}

func runK8s(ctx context.Context, a *app, args []string) int {
	if len(args) == 0 || args[0] != "verify" {
		_, c := a.newFlagSet("k8s")
		return a.usageError(c, "k8s", "expected: aerolvm k8s verify")
	}
	fs, c := a.newFlagSet("k8s verify")
	var o k8sVerifyOptions
	var kubeContext, runtimes string
	fs.StringVar(&o.namespace, "namespace", "aerolvm", "")
	fs.StringVar(&o.workerNamespace, "worker-namespace", "", "")
	fs.StringVar(&o.release, "release", "aerolvm", "")
	fs.StringVar(&o.cluster, "cluster", "", "")
	fs.StringVar(&kubeContext, "kube-context", "", "")
	fs.StringVar(&o.probeImage, "probe-image", "alpine:3.20", "")
	fs.StringVar(&runtimes, "probe-runtimes", "docker,gvisor", "")
	fs.BoolVar(&o.skipSignatures, "skip-signatures", false, "")
	pos, _, err := parseArgs(fs, args[1:])
	if err != nil {
		return a.flagError(c, "k8s", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "k8s", "unexpected argument %q", pos[0])
	}
	for _, rt := range strings.Split(runtimes, ",") {
		if rt = strings.TrimSpace(rt); rt != "" {
			o.probeRuntimes = append(o.probeRuntimes, rt)
		}
	}
	checks := k8sVerify(ctx, k8sEnvFor(a, c, kubeContext), o)
	failed := 0
	for _, ch := range checks {
		switch ch.Result {
		case k8sFail:
			failed++
		case k8sSkip:
			// A skip passes the run, so say it where a person or a CI log
			// will see it, apart from the table.
			a.note("aerolvm: warning: not checked: %s: %s", ch.Name, ch.Detail)
		}
	}
	if c.json {
		a.printJSON(map[string]any{"ok": failed == 0, "checks": checks})
	} else {
		rows := make([][]string, 0, len(checks))
		for _, ch := range checks {
			rows = append(rows, []string{strings.ToUpper(ch.Result), ch.Name, ch.Detail})
		}
		table(a.stdout, "RESULT\tCHECK\tDETAIL", rows)
	}
	if failed > 0 {
		a.note("aerolvm: %d check(s) failed", failed)
		return exitError
	}
	return exitOK
}

const k8sHelp = `Check a Kubernetes install of AerolVM against its security rules.

Usage: aerolvm k8s verify [--namespace aerolvm] [--worker-namespace <ns>]
                          [--release aerolvm] [--cluster <name>]
                          [--kube-context <name>] [--skip-signatures]
                          [--probe-image alpine:3.20] [--probe-runtimes docker,gvisor]
                          [--json]

Checks, and exits 1 if any fails:
  - every image is signed by the AerolVM release workflow (needs cosign);
  - no pod mounts a folder from the machine;
  - no pod but the operator holds a Kubernetes API credential;
  - no pod holds a DNS provider token (Secret volumes may mount only
    tls.crt, tls.key and ca.crt, by name);
  - only the worker pods' runtime and agent containers are privileged, and
    only in the worker namespace;
  - the worker namespace is labelled pod-security.kubernetes.io/enforce=
    privileged, and in cluster mode the release namespace enforces
    restricted;
  - a NetworkPolicy limits each worker pod's egress, and none of the
    policies on it opens a whole private range, every address or every pod;
  - on AWS, each machine that runs a worker pod allows IMDSv2 only, with a
    hop limit of 1, so no pod or sandbox can reach the metadata service;
  - with gateways.gatewayRef, your Gateway accepted the HTTPRoute
    <cluster>-api, the TLSRoute <cluster>-links and the TCPRoute
    <cluster>-ssh, and the listener for sandbox links passes TLS through;
  - a sandbox of each probe runtime cannot reach the AerolVM pods' own
    ports, a cluster DNS pod's address, or the Kubernetes API at its
    Service address and its own addresses.

--namespace is where the chart is installed. In cluster mode the worker
pods run in their own namespace: pass it as --worker-namespace (by default
the same namespace, as in single mode). --cluster is the AerolCluster's
name, the release name by default.

It reads the cluster with your kubectl, and creates the probe sandboxes
through the AerolVM API you are logged in to (aerolvm login, or SB_API_URL
and SB_PAT_TOKEN, for example through kubectl port-forward). The probe
sandboxes are deleted afterwards. It reads the IMDS settings with your aws
CLI and your own AWS credentials (AWS_PROFILE and the rest work as usual);
it never stores them. It needs ec2:DescribeInstances.

A check that cannot run is reported as SKIP, with a warning, and does not
fail the run: the IMDS check when there is no aws CLI, no AWS credentials,
or the machines are not on AWS. --skip-signatures reports the image check
as skipped, for images you built yourself.
`
