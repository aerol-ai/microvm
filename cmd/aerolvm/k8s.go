package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
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
// Kubernetes API credential, and a probe sandbox cannot reach the worker's
// own ports or the Kubernetes API (C24). Phase 2 adds the full layout.
//
// It reads the cluster with the kubectl and cosign already on this machine
// (so the CLI carries no Kubernetes client), and probes through the AerolVM
// API the CLI is logged in to.

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
)

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
}

type k8sVerifyOptions struct {
	namespace, release, probeImage string
	probeRuntimes                  []string
	skipSignatures                 bool
}

// k8sPodList is the part of `kubectl get pods -o json` verify reads.
type k8sPodList struct {
	Items []k8sPod `json:"items"`
}

type k8sPod struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		AutomountServiceAccountToken *bool `json:"automountServiceAccountToken"`
		Volumes                      []struct {
			Name     string `json:"name"`
			HostPath *struct {
				Path string `json:"path"`
			} `json:"hostPath"`
			Projected *struct {
				Sources []struct {
					ServiceAccountToken *json.RawMessage `json:"serviceAccountToken"`
				} `json:"sources"`
			} `json:"projected"`
		} `json:"volumes"`
		Containers []struct {
			Name  string `json:"name"`
			Image string `json:"image"`
			Ports []struct {
				ContainerPort int `json:"containerPort"`
			} `json:"ports"`
			Env []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"env"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		PodIP string `json:"podIP"`
	} `json:"status"`
}

// k8sVerify runs every check and returns them in order.
func k8sVerify(ctx context.Context, env k8sEnv, o k8sVerifyOptions) []k8sCheck {
	selector := "app.kubernetes.io/name=aerolvm,app.kubernetes.io/instance=" + o.release
	raw, err := env.kubectl(ctx, "get", "pods", "-n", o.namespace, "-l", selector, "-o", "json")
	if err != nil {
		return []k8sCheck{{Name: "AerolVM pods found", Result: k8sFail, Detail: err.Error()}}
	}
	var pods k8sPodList
	if err := json.Unmarshal(raw, &pods); err != nil || len(pods.Items) == 0 {
		detail := fmt.Sprintf("no pods labelled %s in namespace %s", selector, o.namespace)
		if err != nil {
			detail = "kubectl output: " + err.Error()
		}
		return []k8sCheck{{Name: "AerolVM pods found", Result: k8sFail, Detail: detail}}
	}
	checks := []k8sCheck{{Name: "AerolVM pods found", Result: k8sPass, Detail: strconv.Itoa(len(pods.Items)) + " pod(s)"}}
	checks = append(checks, k8sImagesSigned(ctx, env, pods.Items, o.skipSignatures))
	checks = append(checks, k8sNoHostMounts(pods.Items), k8sNoAPIRights(pods.Items))
	checks = append(checks, k8sProbe(ctx, env, pods.Items, o)...)
	return checks
}

func k8sImagesSigned(ctx context.Context, env k8sEnv, pods []k8sPod, skip bool) k8sCheck {
	const name = "images signed by the AerolVM release workflow"
	images := map[string]bool{}
	for _, p := range pods {
		for _, c := range p.Spec.Containers {
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
	const name = "no folders mounted from the machine"
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

func k8sNoAPIRights(pods []k8sPod) k8sCheck {
	const name = "no Kubernetes API credential in the pods"
	var found []string
	for _, p := range pods {
		if a := p.Spec.AutomountServiceAccountToken; a == nil || *a {
			found = append(found, p.Metadata.Name+": automountServiceAccountToken is not false")
		}
		for _, v := range p.Spec.Volumes {
			if v.Projected == nil {
				continue
			}
			for _, s := range v.Projected.Sources {
				if s.ServiceAccountToken != nil {
					found = append(found, fmt.Sprintf("%s: volume %s holds a service account token", p.Metadata.Name, v.Name))
				}
			}
		}
	}
	if len(found) > 0 {
		return k8sCheck{Name: name, Result: k8sFail, Detail: strings.Join(found, "; ")}
	}
	return k8sCheck{Name: name, Result: k8sPass}
}

// k8sProbe runs a sandbox of each runtime and has it try every address it
// must not reach: the worker pod's ports on the pod's address and on the
// sandbox bridge's gateway, and the Kubernetes API. Any that answers fails.
func k8sProbe(ctx context.Context, env k8sEnv, pods []k8sPod, o k8sVerifyOptions) []k8sCheck {
	var targets []string
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
		if prefix, err := netip.ParsePrefix(bridge); err == nil {
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
				targets = append(targets, fmt.Sprintf("%s:%d", addr, port))
			}
		}
	}
	if raw, err := env.kubectl(ctx, "get", "svc", "kubernetes", "-n", "default", "-o", "jsonpath={.spec.clusterIP}"); err == nil && strings.TrimSpace(string(raw)) != "" {
		targets = append(targets, strings.TrimSpace(string(raw))+":443")
	}
	command := "for t in " + strings.Join(targets, " ") + `; do nc -z -w 3 "${t%:*}" "${t#*:}" 2>/dev/null && echo "$t"; done; true`
	var checks []k8sCheck
	for _, rt := range o.probeRuntimes {
		name := fmt.Sprintf("a %s sandbox cannot reach the worker or the Kubernetes API", rt)
		out, err := env.probe(ctx, o.probeImage, rt, command)
		switch {
		case err != nil:
			checks = append(checks, k8sCheck{Name: name, Result: k8sFail, Detail: "probe: " + err.Error()})
		case strings.TrimSpace(out) != "":
			checks = append(checks, k8sCheck{Name: name, Result: k8sFail, Detail: "reached " + strings.Join(strings.Fields(out), ", ")})
		default:
			checks = append(checks, k8sCheck{Name: name, Result: k8sPass, Detail: fmt.Sprintf("%d addresses refused", len(targets))})
		}
	}
	return checks
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
				lines := strings.Split(strings.TrimSpace(string(out)), "\n")
				return fmt.Errorf("%v: %s", err, lines[len(lines)-1])
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
	fs.StringVar(&o.release, "release", "aerolvm", "")
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
		if ch.Result == k8sFail {
			failed++
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

Usage: aerolvm k8s verify [--namespace aerolvm] [--release aerolvm]
                          [--kube-context <name>] [--skip-signatures]
                          [--probe-image alpine:3.20] [--probe-runtimes docker,gvisor]
                          [--json]

Checks, and exits 1 if any fails:
  - every image is signed by the AerolVM release workflow (needs cosign);
  - no pod mounts a folder from the machine;
  - no pod holds a Kubernetes API credential;
  - a sandbox of each probe runtime cannot reach the worker pod's own ports
    or the Kubernetes API.

It reads the cluster with your kubectl, and creates the probe sandboxes
through the AerolVM API you are logged in to (aerolvm login, or SB_API_URL
and SB_PAT_TOKEN, for example through kubectl port-forward). The probe
sandboxes are deleted afterwards. --skip-signatures reports the image check
as skipped, for images you built yourself.
`
