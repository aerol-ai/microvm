package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The IMDS hop limit (plans/kubernetes-v2-architecture.md §8.4, P8 Phase 2).
// The cloud metadata service hands out the machine's IAM credentials, so it
// is blocked twice: AerolVM's own firewall drops sandbox traffic to it, and
// the machine itself must refuse anything that is not on the machine.
//
// That second wall is two settings. HttpTokens=required turns IMDSv1 off:
// IMDSv1 answers a plain GET from anywhere that can route to it, so the hop
// limit does nothing for it. HttpPutResponseHopLimit=1 then sends the IMDSv2
// token back with an IP TTL of 1. A pod has its own network namespace, one
// hop past the machine (AWS: "going to the container is considered an
// additional network hop"), and a sandbox is one more inside the pod, so the
// token dies on the way and neither can call the service. Karpenter's
// default node class sets exactly this; managed node groups with a custom
// launch template default to a hop limit of 2, which lets every pod in. A
// machine with the service turned off (HttpEndpoint=disabled) passes too.
//
// It is read with the caller's own aws CLI and credentials. With neither,
// or on machines that are not EC2 instances, the check is skipped with a
// warning and does not fail the run (the plan's error table).

var (
	errK8sNoAWSCLI         = errors.New("no aws CLI on PATH")
	errK8sNoAWSCredentials = errors.New("no AWS credentials")
)

// k8sIMDSBatch keeps each describe-instances command line short; the aws
// CLI pages through the answer itself.
const k8sIMDSBatch = 100

// k8sAWSRegion takes the region from the front of a zone: us-east-1a, a
// Local Zone (us-west-2-lax-1a), a Wavelength Zone (us-east-1-wl1-bos-wlz-1),
// GovCloud (us-gov-west-1a) and the isolated regions (us-isob-east-1a).
var k8sAWSRegion = regexp.MustCompile(`^([a-z]{2}(?:-gov|-iso[a-z]*)?-[a-z]+-\d+)`)

// k8sAWSInstance reads an EC2 node's spec.providerID, aws:///<zone>/<id>.
func k8sAWSInstance(providerID string) (region, id string, ok bool) {
	rest, ok := strings.CutPrefix(providerID, "aws:///")
	if !ok {
		return "", "", false
	}
	zone, id, ok := strings.Cut(rest, "/")
	m := k8sAWSRegion.FindStringSubmatch(zone)
	if !ok || m == nil || !strings.HasPrefix(id, "i-") {
		return "", "", false
	}
	return m[1], id, true
}

// k8sEC2Instances is the part of `aws ec2 describe-instances` verify reads.
type k8sEC2Instances struct {
	Reservations []struct {
		Instances []struct {
			InstanceID      string           `json:"InstanceId"`
			MetadataOptions *k8sIMDSSettings `json:"MetadataOptions"`
		} `json:"Instances"`
	} `json:"Reservations"`
}

type k8sIMDSSettings struct {
	HTTPTokens              string `json:"HttpTokens"`
	HTTPPutResponseHopLimit int    `json:"HttpPutResponseHopLimit"`
	HTTPEndpoint            string `json:"HttpEndpoint"`
}

// problem names what lets a pod reach the service, or "" when nothing does.
func (m *k8sIMDSSettings) problem() string {
	if m == nil {
		return "no metadata options in the answer"
	}
	if m.HTTPEndpoint == "disabled" {
		return ""
	}
	var p []string
	if m.HTTPTokens != "required" {
		p = append(p, fmt.Sprintf("IMDSv1 is on (HttpTokens %s, want required)", m.HTTPTokens))
	}
	if m.HTTPPutResponseHopLimit != 1 {
		p = append(p, fmt.Sprintf("hop limit %d, want 1", m.HTTPPutResponseHopLimit))
	}
	return strings.Join(p, ", ")
}

// awsFailure is a failed aws command: its last line, marked as missing
// credentials when that is why. aws CLI v2 exits 253 when the
// configuration or credentials it needs are missing; v1 exits 255, so the
// message is matched too. Expired or refused credentials are not missing:
// the caller gave some, so that fails instead of skipping.
func awsFailure(code int, stderr []byte) error {
	lines := strings.Split(strings.TrimSpace(string(stderr)), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if code == 253 || strings.Contains(string(stderr), "Unable to locate credentials") {
		return fmt.Errorf("%w: %s", errK8sNoAWSCredentials, last)
	}
	return fmt.Errorf("exit status %d: %s", code, last)
}

// k8sIMDS checks the IMDS settings of every machine that runs a worker pod.
func k8sIMDS(ctx context.Context, env k8sEnv, pods []k8sPod) k8sCheck {
	const name = k8sRuleIMDS
	nodes := map[string]bool{}
	for _, p := range pods {
		if p.Metadata.Labels[k8sComponent] == "worker" && p.Spec.NodeName != "" {
			nodes[p.Spec.NodeName] = true
		}
	}
	if len(nodes) == 0 {
		return k8sCheck{Name: name, Result: k8sSkip, Detail: "no worker pod is on a machine yet"}
	}
	// One list for every node, printed small: a name and a providerID each.
	raw, err := env.kubectl(ctx, "get", "nodes", "-o", `jsonpath={range .items[*]}{.metadata.name}{"\t"}{.spec.providerID}{"\n"}{end}`)
	if err != nil {
		return k8sCheck{Name: name, Result: k8sFail, Detail: "reading the nodes: " + err.Error()}
	}
	providers := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if n, id, ok := strings.Cut(line, "\t"); ok {
			providers[n] = id
		}
	}
	names := make([]string, 0, len(nodes))
	for n := range nodes {
		names = append(names, n)
	}
	sort.Strings(names)
	byRegion := map[string][]string{}
	nodeOf := map[string]string{}
	var unchecked []string
	for _, n := range names {
		region, id, ok := k8sAWSInstance(providers[n])
		if !ok {
			unchecked = append(unchecked, fmt.Sprintf("%s (providerID %q)", n, providers[n]))
			continue
		}
		byRegion[region] = append(byRegion[region], id)
		nodeOf[id] = n
	}
	regions := make([]string, 0, len(byRegion))
	for r := range byRegion {
		regions = append(regions, r)
	}
	sort.Strings(regions)
	var bad []string
	checked := 0
	for _, region := range regions {
		ids := byRegion[region]
		for start := 0; start < len(ids); start += k8sIMDSBatch {
			batch := ids[start:min(start+k8sIMDSBatch, len(ids))]
			args := append([]string{"ec2", "describe-instances", "--region", region, "--output", "json", "--instance-ids"}, batch...)
			out, err := env.aws(ctx, args...)
			switch {
			case errors.Is(err, errK8sNoAWSCLI), errors.Is(err, errK8sNoAWSCredentials):
				return k8sCheck{Name: name, Result: k8sSkip, Detail: err.Error() + "; the IMDS settings of " + strings.Join(names, ", ") + " were not read"}
			case err != nil:
				return k8sCheck{Name: name, Result: k8sFail, Detail: "aws ec2 describe-instances: " + err.Error()}
			}
			var answer k8sEC2Instances
			if err := json.Unmarshal(out, &answer); err != nil {
				return k8sCheck{Name: name, Result: k8sFail, Detail: "aws output: " + err.Error()}
			}
			seen := map[string]bool{}
			for _, r := range answer.Reservations {
				for _, in := range r.Instances {
					seen[in.InstanceID] = true
					if p := in.MetadataOptions.problem(); p != "" {
						bad = append(bad, fmt.Sprintf("%s (%s): %s", nodeOf[in.InstanceID], in.InstanceID, p))
					}
				}
			}
			for _, id := range batch {
				if !seen[id] {
					bad = append(bad, fmt.Sprintf("%s (%s): not in the answer", nodeOf[id], id))
				}
			}
			checked += len(batch)
		}
	}
	switch {
	case len(bad) > 0:
		return k8sCheck{Name: name, Result: k8sFail, Detail: strings.Join(bad, "; ")}
	case len(unchecked) > 0:
		return k8sCheck{Name: name, Result: k8sSkip, Detail: fmt.Sprintf("not EC2 instances, so not read: %s; %d EC2 instance(s) passed", strings.Join(unchecked, ", "), checked)}
	}
	return k8sCheck{Name: name, Result: k8sPass, Detail: fmt.Sprintf("%d EC2 instance(s)", checked)}
}
