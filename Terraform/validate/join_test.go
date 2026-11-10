package validate

import (
	"regexp"
	"strings"
	"testing"
)

// node_join_tokens is kubeadm's "a fresh token for a node added later":
// the module's server token lasts 24h, so a server added after that joins
// with a token made on the cluster (`aerolvm join-command --json`). These
// checks keep its three promises offline: the value is a token the
// cluster will parse, it reaches only the node it names, and the seed (which
// never joins) cannot be named.

func TestNodeJoinTokensMatchTheClusterTokenFormat(t *testing.T) {
	block := hclVariable(readTF(t, "variables.tf"), "node_join_tokens")
	if block == "" {
		t.Fatal("Terraform/variables.tf declares no node_join_tokens")
	}
	for _, want := range []string{"type        = map(string)", "sensitive   = true", "nullable    = false", "default     = {}"} {
		if !strings.Contains(block, want) {
			t.Errorf("node_join_tokens lacks %q:\n%s", want, block)
		}
	}
	// The validation's regex is the cluster's joinTokenPattern, so Terraform
	// refuses at plan what the join port would refuse at boot.
	tf := regexp.MustCompile(`regex\("([^"]+)", t\)`).FindStringSubmatch(block)
	if tf == nil {
		t.Fatalf("node_join_tokens has no regex validation:\n%s", block)
	}
	goSrc := readTF(t, "..", "internal", "cluster", "pki.go")
	g := regexp.MustCompile("joinTokenPattern = regexp.MustCompile\\(`([^`]+)`\\)").FindStringSubmatch(goSrc)
	if g == nil {
		t.Fatal("internal/cluster/pki.go has no joinTokenPattern")
	}
	if want := strings.ReplaceAll(g[1], `\`, `\\`); tf[1] != want {
		t.Errorf("node_join_tokens validates %q, but the cluster's token pattern is %q (HCL-escaped %q)", tf[1], g[1], want)
	}
	re := regexp.MustCompile(g[1])
	for tok, ok := range map[string]bool{
		"abcdef.0123456789abcdefghijklmnopqrstuv": true,
		"ABCDEF.0123456789abcdefghijklmnopqrstuv": false,
		"abcdef.short": false,
		"abcdef0123456789abcdefghijklmnopqrstuvw": false,
	} {
		if re.MatchString(tok) != ok {
			t.Errorf("token %q: match=%v, want %v", tok, !ok, ok)
		}
	}
}

func TestNodeJoinTokensReachOnlyTheNodeTheyName(t *testing.T) {
	nodes := readTF(t, "nodes.tf")
	seed := between(t, nodes, `resource "aws_instance" "seed" {`, `resource "aws_instance" "joiner" {`)
	joiner := between(t, nodes, `resource "aws_instance" "joiner" {`, `resource "aws_s3_object" "joiner_identity" {`)
	if strings.Contains(seed, "node_join_tokens") {
		t.Error("the seed's user data reads node_join_tokens; the seed starts the cluster and never joins")
	}
	if !regexp.MustCompile(`join_token\s+= lookup\(var\.node_join_tokens, each\.key, local\.join_tokens\[local\.node_join_role\[each\.key\]\]\)`).MatchString(joiner) {
		t.Error("a joiner's join_token must be lookup(var.node_join_tokens, each.key, <its role's module token>): a fresh token for that node only, else the module's")
	}
	if !regexp.MustCompile(`(?s)precondition \{\s*condition\s+= alltrue\(\[for name in keys\(var\.node_join_tokens\) : contains\(keys\(local\.joiner_nodes\), name\)\]\)`).MatchString(joiner) {
		t.Error("the joiner must refuse a node_join_tokens key that is not a joiner (the seed, or a typo)")
	}
	if !regexp.MustCompile(`join_role\s+= local\.node_join_role\[each\.key\]`).MatchString(joiner) {
		t.Error("a joiner's user data needs join_role: its refusal message names `aerolvm join-command --role <it>`")
	}
}

// between returns src from the first start up to the next end.
func between(t *testing.T, src, start, end string) string {
	t.Helper()
	i := strings.Index(src, start)
	if i < 0 {
		t.Fatalf("no %q", start)
	}
	j := strings.Index(src[i:], end)
	if j < 0 {
		t.Fatalf("no %q after %q", end, start)
	}
	return src[i : i+j]
}
