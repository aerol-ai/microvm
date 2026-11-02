package docker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

// nodeRecorder is a rule backend with the chain management the node guard
// needs; it keeps every rule as "chain spec".
type nodeRecorder struct{ rules []string }

func (n *nodeRecorder) Exists(_, chain string, spec ...string) (bool, error) {
	return slices.Contains(n.rules, chain+" "+strings.Join(spec, " ")), nil
}
func (n *nodeRecorder) Insert(_, chain string, _ int, spec ...string) error {
	n.rules = append(n.rules, chain+" "+strings.Join(spec, " "))
	return nil
}
func (n *nodeRecorder) Delete(_, chain string, spec ...string) error {
	k := chain + " " + strings.Join(spec, " ")
	if i := slices.Index(n.rules, k); i >= 0 {
		n.rules = slices.Delete(n.rules, i, i+1)
		return nil
	}
	return errors.New("No chain/target/match by that name.")
}
func (n *nodeRecorder) EnsureUserChain(string) error         { return nil }
func (n *nodeRecorder) EnsureForwardJump(string) error       { return nil }
func (n *nodeRecorder) EnsureInputChain(string) error        { return nil }
func (n *nodeRecorder) EnsureJumpChain(string, string) error { return nil }
func (n *nodeRecorder) FlushChain(chain string) error {
	n.rules = slices.DeleteFunc(n.rules, func(r string) bool { return strings.HasPrefix(r, chain+" ") })
	return nil
}

func bridgeAPI(status int, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
}

// TestDockerNodeGuard: the guard is scoped to the sandbox network's subnet
// as dockerd reports it; without a firewall the caller hears that it is
// unavailable, never that it is in place.
func TestDockerNodeGuard(t *testing.T) {
	ctx := context.Background()
	if err := (&Client{}).SetNodeGuard(ctx, nil); !errors.Is(err, runtime.ErrNodeGuardUnavailable) {
		t.Fatalf("no rules manager: %v", err)
	}
	off, err := netrules.New(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Client{networkRules: off}).SetNodeGuard(ctx, nil); !errors.Is(err, runtime.ErrNodeGuardUnavailable) {
		t.Fatalf("rules disabled: %v", err)
	}
	if repaired, err := (&Client{}).ReassertNodeGuard(ctx); repaired || err != nil {
		t.Fatal("no rules manager: nothing to re-assert")
	}
	be := &nodeRecorder{}
	c := &Client{networkRules: netrules.NewWithBackend(be), httpClient: bridgeAPI(http.StatusOK,
		`{"Id":"abc","IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}`)}
	if err := c.SetNodeGuard(ctx, []netrules.NodePort{{Proto: "tcp", Port: 15080}}); err != nil {
		t.Fatal(err)
	}
	chains := netrules.NodeChainsFor(netip.MustParsePrefix("172.17.0.0/16"))
	for _, want := range []string{
		netrules.ChainAerolvmNode + " -s 172.17.0.0/16 -j " + chains[0],
		chains[0] + " -s 172.17.0.0/16 -p tcp --dport 15080 -m comment --comment sbx-node-guard -j RETURN",
		chains[0] + " -s 172.17.0.0/16 -m comment --comment sbx-node-guard -j DROP",
	} {
		if !slices.Contains(be.rules, want) {
			t.Errorf("missing %q in %q", want, be.rules)
		}
	}
	if repaired, err := c.ReassertNodeGuard(ctx); repaired || err != nil {
		t.Fatalf("an intact guard: %v %v", repaired, err)
	}
	failing := &Client{networkRules: netrules.NewWithBackend(be), httpClient: bridgeAPI(http.StatusInternalServerError, "x")}
	if err := failing.SetNodeGuard(ctx, nil); err == nil {
		t.Fatal("bridge discovery errors surface")
	}
}
