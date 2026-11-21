//go:build linux && kerneltest

package netrules

// Real-kernel checks of ReplaceEgressPolicy (the root helper's policy
// write), on both rule backends, in a privileged Linux container:
//
//	go test -tags kerneltest ./pkg/docker/netrules/ -run 'KernelReplace'
//
// A first policy leaves exactly ApplyEgressPolicy's rules; a reapply of the
// policy in place leaves every rule where it was (same nft handles, so not
// rewritten); a change leaves only the new policy; the biggest policy
// allowed goes in whole on netlink (more rules than one netlink message
// carries); the clear takes every rule of the address and no other.

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// kernelBigPolicy is the root helper's largest policy (its
// rootpolicy.MaxPolicyCIDRs): more rules than one netlink message carries.
const kernelBigPolicy = 1024

// handles is the user and input chains' nft listing with rule handles.
func handles() string {
	var sb strings.Builder
	for _, c := range []string{ChainAerolvmUser, ChainAerolvmInput} {
		out, _ := exec.Command("nft", "-a", "list", "chain", "ip", "filter", c).CombinedOutput()
		sb.Write(out)
	}
	return sb.String()
}

func TestKernelReplaceEgressPolicy(t *testing.T) {
	const ip = "10.97.0.2"
	keyed := regexp.MustCompile(`-s ` + regexp.QuoteMeta(ip) + `/32 .*sbx-egress`)
	// The address's policy rules in both chains (AEROLVM-INPUT exists only
	// once an allowlist has needed it).
	listing := func() string {
		var sb strings.Builder
		for _, c := range []string{ChainAerolvmUser, ChainAerolvmInput} {
			out, _ := exec.Command("iptables", "-w", "-S", c).CombinedOutput()
			sb.Write(out)
		}
		return sb.String()
	}
	policy := func(*testing.T) []string { return keyed.FindAllString(listing(), -1) }
	for _, backend := range []string{BackendNetlink, BackendExec} {
		t.Run(backend, func(t *testing.T) {
			freshFilter(t)
			ref := func(allow, deny []string) []string {
				// ApplyEgressPolicy's rules on a fresh chain: the reference.
				freshFilter(t)
				m := kernelManager(t, true)
				if err := m.ApplyEgressPolicy(ip, allow, deny); err != nil {
					t.Fatal(err)
				}
				return policy(t)
			}
			first, change := [2][]string{{"192.0.2.7/32", "198.51.100.0/24"}, nil}, [2][]string{{"192.0.2.9/32"}, {"10.0.0.0/8"}}
			wantFirst, wantChange := ref(first[0], first[1]), ref(change[0], change[1])

			freshFilter(t)
			m, err := NewWithOptions(true, backend, ChainAerolvmUser)
			if err != nil {
				t.Fatal(err)
			}
			if err := m.EnsureChain(); err != nil {
				t.Fatal(err)
			}
			neighbours(t, m, 5)
			ctx := context.Background()
			if err := m.ReplaceEgressPolicy(ctx, ip, first[0], first[1]); err != nil {
				t.Fatal(err)
			}
			if got := policy(t); strings.Join(got, "\n") != strings.Join(wantFirst, "\n") {
				t.Fatalf("first policy:\n got %q\nwant %q", got, wantFirst)
			}
			before := handles()
			if err := m.ReplaceEgressPolicy(ctx, ip, first[0], first[1]); err != nil {
				t.Fatal(err)
			}
			if after := handles(); after != before {
				t.Fatalf("a reapply of the policy in place rewrote rules:\n--- before\n%s\n--- after\n%s", before, after)
			}
			if err := m.ReplaceEgressPolicy(ctx, ip, change[0], change[1]); err != nil {
				t.Fatal(err)
			}
			if got := policy(t); strings.Join(got, "\n") != strings.Join(wantChange, "\n") {
				t.Fatalf("changed policy:\n got %q\nwant %q", got, wantChange)
			}
			if backend == BackendNetlink {
				big := make([]string, kernelBigPolicy)
				for i := range big {
					big[i] = fmt.Sprintf("21.%d.%d.0/24", i/256, i%256)
				}
				if err := m.ReplaceEgressPolicy(ctx, ip, big, nil); err != nil {
					t.Fatal(err)
				}
				// Each allow twice (forward ACCEPT, input RETURN), and the
				// two catch-all DROPs.
				if n := len(policy(t)); n != 2*len(big)+2 {
					t.Fatalf("the biggest policy left %d rules, want %d", n, 2*len(big)+2)
				}
			}
			if err := m.ClearEgressPolicyOf(ip); err != nil {
				t.Fatal(err)
			}
			rest := listing()
			if keyed.MatchString(rest) || !strings.Contains(rest, "10.98.0.2") {
				t.Fatalf("the clear left the address's rules or took a neighbour's:\n%s", rest)
			}
		})
	}
}
