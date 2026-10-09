//go:build linux

package netrules

import (
	"errors"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestNetlinkEnsureInputChain(t *testing.T) {
	fake := &fakeNFT{}
	b := &netlinkBackend{newConn: func() (nftAPI, error) { return fake, nil }}
	for i := 0; i < 2; i++ {
		if err := b.EnsureInputChain(ChainAerolvmInput); err != nil {
			t.Fatalf("EnsureInputChain #%d: %v", i, err)
		}
	}
	var returns, jumps int
	for _, r := range fake.rules {
		if isEstablishedReturn(r) {
			returns++
		}
		for _, e := range r.Exprs {
			if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictJump && v.Chain == ChainAerolvmInput {
				jumps++
			}
		}
	}
	if returns != 1 || jumps != 1 {
		t.Fatalf("returns=%d jumps=%d, want 1/1 (idempotent)", returns, jumps)
	}
	// AEROLVM-INPUT plus the INPUT base chain (absent on a fresh nft host),
	// each created exactly once across both calls.
	if len(fake.addedChain) != 2 || fake.addedChain[0].Name != ChainAerolvmInput || fake.addedChain[1].Name != "INPUT" {
		t.Fatalf("chains not created once each: %v", fake.addedChain)
	}
	if fake.addedChain[1].Hooknum == nil || *fake.addedChain[1].Hooknum != *nftables.ChainHookInput {
		t.Fatal("INPUT must be created as a base chain on the input hook")
	}
}

func TestNetlinkEnsureInputChainErrors(t *testing.T) {
	boom := errors.New("boom")
	cases := map[string]*fakeNFT{
		"get":   {getErr: boom},
		"flush": {flushErr: boom},
	}
	for name, fake := range cases {
		t.Run(name, func(t *testing.T) {
			b := &netlinkBackend{newConn: func() (nftAPI, error) { return fake, nil }}
			if err := b.EnsureInputChain(ChainAerolvmInput); err == nil {
				t.Fatal("want error")
			}
		})
	}
	b := &netlinkBackend{newConn: func() (nftAPI, error) { return nil, boom }}
	if err := b.EnsureInputChain(ChainAerolvmInput); err == nil {
		t.Fatal("want conn error")
	}
}

// TestNetlinkInsertPastEndAppends pins the P0-5 ordering fix: inserting at
// position 2 into a chain holding only the established-return rule must
// append below it, not insert above it.
func TestNetlinkInsertPastEndAppends(t *testing.T) {
	fake := &fakeNFT{rules: []*nftables.Rule{{Handle: 1, Exprs: inputEstablishedReturnExprs()}}}
	b := &netlinkBackend{newConn: func() (nftAPI, error) { return fake, nil }}
	if err := b.Insert("filter", ChainAerolvmInput, 2, inputBlockSpec("10.0.0.5")...); err != nil {
		t.Fatal(err)
	}
	if len(fake.appended) != 1 || len(fake.inserted) != 0 {
		t.Fatalf("appended=%d inserted=%d, want 1/0", len(fake.appended), len(fake.inserted))
	}
	if !isEstablishedReturn(fake.rules[0]) {
		t.Fatal("established-return must stay the first rule")
	}
	fake.flushErr = errors.New("boom")
	if err := b.Insert("filter", ChainAerolvmInput, 5, inputBlockSpec("10.0.0.6")...); err == nil {
		t.Fatal("want append flush error")
	}
}

func TestTranslateReturnVerdict(t *testing.T) {
	exprs, err := exprsFromRulespec(inputPolicyReturnSpec("10.0.0.1", "10.88.0.0/16")...)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := exprs[len(exprs)-1].(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictReturn {
		t.Fatalf("last expr = %#v, want return verdict", exprs[len(exprs)-1])
	}
}
