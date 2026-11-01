package clusterlist

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// fanOutCluster is any real cluster client: not the single-node Noop type.
type fanOutCluster struct{ *cluster.Noop }

// Only a list that fans out takes a slot: a single node's list is its own
// store, and a peer's forwarded hop belongs to a list that already holds a
// slot on the node that fanned out (refusing it would only make that list
// partial).
func TestAdmitGatesOnlyListsThatFanOut(t *testing.T) {
	gate := apihttp.NewGate(1, 0, apihttp.GateMetrics{})
	hold, err := gate.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer hold()

	noop := cluster.NewNoop("self", "http://self", "")
	real := &fanOutCluster{Noop: noop}
	plain := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	hop := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	hop.Header.Set(cluster.HeaderForwarded, "1")

	cases := []struct {
		name     string
		gate     *apihttp.Gate
		c        cluster.Client
		r        *http.Request
		wantShed bool
	}{
		{name: "a fan-out list with every slot taken is shed", gate: gate, c: real, r: plain, wantShed: true},
		{name: "a single node is never gated", gate: gate, c: noop, r: plain},
		{name: "no cluster client is never gated", gate: gate, c: nil, r: plain},
		{name: "a peer's forwarded hop is never gated", gate: gate, c: real, r: hop},
		{name: "no gate admits", gate: nil, c: real, r: plain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			release, err := Admit(tc.gate, tc.c, tc.r)
			if tc.wantShed {
				if !errors.Is(err, apihttp.ErrOverloaded) {
					t.Fatalf("err = %v, want ErrOverloaded", err)
				}
				return
			}
			if err != nil || release == nil {
				t.Fatalf("err = %v release nil = %v", err, release == nil)
			}
			release()
		})
	}
}
