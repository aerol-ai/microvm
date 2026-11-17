package api

// Review repro (issue #1349): on Kubernetes "a loopback peer" is not "this
// pod". An Istio sidecar delivers every inbound connection to the app from
// 127.0.0.6 (its InboundPassthrough bind address), so with a sidecar on a
// server or gateway pod every in-mesh caller of :21212 counts as the pod
// itself, and SB_PAT_SCOPE=host takes the admin token from it. FAILS on
// 0e6d04535.

import (
	"net/http/httptest"
	"testing"
)

func TestReviewSidecarSourceCountsAsHost(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/whoami", nil)
	r.RemoteAddr = "127.0.0.6:41234" // Envoy's inbound passthrough source
	if got := requestOrigin(r, false); got == originHost {
		t.Errorf("a request relayed by a mesh sidecar is origin %q: the admin token is taken from any caller in the mesh", got)
	}
}
