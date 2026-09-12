package cluster

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestClusterWasmMigrateHTTPClientBranchesStep1(t *testing.T) {
	internalClient := &http.Client{Timeout: 100 * time.Millisecond}
	c := &Cluster{internalClient: internalClient}

	client, endpoint, err := c.PeerDialMember(Member{NodeID: "peer-1", InternalURL: "https://internal"})
	if err != nil || client != internalClient || endpoint != "https://internal" {
		t.Fatalf("internal path client=%p endpoint=%q err=%v", client, endpoint, err)
	}

	client, endpoint, err = c.PeerDialMember(Member{NodeID: "peer-1"})
	if !errors.Is(err, ErrPeerInternalURLRequired) || client != nil || endpoint != "" {
		t.Fatalf("missing internal URL client=%p endpoint=%q err=%v", client, endpoint, err)
	}

	if _, _, err := c.PeerDialMember(Member{}); err == nil {
		t.Fatal("expected error when both internal and public endpoints are empty")
	}
}

func TestWasmMigrateHTTPErrorBranches(t *testing.T) {
	ctx := context.Background()
	err := wasmMigrateHTTP(ctx, NewNoop("n", "http://x", ""), "peer-1", "https://internal", http.MethodGet, "/p", nil, nil, nil)
	if !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("provider-less client error=%v", err)
	}
}
