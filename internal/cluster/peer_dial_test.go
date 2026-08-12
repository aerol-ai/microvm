package cluster

import (
	"errors"
	"net/http"
	"testing"
)

func TestPeerDialFailClosedRequiresInternalURL(t *testing.T) {
	internal := &http.Client{}
	public := &http.Client{}
	_, _, err := PeerDial(Member{NodeID: "n1", APIURL: "http://public"}, public, internal)
	if !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("PeerDial without InternalURL = %v, want ErrPeerInternalURLRequired", err)
	}
	_, _, err = PeerDialPath(Member{NodeID: "n1", APIURL: "http://public"}, public, internal, "/v1/x")
	if !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("PeerDialPath without InternalURL = %v, want ErrPeerInternalURLRequired", err)
	}
}

func TestPeerDialUsesInternalWhenPresent(t *testing.T) {
	internal := &http.Client{}
	public := &http.Client{}
	client, base, err := PeerDial(Member{
		NodeID:      "n1",
		APIURL:      "http://public",
		InternalURL: "https://internal:7002",
	}, public, internal)
	if err != nil {
		t.Fatalf("PeerDial: %v", err)
	}
	if client != internal || base != "https://internal:7002" {
		t.Fatalf("got client=%v base=%q, want internal client and InternalURL", client == internal, base)
	}
}

func TestPeerDialFallsBackToPublicWithoutTLS(t *testing.T) {
	public := &http.Client{}
	client, base, err := PeerDial(Member{
		NodeID: "n1",
		APIURL: "http://public",
	}, public, nil)
	if err != nil {
		t.Fatalf("PeerDial: %v", err)
	}
	if client != public || base != "http://public" {
		t.Fatalf("got client=%v base=%q, want public", client == public, base)
	}
}

func TestPeerDialPathAppendsSuffix(t *testing.T) {
	internal := &http.Client{}
	client, endpoint, err := PeerDialPath(Member{
		NodeID:      "n1",
		InternalURL: "https://internal:7002/",
	}, nil, internal, "/v1/cluster/internal/secrets")
	if err != nil {
		t.Fatalf("PeerDialPath: %v", err)
	}
	if client != internal {
		t.Fatal("expected internal client")
	}
	if endpoint != "https://internal:7002/v1/cluster/internal/secrets" {
		t.Fatalf("endpoint=%q", endpoint)
	}
}
