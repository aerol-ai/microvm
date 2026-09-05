package cluster

import (
	"errors"
	"net/http"
	"testing"
)

func TestPeerDialFailClosedRequiresInternalURL(t *testing.T) {
	internal := &http.Client{}
	_, _, err := PeerDial(Member{NodeID: "n1", APIURL: "http://public"}, internal)
	if !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("PeerDial without InternalURL = %v, want ErrPeerInternalURLRequired", err)
	}
	_, _, err = PeerDialPath(Member{NodeID: "n1", APIURL: "http://public"}, internal, "/v1/x")
	if !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("PeerDialPath without InternalURL = %v, want ErrPeerInternalURLRequired", err)
	}
}

func TestPeerDialUsesInternalWhenPresent(t *testing.T) {
	internal := &http.Client{}
	client, base, err := PeerDial(Member{
		NodeID:      "n1",
		APIURL:      "http://public",
		InternalURL: "https://internal:7002",
	}, internal)
	if err != nil {
		t.Fatalf("PeerDial: %v", err)
	}
	if client != internal || base != "https://internal:7002" {
		t.Fatalf("got client=%v base=%q, want internal client and InternalURL", client == internal, base)
	}
}

func TestPeerDialRejectsMissingTLSClient(t *testing.T) {
	_, _, err := PeerDial(Member{NodeID: "n1", InternalURL: "https://internal:7002"}, nil)
	if !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("PeerDial without mTLS client = %v, want ErrPeerInternalURLRequired", err)
	}
}

func TestPeerDialRejectsPlaintextOrCredentialedInternalURL(t *testing.T) {
	internal := &http.Client{}
	for _, raw := range []string{"http://internal:7002", "https://user:pass@internal:7002", "//internal:7002", "https:///missing-host"} {
		_, _, err := PeerDial(Member{NodeID: "n1", InternalURL: raw}, internal)
		if !errors.Is(err, ErrPeerInternalURLInvalid) {
			t.Fatalf("PeerDial(%q) = %v, want ErrPeerInternalURLInvalid", raw, err)
		}
	}
}

func TestPeerDialPathAppendsSuffix(t *testing.T) {
	internal := &http.Client{}
	client, endpoint, err := PeerDialPath(Member{
		NodeID:      "n1",
		InternalURL: "https://internal:7002/",
	}, internal, "/v1/cluster/internal/secrets")
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
