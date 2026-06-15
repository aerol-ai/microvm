package sshgateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"golang.org/x/crypto/ssh"
)

// ownerAPIStub stands in for this node's own v1 API. In production
// clusterForwardWrap proxies GET /v1/sandboxes/{id} to the owner; here the stub
// returns the owner's authoritative sandbox view directly so we can exercise the
// edge-side remote auth + routing without a real cluster.
var errNotFoundStub = errors.New("not found")

func ownerAPIStub(t *testing.T, sandbox *models.Sandbox, wantToken string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantToken != "" && r.Header.Get("Authorization") != "Bearer "+wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if sandbox == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sandbox)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newRemoteGateway(t *testing.T, baseURL, pat string, local *fakeLookup) *Gateway {
	t.Helper()
	return &Gateway{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		svc:           local,
		remoteBaseURL: baseURL,
		remotePAT:     pat,
	}
}

func TestPublicKeyCallback_RemoteOwned(t *testing.T) {
	signer, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "id"))
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	wrongSigner, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	authorized := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	owner := &models.Sandbox{
		ID:           "sb-remote",
		Status:       models.SandboxStatusStarted,
		ContainerIP:  "10.0.0.9",
		SSHPublicKey: authorized,
	}

	t.Run("authorizes against owner key when not held locally", func(t *testing.T) {
		srv := ownerAPIStub(t, owner, "pat-1")
		// Local store does not have the sandbox (remote-owned).
		g := newRemoteGateway(t, srv.URL, "pat-1", &fakeLookup{err: errNotFoundStub})
		perms, err := g.publicKeyCallback(context.Background())(fakeConnMetadata{user: "sb-remote"}, signer.PublicKey())
		if err != nil {
			t.Fatalf("expected remote auth success, got %v", err)
		}
		if perms.Extensions["remote"] != "1" {
			t.Fatalf("expected remote=1 marker, got %+v", perms.Extensions)
		}
		if perms.Extensions["sandbox_id"] != "sb-remote" || perms.Extensions["mode"] != "session" {
			t.Fatalf("unexpected perms: %+v", perms.Extensions)
		}
	})

	t.Run("forged key denied", func(t *testing.T) {
		srv := ownerAPIStub(t, owner, "pat-1")
		g := newRemoteGateway(t, srv.URL, "pat-1", &fakeLookup{err: errNotFoundStub})
		if _, err := g.publicKeyCallback(context.Background())(fakeConnMetadata{user: "sb-remote"}, wrongSigner.PublicKey()); err == nil {
			t.Fatal("expected permission denied for forged key")
		}
	})

	t.Run("unknown sandbox denied", func(t *testing.T) {
		srv := ownerAPIStub(t, nil, "pat-1") // 404
		g := newRemoteGateway(t, srv.URL, "pat-1", &fakeLookup{err: errNotFoundStub})
		if _, err := g.publicKeyCallback(context.Background())(fakeConnMetadata{user: "ghost"}, signer.PublicKey()); err == nil {
			t.Fatal("expected permission denied for unknown sandbox")
		}
	})

	t.Run("stopped remote sandbox denied", func(t *testing.T) {
		stopped := *owner
		stopped.Status = models.SandboxStatusStopped
		srv := ownerAPIStub(t, &stopped, "pat-1")
		g := newRemoteGateway(t, srv.URL, "pat-1", &fakeLookup{err: errNotFoundStub})
		if _, err := g.publicKeyCallback(context.Background())(fakeConnMetadata{user: "sb-remote"}, signer.PublicKey()); err == nil {
			t.Fatal("expected permission denied for stopped sandbox")
		}
	})
}

// TestPublicKeyCallback_SingleNodeNeverRemote asserts the byte-for-byte
// single-node guarantee: with no RemoteAPIBaseURL configured, a local lookup
// miss is a flat denial and the remote path is never attempted.
func TestPublicKeyCallback_SingleNodeNeverRemote(t *testing.T) {
	signer, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "id"))
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	// remoteBaseURL empty → single-node.
	g := newRemoteGateway(t, "", "", &fakeLookup{err: errNotFoundStub})
	if _, err := g.publicKeyCallback(context.Background())(fakeConnMetadata{user: "sb-x"}, signer.PublicKey()); err == nil {
		t.Fatal("expected permission denied; single-node must not attempt remote auth")
	}
}

// TestPublicKeyCallback_LocalWins asserts a locally-owned sandbox takes the
// local path (no remote marker) even when remote routing is configured.
func TestPublicKeyCallback_LocalWins(t *testing.T) {
	signer, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "id"))
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	authorized := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	local := &fakeLookup{sandbox: &models.Sandbox{
		ID:           "sb-local",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-1",
		SSHPublicKey: authorized,
	}}
	g := newRemoteGateway(t, "http://127.0.0.1:1/should-not-be-called", "pat", local)
	perms, err := g.publicKeyCallback(context.Background())(fakeConnMetadata{user: "sb-local"}, signer.PublicKey())
	if err != nil {
		t.Fatalf("local auth: %v", err)
	}
	if perms.Extensions["remote"] == "1" {
		t.Fatal("local sandbox must not be marked remote")
	}
}

func TestHTTPToWS(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:8080/v1/x": "ws://127.0.0.1:8080/v1/x",
		"https://node.internal/v1/y": "wss://node.internal/v1/y",
		"ftp://weird":                "ftp://weird",
	}
	for in, want := range cases {
		if got := httpToWS(in); got != want {
			t.Errorf("httpToWS(%q) = %q, want %q", in, got, want)
		}
	}
}
