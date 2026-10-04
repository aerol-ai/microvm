package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePAT writes a PAT file under a temp dir and returns its path.
func writePAT(t *testing.T, token string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "cluster-pat")
	if err := os.WriteFile(p, []byte(token), 0o600); err != nil {
		t.Fatalf("write pat: %v", err)
	}
	return p
}

func TestResolveAOCRPullAuth_NilWhenUnconfigured(t *testing.T) {
	c := &Client{}
	if got := c.resolveAOCRPullAuth("aocr.aerol.ai/cluster/c1/templates/py311:latest"); got != nil {
		t.Fatalf("expected nil auth when unconfigured, got %+v", got)
	}
}

func TestResolveAOCRPullAuth_TemplatesAndSnapshots(t *testing.T) {
	patPath := writePAT(t, "tok-123\n") // trailing newline must be trimmed
	c := &Client{}
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai", ""}, "prod-aerolvm-us-east-1", patPath)

	for _, ref := range []string{
		"aocr.aerol.ai/cluster/prod-aerolvm-us-east-1/templates/py311:latest",
		"aocr.aerol.ai/cluster/prod-aerolvm-us-east-1/snapshots/py-ready:latest",
	} {
		got := c.resolveAOCRPullAuth(ref)
		if got == nil {
			t.Fatalf("expected auth for %q, got nil", ref)
		}
		if got.Server != "aocr.aerol.ai" {
			t.Errorf("ref %q: Server = %q, want aocr.aerol.ai", ref, got.Server)
		}
		if got.Username != "prod-aerolvm-us-east-1" {
			t.Errorf("ref %q: Username = %q, want cluster id", ref, got.Username)
		}
		if got.Password != "tok-123" {
			t.Errorf("ref %q: Password = %q, want trimmed token", ref, got.Password)
		}
	}
}

func TestResolveAOCRPullAuth_ScopingRules(t *testing.T) {
	patPath := writePAT(t, "tok")
	c := &Client{}
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", patPath)

	cases := []struct {
		name string
		ref  string
		want bool
	}{
		{"other host cluster path", "ghcr.io/cluster/c1/templates/py311:latest", false},
		{"configured host non-cluster repo", "aocr.aerol.ai/acme/my-image:latest", false},
		{"configured host mirror namespace", "aocr.aerol.ai/mirror/aocr/ghcr/foo:latest", false},
		{"docker hub short ref (no host)", "ubuntu:22.04", false},
		{"cluster prefix collision", "aocr.aerol.ai/clusterfoo/bar:latest", false},
		{"configured host cluster path", "aocr.aerol.ai/cluster/c1/templates/py311:latest", true},
		{"transport prefix stripped", "docker://aocr.aerol.ai/cluster/c1/snapshots/s:latest", true},
		{"default https port stripped", "aocr.aerol.ai:443/cluster/c1/templates/py311:latest", true},
		{"non-default port is significant", "aocr.aerol.ai:5000/cluster/c1/templates/py311:latest", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := c.resolveAOCRPullAuth(tc.ref) != nil
			if got != tc.want {
				t.Fatalf("resolveAOCRPullAuth(%q) matched=%v, want %v", tc.ref, got, tc.want)
			}
		})
	}
}

func TestResolveAOCRPullAuth_PATReadFreshEachCall(t *testing.T) {
	patPath := writePAT(t, "first")
	c := &Client{}
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", patPath)

	ref := "aocr.aerol.ai/cluster/c1/templates/py311:latest"
	if got := c.resolveAOCRPullAuth(ref); got == nil || got.Password != "first" {
		t.Fatalf("first resolve: got %+v, want password=first", got)
	}
	// Rotate the PAT on disk; the next resolve must reflect it without any
	// restart or reconfigure — the rotation contract.
	if err := os.WriteFile(patPath, []byte("second"), 0o600); err != nil {
		t.Fatalf("rotate pat: %v", err)
	}
	if got := c.resolveAOCRPullAuth(ref); got == nil || got.Password != "second" {
		t.Fatalf("after rotation: got %+v, want password=second", got)
	}
}

func TestResolveAOCRPullAuth_NilWhenPATMissing(t *testing.T) {
	c := &Client{}
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", filepath.Join(t.TempDir(), "does-not-exist"))
	if got := c.resolveAOCRPullAuth("aocr.aerol.ai/cluster/c1/templates/py311:latest"); got != nil {
		t.Fatalf("expected nil auth when PAT file missing, got %+v", got)
	}
}

// newAOCRCaptureClient builds a Client whose pull transport records the
// X-Registry-Auth header and the fromImage query of the /images/create call,
// with pulls initialized so pullImageDedup is safe to drive directly.
func newAOCRCaptureClient(gotAuthB64, gotFrom *string) *Client {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		*gotAuthB64 = r.Header.Get("X-Registry-Auth")
		*gotFrom = r.URL.Query().Get("fromImage")
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"status":"done"}`)),
			Header:     make(http.Header),
		}, nil
	})
	return &Client{
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		streamClient: &http.Client{Transport: transport},
		httpClient:   &http.Client{Transport: transport},
		pulls:        make(map[string]*imagePull),
	}
}

// TestPullImageDedup_SetsClusterPATForClusterRef is the end-to-end assertion
// that the back-fill actually reaches the daemon request: a nil-auth pull of an
// AOCR cluster ref (the template-puller's exact call shape) must carry the
// cluster PAT in X-Registry-Auth, and the ref must not be mirror-rewritten.
func TestPullImageDedup_SetsClusterPATForClusterRef(t *testing.T) {
	patPath := writePAT(t, "tok-xyz")
	var gotAuthB64, gotFrom string
	c := newAOCRCaptureClient(&gotAuthB64, &gotFrom)
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "prod-aerolvm-us-east-1", patPath)

	ref := "aocr.aerol.ai/cluster/prod-aerolvm-us-east-1/templates/py311:latest"
	if err := c.PullImage(context.Background(), ref, nil); err != nil {
		t.Fatalf("PullImage: %v", err)
	}
	if gotFrom != ref {
		t.Fatalf("fromImage = %q, want %q (no mirror rewrite expected)", gotFrom, ref)
	}
	if gotAuthB64 == "" {
		t.Fatal("X-Registry-Auth missing; cluster PAT was not applied to the pull")
	}
	decoded, err := base64.StdEncoding.DecodeString(gotAuthB64)
	if err != nil {
		t.Fatalf("decode X-Registry-Auth: %v", err)
	}
	var a map[string]string
	if err := json.Unmarshal(decoded, &a); err != nil {
		t.Fatalf("unmarshal auth: %v", err)
	}
	if a["username"] != "prod-aerolvm-us-east-1" || a["password"] != "tok-xyz" || a["serveraddress"] != "aocr.aerol.ai" {
		t.Fatalf("auth payload mismatch: %+v", a)
	}
}

// TestPullImageDedup_NoAuthForNonClusterRef confirms the back-fill stays scoped:
// a non-cluster repo on the same AOCR host must not borrow the cluster PAT.
func TestPullImageDedup_NoAuthForNonClusterRef(t *testing.T) {
	patPath := writePAT(t, "tok-xyz")
	var gotAuthB64, gotFrom string
	c := newAOCRCaptureClient(&gotAuthB64, &gotFrom)
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", patPath)

	if err := c.PullImage(context.Background(), "aocr.aerol.ai/acme/my-image:latest", nil); err != nil {
		t.Fatalf("PullImage: %v", err)
	}
	if gotAuthB64 != "" {
		t.Fatalf("unexpected X-Registry-Auth for non-cluster ref: %q", gotAuthB64)
	}
}

func TestConfigureAOCRPullAuth_NoOpWhenIncomplete(t *testing.T) {
	patPath := writePAT(t, "tok")
	cases := []struct {
		name      string
		hosts     []string
		clusterID string
		patPath   string
	}{
		{"empty cluster id", []string{"aocr.aerol.ai"}, "", patPath},
		{"empty pat path", []string{"aocr.aerol.ai"}, "c1", ""},
		{"no non-empty hosts", []string{"", "  "}, "c1", patPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{}
			c.ConfigureAOCRPullAuth(tc.hosts, tc.clusterID, tc.patPath)
			if c.aocrPullAuth != nil {
				t.Fatalf("expected aocrPullAuth to stay nil for incomplete config")
			}
			if a := NewAOCRPullAuth(tc.hosts, tc.clusterID, tc.patPath); a != nil {
				t.Fatalf("NewAOCRPullAuth = %+v, want nil for incomplete config", a)
			}
		})
	}
}

// TestConfigureAOCRPullAuth_IncompleteKeepsPrior pins the documented no-op: an
// incomplete reconfigure must not silently switch a configured node back to
// anonymous pulls.
func TestConfigureAOCRPullAuth_IncompleteKeepsPrior(t *testing.T) {
	c := &Client{}
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", writePAT(t, "tok"))
	prior := c.aocrPullAuth
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "", "")
	if c.aocrPullAuth != prior || prior == nil {
		t.Fatalf("incomplete reconfigure replaced the credential: prior=%p now=%p", prior, c.aocrPullAuth)
	}
}

// TestAOCRPullAuthResolve_ErrorContract covers the exported resolver the
// containerd driver shares: out-of-scope refs never touch the PAT file, an
// in-scope ref with an unusable PAT returns an error naming the path (never
// the contents), and a nil receiver is a valid "feature off".
func TestAOCRPullAuthResolve_ErrorContract(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing-pat")
	blank := filepath.Join(dir, "blank-pat")
	if err := os.WriteFile(blank, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clusterRef := "aocr.aerol.ai/cluster/c1/snapshots/s:latest--ttl-1h"

	cases := []struct {
		name    string
		auth    *AOCRPullAuth
		ref     string
		wantErr error
	}{
		{"nil receiver", nil, clusterRef, nil},
		{"blank ref", NewAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", missing), "  ", nil},
		{"out of scope host skips PAT read", NewAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", missing), "ghcr.io/cluster/c1/x:1", nil},
		{"out of scope repo skips PAT read", NewAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", missing), "aocr.aerol.ai/acme/x:1", nil},
		{"in scope, PAT missing", NewAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", missing), clusterRef, os.ErrNotExist},
		{"in scope, PAT blank", NewAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", blank), clusterRef, os.ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.auth.Resolve(tc.ref)
			if got != nil {
				t.Fatalf("Resolve returned auth %+v, want nil", got)
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Resolve err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Resolve err = %v, want errors.Is %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.auth.patPath) {
				t.Fatalf("Resolve err %q does not name the PAT path %q", err, tc.auth.patPath)
			}
		})
	}
}

func TestAOCRPullAuthResolve_InScope(t *testing.T) {
	a := NewAOCRPullAuth([]string{" AOCR.aerol.ai/ "}, " c1 ", writePAT(t, "tok-1\n"))
	got, err := a.Resolve("aocr.aerol.ai/cluster/c1/snapshots/s:latest--ttl-1h")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got == nil || got.Server != "aocr.aerol.ai" || got.Username != "c1" || got.Password != "tok-1" {
		t.Fatalf("Resolve = %+v, want server=aocr.aerol.ai user=c1 password=tok-1", got)
	}
}
