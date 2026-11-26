package kubepod

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeServiceAccount points the in-cluster settings at srv: its address
// in the env, its certificate as the CA, and a token file.
func fakeServiceAccount(t *testing.T, srv *httptest.Server, token string) string {
	t.Helper()
	dir := t.TempDir()
	old := serviceAccountDir
	serviceAccountDir = dir
	t.Cleanup(func() { serviceAccountDir = old })
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), ca, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	t.Setenv("KUBERNETES_SERVICE_HOST", u.Hostname())
	t.Setenv("KUBERNETES_SERVICE_PORT", u.Port())
	return dir
}

func TestInClusterClient(t *testing.T) {
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"metadata":{"name":"p1","uid":"u1"}}`))
	}))
	defer srv.Close()
	dir := fakeServiceAccount(t, srv, "token-1")

	c, err := InClusterClient()
	if err != nil {
		t.Fatalf("InClusterClient: %v", err)
	}
	p, err := c.GetPod(context.Background(), "ns", "p1")
	if err != nil || p.Metadata.UID != "u1" {
		t.Fatalf("GetPod over TLS = %+v, %v", p, err)
	}
	// The kubelet rotates the token: the next call reads the new one.
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("token-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPod(context.Background(), "ns", "p1"); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != "Bearer token-1" || seen[1] != "Bearer token-2" {
		t.Fatalf("tokens sent = %q", seen)
	}
	// A token that cannot be read fails the call, not the client.
	if err := os.Remove(filepath.Join(dir, "token")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPod(context.Background(), "ns", "p1"); err == nil || !strings.Contains(err.Error(), "service account token") {
		t.Fatalf("GetPod without a token = %v", err)
	}
}

func TestInClusterClientRefuses(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()

	t.Run("not in a pod", func(t *testing.T) {
		t.Setenv("KUBERNETES_SERVICE_HOST", "")
		if _, err := InClusterClient(); err == nil || !strings.Contains(err.Error(), "not running in a Kubernetes pod") {
			t.Fatalf("InClusterClient = %v", err)
		}
	})
	t.Run("no CA", func(t *testing.T) {
		dir := fakeServiceAccount(t, srv, "tok")
		_ = os.Remove(filepath.Join(dir, "ca.crt"))
		if _, err := InClusterClient(); err == nil || !strings.Contains(err.Error(), "CA") {
			t.Fatalf("InClusterClient = %v", err)
		}
	})
	t.Run("CA with no certificate", func(t *testing.T) {
		dir := fakeServiceAccount(t, srv, "tok")
		if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("not pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := InClusterClient(); err == nil || !strings.Contains(err.Error(), "no certificate") {
			t.Fatalf("InClusterClient = %v", err)
		}
	})
}

func TestClientErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/ns/pods/plain":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("upstream down\n"))
		case "/api/v1/namespaces/ns/pods/badjson":
			_, _ = w.Write([]byte("{"))
		case "/api/v1/namespaces/ns/pods/status":
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"kind":"Status","reason":"AlreadyExists","message":"pods \"status\" already exists"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	c := NewClient(srv.URL+"/", nil, nil)

	_, err := c.GetPod(context.Background(), "ns", "plain")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != 502 || ae.Message != "upstream down" || ae.Reason != "" {
		t.Fatalf("plain error = %#v", err)
	}
	if !strings.Contains(err.Error(), "GET /api/v1/namespaces/ns/pods/plain: 502") {
		t.Errorf("message = %q", err.Error())
	}
	if _, err := c.GetPod(context.Background(), "ns", "badjson"); err == nil || !strings.Contains(err.Error(), "decode reply") {
		t.Errorf("bad JSON = %v", err)
	}
	_, err = c.GetPod(context.Background(), "ns", "status")
	if !isAlreadyExists(err) || isConflict(err) || isNotFound(err) {
		t.Errorf("status error = %v: want AlreadyExists only", err)
	}
	_, err = c.GetPod(context.Background(), "ns", "missing")
	if !isNotFound(err) {
		t.Errorf("missing = %v, want not found", err)
	}
	if isNotFound(errors.New("plain")) {
		t.Error("a non-API error is not a 404")
	}

	srv.Close()
	if _, err := c.GetPod(context.Background(), "ns", "plain"); err == nil || isNotFound(err) {
		t.Errorf("closed server = %v, want a transport error", err)
	}
	if err := c.DeletePod(context.Background(), "ns", "p", "", 0); err == nil {
		t.Error("delete to a closed server: want an error")
	}
	if _, err := c.CreatePod(context.Background(), "ns", &Pod{}); err == nil {
		t.Error("create to a closed server: want an error")
	}
	bad := NewClient("http://bad host", nil, nil)
	if _, err := bad.GetPod(context.Background(), "ns", "p"); err == nil {
		t.Error("a malformed host: want an error")
	}
	if err := c.do(context.Background(), http.MethodPost, "/x", func() {}, nil); err == nil {
		t.Error("a body that cannot be encoded: want an error")
	}
}

func TestDeletePodOptions(t *testing.T) {
	f := newFakeAPI(t)
	f.setGoneAfter(-1)
	c := f.client()
	f.put(podOf("w", "sb-1"))
	// A grace under a second is sent as one second, never zero.
	if err := c.DeletePod(context.Background(), testNS, "sb-1", "", 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePod(context.Background(), testNS, "sb-1", "uid-other", 5*time.Second); !isConflict(err) {
		t.Fatalf("delete with a stale UID = %v, want a conflict", err)
	}
	dc := f.deleteCalls()
	if len(dc) != 2 || dc[0].grace != 1 || dc[0].uid != "" || dc[1].grace != 5 || dc[1].uid != "uid-other" {
		t.Fatalf("deletes = %+v", dc)
	}
}
