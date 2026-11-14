package kubeapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testCA makes a CA and client certificates it signs.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "front-proxy-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) client(t *testing.T, cn string, usage x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func (ca *testCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

func forwarded(certs ...*x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/apis", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: certs}
	r.Header.Set("X-Remote-User", "alice")
	r.Header.Add("X-Remote-Group", "dev")
	r.Header.Add("X-Remote-Group", "system:authenticated")
	r.Header.Set("X-Remote-Extra-Scopes", "a")
	return r
}

func TestFrontProxy(t *testing.T) {
	ca, other := newTestCA(t), newTestCA(t)
	fp := &FrontProxy{CAs: ca.pool(), AllowedNames: []string{"front-proxy-client"}}
	u, err := fp.Authenticate(forwarded(ca.client(t, "front-proxy-client", x509.ExtKeyUsageClientAuth)))
	if err != nil || u.Name != "alice" || strings.Join(u.Groups, ",") != "dev,system:authenticated" || u.Extra["scopes"][0] != "a" {
		t.Fatalf("Authenticate = %+v %v", u, err)
	}
	for name, r := range map[string]*http.Request{
		"no TLS":            httptest.NewRequest(http.MethodGet, "/", nil),
		"another CA":        forwarded(other.client(t, "front-proxy-client", x509.ExtKeyUsageClientAuth)),
		"a name not listed": forwarded(ca.client(t, "someone", x509.ExtKeyUsageClientAuth)),
		"a server cert":     forwarded(ca.client(t, "front-proxy-client", x509.ExtKeyUsageServerAuth)),
	} {
		if _, err := fp.Authenticate(r); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: %v", name, err)
		}
	}
	noUser := forwarded(ca.client(t, "front-proxy-client", x509.ExtKeyUsageClientAuth))
	noUser.Header.Del("X-Remote-User")
	if _, err := fp.Authenticate(noUser); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("no user: %v", err)
	}
	// Any certificate the CA signed, when no names are listed, and the
	// cluster's own header names.
	open := &FrontProxy{CAs: ca.pool(), UserHeaders: []string{"X-Who"}, GroupHeaders: []string{"X-Teams"}, ExtraPrefix: []string{"X-More-"}}
	r := forwarded(ca.client(t, "anyone", x509.ExtKeyUsageClientAuth))
	r.Header.Set("X-Who", "bob")
	r.Header.Set("X-Teams", "ops")
	r.Header.Set("X-More-Tier", "gold")
	if u, err := open.Authenticate(r); err != nil || u.Name != "bob" || u.Groups[0] != "ops" || u.Extra["tier"][0] != "gold" {
		t.Fatalf("custom headers = %+v %v", u, err)
	}
	cfg := ServingTLS(tls.Certificate{}, fp)
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven || cfg.ClientCAs != fp.CAs || cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("serving TLS = %+v", cfg)
	}
}

func TestCachedAuthorizer(t *testing.T) {
	calls := 0
	var fail error
	clock := time.Unix(1000, 0)
	c := &CachedAuthorizer{TTL: 10 * time.Second, now: func() time.Time { return clock }, Next: AuthorizerFunc(func(context.Context, User, Attributes) (bool, string, error) {
		calls++
		return calls%2 == 1, "r", fail
	})}
	ctx := context.Background()
	u := User{Name: "alice", Groups: []string{"b", "a"}}
	at := Attributes{Verb: "list", Group: Group, Resource: "sandboxes", Namespace: "a"}
	if ok, _, _ := c.Authorize(ctx, u, at); !ok || calls != 1 {
		t.Fatalf("first = %v, %d calls", ok, calls)
	}
	// The same question, groups in another order: from the cache.
	if ok, _, _ := c.Authorize(ctx, User{Name: "alice", Groups: []string{"a", "b"}}, at); !ok || calls != 1 {
		t.Fatalf("cached = %v, %d calls", ok, calls)
	}
	clock = clock.Add(11 * time.Second)
	if ok, _, _ := c.Authorize(ctx, u, at); ok || calls != 2 {
		t.Fatalf("after the TTL = %v, %d calls", ok, calls)
	}
	fail = errors.New("down")
	at.Verb = "get"
	if _, _, err := c.Authorize(ctx, u, at); err == nil {
		t.Fatal("an error was swallowed")
	}
	if _, ok := c.answers[strings.Join([]string{"alice", "a,b", "map[]", "get", Group, "sandboxes", "a", ""}, "\x00")]; ok {
		t.Fatal("an error was cached")
	}
	// Past the bound it starts over.
	fail = nil
	for i := 0; i < maxCachedAnswers+1; i++ {
		at.Name = string(rune('a'+i%26)) + strings.Repeat("x", i/26)
		_, _, _ = c.Authorize(ctx, u, at)
	}
	if len(c.answers) > maxCachedAnswers {
		t.Fatalf("%d cached answers", len(c.answers))
	}
}

func TestKubeClient(t *testing.T) {
	ca := newTestCA(t)
	var sar map[string]any
	status := http.StatusOK
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no token", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-system/configmaps/extension-apiserver-authentication":
			names, _ := json.Marshal([]string{"front-proxy-client"})
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{
				"requestheader-client-ca-file":       string(ca.pem),
				"requestheader-allowed-names":        string(names),
				"requestheader-username-headers":     `["X-Remote-User"]`,
				"requestheader-group-headers":        `["X-Remote-Group"]`,
				"requestheader-extra-headers-prefix": `["X-Remote-Extra-"]`,
			}})
		case "/apis/authorization.k8s.io/v1/subjectaccessreviews":
			_ = json.NewDecoder(r.Body).Decode(&sar)
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"allowed": true, "reason": "rbac"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	k := &KubeClient{Host: ts.URL, Token: func() (string, error) { return "tok", nil }, Client: ts.Client()}
	ctx := context.Background()
	fp, err := k.FrontProxyConfig(ctx)
	if err != nil || fp.CAs == nil || fp.AllowedNames[0] != "front-proxy-client" || fp.UserHeaders[0] != "X-Remote-User" {
		t.Fatalf("FrontProxyConfig = %+v %v", fp, err)
	}
	ok, reason, err := k.SubjectAccessReview(ctx, User{Name: "alice", Groups: []string{"dev"}}, Attributes{Verb: "get", Group: Group, Resource: "sandboxes", Namespace: "a", Name: "web"})
	if err != nil || !ok || reason != "rbac" {
		t.Fatalf("SAR = %v %q %v", ok, reason, err)
	}
	spec := sar["spec"].(map[string]any)
	ra := spec["resourceAttributes"].(map[string]any)
	if sar["kind"] != "SubjectAccessReview" || spec["user"] != "alice" || ra["verb"] != "get" || ra["namespace"] != "a" || ra["name"] != "web" {
		t.Fatalf("SAR body = %v", sar)
	}
	status = http.StatusInternalServerError
	if _, _, err := k.SubjectAccessReview(ctx, User{Name: "alice"}, Attributes{}); err == nil {
		t.Fatal("a failed review")
	}
	k.Token = func() (string, error) { return "", errors.New("no token file") }
	if _, err := k.FrontProxyConfig(ctx); err == nil {
		t.Fatal("no token")
	}
	k.Token = func() (string, error) { return "tok", nil }
	k.Host = ts.URL + "/nowhere"
	if _, err := k.FrontProxyConfig(ctx); err == nil {
		t.Fatal("a missing config map")
	}
}

func TestInClusterClientOutsideAPod(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := InClusterClient(); err == nil {
		t.Fatal("an in-cluster client outside a pod")
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	if _, err := InClusterClient(); err == nil {
		t.Fatal("an in-cluster client without the service account files")
	}
}
