package nodejoin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// fakeOperator is the operator's join-token endpoint over TLS: each answer
// in turn, then the last again. It records the bearer tokens it was shown.
type fakeOperator struct {
	srv     *httptest.Server
	mu      sync.Mutex
	answers []func(w http.ResponseWriter)
	asked   []string
	nodes   []string
}

func newFakeOperator(t *testing.T, answers ...func(w http.ResponseWriter)) *fakeOperator {
	t.Helper()
	f := &fakeOperator{answers: answers}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Node string `json:"node"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.asked = append(f.asked, r.Header.Get("Authorization"))
		f.nodes = append(f.nodes, body.Node)
		a := f.answers[min(len(f.asked), len(f.answers))-1]
		f.mu.Unlock()
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		a(w)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// ca is the PEM a pod is given to trust the operator by.
func (f *fakeOperator) ca() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
}

func (f *fakeOperator) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

func grantAnswer(g operatorGrant) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) { _ = json.NewEncoder(w).Encode(g) }
}

func refuseAnswer(code int, why string, retryAfter string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": why})
	}
}

// identityToken writes the pod's projected ServiceAccount token.
func identityToken(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A pod's setup asks the operator, then joins with what it got, as a
// machine with a token does; the kept answer is gone once the join is done.
func TestJoinFromOperator(t *testing.T) {
	r := newJoinRig(t)
	r.host.notRoot = true
	tok := r.srv.token(cluster.JoinRoleWorker)
	op := newFakeOperator(t,
		refuseAnswer(http.StatusServiceUnavailable, "the servers made no join token: no leader", ""),
		grantAnswer(operatorGrant{Token: tok, CACertHash: cluster.CACertHash(r.srv.ca.Certificate()), JoinURL: r.srv.url, ExpiresAt: time.Now().Add(10 * time.Minute)}))
	o := JoinOptions{NodeID: "node-a", FilesOnly: true, WaitTimeout: 2 * time.Second, FromOperator: &OperatorJoin{
		URL: op.srv.URL + "/v1/join-token", CA: op.ca(), TokenFile: identityToken(t, "pod-token\n"), Backoff: 10 * time.Millisecond,
	}}
	res, err := r.joiner().Run(context.Background(), o)
	if err != nil {
		t.Fatalf("join --from-operator: %v\n%s", err, r.out.String())
	}
	if res.NodeID != "node-a" || res.Role != cluster.JoinRoleWorker {
		t.Fatalf("result = %+v", res)
	}
	if op.requests() != 2 || op.asked[1] != "Bearer pod-token" || op.nodes[1] != "node-a" {
		t.Fatalf("operator asked %v for %v", op.asked, op.nodes)
	}
	if env, _ := readEnvFile(r.paths.ClusterEnv); env["SB_ENABLE_CLUSTER"] != "true" || env["SB_NODE_ROLE"] != "worker" {
		t.Fatalf("cluster.env = %v", env)
	}
	if exists(grantFile(r.paths)) {
		t.Fatal("the spent join token was kept")
	}
	if !strings.Contains(r.out.String(), "asking the operator") || !strings.Contains(r.out.String(), "no leader; asking again") {
		t.Fatalf("output: %s", r.out.String())
	}
}

// A setup run again before its join finished reuses the token it was given,
// so the servers see the same token and key; one near its end is not.
func TestOperatorGrantIsKeptForARerun(t *testing.T) {
	r := newJoinRig(t)
	op := newFakeOperator(t, grantAnswer(operatorGrant{Token: "a.b", CACertHash: "sha256:x", JoinURL: "https://s0:7003", ExpiresAt: time.Now().Add(10 * time.Minute)}))
	oj := OperatorJoin{URL: op.srv.URL, CA: op.ca(), TokenFile: identityToken(t, "pod-token")}
	g, err := r.joiner().operatorGrant(context.Background(), oj, "node-a")
	if err != nil || g.Token != "a.b" {
		t.Fatalf("grant = %+v %v", g, err)
	}
	info, err := os.Stat(grantFile(r.paths))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("kept grant: %v %v", info, err)
	}
	if g2, err := r.joiner().operatorGrant(context.Background(), oj, "node-a"); err != nil || g2.Token != "a.b" || op.requests() != 1 {
		t.Fatalf("rerun = %+v %v after %d requests", g2, err, op.requests())
	}
	// Under a minute left: asked for afresh.
	stale, _ := json.Marshal(operatorGrant{Token: "old.one", JoinURL: "https://s0:7003", ExpiresAt: time.Now().Add(30 * time.Second)})
	mustWrite(t, grantFile(r.paths), string(stale))
	if g3, err := r.joiner().operatorGrant(context.Background(), oj, "node-a"); err != nil || g3.Token != "a.b" || op.requests() != 2 {
		t.Fatalf("stale kept grant = %+v %v after %d requests", g3, err, op.requests())
	}
	for _, bad := range []string{"not json", `{"token":"","join_url":"x"}`} {
		mustWrite(t, grantFile(r.paths), bad)
		if _, ok := readGrant(grantFile(r.paths), time.Now()); ok {
			t.Fatalf("%q read as a grant", bad)
		}
	}
}

// What the operator refuses stops the join at once; what it says to ask
// again is asked again until the wait runs out. Each says why.
func TestOperatorGrantRefusals(t *testing.T) {
	for _, tc := range []struct {
		name     string
		answers  []func(w http.ResponseWriter)
		token    string
		ca       []byte
		wait     time.Duration
		want     string
		requests int
	}{
		{"wrong machine", []func(http.ResponseWriter){refuseAnswer(http.StatusForbidden, "wrong machine: the token was made on m2", "")},
			"t", nil, time.Second, "the operator refused (403): wrong machine", 1},
		{"already given", []func(http.ResponseWriter){refuseAnswer(http.StatusConflict, "pod p got its join token at", "")},
			"t", nil, time.Second, "(409): pod p got its join token", 1},
		{"no leader for longer than the wait", []func(http.ResponseWriter){refuseAnswer(http.StatusServiceUnavailable, "no leader", "")},
			"t", nil, 100 * time.Millisecond, "no join token from the operator in 100ms", 0},
		{"busy, then told when to ask", []func(http.ResponseWriter){refuseAnswer(http.StatusTooManyRequests, "busy", "1"), refuseAnswer(http.StatusForbidden, "no", "")},
			"t", nil, 5 * time.Second, "(403): no", 2},
		{"an answer that is not JSON", []func(http.ResponseWriter){func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>")) }},
			"t", nil, time.Second, "not JSON", 1},
		{"an answer with no token", []func(http.ResponseWriter){grantAnswer(operatorGrant{JoinURL: "https://s0:7003"})},
			"t", nil, time.Second, "no token or join URL", 1},
		{"a plain-text refusal", []func(http.ResponseWriter){func(w http.ResponseWriter) { w.WriteHeader(http.StatusUnauthorized); _, _ = w.Write([]byte("go away")) }},
			"t", nil, time.Second, "(401): go away", 1},
		{"an empty pod token", []func(http.ResponseWriter){refuseAnswer(http.StatusForbidden, "x", "")},
			"  ", nil, time.Second, "token is empty", 0},
		{"a CA that is not PEM", []func(http.ResponseWriter){refuseAnswer(http.StatusForbidden, "x", "")},
			"t", []byte("nope"), time.Second, "holds no PEM certificate", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newJoinRig(t)
			op := newFakeOperator(t, tc.answers...)
			ca := tc.ca
			if ca == nil {
				ca = op.ca()
			}
			oj := OperatorJoin{URL: op.srv.URL, CA: ca, TokenFile: identityToken(t, tc.token), Wait: tc.wait, Backoff: 20 * time.Millisecond}
			_, err := r.joiner().operatorGrant(context.Background(), oj, "node-a")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if tc.requests > 0 && op.requests() != tc.requests {
				t.Fatalf("%d requests, want %d", op.requests(), tc.requests)
			}
			if exists(grantFile(r.paths)) {
				t.Fatal("a refusal was kept as a grant")
			}
		})
	}
}

// An operator that is not there yet is asked again; one whose certificate
// another CA signed is never trusted.
func TestOperatorGrantTransport(t *testing.T) {
	r := newJoinRig(t)
	op := newFakeOperator(t, grantAnswer(operatorGrant{Token: "a.b", JoinURL: "https://s0:7003", ExpiresAt: time.Now().Add(time.Hour)}))
	oj := OperatorJoin{URL: op.srv.URL, CA: otherCA(t), TokenFile: identityToken(t, "t"), Wait: 100 * time.Millisecond, Backoff: 20 * time.Millisecond}
	if _, err := r.joiner().operatorGrant(context.Background(), oj, ""); err == nil || !strings.Contains(err.Error(), "did not answer") || op.requests() != 0 {
		t.Fatalf("an operator another CA vouches for: %v (%d requests)", err, op.requests())
	}
	// Gone: the token file the kubelet should have made.
	oj = OperatorJoin{URL: op.srv.URL, CA: op.ca(), TokenFile: filepath.Join(t.TempDir(), "none")}
	if _, err := r.joiner().operatorGrant(context.Background(), oj, ""); err == nil || !strings.Contains(err.Error(), "ServiceAccount token") {
		t.Fatalf("no token file: %v", err)
	}
	// Stopped while waiting to ask again.
	slow := newFakeOperator(t, refuseAnswer(http.StatusServiceUnavailable, "no leader", ""))
	ctx, cancel := context.WithCancel(context.Background())
	oj = OperatorJoin{URL: slow.srv.URL, CA: slow.ca(), TokenFile: identityToken(t, "t"), Backoff: time.Hour, Wait: 2 * time.Hour}
	go func() {
		for slow.requests() == 0 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	if _, err := r.joiner().operatorGrant(ctx, oj, ""); err != context.Canceled {
		t.Fatalf("cancelled: %v", err)
	}
}

// --from-operator is a pod's setup: files only, and the operator gives the
// URL, token and CA hash.
func TestJoinFromOperatorFlags(t *testing.T) {
	r := newJoinRig(t)
	from := func() *OperatorJoin {
		return &OperatorJoin{URL: "https://op/v1/join-token", CA: []byte("x"), TokenFile: "/t"}
	}
	for _, tc := range []struct {
		o    JoinOptions
		want string
	}{
		{JoinOptions{FromOperator: from()}, "add --files-only"},
		{JoinOptions{FilesOnly: true, URL: "https://s0:7003", FromOperator: from()}, "takes no join URL"},
		{JoinOptions{FilesOnly: true, Token: "a.b", FromOperator: from()}, "takes no join URL, --token"},
		{JoinOptions{FilesOnly: true, ByCertificate: true, FromOperator: from()}, "--by-certificate"},
		{JoinOptions{FilesOnly: true, FromOperator: &OperatorJoin{URL: "http://op", TokenFile: "/t"}}, "https URL"},
		{JoinOptions{FilesOnly: true, FromOperator: &OperatorJoin{URL: "https://op"}}, "--identity-token is required"},
	} {
		if _, err := r.joiner().Run(context.Background(), tc.o); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: err = %v, want %q", tc.o, err, tc.want)
		}
	}
}

// otherCA is a CA that signed nothing the fake operator serves.
func otherCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "another CA"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
