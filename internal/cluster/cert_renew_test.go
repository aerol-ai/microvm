package cluster

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// Node cert renewal (cert_renew.go): due at two thirds of life, the same
// key, atomic write, reload on the next handshake, and the failure metrics.

func TestRenewDueAtTwoThirds(t *testing.T) {
	start := time.Unix(0, 0)
	leaf := &x509.Certificate{NotBefore: start, NotAfter: start.Add(90 * time.Minute)}
	for at, want := range map[time.Duration]bool{0: false, 59*time.Minute + 59*time.Second: false, 60 * time.Minute: true, 89 * time.Minute: true} {
		if got := renewDue(leaf, start.Add(at)); got != want {
			t.Fatalf("renewDue at %s = %v, want %v", at, got, want)
		}
	}
	for life, want := range map[time.Duration]time.Duration{
		10 * time.Minute: 30 * time.Second, time.Minute: certRenewCheckMin, NodeCertLifetime: certRenewCheckMax,
	} {
		if got := renewCheckEvery(&x509.Certificate{NotBefore: start, NotAfter: start.Add(life)}); got != want {
			t.Fatalf("renewCheckEvery(%s) = %s, want %s", life, got, want)
		}
	}
	if renewCheckEvery(nil) != certRenewCheckMax {
		t.Fatal("renewCheckEvery(nil)")
	}
}

// renewHarness is a node's TLS dir signed by the shared test CA, a signer
// for that CA, and a renewer on a fake clock.
type renewHarness struct {
	dir   string
	ct    *ClusterTLS
	ca    *ClusterCA
	leaf  *x509.Certificate
	now   time.Time
	calls int
	r     *certRenewer
}

func newRenewHarness(t *testing.T, nodeID string) *renewHarness {
	t.Helper()
	dir := writeTestClusterTLSDir(t, nodeID)
	ct, err := loadClusterTLS(dir)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseClusterCA(sharedTestCAPEM, sharedCAKeyPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := leafCertificate(&ct.nodeCert)
	h := &renewHarness{dir: dir, ct: ct, ca: ca, leaf: leaf, now: leaf.NotBefore.Add(time.Minute)}
	h.r = &certRenewer{tls: ct, nodeID: nodeID, now: func() time.Time { return h.now }}
	return h
}

func (h *renewHarness) signSameKey(t *testing.T) func(context.Context, []byte) ([]byte, error) {
	return func(_ context.Context, csrPEM []byte) ([]byte, error) {
		h.calls++
		csr, err := ParseCertificateRequestPEM(csrPEM)
		if err != nil {
			t.Fatalf("renewer sent a bad CSR: %v", err)
		}
		certPEM, _, err := h.ca.SignNodeCert(NodeCertRequest{PublicKey: csr.PublicKey, NodeID: h.r.nodeID, Role: JoinRoleWorker})
		return certPEM, err
	}
}

func TestCertRenewerRenewsAtTwoThirdsWithTheSameKey(t *testing.T) {
	h := newRenewHarness(t, "renew-1")
	h.r.renew = h.signSameKey(t)
	before := certRenewals.Value()
	// Not due: nothing is sent.
	if leaf, err := h.r.tick(context.Background()); err != nil || leaf.SerialNumber.Cmp(h.leaf.SerialNumber) != 0 || h.calls != 0 {
		t.Fatalf("tick before 2/3 = %v %v, %d calls", leaf, err, h.calls)
	}
	// Past two thirds: renewed, written atomically, served on the next
	// handshake.
	h.now = h.leaf.NotBefore.Add(h.leaf.NotAfter.Sub(h.leaf.NotBefore) * 2 / 3).Add(time.Second)
	renewed, err := h.r.tick(context.Background())
	if err != nil || h.calls != 1 {
		t.Fatalf("tick past 2/3 = %v, %d calls", err, h.calls)
	}
	if CertKeyHash(renewed) != CertKeyHash(h.leaf) || ExtractPeerRole(renewed) != JoinRoleWorker {
		t.Fatalf("renewed cert = %v", renewed.DNSNames)
	}
	onDisk, _ := os.ReadFile(filepath.Join(h.dir, tlsNodeCertFile))
	if fromDisk, _ := firstPEMCertificate(onDisk); fromDisk == nil || fromDisk.SerialNumber.Cmp(renewed.SerialNumber) != 0 {
		t.Fatal("node.crt was not replaced")
	}
	served, err := h.ct.certificateForHandshake()
	if err != nil {
		t.Fatal(err)
	}
	if sl, _ := leafCertificate(served); sl.SerialNumber.Cmp(renewed.SerialNumber) != 0 {
		t.Fatal("the renewed cert is not served on the next handshake")
	}
	if certRenewals.Value() != before+1 || certRenewFailingSince.Value() != 0 {
		t.Fatalf("metrics: renewals %d failing since %d", certRenewals.Value(), certRenewFailingSince.Value())
	}
	// The new cert is fresh: not due again.
	if _, err := h.r.tick(context.Background()); err != nil || h.calls != 1 {
		t.Fatalf("tick after renewal = %v, %d calls", err, h.calls)
	}
	// No temp files are left beside it.
	entries, _ := os.ReadDir(h.dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file %s left behind", e.Name())
		}
	}
}

func TestCertRenewerFailures(t *testing.T) {
	other := mustCA(t)
	otherKey, _, _ := NewNodeKey()
	cases := map[string]func(h *renewHarness) func(context.Context, []byte) ([]byte, error){
		"signer error": func(*renewHarness) func(context.Context, []byte) ([]byte, error) {
			return func(context.Context, []byte) ([]byte, error) { return nil, errors.New("all servers down") }
		},
		"junk answer": func(*renewHarness) func(context.Context, []byte) ([]byte, error) {
			return func(context.Context, []byte) ([]byte, error) { return []byte("junk"), nil }
		},
		"another key": func(h *renewHarness) func(context.Context, []byte) ([]byte, error) {
			return func(context.Context, []byte) ([]byte, error) {
				p, _, err := h.ca.SignNodeCert(NodeCertRequest{PublicKey: &otherKey.PublicKey, NodeID: h.r.nodeID, Role: JoinRoleWorker})
				return p, err
			}
		},
		"another node": func(h *renewHarness) func(context.Context, []byte) ([]byte, error) {
			return func(_ context.Context, csrPEM []byte) ([]byte, error) {
				csr, _ := ParseCertificateRequestPEM(csrPEM)
				p, _, err := h.ca.SignNodeCert(NodeCertRequest{PublicKey: csr.PublicKey, NodeID: "someone-else", Role: JoinRoleWorker})
				return p, err
			}
		},
		"another CA": func(h *renewHarness) func(context.Context, []byte) ([]byte, error) {
			return func(_ context.Context, csrPEM []byte) ([]byte, error) {
				csr, _ := ParseCertificateRequestPEM(csrPEM)
				p, _, err := other.SignNodeCert(NodeCertRequest{PublicKey: csr.PublicKey, NodeID: h.r.nodeID, Role: JoinRoleWorker})
				return p, err
			}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			h := newRenewHarness(t, "renew-f")
			h.r.renew = mk(h)
			h.now = h.leaf.NotAfter.Add(-time.Minute)
			certRenewFailingSince.Set(0)
			before := certRenewFailures.Value()
			orig, _ := os.ReadFile(filepath.Join(h.dir, tlsNodeCertFile))
			if _, err := h.r.tick(context.Background()); err == nil {
				t.Fatal("a bad renewal reported success")
			}
			if certRenewFailures.Value() != before+1 || certRenewFailingSince.Value() != h.now.Unix() {
				t.Fatalf("metrics: failures %d->%d, failing since %d", before, certRenewFailures.Value(), certRenewFailingSince.Value())
			}
			// The served cert is untouched.
			if now, _ := os.ReadFile(filepath.Join(h.dir, tlsNodeCertFile)); !bytes.Equal(now, orig) {
				t.Fatal("a bad renewal replaced node.crt")
			}
			// A second failure keeps the original "failing since".
			h.now = h.now.Add(time.Second)
			_, _ = h.r.tick(context.Background())
			if certRenewFailingSince.Value() != h.now.Add(-time.Second).Unix() {
				t.Fatal("failing-since moved on a repeated failure")
			}
		})
	}
	certRenewFailingSince.Set(0)
}

func TestCertRenewerSkipsBeforeAdopt(t *testing.T) {
	h := newRenewHarness(t, "renew-s")
	h.r.renew = func(context.Context, []byte) ([]byte, error) { return nil, ErrNotAdmitted }
	h.now = h.leaf.NotAfter.Add(-time.Minute)
	skipped, failures := certRenewSkipped.Value(), certRenewFailures.Value()
	if _, err := h.r.tick(context.Background()); err != nil {
		t.Fatalf("pre-adopt renewal = %v", err)
	}
	if certRenewSkipped.Value() != skipped+1 || certRenewFailures.Value() != failures {
		t.Fatal("a pre-adopt cluster counted a renewal failure")
	}
	// No path to write to is a failure, not a panic.
	h.r.renew = h.signSameKey(t)
	h.ct.certPath, h.ct.keyPath = "", ""
	if _, err := h.r.tick(context.Background()); err == nil {
		t.Fatal("renewal with nowhere to write succeeded")
	}
	// A key that can't sign.
	h2 := newRenewHarness(t, "renew-k")
	h2.ct.certPath, h2.ct.keyPath = "", ""
	h2.ct.nodeCert.PrivateKey = "not a key"
	h2.now = h2.leaf.NotAfter.Add(-time.Minute)
	h2.r.renew = h2.signSameKey(t)
	if _, err := h2.r.tick(context.Background()); err == nil {
		t.Fatal("renewal with an unusable key succeeded")
	}
	var broken certRenewer
	broken.tls = &ClusterTLS{}
	if _, err := broken.tick(context.Background()); err == nil {
		t.Fatal("renewer without a cert succeeded")
	}
}

func TestStartCertRenewerLoop(t *testing.T) {
	startCertRenewer(nil)()
	startCertRenewer(&certRenewer{})()
	h := newRenewHarness(t, "renew-loop")
	h.now = h.leaf.NotAfter.Add(-time.Minute)
	done := make(chan struct{}, 1)
	h.r.renew = func(_ context.Context, csr []byte) ([]byte, error) {
		select {
		case done <- struct{}{}:
		default:
		}
		return nil, ErrNotAdmitted
	}
	stop := startCertRenewer(h.r)
	defer stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop never ticked")
	}
	r := &certRenewer{tls: h.ct, nodeID: "x", renew: h.r.renew}
	stop2 := startCertRenewer(r)
	stop2()
	if r.now == nil {
		t.Fatal("startCertRenewer left the clock unset")
	}
}

// A worker renews through the server tier; a server's 503 moves on, a
// pre-adopt refusal is recognised.
func TestAgentRenewViaServers(t *testing.T) {
	h := newRenewHarness(t, "renew-agent")
	key := h.ct.nodeCert.PrivateKey.(crypto.Signer)
	csr, _ := NewNodeCSR(key, "renew-agent")
	notAdmitted := false
	reply := func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != PublicInternalRenewCertPath {
			return false
		}
		if notAdmitted {
			w.WriteHeader(http.StatusPreconditionFailed)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": ErrNotAdmitted.Error()})
			return true
		}
		var req RenewCertRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		c, _ := ParseCertificateRequestPEM([]byte(req.CSR))
		p, _, _ := h.ca.SignNodeCert(NodeCertRequest{PublicKey: c.PublicKey, NodeID: "renew-agent", Role: JoinRoleWorker})
		_ = json.NewEncoder(w).Encode(RenewCertResponse{NodeCert: string(p)})
		return true
	}
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, reply))
	got, err := agent.renewViaServers(context.Background(), csr)
	if err != nil || !strings.Contains(string(got), "CERTIFICATE") {
		t.Fatalf("agent renew = %v", err)
	}
	notAdmitted = true
	if _, err := agent.renewViaServers(context.Background(), csr); !errors.Is(err, ErrNotAdmitted) {
		t.Fatalf("agent renew before adopt = %v", err)
	}
}

// A worker forwards join-token routes to the server tier and gets the
// server's refusals back as sentinels.
func TestAgentJoinTokensViaServers(t *testing.T) {
	reply := func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == PublicJoinTokensPath:
			var req JoinTokenCreateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.TTL == "0" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": ErrJoinTTLNeedsWrappedCustody.Error()})
				return true
			}
			_ = json.NewEncoder(w).Encode(JoinTokenCreated{ID: "abcdef", Role: req.Role, Token: "abcdef." + strings.Repeat("a", 32)})
		case r.Method == http.MethodGet && r.URL.Path == PublicJoinTokensPath:
			_ = json.NewEncoder(w).Encode(JoinTokenList{Tokens: []JoinTokenInfo{{ID: "abcdef"}}})
		case r.Method == http.MethodDelete && r.URL.Path == PublicJoinTokensPath+"/abcdef":
			w.WriteHeader(http.StatusNoContent)
		default:
			return false
		}
		return true
	}
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, reply), Member{NodeID: "w2", Alive: true, Role: config.NodeRoleWorker})
	ctx := context.Background()
	var mgr JoinTokenManager = agent
	created, err := mgr.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleWorker})
	if err != nil || created.ID != "abcdef" {
		t.Fatalf("create = %+v %v", created, err)
	}
	if _, err := mgr.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleWorker, TTL: "0"}); !errors.Is(err, ErrJoinTTLNeedsWrappedCustody) {
		t.Fatalf("refused create = %v", err)
	}
	if list, err := mgr.ListJoinTokens(ctx); err != nil || len(list.Tokens) != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	if err := mgr.RevokeJoinToken(ctx, "abcdef"); err != nil {
		t.Fatalf("revoke = %v", err)
	}
	if err := mgr.RevokeJoinToken(ctx, "BAD!"); !errors.Is(err, ErrJoinBadRequest) {
		t.Fatalf("revoke bad id = %v", err)
	}
	if agentJoinError(nil) != nil || agentJoinError(errors.New("x")).Error() != "x" {
		t.Fatal("agentJoinError passthrough")
	}
	if !isPeerRetryable(ErrNoCASigner) || !isPeerRetryable(statusError{status: http.StatusServiceUnavailable}) || isPeerRetryable(ErrNotAdmitted) {
		t.Fatal("isPeerRetryable")
	}
	if err := peerJoinError(500, "plain"); !strings.Contains(err.Error(), "plain") {
		t.Fatalf("peerJoinError = %v", err)
	}
}
