package cluster

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// Failure paths of the join service and renewal that need a broken
// dependency: a failing random source, a key that refuses to sign, files
// that can't be written.

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy exhausted") }

// failingSigner holds a real public key but refuses to sign.
type failingSigner struct{ pub crypto.PublicKey }

func (s failingSigner) Public() crypto.PublicKey { return s.pub }
func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("hsm unplugged")
}

func TestPKIRandomAndSignerFailures(t *testing.T) {
	ca := mustCA(t)
	key, _, _ := NewNodeKey()
	prev := pkiRandom
	pkiRandom = failingReader{}
	_, tokErr := GenerateJoinToken()
	_, _, caErr := GenerateClusterCA("x", time.Now())
	_, _, signErr := ca.SignNodeCert(NodeCertRequest{PublicKey: &key.PublicKey, NodeID: "n", Role: JoinRoleWorker})
	pkiRandom = prev
	if tokErr == nil || caErr == nil || signErr == nil {
		t.Fatalf("a failing random source gave token %v, CA %v, cert %v", tokErr, caErr, signErr)
	}

	bad := failingSigner{pub: &key.PublicKey}
	if _, err := NewNodeCSR(bad, "n"); err == nil {
		t.Fatal("CSR from a key that can't sign")
	}
	broken := &ClusterCA{cert: ca.Certificate(), key: failingSigner{pub: ca.Certificate().PublicKey}}
	if _, _, err := broken.SignNodeCert(NodeCertRequest{PublicKey: &key.PublicKey, NodeID: "n", Role: JoinRoleWorker}); err == nil {
		t.Fatal("cert from a CA key that can't sign")
	}
	// A PKCS#8 key that can't sign (X25519) is not a CA key.
	x, _ := ecdh.X25519().GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(x)
	if _, err := parsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err == nil {
		t.Fatal("X25519 accepted as a signing key")
	}
	// ca.crt can't be written (a directory sits there).
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, caStoreCertFile, "x"), 0o700)
	if err := SaveClusterCA(dir, ca); err == nil {
		t.Fatal("CA saved over a directory")
	}
}

func TestCertRenewerFailurePaths(t *testing.T) {
	ctx := context.Background()
	// The served cert can't be read and there is no last good one.
	r := &certRenewer{tls: &ClusterTLS{certPath: "/nonexistent/node.crt", keyPath: "/nonexistent/node.key"}, now: time.Now}
	if _, err := r.tick(ctx); err == nil {
		t.Fatal("tick without a cert succeeded")
	}
	// A key that refuses to sign the CSR.
	h := newRenewHarness(t, "renew-sign")
	h.ct.certPath, h.ct.keyPath = "", ""
	h.ct.nodeCert.PrivateKey = failingSigner{pub: h.leaf.PublicKey}
	h.now = h.leaf.NotAfter.Add(-time.Minute)
	h.r.renew = h.signSameKey(t)
	if _, err := h.r.tick(ctx); err == nil {
		t.Fatal("renewal with a key that can't sign succeeded")
	}
	// Logged skip and logged success.
	h2 := newRenewHarness(t, "renew-log")
	h2.r.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	h2.now = h2.leaf.NotAfter.Add(-time.Minute)
	h2.r.renew = func(context.Context, []byte) ([]byte, error) { return nil, ErrNotAdmitted }
	if _, err := h2.r.tick(ctx); err != nil {
		t.Fatal(err)
	}
	h2.r.renew = h2.signSameKey(t)
	if _, err := h2.r.tick(ctx); err != nil {
		t.Fatal(err)
	}
	// node.crt's directory is gone: the write fails.
	h3 := newRenewHarness(t, "renew-write")
	h3.now = h3.leaf.NotAfter.Add(-time.Minute)
	h3.r.renew = h3.signSameKey(t)
	served, _ := h3.ct.certificateForHandshake()
	h3.ct.certPath = filepath.Join(t.TempDir(), "gone", "node.crt")
	h3.ct.keyPath = h3.ct.certPath
	h3.ct.current.Store(served)
	if _, err := h3.r.tick(ctx); err == nil {
		t.Fatal("renewal into a missing directory succeeded")
	}
	certRenewFailingSince.Set(0)

	// A server with a CA key but no TLS: no leaf to renew.
	c := &Cluster{fsm: newPlacementFSM()}
	c.ca.set(mustCA(t))
	if _, err := c.renewViaServers(ctx, nil); err == nil {
		t.Fatal("in-process renewal without TLS succeeded")
	}
	if _, err := c.currentLeaf(); err == nil {
		t.Fatal("leaf without TLS")
	}
	c.tls = &ClusterTLS{certPath: "/nonexistent/a", keyPath: "/nonexistent/b"}
	if _, err := c.currentLeaf(); err == nil {
		t.Fatal("leaf with unreadable files")
	}
	c.tls = &ClusterTLS{caPEM: []byte("junk")}
	if _, _, err := c.clusterCACert(); err == nil {
		t.Fatal("junk ca.crt parsed")
	}

	// A worker whose server hangs up mid-request.
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != PublicInternalRenewCertPath {
			return false
		}
		panic(http.ErrAbortHandler)
	}))
	if _, err := agent.renewViaServers(ctx, []byte("csr")); err == nil {
		t.Fatal("renewal through a hung-up server succeeded")
	}
}

func TestJoinServiceFailurePaths(t *testing.T) {
	ctx := context.Background()
	// Role defaults to worker; the write then fails without Raft.
	if _, err := (&Cluster{}).CreateJoinToken(ctx, JoinTokenCreateRequest{}); err == nil {
		t.Fatal("create without Raft succeeded")
	}
	// A CA store that can't be read stops adopt.
	c := edgeCluster(t, "fail-1")
	_ = os.MkdirAll(filepath.Join(c.cfg.ClusterCADir, caStoreKeyFile), 0o700)
	if _, err := c.Adopt(ctx, AdoptRequest{}); err == nil {
		t.Fatal("adopt with an unreadable CA store succeeded")
	}
	// Adopt with members but no Raft: the write fails after the CA is in.
	c2 := edgeCluster(t, "fail-2")
	c2.gossip = &gossipNode{memberIndex: newGossipMemberIndex()}
	c2.gossip.memberIndex.upsert(Member{NodeID: "fail-2", Alive: true, Role: config.NodeRoleServer})
	if _, err := c2.Adopt(ctx, AdoptRequest{CAKey: string(sharedCAKeyPEM(t))}); err == nil {
		t.Fatal("adopt without Raft succeeded")
	}
	// The FSM adopt rule for a key another node holds, and a second rekey
	// retiring the first previous key.
	f := newPlacementFSM()
	applyDenyLogAt(t, f, 1, command{Op: opAdoptNodes, StampUnixNano: 1, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{{NodeID: "a", Role: JoinRoleWorker, KeyHash: testKey("a")}}}})
	res, _ := applyDenyLogAt(t, f, 2, command{Op: opAdoptNodes, StampUnixNano: 2, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{{NodeID: "b", Role: JoinRoleWorker, KeyHash: testKey("a")}}}}).(JoinAdoptResult)
	if res.Skipped["b"] == "" {
		t.Fatalf("adopt of a held key = %+v", res)
	}
	for i, k := range []string{"a2", "a3"} {
		old := "a"
		if i == 1 {
			old = "a2"
		}
		applyDenyLogAt(t, f, uint64(3+i), command{Op: opRekeyNode, StampUnixNano: 3, JoinRekey: &JoinRekeyCommand{NodeID: "a", OldKeyHash: testKey(old), NewKeyHash: testKey(k)}})
	}
	if rec, _ := f.admittedNode("a"); rec.KeyHash != testKey("a3") || rec.PrevKeyHash != testKey("a2") {
		t.Fatalf("after two rekeys = %+v", rec)
	}
	if _, held := f.admittedByKey[testKey("a")]; held {
		t.Fatal("the first key is still indexed after two rekeys")
	}

	// peerLeaf refuses a cert that names another node.
	other, err := loadClusterTLS(writeTestClusterTLSDir(t, "someone-else"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", other.serverConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()
	if _, err := c.peerLeaf(ctx, Member{NodeID: "expected", InternalURL: "https://" + ln.Addr().(*net.TCPAddr).String()}); err == nil {
		t.Fatal("peerLeaf took a cert for another node")
	}
	if leaf, err := c.peerLeaf(ctx, Member{NodeID: "someone-else", InternalURL: "https://" + ln.Addr().String()}); err != nil || ExtractPeerNodeID(leaf) != "someone-else" {
		t.Fatalf("peerLeaf = %v", err)
	}
}
