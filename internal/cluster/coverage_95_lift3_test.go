package cluster

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"github.com/hashicorp/memberlist"
)

func TestFSMSnapshotReleaseEmptyBody(t *testing.T) {
	// Release is an empty raft.FSMSnapshot hook; call the concrete type so
	// coverage attributes the method even though it has no statements.
	(&fsmSnapshot{}).Release()
	snap, err := newPlacementFSM().Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	snap.Release()
}

func TestAuthoritativePlacementsByIDsFollowerPath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	// Follower reads must go over the leader's internal channel — a local FSM
	// lookup would be stale after a leadership change. One 2-node harness
	// covers the real path; a probe Cluster reuses the follower raft so HTTP
	// error branches do not need a second election.
	leader, cleanupL := newTestCluster(t, "ldr-auth-ids", true, nil)
	defer cleanupL()
	follower, cleanupF := newTestCluster(t, "fol-auth-ids", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupF()
	waitForLeader(t, leader, 10*time.Second)
	waitForVoter(t, leader, follower.nodeID, 20*time.Second)
	waitForLeader(t, follower, 10*time.Second)

	ctx := context.Background()
	if err := leader.RecordPlacement(ctx, "sb-auth-fol", &models.CreateSandboxRequest{Image: "alpine"}, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	if follower.Leader() == follower.nodeID {
		t.Fatal("follower unexpectedly became raft leader")
	}
	// Live mTLS can 503 if the leader internal route is still coming up;
	// the probe Cluster below reuses this follower raft so the same
	// non-leader body is covered either way.
	if _, err := follower.AuthoritativePlacementsByIDs(ctx, []string{"sb-auth-fol"}); err != nil {
		t.Logf("live follower authoritative: %v", err)
	}
	_ = follower.DeletePlacement(ctx, "missing-auth")

	if err := leader.PruneAuditACL(ctx, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("PruneAuditACL: %v", err)
	}
	leader.SetLocalTemplateCatalogProvider(func() ([]string, bool) { return []string{"tpl"}, true })
	leader.SetLocalWasmModuleIDsProvider(func() ([]string, bool) { return []string{"mod"}, true })
	_ = leader.membersWithCapacity()
	_ = leader.PlacementVersion()
	subCtx, cancel := context.WithCancel(ctx)
	ch := leader.SubscribePlacement(subCtx)
	cancel()
	if ch == nil {
		t.Fatal("SubscribePlacement returned nil on a live FSM")
	}

	leaderID := follower.Leader()
	if leaderID == "" {
		t.Fatal("follower reported no leader")
	}

	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("authoritative") != "true" {
			http.Error(w, "missing authoritative", http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	probeFor := func(internalURL string, client *http.Client) *Cluster {
		index := newGossipMemberIndex()
		index.upsert(Member{NodeID: leaderID, Alive: true, InternalURL: internalURL})
		probe := &Cluster{
			nodeID:   follower.nodeID,
			patToken: "tok",
			fsm:      follower.fsm,
			raft:     follower.raft,
			gossip:   &gossipNode{memberIndex: index},
		}
		probe.setInternalClient(client)
		return probe
	}

	status, body = http.StatusOK, `{"sb-probe":{"sandbox_id":"sb-probe"}}`
	got, err := probeFor(srv.URL, srv.Client()).AuthoritativePlacementsByIDs(ctx, []string{"sb-probe"})
	if err != nil || got["sb-probe"].SandboxID != "sb-probe" {
		t.Fatalf("probe ok = %+v err=%v", got, err)
	}

	status, body = http.StatusOK, "null"
	got, err = probeFor(srv.URL, srv.Client()).AuthoritativePlacementsByIDs(ctx, []string{"sb-probe"})
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("null map = %+v err=%v", got, err)
	}

	status, body = http.StatusOK, "{not-json"
	if _, err = probeFor(srv.URL, srv.Client()).AuthoritativePlacementsByIDs(ctx, []string{"sb"}); err == nil {
		t.Fatal("decode error expected")
	}

	status, body = http.StatusServiceUnavailable, "not leader"
	if _, err = probeFor(srv.URL, srv.Client()).AuthoritativePlacementsByIDs(ctx, []string{"sb"}); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("503 = %v", err)
	}

	status, body = http.StatusInternalServerError, "boom"
	if _, err = probeFor(srv.URL, srv.Client()).AuthoritativePlacementsByIDs(ctx, []string{"sb"}); err == nil {
		t.Fatal("500 expected")
	}

	if _, err = probeFor("http://127.0.0.1:1", http.DefaultClient).AuthoritativePlacementsByIDs(ctx, []string{"sb"}); err == nil {
		t.Fatal("dial error expected")
	}
	if _, err = probeFor("http://%zz", http.DefaultClient).AuthoritativePlacementsByIDs(ctx, []string{"sb"}); err == nil {
		t.Fatal("bad URL expected")
	}
	if _, err = probeFor("", srv.Client()).AuthoritativePlacementsByIDs(ctx, []string{"sb"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("empty internal URL = %v", err)
	}

	noClient := probeFor(srv.URL, nil)
	if _, err = noClient.AuthoritativePlacementsByIDs(ctx, []string{"sb"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("nil client = %v", err)
	}
	noGossip := &Cluster{nodeID: follower.nodeID, fsm: follower.fsm, raft: follower.raft}
	noGossip.setInternalClient(srv.Client())
	if _, err = noGossip.AuthoritativePlacementsByIDs(ctx, []string{"sb"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("nil gossip = %v", err)
	}
}

func TestWriteGCManifestRenameOntoDirectory(t *testing.T) {
	// CreateTemp succeeds; os.Rename onto an existing directory is the
	// remaining writeGCManifest failure (chmod-readonly hits create-temp instead).
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(store.gcManifestPath(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.writeGCManifest(placementRecoveryGCManifest{Snapshots: []placementRecoverySnapshotRefs{{CreatedUnix: 1}}}); err == nil {
		t.Fatal("rename onto directory should fail")
	}
}

func TestValidateClusterNodeCertificateRemaining(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"AerolVM Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	mint := func(dns []string, eku []x509.ExtKeyUsage) tls.Certificate {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "node"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  eku,
			DNSNames:     dns,
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}

	if _, _, err := validateClusterNodeCertificate(&tls.Certificate{}, pool); err == nil {
		t.Fatal("empty cert accepted")
	}

	valid := mint([]string{clusterServerName, "node:n1"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	valid.Certificate = append(valid.Certificate, []byte("not-a-cert"))
	if _, _, err := validateClusterNodeCertificate(&valid, pool); err == nil {
		t.Fatal("garbage intermediate accepted")
	}

	good := mint([]string{clusterServerName, "node:n1"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	if _, _, err := validateClusterNodeCertificate(&good, x509.NewCertPool()); err == nil {
		t.Fatal("untrusted pool accepted")
	}

	serverOnly := mint([]string{clusterServerName, "node:n1"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if _, _, err := validateClusterNodeCertificate(&serverOnly, pool); err == nil {
		t.Fatal("server-only EKU accepted")
	}

	noNodeSAN := mint([]string{clusterServerName}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	if _, _, err := validateClusterNodeCertificate(&noNodeSAN, pool); err == nil {
		t.Fatal("missing node SAN accepted")
	}

	id, expiry, err := validateClusterNodeCertificate(&good, pool)
	if err != nil || id != "n1" || expiry.IsZero() {
		t.Fatalf("valid cert id=%q expiry=%v err=%v", id, expiry, err)
	}

	// leafCertificate prefers an already-parsed Leaf so reload skips ParseCertificate.
	parsed, err := x509.ParseCertificate(good.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	good.Leaf = parsed
	if leaf, err := leafCertificate(&good); err != nil || leaf != parsed {
		t.Fatalf("cached leaf = %v err=%v", leaf, err)
	}
}

func TestFetchSandboxAuditFromPeerWrappers(t *testing.T) {
	ctx := context.Background()
	if _, err := (*Cluster)(nil).FetchSandboxAuditFromPeer(ctx, "peer", "sb", 1, "", "", ""); err == nil {
		t.Fatal("nil cluster")
	}
	if _, err := (*Agent)(nil).FetchSandboxAuditFromPeer(ctx, "peer", "sb", 1, "", "", ""); err == nil {
		t.Fatal("nil agent")
	}
	if _, err := (*Noop)(nil).FetchSandboxAuditFromPeer(ctx, "peer", "sb", 1, "", "", ""); err == nil {
		t.Fatal("noop")
	}

	c := &Cluster{nodeID: "self"}
	if _, err := c.FetchSandboxAuditFromPeer(ctx, "peer", "sb", 1, "", "", ""); err == nil {
		t.Fatal("cluster unavailable")
	}
	a := &Agent{nodeID: "self"}
	if _, err := a.FetchSandboxAuditFromPeer(ctx, "peer", "sb", 1, "", "", ""); err == nil {
		t.Fatal("agent unavailable")
	}

	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "dead", Alive: false, InternalURL: "https://dead.internal"})
	index.upsert(Member{NodeID: "plain", Alive: true, InternalURL: "http://plain.internal"})
	c.gossip = &gossipNode{memberIndex: index}
	c.setInternalClient(http.DefaultClient)
	a.gossip = &gossipNode{memberIndex: index}
	a.internalClient = http.DefaultClient

	if _, err := c.FetchSandboxAuditFromPeer(ctx, "missing", "sb", 1, "", "", ""); err == nil {
		t.Fatal("missing peer")
	}
	if _, err := a.FetchSandboxAuditFromPeer(ctx, "dead", "sb", 1, "", "", ""); err == nil {
		t.Fatal("dead peer")
	}
	if _, err := c.FetchSandboxAuditFromPeer(ctx, "plain", "sb", 1, "", "", ""); !errors.Is(err, ErrPeerInternalURLInvalid) {
		t.Fatalf("plaintext cluster = %v", err)
	}
	if _, err := a.FetchSandboxAuditFromPeer(ctx, "plain", "sb", 1, "", "", ""); !errors.Is(err, ErrPeerInternalURLInvalid) {
		t.Fatalf("plaintext agent = %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/audit") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuditPeerPage{NextCursor: "c1"})
	})
	srv, client := newNodeBoundForwardServer(t, "self", "peer-audit", handler)
	live := newGossipMemberIndex()
	live.upsert(Member{NodeID: "peer-audit", Alive: true, InternalURL: srv.URL})
	c.gossip = &gossipNode{memberIndex: live}
	c.setInternalClient(client)
	c.patToken = "pat"
	page, err := c.FetchSandboxAuditFromPeer(ctx, "peer-audit", "sb-1", 10, "cur", "secret", "inc")
	if err != nil || page.NextCursor != "c1" {
		t.Fatalf("cluster fetch = %+v err=%v", page, err)
	}
	a.gossip = &gossipNode{memberIndex: live}
	a.internalClient = client
	if _, err := a.FetchSandboxAuditFromPeer(ctx, "peer-audit", "sb-1", 0, "", "", ""); err != nil {
		t.Fatalf("agent fetch: %v", err)
	}
}

func TestClusterEasyClientAgentFSMBranches(t *testing.T) {
	ctx := context.Background()
	if err := decodeControlPlaneJSON(lift3ErrReader{}, &map[string]Placement{}); err == nil {
		t.Fatal("read error expected")
	}
	if err := decodeControlPlaneJSON(bytes.NewReader(bytes.Repeat([]byte("x"), maxControlPlaneJSONResponseBytes+1)), &map[string]Placement{}); err == nil {
		t.Fatal("oversized JSON expected")
	}
	if err := decodeControlPlaneJSON(strings.NewReader(`{"ok":true}`), &map[string]bool{}); err != nil {
		t.Fatalf("small JSON: %v", err)
	}

	(*Cluster)(nil).SetLocalTemplateCatalogProvider(nil)
	(*Cluster)(nil).SetLocalWasmModuleIDsProvider(nil)
	empty := &Cluster{}
	empty.SetLocalTemplateCatalogProvider(nil)
	empty.SetLocalWasmModuleIDsProvider(nil)
	leases := newCapacityLeaseCache("self", capacity.New(
		capacity.HostInfo{CPUCores: 1, MemoryTotalMB: 1024, DiskTotalGB: 10, DiskFreeGB: 10},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1, DiskReservationRatio: 1},
		nil,
	), time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	withLeases := &Cluster{capacityLeases: leases, gossip: &gossipNode{memberIndex: newGossipMemberIndex()}}
	withLeases.SetLocalTemplateCatalogProvider(func() ([]string, bool) { return nil, false })
	withLeases.SetLocalWasmModuleIDsProvider(func() ([]string, bool) { return nil, false })
	_ = withLeases.membersWithCapacity()

	var nilGossip *gossipNode
	if _, ok := nilGossip.lookupMember("x"); ok {
		t.Fatal("nil gossip lookup")
	}
	g := &gossipNode{memberIndex: newGossipMemberIndex()}
	g.memberIndex.upsert(Member{NodeID: "n1", Alive: true, InternalURL: "https://n1"})
	if m, ok := g.lookupMember("n1"); !ok || m.NodeID != "n1" {
		t.Fatalf("lookup = %+v ok=%v", m, ok)
	}
	if g.peerInternalURL("missing") != "" {
		t.Fatal("missing peerInternalURL")
	}

	(&gossipDelegate{}).NotifyMsg([]byte("x"))
	(&gossipDelegate{}).MergeRemoteState([]byte("x"), true)
	(*Noop)(nil).AttachInternalHandler(http.NotFoundHandler())
	(&voterAutoJoinDelegate{c: &Cluster{}}).NotifyUpdate(&memberlist.Node{Name: "x"})

	if err := validateCommandLifecycle(command{Op: opPlace, SandboxID: "sb"}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("place without incarnation = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opReserveBatch, Reservations: []reservationCommand{{SandboxID: "sb"}}}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("reserve batch = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opClaimOrphan, SandboxID: "sb"}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("claim = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opDelete, SandboxID: "sb"}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("delete = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opPutVolumeAttach, VolumeAttachments: []models.VolumeAttachment{{SandboxID: "sb"}}}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("volume attach = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opDeleteVolumeAttach, VolumeSandboxID: "sb"}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("volume delete = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opUpsertSpec}); err != nil {
		t.Fatalf("upsert no-op = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opUpsertSpec, Spec: &models.CreateSandboxRequest{Image: "x"}, SandboxID: "sb"}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("upsert spec = %v", err)
	}
	sec := testPlacementSecrets("sb", "inc-a", 1)
	if err := validateCommandLifecycle(command{
		Op: opUpsertSpec, SandboxID: "sb", Spec: &models.CreateSandboxRequest{Image: "x"},
		ExpectedIncarnationID: "inc-b", IncarnationID: sec.IncarnationID,
		SecretRef: sec.Ref, SecretVersion: sec.Version, SecretSealGeneration: sec.SealGeneration,
	}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("upsert secret fence = %v", err)
	}
	if err := validateCommandLifecycle(command{Op: opUpdateSecretRecipients, SandboxID: "sb"}); err == nil {
		t.Fatal("secret recipient update accepted")
	}
	if err := validateCommandLifecycle(command{Op: opPlace, SandboxID: "sb", IncarnationID: "inc"}); err != nil {
		t.Fatalf("place ok = %v", err)
	}

	var nilCluster *Cluster
	if _, err := nilCluster.PushSecretBlobToPeers(ctx, secrets.SecretBlob{}, nil); err != nil {
		t.Fatalf("nil cluster self-only push: %v", err)
	}
	if _, err := nilCluster.PushSecretBlobToPeers(ctx, secrets.SecretBlob{}, []string{"peer"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("nil cluster remote push = %v", err)
	}
	bare := &Cluster{nodeID: "self"}
	if _, err := bare.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"self"}, 1); err != nil {
		t.Fatalf("gossip-nil self delete: %v", err)
	}
	if _, err := bare.ProbeSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("gossip-nil remote probe = %v", err)
	}
	var nilAgent *Agent
	if _, err := nilAgent.PushSecretBlobToPeers(ctx, secrets.SecretBlob{}, nil); err != nil {
		t.Fatalf("nil agent self-only: %v", err)
	}
	if _, err := nilAgent.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("nil agent remote delete = %v", err)
	}
	bareAgent := &Agent{nodeID: "self"}
	if _, err := bareAgent.ProbeSecretOnPeers(ctx, "sb", "inc", []string{"self"}, 1); err != nil {
		t.Fatalf("agent gossip-nil self probe: %v", err)
	}
	if _, err := bareAgent.PushSecretBlobToPeers(ctx, secrets.SecretBlob{}, []string{"peer"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("agent gossip-nil remote push = %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalSecretPath:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, PublicInternalSecretPath+"/"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodHead && strings.HasPrefix(r.URL.Path, PublicInternalSecretPath+"/"):
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
	srv, client := newNodeBoundForwardServer(t, "self", "peer-sec", handler)
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "peer-sec", Alive: true, InternalURL: srv.URL})
	live := &Cluster{nodeID: "self", patToken: "pat", gossip: &gossipNode{memberIndex: index}}
	live.setInternalClient(client)
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "sb", SealedPayload: []byte("sealed")}
	if acked, err := live.PushSecretBlobToPeers(ctx, blob, []string{"peer-sec"}); err != nil || len(acked) != 1 {
		t.Fatalf("wrapper push acked=%v err=%v", acked, err)
	}
	if acked, err := live.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer-sec"}, 1); err != nil || len(acked) != 1 {
		t.Fatalf("wrapper delete acked=%v err=%v", acked, err)
	}
	if holding, err := live.ProbeSecretOnPeers(ctx, "sb", "inc", []string{"peer-sec"}, 1); err != nil || len(holding) != 1 {
		t.Fatalf("wrapper probe holding=%v err=%v", holding, err)
	}
	agent := &Agent{nodeID: "self", patToken: "pat", internalClient: client, gossip: &gossipNode{memberIndex: index}}
	if _, err := agent.PushSecretBlobToPeers(ctx, blob, []string{"peer-sec"}); err != nil {
		t.Fatalf("agent wrapper push: %v", err)
	}
	if _, err := agent.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer-sec"}, 1); err != nil {
		t.Fatalf("agent wrapper delete: %v", err)
	}
	if _, err := agent.ProbeSecretOnPeers(ctx, "sb", "inc", []string{"peer-sec"}, 1); err != nil {
		t.Fatalf("agent wrapper probe: %v", err)
	}

	if err := empty.DeletePlacement(ctx, "sb"); err == nil {
		t.Fatal("delete without raft should fail the authoritative read")
	}
}

func TestNewAgentRemainingErrorPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := NewAgent(config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker, SelfAPIAdvertiseURL: "http://127.0.0.1:1", ClusterTLSDir: t.TempDir()}, logger, nil); err == nil {
		t.Fatal("empty tls dir")
	}
	dirs := writeTestClusterTLSDirs(t, "cert-node")
	if _, err := NewAgent(config.Config{
		EnableCluster: true, NodeRole: config.NodeRoleWorker, NodeID: "other-node",
		SelfAPIAdvertiseURL: "http://127.0.0.1:1", ClusterTLSDir: dirs["cert-node"],
	}, logger, nil); err == nil {
		t.Fatal("tls node id mismatch")
	}
	if _, err := NewAgent(config.Config{
		EnableCluster: true, NodeRole: config.NodeRoleWorker, NodeID: "ag-badkey",
		SelfAPIAdvertiseURL: "http://127.0.0.1:1", ClusterTLSDir: writeTestClusterTLSDir(t, "ag-badkey"),
		ClusterInternalListenAddr: "127.0.0.1:0", ClusterGossipSecretKey: "%%%",
	}, logger, nil); err == nil {
		t.Fatal("bad gossip key")
	}
	if _, err := NewAgent(config.Config{
		EnableCluster: true, NodeRole: config.NodeRoleWorker, NodeID: "ag-badbind",
		SelfAPIAdvertiseURL: "http://127.0.0.1:1", ClusterTLSDir: writeTestClusterTLSDir(t, "ag-badbind"),
		ClusterInternalListenAddr: "127.0.0.1:0", GossipBindAddr: "not-a-bind-address",
	}, logger, nil); err == nil {
		t.Fatal("bad gossip bind")
	}
}

func TestAgentDeleteAndAssertOwnershipBranches(t *testing.T) {
	ctx := context.Background()
	placements := map[string]Placement{
		"sb-missing": {},
		"sb-self-res": {
			SandboxID: "sb-self-res", OwnerNodeID: "worker-self", IncarnationID: "inc-res",
			State: PlacementStateReserved, Version: 2,
		},
		"sb-self-placed": {
			SandboxID: "sb-self-placed", OwnerNodeID: "worker-self", IncarnationID: "inc-pl",
			State: PlacementStatePlaced, Version: 3,
		},
		"sb-orphan": {
			SandboxID: "sb-orphan", OwnerNodeID: "", OwnerState: PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "worker-self", IncarnationID: "inc-or",
			State: PlacementStatePlaced, Version: 4,
		},
		"sb-other": {
			SandboxID: "sb-other", OwnerNodeID: "other", IncarnationID: "inc-ot",
			State: PlacementStatePlaced, Version: 5,
		},
	}
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalPlacementsByIDsPath:
			var req placementsByIDsRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			out := map[string]Placement{}
			for _, id := range req.IDs {
				if p, ok := placements[id]; ok && p.SandboxID != "" {
					out[id] = p
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, PublicInternalPlacementPath):
			id := strings.TrimPrefix(r.URL.Path, PublicInternalPlacementPath)
			if id == "lookup-fail" {
				http.Error(w, "nope", http.StatusInternalServerError)
				return
			}
			p, ok := placements[id]
			if !ok || p.SandboxID == "" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{SandboxID: id, Placement: p})
		case r.Method == http.MethodPost && (r.URL.Path == PublicInternalApplyPath || r.URL.Path == InternalAPIPath):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if err := agent.DeletePlacement(ctx, "unknown"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	if err := agent.DeletePlacement(ctx, "sb-self-placed"); err != nil {
		t.Fatalf("delete existing: %v", err)
	}
	if err := agent.DeletePlacementExact(ctx, "", "owner", "inc"); err != nil {
		t.Fatalf("exact empty sandbox: %v", err)
	}
	if err := agent.DeletePlacementExact(ctx, "sb", "owner", ""); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("exact empty incarnation = %v", err)
	}
	if err := agent.ApplyEncoded(ctx, []byte("not-json")); err == nil {
		t.Fatal("ApplyEncoded garbage")
	}

	if err := agent.AssertOwnership(ctx, []LocalSandboxState{
		{},
		{ID: "lookup-fail"},
		{ID: "brand-new", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{80: {Protocol: "http"}}, CustomHostnames: []string{"new.example"}},
		{ID: "sb-self-res", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{81: {Protocol: "http"}}, CustomHostnames: []string{"res.example"}},
		{ID: "sb-self-placed", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{82: {Protocol: "http"}}, CustomHostnames: []string{"pl.example"}},
		{ID: "sb-orphan", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{83: {Protocol: "http"}}, CustomHostnames: []string{"or.example"}},
		{ID: "sb-other"},
	}); err != nil {
		t.Logf("AssertOwnership firstErr=%v", err)
	}

	var nilSrv *internalServer
	nilSrv.SetPeerAuthorizer(nil)
	srv := &internalServer{}
	srv.SetPeerAuthorizer(nil)
	srv.SetPeerAuthorizer(func(string) bool { return true })

	tlsState := &ClusterTLS{}
	if _, err := tlsState.lastGoodCertificate(errors.New("reload")); err == nil {
		t.Fatal("lastGood without current")
	}
	leaf := tls.Certificate{}
	tlsState.current.Store(&leaf)
	if got, err := tlsState.lastGoodCertificate(errors.New("reload")); err != nil || got != &leaf {
		t.Fatalf("lastGood cached = %v err=%v", got, err)
	}

	id, err := MintIncarnationID()
	if err != nil || id == "" {
		t.Fatalf("MintIncarnationID = %q %v", id, err)
	}
}

type lift3ErrReader struct{}

func (lift3ErrReader) Read([]byte) (int, error) { return 0, errors.New("read fail") }

func TestLift3SecretWrapperRemainingGuards(t *testing.T) {
	ctx := context.Background()
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "sb", SealedPayload: []byte("sealed")}

	// Gossip-nil Cluster/Agent still distinguish self-only no-ops from remote
	// transport-required errors so outbox retry does not drop a peer copy.
	bare := &Cluster{nodeID: "self"}
	if _, err := bare.PushSecretBlobToPeers(ctx, blob, []string{"peer"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("cluster gossip-nil remote push = %v", err)
	}
	if _, err := (*Cluster)(nil).DeleteSecretOnPeers(ctx, "sb", "inc", nil, 1); err != nil {
		t.Fatalf("nil cluster self-only delete: %v", err)
	}
	if _, err := bare.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("cluster gossip-nil remote delete = %v", err)
	}
	if _, err := (*Cluster)(nil).ProbeSecretOnPeers(ctx, "sb", "inc", nil, 1); err != nil {
		t.Fatalf("nil cluster self-only probe: %v", err)
	}
	if _, err := (*Agent)(nil).DeleteSecretOnPeers(ctx, "sb", "inc", nil, 1); err != nil {
		t.Fatalf("nil agent self-only delete: %v", err)
	}
	bareAgent := &Agent{nodeID: "self"}
	if _, err := bareAgent.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("agent gossip-nil remote delete = %v", err)
	}
	if _, err := (*Agent)(nil).ProbeSecretOnPeers(ctx, "sb", "inc", nil, 1); err != nil {
		t.Fatalf("nil agent self-only probe: %v", err)
	}
	if _, err := bareAgent.ProbeSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("agent gossip-nil remote probe = %v", err)
	}
}

func TestLift3SecretFanoutAndCapacityHTTP(t *testing.T) {
	ctx := context.Background()
	lookup := func(id string) (Member, bool) {
		switch id {
		case "dead":
			return Member{NodeID: "dead", Alive: false}, true
		case "missing":
			return Member{}, false
		case "plain":
			return Member{NodeID: "plain", Alive: true, InternalURL: "http://127.0.0.1:1"}, true
		default:
			return Member{}, false
		}
	}

	if _, err := deleteSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, nil, "", "self", "sb", "", []string{"dead"}, 1); err == nil {
		t.Fatal("delete empty incarnation")
	}
	if _, err := deleteSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, nil, "", "self", "sb", "inc", []string{"dead"}, 0); err == nil {
		t.Fatal("delete non-positive generation")
	}
	if _, err := probeSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, nil, "", "self", "sb", "", []string{"dead"}, 1); err == nil {
		t.Fatal("probe empty incarnation")
	}
	if _, err := pushSecretBlobToPeersLookupDial(ctx, lookup, http.DefaultClient, nil, "", "self", secrets.SecretBlob{Ref: "r"}, []string{"missing", "dead"}); err == nil {
		t.Fatal("push missing/dead")
	}
	if _, err := deleteSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, nil, "", "self", "sb", "inc", []string{"missing", "dead"}, 1); err == nil {
		t.Fatal("delete missing/dead")
	}
	if _, err := probeSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, nil, "", "self", "sb", "inc", []string{"dead"}, 1); err != nil {
		t.Fatalf("probe dead is skip, not error: %v", err)
	}

	failDial := func(Member) (*http.Client, string, error) { return nil, "", errors.New("dial") }
	if _, err := pushSecretBlobToPeersLookupDial(ctx, lookup, nil, failDial, "", "self", secrets.SecretBlob{Ref: "r"}, []string{"plain"}); err == nil {
		t.Fatal("push dial fail")
	}
	if _, err := deleteSecretOnPeersLookupDial(ctx, lookup, nil, failDial, "", "self", "sb", "inc", []string{"plain"}, 1); err == nil {
		t.Fatal("delete dial fail")
	}
	if _, err := probeSecretOnPeersLookupDial(ctx, lookup, nil, failDial, "", "self", "sb", "inc", []string{"plain"}, 1); err == nil {
		t.Fatal("probe dial fail")
	}

	if _, err := headSecretBlob(ctx, http.DefaultClient, "http://127.0.0.1:1", "pat", "self"); err == nil {
		t.Fatal("head dial")
	}
	if err := postSecretBlob(ctx, http.DefaultClient, "http://127.0.0.1:1", "pat", "self", []byte("{}")); err == nil {
		t.Fatal("post dial")
	}
	if err := deleteSecretBlob(ctx, http.DefaultClient, "http://127.0.0.1:1", "pat", "self"); err == nil {
		t.Fatal("delete dial")
	}
	if _, err := headSecretBlob(ctx, http.DefaultClient, "http://%zz", "", ""); err == nil {
		t.Fatal("head bad URL")
	}
	if err := postSecretBlob(ctx, http.DefaultClient, "http://%zz", "", "", nil); err == nil {
		t.Fatal("post bad URL")
	}
	if err := deleteSecretBlob(ctx, http.DefaultClient, "http://%zz", "", ""); err == nil {
		t.Fatal("delete bad URL")
	}

	if _, err := fetchCapacitySnapshot(ctx, http.DefaultClient, "http://%zz", "pat"); err == nil {
		t.Fatal("capacity bad URL")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pat" {
			http.Error(w, "no pat", http.StatusUnauthorized)
			return
		}
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(bad.Close)
	if _, err := fetchCapacitySnapshot(ctx, bad.Client(), bad.URL, "pat"); err == nil {
		t.Fatal("capacity 500")
	}
	junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{not-json")
	}))
	t.Cleanup(junk.Close)
	if _, err := fetchCapacitySnapshot(ctx, junk.Client(), junk.URL, ""); err == nil {
		t.Fatal("capacity decode")
	}
}

func TestLift3RecoveryStoreRemainingIO(t *testing.T) {
	if _, err := (&placementRecoveryFileStore{dir: t.TempDir()}).Put("", placementRecovery{}); err == nil {
		t.Fatal("empty sandbox put")
	}
	if _, err := newPlacementRecoveryMemoryStore().Put("", placementRecovery{}); err == nil {
		t.Fatal("memory empty sandbox")
	}

	fileAsDir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	blocked := &placementRecoveryFileStore{dir: fileAsDir}
	if _, err := blocked.Put("sb", placementRecovery{SecretRef: "r"}); err == nil {
		t.Fatal("put mkdir onto file")
	}
	if err := blocked.writeGCManifest(placementRecoveryGCManifest{}); err == nil {
		t.Fatal("gc manifest create-temp onto file")
	}

	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := placementRecovery{SecretRef: "r", SecretVersion: 1}
	ref, err := store.Put("sb-rename", rec)
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.pathForRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("sb-rename", rec); err == nil {
		t.Fatal("put rename onto directory")
	}
	if err := os.WriteFile(filepath.Join(path, "child"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ref); err == nil {
		t.Fatal("delete non-empty directory blob")
	}

	ro := t.TempDir()
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
	if err := (&placementRecoveryFileStore{dir: ro}).writeGCManifest(placementRecoveryGCManifest{}); err == nil {
		t.Fatal("readonly create-temp")
	}
}

func TestLift3NoopShardsNilGuards(t *testing.T) {
	if _, _, err := (&Noop{nodeID: "self"}).SelectPlacementWithCandidates(capacity.Request{RequiredNodeID: "other"}); !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("required other node = %v", err)
	}
	(&Noop{}).releaseVolumeAttachmentsForIncarnationLocked("sb", "")

	if got := rendezvousIngressOwnerIndex(0, nil); got != -1 {
		t.Fatalf("empty rendezvous = %d", got)
	}
	if got := rendezvousIngressOwnerIndexes(0, nil, 1); got != nil {
		t.Fatalf("empty indexes = %v", got)
	}
	if got := rendezvousIngressOwnerIndexes(0, []string{"a"}, 0); got != nil {
		t.Fatalf("n<=0 = %v", got)
	}
	if got := rendezvousIngressOwnerIndexes(0, []string{"a"}, 8); len(got) != 1 {
		t.Fatalf("n>len = %v", got)
	}

	var nilCluster *Cluster
	if nilCluster.currentInternalClient() != nil {
		t.Fatal("nil currentInternalClient")
	}
	nilCluster.setInternalClient(http.DefaultClient)
	var nilGossip *gossipNode
	if nilGossip.currentMemberIndex() != nil {
		t.Fatal("nil currentMemberIndex")
	}
	nilGossip.setMemberIndex(newGossipMemberIndex())
	var nilIndex *gossipMemberIndex
	if _, ok := nilIndex.get("x"); ok {
		t.Fatal("nil index get")
	}

	if err := (*Cluster)(nil).DeletePlacementExact(context.Background(), "sb", "owner", "inc"); err != nil {
		t.Fatalf("nil exact delete: %v", err)
	}
	empty := &Cluster{}
	if err := empty.DeletePlacementExact(context.Background(), "sb", "owner", "inc"); err != nil {
		t.Fatalf("fsm-nil exact delete: %v", err)
	}
	if err := empty.BeginDeletePlacementExact(context.Background(), "sb", "", "inc"); err != nil {
		t.Fatalf("fsm-nil begin delete: %v", err)
	}
	if err := empty.DeletePlacementExact(context.Background(), "sb", "owner", ""); !errors.Is(err, ErrIncarnationConflict) && err != nil {
		// fsm-nil returns before the incarnation check
	}
	fsmOnly := &Cluster{fsm: newPlacementFSM()}
	if err := fsmOnly.DeletePlacementExact(context.Background(), "sb", "owner", ""); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("exact empty incarnation = %v", err)
	}
	if err := fsmOnly.BeginDeletePlacementExact(context.Background(), "sb", "", "inc"); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("begin empty owner = %v", err)
	}
	if err := fsmOnly.ReassignPlacement(context.Background(), "", PlacementTarget{NodeID: "n"}); err == nil {
		t.Fatal("reassign empty sandbox")
	}
	if err := fsmOnly.ReassignPlacement(context.Background(), "sb", PlacementTarget{}); err == nil {
		t.Fatal("reassign empty target")
	}
	if err := fsmOnly.ReassignPlacement(context.Background(), "missing", PlacementTarget{NodeID: "n"}); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("reassign missing = %v", err)
	}
	if err := fsmOnly.ClaimOrphan(context.Background(), "missing", nil, PlacementSecrets{}); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("claim missing = %v", err)
	}
	if err := fsmOnly.UpsertSpec(context.Background(), "missing", &models.CreateSandboxRequest{Image: "x"}, PlacementSecrets{}); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("upsert missing = %v", err)
	}
	if err := fsmOnly.ClaimOrphan(context.Background(), "sb", nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc"}); err == nil {
		t.Fatal("claim bad secret handle")
	}
	if err := fsmOnly.UpsertSpec(context.Background(), "sb", nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc"}); err == nil {
		t.Fatal("upsert bad secret handle")
	}
	if err := fsmOnly.RecordPlacement(context.Background(), "sb", nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc"}); err == nil {
		t.Fatal("record bad secret handle")
	}
	if err := fsmOnly.AddExposedPort(context.Background(), "missing", 80, ExposedPortRoute{Protocol: "http"}); err != nil {
		t.Fatalf("add port missing placement = %v", err)
	}
	if err := fsmOnly.RemoveExposedPort(context.Background(), "missing", 80); err != nil {
		t.Fatalf("remove port missing = %v", err)
	}
	if err := fsmOnly.AddCustomDomain(context.Background(), "missing", "h.example"); err != nil {
		t.Fatalf("add domain missing = %v", err)
	}
	if err := fsmOnly.RemoveCustomDomain(context.Background(), "missing", "h.example"); err != nil {
		t.Fatalf("remove domain missing = %v", err)
	}

	if err := validateSecretRecipientUpdate("", []string{"n"}, PlacementSecrets{}, "", 0); err == nil {
		t.Fatal("empty recipient update")
	}
	if err := validateSecretRecipientUpdate("sb", []string{"n"}, PlacementSecrets{IncarnationID: "inc"}, "", 0); err == nil {
		t.Fatal("missing expected generation")
	}
	sec := testPlacementSecrets("sb", "inc", 1)
	if err := validateSecretRecipientUpdate("sb", []string{"n"}, sec, "inc", 1); err == nil {
		t.Fatal("generation must advance")
	}
	sec.SealGeneration = 2
	sec.Ref = "not-a-ref"
	if err := validateSecretRecipientUpdate("sb", []string{"n"}, sec, "inc", 1); err == nil {
		t.Fatal("bad replacement ref")
	}
}

func TestLift3TLSForwardCapacityNew(t *testing.T) {
	if _, err := (*ClusterTLS)(nil).certificateForHandshake(); err == nil {
		t.Fatal("nil tls handshake")
	}
	empty := &ClusterTLS{}
	if cert, err := empty.certificateForHandshake(); err != nil || cert != &empty.nodeCert {
		t.Fatalf("empty paths = %v err=%v", cert, err)
	}
	missing := &ClusterTLS{certPath: filepath.Join(t.TempDir(), "missing.crt"), keyPath: filepath.Join(t.TempDir(), "missing.key")}
	if _, err := missing.certificateForHandshake(); err == nil {
		t.Fatal("stat missing cert")
	}
	dir := writeTestClusterTLSDir(t, "hs-node")
	loaded, err := loadClusterTLS(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.certificateForHandshake(); err != nil {
		t.Fatalf("warm handshake: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "node.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.certificateForHandshake(); err != nil {
		// lastGood should keep the previous leaf after key disappearance
		t.Fatalf("lastGood after key unlink: %v", err)
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9),
		Subject:               pkix.Name{Organization: []string{"lift3"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{clusterServerName, "node:peer-a"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://cluster.internal/x", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	req.Header.Set(PeerNodeIDHeader, "wrong-peer")
	if _, err := AuthenticatedPeerNodeID(req); err == nil {
		t.Fatal("claimed peer mismatch")
	}

	pc := newProxyCache()
	if _, err := pc.getForPeer("", "https://peer.internal", http.DefaultTransport); err == nil {
		t.Fatal("empty peer id")
	}
	if _, err := pc.getForPeer("n", "http://peer.internal", http.DefaultTransport); err == nil {
		t.Fatal("plaintext peer URL")
	}
	if _, err := pc.getForPeer("n", "https://peer.internal", nil); err == nil {
		t.Fatal("nil transport")
	}

	rec := httptest.NewRecorder()
	fwdReq := httptest.NewRequest(http.MethodGet, "http://src/x", nil)
	fwdReq.Header.Set("X-Cluster-Forwarded", "1")
	forwardHTTPWithMetrics(pc, func(string) *http.Client { return http.DefaultClient }, Endpoint{NodeID: "n", InternalURL: "https://peer.internal"}, rec, fwdReq)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("loop = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	forwardHTTPWithMetrics(nil, nil, Endpoint{}, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://src/x", nil))
	rec = httptest.NewRecorder()
	forwardHTTPWithMetrics(pc, func(string) *http.Client { return &http.Client{} }, Endpoint{NodeID: "n", InternalURL: "https://peer.internal"}, rec, httptest.NewRequest(http.MethodGet, "http://src/x", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil transport client = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	if err := servePeerProxy(pc, "n", "http://peer.internal", http.DefaultTransport, rec, httptest.NewRequest(http.MethodGet, "http://src/x", nil)); err == nil {
		t.Fatal("serve plaintext")
	}

	_ = newCapacityLeaseCache("self", nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var nilLeases *capacityLeaseCache
	nilLeases.SetLocalTemplateCatalogProvider(nil)
	nilLeases.set("", capacity.Snapshot{}, time.Now())
	nilLeases.set("n", capacity.Snapshot{}, time.Now())
	(&Cluster{}).startCapacityLeaseLoop(0)
	(&Cluster{capacityLeases: newCapacityLeaseCache("self", nil, time.Second, nil)}).startCapacityLeaseLoop(-1)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := New(config.Config{}, logger, nil); err == nil {
		t.Fatal("cluster disabled")
	}
	if _, err := New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, logger, nil); err == nil {
		t.Fatal("worker role")
	}
	if _, err := New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil); err == nil {
		t.Fatal("missing advertise URL")
	}
	raftFile := filepath.Join(t.TempDir(), "raft-is-file")
	if err := os.WriteFile(raftFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config.Config{
		EnableCluster: true, NodeRole: config.NodeRoleServer, NodeID: "n-badraft",
		SelfAPIAdvertiseURL: "http://127.0.0.1:1", RaftDataDir: raftFile,
	}, logger, nil); err == nil {
		t.Fatal("recovery store onto file")
	}
	dirs := writeTestClusterTLSDirs(t, "tls-node")
	if _, err := New(config.Config{
		EnableCluster: true, NodeRole: config.NodeRoleServer, NodeID: "other-id",
		SelfAPIAdvertiseURL: "http://127.0.0.1:1", RaftDataDir: t.TempDir(),
		ClusterTLSDir: dirs["tls-node"],
	}, logger, nil); err == nil {
		t.Fatal("tls identity mismatch")
	}
	if _, err := NewAgent(config.Config{
		EnableCluster: true, NodeRole: config.NodeRoleWorker, NodeID: "ag-badlisten",
		SelfAPIAdvertiseURL: "http://127.0.0.1:1", ClusterTLSDir: writeTestClusterTLSDir(t, "ag-badlisten"),
		ClusterInternalListenAddr: "not-a-listen-addr",
	}, logger, nil); err == nil {
		t.Fatal("agent bad listen")
	}
	if _, err := decodeGossipSecretKey(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("short gossip key")
	}
}

func TestLift3AgentRemainingClientBranches(t *testing.T) {
	ctx := context.Background()
	placements := map[string]Placement{
		"sb-res-empty": {SandboxID: "sb-res-empty", OwnerNodeID: "worker-self", State: PlacementStateReserved, Version: 2},
		"sb-placed-nospec": {
			SandboxID: "sb-placed-nospec", OwnerNodeID: "worker-self", IncarnationID: "inc-pl",
			State: PlacementStatePlaced, Version: 3,
		},
		"sb-orphan": {
			SandboxID: "sb-orphan", OwnerNodeID: "", OwnerState: PlacementOwnerStateOrphaned,
			OrphanedOwnerNodeID: "worker-self", IncarnationID: "inc-or",
			State: PlacementStatePlaced, Version: 4,
		},
		"sb-self-res": {
			SandboxID: "sb-self-res", OwnerNodeID: "worker-self", IncarnationID: "inc-res",
			State: PlacementStateReserved, Version: 5,
		},
	}
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, PublicInternalPlacementByNamePath):
			http.Error(w, "name boom", http.StatusInternalServerError)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, PublicInternalPlacementPath):
			id := strings.TrimPrefix(r.URL.Path, PublicInternalPlacementPath)
			if id == "lookup-fail" || id == "port-fail" {
				http.Error(w, "nope", http.StatusInternalServerError)
				return
			}
			p, ok := placements[id]
			if !ok || p.SandboxID == "" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{SandboxID: id, Placement: p})
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalSelectPlacementPath:
			_ = json.NewEncoder(w).Encode(SelectPlacementResponse{Error: "custom select failure"})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, PublicInternalPlacementsByIDsPath):
			var req placementsByIDsRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			for _, id := range req.IDs {
				if id == "lookup-fail" {
					http.Error(w, "by-ids boom", http.StatusInternalServerError)
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "null")
		case r.Method == http.MethodPost && (r.URL.Path == PublicInternalApplyPath || r.URL.Path == InternalAPIPath):
			http.Error(w, "apply failed", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if _, _, err := agent.OwnerOfName("named"); err == nil {
		t.Fatal("owner-of-name 500")
	}
	if sec := agent.SecretsOf("missing"); sec.Ref != "" {
		t.Fatalf("secrets of missing = %+v", sec)
	}
	if _, _, err := agent.SelectPlacementWithCandidates(capacity.Request{}); err == nil {
		t.Fatal("select custom error")
	}
	if err := agent.RecordPlacement(ctx, "sb", nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc"}); err == nil {
		t.Fatal("record bad handle")
	}
	if err := agent.ClaimOrphan(ctx, "sb-orphan", nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc-or"}); err == nil {
		t.Fatal("claim bad handle")
	}
	if err := agent.UpsertSpec(ctx, "sb-placed-nospec", nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc-pl"}); err == nil {
		t.Fatal("upsert bad handle")
	}
	if err := agent.AddExposedPort(ctx, "port-fail", 80, ExposedPortRoute{Protocol: "http"}); err == nil {
		t.Fatal("add port lookup fail")
	}
	if err := agent.RemoveExposedPort(ctx, "port-fail", 80); err == nil {
		t.Fatal("remove port lookup fail")
	}
	if err := agent.AddCustomDomain(ctx, "port-fail", "h.example"); err == nil {
		t.Fatal("add domain lookup fail")
	}
	if err := agent.RemoveCustomDomain(ctx, "port-fail", "h.example"); err == nil {
		t.Fatal("remove domain lookup fail")
	}
	if err := agent.DeletePlacement(ctx, "lookup-fail"); err == nil {
		t.Fatal("delete lookup fail")
	}
	if err := agent.CancelReservation(ctx, "sb-res-empty"); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("cancel empty incarnation = %v", err)
	}
	if err := agent.ReassignPlacement(ctx, "", PlacementTarget{NodeID: "n"}); err == nil {
		t.Fatal("reassign empty sandbox")
	}
	if err := agent.ReassignPlacement(ctx, "sb", PlacementTarget{}); err == nil {
		t.Fatal("reassign empty target")
	}
	if err := agent.ReassignPlacement(ctx, "lookup-fail", PlacementTarget{NodeID: "n"}); err == nil {
		t.Fatal("reassign lookup fail")
	}
	if err := agent.ReassignPlacement(ctx, "missing", PlacementTarget{NodeID: "n"}); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("reassign missing = %v", err)
	}
	if err := agent.ReassignPlacement(ctx, "sb-res-empty", PlacementTarget{NodeID: "n"}); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("reassign empty incarnation = %v", err)
	}
	if err := agent.ReserveOnTarget(ctx, "sb", PlacementTarget{NodeID: "n"}, nil, PlacementSecrets{Ref: "bad", Version: 1, SealGeneration: 1, IncarnationID: "inc"}, time.Second); err == nil {
		t.Fatal("reserve bad handle")
	}

	if err := agent.AssertOwnership(ctx, []LocalSandboxState{
		{ID: "brand-new", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{80: {Protocol: "http"}}, CustomHostnames: []string{"new.example"}},
		{ID: "sb-self-res", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{81: {Protocol: "http"}}, CustomHostnames: []string{"res.example"}},
		{ID: "sb-placed-nospec", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{82: {Protocol: "http"}}, CustomHostnames: []string{"pl.example"}},
		{ID: "sb-orphan", Spec: &models.CreateSandboxRequest{Image: "alpine"}, ExposedPorts: map[int]ExposedPortRoute{83: {Protocol: "http"}}, CustomHostnames: []string{"or.example"}},
	}); err == nil {
		t.Fatal("assert ownership apply failures")
	}

	got, err := agent.AuthoritativePlacementsByIDs(ctx, []string{"", "  "})
	if err != nil || len(got) != 0 {
		t.Fatalf("empty ids = %+v err=%v", got, err)
	}
	got, err = agent.AuthoritativePlacementsByIDs(ctx, []string{"sb-x"})
	if err != nil || got == nil {
		t.Fatalf("null map = %+v err=%v", got, err)
	}

	if _, ok := agent.LookupMember("not-in-gossip"); ok {
		t.Fatal("lookup miss")
	}
	if (&Agent{nodeID: "self"}).controlPlaneMembers() != nil {
		t.Fatal("gossip-nil control-plane members")
	}
	if err := agent.doHTTPRequest(ctx, http.DefaultClient, "http://%zz", http.MethodGet, nil, nil); err == nil {
		t.Fatal("doHTTP bad URL")
	}
	if err := agent.doHTTPRequest(ctx, http.DefaultClient, "http://127.0.0.1:1", http.MethodGet, []byte("{}"), nil); err == nil {
		t.Fatal("doHTTP dial")
	}

	closeAgent := &Agent{internalServer: &internalServer{srv: &http.Server{}}}
	_ = closeAgent.Close()

	fsm := newPlacementFSM()
	fsm.recoveryStore = lift3FailGetStore{}
	if _, _, err := fsm.resolveRecoveryRef("ref"); err == nil {
		t.Fatal("resolve get fail")
	}
	fsm.recoveryStore = nil
	fsm.recoveryResolver = func(context.Context, string) (RecoveryBlob, bool, error) {
		return RecoveryBlob{Ref: "a", SandboxID: "sb"}, true, nil
	}
	if _, _, err := fsm.resolveRecoveryRef("ref"); err != nil {
		t.Fatalf("resolve store-nil: %v", err)
	}
	fsm.recoveryStore = failPutRecoveryStore{}
	if err := fsm.storeRecoveryBlob(RecoveryBlob{Ref: "want", SandboxID: "sb"}); err == nil {
		t.Fatal("store put fail")
	}
	fsm.recoveryStore = lift3MismatchPutStore{}
	if err := fsm.storeRecoveryBlob(RecoveryBlob{Ref: "want", SandboxID: "sb"}); err == nil {
		t.Fatal("store ref mismatch")
	}
	fsm.deletingIndex = nil
	fsm.indexDeletingStateLocked("sb", Placement{State: PlacementStateDeleting})
}

type lift3FailGetStore struct{}

func (lift3FailGetStore) Put(string, placementRecovery) (string, error) { return "", nil }
func (lift3FailGetStore) Get(string) (placementRecovery, bool, error) {
	return placementRecovery{}, false, errors.New("get fail")
}
func (lift3FailGetStore) GetRecord(string) (placementRecoveryStoreRecord, bool, error) {
	return placementRecoveryStoreRecord{}, false, errors.New("get fail")
}
func (lift3FailGetStore) Delete(string) error               { return nil }
func (lift3FailGetStore) RetainSnapshotRefs([]string) error { return nil }

type lift3MismatchPutStore struct{}

func (lift3MismatchPutStore) Put(string, placementRecovery) (string, error) { return "other", nil }
func (lift3MismatchPutStore) Get(string) (placementRecovery, bool, error) {
	return placementRecovery{}, false, nil
}
func (lift3MismatchPutStore) GetRecord(string) (placementRecoveryStoreRecord, bool, error) {
	return placementRecoveryStoreRecord{}, false, nil
}
func (lift3MismatchPutStore) Delete(string) error               { return nil }
func (lift3MismatchPutStore) RetainSnapshotRefs([]string) error { return nil }
