package cluster

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/hashicorp/raft"
)

func TestNoopAdditionalMethods(t *testing.T) {
	n := NewNoop("", "http://localhost:21212")
	if n.SelfNodeID() != "standalone" {
		t.Fatalf("SelfNodeID() = %q, want standalone", n.SelfNodeID())
	}
	if n.SelfAPIURL() != "http://localhost:21212" {
		t.Fatalf("SelfAPIURL() = %q", n.SelfAPIURL())
	}
	if _, _, err := n.OwnerOfName("demo"); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("OwnerOfName() error = %v, want ErrUnknownSandbox", err)
	}
	if n.SpecOf("demo") != nil {
		t.Fatal("SpecOf() should be nil in single-node mode")
	}
	if got := n.SecretsOf("demo"); got.Ref != "" || got.Version != 0 || len(got.LegacySealed) != 0 {
		t.Fatalf("SecretsOf() = %+v, want zero value", got)
	}
	if got := n.SealedSecretsOf("demo"); got != nil {
		t.Fatalf("SealedSecretsOf() = %v, want nil", got)
	}
	if err := n.AddExposedPort(context.Background(), "demo", 8080, ExposedPortRoute{Protocol: "http"}); err != nil {
		t.Fatalf("AddExposedPort() error = %v", err)
	}
	if err := n.RemoveExposedPort(context.Background(), "demo", 8080); err != nil {
		t.Fatalf("RemoveExposedPort() error = %v", err)
	}
	if got := n.ExposedPortsOf("demo"); got != nil {
		t.Fatalf("ExposedPortsOf() = %v, want nil", got)
	}
	if err := n.ReserveOnTarget(context.Background(), "demo", PlacementTarget{}, nil, PlacementSecrets{}, time.Second); err != nil {
		t.Fatalf("ReserveOnTarget() error = %v", err)
	}
	if err := n.CancelReservation(context.Background(), "demo"); err != nil {
		t.Fatalf("CancelReservation() error = %v", err)
	}
	if err := n.SetNodeDrainState(context.Background(), "node-a", true); err != nil {
		t.Fatalf("SetNodeDrainState() error = %v", err)
	}
	if err := n.RemoveMember(context.Background(), "missing", false); !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("RemoveMember() error = %v, want ErrUnknownMember", err)
	}
	if n.IsNodeDrained("node-a") {
		t.Fatal("IsNodeDrained() should be false in single-node mode")
	}
	if err := n.ApplyEncoded(context.Background(), []byte("payload")); err != nil {
		t.Fatalf("ApplyEncoded() error = %v", err)
	}
	n.AttachInternalHandler(http.NotFoundHandler())
	if got := n.Placements(); got != nil {
		t.Fatalf("Placements() = %v, want nil", got)
	}
	if got := n.PlacementsForShards(PlacementShardFilter{}); got != nil {
		t.Fatalf("PlacementsForShards() = %v, want nil", got)
	}
	if got := n.PlacementPage(PlacementPageRequest{}); len(got.Placements) != 0 || got.NextPageToken != "" {
		t.Fatalf("PlacementPage() = %+v, want zero value fields", got)
	}
	if placement, ok := n.PlacementOf("demo"); ok || placement.SandboxID != "" || placement.OwnerNodeID != "" || placement.Version != 0 {
		t.Fatalf("PlacementOf() = (%+v, %v), want zero placement and false", placement, ok)
	}
	if got := n.PlacementVersion(); got != 0 {
		t.Fatalf("PlacementVersion() = %d, want 0", got)
	}
	if got := n.SubscribePlacement(context.Background()); got != nil {
		t.Fatalf("SubscribePlacement() = %v, want nil", got)
	}
	if got, err := n.SelectPlacement(capacity.Request{CPU: 1}); err != nil || got.NodeID == "" {
		t.Fatal("SelectPlacement() should still return self target metadata")
	}
}

func TestDecodeGossipSecretKeyAndAdvertiseHelpers(t *testing.T) {
	if key, err := decodeGossipSecretKey(""); err != nil || key != nil {
		t.Fatalf("decode empty key = (%v, %v), want (nil, nil)", key, err)
	}
	if _, err := decodeGossipSecretKey("not-base64"); err == nil {
		t.Fatal("decodeGossipSecretKey() accepted invalid base64")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	if key, err := decodeGossipSecretKey(encoded); err != nil || len(key) != 16 {
		t.Fatalf("decodeGossipSecretKey() = (%d bytes, %v), want 16-byte key", len(key), err)
	}

	if got := deriveInternalAdvertiseURL("https://node.example/internal/", ":9443", "0.0.0.0:9443"); got != "https://node.example/internal" {
		t.Fatalf("operator advertise URL = %q, want operator override without trailing slash", got)
	}
	if got := deriveInternalAdvertiseURL("", "192.0.2.4:9443", "0.0.0.0:9443"); got != "https://192.0.2.4:9443" {
		t.Fatalf("derived advertise URL = %q, want listen host fallback", got)
	}
	if got := deriveInternalAdvertiseURL("", ":9443", "[::]:9443"); got != "https://127.0.0.1:9443" {
		t.Fatalf("derived wildcard advertise URL = %q, want loopback fallback", got)
	}

	if host, port := splitHostForAdvertise("127.0.0.1:9443"); host != "127.0.0.1" || port != "9443" {
		t.Fatalf("splitHostForAdvertise() = (%q,%q), want (127.0.0.1,9443)", host, port)
	}
	if host, port := splitHostForAdvertise("example.internal"); host != "example.internal" || port != "" {
		t.Fatalf("splitHostForAdvertise() = (%q,%q), want (example.internal,'')", host, port)
	}
	if !isUnspecifiedHost("0.0.0.0") || !isUnspecifiedHost("[::]") || isUnspecifiedHost("192.0.2.4") {
		t.Fatal("isUnspecifiedHost() did not classify hosts correctly")
	}
	if (&Cluster{}).HealthyForReads() {
		t.Fatal("zero-value Cluster should not report HealthyForReads")
	}
}

func TestExposedPortRoutesForPlacementCoversBothShapes(t *testing.T) {
	routes := ExposedPortRoutesForPlacement(Placement{
		ExposedPortRoutes: map[int]ExposedPortRoute{5432: {Protocol: "tcp", HostPort: 22432, PublicURL: "tcp://sandbox.example.com:22432"}},
	})
	if routes[5432].HostPort != 22432 {
		t.Fatalf("route metadata = %+v, want host port preserved", routes[5432])
	}
	routes[5432] = ExposedPortRoute{Protocol: "http"}
	legacy := ExposedPortRoutesForPlacement(Placement{ExposedPorts: map[int]string{8080: "http"}})
	if legacy[8080].Protocol != "http" || legacy[8080].HostPort != 0 {
		t.Fatalf("legacy route = %+v, want protocol-only route", legacy[8080])
	}
	if got := ExposedPortRoutesForPlacement(Placement{}); got != nil {
		t.Fatalf("empty placement routes = %v, want nil", got)
	}
}

func TestClusterMetricHelpersAdditional(t *testing.T) {
	forwardBefore := raftLeaderForward.Value()
	forwardErrBefore := expvarMapValue(raftLeaderForwardErrs, "reservation_conflict")
	snapshotBefore := raftSnapshotTotal.Value()
	snapshotErrBefore := expvarMapValue(raftSnapshotErrors, "timeout")
	restoreBefore := raftSnapshotRestore.Value()
	restoreErrBefore := expvarMapValue(raftSnapshotRestoreErrs, "decode")
	targetMissBefore := expvarMapValue(ownerForwardTargetMisses, "target_unknown")
	expiredBefore := clusterReservationsExpired.Value()

	done := beginLeaderForwardApply()
	done(ErrReservationConflict)
	recordSnapshotPersist(5*time.Millisecond, 1234, 5, context.DeadlineExceeded)
	recordSnapshotRestore(3*time.Millisecond, errors.New("decode failure"))
	recordOwnerForwardTargetMiss("target_unknown")
	recordExpiredReservation()

	if got := raftLeaderForward.Value() - forwardBefore; got != 1 {
		t.Fatalf("leader forward delta = %d, want 1", got)
	}
	if got := expvarMapValue(raftLeaderForwardErrs, "reservation_conflict") - forwardErrBefore; got != 1 {
		t.Fatalf("leader forward error delta = %d, want 1", got)
	}
	if got := raftSnapshotTotal.Value() - snapshotBefore; got != 1 {
		t.Fatalf("snapshot persist delta = %d, want 1", got)
	}
	if got := expvarMapValue(raftSnapshotErrors, "timeout") - snapshotErrBefore; got != 1 {
		t.Fatalf("snapshot timeout delta = %d, want 1", got)
	}
	if got := raftSnapshotRestore.Value() - restoreBefore; got != 1 {
		t.Fatalf("snapshot restore delta = %d, want 1", got)
	}
	if got := expvarMapValue(raftSnapshotRestoreErrs, "decode") - restoreErrBefore; got != 1 {
		t.Fatalf("snapshot restore decode delta = %d, want 1", got)
	}
	if got := expvarMapValue(ownerForwardTargetMisses, "target_unknown") - targetMissBefore; got != 1 {
		t.Fatalf("owner forward target miss delta = %d, want 1", got)
	}
	if got := clusterReservationsExpired.Value() - expiredBefore; got != 1 {
		t.Fatalf("expired reservation delta = %d, want 1", got)
	}
	if got := classifyClusterMetricError(errors.New("forwarding loop detected")); got != "stale_owner" {
		t.Fatalf("stale owner classification = %q, want stale_owner", got)
	}
	if got := classifyClusterMetricError(errors.New("peer API URL unknown")); got != "target_unknown" {
		t.Fatalf("target unknown classification = %q, want target_unknown", got)
	}
}

func TestTLSStreamLayerDialAcceptAndClose(t *testing.T) {
	cert := mustSelfSignedCert(t)
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	clientCfg := &tls.Config{InsecureSkipVerify: true}
	advertise := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9443}

	layer, err := newTLSStreamLayer("127.0.0.1:0", advertise, serverCfg, clientCfg)
	if err != nil {
		t.Fatalf("newTLSStreamLayer() error = %v", err)
	}
	defer layer.Close()

	acceptErr := make(chan error, 1)
	go func() {
		conn, err := layer.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		defer conn.Close()
		if tlsConn, ok := conn.(*tls.Conn); ok {
			acceptErr <- tlsConn.Handshake()
			return
		}
		acceptErr <- nil
	}()

	conn, err := layer.Dial(raft.ServerAddress(layer.listener.Addr().String()), time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	conn.Close()
	if err := <-acceptErr; err != nil {
		t.Fatalf("Accept()/Handshake error = %v", err)
	}
	if layer.Addr().String() != advertise.String() {
		t.Fatalf("Addr() = %q, want %q", layer.Addr(), advertise)
	}
	if err := layer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNewTLSStreamLayerRequiresConfigs(t *testing.T) {
	if _, err := newTLSStreamLayer("127.0.0.1:0", &net.TCPAddr{}, nil, &tls.Config{}); err == nil {
		t.Fatal("newTLSStreamLayer() accepted nil server config")
	}
	if _, err := newTLSStreamLayer("127.0.0.1:0", &net.TCPAddr{}, &tls.Config{}, nil); err == nil {
		t.Fatal("newTLSStreamLayer() accepted nil client config")
	}
}

func mustSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert
}
