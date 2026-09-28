package v1

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
)

// POST /v1/sandboxes must reach the bounded placement selector, never the
// candidate-returning one.
//
// On an agent-role node (every ingress and worker) SelectPlacementWithCandidates
// is a control-plane RPC whose response carries one Member per eligible worker:
// ~850 bytes each, so ~1.7 MB per create at 2,000 nodes — paid even when the
// candidates are discarded, because the call sat ahead of the secret-fanout
// check. SelectPlacementForCreate returns the handful of recipient IDs instead
// and keeps a create's answer O(1) in fleet size.
//
// This regression survived an earlier fix because native v1 kept its own copy
// of the create flow while the facades moved to the shared one. The assertion
// is on the call, not the byte count, so a future re-fork fails here.
func TestClusterCreateUsesBoundedPlacementSelector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, tc := range []struct {
		name string
		cfg  config.Config
	}{
		{"secret fanout off", config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}},
		{
			"secret fanout on",
			config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer, SecretRecipientBackupCount: 2},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := service.New(tc.cfg, logger, nil, nil, nil, nil, nil, nil, nil)
			fake := &createForwardCluster{
				Noop:   cluster.NewNoop("server-a", "http://server-a", ""),
				target: cluster.PlacementTarget{NodeID: "worker-b", APIURL: "http://worker-b", InternalURL: "https://worker-b", IsSelf: false},
				members: []cluster.Member{
					{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer},
					{NodeID: "worker-b", APIURL: "http://worker-b", Alive: true, Role: config.NodeRoleWorker},
					{NodeID: "worker-c", APIURL: "http://worker-c", Alive: true, Role: config.NodeRoleWorker},
				},
			}
			svc.AttachCluster(fake)
			h := &handlers{deps: Deps{Service: svc, Logger: logger}}

			rr := httptest.NewRecorder()
			h.clusterCreateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`)))

			if fake.selectPlacementHit != 0 {
				t.Fatalf("create called SelectPlacementWithCandidates %d times; it ships one Member per eligible worker (~1.7 MB at 2k nodes)", fake.selectPlacementHit)
			}
			if fake.selectForCreateHit != 1 {
				t.Fatalf("create called SelectPlacementForCreate %d times, want exactly 1", fake.selectForCreateHit)
			}
			if fake.forwardedTarget != "worker-b" {
				t.Fatalf("forwarded target = %q, want worker-b", fake.forwardedTarget)
			}
		})
	}
}

// The reservation the router writes must carry the recipient set the control
// plane chose, so the create target seals to that set instead of recomputing it
// from a candidate list it should never have received.
func TestClusterCreateReservesWithControlPlaneChosenRecipients(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{
		EnableCluster:              true,
		NodeRole:                   config.NodeRoleServer,
		SecretRecipientBackupCount: 2,
	}, logger, nil, nil, nil, nil, nil, nil, nil)
	fake := &createForwardCluster{
		Noop:   cluster.NewNoop("server-a", "http://server-a", ""),
		target: cluster.PlacementTarget{NodeID: "worker-b", APIURL: "http://worker-b", InternalURL: "https://worker-b"},
		members: []cluster.Member{
			{NodeID: "worker-b", APIURL: "http://worker-b", Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "worker-c", APIURL: "http://worker-c", Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "worker-d", APIURL: "http://worker-d", Alive: true, Role: config.NodeRoleWorker},
		},
	}
	svc.AttachCluster(fake)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, httptest.NewRequest(http.MethodPost,
		"/v1/sandboxes", strings.NewReader(`{"image":"alpine","env":{"API_KEY":"s3cr3t"},"failover":{"policy":"recreate"}}`)))

	if len(fake.reserveCalls) != 1 {
		t.Fatalf("reserve calls = %d, want 1", len(fake.reserveCalls))
	}
	got := fake.reserveCalls[0].secrets.Recipients
	if len(got) == 0 {
		t.Fatal("reservation recorded no secret recipients; the target would have to recompute the seal set")
	}
	// Bounded: owner plus the configured backups, never the whole fleet.
	if len(got) > 1+svc.SecretRecipientBackupCount() {
		t.Fatalf("reservation recorded %d recipients (%v), want at most owner+%d",
			len(got), got, svc.SecretRecipientBackupCount())
	}
	for _, id := range got {
		if strings.TrimSpace(id) == "" {
			t.Fatalf("reservation recorded a blank recipient in %v", got)
		}
	}
}
