package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	secretspkg "github.com/aerol-ai/microvm/pkg/secrets"
	"github.com/hashicorp/raft"
)

// cov96FwdSetSelfInternalURL rewrites the InternalURL this node gossips for
// itself. On a single-voter cluster the leader is self, so this is the URL
// forwardArtifactCatalogEpochToLeader dials.
func cov96FwdSetSelfInternalURL(c *Cluster, url string) {
	c.gossip.delegate.mu.Lock()
	c.gossip.delegate.selfMeta.InternalURL = url
	c.gossip.delegate.mu.Unlock()
	c.gossip.refreshMemberIndex()
}

func TestCov96ForwardArtifactEpochNoLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "cov96-fwd-noleader", false, nil)
	defer cleanup()

	_, err := c.forwardArtifactCatalogEpochToLeader(context.Background(), "templates", c.nodeID, "holder")
	if !errors.Is(err, ErrNotLeader) {
		t.Fatalf("no leader: err = %v, want ErrNotLeader", err)
	}
}

func TestCov96ForwardArtifactEpochToLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "cov96-fwd-leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	var (
		mu      sync.Mutex
		handler http.HandlerFunc
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		h := handler
		mu.Unlock()
		h(w, r)
	}))
	defer srv.Close()

	c.patToken = "cov96-pat"
	c.setInternalClient(&http.Client{})
	c.invalidatePeerClient(c.nodeID)
	cov96FwdSetSelfInternalURL(c, srv.URL+"/")

	ctx := context.Background()

	t.Run("peer allocation is refused", func(t *testing.T) {
		_, err := c.forwardArtifactCatalogEpochToLeader(ctx, "templates", "some-other-node", "holder")
		if !errors.Is(err, ErrNotLeader) {
			t.Fatalf("err = %v, want ErrNotLeader", err)
		}
	})

	t.Run("missing internal client", func(t *testing.T) {
		c.setInternalClient(nil)
		defer c.setInternalClient(&http.Client{})
		_, err := c.forwardArtifactCatalogEpochToLeader(ctx, "templates", c.nodeID, "holder")
		if !errors.Is(err, ErrPeerInternalURLRequired) {
			t.Fatalf("err = %v, want ErrPeerInternalURLRequired", err)
		}
	})

	t.Run("leader advertises no internal url", func(t *testing.T) {
		cov96FwdSetSelfInternalURL(c, "")
		defer cov96FwdSetSelfInternalURL(c, srv.URL+"/")
		_, err := c.forwardArtifactCatalogEpochToLeader(ctx, "templates", c.nodeID, "holder")
		if !errors.Is(err, ErrPeerInternalURLRequired) {
			t.Fatalf("err = %v, want ErrPeerInternalURLRequired", err)
		}
	})

	t.Run("unparseable internal url", func(t *testing.T) {
		cov96FwdSetSelfInternalURL(c, "http://bad\x7fhost")
		defer cov96FwdSetSelfInternalURL(c, srv.URL+"/")
		_, err := c.forwardArtifactCatalogEpochToLeader(ctx, "templates", c.nodeID, "holder")
		if err == nil || !strings.Contains(err.Error(), "build artifact catalogue epoch allocation") {
			t.Fatalf("err = %v, want build error", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		dead := httptest.NewServer(http.NotFoundHandler())
		deadURL := dead.URL
		dead.Close()
		cov96FwdSetSelfInternalURL(c, deadURL)
		defer cov96FwdSetSelfInternalURL(c, srv.URL+"/")
		_, err := c.forwardArtifactCatalogEpochToLeader(ctx, "templates", c.nodeID, "holder")
		if err == nil || !strings.Contains(err.Error(), "cluster: artifact catalogue epoch allocation:") {
			t.Fatalf("err = %v, want transport error", err)
		}
	})

	cases := []struct {
		name      string
		status    int
		body      string
		wantEpoch int64
		wantIs    error
		wantSub   string
	}{
		{name: "503 means not leader", status: http.StatusServiceUnavailable, body: "not leader", wantIs: ErrNotLeader},
		{name: "non-200 carries body", status: http.StatusForbidden, body: "  denied by policy \n", wantSub: "status 403: denied by policy"},
		{name: "undecodable body", status: http.StatusOK, body: "not-json", wantSub: "decode artifact catalogue epoch allocation"},
		{name: "zero epoch", status: http.StatusOK, body: `{"epoch":0}`, wantSub: "returned no token"},
		{name: "valid epoch", status: http.StatusOK, body: `{"epoch":42}`, wantEpoch: 42},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got ArtifactCatalogEpochRequest
			var gotPath, gotMethod, gotAuth, gotPeer, gotType string
			mu.Lock()
			handler = func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotMethod = r.URL.Path, r.Method
				gotAuth = r.Header.Get("Authorization")
				gotPeer = r.Header.Get(PeerNodeIDHeader)
				gotType = r.Header.Get("Content-Type")
				raw, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(raw, &got)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}
			mu.Unlock()

			epoch, err := c.forwardArtifactCatalogEpochToLeader(ctx, "templates", c.nodeID, "holder-1")
			switch {
			case tc.wantIs != nil:
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("err = %v, want %v", err, tc.wantIs)
				}
			case tc.wantSub != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
					t.Fatalf("err = %v, want substring %q", err, tc.wantSub)
				}
			default:
				if err != nil || epoch != tc.wantEpoch {
					t.Fatalf("epoch, err = %d, %v; want %d, nil", epoch, err, tc.wantEpoch)
				}
			}
			if gotMethod != http.MethodPost || gotPath != PublicInternalArtifactCatalogEpochPath {
				t.Fatalf("request = %s %s", gotMethod, gotPath)
			}
			if gotAuth != "Bearer cov96-pat" || gotPeer != c.nodeID || gotType != "application/json" {
				t.Fatalf("headers auth=%q peer=%q type=%q", gotAuth, gotPeer, gotType)
			}
			if got.Kind != "templates" || got.Holder != "holder-1" {
				t.Fatalf("body = %+v", got)
			}
		})
	}
}

// --- placementFSM apply error branches reachable with one crafted command ---

func cov96FwdApply(f *placementFSM, cmd command) error {
	payload, err := encodeCommand(cmd)
	if err != nil {
		return err
	}
	res := f.Apply(&raft.Log{Index: 1, Data: payload})
	if res == nil {
		return nil
	}
	if err, ok := res.(error); ok {
		return err
	}
	return nil
}

func cov96FwdSeed(t *testing.T, f *placementFSM, id string, p Placement) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.storePlacementLocked(id, p); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

func TestCov96ForwardFSMApplyErrorBranches(t *testing.T) {
	const sb, inc = "sb-cov96", "inc-1"
	validRef := secretspkg.FormatRef(sb, inc, secretspkg.RefVersion)
	deleting := Placement{OwnerNodeID: "n1", IncarnationID: inc, State: PlacementStateDeleting}
	active := Placement{OwnerNodeID: "n1", IncarnationID: inc}
	orphan := Placement{IncarnationID: inc, OwnerState: PlacementOwnerStateOrphaned}
	reserved := Placement{OwnerNodeID: "n1", IncarnationID: inc, State: PlacementStateReserved, SecretRecipients: []string{"n1", "n2"}}
	spec := &models.CreateSandboxRequest{Image: "alpine"}

	cases := []struct {
		name   string
		seed   *Placement
		cmd    command
		wantIs error
		wantOK bool
	}{
		{name: "place bad secret handle", cmd: command{Op: opPlace, SandboxID: sb, OwnerNodeID: "n1", IncarnationID: inc, SecretRef: "bogus"}, wantIs: ErrInvalidSecretHandle},
		{name: "place onto deleting", seed: &deleting, cmd: command{Op: opPlace, SandboxID: sb, OwnerNodeID: "n1", ExpectedIncarnationID: inc}, wantIs: ErrReservationConflict},
		{name: "place promotion changes recipients", seed: &reserved, cmd: command{Op: opPlace, SandboxID: sb, OwnerNodeID: "n1", ExpectedIncarnationID: inc, SecretRecipients: []string{"n1", "n3"}}, wantIs: ErrInvalidSecretHandle},

		{name: "begin delete unknown", cmd: command{Op: opBeginDelete, SandboxID: sb, ExpectedIncarnationID: inc}, wantIs: ErrUnknownSandbox},
		{name: "begin delete stale incarnation", seed: &active, cmd: command{Op: opBeginDelete, SandboxID: sb, ExpectedIncarnationID: "other", ExpectedOwnerNodeIDSet: true, ExpectedOwnerNodeID: "n1"}, wantIs: ErrIncarnationConflict},
		{name: "begin delete orphaned", seed: &orphan, cmd: command{Op: opBeginDelete, SandboxID: sb, ExpectedIncarnationID: inc, ExpectedOwnerNodeIDSet: true}, wantIs: ErrReservationConflict},
		{name: "begin delete already deleting", seed: &deleting, cmd: command{Op: opBeginDelete, SandboxID: sb, ExpectedIncarnationID: inc, ExpectedOwnerNodeIDSet: true, ExpectedOwnerNodeID: "n1"}, wantOK: true},

		{name: "reassign without incarnation", seed: &active, cmd: command{Op: opReassign, SandboxID: sb, OwnerNodeID: "n2"}, wantIs: ErrIncarnationConflict},

		{name: "claim orphan stale incarnation", seed: &orphan, cmd: command{Op: opClaimOrphan, SandboxID: sb, OwnerNodeID: "n2", IncarnationID: "other"}, wantIs: ErrIncarnationConflict},
		{name: "claim orphan bad secret", seed: &orphan, cmd: command{Op: opClaimOrphan, SandboxID: sb, OwnerNodeID: "n2", IncarnationID: inc, SecretRef: "bogus"}, wantIs: ErrInvalidSecretHandle},
		{name: "claim orphan deleting", seed: &deleting, cmd: command{Op: opClaimOrphan, SandboxID: sb, OwnerNodeID: "n2", IncarnationID: inc}, wantIs: ErrReservationConflict},

		{name: "upsert spec stale incarnation", seed: &active, cmd: command{Op: opUpsertSpec, SandboxID: sb, Spec: spec, ExpectedIncarnationID: "other"}, wantIs: ErrIncarnationConflict},
		{name: "upsert spec bad secret", seed: &active, cmd: command{Op: opUpsertSpec, SandboxID: sb, ExpectedIncarnationID: inc, IncarnationID: inc, SecretRef: "bogus"}, wantIs: ErrInvalidSecretHandle},

		{name: "update recipients unknown", cmd: cov96FwdRecipientsCmd(sb, inc, validRef), wantIs: ErrUnknownSandbox},
		{name: "update recipients deleting", seed: &deleting, cmd: cov96FwdRecipientsCmd(sb, inc, validRef), wantIs: ErrReservationConflict},
		{name: "update recipients stale incarnation", seed: &Placement{OwnerNodeID: "n1", IncarnationID: "other"}, cmd: cov96FwdRecipientsCmd(sb, inc, validRef), wantIs: ErrSecretRecipientsCASMismatch},

		{name: "add port deleting", seed: &deleting, cmd: command{Op: opAddExposedPort, SandboxID: sb, Port: 8080, ExpectedIncarnationID: inc}, wantIs: ErrReservationConflict},
		{name: "remove port deleting", seed: &deleting, cmd: command{Op: opRemoveExposedPort, SandboxID: sb, Port: 8080, ExpectedIncarnationID: inc}, wantIs: ErrReservationConflict},
		{name: "add domain deleting", seed: &deleting, cmd: command{Op: opAddCustomDomain, SandboxID: sb, Hostname: "a.example.com", ExpectedIncarnationID: inc}, wantIs: ErrReservationConflict},
		{name: "remove domain deleting", seed: &deleting, cmd: command{Op: opRemoveCustomDomain, SandboxID: sb, Hostname: "a.example.com", ExpectedIncarnationID: inc}, wantIs: ErrReservationConflict},

		{name: "delete volume attach unknown placement", cmd: command{Op: opDeleteVolumeAttach, VolumeSandboxID: sb, ExpectedIncarnationID: inc}, wantIs: ErrIncarnationConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPlacementFSM()
			if tc.seed != nil {
				cov96FwdSeed(t, f, sb, *tc.seed)
			}
			err := cov96FwdApply(f, tc.cmd)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("apply: %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("apply err = %v, want %v", err, tc.wantIs)
			}
		})
	}
}

func cov96FwdRecipientsCmd(sb, inc, ref string) command {
	return command{
		Op: opUpdateSecretRecipients, SandboxID: sb, SecretRecipients: []string{"n1", "n2"},
		SecretRef: ref, SecretVersion: secretspkg.RefVersion, SecretSealGeneration: 2,
		ExpectedIncarnationID: inc, ExpectedSealGeneration: 1,
	}
}

func TestCov96ForwardFSMRecipientsRecorded(t *testing.T) {
	const sb, inc = "sb-cov96-rcpt", "inc-r"
	ref := secretspkg.FormatRef(sb, inc, secretspkg.RefVersion)

	f := newPlacementFSM()
	cov96FwdSeed(t, f, sb, Placement{IncarnationID: inc, OwnerState: PlacementOwnerStateOrphaned})
	if err := cov96FwdApply(f, command{Op: opClaimOrphan, SandboxID: sb, OwnerNodeID: "n2", IncarnationID: inc,
		SecretRef: ref, SecretVersion: secretspkg.RefVersion, SecretSealGeneration: 2, SecretRecipients: []string{" n2", "n2", "n3"}}); err != nil {
		t.Fatalf("claim: %v", err)
	}
	got, _ := f.get(sb)
	if got.OwnerNodeID != "n2" || strings.Join(got.SecretRecipients, ",") != "n2,n3" {
		t.Fatalf("claimed placement = owner %q recipients %v", got.OwnerNodeID, got.SecretRecipients)
	}

	if err := cov96FwdApply(f, command{Op: opUpsertSpec, SandboxID: sb, ExpectedIncarnationID: inc, IncarnationID: inc,
		SecretRef: ref, SecretVersion: secretspkg.RefVersion, SecretSealGeneration: 3, SecretRecipients: []string{"n2", "n4"}}); err != nil {
		t.Fatalf("upsert spec: %v", err)
	}
	got, _ = f.get(sb)
	if strings.Join(got.SecretRecipients, ",") != "n2,n4" || got.SecretSealGeneration != 3 {
		t.Fatalf("upserted placement recipients %v generation %d", got.SecretRecipients, got.SecretSealGeneration)
	}
}

func TestCov96ForwardFSMVolumeAttachGuards(t *testing.T) {
	const sb, inc = "sb-cov96-vol", "inc-v"
	attach := models.VolumeAttachment{Tenant: "t1", VolumeID: "vol-1", SandboxID: sb, IncarnationID: inc, Target: "/data", Source: "s3://b"}

	for _, tc := range []struct {
		name   string
		seed   *Placement
		wantIs error
	}{
		{name: "placement missing", wantIs: ErrIncarnationConflict},
		{name: "placement deleting", seed: &Placement{OwnerNodeID: "n1", IncarnationID: inc, State: PlacementStateDeleting}, wantIs: ErrReservationConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPlacementFSM()
			f.volumes[volumeKey("t1", "vol-1")] = models.Volume{Tenant: "t1", Name: "data", ID: "vol-1", Backend: "s3"}
			if tc.seed != nil {
				cov96FwdSeed(t, f, sb, *tc.seed)
			}
			err := cov96FwdApply(f, command{Op: opPutVolumeAttach, VolumeAttachments: []models.VolumeAttachment{attach}})
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("err = %v, want %v", err, tc.wantIs)
			}
		})
	}
}

func TestCov96ForwardFSMArtifactCatalogBranches(t *testing.T) {
	const kind, node = "templates", "n1"

	t.Run("publish lazily builds a nil catalogue", func(t *testing.T) {
		f := newPlacementFSM()
		f.artifactCatalog = nil
		if err := cov96FwdApply(f, command{Op: opPublishArtifactCatalog, ArtifactKind: kind, NodeID: node,
			ArtifactEpoch: 1, ArtifactRevision: 1, ArtifactChunkFirst: true, ArtifactChunkFinal: true,
			ArtifactRows: []ArtifactCatalogRow{{ID: "a", Tenant: "t"}}}); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if got := f.artifactCatalog[kind].Committed[node]; got.Epoch != 1 || len(got.Rows) != 1 {
			t.Fatalf("committed = %+v", got)
		}
	})

	t.Run("publish fills nil committed and pending maps", func(t *testing.T) {
		f := newPlacementFSM()
		f.artifactCatalog[kind] = &artifactCatalogKindState{}
		if err := cov96FwdApply(f, command{Op: opPublishArtifactCatalog, ArtifactKind: kind, NodeID: node,
			ArtifactEpoch: 1, ArtifactRevision: 1, ArtifactChunkFirst: true}); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if _, ok := f.artifactCatalog[kind].Pending[node]; !ok {
			t.Fatal("first non-final chunk should be pending")
		}
	})

	t.Run("continuation for a replaced snapshot is superseded", func(t *testing.T) {
		f := newPlacementFSM()
		f.artifactCatalog[kind] = &artifactCatalogKindState{
			Committed: map[string]artifactCatalogNodeState{},
			Pending:   map[string]artifactCatalogNodeState{node: {Epoch: 1, Revision: 1, Rows: map[string]ArtifactCatalogRow{}}},
		}
		err := cov96FwdApply(f, command{Op: opPublishArtifactCatalog, ArtifactKind: kind, NodeID: node,
			ArtifactEpoch: 1, ArtifactRevision: 2})
		if !errors.Is(err, ErrArtifactCatalogSuperseded) {
			t.Fatalf("err = %v, want ErrArtifactCatalogSuperseded", err)
		}
	})

	t.Run("allocate requires holder", func(t *testing.T) {
		f := newPlacementFSM()
		err := cov96FwdApply(f, command{Op: opAllocateArtifactEpoch, ArtifactKind: kind, NodeID: node})
		if err == nil || !strings.Contains(err.Error(), "requires kind, node_id and holder") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("allocate on nil catalogue", func(t *testing.T) {
		f := newPlacementFSM()
		f.artifactCatalog = nil
		payload, _ := encodeCommand(command{Op: opAllocateArtifactEpoch, ArtifactKind: kind, NodeID: node, ArtifactHolder: "h"})
		res, ok := f.Apply(&raft.Log{Index: 1, Data: payload}).(artifactEpochApplyResult)
		if !ok || res.Epoch != 1 {
			t.Fatalf("result = %#v", res)
		}
	})

	t.Run("allocate outranks a pending epoch", func(t *testing.T) {
		f := newPlacementFSM()
		f.artifactCatalog[kind] = &artifactCatalogKindState{
			Committed: map[string]artifactCatalogNodeState{node: {Epoch: 2}},
			Pending:   map[string]artifactCatalogNodeState{node: {Epoch: 5}},
		}
		payload, _ := encodeCommand(command{Op: opAllocateArtifactEpoch, ArtifactKind: kind, NodeID: node, ArtifactHolder: "h"})
		res, ok := f.Apply(&raft.Log{Index: 1, Data: payload}).(artifactEpochApplyResult)
		if !ok || res.Epoch != 6 {
			t.Fatalf("result = %#v, want epoch 6", res)
		}
	})
}

func TestCov96ForwardFSMRetireNodeStorageNilMap(t *testing.T) {
	f := newPlacementFSM()
	f.storageRetirements = nil
	if err := cov96FwdApply(f, command{Op: opRetireNodeStorage, NodeID: " n9 ", StorageRetirement: &NodeStorageRetirement{Actor: "op"}}); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if got := f.storageRetirements["n9"]; got.NodeID != "n9" || got.Actor != "op" {
		t.Fatalf("retirement = %+v", got)
	}
}
