package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// Once servers sign, a worker makes no volume row: it may read one that
// exists through the upsert, remove a delete_with_sandbox row, and attach
// or detach only its own sandboxes. Before, every node writes as it always
// did.
func TestWorkerVolumeWritesBoundToItsSandbox(t *testing.T) {
	tenant := volumes.TenantForOwnerRef("team:a")
	other := volumes.TenantForOwnerRef("team:b")
	vol := func(tenant, name, source string, dws bool) models.Volume {
		return models.Volume{ID: "vol-" + name, Tenant: tenant, Name: name, Backend: volumes.BackendS3, Source: source, DeleteWithSandbox: dws}
	}
	mine := vol(tenant, "data", "vols/pfx/"+tenant+"/data", false)
	theirs := vol(other, "data", "vols/pfx/"+other+"/data", false)
	dws := vol(other, "tmp", "vols/pfx/"+other+"/tmp", true)
	st := fakeProposalState{signing: true,
		placements: map[string]Placement{
			"sb-mine":   {SandboxID: "sb-mine", OwnerNodeID: "wkr-1", OwnerRef: "team:a", State: PlacementStateReserved},
			"sb-placed": {SandboxID: "sb-placed", OwnerNodeID: "wkr-1", OwnerRef: "team:a"},
			"sb-theirs": {SandboxID: "sb-theirs", OwnerNodeID: "wkr-2", OwnerRef: "team:b", State: PlacementStateReserved},
		},
		volumes: map[string]models.Volume{
			volumeKey(mine.Tenant, mine.ID):     mine,
			volumeKey(theirs.Tenant, theirs.ID): theirs,
			volumeKey(dws.Tenant, dws.ID):       dws,
		},
	}
	upsert := func(v models.Volume) command {
		return command{Op: opUpsertVolume, Volume: &v}
	}
	attach := func(sb, tenant, id, source string) command {
		return command{Op: opPutVolumeAttach, VolumeAttachments: []models.VolumeAttachment{{Tenant: tenant, VolumeID: id, SandboxID: sb, IncarnationID: "i", Target: "/d", Source: source}}}
	}
	for _, tc := range []struct {
		name string
		cmd  command
		want bool
	}{
		{"a row that exists", upsert(vol(tenant, "data", "other-bucket/x", false)), true},
		{"a first use", upsert(vol(tenant, "new", "vols/pfx/"+tenant+"/new", false)), false},
		{"an upsert with no row", command{Op: opUpsertVolume}, false},
		{"delete a row", command{Op: opDeleteVolume, VolumeTenant: tenant, VolumeID: mine.ID}, false},
		{"delete another tenant's row", command{Op: opDeleteVolume, VolumeTenant: other, VolumeID: theirs.ID}, false},
		{"delete a delete_with_sandbox row", command{Op: opDeleteVolume, VolumeTenant: other, VolumeID: dws.ID, VolumeReclaimNodeID: "wkr-1"}, true},
		{"a reclaim drained by another node", command{Op: opDeleteVolume, VolumeTenant: other, VolumeID: dws.ID, VolumeReclaimNodeID: "wkr-2"}, false},
		{"a reclaim of another source", command{Op: opDeleteVolume, VolumeTenant: other, VolumeID: dws.ID, VolumeReclaimSource: "other-bucket/x"}, false},
		{"delete an unknown row", command{Op: opDeleteVolume, VolumeTenant: tenant, VolumeID: "vol-none"}, true},
		{"attach to its own sandbox", attach("sb-mine", tenant, mine.ID, mine.Source), true},
		{"attach to its own placed sandbox", attach("sb-placed", tenant, mine.ID, mine.Source), true},
		{"attach another tenant's volume", attach("sb-mine", other, theirs.ID, theirs.Source), false},
		{"attach to another node's sandbox", attach("sb-theirs", other, theirs.ID, theirs.Source), false},
		{"attach with another source", attach("sb-mine", tenant, mine.ID, "other-bucket/x"), false},
		{"attach nothing", command{Op: opPutVolumeAttach}, false},
		{"detach its own sandbox", command{Op: opDeleteVolumeAttach, VolumeSandboxID: "sb-mine"}, true},
		{"detach another node's sandbox", command{Op: opDeleteVolumeAttach, VolumeSandboxID: "sb-theirs"}, false},
		{"detach an unknown sandbox", command{Op: opDeleteVolumeAttach, VolumeSandboxID: "sb-none"}, true},
	} {
		if got := peerMayPropose(JoinRoleWorker, "wkr-1", tc.cmd, st); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
		if !peerMayPropose(JoinRoleServer, "srv-1", tc.cmd, st) {
			t.Errorf("%s: a server may not", tc.name)
		}
	}
	st.signing = false
	if !peerMayPropose(JoinRoleWorker, "wkr-1", upsert(vol(other, "new", "other-bucket", false)), st) {
		t.Fatal("before servers sign, a worker's volume write was refused")
	}
	if volumeTenantOf("op-main", "") != true || volumeTenantOf("t-x", "") || volumeTenantOf(tenant, "team:b") {
		t.Fatal("volume tenant of an owner")
	}
}

// A worker's upsert of an existing row reaches the log as that row: should
// the row go and the get-or-create make it again, it is the row a server
// made, never the sender's.
func TestLeaderStampsAWorkersVolumeUpsert(t *testing.T) {
	c := stampLeader(t, "ldr-vol-stamp", workerMember("wkr-9", ""))
	tenant := volumes.TenantForOwnerRef("team:a")
	row := models.Volume{ID: "vol-1", Tenant: tenant, Name: "data", Backend: volumes.BackendS3, Source: "vols/pfx/" + tenant + "/data", CreatedAt: time.Unix(10, 0).UTC()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := c.VolumeUpsert(ctx, row, 0); err != nil {
		t.Fatal(err)
	}
	sent := models.Volume{ID: "vol-2", Tenant: tenant, Name: "data", Backend: volumes.BackendS3, Source: "other-bucket/x/" + tenant + "/data"}
	raw, _ := encodeCommand(command{Op: opUpsertVolume, Volume: &sent})
	// Before servers sign, the command goes as sent.
	out, _, err := c.stampProposal(raw, command{Op: opUpsertVolume, Volume: &sent}, "wkr-9", false)
	if err != nil || string(out) != string(raw) {
		t.Fatalf("before servers sign: %s, %v", out, err)
	}
	c.fsm.mu.Lock()
	c.fsm.serverSigning = &ServerSigning{Sealed: []byte("x"), SinceUnixNano: 1}
	c.fsm.mu.Unlock()
	_, cmd, err := c.stampProposal(raw, command{Op: opUpsertVolume, Volume: &sent}, "wkr-9", false)
	if err != nil || cmd.Volume == nil || cmd.Volume.ID != "vol-1" || cmd.Volume.Source != row.Source {
		t.Fatalf("stamped %+v, %v", cmd.Volume, err)
	}
	// A server's goes as sent; a first use from a worker has nothing to
	// stamp (the rule refuses it).
	if _, cmd, _ := c.stampProposal(raw, command{Op: opUpsertVolume, Volume: &sent}, "srv-1", true); cmd.Volume.ID != "vol-2" {
		t.Fatal("a server's upsert rewritten")
	}
	fresh := sent
	fresh.Name = "fresh"
	if _, cmd, _ := c.stampProposal(raw, command{Op: opUpsertVolume, Volume: &fresh}, "wkr-9", false); cmd.Volume.Name != "fresh" {
		t.Fatal("a first use rewritten")
	}
}

// The leader reads volume rows for the rule from its FSM.
func TestVolumeRowReadsForTheRule(t *testing.T) {
	c := stampLeader(t, "ldr-vol-read")
	tenant := volumes.TenantForOwnerRef("team:a")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := c.VolumeUpsert(ctx, models.Volume{ID: "vol-1", Tenant: tenant, Name: "data", Backend: volumes.BackendS3, Source: "vols/" + tenant + "/data"}, 0); err != nil {
		t.Fatal(err)
	}
	st := leaderProposalState{placementFSM: c.fsm, c: c}
	if v, ok := st.volumeForProposal(tenant, "vol-1"); !ok || v.Name != "data" {
		t.Fatalf("by id: %+v %v", v, ok)
	}
	if v, ok := st.volumeByNameForProposal(tenant, "data"); !ok || v.ID != "vol-1" {
		t.Fatalf("by name: %+v %v", v, ok)
	}
	if _, ok := st.volumeForProposal(tenant, "vol-none"); ok {
		t.Fatal("an unknown id")
	}
	if _, ok := st.volumeByNameForProposal(tenant, "none"); ok {
		t.Fatal("an unknown name")
	}
	var none *placementFSM
	if _, ok := none.volumeForProposal(tenant, "vol-1"); ok {
		t.Fatal("no FSM")
	}
	if _, ok := none.volumeByNameForProposal(tenant, "data"); ok {
		t.Fatal("no FSM")
	}
}

// A call a worker or gateway sent on: a forward over a verified
// connection from a peer whose role is not server.
func TestSentOnByNonServer(t *testing.T) {
	req := func(forwarded bool, role string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		if forwarded {
			r.Header.Set(HeaderForwarded, "1")
		}
		if role != "-" {
			cert := &x509.Certificate{DNSNames: []string{"node:p1", "role:" + role}}
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		}
		return r
	}
	for _, tc := range []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"a gateway's forward", req(true, JoinRoleIngress), true},
		{"a worker's forward", req(true, JoinRoleWorker), true},
		{"a server's forward", req(true, JoinRoleServer), false},
		{"not a forward", req(false, JoinRoleIngress), false},
		{"no certificate", req(true, "-"), false},
		{"no request", nil, false},
	} {
		if got := SentOnByNonServer(nil, tc.r); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}
