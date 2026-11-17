package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// stampLeader is a single-node leader whose cluster lives under
// sb.example.com with its API at api.example.com, and which knows the
// workers in members.
func stampLeader(t *testing.T, name string, members ...Member) *Cluster {
	t.Helper()
	c, cleanup := newTestClusterWithCfg(t, name, true, nil, func(cfg *config.Config) {
		cfg.Domain = "sb.example.com"
		cfg.PublicHost = "api.example.com"
	})
	t.Cleanup(cleanup)
	waitForLeader(t, c, 10*time.Second)
	seedGossipView(t, c, members)
	return c
}

func workerMember(id, dataPlaneHost string) Member {
	m := recreateCandidate(id, config.NodeRoleWorker, 100)
	m.DataPlaneHost = dataPlaneHost
	return m
}

// A worker binds a customer's hostname to a sandbox it owns, but never one
// of the cluster's own names: the base domain, a name under it (another
// sandbox's, or the API's), or the API host.
func TestWorkerCannotBindClusterHostnames(t *testing.T) {
	c := stampLeader(t, "ldr-names", workerMember("wkr-9", "10.0.0.9"))
	w := workerApplyCtx("wkr-9")
	inc, _ := MintIncarnationID()
	public := true
	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-w", OwnerNodeID: "wkr-9", IncarnationID: inc,
		Spec: &models.CreateSandboxRequest{Image: "alpine", AllowPublicTraffic: &public}})
	if err := c.ApplyEncoded(w, place); err != nil {
		t.Fatalf("place: %v", err)
	}
	for _, host := range []string{"api.sb.example.com", "sb-other.sb.example.com", "sb.example.com", "api.example.com"} {
		add, _ := encodeCommand(command{Op: opAddCustomDomain, SandboxID: "sb-w", Hostname: host, ExpectedIncarnationID: inc})
		if err := c.ApplyEncoded(w, add); !errors.Is(err, ErrPeerProposalRefused) {
			t.Errorf("bind %s = %v, want ErrPeerProposalRefused", host, err)
		}
	}
	add, _ := encodeCommand(command{Op: opAddCustomDomain, SandboxID: "sb-w", Hostname: "app.customer.com", ExpectedIncarnationID: inc})
	if err := c.ApplyEncoded(w, add); err != nil {
		t.Fatalf("bind a customer hostname: %v", err)
	}
	if p, _ := c.fsm.get("sb-w"); len(p.CustomHostnames) != 1 || p.CustomHostnames[0] != "app.customer.com" {
		t.Fatalf("custom hostnames %v", p.CustomHostnames)
	}
}

// Where a worker's sandbox is reached comes from the leader's member
// records, not from what the worker wrote; a reservation records who sent
// it, and only that node, its target or a server cancels it.
func TestLeaderStampsWorkerProposals(t *testing.T) {
	thin := workerMember("wkr-thin", "")
	thin.APIURL = ""
	c := stampLeader(t, "ldr-stamp", workerMember("wkr-9", "10.0.0.9"), workerMember("wkr-b", "10.0.0.11"), workerMember("wkr-3", "10.0.0.3"), thin)
	ctx := context.Background()
	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-p", OwnerNodeID: "wkr-9", IncarnationID: "inc-p",
		OwnerAPIURL: "http://elsewhere.example", OwnerDataPlaneHost: "203.0.113.7", Spec: &models.CreateSandboxRequest{Image: "alpine"}})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), place); err != nil {
		t.Fatalf("place: %v", err)
	}
	if p, _ := c.fsm.get("sb-p"); p.OwnerAPIURL != "http://wkr-9" || p.OwnerDataPlaneHost != "10.0.0.9" {
		t.Fatalf("placed at %q / %q, want the member record's", p.OwnerAPIURL, p.OwnerDataPlaneHost)
	}
	// A node the leader has no member record for names no address.
	ghost, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-g", OwnerNodeID: "wkr-ghost", IncarnationID: "inc-g",
		OwnerAPIURL: "http://wkr-ghost", Spec: &models.CreateSandboxRequest{Image: "alpine"}})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-ghost"), ghost); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("place by a node with no member record = %v", err)
	}

	// A member whose gossip record lost its addresses (a cut meta tier)
	// places its own sandbox at the addresses it sends; another node cannot
	// name it as the target of a reservation.
	own, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-thin", OwnerNodeID: "wkr-thin", IncarnationID: "inc-t",
		OwnerAPIURL: "http://wkr-thin", OwnerDataPlaneHost: "10.0.0.20", Spec: &models.CreateSandboxRequest{Image: "alpine"}})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-thin"), own); err != nil {
		t.Fatalf("thin record, own place: %v", err)
	}
	if p, _ := c.fsm.get("sb-thin"); p.OwnerAPIURL != "http://wkr-thin" || p.OwnerDataPlaneHost != "10.0.0.20" {
		t.Fatalf("thin record placed at %q / %q", p.OwnerAPIURL, p.OwnerDataPlaneHost)
	}
	toThin, _ := encodeCommand(command{Op: opReserve, SandboxID: "sb-rt", OwnerNodeID: "wkr-thin", IncarnationID: "inc-rt",
		OwnerAPIURL: "http://elsewhere.example", Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64},
		ExpiresUnix: time.Now().Add(2 * time.Minute).Unix()})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), toThin); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("reserve on a node with no API URL on record = %v", err)
	}

	reserve, _ := encodeCommand(command{Op: opReserve, SandboxID: "sb-r", OwnerNodeID: "wkr-b", IncarnationID: "inc-r",
		OwnerAPIURL: "http://elsewhere.example", ReservedBy: "wkr-3",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}, ExpiresUnix: time.Now().Add(2 * time.Minute).Unix()})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), reserve); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	p, _ := c.fsm.get("sb-r")
	if p.ReservedBy != "wkr-9" || p.OwnerAPIURL != "http://wkr-b" || p.OwnerDataPlaneHost != "10.0.0.11" {
		t.Fatalf("reservation = by %q at %q / %q", p.ReservedBy, p.OwnerAPIURL, p.OwnerDataPlaneHost)
	}
	cancel, _ := encodeCommand(command{Op: opCancelReserve, SandboxID: "sb-r", ExpectedIncarnationID: "inc-r"})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-3"), cancel); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("cancel by a third node = %v", err)
	}
	if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), cancel); err != nil {
		t.Fatalf("cancel by the node that reserved it: %v", err)
	}
	if _, ok := c.fsm.get("sb-r"); ok {
		t.Fatal("reservation not cancelled")
	}

	// The leader's own proposals keep their addresses and name it.
	if err := c.applyCommand(ctx, command{Op: opReserve, SandboxID: "sb-l", OwnerNodeID: "wkr-b", OwnerAPIURL: "http://as-given",
		IncarnationID: "inc-l", Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64},
		ExpiresUnix: time.Now().Add(2 * time.Minute).Unix()}); err != nil {
		t.Fatalf("leader reserve: %v", err)
	}
	if p, _ := c.fsm.get("sb-l"); p.ReservedBy != c.nodeID || p.OwnerAPIURL != "http://as-given" {
		t.Fatalf("leader reservation = by %q at %q", p.ReservedBy, p.OwnerAPIURL)
	}
}

// A worker claims another node's reclaim entry only when the listing would
// offer it: not from a live node that drains its own.
func TestWorkerClaimsOnlyAdoptableReclaims(t *testing.T) {
	c := stampLeader(t, "ldr-reclaim", workerMember("wkr-9", ""), workerMember("wkr-live", ""))
	now := time.Now()
	held := VolumeReclaim{Tenant: "t-1", VolumeID: "vol-held", NodeID: "wkr-live", RecordedUnixNano: now.Add(-time.Hour).UnixNano()}
	dead := VolumeReclaim{Tenant: "t-1", VolumeID: "vol-dead", NodeID: "wkr-gone", RecordedUnixNano: now.Add(-time.Hour).UnixNano()}
	fresh := VolumeReclaim{Tenant: "t-1", VolumeID: "vol-fresh", NodeID: "wkr-gone", RecordedUnixNano: now.UnixNano()}
	c.fsm.mu.Lock()
	for _, r := range []VolumeReclaim{held, dead, fresh} {
		c.fsm.putVolumeReclaimLocked(r)
	}
	c.fsm.mu.Unlock()
	claim := func(r VolumeReclaim) error {
		cmd, err := claimVolumeReclaimCommand(r, "wkr-9")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := encodeCommand(cmd)
		return c.ApplyEncoded(workerApplyCtx("wkr-9"), raw)
	}
	if err := claim(held); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("claim from a live node that drains = %v", err)
	}
	if err := claim(fresh); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("claim of a dead node's entry before it may move = %v", err)
	}
	// Two sweepers, three adopters an entry: wkr-9 is one of them.
	if err := claim(dead); err != nil {
		t.Fatalf("claim of a dead node's old entry: %v", err)
	}
}

// proverRecreator is a recreator that also checks DNS proofs.
type proverRecreator struct {
	recordingRecreator
	proved []string
}

func (p *proverRecreator) ProveCustomDomain(_ context.Context, host, owner string) error {
	p.proved = append(p.proved, host+"@"+owner)
	if host == "noproof.customer.com" {
		return errors.New("no TXT record")
	}
	return nil
}

// The leader checks the DNS proof of a hostname a worker adds, against the
// sandbox's owner, and does not ask again for one the sandbox holds.
func TestLeaderChecksWorkerDomainProof(t *testing.T) {
	c := stampLeader(t, "ldr-proof", workerMember("wkr-9", ""))
	prover := &proverRecreator{recordingRecreator: recordingRecreator{calls: map[string]recordedRecreate{}}}
	c.AttachRecreator(prover)
	w := workerApplyCtx("wkr-9")
	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-d", OwnerNodeID: "wkr-9", IncarnationID: "inc-d", OwnerRef: "team:payments",
		Spec: &models.CreateSandboxRequest{Image: "alpine"}})
	if err := c.ApplyEncoded(w, place); err != nil {
		t.Fatal(err)
	}
	add := func(host string) error {
		raw, _ := encodeCommand(command{Op: opAddCustomDomain, SandboxID: "sb-d", Hostname: host, ExpectedIncarnationID: "inc-d"})
		return c.ApplyEncoded(w, raw)
	}
	if err := add("noproof.customer.com"); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("add without a proof = %v", err)
	}
	if err := add("app.customer.com"); err != nil {
		t.Fatalf("add with a proof: %v", err)
	}
	if err := add("app.customer.com"); err != nil {
		t.Fatalf("add again: %v", err)
	}
	if len(prover.proved) != 2 || prover.proved[1] != "app.customer.com@team:payments" {
		t.Fatalf("proofs asked %v", prover.proved)
	}
}

// A leader with no domain of its own (a Kubernetes server: only gateways
// serve the edge) still refuses the names its members serve.
func TestWorkerCannotBindMembersPublicNames(t *testing.T) {
	gw := workerMember("gw-1", "")
	gw.Role = config.NodeRoleIngress
	gw.PublicHost = "edge.example.net:443"
	c, cleanup := newTestCluster(t, "ldr-members-names", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	seedGossipView(t, c, []Member{workerMember("wkr-9", ""), gw})
	w := workerApplyCtx("wkr-9")
	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-m", OwnerNodeID: "wkr-9", IncarnationID: "inc-m",
		Spec: &models.CreateSandboxRequest{Image: "alpine"}})
	if err := c.ApplyEncoded(w, place); err != nil {
		t.Fatal(err)
	}
	for host, refused := range map[string]bool{"edge.example.net": true, "sb-x.edge.example.net": true, "app.customer.com": false} {
		add, _ := encodeCommand(command{Op: opAddCustomDomain, SandboxID: "sb-m", Hostname: host, ExpectedIncarnationID: "inc-m"})
		err := c.ApplyEncoded(w, add)
		if refused != errors.Is(err, ErrPeerProposalRefused) {
			t.Errorf("bind %s = %v", host, err)
		}
	}
}
