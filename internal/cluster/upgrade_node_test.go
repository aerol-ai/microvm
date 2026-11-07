package cluster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Tests for the node side of a rollout step (upgrade_node.go): the fence,
// stage, apply, finalize and status, with a fake host and file sources.

// fakeUpgradeHost is nodeupgrade.Host with no systemd and no network.
type fakeUpgradeHost struct {
	fetch   map[string][]byte
	fetched []string
	missing map[string]bool
	active  map[string]bool
	freeLow bool
}

func (h *fakeUpgradeHost) UnitActive(_ context.Context, unit string) bool { return h.active[unit] }
func (h *fakeUpgradeHost) StopUnit(context.Context, string) error         { return nil }
func (h *fakeUpgradeHost) StartUnit(context.Context, string) error        { return nil }
func (h *fakeUpgradeHost) RestartUnit(context.Context, string) error      { return nil }
func (h *fakeUpgradeHost) UnitControlGroup(context.Context, string) string {
	return ""
}
func (h *fakeUpgradeHost) LookPath(name string) (string, error) {
	if h.missing[name] {
		return "", errors.New("not found")
	}
	return "/usr/bin/" + name, nil
}
func (h *fakeUpgradeHost) FreeBytes(string) (uint64, uint64, error) {
	if h.freeLow {
		return 1 << 20, 1, nil
	}
	return 1 << 40, 1, nil
}
func (h *fakeUpgradeHost) Run(context.Context, string, ...string) ([]byte, error) { return nil, nil }
func (h *fakeUpgradeHost) Fetch(_ context.Context, url string) (io.ReadCloser, int64, error) {
	h.fetched = append(h.fetched, url)
	b, ok := h.fetch[url]
	if !ok {
		return nil, 0, fmt.Errorf("GET %s: 404", url)
	}
	return io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
}
func (h *fakeUpgradeHost) HealthVersion(context.Context, string) (string, error) { return "", nil }
func (h *fakeUpgradeHost) GatewayProtocol(context.Context, string) (int, error)  { return 0, nil }
func (h *fakeUpgradeHost) StartDrain(string) (int, error)                        { return 0, nil }

func sumOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// upgradeNodeRig is an upgradeNode over a temp node layout.
type upgradeNodeRig struct {
	u        *upgradeNode
	host     *fakeUpgradeHost
	paths    nodeupgrade.Paths
	launched []nodeupgrade.Request
	fence    UpgradeFence
	fenceErr error
	audits   []UpgradeAuditEvent
}

func newUpgradeNodeRig(t *testing.T, isServer bool) *upgradeNodeRig {
	dir := t.TempDir()
	p := nodeupgrade.Paths{
		StateDir: filepath.Join(dir, "upgrade"), DBPath: filepath.Join(dir, "state.db"),
		Sandboxd: filepath.Join(dir, "bin", "sandboxd"), Toolboxd: filepath.Join(dir, "bin", "toolboxd"),
		ReleaseURL: "https://releases.example",
	}
	if err := os.MkdirAll(filepath.Dir(p.Sandboxd), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(p.Sandboxd, []byte("old sandboxd"), 0o755)
	_ = os.WriteFile(p.Toolboxd, []byte("old toolboxd"), 0o755)
	g := &upgradeNodeRig{host: &fakeUpgradeHost{fetch: map[string][]byte{}, missing: map[string]bool{}, active: map[string]bool{}}, paths: p}
	u := newUpgradeNode(config.Config{RemoteUpgrade: true}, "n1", isServer, nil)
	u.host = g.host
	u.paths = func() (nodeupgrade.Paths, error) { return p, nil }
	u.launch = func(_ context.Context, _ nodeupgrade.Host, bin string, req nodeupgrade.Request) (string, error) {
		if bin != p.Sandboxd {
			return "", fmt.Errorf("launched %s", bin)
		}
		g.launched = append(g.launched, req)
		return req.Op, nil
	}
	u.fence = func(context.Context, string) (UpgradeFence, error) { return g.fence, g.fenceErr }
	u.audit = func(ev UpgradeAuditEvent) { g.audits = append(g.audits, ev) }
	u.fetchRetry = time.Millisecond
	g.u = u
	return g
}

// stepOp is n1's op in stepRollout: the first upgrade pass of r1
// (rolloutOpID).
const stepOp = "r1-u0"

// stepRollout is a committed rollout in which n1 is in state.
func stepRollout(state, nodeState string, files map[string]string) *RolloutRecord {
	return &RolloutRecord{
		ID: "r1", State: state, Direction: upgradewire.DirectionUpgrade, TargetVersion: "v2", PreviousVersion: "v1",
		Caller: "pat:op", Files: files, PrevFiles: map[string]string{"sandboxd_linux_amd64": strings.Repeat("c", 64)},
		Nodes: map[string]*RolloutNodeRecord{"n1": {NodeID: "n1", State: nodeState, Op: stepOp}},
	}
}

func TestCheckUpgradeFence(t *testing.T) {
	files := map[string]string{"sandboxd_linux_amd64": strings.Repeat("a", 64)}
	good := UpgradeStepRequest{RolloutID: "r1", Step: UpgradeStepStage, Direction: upgradewire.DirectionUpgrade, Version: "v2", Files: files, Term: 7}
	fence := func(state, nodeState string) UpgradeFence {
		return UpgradeFence{Leader: "lead", Term: 7, Rollout: stepRollout(state, nodeState, files)}
	}
	cases := []struct {
		name   string
		caller string
		edit   func(*UpgradeStepRequest, *UpgradeFence)
		code   string
	}{
		{"ok", "lead", nil, ""},
		{"no leader", "lead", func(_ *UpgradeStepRequest, f *UpgradeFence) { f.Leader = "" }, upgradeCodeRetry},
		{"not the leader", "other", nil, upgradeCodeNotLeader},
		{"older term", "lead", func(r *UpgradeStepRequest, _ *UpgradeFence) { r.Term = 6 }, upgradeCodeStaleTerm},
		{"newer term", "lead", func(r *UpgradeStepRequest, _ *UpgradeFence) { r.Term = 8 }, upgradeCodeRetry},
		{"no rollout", "lead", func(_ *UpgradeStepRequest, f *UpgradeFence) { f.Rollout = nil }, upgradeCodeNotInRecord},
		{"other rollout", "lead", func(r *UpgradeStepRequest, _ *UpgradeFence) { r.RolloutID = "r0" }, upgradeCodeNotInRecord},
		{"node not in it", "lead", func(_ *UpgradeStepRequest, f *UpgradeFence) { f.Rollout.Nodes = nil }, upgradeCodeNotInRecord},
		{"wrong direction", "lead", func(r *UpgradeStepRequest, _ *UpgradeFence) { r.Direction = upgradewire.DirectionRollback }, upgradeCodeNotInRecord},
		{"wrong version", "lead", func(r *UpgradeStepRequest, _ *UpgradeFence) { r.Version = "v9" }, upgradeCodeNotInRecord},
		{"file not in record", "lead", func(r *UpgradeStepRequest, _ *UpgradeFence) {
			r.Files = map[string]string{"sandboxd_linux_amd64": strings.Repeat("f", 64)}
		}, upgradeCodeNotInRecord},
		{"cache file not in record", "lead", func(r *UpgradeStepRequest, _ *UpgradeFence) {
			r.CacheFiles = map[string]string{"evil": strings.Repeat("e", 64)}
		}, upgradeCodeNotInRecord},
		{"stage while finalizing", "lead", func(_ *UpgradeStepRequest, f *UpgradeFence) { f.Rollout.State = upgradewire.StateFinalizing }, upgradewire.ErrCodeRolloutConflict},
		{"stage a done node", "lead", func(_ *UpgradeStepRequest, f *UpgradeFence) { f.Rollout.Nodes["n1"].State = upgradewire.NodeDone }, upgradewire.ErrCodeRolloutConflict},
		{"apply ok", "lead", func(r *UpgradeStepRequest, f *UpgradeFence) {
			r.Step, r.Op = UpgradeStepApply, stepOp
			f.Rollout.State, f.Rollout.Nodes["n1"].State = upgradewire.StateRunning, upgradewire.NodeUpgrading
		}, ""},
		{"apply catching up a node once done", "lead", func(r *UpgradeStepRequest, f *UpgradeFence) {
			r.Step, r.Op = UpgradeStepApply, stepOp
			f.Rollout.State, f.Rollout.Nodes["n1"].State = upgradewire.StateDone, upgradewire.NodeUpgrading
		}, ""},
		{"apply another op", "lead", func(r *UpgradeStepRequest, f *UpgradeFence) {
			r.Step, r.Op = UpgradeStepApply, "op9"
			f.Rollout.State, f.Rollout.Nodes["n1"].State = upgradewire.StateRunning, upgradewire.NodeUpgrading
		}, upgradeCodeNotInRecord},
		{"apply a staged node", "lead", func(r *UpgradeStepRequest, f *UpgradeFence) {
			r.Step, r.Op = UpgradeStepApply, stepOp
			f.Rollout.State = upgradewire.StateRunning
		}, upgradeCodeNotInRecord},
		// R12: stop, a pause, a failure or a restage starts no new restart,
		// even one the leader marked and called before the command landed.
		{"apply after stop", "lead", func(r *UpgradeStepRequest, f *UpgradeFence) {
			r.Step, r.Op = UpgradeStepApply, stepOp
			f.Rollout.State, f.Rollout.Nodes["n1"].State = upgradewire.StateStopped, upgradewire.NodeUpgrading
		}, upgradewire.ErrCodeRolloutConflict},
		{"apply while paused", "lead", func(r *UpgradeStepRequest, f *UpgradeFence) {
			r.Step, r.Op = UpgradeStepApply, stepOp
			f.Rollout.State, f.Rollout.Nodes["n1"].State = upgradewire.StatePaused, upgradewire.NodeUpgrading
		}, upgradewire.ErrCodeRolloutConflict},
		{"apply after a failure", "lead", func(r *UpgradeStepRequest, f *UpgradeFence) {
			r.Step, r.Op = UpgradeStepApply, stepOp
			f.Rollout.State, f.Rollout.Nodes["n1"].State = upgradewire.StateFailed, upgradewire.NodeUpgrading
		}, upgradewire.ErrCodeRolloutConflict},
		{"apply while restaging", "lead", func(r *UpgradeStepRequest, f *UpgradeFence) {
			r.Step, r.Op = UpgradeStepApply, stepOp
			f.Rollout.Nodes["n1"].State = upgradewire.NodeUpgrading
		}, upgradewire.ErrCodeRolloutConflict},
		{"apply an op of an earlier pass", "lead", func(r *UpgradeStepRequest, f *UpgradeFence) {
			r.Step, r.Op = UpgradeStepApply, stepOp
			f.Rollout.State, f.Rollout.Attempt, f.Rollout.Nodes["n1"].State = upgradewire.StateRunning, 1, upgradewire.NodeUpgrading
		}, upgradeCodeNotInRecord},
		{"finalize ok", "lead", func(r *UpgradeStepRequest, f *UpgradeFence) {
			r.Step = UpgradeStepFinalize
			f.Rollout.State = upgradewire.StateFinalizing
		}, ""},
		{"finalize too early", "lead", func(r *UpgradeStepRequest, _ *UpgradeFence) { r.Step = UpgradeStepFinalize }, upgradewire.ErrCodeRolloutConflict},
		{"unknown step", "lead", func(r *UpgradeStepRequest, _ *UpgradeFence) { r.Step = "dance" }, ""},
		{"rollback files", "lead", func(r *UpgradeStepRequest, f *UpgradeFence) {
			r.Step, r.Op, r.Direction, r.Version = UpgradeStepApply, "r1-b0", upgradewire.DirectionRollback, "v1"
			r.Files = map[string]string{"sandboxd_linux_amd64": strings.Repeat("c", 64)}
			f.Rollout.Direction, f.Rollout.State, f.Rollout.Nodes["n1"].State = upgradewire.DirectionRollback, upgradewire.StateRollingBack, upgradewire.NodeUpgrading
			f.Rollout.Nodes["n1"].Op = "r1-b0"
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, f := good, fence(upgradewire.StateStaging, upgradewire.NodePending)
			req.Files = files
			if tc.edit != nil {
				tc.edit(&req, &f)
			}
			err := checkUpgradeFence(tc.caller, "n1", req, f)
			if tc.name == "unknown step" {
				if err == nil {
					t.Fatal("unknown step passed")
				}
				return
			}
			if tc.code == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if stepCode(err) != tc.code {
				t.Fatalf("err = %v, want code %s", err, tc.code)
			}
		})
	}
}

func TestUpgradeNodeStageServerFromRelease(t *testing.T) {
	g := newUpgradeNodeRig(t, true)
	sd, tb, arm := []byte("new sandboxd"), []byte("new toolboxd"), []byte("arm sandboxd")
	files := map[string]string{"sandboxd_linux_amd64": sumOf(sd), "toolboxd_linux_amd64": sumOf(tb)}
	all := map[string]string{"sandboxd_linux_amd64": sumOf(sd), "toolboxd_linux_amd64": sumOf(tb), "sandboxd_linux_arm64": sumOf(arm)}
	g.host.fetch["https://releases.example/v2/sandboxd_linux_amd64"] = sd
	g.host.fetch["https://releases.example/v2/toolboxd_linux_amd64"] = tb
	g.host.fetch["https://releases.example/v2/sandboxd_linux_arm64"] = arm
	g.fence = UpgradeFence{Leader: "lead", Term: 3, Rollout: stepRollout(upgradewire.StateStaging, upgradewire.NodePending, all)}
	req := UpgradeStepRequest{RolloutID: "r1", Step: UpgradeStepStage, Direction: upgradewire.DirectionUpgrade, Version: "v2",
		Files: files, CacheFiles: all, Source: upgradewire.SourceRelease, Term: 3}
	resp, err := g.u.Step(context.Background(), "lead", req)
	if err != nil || resp.State != UpgradeNodeStaged || len(resp.Fetched) != 3 || resp.Installed["sandboxd"] != sumOf([]byte("old sandboxd")) {
		t.Fatalf("stage = %+v %v", resp, err)
	}
	store := nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(g.paths.StateDir)}
	if !store.Has(sumOf(arm)) {
		t.Fatal("a server did not cache the other CPU type's file")
	}
	// A repeat downloads nothing.
	g.host.fetched = nil
	if resp, err := g.u.Step(context.Background(), "lead", req); err != nil || len(resp.Fetched) != 0 || len(g.host.fetched) != 0 {
		t.Fatalf("repeat stage = %+v %v (fetched %v)", resp, err, g.host.fetched)
	}
	if len(g.audits) != 2 || g.audits[0].Caller != "pat:op" || g.audits[0].RolloutID != "r1" || g.audits[0].Result != "success" {
		t.Fatalf("audit = %+v", g.audits)
	}
	// The term was recorded and survives a restart.
	raw, _ := os.ReadFile(termPath(g.paths))
	if strings.TrimSpace(string(raw)) != "3" {
		t.Fatalf("term file = %q", raw)
	}
	u2 := newUpgradeNodeRig(t, true).u
	u2.paths = g.u.paths
	if err := u2.obeyTerm(g.paths, 2); stepCode(err) != upgradeCodeStaleTerm {
		t.Fatalf("older term after restart = %v", err)
	}
	// A stage failure (a bad hash at the source) is a 422.
	bad := map[string]string{"sandboxd_linux_amd64": strings.Repeat("d", 64), "toolboxd_linux_amd64": sumOf(tb)}
	g.fence.Rollout.Files = bad
	g.host.fetch["https://releases.example/v2/sandboxd_linux_amd64"] = []byte("tampered")
	_, err = g.u.Step(context.Background(), "lead", UpgradeStepRequest{RolloutID: "r1", Step: UpgradeStepStage, Direction: upgradewire.DirectionUpgrade, Version: "v2", Files: bad, Source: upgradewire.SourceRelease, Term: 3})
	var se *UpgradeStepError
	if !errors.As(err, &se) || se.Status != http.StatusUnprocessableEntity || !strings.Contains(se.Reason, "SHA-256") {
		t.Fatalf("tampered stage = %v", err)
	}
}

func TestUpgradeNodeStageWorkerCopiesFromServers(t *testing.T) {
	g := newUpgradeNodeRig(t, false)
	sd, tb := []byte("new sandboxd"), []byte("new toolboxd")
	files := map[string]string{"sandboxd_linux_amd64": sumOf(sd), "toolboxd_linux_amd64": sumOf(tb)}
	var busyOnce bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(PeerNodeIDHeader) != "n1" || r.Header.Get("Authorization") != "Bearer pat" {
			http.Error(w, "who", http.StatusForbidden)
			return
		}
		if !busyOnce {
			busyOnce = true
			w.Header().Set("Retry-After", "1")
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		sum := strings.TrimPrefix(r.URL.Path, PublicInternalUpgradeFilesPath)
		for _, b := range [][]byte{sd, tb} {
			if sumOf(b) == sum {
				_, _ = w.Write(b)
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	g.u.patToken = "pat"
	g.u.servers = func() []Member { return []Member{{NodeID: "s1", InternalURL: srv.URL}} }
	g.u.clientFor = func(string) *http.Client { return &http.Client{Timeout: time.Millisecond} }
	g.fence = UpgradeFence{Leader: "lead", Term: 1, Rollout: stepRollout(upgradewire.StateStaging, upgradewire.NodePending, files)}
	req := UpgradeStepRequest{RolloutID: "r1", Step: UpgradeStepStage, Direction: upgradewire.DirectionUpgrade, Version: "v2", Files: files, Source: upgradewire.SourceRelease, Term: 1}
	resp, err := g.u.Step(context.Background(), "lead", req)
	if err != nil || len(resp.Fetched) != 2 {
		t.Fatalf("worker stage = %+v %v", resp, err)
	}
	if len(g.host.fetched) != 0 {
		t.Fatalf("a worker reached the release URL: %v", g.host.fetched)
	}
	// No server holds it: the copy keeps trying until the context ends.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := g.u.copyFromServers(ctx, strings.Repeat("9", 64)); err == nil {
		t.Fatal("copy of a missing file succeeded")
	}
	if _, err := g.u.copyFromServers(ctx, "nope"); !errors.Is(err, nodeupgrade.ErrBadHash) {
		t.Fatalf("bad hash copy = %v", err)
	}
	g.u.servers = func() []Member { return nil }
	if _, err := g.u.copyFromServers(ctx, strings.Repeat("9", 64)); err == nil || !strings.Contains(err.Error(), "no live server") {
		t.Fatalf("copy with no servers = %v", err)
	}
	if _, _, err := g.u.copyFrom(ctx, Member{NodeID: "x"}, strings.Repeat("9", 64)); err == nil {
		t.Fatal("copy from a member without a URL")
	}
}

func writeOpState(t *testing.T, dir, op, phase, errMsg string) {
	t.Helper()
	_ = os.MkdirAll(dir, 0o700)
	b, _ := json.Marshal(map[string]any{"format": 1, "op": op, "version": "v2", "phase": phase, "error": errMsg})
	if err := os.WriteFile(filepath.Join(dir, op+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeNodeApply(t *testing.T) {
	g := newUpgradeNodeRig(t, false)
	sd, tb := []byte("new sandboxd"), []byte("new toolboxd")
	files := map[string]string{"sandboxd_linux_amd64": sumOf(sd), "toolboxd_linux_amd64": sumOf(tb)}
	store := nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(g.paths.StateDir)}
	for _, b := range [][]byte{sd, tb} {
		if _, _, err := store.Put(sumOf(b), bytes.NewReader(b)); err != nil {
			t.Fatal(err)
		}
	}
	g.fence = UpgradeFence{Leader: "lead", Term: 2, Rollout: stepRollout(upgradewire.StateRunning, upgradewire.NodeUpgrading, files)}
	req := UpgradeStepRequest{RolloutID: "r1", Step: UpgradeStepApply, Direction: upgradewire.DirectionUpgrade, Version: "v2", Files: files, Op: stepOp, Term: 2, HealthTimeout: "1m", AllowUnversioned: true}
	resp, err := g.u.Step(context.Background(), "lead", req)
	if err != nil || resp.State != UpgradeNodeStarted || resp.Op != stepOp || len(g.launched) != 1 {
		t.Fatalf("apply = %+v %v", resp, err)
	}
	l := g.launched[0]
	if l.From == "" || l.HealthTimeout != time.Minute || !l.AllowUnversioned || l.Rollback || l.SHA256["sandboxd_linux_amd64"] != sumOf(sd) {
		t.Fatalf("launched %+v", l)
	}
	if got, _ := os.ReadFile(filepath.Join(l.From, "sandboxd_linux_amd64")); !bytes.Equal(got, sd) {
		t.Fatal("the files were not handed to the upgrader")
	}
	// The node's own record answers a repeat: never a second upgrade.
	for phase, want := range map[string]string{"swapping": UpgradeNodeStarted, "done": UpgradeNodeDone, "failed": UpgradeNodeFailed} {
		writeOpState(t, g.paths.StateDir, stepOp, phase, "boom")
		resp, err := g.u.Step(context.Background(), "lead", req)
		if err != nil || resp.State != want || len(g.launched) != 1 {
			t.Fatalf("repeat with op %s = %+v %v", phase, resp, err)
		}
	}
	_ = os.Remove(filepath.Join(g.paths.StateDir, stepOp+".json"))
	// Another upgrade holds the lock: upgrade_running.
	lk, err := os.OpenFile(filepath.Join(g.paths.StateDir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = syscall.Flock(int(lk.Fd()), syscall.LOCK_EX)
	_, _ = lk.WriteAt([]byte("other-op\n"), 0)
	_, err = g.u.Step(context.Background(), "lead", req)
	if stepCode(err) != upgradewire.ErrCodeUpgradeRunning {
		t.Fatalf("apply while locked = %v", err)
	}
	if st := g.u.Status(stepOp); !st.OpRunning || st.OpFound {
		t.Fatalf("status while locked = %+v", st)
	}
	_ = syscall.Flock(int(lk.Fd()), syscall.LOCK_UN)
	_ = lk.Close()
	// Already on the version: 200 done, nothing launched.
	req.Version = version.Version
	g.fence.Rollout.TargetVersion = version.Version
	if resp, err := g.u.Step(context.Background(), "lead", req); err != nil || resp.State != UpgradeNodeDone {
		t.Fatalf("apply of the running version = %+v %v", resp, err)
	}
}

func TestUpgradeNodeRollbackApply(t *testing.T) {
	g := newUpgradeNodeRig(t, false)
	// The node's *.prev is the previous version's file: no copy needed.
	prev := []byte("v1 sandboxd")
	if err := os.WriteFile(g.paths.Sandboxd+".prev", prev, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"sandboxd_linux_amd64": sumOf(prev)}
	r := stepRollout(upgradewire.StateRollingBack, upgradewire.NodeUpgrading, nil)
	r.Direction, r.PrevFiles = upgradewire.DirectionRollback, files
	g.fence = UpgradeFence{Leader: "lead", Term: 1, Rollout: r}
	r.Nodes["n1"].Op = "r1-b0"
	req := UpgradeStepRequest{RolloutID: "r1", Step: UpgradeStepApply, Direction: upgradewire.DirectionRollback, Version: "v1", Files: files, Op: "r1-b0", Term: 1}
	if _, err := g.u.Step(context.Background(), "lead", req); err != nil || len(g.launched) != 1 || !g.launched[0].Rollback || g.launched[0].From == "" {
		t.Fatalf("rollback apply = %v %+v", err, g.launched)
	}
	// No copy anywhere: fall back to the upgrader's own *.prev rollback.
	missing := map[string]string{"sandboxd_linux_amd64": strings.Repeat("7", 64)}
	r.PrevFiles = missing
	g.u.servers = func() []Member { return nil }
	r.Attempt = 1
	req.Files, req.Op = missing, "r1-b1"
	r.Nodes["n1"].Op = "r1-b1"
	saved := materializeTimeout
	materializeTimeout = 20 * time.Millisecond
	defer func() { materializeTimeout = saved }()
	if _, err := g.u.Step(context.Background(), "lead", req); err != nil || len(g.launched) != 2 || g.launched[1].SHA256 != nil || !g.launched[1].Rollback {
		t.Fatalf("fallback rollback = %v %+v", err, g.launched)
	}
	// The leader's earlier call launched the unit but its answer was lost:
	// the running unit answers started, and nothing launches twice.
	r.Attempt = 2
	req.Op = "r1-b2"
	r.Nodes["n1"].Op = "r1-b2"
	g.host.active[nodeupgrade.LaunchUnit("r1-b2")] = true
	if resp, err := g.u.Step(context.Background(), "lead", req); err != nil || resp.State != UpgradeNodeStarted || len(g.launched) != 2 {
		t.Fatalf("apply while its unit runs = %+v %v (%d launches)", resp, err, len(g.launched))
	}
}

// R5b: a server's upgrader runs its own quorum guard before it stops
// sandboxd (cmd/sandboxd serverStopGuard). The node used to switch that
// guard off on every call; now a server keeps it unless the rollout itself
// was applied with allow_downtime. A worker holds no vote, so its guard has
// nothing to check.
func TestUpgradeNodeApplyAllowDowntimeFromTheRollout(t *testing.T) {
	sd, tb := []byte("new sandboxd"), []byte("new toolboxd")
	files := map[string]string{"sandboxd_linux_amd64": sumOf(sd), "toolboxd_linux_amd64": sumOf(tb)}
	cases := []struct {
		name          string
		server        bool
		allowDowntime bool
		want          bool
	}{
		{"server keeps its guard", true, false, false},
		{"server in an allow_downtime rollout", true, true, true},
		{"worker has no vote", false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newUpgradeNodeRig(t, tc.server)
			store := nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(g.paths.StateDir)}
			for _, b := range [][]byte{sd, tb} {
				if _, _, err := store.Put(sumOf(b), bytes.NewReader(b)); err != nil {
					t.Fatal(err)
				}
			}
			r := stepRollout(upgradewire.StateRunning, upgradewire.NodeUpgrading, files)
			r.AllowDowntime = tc.allowDowntime
			g.fence = UpgradeFence{Leader: "lead", Term: 2, Rollout: r}
			req := UpgradeStepRequest{RolloutID: "r1", Step: UpgradeStepApply, Direction: upgradewire.DirectionUpgrade, Version: "v2", Files: files, Op: stepOp, Term: 2}
			if _, err := g.u.Step(context.Background(), "lead", req); err != nil || len(g.launched) != 1 {
				t.Fatalf("apply = %v, %d launches", err, len(g.launched))
			}
			if g.launched[0].AllowDowntime != tc.want {
				t.Fatalf("AllowDowntime = %v, want %v", g.launched[0].AllowDowntime, tc.want)
			}
		})
	}
}

// R12: the files of an apply may take up to materializeTimeout to arrive.
// A stop, a rollback or a new leader that lands meanwhile must stop the
// restart, so the node reads the fence again right before the launch.
func TestUpgradeNodeApplyChecksTheFenceAgainBeforeLaunch(t *testing.T) {
	sd, tb := []byte("new sandboxd"), []byte("new toolboxd")
	files := map[string]string{"sandboxd_linux_amd64": sumOf(sd), "toolboxd_linux_amd64": sumOf(tb)}
	req := UpgradeStepRequest{RolloutID: "r1", Step: UpgradeStepApply, Direction: upgradewire.DirectionUpgrade, Version: "v2", Files: files, Op: stepOp, Term: 2}
	cases := []struct {
		name  string
		later func(f *UpgradeFence)
		code  string
	}{
		{"stopped", func(f *UpgradeFence) { f.Rollout.State = upgradewire.StateStopped }, upgradewire.ErrCodeRolloutConflict},
		{"rolled back", func(f *UpgradeFence) {
			f.Rollout.State, f.Rollout.Direction, f.Rollout.Attempt = upgradewire.StateRollingBack, upgradewire.DirectionRollback, 1
		}, upgradeCodeNotInRecord},
		{"new leader", func(f *UpgradeFence) { f.Leader, f.Term = "lead2", 3 }, upgradeCodeNotLeader},
		{"fence unreadable", nil, upgradeCodeRetry},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newUpgradeNodeRig(t, false)
			store := nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(g.paths.StateDir)}
			for _, b := range [][]byte{sd, tb} {
				if _, _, err := store.Put(sumOf(b), bytes.NewReader(b)); err != nil {
					t.Fatal(err)
				}
			}
			reads := 0
			g.u.fence = func(context.Context, string) (UpgradeFence, error) {
				reads++
				f := UpgradeFence{Leader: "lead", Term: 2, Rollout: stepRollout(upgradewire.StateRunning, upgradewire.NodeUpgrading, files)}
				if reads > 1 {
					if tc.later == nil {
						return UpgradeFence{}, errors.New("no server answered")
					}
					tc.later(&f)
				}
				return f, nil
			}
			_, err := g.u.Step(context.Background(), "lead", req)
			if stepCode(err) != tc.code || len(g.launched) != 0 || reads != 2 {
				t.Fatalf("apply = %v (code %q), %d launches, %d fence reads; want %s, none, 2", err, stepCode(err), len(g.launched), reads, tc.code)
			}
		})
	}
}

func TestUpgradeNodeRefusalsAndFinalize(t *testing.T) {
	g := newUpgradeNodeRig(t, false)
	req := UpgradeStepRequest{RolloutID: "r1", Step: UpgradeStepStage, Direction: upgradewire.DirectionUpgrade, Version: "v2", Term: 1}
	g.u.cfg.RemoteUpgrade = false
	if _, err := g.u.Step(context.Background(), "lead", req); stepCode(err) != upgradewire.ErrCodeRemoteUpgradeDisabled {
		t.Fatalf("remote off = %v", err)
	}
	g.u.cfg.RemoteUpgrade = true
	g.fenceErr = errors.New("no server answered")
	if _, err := g.u.Step(context.Background(), "lead", req); stepCode(err) != upgradeCodeRetry {
		t.Fatalf("fence error = %v", err)
	}
	g.fenceErr = &UpgradeStepError{Status: 404, Code: "x"}
	if _, err := g.u.Step(context.Background(), "lead", req); stepCode(err) != "x" {
		t.Fatalf("fence refusal = %v", err)
	}
	g.fenceErr = nil
	saved := g.u.fence
	g.u.fence = nil
	if _, err := g.u.Step(context.Background(), "lead", req); stepCode(err) != upgradeCodeRetry {
		t.Fatalf("no fence = %v", err)
	}
	g.u.fence = saved
	// finalize runs even with remote upgrade off: it swaps no binary.
	g.u.cfg.RemoteUpgrade = false
	g.fence = UpgradeFence{Leader: "lead", Term: 1, Rollout: stepRollout(upgradewire.StateFinalizing, upgradewire.NodeDone, nil)}
	fin := UpgradeStepRequest{RolloutID: "r1", Step: UpgradeStepFinalize, Direction: upgradewire.DirectionUpgrade, Version: "v2", Term: 1}
	if _, err := g.u.Step(context.Background(), "lead", fin); stepCode(err) != upgradeCodeRetry {
		t.Fatalf("finalize without a store = %v", err)
	}
	g.u.AttachOneWayMigrator(func(context.Context) error { return errors.New("disk") }, false)
	if _, err := g.u.Step(context.Background(), "lead", fin); err == nil || !strings.Contains(err.Error(), "disk") {
		t.Fatalf("finalize failure = %v", err)
	}
	runs := 0
	g.u.AttachOneWayMigrator(func(context.Context) error { runs++; return nil }, false)
	if resp, err := g.u.Step(context.Background(), "lead", fin); err != nil || resp.State != UpgradeNodeMigrated || runs != 1 || !g.u.schemaDone.Load() {
		t.Fatalf("finalize = %+v %v", resp, err)
	}
	var nilNode *upgradeNode
	nilNode.AttachOneWayMigrator(nil, true)
	u := newUpgradeNode(config.Config{}, "x", false, nil)
	u.AttachOneWayMigrator(func(context.Context) error { return nil }, true)
	if !u.schemaDone.Load() {
		t.Fatal("a database with nothing pending is not finished")
	}
}

func TestUpgradeNodeStatus(t *testing.T) {
	g := newUpgradeNodeRig(t, true)
	g.u.appliedIndex = func() uint64 { return 42 }
	writeOpState(t, g.paths.StateDir, "op7", "done", "")
	st := g.u.Status("op7")
	if st.NodeID != "n1" || st.Version != version.Version || st.AppliedIndex != 42 || !st.OpFound || st.OpPhase != "done" || !st.RemoteUpgrade || st.FSMOpsVersion != fsmOpsVersion {
		t.Fatalf("status = %+v", st)
	}
	if st := g.u.Status("missing"); st.OpFound {
		t.Fatalf("missing op = %+v", st)
	}
	g.u.paths = func() (nodeupgrade.Paths, error) { return nodeupgrade.Paths{}, errors.New("no env") }
	if st := g.u.Status("op7"); st.OpFound {
		t.Fatal("status without paths found an op")
	}
	if _, err := g.u.Step(context.Background(), "lead", UpgradeStepRequest{RolloutID: "r1", Step: UpgradeStepFinalize}); err == nil {
		t.Fatal("step without paths")
	}
}

func TestUpgradeNodeHelpers(t *testing.T) {
	if trimFence(nil, "x") != nil {
		t.Fatal("trim nil")
	}
	r := stepRollout(upgradewire.StateRunning, upgradewire.NodePending, nil)
	r.Nodes["n2"] = &RolloutNodeRecord{NodeID: "n2"}
	if got := trimFence(r, "n1"); len(got.Nodes) != 1 || got.Nodes["n1"] == nil || len(r.Nodes) != 2 {
		t.Fatalf("trim = %+v", got.Nodes)
	}
	members := []Member{
		{NodeID: "lead", Alive: true, InternalURL: "u", Role: "server"},
		{NodeID: "b", Alive: true, InternalURL: "u", Role: "server"},
		{NodeID: "a", Alive: true, InternalURL: "u", Role: "server"},
		{NodeID: "dead", Alive: false, InternalURL: "u", Role: "server"},
		{NodeID: "w", Alive: true, InternalURL: "u", Role: "worker"},
		{NodeID: "self", Alive: true, InternalURL: "u", Role: "server"},
	}
	got := serversForCopy(members, "self", "lead")
	if len(got) != 3 || got[0].NodeID != "a" || got[1].NodeID != "b" || got[2].NodeID != "lead" {
		t.Fatalf("servers for copy = %+v", got)
	}
	body, _ := json.Marshal(upgradewire.ErrorResponse{Error: "c", Reason: "r"})
	if err := decodeUpgradeStepError(409, body); stepCode(err) != "c" {
		t.Fatalf("decode = %v", err)
	}
	if err := decodeUpgradeStepError(500, []byte("plain")); err.Error() != "plain" {
		t.Fatalf("decode plain = %v", err)
	}
	if (&UpgradeStepError{Code: "c", Reason: "r"}).Error() != "c: r" || (&UpgradeStepError{Reason: "r"}).Error() != "r" {
		t.Fatal("error text")
	}
}
