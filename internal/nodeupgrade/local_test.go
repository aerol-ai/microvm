package nodeupgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// localRig is a Local over a temp state directory, a fake systemd and a
// clock the test moves.
type localRig struct {
	t     *testing.T
	l     *Local
	host  *fakeHost
	clock time.Time
}

func newLocalRig(t *testing.T) *localRig {
	t.Helper()
	r := &localRig{t: t, clock: time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)}
	dir := t.TempDir()
	r.host = newFakeHost(t, &Paths{})
	r.l = &Local{
		StateDir:       filepath.Join(dir, "upgrade"),
		Host:           r.host,
		Binary:         func() (string, error) { return "/usr/local/bin/sandboxd", nil },
		RunningVersion: "v0.6.12",
		Now:            func() time.Time { return r.clock },
	}
	return r
}

// asset is this machine's name for a release file, so Launch's own check
// (which reads runtime's platform) agrees with the rig's.
func asset(name string) string { return name + "_" + runtime.GOOS + "_" + runtime.GOARCH }

func otherArch() string {
	if runtime.GOARCH == "amd64" {
		return "arm64"
	}
	return "amd64"
}

var (
	sumA = strings.Repeat("a", 64)
	sumB = strings.Repeat("b", 64)
	sumC = strings.Repeat("c", 64)
)

func (r *localRig) launches() []string {
	var out []string
	for _, c := range strings.Split(r.host.callLog(), "\n") {
		if strings.HasPrefix(c, "run systemd-run ") {
			out = append(out, c)
		}
	}
	return out
}

func (r *localRig) writeState(op, version string, phase Phase, started time.Time) {
	r.t.Helper()
	if err := os.MkdirAll(r.l.StateDir, 0o700); err != nil {
		r.t.Fatal(err)
	}
	st := &State{Format: stateFormat, Op: op, Version: version, FromVersion: "v0.6.11", Phase: phase, StartedAt: started}
	if err := st.save(r.l.StateDir, started); err != nil {
		r.t.Fatal(err)
	}
}

func releaseRequest(version string) upgradewire.NodeUpgradeRequest {
	return upgradewire.NodeUpgradeRequest{Version: version, Source: upgradewire.SourceRelease, Files: map[string]string{
		asset("sandboxd"): sumA,
		asset("toolboxd"): sumB,
		"release.json":    sumC,
		"sandboxd_" + runtime.GOOS + "_" + otherArch(): sumC,
		"toolboxd_" + runtime.GOOS + "_" + otherArch(): sumC,
	}}
}

func TestLocalStartLaunchesOnceAndRetriesGetTheSameOp(t *testing.T) {
	r := newLocalRig(t)
	ctx := context.Background()
	resp, started, err := r.l.Start(ctx, releaseRequest("v0.6.13"))
	if err != nil || !started || resp.State != upgradewire.NodeOpPending || resp.Version != "v0.6.13" || resp.From != "v0.6.12" || resp.Op == "" {
		t.Fatalf("start = %+v %v %v", resp, started, err)
	}
	launches := r.launches()
	if len(launches) != 1 || !strings.Contains(launches[0], "--unit=aerolvm-upgrade-"+resp.Op) ||
		!strings.Contains(launches[0], asset("sandboxd")+"="+sumA) || strings.Contains(launches[0], otherArch()) ||
		!strings.Contains(launches[0], "release.json="+sumC) || strings.Contains(launches[0], "--from") {
		t.Fatalf("launch = %q", launches)
	}
	// The upgrader has written nothing yet: GET says pending.
	if got, ok := r.l.Latest(ctx); !ok || got.Op != resp.Op || got.State != upgradewire.NodeOpPending {
		t.Fatalf("latest = %+v %v", got, ok)
	}
	// A retried POST for the same version gets the same op, no second launch.
	again, started, err := r.l.Start(ctx, releaseRequest("v0.6.13"))
	if err != nil || !started || again.Op != resp.Op || len(r.launches()) != 1 {
		t.Fatalf("retry = %+v %v %v (%d launches)", again, started, err, len(r.launches()))
	}
	// Another version while it runs is refused.
	var running *ErrRunning
	if _, _, err := r.l.Start(ctx, releaseRequest("v0.6.14")); !errors.As(err, &running) || running.Op != resp.Op || running.Version != "v0.6.13" {
		t.Fatalf("other version = %v", err)
	}
	// The upgrader writes its record: GET reads it.
	r.clock = r.clock.Add(time.Second)
	r.writeState(resp.Op, "v0.6.13", PhaseSwapping, r.clock)
	if got, _ := r.l.Latest(ctx); got.State != string(PhaseSwapping) || got.From != "v0.6.11" {
		t.Fatalf("latest with a record = %+v", got)
	}
	if again, started, err := r.l.Start(ctx, releaseRequest("v0.6.13")); err != nil || !started || again.State != string(PhaseSwapping) {
		t.Fatalf("retry mid-swap = %+v %v %v", again, started, err)
	}
	// Once it is done the node may start another.
	r.writeState(resp.Op, "v0.6.13", PhaseDone, r.clock)
	if _, started, err := r.l.Start(ctx, releaseRequest("v0.6.14")); err != nil || !started || len(r.launches()) != 2 {
		t.Fatalf("after done = %v %v", started, err)
	}
}

func TestLocalPendingThatNeverWroteARecordFails(t *testing.T) {
	r := newLocalRig(t)
	ctx := context.Background()
	resp, _, err := r.l.Start(ctx, releaseRequest("v0.6.13"))
	if err != nil {
		t.Fatal(err)
	}
	// systemd still runs the unit: still starting, even past the grace.
	r.host.active[LaunchUnit(resp.Op)] = true
	r.clock = r.clock.Add(time.Minute)
	if got, _ := r.l.Latest(ctx); got.State != upgradewire.NodeOpPending {
		t.Fatalf("unit active = %+v", got)
	}
	// The unit is gone and no record appeared: it failed early.
	r.host.active[LaunchUnit(resp.Op)] = false
	got, ok := r.l.Latest(ctx)
	if !ok || got.State != upgradewire.NodeOpFailed || !strings.Contains(got.Error, "journalctl -u aerolvm-upgrade-"+resp.Op) {
		t.Fatalf("vanished = %+v", got)
	}
	// It no longer blocks a new upgrade.
	if _, started, err := r.l.Start(ctx, releaseRequest("v0.6.14")); err != nil || !started {
		t.Fatalf("after vanished = %v %v", started, err)
	}
}

func TestLocalAlreadyRunningIsANoop(t *testing.T) {
	r := newLocalRig(t)
	ctx := context.Background()
	if _, ok := r.l.Latest(ctx); ok {
		t.Fatal("a node with no operation answered one")
	}
	resp, started, err := r.l.Start(ctx, releaseRequest("v0.6.12"))
	if err != nil || started || resp.State != upgradewire.NodeOpDone || resp.Op != "" || resp.Version != "v0.6.12" || len(r.launches()) != 0 {
		t.Fatalf("same version, no op = %+v %v %v", resp, started, err)
	}
	// With the op that installed it on record, that op is the answer.
	r.writeState("op-1", "v0.6.12", PhaseDone, r.clock)
	resp, started, err = r.l.Start(ctx, releaseRequest("v0.6.12"))
	if err != nil || started || resp.Op != "op-1" || resp.From != "v0.6.11" {
		t.Fatalf("same version, with op = %+v %v %v", resp, started, err)
	}
	if got, ok := r.l.Latest(ctx); !ok || got.Op != "op-1" || got.State != upgradewire.NodeOpDone {
		t.Fatalf("latest = %+v", got)
	}
}

func TestLocalRefusesWhileTheLockIsHeld(t *testing.T) {
	r := newLocalRig(t)
	r.writeState("op-hand", "v0.6.20", PhaseStaging, r.clock)
	lk, err := acquireLock(r.l.StateDir, "op-hand")
	if err != nil {
		t.Fatal(err)
	}
	var running *ErrRunning
	if _, _, err := r.l.Start(context.Background(), releaseRequest("v0.6.13")); !errors.As(err, &running) || running.Op != "op-hand" || running.Version != "v0.6.20" ||
		!strings.Contains(err.Error(), "op-hand (to v0.6.20)") {
		t.Fatalf("held = %v", err)
	}
	lk.release()
	if _, started, err := r.l.Start(context.Background(), releaseRequest("v0.6.13")); err != nil || !started {
		t.Fatalf("released = %v %v", started, err)
	}
}

func TestLocalUploadSource(t *testing.T) {
	r := newLocalRig(t)
	ctx := context.Background()
	sandboxd, toolboxd := []byte("new sandboxd"), []byte("new toolboxd")
	req := upgradewire.NodeUpgradeRequest{Version: "v0.6.13", Source: upgradewire.SourceUpload,
		Files: map[string]string{asset("sandboxd"): sum(sandboxd), asset("toolboxd"): sum(toolboxd)}}
	var missing *ErrFilesMissing
	if _, _, err := r.l.Start(ctx, req); !errors.As(err, &missing) || len(missing.Names) != 2 || missing.Names[0] != asset("sandboxd") ||
		!strings.Contains(err.Error(), upgradewire.NodeUpgradeFilesPath) {
		t.Fatalf("nothing uploaded = %v", err)
	}
	if r.l.HasFile(sum(sandboxd)) {
		t.Fatal("HasFile before upload")
	}
	for _, b := range [][]byte{sandboxd, toolboxd} {
		if created, size, err := r.l.PutFile(sum(b), strings.NewReader(string(b))); err != nil || !created || size != int64(len(b)) {
			t.Fatalf("put = %v %d %v", created, size, err)
		}
	}
	if created, _, err := r.l.PutFile(sum(sandboxd), strings.NewReader("ignored")); err != nil || created {
		t.Fatalf("second put = %v %v", created, err)
	}
	if _, _, err := r.l.PutFile(sumA, strings.NewReader("not a")); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("mismatch = %v", err)
	}
	resp, started, err := r.l.Start(ctx, req)
	if err != nil || !started {
		t.Fatalf("start = %v %v", started, err)
	}
	from := filepath.Join(r.l.StateDir, fromDirName, resp.Op)
	if got := readFile(t, filepath.Join(from, asset("sandboxd"))); got != string(sandboxd) {
		t.Fatalf("materialized sandboxd = %q", got)
	}
	if l := r.launches(); len(l) != 1 || !strings.Contains(l[0], "--from "+from) {
		t.Fatalf("launch = %q", l)
	}
}

func TestLocalStartCleansUpWhenLaunchFails(t *testing.T) {
	ctx := context.Background()
	body := []byte("sandboxd")
	tool := []byte("toolboxd")
	req := upgradewire.NodeUpgradeRequest{Version: "v0.6.13", Source: upgradewire.SourceUpload,
		Files: map[string]string{asset("sandboxd"): sum(body), asset("toolboxd"): sum(tool)}}
	for _, tc := range []struct {
		name   string
		mutate func(*localRig)
		want   string
	}{
		{"no binary", func(r *localRig) { r.l.Binary = func() (string, error) { return "", errors.New("no /proc") } }, "find the sandboxd binary"},
		{"systemd-run fails", func(r *localRig) { r.l.Host = &runFailHost{Host: r.host} }, "systemd-run"},
		{"relative binary", func(r *localRig) { r.l.Binary = func() (string, error) { return "sandboxd", nil } }, "absolute path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newLocalRig(t)
			for _, b := range [][]byte{body, tool} {
				if _, _, err := r.l.PutFile(sum(b), strings.NewReader(string(b))); err != nil {
					t.Fatal(err)
				}
			}
			tc.mutate(r)
			if _, _, err := r.l.Start(ctx, req); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v", err)
			}
			entries, _ := os.ReadDir(filepath.Join(r.l.StateDir, fromDirName))
			if len(entries) != 0 {
				t.Fatalf("left %d per-op directories", len(entries))
			}
			if _, ok := r.l.Latest(ctx); ok {
				t.Fatal("a failed launch left a pending op")
			}
		})
	}
}

type runFailHost struct{ Host }

func (h *runFailHost) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte("Unit already exists"), errors.New("exit status 1")
}

func TestLocalRejectsBadRequests(t *testing.T) {
	r := newLocalRig(t)
	good := releaseRequest("v0.6.13").Files
	with := func(mut func(*upgradewire.NodeUpgradeRequest)) upgradewire.NodeUpgradeRequest {
		req := upgradewire.NodeUpgradeRequest{Version: "v0.6.13", Source: upgradewire.SourceRelease, Files: map[string]string{}}
		for k, v := range good {
			req.Files[k] = v
		}
		mut(&req)
		return req
	}
	for _, tc := range []struct {
		name string
		req  upgradewire.NodeUpgradeRequest
		want string
	}{
		{"bad version", with(func(q *upgradewire.NodeUpgradeRequest) { q.Version = "../x" }), "not a release tag"},
		{"bad source", with(func(q *upgradewire.NodeUpgradeRequest) { q.Source = "ftp" }), `source "ftp"`},
		{"bad timeout", with(func(q *upgradewire.NodeUpgradeRequest) { q.HealthTimeout = "soon" }), "health_timeout"},
		{"negative timeout", with(func(q *upgradewire.NodeUpgradeRequest) { q.HealthTimeout = "-1s" }), "health_timeout"},
		{"bad hash", with(func(q *upgradewire.NodeUpgradeRequest) { q.Files[asset("sandboxd")] = "ABC" }), "lower-case hex"},
		{"not a release file", with(func(q *upgradewire.NodeUpgradeRequest) { q.Files["evil.sh"] = sumA }), "not a release file"},
		{"other platform only", upgradewire.NodeUpgradeRequest{Version: "v0.6.13",
			Files: map[string]string{"sandboxd_" + runtime.GOOS + "_" + otherArch(): sumA}}, "no file for this node's platform"},
		{"upload without files", upgradewire.NodeUpgradeRequest{Version: "v0.6.13", Source: upgradewire.SourceUpload, Rollback: true}, "needs the uploaded files"},
		{"no toolboxd", with(func(q *upgradewire.NodeUpgradeRequest) { delete(q.Files, asset("toolboxd")) }), "no toolboxd"},
		{"no files, no rollback", upgradewire.NodeUpgradeRequest{Version: "v0.6.13"}, "--sha256"},
	} {
		if _, _, err := r.l.Start(context.Background(), tc.req); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want usage error with %q", tc.name, err, tc.want)
		}
	}
	// A rollback needs no files and takes a health timeout.
	if _, started, err := r.l.Start(context.Background(), upgradewire.NodeUpgradeRequest{Version: "v0.6.11", Rollback: true, HealthTimeout: "3m"}); err != nil || !started {
		t.Fatalf("rollback = %v %v", started, err)
	}
	if l := r.launches(); len(l) != 1 || !strings.Contains(l[0], "--rollback") || !strings.Contains(l[0], "--health-timeout 3m0s") {
		t.Fatalf("rollback launch = %q", l)
	}
	if r.l.Platform() != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("platform = %s", r.l.Platform())
	}
}

func TestLocalPrune(t *testing.T) {
	r := newLocalRig(t)
	old := []byte("old upload")
	fresh := []byte("fresh upload")
	for _, b := range [][]byte{old, fresh} {
		if _, _, err := r.l.PutFile(sum(b), strings.NewReader(string(b))); err != nil {
			t.Fatal(err)
		}
	}
	store := r.l.store()
	oldPath, _ := store.Path(sum(old))
	longAgo := time.Now().Add(-2 * UploadMaxAge)
	if err := os.Chtimes(oldPath, longAgo, longAgo); err != nil {
		t.Fatal(err)
	}
	// Per-op directories: a finished one and an unfinished one, both old,
	// and a fresh one.
	base := filepath.Join(r.l.StateDir, fromDirName)
	for _, op := range []string{"op-done", "op-busy", "op-new"} {
		if err := os.MkdirAll(filepath.Join(base, op), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r.writeState("op-done", "v0.6.13", PhaseDone, r.clock)
	r.writeState("op-busy", "v0.6.13", PhaseSwapping, r.clock)
	for _, op := range []string{"op-done", "op-busy"} {
		if err := os.Chtimes(filepath.Join(base, op), longAgo, longAgo); err != nil {
			t.Fatal(err)
		}
	}
	r.l.Now = time.Now
	r.l.prune()
	if store.Has(sum(old)) || !store.Has(sum(fresh)) {
		t.Fatalf("store after prune: old=%v fresh=%v", store.Has(sum(old)), store.Has(sum(fresh)))
	}
	for op, want := range map[string]bool{"op-done": false, "op-busy": true, "op-new": true} {
		if _, err := os.Stat(filepath.Join(base, op)); (err == nil) != want {
			t.Errorf("%s kept = %v, want %v", op, err == nil, want)
		}
	}
	// A HEAD renews an upload's hour.
	freshPath, _ := store.Path(sum(fresh))
	if err := os.Chtimes(freshPath, longAgo, longAgo); err != nil {
		t.Fatal(err)
	}
	if !r.l.HasFile(sum(fresh)) {
		t.Fatal("HasFile lost the file")
	}
	r.l.prune()
	if !store.Has(sum(fresh)) {
		t.Fatal("a file confirmed by HEAD was pruned")
	}
}

func TestLocalErrorsRead(t *testing.T) {
	if (&ErrRunning{}).Error() != "another upgrade is running on this node" {
		t.Fatal((&ErrRunning{}).Error())
	}
	if got := (&ErrFilesMissing{Names: []string{"a", "b"}}).Error(); !strings.HasPrefix(got, "these files were not uploaded: a, b") {
		t.Fatal(got)
	}
}
