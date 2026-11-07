package nodeupgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/release"
)

// The whole of §6.3 on a healthy node: stage, verify, stop, back up, swap
// toolboxd, caddy and sandboxd in that order keeping *.prev, start, wait
// for the new version.
func TestUpgradeSwapsEveryFileAndKeepsThePreviousOnes(t *testing.T) {
	old, next := newRelease("v0.6.11"), newRelease("v0.6.12").withMeta(nil)
	r := newRig(t, old)
	st, err := r.u.Run(context.Background(), r.from(next))
	if err != nil {
		t.Fatalf("Run: %v\n%s\ncalls:\n%s", err, r.out, r.host.callLog())
	}
	if st.Phase != PhaseDone || st.Result != ResultUpgraded || st.FromVersion != "v0.6.11" {
		t.Fatalf("state = %s/%s from %q, want done/upgraded from v0.6.11", st.Phase, st.Result, st.FromVersion)
	}
	r.assertInstalled(next, next.caddy)
	r.assertPrev(r.paths.Sandboxd, old.sandboxd)
	r.assertPrev(r.paths.Toolboxd, old.toolboxd)
	r.assertPrev(r.paths.Caddy, old.caddy)
	r.order("stop sandboxd", "restart caddy", "restart sandboxd")
	if got := readFile(t, st.BackupPath); got != "db before the upgrade" {
		t.Fatalf("backup = %q", got)
	}
	if filepath.Dir(st.BackupPath) != r.paths.StateDir {
		t.Fatalf("backup %s is not in the state directory", st.BackupPath)
	}
	if _, err := os.Stat(filepath.Join(r.paths.StateDir, next.version)); !os.IsNotExist(err) {
		t.Fatalf("the staged files were not cleaned up: %v", err)
	}
	// The record on disk is the one returned.
	disk, err := LoadState(r.paths.StateDir, st.Op)
	if err != nil {
		t.Fatal(err)
	}
	if disk.Phase != PhaseDone || len(disk.Files) != 4 {
		t.Fatalf("record on disk = %+v", disk)
	}
	for _, f := range disk.Files {
		if f.Path != "" && (!f.Changed || f.PrevSHA256 == "") {
			t.Fatalf("file %s not recorded as changed with its previous hash: %+v", f.Role, f)
		}
	}
	// The release's install.sh hash matches no recorded host setup, but the
	// upgrader's own fallback is empty: host apply ran.
	if st.HostApply != HostApplyDone {
		t.Fatalf("host apply = %s", st.HostApply)
	}
	r.order("run sandboxd host apply --env-file "+r.paths.EnvFile, "restart sandboxd")
	if got := InstalledHostSetup(r.paths.StateDir, ""); got != next.meta.HostSetupSHA256 {
		t.Fatalf("recorded host setup = %q, want the release's", got)
	}
}

// Same files already installed: exit 0, nothing stopped or written but the
// record (§6.3: "returns 200 and does nothing").
func TestUpgradeToTheInstalledVersionIsANoop(t *testing.T) {
	cur := newRelease("v0.6.12")
	r := newRig(t, cur)
	st, err := r.u.Run(context.Background(), r.from(cur))
	if err != nil {
		t.Fatal(err)
	}
	if st.Result != ResultNoop || st.Phase != PhaseDone {
		t.Fatalf("state = %s/%s", st.Phase, st.Result)
	}
	r.never("stop sandboxd")
	r.never("restart")
	if _, err := os.Stat(r.paths.Sandboxd + ".prev"); !os.IsNotExist(err) {
		t.Fatal("a noop kept a .prev")
	}
}

// Caddy restarts only when its file changed, and only an active Caddy.
func TestUpgradeRestartsCaddyOnlyWhenItChanged(t *testing.T) {
	old := newRelease("v0.6.11")
	next := newRelease("v0.6.12")
	next.caddy = old.caddy
	r := newRig(t, old)
	st, err := r.u.Run(context.Background(), r.from(next))
	if err != nil {
		t.Fatal(err)
	}
	if st.CaddyRestart || st.file(roleCaddy).Changed {
		t.Fatalf("caddy restart planned for an unchanged file: %+v", st)
	}
	r.never("restart caddy")
	if _, err := os.Stat(r.paths.Caddy + ".prev"); !os.IsNotExist(err) {
		t.Fatal("an unchanged caddy was swapped")
	}

	// Changed but inactive: swapped, not restarted.
	r2 := newRig(t, old)
	r2.host.active[caddyUnit] = false
	if _, err := r2.u.Run(context.Background(), r2.from(newRelease("v0.6.12"))); err != nil {
		t.Fatal(err)
	}
	r2.never("restart caddy")
	r2.assertPrev(r2.paths.Caddy, old.caddy)
}

// A node with no Caddy (local mode) skips a caddy file in the request.
func TestUpgradeSkipsCaddyOnANodeWithoutIt(t *testing.T) {
	old := newRelease("v0.6.11")
	r := newRig(t, old)
	r.u.Paths.Caddy = ""
	st, err := r.u.Run(context.Background(), r.from(newRelease("v0.6.12")))
	if err != nil {
		t.Fatal(err)
	}
	if st.file(roleCaddy) != nil {
		t.Fatal("caddy is in the op of a node without Caddy")
	}
	if !strings.Contains(r.out.String(), "this node runs no Caddy") {
		t.Fatalf("output: %s", r.out)
	}
}

// Files from SB_RELEASE_URL: <base>/<version>/<asset>, streamed and hashed.
func TestUpgradeDownloadsFromTheReleaseURL(t *testing.T) {
	r := newRig(t, newRelease("v0.6.11"))
	next := newRelease("v0.6.12")
	req := r.served(next)
	if _, err := r.u.Run(context.Background(), req); err != nil {
		t.Fatalf("Run: %v\n%s", err, r.out)
	}
	want := r.paths.ReleaseURL + "/v0.6.12/sandboxd_linux_amd64"
	found := false
	for _, u := range r.host.fetches {
		found = found || u == want
	}
	if !found {
		t.Fatalf("fetched %v, want %s among them", r.host.fetches, want)
	}
	r.assertInstalled(next, next.caddy)
}

// Every refusal before anything stops: the node keeps running the old set
// and the record says why.
func TestUpgradeRefusesBeforeAnythingStops(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *rig) Request
		want  string
	}{
		{name: "downgrade", setup: func(r *rig) Request { return r.from(newRelease("v0.6.10")) }, want: "a downgrade is a rollback"},
		{name: "unversioned target", setup: func(r *rig) Request { return r.from(newRelease("itest-abc")) }, want: "--allow-unversioned"},
		{name: "unknown installed version", setup: func(r *rig) Request {
			writeFile(r.t, r.paths.Sandboxd, []byte("an old sandboxd with no version command\n"))
			r.host.running = ""
			return r.from(newRelease("v0.6.12"))
		}, want: "cannot tell which version is installed"},
		{name: "hash mismatch", setup: func(r *rig) Request {
			req := r.from(newRelease("v0.6.12"))
			req.SHA256["toolboxd_linux_amd64"] = strings.Repeat("b", 64)
			return req
		}, want: "want " + strings.Repeat("b", 64)},
		{name: "missing download", setup: func(r *rig) Request {
			req := r.served(newRelease("v0.6.12"))
			delete(r.host.fetch, r.paths.ReleaseURL+"/v0.6.12/toolboxd_linux_amd64")
			return req
		}, want: "404"},
		{name: "no systemd-run", setup: func(r *rig) Request {
			r.host.missing["systemd-run"] = true
			return r.from(newRelease("v0.6.12"))
		}, want: "systemd-run not found"},
		{name: "no free space", setup: func(r *rig) Request {
			r.host.free[filepath.Join(r.paths.StateDir, "v0.6.12")] = 10 << 20
			return r.from(newRelease("v0.6.12"))
		}, want: "not enough free space"},
		{name: "free space unknown", setup: func(r *rig) Request {
			r.host.freeErr = errors.New("statfs: no")
			return r.from(newRelease("v0.6.12"))
		}, want: "statfs: no"},
		{name: "staged sandboxd is another version", setup: func(r *rig) Request {
			rel := newRelease("v0.6.12")
			rel.sandboxd = fakeBinary("v0.6.13", true)
			return r.from(rel)
		}, want: "the staged sandboxd is v0.6.13, not v0.6.12"},
		{name: "release.json for another version", setup: func(r *rig) Request {
			return r.from(newRelease("v0.6.12").withMeta(func(m *release.Metadata) { m.Version = "v0.6.13"; m.UpgradeFromMin = "v0.6.0" }))
		}, want: "release.json describes v0.6.13"},
		{name: "below upgrade_from_min", setup: func(r *rig) Request {
			return r.from(newRelease("v0.6.12").withMeta(func(m *release.Metadata) { m.UpgradeFromMin = "v0.6.12" }))
		}, want: "cannot upgrade straight to"},
		{name: "host changes need the network", setup: func(r *rig) Request {
			return r.from(newRelease("v0.6.12").withMeta(func(m *release.Metadata) { m.HostSetupNeedsNetwork = true }))
		}, want: "re-run install.sh"},
		{name: "a file too large", setup: func(r *rig) Request {
			old := maxFileBytes
			maxFileBytes = 8
			r.t.Cleanup(func() { maxFileBytes = old })
			return r.from(newRelease("v0.6.12"))
		}, want: "larger than 8 bytes"},
		{name: "the stop guard refuses", setup: func(r *rig) Request {
			r.u.BeforeStop = func(_ context.Context, allow bool) error {
				if allow {
					return errors.New("allowDowntime should be false")
				}
				return errors.New("refusing to stop sandboxd: quorum")
			}
			return r.from(newRelease("v0.6.12"))
		}, want: "refusing to stop sandboxd: quorum"},
		{name: "a release.json that does not parse", setup: func(r *rig) Request {
			req := r.from(newRelease("v0.6.12"))
			writeFile(r.t, filepath.Join(req.From, "release.json"), []byte("{"))
			req.SHA256["release.json"] = sum([]byte("{"))
			return req
		}, want: "decode release.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := newRelease("v0.6.11")
			r := newRig(t, old)
			st, err := r.u.Run(context.Background(), tc.setup(r))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q\n%s", err, tc.want, r.out)
			}
			r.never("stop sandboxd")
			if st != nil {
				if st.Phase != PhaseFailed || !strings.Contains(st.Error, tc.want) {
					t.Fatalf("record = %s %q", st.Phase, st.Error)
				}
				disk, lerr := LoadState(r.paths.StateDir, st.Op)
				if lerr != nil || disk.Phase != PhaseFailed {
					t.Fatalf("record on disk = %+v, %v", disk, lerr)
				}
			}
			if got := readFile(t, r.paths.Toolboxd); got != string(old.toolboxd) {
				t.Fatalf("toolboxd changed: %q", got)
			}
		})
	}
}

// The checks that let a request through on purpose.
func TestUpgradeAllowsWhatItWasToldTo(t *testing.T) {
	t.Run("rollback allows a downgrade", func(t *testing.T) {
		r := newRig(t, newRelease("v0.6.11"))
		req := r.from(newRelease("v0.6.10"))
		req.Rollback = true
		if _, err := r.u.Run(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("--allow-unversioned takes a test build", func(t *testing.T) {
		r := newRig(t, newRelease("v0.6.11"))
		req := r.from(newRelease("itest-abc"))
		req.AllowUnversioned = true
		st, err := r.u.Run(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if st.FromVersion != "v0.6.11" {
			t.Fatalf("from = %q", st.FromVersion)
		}
	})
	t.Run("an old binary is asked over /health, never run", func(t *testing.T) {
		old := newRelease("v0.6.10")
		old.sandboxd = fakeBinary("v0.6.10", false)
		r := newRig(t, old)
		st, err := r.u.Run(context.Background(), r.from(newRelease("v0.6.12")))
		if err != nil {
			t.Fatal(err)
		}
		if st.FromVersion != "v0.6.10" {
			t.Fatalf("from = %q", st.FromVersion)
		}
		if strings.Contains(r.host.callLog(), "run sandboxd version") && !strings.Contains(r.host.callLog(), "run sandboxd_linux_amd64 version") {
			t.Fatalf("the installed binary without `sandboxd version` was run:\n%s", r.host.callLog())
		}
		for _, c := range strings.Split(r.host.callLog(), "\n") {
			if c == "run sandboxd version -o json" {
				t.Fatalf("the installed old binary was run: %s", r.host.callLog())
			}
		}
	})
	t.Run("a stopped sandboxd is left stopped", func(t *testing.T) {
		r := newRig(t, newRelease("v0.6.11"))
		r.host.active[sandboxdUnit] = false
		r.host.running = ""
		req := r.from(newRelease("v0.6.12"))
		req.AllowUnversioned = true
		st, err := r.u.Run(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if st.WasActive {
			t.Fatal("WasActive for a stopped unit")
		}
		r.never("stop sandboxd")
		r.never("restart sandboxd")
		r.assertPrev(r.paths.Sandboxd, newRelease("v0.6.11").sandboxd)
	})
}

// Host apply runs only when the target's install.sh differs from the one
// that set the host up, never on a rollback, and is skipped when the caller
// applied it already.
func TestUpgradeHostApplyDecision(t *testing.T) {
	setup := strings.Repeat("c", 64)
	cases := []struct {
		name      string
		recorded  string // host-setup.sha256 on disk
		self      string // the upgrader's own install.sh hash
		skip      bool
		rollback  bool
		noMeta    bool
		want      string
		wantRuns  bool
		wantSaved string
	}{
		{name: "differs from the recorded setup", recorded: strings.Repeat("d", 64), want: HostApplyDone, wantRuns: true, wantSaved: setup},
		{name: "matches the recorded setup", recorded: setup, want: HostApplyNotNeeded, wantSaved: setup},
		{name: "matches the upgrader's own when none is recorded", self: setup, want: HostApplyNotNeeded},
		{name: "the caller applied it", recorded: strings.Repeat("d", 64), skip: true, want: HostApplySkipped, wantSaved: setup},
		{name: "a rollback never applies", recorded: strings.Repeat("d", 64), rollback: true, want: HostApplyNotNeeded, wantSaved: strings.Repeat("d", 64)},
		{name: "no release.json", noMeta: true, want: HostApplyNotNeeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, newRelease("v0.6.11"))
			r.u.SelfHostSetupSHA256 = tc.self
			if tc.recorded != "" {
				if err := RecordHostSetup(r.paths.StateDir, tc.recorded); err != nil {
					t.Fatal(err)
				}
			}
			rel := newRelease("v0.6.12")
			if !tc.noMeta {
				rel = rel.withMeta(func(m *release.Metadata) { m.HostSetupSHA256 = setup })
			}
			req := r.from(rel)
			req.SkipHostApply, req.Rollback = tc.skip, tc.rollback
			st, err := r.u.Run(context.Background(), req)
			if err != nil {
				t.Fatalf("Run: %v\n%s", err, r.out)
			}
			if st.HostApply != tc.want {
				t.Fatalf("host apply = %s, want %s", st.HostApply, tc.want)
			}
			if ran := strings.Contains(r.host.callLog(), "host apply"); ran != tc.wantRuns {
				t.Fatalf("host apply ran = %v; calls:\n%s", ran, r.host.callLog())
			}
			if got := InstalledHostSetup(r.paths.StateDir, ""); got != tc.wantSaved {
				t.Fatalf("recorded setup = %q, want %q", got, tc.wantSaved)
			}
		})
	}
}

// The egress gateway restarts only when the target no longer speaks the
// running gateway's protocol.
func TestUpgradeGatewayRestartDecision(t *testing.T) {
	cases := []struct {
		name     string
		active   bool
		protocol int
		probeErr error
		speaks   []int
		noMeta   bool
		want     bool
	}{
		{name: "still spoken", active: true, protocol: 1, speaks: []int{1, 2}, want: false},
		{name: "no longer spoken", active: true, protocol: 1, speaks: []int{2, 3}, want: true},
		{name: "no gateway running", active: false, protocol: 1, speaks: []int{2, 3}, want: false},
		{name: "gateway cannot be asked", active: true, probeErr: errors.New("refused"), speaks: []int{2, 3}, want: false},
		{name: "no release.json", active: true, protocol: 1, noMeta: true, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, newRelease("v0.6.11"))
			r.host.active[gatewayUnit] = tc.active
			r.host.gateway, r.host.gatewayErr = tc.protocol, tc.probeErr
			rel := newRelease("v0.6.12")
			if !tc.noMeta {
				rel = rel.withMeta(func(m *release.Metadata) { m.EgressGatewayProtocol = tc.speaks })
			}
			r.u.SelfHostSetupSHA256 = strings.Repeat("a", 64) // no host apply
			st, err := r.u.Run(context.Background(), r.from(rel))
			if err != nil {
				t.Fatalf("Run: %v\n%s", err, r.out)
			}
			if st.GatewayRestart != tc.want || st.GatewayRestarted != tc.want {
				t.Fatalf("gateway restart = %v/%v, want %v", st.GatewayRestart, st.GatewayRestarted, tc.want)
			}
			if tc.want {
				r.order("stop sandboxd", "restart "+gatewayUnit, "restart sandboxd")
			} else {
				r.never("restart " + gatewayUnit)
			}
			if !tc.active {
				r.never("probe gateway")
			}
		})
	}
}

// §6.3 step 9: the database backup comes back only when the new binary
// never got past opening its store; once it did (the marker), never. The
// *.prev files always come back, and the old sandboxd is started again.
func TestUpgradeFailureRestoresTheBackupOnlyWhenTheStoreNeverOpened(t *testing.T) {
	cases := []struct {
		name        string
		newSandboxd []byte
		rollback    bool
		wantRestore bool
	}{
		{name: "new binary dies before its store opens", newSandboxd: fakeBinary("v0.6.12", true, "BROKEN"), wantRestore: true},
		{name: "new binary opens its store then fails", newSandboxd: fakeBinary("v0.6.12", true, "UNHEALTHY"), wantRestore: false},
		{name: "a rollback never restores", newSandboxd: fakeBinary("v0.6.10", false, "BROKEN"), rollback: true, wantRestore: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := newRelease("v0.6.11")
			r := newRig(t, old)
			// The failed boot wrote to the database; a stale marker from
			// the old binary's boot must not count.
			if err := WriteStoreOpenedMarker(r.paths.DBPath, "v0.6.11"); err != nil {
				t.Fatal(err)
			}
			rel := newRelease("v0.6.12")
			if tc.rollback {
				rel = newRelease("v0.6.10")
			}
			rel.sandboxd = tc.newSandboxd
			req := r.from(rel)
			req.Rollback = tc.rollback
			// Simulate the new boot writing to the database.
			r.u.hook = func(point string) {
				if point == "started" {
					writeFile(t, r.paths.DBPath, []byte("db after the failed boot"))
				}
			}
			st, err := r.u.Run(context.Background(), req)
			if err == nil {
				t.Fatalf("a failing new binary passed\n%s", r.out)
			}
			if st.Phase != PhaseFailed || st.Result != ResultFailed {
				t.Fatalf("state = %s/%s", st.Phase, st.Result)
			}
			r.assertInstalled(old, old.caddy)
			if st.BackupRestored != tc.wantRestore {
				t.Fatalf("backup restored = %v, want %v\n%s", st.BackupRestored, tc.wantRestore, r.out)
			}
			wantDB := "db after the failed boot"
			if tc.wantRestore {
				wantDB = "db before the upgrade"
			}
			if got := readFile(t, r.paths.DBPath); got != wantDB {
				t.Fatalf("database = %q, want %q", got, wantDB)
			}
			// The old sandboxd runs again.
			r.order("restart sandboxd", "stop sandboxd", "restart sandboxd")
			if v, _ := r.host.HealthVersion(context.Background(), ""); v != "v0.6.11" {
				t.Fatalf("running %q after the revert, want v0.6.11", v)
			}
			for _, f := range st.Files {
				if f.Swapped {
					t.Fatalf("%s still marked swapped after the revert", f.Role)
				}
			}
		})
	}
}

// Failures after the stop and before the start: files back, database
// untouched (the new binary never ran), old sandboxd started again, and
// services the swap restarted are restarted onto the old files.
func TestUpgradeFailureMidSwapPutsTheFilesBack(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *rig)
		want  string
	}{
		{name: "host apply fails", setup: func(r *rig) {
			r.host.fail["host apply"] = errors.New("exit 1")
		}, want: "install.sh said no"},
		{name: "caddy restart fails", setup: func(r *rig) {
			r.host.fail["restart caddy"] = errors.New("caddy refused")
		}, want: "caddy refused"},
		{name: "gateway restart fails", setup: func(r *rig) {
			r.host.active[gatewayUnit] = true
			r.host.gateway = 1
			r.host.fail["restart "+gatewayUnit] = errors.New("gateway refused")
		}, want: "gateway refused"},
		{name: "stop fails", setup: func(r *rig) {
			r.host.fail["stop sandboxd"] = errors.New("stop timed out")
		}, want: "stop timed out"},
		{name: "backup fails", setup: func(r *rig) {
			r.u.Backup = func(context.Context, string, string) error { return errors.New("disk full") }
		}, want: "disk full"},
		{name: "swap fails", setup: func(r *rig) {
			// The new toolboxd cannot be written beside the installed one.
			if err := os.MkdirAll(r.paths.Toolboxd+".new", 0o755); err != nil {
				r.t.Fatal(err)
			}
			writeFile(r.t, filepath.Join(r.paths.Toolboxd+".new", "x"), []byte("x"))
		}, want: "copy "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := newRelease("v0.6.11")
			r := newRig(t, old)
			tc.setup(r)
			rel := newRelease("v0.6.12").withMeta(func(m *release.Metadata) { m.EgressGatewayProtocol = []int{2, 3} })
			st, err := r.u.Run(context.Background(), r.from(rel))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q\n%s", err, tc.want, r.out)
			}
			r.assertInstalled(old, old.caddy)
			if st.BackupRestored {
				t.Fatal("restored the backup although the new binary never ran")
			}
			if got := readFile(t, r.paths.DBPath); got != "db before the upgrade" {
				t.Fatalf("database = %q", got)
			}
			if st.Phase != PhaseFailed {
				t.Fatalf("phase = %s", st.Phase)
			}
			if tc.name != "stop fails" {
				r.order("stop sandboxd", "restart sandboxd")
			}
			// A service restarted onto the new files is restarted again
			// onto the old ones, after they are back.
			if st.CaddyRestarted {
				r.order("restart caddy", "restart caddy")
			}
		})
	}
}

// A repeated op answers with what it did; an unfinished op whose upgrader
// died is resolved by the next call that gets the lock.
func TestUpgradeRepeatedOpIsIdempotent(t *testing.T) {
	r := newRig(t, newRelease("v0.6.11"))
	req := r.from(newRelease("v0.6.12"))
	req.Op = "op-1"
	first, err := r.u.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	calls := len(strings.Split(r.host.callLog(), "\n"))
	again, err := r.u.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if again.Result != first.Result || again.Op != "op-1" {
		t.Fatalf("repeat = %+v", again)
	}
	if n := len(strings.Split(r.host.callLog(), "\n")); n != calls {
		t.Fatalf("the repeat did work: %d calls, was %d", n, calls)
	}

	// A failed op answers with its error.
	r2 := newRig(t, newRelease("v0.6.11"))
	bad := r2.from(newRelease("v0.6.10"))
	bad.Op = "op-2"
	if _, err := r2.u.Run(context.Background(), bad); err == nil {
		t.Fatal("downgrade passed")
	}
	if _, err := r2.u.Run(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "op op-2 failed") {
		t.Fatalf("repeat of a failed op: %v", err)
	}

	// An unfinished op left by a dead upgrader.
	r3 := newRig(t, newRelease("v0.6.11"))
	next := newRelease("v0.6.12")
	st := &State{Format: stateFormat, Op: "op-3", Version: "v0.6.12", Phase: PhaseStopping, Files: []FileState{
		{Role: roleSandboxd, Asset: "sandboxd", Path: r3.paths.Sandboxd, SHA256: sum(next.sandboxd), PrevSHA256: sum(newRelease("v0.6.11").sandboxd), Changed: true},
	}}
	if err := os.MkdirAll(r3.paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := st.save(r3.paths.StateDir, r3.now); err != nil {
		t.Fatal(err)
	}
	req3 := r3.from(newRelease("v0.6.12"))
	req3.Op = "op-3"
	got, err := r3.u.Run(context.Background(), req3)
	if err == nil || got.Result != ResultRevertedAtBoot {
		t.Fatalf("unfinished op: %+v, %v", got, err)
	}
}

// One upgrade at a time on a node (§6.3).
func TestUpgradeRefusesASecondUpgradeWhileOneRuns(t *testing.T) {
	r := newRig(t, newRelease("v0.6.11"))
	if err := os.MkdirAll(r.paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	held, err := acquireLock(r.paths.StateDir, "op-running")
	if err != nil {
		t.Fatal(err)
	}
	defer held.release()
	_, err = r.u.Run(context.Background(), r.from(newRelease("v0.6.12")))
	if !errors.Is(err, ErrBusy) || !strings.Contains(err.Error(), "op-running") {
		t.Fatalf("err = %v, want ErrBusy naming op-running", err)
	}
	r.never("stop sandboxd")
}

// A bad request never touches the node.
func TestUpgradeRejectsABadRequest(t *testing.T) {
	r := newRig(t, newRelease("v0.6.11"))
	_, err := r.u.Run(context.Background(), Request{Version: "../etc", SHA256: map[string]string{"sandboxd": strings.Repeat("a", 64)}})
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(r.paths.StateDir); !os.IsNotExist(err) {
		t.Fatal("a rejected request made the state directory")
	}
}

// The stop guard runs once, after every check, with the request's
// AllowDowntime; it never runs for a no-op or when sandboxd is not running.
func TestUpgradeStopGuardRunsOnceBeforeTheStop(t *testing.T) {
	t.Run("runs with allow-downtime, then the upgrade goes on", func(t *testing.T) {
		r := newRig(t, newRelease("v0.6.11"))
		calls := 0
		r.u.BeforeStop = func(_ context.Context, allow bool) error {
			calls++
			if !allow {
				t.Errorf("allowDowntime = false, want true")
			}
			if strings.Contains(r.out.String(), "stopped sandboxd") {
				t.Errorf("guard ran after the stop")
			}
			return nil
		}
		req := r.from(newRelease("v0.6.12"))
		req.AllowDowntime = true
		if _, err := r.u.Run(context.Background(), req); err != nil {
			t.Fatalf("Run: %v\n%s", err, r.out)
		}
		if calls != 1 {
			t.Fatalf("guard calls = %d", calls)
		}
	})
	t.Run("not for a no-op", func(t *testing.T) {
		r := newRig(t, newRelease("v0.6.12"))
		r.u.BeforeStop = func(context.Context, bool) error { t.Error("guard ran for a no-op"); return nil }
		if _, err := r.u.Run(context.Background(), r.from(newRelease("v0.6.12"))); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("not when sandboxd is stopped", func(t *testing.T) {
		r := newRig(t, newRelease("v0.6.11"))
		r.host.active[sandboxdUnit] = false
		r.u.BeforeStop = func(context.Context, bool) error { t.Error("guard ran with sandboxd stopped"); return nil }
		_, _ = r.u.Run(context.Background(), r.from(newRelease("v0.6.12")))
	})
}
