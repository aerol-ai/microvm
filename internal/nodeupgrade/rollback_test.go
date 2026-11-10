package nodeupgrade

import (
	"context"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/release"
)

// §6.8: `sandboxd upgrade node <old> --rollback` with no files puts back the
// *.prev files the last upgrade kept, needs no download, never restores the
// database backup, and restarts a gateway the upgrade restarted. Doing it
// again is a noop, and an upgrade back to the new version works.
func TestRollbackPutsThePrevFilesBack(t *testing.T) {
	old := newRelease("v0.6.11")
	next := newRelease("v0.6.12").withMeta(func(m *release.Metadata) { m.EgressGatewayProtocol = []int{2, 3} })
	r := newRig(t, old)
	r.host.active[gatewayUnit] = true
	r.host.gateway = 1
	r.u.SelfHostSetupSHA256 = next.meta.HostSetupSHA256
	up := r.from(next)
	if _, err := r.u.Run(context.Background(), up); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, r.out)
	}
	writeFile(t, r.paths.DBPath, []byte("db written by v0.6.12"))

	st, err := r.u.Run(context.Background(), Request{Version: "v0.6.11", Rollback: true})
	if err != nil {
		t.Fatalf("rollback: %v\n%s", err, r.out)
	}
	if st.Result != ResultUpgraded || !st.Rollback || st.FromVersion != "v0.6.12" {
		t.Fatalf("rollback record = %+v", st)
	}
	r.assertInstalled(old, old.caddy)
	if got := readFile(t, r.paths.DBPath); got != "db written by v0.6.12" {
		t.Fatalf("the rollback touched the database: %q", got)
	}
	if !st.GatewayRestarted {
		t.Fatal("the gateway the upgrade restarted was not restarted onto the old binary")
	}
	if len(r.host.fetches) != 0 {
		t.Fatalf("a rollback downloaded %v", r.host.fetches)
	}
	if v, _ := r.host.HealthVersion(context.Background(), ""); v != "v0.6.11" {
		t.Fatalf("running %q after the rollback", v)
	}

	again, err := r.u.Run(context.Background(), Request{Version: "v0.6.11", Rollback: true})
	if err != nil || again.Result != ResultNoop {
		t.Fatalf("second rollback: %+v, %v", again, err)
	}

	// And forward again, from the same files.
	fwd, err := r.u.Run(context.Background(), up)
	if err != nil || fwd.Result != ResultUpgraded {
		t.Fatalf("upgrade after the rollback: %+v, %v\n%s", fwd, err, r.out)
	}
	r.assertInstalled(next, next.caddy)
}

func TestRollbackRefusesWhatItCannotTrust(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *rig)
		ver   string
		want  string
	}{
		{name: "never upgraded", setup: func(*rig) {}, ver: "v0.6.11", want: "no upgrade on this node kept"},
		{name: "kept files are another version", setup: func(r *rig) {
			if _, err := r.u.Run(context.Background(), r.from(newRelease("v0.6.12"))); err != nil {
				r.t.Fatal(err)
			}
		}, ver: "v0.6.10", want: "are v0.6.11, not v0.6.10"},
		{name: "a .prev was replaced", setup: func(r *rig) {
			if _, err := r.u.Run(context.Background(), r.from(newRelease("v0.6.12"))); err != nil {
				r.t.Fatal(err)
			}
			writeFile(r.t, r.paths.Toolboxd+".prev", []byte("tampered"))
		}, ver: "v0.6.11", want: "is not the file the upgrade replaced"},
		{name: "installed files moved on", setup: func(r *rig) {
			if _, err := r.u.Run(context.Background(), r.from(newRelease("v0.6.12"))); err != nil {
				r.t.Fatal(err)
			}
			writeFile(r.t, r.paths.Sandboxd, fakeBinary("v0.6.13", true))
		}, ver: "v0.6.11", want: "no upgrade on this node kept"},
		{name: "upgrade installed a file where there was none", setup: func(r *rig) {
			req := r.from(newRelease("v0.6.12"))
			if err := removeFile(r.paths.Caddy); err != nil {
				r.t.Fatal(err)
			}
			if _, err := r.u.Run(context.Background(), req); err != nil {
				r.t.Fatal(err)
			}
		}, ver: "v0.6.11", want: "where there was none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, newRelease("v0.6.11"))
			tc.setup(r)
			_, err := r.u.Run(context.Background(), Request{Version: tc.ver, Rollback: true})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A rollback given files (a node with no *.prev, §6.8) downgrades through
// the normal path.
func TestRollbackWithFilesDowngrades(t *testing.T) {
	r := newRig(t, newRelease("v0.6.12"))
	prev := newRelease("v0.6.11")
	req := r.from(prev)
	req.Rollback = true
	st, err := r.u.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if st.Result != ResultUpgraded {
		t.Fatalf("result = %s", st.Result)
	}
	r.assertInstalled(prev, prev.caddy)
}
