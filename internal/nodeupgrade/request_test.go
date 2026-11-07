package nodeupgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every input that reaches a path, a URL or a unit name is checked before
// anything else runs (§8).
func TestRequestValidation(t *testing.T) {
	h := func(c string) string { return strings.Repeat(c, 64) }
	both := map[string]string{"sandboxd_linux_amd64": h("a"), "toolboxd_linux_amd64": h("b")}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range both {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name    string
		req     Request
		want    string // "" = valid
		roles   int
		notUsge bool
	}{
		{name: "valid", req: Request{Version: "v0.6.12", SHA256: both}, roles: 2},
		{name: "every file and the tag-prefixed names", req: Request{Version: "v0.6.12", SHA256: with(map[string]string{"v0.6.12_caddy_linux_amd64": h("c"), "release.json": h("d")})}, roles: 4},
		{name: "upper-case hash", req: Request{Version: "v0.6.12", SHA256: map[string]string{"sandboxd": strings.ToUpper(h("a")), "toolboxd": h("b")}}, roles: 2},
		{name: "path in version", req: Request{Version: "../../etc", SHA256: both}, want: "not a release tag"},
		{name: "slash in version", req: Request{Version: "v1/x", SHA256: both}, want: "not a release tag"},
		{name: "bad op", req: Request{Version: "v1.0.0", SHA256: both, Op: "a b"}, want: "--op"},
		{name: "negative timeout", req: Request{Version: "v1.0.0", SHA256: both, HealthTimeout: -time.Second}, want: "--health-timeout"},
		{name: "no hashes", req: Request{Version: "v1.0.0"}, want: "--sha256"},
		{name: "rollback with no hashes", req: Request{Version: "v1.0.0", Rollback: true}},
		{name: "--from with no hashes", req: Request{Version: "v1.0.0", Rollback: true, From: "/x"}, want: "--from needs"},
		{name: "short hash", req: Request{Version: "v1.0.0", SHA256: with(map[string]string{"caddy": "abc"})}, want: "not a hex SHA-256"},
		{name: "unknown file", req: Request{Version: "v1.0.0", SHA256: with(map[string]string{"evil.sh": h("e")})}, want: "not a release file"},
		{name: "path as a file name", req: Request{Version: "v1.0.0", SHA256: with(map[string]string{"../sandboxd": h("e")})}, want: "not a release file"},
		{name: "another CPU type", req: Request{Version: "v1.0.0", SHA256: map[string]string{"sandboxd_linux_arm64": h("a"), "toolboxd_linux_amd64": h("b")}}, want: "built for linux_arm64", notUsge: true},
		{name: "another OS", req: Request{Version: "v1.0.0", SHA256: map[string]string{"sandboxd_darwin_amd64": h("a"), "toolboxd": h("b")}}, want: "built for darwin_amd64", notUsge: true},
		{name: "two sandboxd files", req: Request{Version: "v1.0.0", SHA256: with(map[string]string{"sandboxd": h("e")})}, want: "two sandboxd files"},
		{name: "no toolboxd", req: Request{Version: "v1.0.0", SHA256: map[string]string{"sandboxd": h("a")}}, want: "no toolboxd file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			specs, err := tc.req.validate("linux", "amd64")
			if tc.want == "" {
				if err != nil {
					t.Fatalf("validate: %v", err)
				}
				if len(specs) != tc.roles {
					t.Fatalf("%d files, want %d", len(specs), tc.roles)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if errors.Is(err, ErrUsage) == tc.notUsge {
				t.Fatalf("usage error = %v for %v", errors.Is(err, ErrUsage), err)
			}
		})
	}
	if !archMatches("armv7", "arm") || archMatches("armv7", "arm64") {
		t.Fatal("32-bit ARM names")
	}
}

func TestRequestArgs(t *testing.T) {
	req := Request{
		Version: "v0.6.12", From: "/tmp/rel", Rollback: true, AllowUnversioned: true, SkipHostApply: true,
		Op: "op-1", HealthTimeout: 90 * time.Second,
		SHA256: map[string]string{"toolboxd": "b", "sandboxd": "a"},
	}
	want := "upgrade node v0.6.12 --sha256 sandboxd=a --sha256 toolboxd=b --from /tmp/rel --rollback --allow-unversioned --skip-host-apply --op op-1 --health-timeout 1m30s"
	if got := strings.Join(req.Args(), " "); got != want {
		t.Fatalf("args = %s", got)
	}
	if got := strings.Join(Request{Version: "v1.0.0"}.Args(), " "); got != "upgrade node v1.0.0" {
		t.Fatalf("minimal args = %s", got)
	}
	if id := NewOpID(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)); !strings.HasPrefix(id, "20260102t030405-") || !opRe.MatchString(id) {
		t.Fatalf("op id %q", id)
	}
}

// The Firecracker move, ported from install.sh's
// keep_firecracker_vms_running and its test: only firecracker processes
// move, a VM writing to a pipe also gets a reader that moves after it, and
// a host without cgroup v2 or without the unit's cgroup is left alone.
func TestKeepFirecrackerVMsRunning(t *testing.T) {
	r := newRig(t, newRelease("v0.6.11"))
	cg, proc := r.paths.CgroupRoot, r.paths.ProcRoot
	unit := "/system.slice/sandboxd.service"
	r.host.cgroup = unit
	writeFile(t, filepath.Join(cg, "cgroup.controllers"), []byte("cpu memory\n"))
	writeFile(t, filepath.Join(cg, unit, "cgroup.procs"), []byte("100\n101\n102\nnot-a-pid\n103\n"))
	writeFile(t, filepath.Join(proc, "100", "cmdline"), []byte("/usr/local/bin/sandboxd\x00"))
	writeFile(t, filepath.Join(proc, "101", "cmdline"), []byte("/firecracker\x00--id\x00sb-a\x00"))
	writeFile(t, filepath.Join(proc, "102", "cmdline"), []byte("/usr/bin/rclone\x00mount\x00"))
	writeFile(t, filepath.Join(proc, "103", "cmdline"), []byte("/usr/local/bin/firecracker\x00--api-sock\x00x\x00"))
	if err := os.MkdirAll(filepath.Join(proc, "103", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("pipe:[4242]", filepath.Join(proc, "103", "fd", "1")); err != nil {
		t.Fatal(err)
	}
	moved := r.u.keepFirecrackerVMsRunning(context.Background())
	if moved != 3 {
		t.Fatalf("moved %d, want the two VMs and one reader", moved)
	}
	got := readFile(t, filepath.Join(cg, vmmCgroup, "cgroup.procs"))
	if got != "101\n103\n9001\n" {
		t.Fatalf("aerolvm-vmm/cgroup.procs = %q, want both VMs then the reader", got)
	}
	if len(r.host.drains) != 1 || r.host.drains[0] != filepath.Join(proc, "103", "fd", "1") {
		t.Fatalf("drains = %v", r.host.drains)
	}

	// Without the unit's cgroup, or without cgroup v2: nothing.
	r.host.cgroup = ""
	if n := r.u.keepFirecrackerVMsRunning(context.Background()); n != 0 {
		t.Fatalf("no unit cgroup: moved %d", n)
	}
	r.host.cgroup = "/gone"
	if n := r.u.keepFirecrackerVMsRunning(context.Background()); n != 0 {
		t.Fatalf("no cgroup.procs: moved %d", n)
	}
	if err := os.Remove(filepath.Join(cg, "cgroup.controllers")); err != nil {
		t.Fatal(err)
	}
	r.host.cgroup = unit
	if n := r.u.keepFirecrackerVMsRunning(context.Background()); n != 0 {
		t.Fatalf("no cgroup v2: moved %d", n)
	}
}

// The upgrade moves the VMs before it stops sandboxd.
func TestUpgradeMovesFirecrackerVMsBeforeTheStop(t *testing.T) {
	r := newRig(t, newRelease("v0.6.11"))
	r.host.cgroup = "/system.slice/sandboxd.service"
	writeFile(t, filepath.Join(r.paths.CgroupRoot, "cgroup.controllers"), nil)
	writeFile(t, filepath.Join(r.paths.CgroupRoot, r.host.cgroup, "cgroup.procs"), []byte("7\n"))
	writeFile(t, filepath.Join(r.paths.ProcRoot, "7", "cmdline"), []byte("/firecracker\x00"))
	if _, err := r.u.Run(context.Background(), r.from(newRelease("v0.6.12"))); err != nil {
		t.Fatal(err)
	}
	r.order("cgroup sandboxd", "stop sandboxd")
	if !strings.Contains(r.out.String(), "moved 1 Firecracker VM") {
		t.Fatalf("output: %s", r.out)
	}
}
