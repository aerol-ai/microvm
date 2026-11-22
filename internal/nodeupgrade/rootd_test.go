package nodeupgrade

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootswap"
)

// The root helper on a privilege mode split VM (rootd.go, M1 PR 10): the
// upgrade installs a new aerolvm-rootd only once internal/rootswap has
// checked its signature, and only the copy rootswap made.

// testKey makes a release key and points releaseKeys at it.
func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	releaseKeys = func() ([]ed25519.PublicKey, error) { return []ed25519.PublicKey{pub}, nil }
	t.Cleanup(func() { releaseKeys = rootswap.ReleaseKeys })
	return priv
}

// helperFiles is a signed helper for version: binary, manifest, signature.
func helperFiles(t *testing.T, priv ed25519.PrivateKey, version string) map[string][]byte {
	t.Helper()
	bin := []byte("#!fake aerolvm-rootd " + version + "\n")
	m, err := rootswap.NewManifest(bytes.NewReader(bin), version, 3, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	raw, sig, err := rootswap.Sign(priv, m)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{rootswap.BinaryName: bin, rootswap.ManifestName: raw, rootswap.SignatureName: sig}
}

// realDir is a temp folder reached with no link on the way.
func realDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// splitRig is a privilege mode split node: its upgrade folder outside the
// data folder, and helper running from RootdDir.
func splitRig(t *testing.T, installed releaseFiles, helper map[string][]byte) *rig {
	t.Helper()
	r := newRigIn(t, realDir(t), installed)
	r.paths.Split = true
	r.paths.StateDir = filepath.Join(r.dir, "var-lib-aerolvm-upgrade")
	r.paths.RootdDir = filepath.Join(r.dir, "usr-local-lib-aerolvm-rootd")
	for name, data := range helper {
		writeFile(t, filepath.Join(r.paths.RootdDir, name), data)
	}
	r.host.active[rootdUnit] = true
	r.u.Paths = r.paths
	return r
}

// withHelper adds a helper's three files to a request, under the names a
// release gives them.
func (r *rig) withHelper(req Request, helper map[string][]byte) Request {
	r.t.Helper()
	for name, data := range helper {
		writeFile(r.t, filepath.Join(req.From, name), data)
		req.SHA256[name] = sum(data)
	}
	return req
}

func (r *rig) assertHelper(want map[string][]byte) {
	r.t.Helper()
	for name, data := range want {
		if got := readFile(r.t, filepath.Join(r.paths.RootdDir, name)); got != string(data) {
			r.t.Fatalf("%s = %q, want %q", name, got, data)
		}
	}
	// No checked copy is left behind: only the three files and their
	// *.prev.
	entries, _ := os.ReadDir(r.paths.RootdDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), rootswap.BinaryName+"-") || strings.HasPrefix(e.Name(), ".") {
			r.t.Fatalf("left in the helper's folder: %s", e.Name())
		}
	}
}

func TestUpgradeInstallsTheSignedHelper(t *testing.T) {
	priv := testKey(t)
	old, oldHelper := newRelease("v0.7.7"), helperFiles(t, priv, "v0.7.7")
	r := splitRig(t, old, oldHelper)
	next, nextHelper := newRelease("v0.7.8"), helperFiles(t, priv, "v0.7.8")
	st, err := r.u.Run(t.Context(), r.withHelper(r.from(next), nextHelper))
	if err != nil {
		t.Fatalf("upgrade: %v\n%s", err, r.out)
	}
	if st.Result != ResultUpgraded || !st.RootdRestarted {
		t.Fatalf("state %+v", st)
	}
	r.assertInstalled(next, next.caddy)
	r.assertHelper(nextHelper)
	r.assertPrev(filepath.Join(r.paths.RootdDir, rootswap.BinaryName), oldHelper[rootswap.BinaryName])
	// The helper restarts with sandboxd stopped, before the new sandboxd
	// starts on it.
	r.order("stop sandboxd", "restart aerolvm-rootd", "restart sandboxd")
	if !strings.Contains(r.out.String(), "signature checked") {
		t.Fatalf("output:\n%s", r.out)
	}
	// The running helper is now the new one, read from signed bytes.
	keys, _ := releaseKeys()
	if m := RunningRootHelper(r.paths.RootdDir, keys); m == nil || m.Version != "v0.7.8" {
		t.Fatalf("running helper %+v", m)
	}
}

func TestUpgradeRefusesAHelperItCannotVouchFor(t *testing.T) {
	priv := testKey(t)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		helper func() map[string][]byte
		want   string
	}{
		{"signed with another key", func() map[string][]byte { return helperFiles(t, other, "v0.7.8") }, "bad_signature"},
		{"another binary than the manifest names", func() map[string][]byte {
			h := helperFiles(t, priv, "v0.7.8")
			h[rootswap.BinaryName] = []byte("#!fake aerolvm-rootd v0.7.8 but changed\n")
			return h
		}, "wrong_size"},
		{"older than the running helper", func() map[string][]byte { return helperFiles(t, priv, "v0.7.6") }, "older"},
		{"another release than the upgrade", func() map[string][]byte { return helperFiles(t, priv, "v0.7.9") }, "not v0.7.8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, oldHelper := newRelease("v0.7.7"), helperFiles(t, priv, "v0.7.7")
			r := splitRig(t, old, oldHelper)
			req := r.withHelper(r.from(newRelease("v0.7.8")), tc.helper())
			st, err := r.u.Run(t.Context(), req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if st.Result != ResultFailed {
				t.Fatalf("state %+v", st)
			}
			// Nothing stopped, nothing changed, no copy left.
			r.never("stop sandboxd")
			r.assertInstalled(old, old.caddy)
			r.assertHelper(oldHelper)
		})
	}
}

func TestUpgradePutsTheHelperBackWithTheRest(t *testing.T) {
	priv := testKey(t)
	old, oldHelper := newRelease("v0.7.7"), helperFiles(t, priv, "v0.7.7")
	r := splitRig(t, old, oldHelper)
	next := newRelease("v0.7.8")
	next.sandboxd = fakeBinary("v0.7.8", true, "BROKEN")
	_, err := r.u.Run(t.Context(), r.withHelper(r.from(next), helperFiles(t, priv, "v0.7.8")))
	if err == nil {
		t.Fatal("a sandboxd that never came up was kept")
	}
	r.assertInstalled(old, old.caddy)
	r.assertHelper(oldHelper)
	// Restarted onto the new helper, then again onto the old one.
	r.order("restart aerolvm-rootd", "restart sandboxd", "restart aerolvm-rootd")
}

func TestSingleNodeSkipsTheHelper(t *testing.T) {
	priv := testKey(t)
	r := newRigIn(t, realDir(t), newRelease("v0.7.7"))
	next := newRelease("v0.7.8")
	st, err := r.u.Run(t.Context(), r.withHelper(r.from(next), helperFiles(t, priv, "v0.7.8")))
	if err != nil {
		t.Fatalf("upgrade: %v\n%s", err, r.out)
	}
	if st.file(roleRootd) != nil || !strings.Contains(r.out.String(), "runs no root helper") {
		t.Fatalf("state %+v\n%s", st, r.out)
	}
	r.never("aerolvm-rootd")
}

func TestSplitNodeRefusesAnUpgradeFolderTheAgentCanWrite(t *testing.T) {
	r := newRig(t, newRelease("v0.7.7"))
	r.u.Paths.Split = true // StateDir is beside the database
	_, err := r.u.Run(t.Context(), r.from(newRelease("v0.7.8")))
	if err == nil || !strings.Contains(err.Error(), "SB_UPGRADE_STATE_DIR") {
		t.Fatalf("err = %v", err)
	}
	r.never("stop sandboxd")
}

func TestHelperFilesGoTogether(t *testing.T) {
	req := Request{Version: "v0.7.8", SHA256: map[string]string{
		"sandboxd_linux_amd64": strings.Repeat("a", 64), "toolboxd_linux_amd64": strings.Repeat("b", 64),
		"aerolvm-rootd_linux_amd64": strings.Repeat("c", 64),
	}}
	if _, err := req.validate("linux", "amd64"); err == nil || !strings.Contains(err.Error(), "1 of the root helper's 3 files") {
		t.Fatalf("err = %v", err)
	}
	req.SHA256["aerolvm-rootd_linux_amd64.manifest"] = strings.Repeat("d", 64)
	req.SHA256["v0.7.8_aerolvm-rootd_linux_amd64.sig"] = strings.Repeat("e", 64)
	specs, err := req.validate("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]bool{}
	for _, s := range specs {
		roles[s.role] = true
	}
	for _, want := range []string{roleRootd, roleRootdManifest, roleRootdSig} {
		if !roles[want] {
			t.Fatalf("roles %v lack %s", roles, want)
		}
	}
	if _, err := roleOf("aerolvm-rootd_linux_arm64.sig", "linux", "amd64"); err == nil || !strings.Contains(err.Error(), "built for linux_arm64") {
		t.Fatalf("err = %v", err)
	}
}

func TestInstallRootHelper(t *testing.T) {
	priv := testKey(t)
	base := realDir(t)
	dir := filepath.Join(base, "usr-local-lib-aerolvm-rootd")
	stage := func(h map[string][]byte) string {
		from, err := os.MkdirTemp(base, "from")
		if err != nil {
			t.Fatal(err)
		}
		for name, data := range h {
			writeFile(t, filepath.Join(from, name), data)
		}
		return from
	}
	first := helperFiles(t, priv, "v0.7.8")
	res, err := InstallRootHelper(stage(first), dir, false)
	if err != nil || !res.Changed || res.Manifest.Version != "v0.7.8" {
		t.Fatalf("fresh install: %+v %v", res, err)
	}
	for name, data := range first {
		if got := readFile(t, filepath.Join(dir, name)); got != string(data) {
			t.Fatalf("%s = %q", name, got)
		}
	}
	if st, err := os.Stat(filepath.Join(dir, rootswap.ManifestName)); err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("manifest mode %v %v", st.Mode(), err)
	}
	// Again: nothing to do, and no copy left.
	res, err = InstallRootHelper(stage(first), dir, false)
	if err != nil || res.Changed {
		t.Fatalf("second install: %+v %v", res, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 3 {
		t.Fatalf("helper folder holds %d entries", len(entries))
	}
	// Older: refused, unless allowed (a rollback).
	older := helperFiles(t, priv, "v0.7.7")
	if _, err := InstallRootHelper(stage(older), dir, false); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("older: %v", err)
	}
	if res, err := InstallRootHelper(stage(older), dir, true); err != nil || !res.Changed {
		t.Fatalf("rollback: %+v %v", res, err)
	}
	// A folder others can write is not where a checked helper comes from.
	open := stage(first)
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallRootHelper(open, dir, false); err == nil || !strings.Contains(err.Error(), "written by others") {
		t.Fatalf("open folder: %v", err)
	}
	if _, err := InstallRootHelper("relative", dir, false); err == nil {
		t.Fatal("a relative folder passed")
	}
	if err := os.Symlink(stage(first), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallRootHelper(filepath.Join(base, "link"), dir, false); err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Fatalf("link: %v", err)
	}
	writeFile(t, filepath.Join(base, "file"), []byte("x"))
	if _, err := InstallRootHelper(filepath.Join(base, "file"), dir, false); err == nil || !strings.Contains(err.Error(), "not a folder") {
		t.Fatalf("file: %v", err)
	}
	// Unsigned: refused.
	unsigned := stage(first)
	_ = os.Remove(filepath.Join(unsigned, rootswap.SignatureName))
	if _, err := InstallRootHelper(unsigned, dir, false); err == nil || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("unsigned: %v", err)
	}
}

func TestRunningRootHelper(t *testing.T) {
	priv := testKey(t)
	keys, _ := releaseKeys()
	dir := realDir(t)
	if RunningRootHelper(dir, keys) != nil {
		t.Fatal("an empty folder has a helper")
	}
	h := helperFiles(t, priv, "v0.7.8")
	for name, data := range h {
		writeFile(t, filepath.Join(dir, name), data)
	}
	if m := RunningRootHelper(dir, keys); m == nil || m.Version != "v0.7.8" {
		t.Fatalf("helper %+v", m)
	}
	// A binary the manifest does not name is not vouched for.
	writeFile(t, filepath.Join(dir, rootswap.BinaryName), []byte("other"))
	if RunningRootHelper(dir, keys) != nil {
		t.Fatal("a changed binary was vouched for")
	}
	_ = os.Remove(filepath.Join(dir, rootswap.SignatureName))
	if RunningRootHelper(dir, keys) != nil {
		t.Fatal("no signature, still vouched for")
	}
	writeFile(t, filepath.Join(dir, rootswap.SignatureName), []byte("bad"))
	if RunningRootHelper(dir, keys) != nil {
		t.Fatal("a bad signature, still vouched for")
	}
}

func TestResolvePathsSplit(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "sandboxd.env")
	writeFile(t, env, []byte("SB_PRIVILEGE_MODE=split\nSB_UPGRADE_STATE_DIR=/var/lib/aerolvm-upgrade/\n"))
	p, err := ResolvePaths(env, func(string) string { return "" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Split || p.RootdDir != DefaultRootdDir || p.StateDir != "/var/lib/aerolvm-upgrade" {
		t.Fatalf("paths %+v", p)
	}
	writeFile(t, env, []byte("SB_UPGRADE_STATE_DIR=upgrade\n"))
	if _, err := ResolvePaths(env, func(string) string { return "" }, nil); err == nil {
		t.Fatal("a relative upgrade folder passed")
	}
	// Single: no helper, the folder beside the database.
	writeFile(t, env, []byte("SB_PRIVILEGE_MODE=single\n"))
	if p, _ := ResolvePaths(env, func(string) string { return "" }, nil); p.Split || p.RootdDir != "" || p.StateDir != "/var/lib/sandboxd/upgrade" {
		t.Fatalf("single paths %+v", p)
	}
}

func TestWithin(t *testing.T) {
	for _, tc := range []struct {
		path, dir string
		want      bool
	}{
		{"/var/lib/sandboxd/upgrade", "/var/lib/sandboxd", true},
		{"/var/lib/sandboxd", "/var/lib/sandboxd/", true},
		{"/var/lib/sandboxd-upgrade", "/var/lib/sandboxd", false},
		{"/var/lib/aerolvm-upgrade", "/var/lib/sandboxd", false},
	} {
		if got := within(tc.path, tc.dir); got != tc.want {
			t.Errorf("within(%q, %q) = %v", tc.path, tc.dir, got)
		}
	}
}

// The database's folder is the agent's on a split node: a link it leaves at
// the restore's temporary name is replaced, never written through.
func TestRestoreBackupFollowsNoLink(t *testing.T) {
	dir := realDir(t)
	db := filepath.Join(dir, "state.db")
	backup := filepath.Join(dir, "op.state.db")
	target := filepath.Join(dir, "root-file")
	writeFile(t, db, []byte("new"))
	writeFile(t, backup, []byte("old"))
	writeFile(t, target, []byte("root's"))
	if err := os.Symlink(target, db+".restore"); err != nil {
		t.Fatal(err)
	}
	if err := restoreBackup(dir, backup, db); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, target); got != "root's" {
		t.Fatalf("the link's target was written: %q", got)
	}
	if got := readFile(t, db); got != "old" {
		t.Fatalf("database %q", got)
	}
}
