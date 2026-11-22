package isolate

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testRootJail(base string) RootJail {
	return RootJail{ChrootBase: base, WorkerdPath: "/usr/local/bin/workerd", UID: 1000, GID: 1000, AgentUID: 65531,
		SeccompMode: SeccompEnforce, ShimPath: "/usr/local/bin/aerolvm-rootd"}
}

func TestRootJailValidate(t *testing.T) {
	ok := testRootJail("/srv/isolate-jail")
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*RootJail){
		"relative base":       func(r *RootJail) { r.ChrootBase = "srv" },
		"root base":           func(r *RootJail) { r.ChrootBase = "/" },
		"untidy base":         func(r *RootJail) { r.ChrootBase = "/srv/../etc" },
		"no workerd":          func(r *RootJail) { r.WorkerdPath = "" },
		"relative shim":       func(r *RootJail) { r.ShimPath = "aerolvm-rootd" },
		"root jail user":      func(r *RootJail) { r.UID = 0 },
		"root jail group":     func(r *RootJail) { r.GID = 0 },
		"root agent":          func(r *RootJail) { r.AgentUID = 0 },
		"the jail's own user": func(r *RootJail) { r.AgentUID = r.UID },
		"an unknown mode":     func(r *RootJail) { r.SeccompMode = "loose" },
	} {
		r := ok
		mut(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: validated", name)
		}
	}
	for _, mode := range []string{SeccompAudit, SeccompOff, ""} {
		r := ok
		r.SeccompMode = mode
		if err := r.Validate(); err != nil {
			t.Errorf("mode %q: %v", mode, err)
		}
	}
}

// TestRootJailGroupNames: whatever the agent names, the jail touches only
// one folder under its base, never the base tree itself.
func TestRootJailGroupNames(t *testing.T) {
	base := t.TempDir()
	r := testRootJail(base)
	for _, bad := range []string{"", ".base", ".hidden", "a/b", "../etc", "a\x00"} {
		if _, err := r.Prepare(bad); err == nil {
			t.Errorf("Prepare(%q) worked", bad)
		}
		if _, err := r.Command(bad); err == nil {
			t.Errorf("Command(%q) worked", bad)
		}
		if err := r.Teardown(bad); err == nil {
			t.Errorf("Teardown(%q) worked", bad)
		}
		if r.Prepared(bad) {
			t.Errorf("Prepared(%q)", bad)
		}
	}
	if got := r.RunDir("g"); got != filepath.Join(base, "g", JailRunDirName) {
		t.Fatalf("RunDir = %s", got)
	}
	// An unprepared group has no command: nothing runs outside a whole jail.
	if _, err := r.Command("g"); err == nil || !strings.Contains(err.Error(), "not prepared") {
		t.Fatalf("Command of an unprepared group: %v", err)
	}
	// Groups lists group folders only: not the base tree, a hidden or
	// half-named folder, or a file.
	for _, d := range []string{".base", ".next", "g1", "g2"} {
		if err := os.Mkdir(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	groups, err := r.Groups()
	if err != nil || !slices.Equal(groups, []string{"g1", "g2"}) {
		t.Fatalf("Groups = %v, %v", groups, err)
	}
	// Teardown removes a group folder with nothing mounted on it, and a
	// missing one is no error.
	if err := r.Teardown("g1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "g1")); !os.IsNotExist(err) {
		t.Fatal("g1 left behind")
	}
	if err := r.Teardown("g1"); err != nil {
		t.Fatal(err)
	}
	if groups, err := (testRootJail(filepath.Join(base, "missing"))).Groups(); err != nil || groups != nil {
		t.Fatalf("Groups of a missing base = %v, %v", groups, err)
	}
}

func TestShimSpecUmask(t *testing.T) {
	zero, wide := uint32(0), uint32(0o1777)
	spec := jailShimSpec{Chroot: "/srv/j/g", Cwd: "/run", UID: 1000, GID: 1000, Argv: []string{"/workerd"}, Umask: &zero}
	raw, err := encodeJailShimSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeJailShimSpec(raw)
	if err != nil || got.Umask == nil || *got.Umask != 0 {
		t.Fatalf("decoded %+v, %v", got, err)
	}
	// Single mode's spec carries no mask, and keeps the shim's.
	spec.Umask = nil
	if raw, _ = encodeJailShimSpec(spec); strings.Contains(raw, "umask") {
		t.Fatalf("an unset mask is on the wire: %s", raw)
	}
	spec.Umask = &wide
	if _, err := encodeJailShimSpec(spec); err == nil {
		t.Fatal("a mask past 0777 passed")
	}
}
