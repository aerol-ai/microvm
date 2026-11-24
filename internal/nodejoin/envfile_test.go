package nodejoin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.env")
	mustWrite(t, path, "# comment\n\nA=1\nexport B=\"two words\"\nC='3'\nD=a=b\nnot a line\n=nokey\nA=override\n")
	got, err := readEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"A": "override", "B": "two words", "C": "3", "D": "a=b"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s = %q, want %q", k, got[k], v)
		}
	}
	if m, err := readEnvFile(filepath.Join(dir, "missing")); err != nil || len(m) != 0 {
		t.Fatalf("missing file = %v %v", m, err)
	}
	if _, err := readEnvFile(dir); err == nil {
		t.Fatal("a directory read as an env file")
	}
}

func TestMergeEnvFile(t *testing.T) {
	cases := []struct {
		name, old, header, want string
		set                     [][2]string
	}{
		{name: "new file gets the header", header: "# head\n", set: [][2]string{{"A", "1"}, {"B", "2"}}, want: "# head\nA=1\nB=2\n"},
		{name: "rewritten in place, others kept", old: "# keep\nX=9\nA=old\nY=8", set: [][2]string{{"A", "new"}, {"C", "3"}}, want: "# keep\nX=9\nA=new\nY=8\nC=3\n"},
		{name: "an empty value drops the key", old: "A=1\nB=2\n", set: [][2]string{{"A", ""}}, want: "B=2\n"},
		{name: "duplicates of a set key collapse", old: "A=1\nA=2\nB=3\n", set: [][2]string{{"A", "9"}}, want: "A=9\nB=3\n"},
		{name: "no header on an existing file", old: "Z=1\n", header: "# head\n", set: [][2]string{{"A", "1"}}, want: "Z=1\nA=1\n"},
		{name: "a dropped key that is absent writes nothing", old: "Z=1\n", set: [][2]string{{"A", ""}}, want: "Z=1\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c.env")
			if tc.old != "" {
				mustWrite(t, path, tc.old)
			}
			var set envSet
			for _, kv := range tc.set {
				set.set(kv[0], kv[1])
			}
			if err := mergeEnvFile(path, tc.header, set); err != nil {
				t.Fatal(err)
			}
			if got := readFile(t, path); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
				t.Fatalf("mode %v, want 0600", st.Mode().Perm())
			}
		})
	}
	// Setting a key twice keeps one place for it, with the last value.
	var set envSet
	set.set("A", "1")
	set.set("A", "2")
	if len(set.keys) != 1 || set.values["A"] != "2" {
		t.Fatalf("set = %+v", set)
	}
	if err := mergeEnvFile(t.TempDir(), "", set); err == nil {
		t.Fatal("merged into a directory")
	}
}

func TestFileJournal(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "old.txt")
	mustWrite(t, existing, "before")
	created := filepath.Join(dir, "sub", "new.txt")
	removed := filepath.Join(dir, "gone.txt")
	mustWrite(t, removed, "here")
	envPath := filepath.Join(dir, "c.env")

	j := &fileJournal{}
	if j.changed() {
		t.Fatal("an empty journal changed something")
	}
	if err := j.write(existing, []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := j.write(existing, []byte("after again"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := j.write(created, []byte("fresh"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := j.remove(removed); err != nil {
		t.Fatal(err)
	}
	if err := j.remove(filepath.Join(dir, "never.txt")); err != nil {
		t.Fatal(err)
	}
	var set envSet
	set.set("A", "1")
	if err := j.mergeEnv(envPath, "", set); err != nil {
		t.Fatal(err)
	}
	if !j.changed() {
		t.Fatal("journal says nothing changed")
	}
	if failed := j.rollback(); len(failed) != 0 {
		t.Fatalf("rollback failed for %v", failed)
	}
	if readFile(t, existing) != "before" || exists(created) || readFile(t, removed) != "here" || exists(envPath) {
		t.Fatal("rollback did not restore every file")
	}

	// Writing the same bytes back is no change.
	j = &fileJournal{}
	if err := j.write(existing, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	if j.changed() {
		t.Fatal("same bytes reported as a change")
	}
	// A file that can't be read can't be remembered.
	if err := j.write(filepath.Join(existing, "under-a-file"), []byte("x"), 0o600); err == nil {
		t.Fatal("wrote under a regular file")
	}
}

// A link at a path init or join writes is refused before anything is read
// or written: in privilege mode split sandboxd's user owns those folders,
// and root must never read or write what such a link names.
func TestFileJournalRefusesALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "root-only")
	mustWrite(t, target, "not for the journal")
	link := filepath.Join(dir, "node.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	j := &fileJournal{}
	err := j.write(link, []byte("new key"), 0o600)
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("write through a link: %v, want a refusal", err)
	}
	if err := j.remove(link); err == nil {
		t.Fatal("remove of a link was not refused")
	}
	if readFile(t, target) != "not for the journal" {
		t.Fatal("the link's target changed")
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v", err)
	}
	if len(j.entries) != 0 || j.changed() {
		t.Fatal("the journal remembered a link")
	}
	// A folder or other non-file is refused too.
	sub := filepath.Join(dir, "a-dir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := j.write(sub, []byte("x"), 0o600); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("write over a folder: %v, want a refusal", err)
	}
}
