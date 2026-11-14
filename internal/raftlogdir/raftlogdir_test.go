package raftlogdir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolve(t *testing.T) {
	type layout struct {
		recorded   string // "own" is the test's own log dir
		stable     bool   // the node has run
		defaultLog bool   // a log in <data>/raft-wal
		ownLog     bool   // a log in the own dir
	}
	for _, tc := range []struct {
		name       string
		have       layout
		configured string // "own", "default", "other", a literal, or ""
		want       string // "own", "default", or "" for an error
		wantErr    string
		recorded   bool // Resolve leaves a record naming own
	}{
		{name: "new node, unset", want: "default"},
		{name: "new node, the default named", configured: "default", want: "default"},
		{name: "new node, a disk of its own", configured: "own", want: "own", recorded: true},
		{name: "old node, unset", have: layout{stable: true, defaultLog: true}, want: "default"},
		{name: "old node, set later", have: layout{stable: true, defaultLog: true}, configured: "own",
			wantErr: "would leave behind"},
		{name: "a stale log in the configured dir", have: layout{ownLog: true}, configured: "own",
			wantErr: "does not name"},
		{name: "recorded, same configured", have: layout{recorded: "own", stable: true, ownLog: true}, configured: "own",
			want: "own", recorded: true},
		{name: "recorded, unset later (tools, or a dropped setting)", have: layout{recorded: "own", stable: true, ownLog: true},
			want: "own", recorded: true},
		{name: "recorded, another configured", have: layout{recorded: "own", stable: true, ownLog: true}, configured: "other",
			wantErr: "does not move"},
		{name: "recorded, the default configured", have: layout{recorded: "own", stable: true, ownLog: true}, configured: "default",
			wantErr: "does not move"},
		{name: "recorded, disk not mounted", have: layout{recorded: "own", stable: true}, configured: "own",
			wantErr: "is its disk mounted"},
		{name: "recorded, crashed before the first write", have: layout{recorded: "own"}, configured: "own",
			want: "own", recorded: true},
		{name: "relative path", configured: "relative/dir", wantErr: "not an absolute path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			data, own := filepath.Join(root, "raft"), filepath.Join(root, "disk", "raft-wal")
			def := filepath.Join(data, DefaultName)
			if err := os.MkdirAll(data, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.have.recorded == "own" {
				if err := os.WriteFile(filepath.Join(data, LocationFile), []byte(own+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.have.stable {
				touch(t, filepath.Join(data, stableFile))
			}
			if tc.have.defaultLog {
				touch(t, filepath.Join(def, metaFile))
			}
			if tc.have.ownLog {
				touch(t, filepath.Join(own, "00000000000000000001-0000000000000000.wal"))
			}
			configured := map[string]string{"own": own, "default": def, "other": filepath.Join(root, "other")}[tc.configured]
			if configured == "" {
				configured = tc.configured
			}

			got, err := Resolve(data, configured)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Resolve = %q, %v; want an error with %q", got, err, tc.wantErr)
				}
			} else {
				want := map[string]string{"own": own, "default": def}[tc.want]
				if err != nil || got != want {
					t.Fatalf("Resolve = %q, %v; want %q", got, err, want)
				}
			}
			rec, err := Recorded(data)
			if err != nil {
				t.Fatal(err)
			}
			// A record stays as it was: written only on a new node's first
			// start, never changed by a refusal.
			wantRecorded := tc.recorded || tc.have.recorded == "own"
			if (rec == own) != wantRecorded || (rec != "" && rec != own) {
				t.Fatalf("recorded %q afterwards; want own recorded = %v", rec, wantRecorded)
			}
			if wantRecorded {
				if dir, err := Dir(data); err != nil || dir != own {
					t.Fatalf("Dir = %q, %v; want %q", dir, err, own)
				}
			}
		})
	}
}

func TestDirAndRecorded(t *testing.T) {
	data := t.TempDir()
	if dir, err := Dir(data); err != nil || dir != filepath.Join(data, DefaultName) {
		t.Fatalf("Dir with no record = %q, %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(data, LocationFile), []byte("not/absolute\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Recorded(data); err == nil {
		t.Fatal("a relative record was accepted")
	}
	if _, err := Dir(data); err == nil {
		t.Fatal("Dir followed a relative record")
	}
	if err := os.WriteFile(filepath.Join(data, LocationFile), []byte(" /disk/./raft-wal \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if dir, err := Dir(data); err != nil || dir != "/disk/raft-wal" {
		t.Fatalf("Dir = %q, %v; want /disk/raft-wal", dir, err)
	}
	if err := os.Remove(filepath.Join(data, LocationFile)); err != nil {
		t.Fatal(err)
	}
	// A directory there is the log's own default directory: no record.
	if err := os.Mkdir(filepath.Join(data, DefaultName), 0o700); err != nil {
		t.Fatal(err)
	}
	if rec, err := Recorded(data); err != nil || rec != "" {
		t.Fatalf("Recorded with the default directory = %q, %v; want none", rec, err)
	}
	if err := os.Remove(filepath.Join(data, DefaultName)); err != nil {
		t.Fatal(err)
	}
	// Anything else there is neither, and is refused.
	if err := os.Symlink("/elsewhere", filepath.Join(data, LocationFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Recorded(data); err == nil {
		t.Fatal("a link was taken for a record or for none")
	}
}

// The record takes the default directory's place, so a sandboxd too old to
// read it cannot make that directory and open an empty log there.
func TestRecordStopsAnOlderSandboxd(t *testing.T) {
	root := t.TempDir()
	data, own := filepath.Join(root, "raft"), filepath.Join(root, "disk", "raft-wal")
	def := filepath.Join(data, DefaultName)
	// An empty default directory, as a node that never wrote a log leaves.
	if err := os.MkdirAll(def, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := Resolve(data, own); err != nil || got != own {
		t.Fatalf("Resolve = %q, %v", got, err)
	}
	if err := os.MkdirAll(def, 0o700); err == nil {
		t.Fatal("an older sandboxd could still make its log directory")
	}

	// A default directory with something else in it is not replaced.
	data2 := filepath.Join(root, "raft2")
	touch(t, filepath.Join(data2, DefaultName, "notes.txt"))
	if _, err := Resolve(data2, own+"2"); err == nil || !strings.Contains(err.Error(), "must be empty") {
		t.Fatalf("Resolve over a non-empty default directory = %v", err)
	}
}

func TestHoldsLog(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []string
		dirs  []string
		want  bool
	}{
		{name: "missing"},
		{name: "empty", dirs: []string{"."}},
		{name: "lost+found only", dirs: []string{"lost+found"}},
		{name: "meta", files: []string{metaFile}, want: true},
		{name: "a segment", files: []string{"00000000000000000001-0000000000000000.wal"}, want: true},
		{name: "a directory named like a segment", dirs: []string{"x.wal"}},
		{name: "other files", files: []string{"notes.txt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "wal")
			for _, d := range tc.dirs {
				if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, f := range tc.files {
				touch(t, filepath.Join(dir, f))
			}
			if got := HoldsLog(dir); got != tc.want {
				t.Fatalf("HoldsLog = %v, want %v", got, tc.want)
			}
		})
	}
}

// A record that cannot be written refuses the start and leaves no location
// behind.
func TestRecordFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	root := t.TempDir()
	data := filepath.Join(root, "raft")
	if err := os.Mkdir(data, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(data, 0o700) })
	if _, err := Resolve(data, filepath.Join(root, "disk")); err == nil || !strings.Contains(err.Error(), "record") {
		t.Fatalf("Resolve under a read-only data dir = %v; want a record error", err)
	}
	if rec, err := Recorded(data); err != nil || rec != "" {
		t.Fatalf("Recorded = %q, %v; want none", rec, err)
	}
}

// Failures to read the Raft directory refuse the start; they are never taken
// for "no record", which would open the default log in place of the real one.
func TestRecordedFailures(t *testing.T) {
	root := t.TempDir()
	notDir := filepath.Join(root, "file")
	touch(t, notDir)
	if _, err := Recorded(notDir); err == nil {
		t.Fatal("a data dir that is a file was taken for no record")
	}
	if _, err := Resolve(notDir, filepath.Join(root, "disk")); err == nil {
		t.Fatal("Resolve went on past a data dir it could not read")
	}
	data := filepath.Join(root, "raft")
	touch(t, filepath.Join(data, LocationFile))
	if err := os.WriteFile(filepath.Join(data, LocationFile), []byte("relative\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(data, ""); err == nil {
		t.Fatal("Resolve took a relative record")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads an unreadable record and writes a read-only directory")
	}
	if err := os.Chmod(filepath.Join(data, LocationFile), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(data, LocationFile), 0o600) })
	if _, err := Recorded(data); err == nil {
		t.Fatal("an unreadable record was taken for none")
	}
	// A data dir that does not exist yet, under one that cannot be written.
	ro := filepath.Join(root, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	if _, err := Resolve(filepath.Join(ro, "raft"), filepath.Join(root, "disk")); err == nil || !strings.Contains(err.Error(), "record") {
		t.Fatalf("Resolve with a data dir it cannot make = %v", err)
	}
}
