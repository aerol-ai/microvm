//go:build unix

package raftlogdir

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// In privilege mode split the record is sandboxd's user's to write, so a
// tool running as root takes a log outside the data directory only from
// SB_RAFT_WAL_DIR, its own setting; single follows the record, as before.
func TestTrusted(t *testing.T) {
	writeRecord := func(t *testing.T, data, body string) {
		t.Helper()
		if err := os.MkdirAll(data, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(data, LocationFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name       string
		setup      func(t *testing.T, data string)
		configured string
		split      bool
		want       string
		wantErr    string
	}{
		{name: "single follows the record", split: false, configured: "",
			setup: func(t *testing.T, d string) { writeRecord(t, d, "/root\n") }, want: "/root"},
		{name: "split: no record is the default", split: true, configured: "/disk/raft-wal",
			setup: func(t *testing.T, d string) {}, want: ""},
		{name: "split: the default folder is no record", split: true,
			setup: func(t *testing.T, d string) {
				if err := os.MkdirAll(filepath.Join(d, DefaultName), 0o700); err != nil {
					t.Fatal(err)
				}
			}, want: ""},
		{name: "split: the record and the env agree", split: true, configured: "/disk/raft-wal/",
			setup: func(t *testing.T, d string) { writeRecord(t, d, "/disk/raft-wal\n") }, want: "/disk/raft-wal"},
		{name: "split: a record with no setting is refused", split: true,
			setup:   func(t *testing.T, d string) { writeRecord(t, d, "/root\n") },
			wantErr: "SB_RAFT_WAL_DIR in the env files is \"\""},
		{name: "split: a record naming another folder is refused", split: true, configured: "/disk/raft-wal",
			setup:   func(t *testing.T, d string) { writeRecord(t, d, "/var/lib/aerolvm-rootd\n") },
			wantErr: "names /var/lib/aerolvm-rootd"},
		{name: "split: a link is refused", split: true, configured: "/disk/raft-wal",
			setup: func(t *testing.T, d string) {
				writeRecord(t, d+"-elsewhere", "/disk/raft-wal\n")
				if err := os.Symlink(filepath.Join(d+"-elsewhere", LocationFile), filepath.Join(d, LocationFile)); err != nil {
					t.Fatal(err)
				}
			}, wantErr: "a link is refused"},
		{name: "split: a FIFO is refused without waiting", split: true, configured: "/disk/raft-wal",
			setup: func(t *testing.T, d string) {
				if err := syscall.Mkfifo(filepath.Join(d, LocationFile), 0o600); err != nil {
					t.Fatal(err)
				}
			}, wantErr: "neither the log's directory nor a record"},
		{name: "split: a relative record is refused", split: true, configured: "/disk/raft-wal",
			setup:   func(t *testing.T, d string) { writeRecord(t, d, "raft-wal\n") },
			wantErr: "not an absolute path"},
		{name: "split: an over-long record is refused", split: true, configured: "/disk/raft-wal",
			setup:   func(t *testing.T, d string) { writeRecord(t, d, "/"+strings.Repeat("a", maxRecord)) },
			wantErr: "longer than a path"},
		{name: "split: a relative setting is refused", split: true, configured: "disk/raft-wal",
			setup:   func(t *testing.T, d string) { writeRecord(t, d, "/disk/raft-wal\n") },
			wantErr: "not an absolute path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := filepath.Join(t.TempDir(), "raft")
			if err := os.MkdirAll(data, 0o700); err != nil {
				t.Fatal(err)
			}
			c.setup(t, data)
			got, err := Trusted(data, c.configured, c.split)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("Trusted = %q, %v; want an error with %q", got, err, c.wantErr)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("Trusted = %q, %v; want %q", got, err, c.want)
			}
		})
	}
}
