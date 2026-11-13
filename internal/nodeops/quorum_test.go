package nodeops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/raftlogdir"
)

// survivor is a server node with a Raft log, stopped.
func survivor(t *testing.T, env string) node {
	t.Helper()
	n := newNode(t, "SB_NODE_ID=server-1\nSB_RAFT_ADVERTISE_ADDR=10.0.0.5:7000\n"+env)
	makeDB(t, filepath.Join(n.lib, "state.db"), "x")
	write(t, filepath.Join(n.lib, "raft", "raft-stable.bolt"), "stable")
	return n
}

func recoverQuorum(t *testing.T, n node, o QuorumOptions) (QuorumResult, string, error) {
	t.Helper()
	var out bytes.Buffer
	o.ConfigDir, o.Out = n.etc, &out
	if o.Host == nil {
		o.Host = &fakeHost{}
	}
	o.hostname = func() (string, error) { return "server-1.example", nil }
	if o.now == nil {
		o.now = func() time.Time { return time.Unix(1762500000, 0) }
	}
	o.poll = time.Millisecond
	res, err := RecoverQuorum(context.Background(), o)
	return res, out.String(), err
}

// peers.json is byte for byte what raft-lost-quorum-recover.sh wrote, and
// what internal/cluster/raft_recovery.go reads: this node, as the only
// voter. The node is backed up first.
func TestRecoverQuorumWritesPeersJSON(t *testing.T) {
	n := survivor(t, "")
	res, out, err := recoverQuorum(t, n, QuorumOptions{})
	if err != nil {
		t.Fatalf("recover-quorum: %v\n%s", err, out)
	}
	const want = `[
  {
    "id": "server-1",
    "address": "10.0.0.5:7000",
    "non_voter": false,
    "suffrage": "Voter"
  }
]
`
	peers := filepath.Join(n.lib, "raft", "peers.json")
	if got := read(t, peers); got != want {
		t.Fatalf("peers.json:\n%s\nwant:\n%s", got, want)
	}
	if st, _ := os.Stat(peers); st.Mode().Perm() != 0o600 {
		t.Errorf("peers.json mode %v", st.Mode())
	}
	wantBackup := filepath.Join(n.lib, "backups", "pre-recover-quorum-server-1.example-20251107T072000Z.tar.gz")
	if res.Backup != wantBackup || !exists(wantBackup) || res.PeersFile != peers {
		t.Fatalf("result %+v, want the backup at %s", res, wantBackup)
	}
	files, _ := readArchive(t, wantBackup)
	if files[archiveRaft+"/raft-stable.bolt"] != "stable" {
		t.Error("the backup lacks the Raft log")
	}
	for _, s := range []string{"start sandboxd on this node only", "recover-quorum --rejoin --start"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}

	// Again: refused without --force, rewritten with it.
	if _, _, err := recoverQuorum(t, n, QuorumOptions{NoBackup: true}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("second run: %v", err)
	}
	if _, _, err := recoverQuorum(t, n, QuorumOptions{NoBackup: true, Force: true, RaftAddress: "server-1.internal:7000"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, peers), `"address": "server-1.internal:7000"`) {
		t.Fatalf("--force did not rewrite peers.json:\n%s", read(t, peers))
	}
}

func TestRecoverQuorumBackupChoices(t *testing.T) {
	n := survivor(t, "")
	custom := filepath.Join(t.TempDir(), "pre.tgz")
	res, _, err := recoverQuorum(t, n, QuorumOptions{BackupOutput: custom})
	if err != nil || res.Backup != custom || !exists(custom) {
		t.Fatalf("res %+v err %v", res, err)
	}
	n = survivor(t, "")
	res, _, err = recoverQuorum(t, n, QuorumOptions{NoBackup: true})
	if err != nil || res.Backup != "" || exists(filepath.Join(n.lib, "backups")) {
		t.Fatalf("--no-backup: res %+v err %v", res, err)
	}
	// A backup that fails stops the recovery before peers.json.
	n = newNode(t, "SB_NODE_ID=server-1\nSB_RAFT_ADVERTISE_ADDR=10.0.0.5:7000\n")
	write(t, filepath.Join(n.lib, "raft", "raft-stable.bolt"), "stable")
	write(t, filepath.Join(n.lib, "state.db"), "not a database")
	if _, _, err := recoverQuorum(t, n, QuorumOptions{}); err == nil || !strings.Contains(err.Error(), "--no-backup") {
		t.Fatalf("err = %v", err)
	}
	if exists(filepath.Join(n.lib, "raft", "peers.json")) {
		t.Fatal("peers.json written after a failed backup")
	}
}

func TestRecoverQuorumRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		env    string
		o      QuorumOptions
		host   *fakeHost
		noRaft bool
		usage  bool
		want   string
	}{
		"a worker":             {env: "SB_NODE_ROLE=worker\n", want: `role is "worker"`},
		"no address":           {env: "SB_RAFT_ADVERTISE_ADDR=\n", usage: true, want: "--raft-address are required"},
		"a bad node id":        {o: QuorumOptions{NodeID: "-x", RaftAddress: "10.0.0.5:7000"}, env: "SB_NODE_ID=\n", usage: true, want: "is not a node ID"},
		"another node":         {o: QuorumOptions{NodeID: "server-2"}, usage: true, want: "is not this node"},
		"a bind address":       {o: QuorumOptions{RaftAddress: "0.0.0.0:7000"}, usage: true, want: "bind address"},
		"no port":              {o: QuorumOptions{RaftAddress: "10.0.0.5"}, usage: true, want: "--raft-address"},
		"a bad port":           {o: QuorumOptions{RaftAddress: "10.0.0.5:0"}, usage: true, want: "no valid port"},
		"no host":              {o: QuorumOptions{RaftAddress: ":7000"}, usage: true, want: "no host"},
		"no raft data":         {noRaft: true, want: "no Raft data"},
		"sandboxd running":     {host: &fakeHost{active: true}, want: "stop sandboxd on every surviving server"},
		"unreadable env files": {env: "\x00", want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			n := survivor(t, tc.env)
			if tc.noRaft {
				if err := os.RemoveAll(filepath.Join(n.lib, "raft")); err != nil {
					t.Fatal(err)
				}
			}
			if name == "unreadable env files" {
				if err := os.Mkdir(filepath.Join(n.etc, "cluster.env"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.host != nil {
				tc.o.Host = tc.host
			}
			_, _, err := recoverQuorum(t, n, tc.o)
			if err == nil || !strings.Contains(err.Error(), tc.want) || errors.Is(err, ErrUsage) != tc.usage {
				t.Fatalf("err = %v, want %q (usage %v)", err, tc.want, tc.usage)
			}
			if exists(filepath.Join(n.lib, "raft", "peers.json")) {
				t.Fatal("peers.json written by a refused run")
			}
		})
	}
}

// --start starts sandboxd and waits until it renamed peers.json (applied)
// and answers /health.
func TestRecoverQuorumStart(t *testing.T) {
	n := survivor(t, "")
	raft := filepath.Join(n.lib, "raft")
	now := time.Unix(1762500000, 0)
	h := &fakeHost{healthFails: 1}
	h.onStart = func() {
		// sandboxd's Raft setup applies the file at boot.
		_ = os.Rename(filepath.Join(raft, "peers.json"), filepath.Join(raft, fmt.Sprintf("peers.json.applied.%d", now.Unix())))
	}
	// An older applied file from a past recovery is not this one.
	write(t, filepath.Join(raft, "peers.json.applied.100"), "old")
	res, out, err := recoverQuorum(t, n, QuorumOptions{NoBackup: true, Start: true, Host: h, now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("recover-quorum --start: %v\n%s", err, out)
	}
	if filepath.Base(res.Applied) != fmt.Sprintf("peers.json.applied.%d", now.Unix()) || !strings.Contains(out, "recovery applied") {
		t.Fatalf("applied %q\n%s", res.Applied, out)
	}

	// sandboxd comes up but never applies the file.
	n = survivor(t, "")
	h = &fakeHost{}
	if _, _, err := recoverQuorum(t, n, QuorumOptions{NoBackup: true, Start: true, Host: h, Timeout: 20 * time.Millisecond}); err == nil || !strings.Contains(err.Error(), "did not apply") {
		t.Fatalf("err = %v", err)
	}
	// sandboxd never comes up.
	n = survivor(t, "")
	h = &fakeHost{startErr: errors.New("unit failed")}
	if _, _, err := recoverQuorum(t, n, QuorumOptions{NoBackup: true, Start: true, Host: h}); err == nil || !strings.Contains(err.Error(), "unit failed") {
		t.Fatalf("err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := waitApplied(ctx, t.TempDir(), time.Now(), time.Minute, time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitApplied after cancel = %v", err)
	}
	if _, err := startAndWait(ctx, &fakeHost{healthFails: -1}, &bytes.Buffer{}, "u", time.Minute, time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("startAndWait after cancel = %v", err)
	}
}

// --rejoin, on a lost server: its stale Raft directory is kept aside, so
// it comes back as a new voter. The seed's bootstrap flag would make it
// start a cluster of its own, so that is refused.
func TestRecoverQuorumRejoin(t *testing.T) {
	now := time.Unix(1762500000, 0)
	t.Run("moves the old log aside and starts", func(t *testing.T) {
		n := survivor(t, "")
		h := &fakeHost{}
		res, out, err := recoverQuorum(t, n, QuorumOptions{Rejoin: true, Start: true, Host: h, now: func() time.Time { return now }})
		if err != nil {
			t.Fatalf("rejoin: %v\n%s", err, out)
		}
		want := filepath.Join(n.lib, "raft.pre-rejoin.1762500000")
		if res.MovedAside != want || read(t, filepath.Join(want, "raft-stable.bolt")) != "stable" || exists(filepath.Join(n.lib, "raft")) {
			t.Fatalf("moved aside %q\n%s", res.MovedAside, out)
		}
		if !h.called("start") {
			t.Fatal("not started")
		}
		// Twice in one second: the second gets its own name.
		write(t, filepath.Join(n.lib, "raft", "raft-stable.bolt"), "new")
		res, _, err = recoverQuorum(t, n, QuorumOptions{Rejoin: true, now: func() time.Time { return now }})
		if err != nil || res.MovedAside != want+".1" {
			t.Fatalf("second rejoin %+v %v", res, err)
		}
	})
	t.Run("nothing to move", func(t *testing.T) {
		n := survivor(t, "")
		if err := os.RemoveAll(filepath.Join(n.lib, "raft")); err != nil {
			t.Fatal(err)
		}
		_, out, err := recoverQuorum(t, n, QuorumOptions{Rejoin: true})
		if err != nil || !strings.Contains(out, "nothing to move aside") || !strings.Contains(out, "start sandboxd: it rejoins") {
			t.Fatalf("err %v\n%s", err, out)
		}
	})
	t.Run("an empty directory is moved", func(t *testing.T) {
		n := survivor(t, "")
		if err := os.RemoveAll(filepath.Join(n.lib, "raft", "raft-stable.bolt")); err != nil {
			t.Fatal(err)
		}
		if res, _, err := recoverQuorum(t, n, QuorumOptions{Rejoin: true}); err != nil || res.MovedAside == "" {
			t.Fatalf("res %+v err %v", res, err)
		}
	})
	for name, tc := range map[string]struct {
		env     string
		o       QuorumOptions
		host    *fakeHost
		notRaft bool
		want    string
	}{
		"the seed":        {env: "SB_CLUSTER_BOOTSTRAP=true\n", want: "SB_CLUSTER_BOOTSTRAP=true"},
		"running":         {host: &fakeHost{active: true}, want: "sandboxd is running"},
		"a worker":        {env: "SB_NODE_ROLE=worker\n", want: "only a server"},
		"not a raft dir":  {notRaft: true, want: "holds no Raft data"},
		"a failing start": {host: &fakeHost{startErr: errors.New("unit failed")}, o: QuorumOptions{Start: true}, want: "unit failed"},
	} {
		t.Run(name, func(t *testing.T) {
			n := survivor(t, tc.env)
			if tc.notRaft {
				tc.o.RaftDir = n.lib
			}
			tc.o.Rejoin = true
			if tc.host != nil {
				tc.o.Host = tc.host
			}
			_, _, err := recoverQuorum(t, n, tc.o)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if tc.want != "unit failed" && !exists(filepath.Join(n.lib, "raft", "raft-stable.bolt")) {
				t.Fatal("a refused rejoin moved the Raft log")
			}
		})
	}
}

// A log SB_RAFT_WAL_DIR put on a disk of its own goes aside with its Raft
// directory, under the same name; if the directory cannot move, the log is
// put back, so the node never keeps a Raft directory without its log.
func TestRecoverQuorumRejoinMovesALogOnItsOwnDisk(t *testing.T) {
	setup := func(t *testing.T) (node, string) {
		own := filepath.Join(t.TempDir(), "disk", "raft-wal")
		n := survivor(t, "SB_RAFT_WAL_DIR="+own+"\n")
		write(t, filepath.Join(n.lib, "raft", raftlogdir.LocationFile), own+"\n")
		write(t, filepath.Join(own, "wal-meta.db"), "meta")
		return n, own
	}
	t.Run("moved aside together", func(t *testing.T) {
		n, own := setup(t)
		res, out, err := recoverQuorum(t, n, QuorumOptions{Rejoin: true})
		if err != nil {
			t.Fatalf("rejoin: %v\n%s", err, out)
		}
		if res.MovedAsideLog != own+".pre-rejoin.1762500000" || res.MovedAside != filepath.Join(n.lib, "raft.pre-rejoin.1762500000") {
			t.Fatalf("moved aside %+v\n%s", res, out)
		}
		if exists(own) || read(t, filepath.Join(res.MovedAsideLog, "wal-meta.db")) != "meta" || !strings.Contains(out, "its log") {
			t.Fatalf("the log was not moved aside:\n%s", out)
		}
		// A second rejoin in the same second takes a name free for both.
		write(t, filepath.Join(n.lib, "raft", "raft-stable.bolt"), "new")
		write(t, filepath.Join(n.lib, "raft", raftlogdir.LocationFile), own+"\n")
		write(t, filepath.Join(own, "wal-meta.db"), "meta2")
		res, _, err = recoverQuorum(t, n, QuorumOptions{Rejoin: true})
		if err != nil || res.MovedAsideLog != own+".pre-rejoin.1762500000.1" || res.MovedAside != filepath.Join(n.lib, "raft.pre-rejoin.1762500000.1") {
			t.Fatalf("second rejoin %+v %v", res, err)
		}
	})
	t.Run("put back when the directory cannot move", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root renames in a read-only directory")
		}
		n, own := setup(t)
		if err := os.Chmod(n.lib, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(n.lib, 0o700) })
		if _, out, err := recoverQuorum(t, n, QuorumOptions{Rejoin: true}); err == nil {
			t.Fatalf("rejoin moved a directory it could not:\n%s", out)
		}
		if read(t, filepath.Join(own, "wal-meta.db")) != "meta" {
			t.Fatal("the log was left aside")
		}
	})
	t.Run("a log directory already gone", func(t *testing.T) {
		n, own := setup(t)
		if err := os.RemoveAll(own); err != nil {
			t.Fatal(err)
		}
		if res, out, err := recoverQuorum(t, n, QuorumOptions{Rejoin: true}); err != nil || res.MovedAsideLog != "" || res.MovedAside == "" {
			t.Fatalf("rejoin %+v %v\n%s", res, err, out)
		}
	})
	t.Run("a bad record", func(t *testing.T) {
		n, _ := setup(t)
		write(t, filepath.Join(n.lib, "raft", raftlogdir.LocationFile), "relative\n")
		if _, _, err := recoverQuorum(t, n, QuorumOptions{Rejoin: true}); err == nil || !exists(filepath.Join(n.lib, "raft")) {
			t.Fatalf("rejoin with a bad record = %v; want refused, nothing moved", err)
		}
	})
}
