package wasm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/aerol-ai/microvm/pkg/hostproc"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

const helperSockets = "/run/aerolvm-rootd/wasm"

// splitDriver is adoptDriver in privilege mode split: workers are the
// helper's, on its sockets, listed through it.
func splitDriver(t *testing.T) (*Driver, *adoptingSupervisor, *adoptingSupervisor, map[string]*socketClient) {
	d, per, res, clients := adoptDriver(t, true)
	d.cfg.HelperSockets = helperSockets
	d.cfg.Worker = worker.Confinement{UID: 61000, GID: shareGID()}
	d.workerCgroup = nil
	return d, per, res, clients
}

func TestSplitSocketsAreTheHelpers(t *testing.T) {
	d, _, _, _ := splitDriver(t)
	if got := d.workerSocketPath("sb-1"); got != helperSockets+"/w-sb-1.sock" {
		t.Fatalf("worker socket %s", got)
	}
	if got := d.workerSocketPath("../x"); got != "" {
		t.Fatalf("worker socket for a bad id %q", got)
	}
	bucket := residentBucketID("", "dig", 128)
	for index, want := range map[int]string{0: helperSockets + "/r-" + bucket + ".sock", 1: helperSockets + "/r-" + bucket + "-2.sock"} {
		sock := d.residentSocketPath(bucket, index)
		if sock != want {
			t.Fatalf("resident socket %d = %s, want %s", index, sock, want)
		}
		if b, i, ok := d.parseResidentSocket(sock); !ok || b != bucket || i != index {
			t.Fatalf("parse %s = %s %d %v", sock, b, i, ok)
		}
	}
	for _, bad := range []string{helperSockets + "/w-" + bucket + ".sock", "/elsewhere/r-" + bucket + ".sock", helperSockets + "/r-x.sock"} {
		if _, _, ok := d.parseResidentSocket(bad); ok {
			t.Fatalf("parsed %s", bad)
		}
	}
	if d.socketsHome() != helperSockets {
		t.Fatalf("sockets home %s", d.socketsHome())
	}
}

// TestSplitAdoptWorkersThroughTheHelper: boot adoption lists the helper's
// hosts, takes a worker on the helper's socket, and stops one elsewhere.
func TestSplitAdoptWorkersThroughTheHelper(t *testing.T) {
	d, _, res, clients := splitDriver(t)
	bucket := residentBucketID("", "dig", 128)
	good := d.residentSocketPath(bucket, 0)
	clients[good] = &socketClient{loaded: map[string]bool{"": true}}
	per := &heldProc{pid: 5}
	stray := &heldProc{pid: 6}
	resident := &heldProc{pid: 7}
	oldStop := stopProcess
	t.Cleanup(func() { stopProcess = oldStop })
	stopProcess = func(p hostproc.Process) {
		if hp, ok := p.(*heldProc); ok {
			hp.markStopped()
		}
	}
	d.SetWorkerLister(func(context.Context) ([]worker.FoundWorker, error) {
		return []worker.FoundWorker{
			{PID: 5, Socket: d.workerSocketPath("sb-a"), Proc: per},
			{PID: 6, Socket: d.cfg.RunDir + "/sockets/sb-b.sock", Proc: stray},
			{PID: 7, Resident: true, Socket: good, Proc: resident},
		}, nil
	})
	report := d.AdoptWorkers(context.Background())
	if report.Workers != 1 || report.ResidentHosts != 1 || report.Stopped != 1 || !stray.wasStopped() || per.wasStopped() {
		t.Fatalf("report %+v stray stopped %v", report, stray.wasStopped())
	}
	if res.adopted[d.residentHostKey(bucket, 0)] != good {
		t.Fatalf("resident adopted %v", res.adopted)
	}
	d.SetWorkerLister(func(context.Context) ([]worker.FoundWorker, error) { return nil, errors.New("helper down") })
	if r := d.AdoptWorkers(context.Background()); r != (AdoptReport{}) {
		t.Fatalf("helper down: %+v", r)
	}
}

// TestSplitHandsFoldersToTheGroup: sandboxd gives a worker's folder to the
// worker's group, setgid and 2770, as it cannot give it to the worker's
// uid.
func TestSplitHandsFoldersToTheGroup(t *testing.T) {
	d, _, _, _ := splitDriver(t)
	work := filepath.Join(d.cfg.RunDir, "sb-1", "work")
	if err := d.ensureWorkDir(work); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(work)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSetgid == 0 || st.Mode().Perm() != 0o770 || int(st.Sys().(*syscall.Stat_t).Gid) != shareGID() {
		t.Fatalf("work dir %v gid %d", st.Mode(), st.Sys().(*syscall.Stat_t).Gid)
	}
	// A /work that is there already is handed over the same way.
	if err := os.Chmod(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.ensureWorkDir(work); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(work); st.Mode().Perm() != 0o770 {
		t.Fatalf("existing work dir %v", st.Mode())
	}
	// A group sandboxd is not in cannot be given: the error comes back.
	d.cfg.Worker.GID = 4242424
	if err := d.handToWorker(work); err == nil && os.Geteuid() != 0 {
		t.Fatal("a folder went to a group sandboxd is not in")
	}
}

func TestCacheName(t *testing.T) {
	root := "/var/lib/sandboxd/wasm/modules/cache/wazero-compile"
	for dir, want := range map[string]string{
		root + "/owners/operator":               "operator",
		root + "/owners/owner-0123456789abcdef": "owner-0123456789abcdef",
		root + "/slots/0123456789abcdef/cache":  "slots/0123456789abcdef/cache",
		root + "/owners/../../etc":              "",
		"/elsewhere/owners/operator":            "",
		"":                                      "",
		root:                                    "",
	} {
		if got := CacheName(root, dir); got != want {
			t.Errorf("CacheName(%q) = %q, want %q", dir, got, want)
		}
	}
	if CacheName("", root+"/owners/operator") != "" {
		t.Fatal("a name with no root")
	}
}

// TestSplitRecordRoutes: a sandbox record written in split mode names the
// helper's sockets, and boot adoption takes it (the live box found a
// resident sandbox restored instead of adopted, as the record's resident
// socket was read against the run dir).
func TestSplitRecordRoutes(t *testing.T) {
	d, _, _, _ := splitDriver(t)
	bucket := residentBucketID("", "dig", 128)
	for name, tc := range map[string]struct {
		rec  instanceRecord
		want bool
	}{
		"resident":                   {instanceRecord{Socket: d.residentSocketPath(bucket, 1), Resident: true, WorkerKey: d.residentHostKey(bucket, 1)}, true},
		"resident under another key": {instanceRecord{Socket: d.residentSocketPath(bucket, 1), Resident: true, WorkerKey: bucket}, false},
		"resident in the run dir":    {instanceRecord{Socket: filepath.Join(d.cfg.RunDir, "resident", bucket+".sock"), Resident: true, WorkerKey: bucket}, false},
		"its own worker":             {instanceRecord{Socket: d.workerSocketPath("sb-1"), WorkerKey: "sb-1"}, true},
		"another's worker":           {instanceRecord{Socket: d.workerSocketPath("sb-2"), WorkerKey: "sb-1"}, false},
	} {
		if got := d.recordRoutesValid("sb-1", tc.rec, false); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// shareGID is a group this test may give a folder to: its own, or, as
// root, whose gid 0 turns the worker's confinement off, another.
func shareGID() int {
	if g := os.Getgid(); g != 0 {
		return g
	}
	return 4242
}
