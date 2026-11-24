package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/privmode"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// workerSpillSink is cov96aManualSink with the WASM workers' spill folder.
func workerSpillSink(t *testing.T) (*fileAuditSink, string) {
	t.Helper()
	s := cov96aManualSink(t)
	dir := filepath.Join(filepath.Dir(s.path), auditlog.WorkerSpillDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s.workerSpillPath = filepath.Join(dir, auditlog.SpillFileName)
	// A worker takes its lock before it writes a record, which makes it.
	cov96aWrite(t, workerSpillLock(s), nil)
	return s, dir
}

func workerSpillLock(s *fileAuditSink) string {
	return filepath.Join(filepath.Dir(s.workerSpillPath), auditlog.LockFileName)
}

func gapLine(t *testing.T, id string) []byte {
	t.Helper()
	line, err := json.Marshal(auditlog.SpillRecord{Event: SecretAuditEvent{EventID: id, Kind: secretAuditKindGap, Result: secretAuditResultGap, Dropped: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return append(line, '\n')
}

// The workers spill into a folder of their own; the daemon drains it after
// its own spill, and takes only a plain file with one name from it.
func TestDrainWorkerSpill(t *testing.T) {
	t.Run("drained after the daemon's own", func(t *testing.T) {
		s, _ := workerSpillSink(t)
		cov96aWrite(t, s.spillPath, gapLine(t, "daemon-gap"))
		cov96aWrite(t, s.workerSpillPath, gapLine(t, "worker-gap"))
		for s.drainSpill() {
		}
		out, err := os.ReadFile(s.path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(out), "\n") < 2 {
			t.Fatalf("audit log = %q, want both spills", out)
		}
		for _, p := range []string{s.spillPath, s.workerSpillPath} {
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Fatalf("%s left behind: %v", p, err)
			}
		}
	})
	outside := filepath.Join(t.TempDir(), "host-secret")
	cov96aWrite(t, outside, gapLine(t, "host"))
	for name, plant := range map[string]func(s *fileAuditSink) error{
		"symlink":     func(s *fileAuditSink) error { return os.Symlink(outside, s.workerSpillPath) },
		"hard link":   func(s *fileAuditSink) error { return os.Link(outside, s.workerSpillPath) },
		"folder":      func(s *fileAuditSink) error { return os.Mkdir(s.workerSpillPath, 0o700) },
		"empty":       func(s *fileAuditSink) error { return os.WriteFile(s.workerSpillPath, nil, 0o600) },
		"nothing yet": func(*fileAuditSink) error { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := workerSpillSink(t)
			if err := plant(s); err != nil {
				t.Fatal(err)
			}
			if s.drainSpill() {
				t.Fatal("drained what a worker may not hand the daemon")
			}
			if _, err := os.Lstat(s.spillWorkingPath); !os.IsNotExist(err) {
				t.Fatalf("working segment = %v", err)
			}
			if raw, err := os.ReadFile(outside); err != nil || !strings.Contains(string(raw), "host") {
				t.Fatal("the file a link named was touched")
			}
		})
	}
	t.Run("spill without a lock", func(t *testing.T) {
		s, _ := workerSpillSink(t)
		if err := os.Remove(workerSpillLock(s)); err != nil {
			t.Fatal(err)
		}
		cov96aWrite(t, s.workerSpillPath, gapLine(t, "no-lock"))
		if s.drainSpill() {
			t.Fatal("drained without the workers' lock")
		}
		if _, err := os.Lstat(workerSpillLock(s)); !os.IsNotExist(err) {
			t.Fatalf("the daemon made the workers' lock: %v", err)
		}
	})
	t.Run("lock is a link", func(t *testing.T) {
		s, _ := workerSpillSink(t)
		if err := os.Remove(workerSpillLock(s)); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "nologin")
		if err := os.Symlink(target, workerSpillLock(s)); err != nil {
			t.Fatal(err)
		}
		cov96aWrite(t, s.workerSpillPath, gapLine(t, "link-lock"))
		if s.drainSpill() {
			t.Fatal("drained through a linked lock")
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("the daemon made a file through the workers' link: %v", err)
		}
	})
	t.Run("no worker folder", func(t *testing.T) {
		s := cov96aManualSink(t)
		s.workerSpillPath = filepath.Join(t.TempDir(), "absent", auditlog.SpillFileName)
		if s.drainSpill() {
			t.Fatal("drained a folder that is not there")
		}
		if claimed, err := (&fileAuditSink{}).claimWorkerSpill("w"); claimed || err != nil {
			t.Fatalf("sink without a worker spill claimed %v, %v", claimed, err)
		}
	})
}

func TestPrepareWorkerSpillDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit", auditlog.WorkerSpillDirName)
	s := &Service{cfg: config.Config{WasmWorkerDropPrivs: true, WasmWorkerUID: 61000, WasmWorkerGID: 61000}}
	if err := s.prepareWorkerSpillDir(dir); err != nil {
		t.Fatal(err)
	}
	// It stays sandboxd's: each worker gets a folder of its own inside it.
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("spill folder = %v, %v", st, err)
	}
	if uid := int(st.Sys().(*syscall.Stat_t).Uid); uid != os.Geteuid() {
		t.Fatalf("spill folder owner = %d, want sandboxd's %d", uid, os.Geteuid())
	}
	file := filepath.Join(t.TempDir(), "f")
	cov96aWrite(t, file, nil)
	if err := s.prepareWorkerSpillDir(filepath.Join(file, "x")); err == nil {
		t.Fatal("spill folder made under a file")
	}
}

// R3: each worker spills into a folder of its own, and a folder named for
// a sandbox carries only that sandbox's records: a capability for another
// sandbox is refused there.
func TestDrainWorkerSpillFolders(t *testing.T) {
	s, root := workerSpillSink(t)
	s.spillVerify = func(capability string, _ time.Time) (string, string, error) {
		return capability, "inc-" + capability, nil
	}
	mine := filepath.Join(root, "sb-alpha")
	other := filepath.Join(root, "w-0123456789abcdef")
	for _, d := range []string{mine, other} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		cov96aWrite(t, filepath.Join(d, auditlog.LockFileName), nil)
	}
	egress := func(capability, dest string) []byte {
		line, err := json.Marshal(auditlog.SpillRecord{Event: SecretAuditEvent{EventID: dest, Kind: secretAuditKindEgress, Destination: dest, SandboxID: "claimed"}, Capability: capability})
		if err != nil {
			t.Fatal(err)
		}
		return append(line, '\n')
	}
	cov96aWrite(t, filepath.Join(mine, auditlog.SpillFileName), append(egress("alpha", "own.example:443"), egress("beta", "forged.example:443")...))
	cov96aWrite(t, filepath.Join(other, auditlog.SpillFileName), egress("gamma", "host.example:443"))
	// The folders are listed at most once an hour here: everything one
	// listing finds is still drained.
	s.workerScanEvery = time.Hour
	for s.drainSpill() {
	}
	out, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	log := string(out)
	if !strings.Contains(log, "own.example:443") || !strings.Contains(log, "host.example:443") {
		t.Fatalf("records missing from the audit log: %s", log)
	}
	if strings.Contains(log, "forged.example:443") {
		t.Fatal("a record for another sandbox was taken from a sandbox's own folder")
	}
	for _, d := range []string{mine, other} {
		if _, err := os.Stat(filepath.Join(d, auditlog.SpillFileName)); !os.IsNotExist(err) {
			t.Fatalf("%s not drained: %v", d, err)
		}
	}
	if _, err := os.Stat(s.spillWorkingPath + spillFromSuffix); !os.IsNotExist(err) {
		t.Fatalf("folder note left behind: %v", err)
	}
	if spillSandbox(filepath.Join(t.TempDir(), "none")) != "" {
		t.Fatal("a segment without a folder note named a sandbox")
	}

	// A segment that shows up after the listing waits for the next one,
	// so a drain before every audit event does not stat every folder.
	cov96aWrite(t, filepath.Join(other, auditlog.SpillFileName), egress("gamma", "later.example:443"))
	if s.drainSpill() {
		t.Fatal("the folders were listed again within the interval")
	}
	s.workerScanAt = time.Now().Add(-2 * time.Hour)
	for s.drainSpill() {
	}
	if out, _ := os.ReadFile(s.path); !strings.Contains(string(out), "later.example:443") {
		t.Fatal("the next listing did not drain the new segment")
	}
	// A spill folder that is a link, or a plain file, is never listed.
	if err := os.Symlink(other, filepath.Join(root, "sb-link")); err != nil {
		t.Fatal(err)
	}
	cov96aWrite(t, filepath.Join(root, "stray"), nil)
	cov96aWrite(t, filepath.Join(other, auditlog.SpillFileName), egress("gamma", "x.example:443"))
	if got := listWorkerSpills(root); len(got) != 1 || got[0] != filepath.Base(other) {
		t.Fatalf("listWorkerSpills = %v", got)
	}
	if listWorkerSpills(filepath.Join(root, "missing")) != nil {
		t.Fatal("a missing root listed folders")
	}

	// A folder whose worker is gone (retired) is drained under the same
	// rule, then removed; an empty retired one is removed too.
	retired := filepath.Join(root, auditlog.WorkerSpillRetiredPrefix+"sb-alpha")
	empty := filepath.Join(root, auditlog.WorkerSpillRetiredPrefix+"w-00")
	for _, d := range []string{retired, empty} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		cov96aWrite(t, filepath.Join(d, auditlog.LockFileName), nil)
	}
	cov96aWrite(t, filepath.Join(retired, auditlog.SpillFileName), append(egress("alpha", "last.example:443"), egress("beta", "forged2.example:443")...))
	s.workerScanAt = time.Time{}
	for s.drainSpill() {
	}
	s.workerScanAt = time.Time{}
	for s.drainSpill() {
	}
	out, _ = os.ReadFile(s.path)
	if !strings.Contains(string(out), "last.example:443") || strings.Contains(string(out), "forged2.example:443") {
		t.Fatalf("retired folder drained wrongly: %s", out)
	}
	for _, d := range []string{retired, empty} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("retired folder %s kept: %v", d, err)
		}
	}
}

// Only a WASM sandbox's mounts are started for its worker's uid.
func TestMountCtxFor(t *testing.T) {
	s := &Service{cfg: config.Config{WasmWorkerDropPrivs: true, WasmWorkerUID: 61000, WasmWorkerGID: 61000}}
	ctx := context.Background()
	if got := s.mountCtxFor(ctx, &models.Sandbox{Runtime: models.RuntimeDocker}); got != ctx {
		t.Fatal("a container's mounts got a consumer")
	}
	wasmCtx := s.mountCtxFor(ctx, &models.Sandbox{Runtime: models.RuntimeWasm})
	if dropped := worker.ConfinementFor(true, 1, 1).Enabled(); (wasmCtx != ctx) != dropped {
		t.Fatalf("WASM mount ctx changed=%v, want %v", wasmCtx != ctx, dropped)
	}
	s.cfg.WasmWorkerDropPrivs = false
	if s.wasmMountCtx(ctx) != ctx {
		t.Fatal("a consumer with the drop off")
	}
	// Split mode: sandboxd is not root, but the helper drops every worker,
	// so a WASM sandbox's mounts name that consumer, and the helper-backed
	// mount manager first checks the helper lends mount points to WASM
	// hosts (M1 PR 15): one that does not is refused before mounting
	// anything.
	s.cfg.PrivilegeMode, s.cfg.WasmWorkerDropPrivs = privmode.Split, true
	m, err := mounts.NewRemote(slog.New(slog.DiscardHandler), refusingRemote{t}, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.MountAll(s.mountCtxFor(ctx, &models.Sandbox{Runtime: models.RuntimeWasm}), "sb-1",
		[]models.MountSpec{{Type: models.MountTypeNFS, Source: "127.0.0.1:/e", Target: "/mnt"}})
	if !errors.Is(err, mounts.ErrMountsUnavailable) {
		t.Fatalf("a WASM sandbox's mounts on a helper that lends none: %v, want a 501", err)
	}
}

// refusingRemote is a helper that lends no mount points to WASM hosts, and
// fails the test if a mount reaches it.
type refusingRemote struct{ t *testing.T }

func (r refusingRemote) Mount(context.Context, string, mounts.RemoteMode, []models.MountSpec) (mounts.RemoteResult, error) {
	r.t.Fatal("a WASM sandbox's mount reached the root helper")
	return mounts.RemoteResult{}, nil
}

func (refusingRemote) Unmount(context.Context, string, bool) (bool, error) { return false, nil }
func (refusingRemote) Sweep(context.Context, []string) error               { return nil }
func (refusingRemote) Ready() error                                        { return nil }
func (refusingRemote) WasmReady(context.Context) error {
	return fmt.Errorf("%w: the helper lends no mount points to WASM hosts", mounts.ErrMountsUnavailable)
}

// A worker holding its spill lock never stalls the drain: the drain runs on
// the audit writer holding spillMu and the audit lock, so it skips that
// folder for this round (counted) and takes it once the lock is free.
func TestDrainSkipsWorkerHeldSpillLock(t *testing.T) {
	s, root := workerSpillSink(t)
	s.workerScanEvery = 0
	wdir := filepath.Join(root, "sb-held")
	if err := os.Mkdir(wdir, 0o700); err != nil {
		t.Fatal(err)
	}
	cov96aWrite(t, filepath.Join(wdir, auditlog.SpillFileName), gapLine(t, "held"))
	lock := filepath.Join(wdir, auditlog.LockFileName)
	cov96aWrite(t, lock, nil)
	f, err := os.OpenFile(lock, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	busy := auditWorkerSpillBusyTotal.Value()
	done := make(chan bool, 1)
	go func() { done <- s.drainSpill() }()
	select {
	case drained := <-done:
		if drained {
			t.Fatal("drained a folder whose lock a worker holds")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the drain waited for a worker's lock")
	}
	if auditWorkerSpillBusyTotal.Value() != busy+1 {
		t.Fatalf("busy count %d -> %d", busy, auditWorkerSpillBusyTotal.Value())
	}
	// The daemon's own spill still goes in meanwhile.
	app := make(chan error, 1)
	go func() { app <- s.appendSpillRecords(auditlog.SpillRecord{Event: SecretAuditEvent{EventID: "daemon"}}) }()
	select {
	case err := <-app:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the daemon's spill waited for a worker's lock")
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	for s.drainSpill() {
	}
	if _, err := os.Stat(filepath.Join(wdir, auditlog.SpillFileName)); !os.IsNotExist(err) {
		t.Fatalf("the folder was not drained once its lock was free: %v", err)
	}
	if out, _ := os.ReadFile(s.path); !strings.Contains(string(out), "ae-") && !strings.Contains(string(out), "held") {
		t.Fatalf("audit log = %s", out)
	}
}

// A folder note left by a crash between claimSpillFrom's note and its
// rename never names the next segment's sandbox: the daemon's own spill is
// drained as the daemon's.
func TestDrainIgnoresStaleFolderNote(t *testing.T) {
	s, _ := workerSpillSink(t)
	s.spillVerify = func(capability string, _ time.Time) (string, string, error) {
		return capability, "inc-" + capability, nil
	}
	cov96aWrite(t, s.spillWorkingPath+spillFromSuffix, []byte("sb-victim"))
	line, err := json.Marshal(auditlog.SpillRecord{Event: SecretAuditEvent{EventID: "e1", Kind: secretAuditKindEgress, Destination: "daemon.example:443"}, Capability: "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	cov96aWrite(t, s.spillPath, append(line, '\n'))
	for s.drainSpill() {
	}
	out, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "daemon.example:443") {
		t.Fatalf("the daemon's record was bound to the stale note's sandbox: %s", out)
	}
	if _, err := os.Stat(s.spillWorkingPath + spillFromSuffix); !os.IsNotExist(err) {
		t.Fatalf("stale note kept: %v", err)
	}
}
