package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// bootVerifyFixture is a Service whose audit sink is opened on demand with
// the given boot mode, over a directory the test owns across restarts.
func bootVerifyService(t *testing.T, dbPath, mode string, st *storepkg.Store) *Service {
	t.Helper()
	svc := &Service{cfg: config.Config{DBPath: dbPath, SecretAuditRetentionDays: 3650, SecretAuditBootVerify: mode, AuditIndexEnabled: st != nil}, store: st}
	t.Cleanup(svc.CloseSecretAuditSink)
	return svc
}

func emitChained(t *testing.T, sink *fileAuditSink, n int, prefix string) {
	t.Helper()
	for i := range n {
		sink.Emit(SecretAuditEvent{SandboxID: fmt.Sprintf("%s-%d", prefix, i), EventID: fmt.Sprintf("%s-%03d", prefix, i), Result: secretAuditResultSuccess, Reason: secretAuditReasonOK, Kind: secretAuditKindSecretOpen})
	}
	if err := sink.Sync(); err != nil {
		t.Fatal(err)
	}
}

func TestBootVerifyFullModeIsOnePassWithWitnessProbe(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	first := bootVerifyService(t, dbPath, secretAuditBootVerifyFull, nil)
	sink := first.secretAuditSink().(*fileAuditSink)
	emitChained(t, sink, 20, "a")
	w := &stubWitness{}
	first.auditWitness = w
	if err := first.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatal(err)
	}
	shipped, _ := sink.chainTip()
	emitChained(t, sink, 5, "b") // the witnessed head is now an ancestor, not the tip
	first.CloseSecretAuditSink()

	scans := secretAuditFullScans.Load()
	second := bootVerifyService(t, dbPath, secretAuditBootVerifyFull, nil)
	second.auditWitness = w
	second.ensureSecretAuditSink()
	if got := secretAuditFullScans.Load() - scans; got != 1 {
		t.Fatalf("open made %d full passes, want 1", got)
	}
	f := second.secretAuditFile
	if f.bootTrusted != 0 || !f.bootScan.found[shipped] || f.bootScan.records != 25 {
		t.Fatalf("boot scan = trusted %d found %v records %d", f.bootTrusted, f.bootScan.found, f.bootScan.records)
	}
	if err := second.ValidateSecretAuditWitness(); err != nil {
		t.Fatalf("boot witness validation: %v", err)
	}
	if got := secretAuditFullScans.Load() - scans; got != 1 {
		t.Fatalf("boot witness validation re-read the file (%d passes)", got)
	}
	// Once the chain moved on, validation reads again — but still one pass
	// and never an all-hashes slice (the probe is the witnessed head).
	emitChained(t, f, 1, "c")
	if err := second.ValidateSecretAuditWitness(); err != nil {
		t.Fatalf("post-append witness validation: %v", err)
	}
	if got := secretAuditFullScans.Load() - scans; got != 2 {
		t.Fatalf("post-append validation made %d passes total, want 2", got)
	}
	// An older witnessed head (not the receipt) is located by the fallback.
	older := f.bootScan.head
	w.remoteHead, w.remoteOK = older, true
	if ok, _, witnessed, err := second.VerifySecretAuditWitness(); !ok || witnessed != older || err != nil {
		t.Fatalf("older ancestor verify = %v %q %v", ok, witnessed, err)
	}
	// A head that was never in the chain fails.
	w.remoteHead = strings.Repeat("e", 64)
	if ok, _, _, err := second.VerifySecretAuditWitness(); ok || err != nil {
		t.Fatalf("foreign head verify = %v %v", ok, err)
	}
	if err := second.ValidateSecretAuditWitness(); err == nil {
		t.Fatal("foreign witnessed head validated at boot")
	}
}

func TestBootVerifyCheckpointModeReadsOnlyTheTail(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	first := bootVerifyService(t, dbPath, secretAuditBootVerifyCheckpoint, nil)
	sink := first.secretAuditSink().(*fileAuditSink)
	emitChained(t, sink, 30, "p")
	cp := loadVerifiedCheckpoint(sink.verifiedPath)
	if cp == nil {
		t.Fatal("sync did not write secrets.verified")
	}
	st, _ := os.Stat(sink.path)
	if head, eventID := sink.chainTip(); cp.Offset != st.Size() || cp.Head != head || cp.EventID != eventID || cp.LineOffset >= cp.Offset {
		t.Fatalf("checkpoint = %+v, file %d bytes head %s", cp, st.Size(), head)
	}
	// Append without syncing: bytes past the checkpoint are the "tail".
	sink.Emit(SecretAuditEvent{SandboxID: "tail", EventID: "tail-0", Result: secretAuditResultSuccess})
	sink.Emit(SecretAuditEvent{SandboxID: "tail", EventID: "tail-1", Result: secretAuditResultSuccess})
	first.CloseSecretAuditSink() // shutdown syncs: checkpoint moves to EOF
	head, _ := sink.chainTip()
	cp = loadVerifiedCheckpoint(sink.verifiedPath)
	after, _ := os.Stat(sink.path)
	if cp.Offset != after.Size() {
		t.Fatalf("shutdown checkpoint offset %d, file %d", cp.Offset, after.Size())
	}
	// Roll the checkpoint back a few records so this boot has a real tail.
	rolled := *cp
	rolled.Offset, rolled.LineOffset, rolled.Head, rolled.EventID = checkpointAtRecord(t, sink.path, 28)
	raw, _ := json.Marshal(rolled)
	if err := os.WriteFile(sink.verifiedPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	scans := secretAuditFullScans.Load()
	second := bootVerifyService(t, dbPath, secretAuditBootVerifyCheckpoint, nil)
	second.ensureSecretAuditSink()
	f := second.secretAuditFile
	if f == nil || second.secretAuditInitErr != nil {
		t.Fatalf("checkpoint boot failed: %v", second.secretAuditInitErr)
	}
	if f.bootTrusted != rolled.Offset || f.bootScan.records != 3 || f.bootScan.head != head {
		t.Fatalf("boot scan = trusted %d records %d head %s (want %d/3/%s)", f.bootTrusted, f.bootScan.records, f.bootScan.head, rolled.Offset, head)
	}
	second.secretAuditBootVerify.Wait()
	if got := secretAuditFullScans.Load() - scans; got != 1 {
		t.Fatalf("checkpoint boot: %d full passes (want exactly the background one)", got)
	}
	if second.secretAuditChainBroken.Load() || secretAuditChainVerifyOK.Value() != 1 {
		t.Fatal("intact chain reported broken after checkpoint boot")
	}
	if events, _, err := second.ListSecretAuditLocal(context.Background(), "tail", SecretAuditQuery{}); err != nil || len(events) != 2 {
		t.Fatalf("reads after checkpoint boot = %d events err=%v", len(events), err)
	}
	// The writer continues the chain from the verified head.
	emitChained(t, f, 3, "q")
	if _, err := second.VerifySecretAuditChain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if secretAuditChainVerifyOK.Value() != 1 {
		t.Fatal("chain after checkpoint boot + appends does not verify")
	}
}

// checkpointAtRecord returns the checkpoint values for the n-th record.
func checkpointAtRecord(t *testing.T, path string, n int) (offset, lineOffset int64, head, eventID string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var pos int64
	for i, line := range bytes.SplitAfter(raw, []byte("\n")) {
		if len(line) == 0 {
			break
		}
		if i == n {
			var ev SecretAuditEvent
			if err := json.Unmarshal(bytes.TrimSpace(line), &ev); err != nil {
				t.Fatal(err)
			}
			return pos + int64(len(line)), pos, ev.EventHash, ev.EventID
		}
		pos += int64(len(line))
	}
	t.Fatalf("record %d not found", n)
	return 0, 0, "", ""
}

func TestBootVerifyCheckpointModeCatchesPrefixTamperInBackground(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	first := bootVerifyService(t, dbPath, secretAuditBootVerifyCheckpoint, st)
	sink := first.secretAuditSink().(*fileAuditSink)
	emitChained(t, sink, 12, "x")
	first.CloseSecretAuditSink()
	// Tamper with a record inside the checkpoint's trusted prefix.
	raw, err := os.ReadFile(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte(`"sandbox_id":"x-3"`), []byte(`"sandbox_id":"x-Z"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("test setup: record not found")
	}
	if err := os.WriteFile(sink.path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	// Full mode refuses to open, as before.
	full := bootVerifyService(t, dbPath, secretAuditBootVerifyFull, nil)
	full.ensureSecretAuditSink()
	if full.secretAuditInitErr == nil || !strings.Contains(full.secretAuditInitErr.Error(), "event_hash mismatch") {
		t.Fatalf("full boot on tampered prefix err = %v", full.secretAuditInitErr)
	}
	// Checkpoint mode boots (the tail and the checkpoint record verify),
	// then the background pass finds the break and withholds reads.
	breaks := secretAuditIndexChainBreaks.Value()
	cpMode := bootVerifyService(t, dbPath, secretAuditBootVerifyCheckpoint, st)
	cpMode.ensureSecretAuditSink()
	if cpMode.secretAuditInitErr != nil {
		t.Fatalf("checkpoint boot on tampered prefix: %v", cpMode.secretAuditInitErr)
	}
	cpMode.secretAuditBootVerify.Wait()
	if !cpMode.secretAuditChainBroken.Load() || secretAuditChainVerifyOK.Value() != 0 || secretAuditIndexChainBreaks.Value() != breaks+1 {
		t.Fatalf("background pass did not latch the break: broken=%v ok=%d breaks=%d", cpMode.secretAuditChainBroken.Load(), secretAuditChainVerifyOK.Value(), secretAuditIndexChainBreaks.Value()-breaks)
	}
	if cpMode.secretAuditIndex == nil || !cpMode.secretAuditIndex.broken.Load() {
		t.Fatal("index not disabled after the break")
	}
	if _, _, err := cpMode.ListSecretAuditLocal(context.Background(), "x-1", SecretAuditQuery{}); !errors.Is(err, ErrSecretAuditChainBroken) {
		t.Fatalf("read after break err = %v", err)
	}
	// Evidence keeps being appended and stays self-consistent from the
	// checkpoint on.
	emitChained(t, cpMode.secretAuditFile, 2, "after")
	report, err := cpMode.VerifySecretAuditChain(context.Background())
	if err != nil || report.OK || !strings.Contains(report.Error, "event_hash mismatch") {
		t.Fatalf("verify after break = %+v err=%v", report, err)
	}
}

func TestBootVerifyCheckpointFallsBackToFullReadWhenStale(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	first := bootVerifyService(t, dbPath, secretAuditBootVerifyCheckpoint, nil)
	sink := first.secretAuditSink().(*fileAuditSink)
	emitChained(t, sink, 6, "s")
	first.CloseSecretAuditSink()
	good := loadVerifiedCheckpoint(sink.verifiedPath)
	if good == nil {
		t.Fatal("no checkpoint")
	}
	fileSize := good.Offset
	for name, mutate := range map[string]func(cp secretAuditVerifiedCheckpoint) []byte{
		"beyond EOF": func(cp secretAuditVerifiedCheckpoint) []byte {
			cp.Offset += 10
			cp.LineOffset += 10
			b, _ := json.Marshal(cp)
			return b
		},
		"wrong head": func(cp secretAuditVerifiedCheckpoint) []byte {
			cp.Head = strings.Repeat("a", 64)
			b, _ := json.Marshal(cp)
			return b
		},
		"mid-record":     func(cp secretAuditVerifiedCheckpoint) []byte { cp.LineOffset += 5; b, _ := json.Marshal(cp); return b },
		"not on newline": func(cp secretAuditVerifiedCheckpoint) []byte { cp.Offset--; b, _ := json.Marshal(cp); return b },
		"malformed":      func(secretAuditVerifiedCheckpoint) []byte { return []byte("{nope") },
		"zero offset":    func(cp secretAuditVerifiedCheckpoint) []byte { cp.Offset = 0; b, _ := json.Marshal(cp); return b },
		"oversized record": func(cp secretAuditVerifiedCheckpoint) []byte {
			cp.LineOffset = 0
			cp.Offset = secretAuditMaxLineBytes + 2
			b, _ := json.Marshal(cp)
			return b
		},
	} {
		if err := os.WriteFile(sink.verifiedPath, mutate(*good), 0o600); err != nil {
			t.Fatal(err)
		}
		scans := secretAuditFullScans.Load()
		svc := bootVerifyService(t, dbPath, secretAuditBootVerifyCheckpoint, nil)
		svc.ensureSecretAuditSink()
		if svc.secretAuditInitErr != nil {
			t.Fatalf("%s: boot failed: %v", name, svc.secretAuditInitErr)
		}
		if svc.secretAuditFile.bootTrusted != 0 || secretAuditFullScans.Load() != scans+1 {
			t.Fatalf("%s: stale checkpoint was trusted (trusted=%d passes=%d)", name, svc.secretAuditFile.bootTrusted, secretAuditFullScans.Load()-scans)
		}
		if got := loadVerifiedCheckpoint(sink.verifiedPath); got == nil || got.Offset != fileSize || got.Head != good.Head {
			t.Fatalf("%s: boot did not re-pin the checkpoint: %+v", name, got)
		}
		svc.CloseSecretAuditSink()
	}
	// No sidecar at all (first boot on an existing log): full read, then pinned.
	_ = os.Remove(sink.verifiedPath)
	scans := secretAuditFullScans.Load()
	svc := bootVerifyService(t, dbPath, secretAuditBootVerifyCheckpoint, nil)
	svc.ensureSecretAuditSink()
	if svc.secretAuditFile.bootTrusted != 0 || secretAuditFullScans.Load() != scans+1 {
		t.Fatal("first checkpoint boot must read the whole file")
	}
	if loadVerifiedCheckpoint(sink.verifiedPath) == nil {
		t.Fatal("first checkpoint boot did not write the sidecar")
	}
	// An empty log never pins a checkpoint.
	empty := bootVerifyService(t, filepath.Join(t.TempDir(), "state.db"), secretAuditBootVerifyCheckpoint, nil)
	es := empty.secretAuditSink().(*fileAuditSink)
	if err := es.Sync(); err != nil {
		t.Fatal(err)
	}
	if loadVerifiedCheckpoint(es.verifiedPath) != nil {
		t.Fatal("empty log pinned a checkpoint")
	}
	if loadVerifiedCheckpoint("") != nil {
		t.Fatal("empty path loaded")
	}
}

func TestBootVerifyCheckpointSurvivesTornTailAndRetention(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	first := bootVerifyService(t, dbPath, secretAuditBootVerifyCheckpoint, nil)
	sink := first.secretAuditSink().(*fileAuditSink)
	emitChained(t, sink, 8, "t")
	first.CloseSecretAuditSink()
	cp := loadVerifiedCheckpoint(sink.verifiedPath)
	// Crash mid-append after the checkpoint.
	fh, err := os.OpenFile(sink.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteString(`{"time":"2026-01-01T00:00:00Z","sandbox_id":"t-9","event_id":"torn`); err != nil {
		t.Fatal(err)
	}
	_ = fh.Close()
	scans := secretAuditFullScans.Load()
	second := bootVerifyService(t, dbPath, secretAuditBootVerifyCheckpoint, nil)
	second.ensureSecretAuditSink()
	f := second.secretAuditFile
	if second.secretAuditInitErr != nil || f.bootRepair == nil || f.bootTrusted != cp.Offset {
		t.Fatalf("torn tail after checkpoint: err=%v repair=%+v trusted=%d", second.secretAuditInitErr, f.bootRepair, f.bootTrusted)
	}
	if secretAuditFullScans.Load() != scans {
		t.Fatal("torn-tail repair after a checkpoint read the whole file")
	}
	second.secretAuditBootVerify.Wait()
	if second.secretAuditChainBroken.Load() {
		t.Fatal("repaired chain reported broken")
	}
	// The marker is the new head and the checkpoint follows it.
	head, _ := f.chainTip()
	if got := loadVerifiedCheckpoint(f.verifiedPath); got == nil || got.Head != head {
		t.Fatalf("checkpoint after repair = %+v, head %s", got, head)
	}

	// Retention rewrites the file: the checkpoint must follow the new offsets
	// so the next boot still starts from it.
	old := time.Now().UTC().Add(-48 * time.Hour)
	for i := range 5 {
		f.Emit(SecretAuditEvent{Time: old.Add(time.Duration(i) * time.Second), SandboxID: "old", EventID: fmt.Sprintf("old-%d", i), Result: secretAuditResultSuccess})
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	// Those landed after newer records, so prune's prefix rule keeps them;
	// prune the original prefix instead by cutting at the file's start time.
	if err := f.Prune(time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	afterPrune := loadVerifiedCheckpoint(f.verifiedPath)
	st, _ := os.Stat(f.path)
	head, _ = f.chainTip()
	if afterPrune == nil || afterPrune.Offset != st.Size() || afterPrune.Head != head {
		t.Fatalf("checkpoint after prune = %+v, file %d head %s", afterPrune, st.Size(), head)
	}
	second.CloseSecretAuditSink()
	scans = secretAuditFullScans.Load()
	third := bootVerifyService(t, dbPath, secretAuditBootVerifyCheckpoint, nil)
	third.ensureSecretAuditSink()
	if third.secretAuditInitErr != nil || third.secretAuditFile.bootTrusted == 0 || secretAuditFullScans.Load() != scans {
		t.Fatalf("boot after prune: err=%v trusted=%d passes=%d", third.secretAuditInitErr, third.secretAuditFile.bootTrusted, secretAuditFullScans.Load()-scans)
	}
	third.secretAuditBootVerify.Wait()
	if third.secretAuditChainBroken.Load() {
		t.Fatal("pruned chain reported broken")
	}
}

func TestBootVerifyCheckpointWitnessIsProvisionalThenProven(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	first := bootVerifyService(t, dbPath, secretAuditBootVerifyCheckpoint, nil)
	sink := first.secretAuditSink().(*fileAuditSink)
	emitChained(t, sink, 10, "w")
	w := &stubWitness{}
	first.auditWitness = w
	if err := first.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatal(err)
	}
	shipped, _ := sink.chainTip()
	emitChained(t, sink, 10, "v") // the shipped head ends up in the trusted prefix
	first.CloseSecretAuditSink()
	// Move the checkpoint to the last record so the shipped head is before it.
	cp := loadVerifiedCheckpoint(sink.verifiedPath)
	if cp == nil || cp.Head == shipped {
		t.Fatalf("test setup: checkpoint %+v", cp)
	}
	provisional := secretAuditBootWitnessProvisional.Value()
	scans := secretAuditFullScans.Load()
	second := bootVerifyService(t, dbPath, secretAuditBootVerifyCheckpoint, nil)
	second.auditWitness = w
	second.ensureSecretAuditSink()
	if second.secretAuditFile.bootTrusted == 0 {
		t.Fatal("checkpoint not used")
	}
	if err := second.ValidateSecretAuditWitness(); err != nil {
		t.Fatalf("provisional witness validation: %v", err)
	}
	if secretAuditBootWitnessProvisional.Value() != provisional+1 {
		t.Fatal("head in the trusted prefix was not accepted provisionally")
	}
	second.secretAuditBootVerify.Wait()
	if got := secretAuditFullScans.Load() - scans; got != 1 {
		t.Fatalf("checkpoint boot with witness made %d synchronous full passes", got)
	}
	// The witness disagreeing with the local receipt is never provisional.
	w.remoteHead = strings.Repeat("b", 64)
	if err := second.ValidateSecretAuditWitness(); err == nil {
		t.Fatal("foreign remote head accepted")
	}
	if got := secretAuditFullScans.Load() - scans; got != 2 {
		t.Fatalf("foreign head fallback made %d passes total, want 2", got)
	}
	// Remote has nothing: fail closed.
	w.remoteHead, w.remoteOK = "", false
	if err := second.ValidateSecretAuditWitness(); err == nil {
		t.Fatal("missing remote head accepted")
	}
	w.remoteErr = errors.New("witness down")
	if err := second.ValidateSecretAuditWitness(); err == nil {
		t.Fatal("witness error accepted")
	}
	w.remoteErr = nil
	// No receipt at all with an external witness: failure.
	_ = os.Remove(second.secretAuditWitnessTipPath())
	_ = os.Remove(second.secretAuditWitnessPath())
	w.remoteHead, w.remoteOK = shipped, true
	if err := second.ValidateSecretAuditWitness(); err == nil {
		t.Fatal("missing local receipt accepted")
	}
}

func TestBootVerifyHelpersEdgeCases(t *testing.T) {
	var none *fileAuditSink
	if none.bootScanCurrent() {
		t.Fatal("nil sink current")
	}
	none.persistVerifiedLocked()
	(*Service)(nil).startSecretAuditBootVerify()
	(&Service{}).startSecretAuditBootVerify()
	// Unknown mode falls back to full.
	sink, err := newFileAuditSinkWith(t.TempDir(), 1, false, "weird")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	if sink.bootVerify != secretAuditBootVerifyFull {
		t.Fatalf("mode = %q", sink.bootVerify)
	}
	// A directory where the log should be is an I/O error, not a torn tail,
	// in checkpoint mode too.
	bad := t.TempDir()
	if err := os.Mkdir(filepath.Join(bad, secretAuditFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	cp := &secretAuditVerifiedCheckpoint{Offset: 10, LineOffset: 0, Head: "h"}
	if _, ok, _ := scanSecretAuditChainFromCheckpoint(filepath.Join(bad, secretAuditFileName), cp, nil); ok {
		t.Fatal("directory as log trusted a checkpoint")
	}
	if _, err := newFileAuditSinkWith(bad, 1, false, secretAuditBootVerifyCheckpoint); err == nil {
		t.Fatal("directory as log opened")
	}
	if _, ok, err := scanSecretAuditChainFromCheckpoint(filepath.Join(bad, "missing"), cp, nil); ok || err != nil {
		t.Fatalf("missing log: ok=%v err=%v", ok, err)
	}
	// A checkpoint whose record is a retention checkpoint lets the next
	// record break the link, exactly as a full scan would.
	dir := t.TempDir()
	path := filepath.Join(dir, secretAuditFileName)
	head := SecretAuditEvent{Time: time.Now().UTC(), EventID: "cp", Result: secretAuditResultSuccess, Kind: secretAuditKindRetentionCheckpoint, WitnessedThrough: "wt"}
	auditlog.LinkEvent(strings.Repeat("d", 64), &head)
	next := SecretAuditEvent{Time: time.Now().UTC(), EventID: "n", SandboxID: "sb", Result: secretAuditResultSuccess}
	auditlog.LinkEvent(strings.Repeat("c", 64), &next) // does not link to the checkpoint: allowed once
	l1, _ := json.Marshal(head)
	l2, _ := json.Marshal(next)
	raw := append(append(append(l1, '\n'), l2...), '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	scan, ok, err := scanSecretAuditChainFromCheckpoint(path, &secretAuditVerifiedCheckpoint{Offset: int64(len(l1)) + 1, LineOffset: 0, Head: head.EventHash, EventID: "cp"}, []string{head.EventHash})
	if err != nil || !ok || scan.head != next.EventHash || scan.records != 1 || !scan.found[head.EventHash] || scan.witnessedThrough != "wt" {
		t.Fatalf("checkpoint-on-checkpoint scan = %+v ok=%v err=%v", scan, ok, err)
	}
}
