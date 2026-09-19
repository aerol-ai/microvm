package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// mismatchWitness ACKs a ship but then reports a different (or failed) remote
// head so retention cannot treat a local receipt as proof of off-node durability.
// mismatchWitness ACKs a ship but then reports a different (or failed) remote
// head so retention cannot treat a local receipt as proof of off-node durability.
type mismatchWitness struct {
	remoteErr error
}

func (mismatchWitness) WitnessHeads(context.Context, []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	return controlplane.WitnessReceipt{ReceiptID: "rcpt-mismatch"}, nil
}

func (w mismatchWitness) LastWitnessedHead(context.Context, string) (string, bool, error) {
	if w.remoteErr != nil {
		return "", false, w.remoteErr
	}
	return "other", true, nil
}

func TestSecretAuditSinkGuardsSidecarsAndEnterpriseInit(t *testing.T) {
	var nilSink *fileAuditSink
	nilSink.Emit(SecretAuditEvent{})
	if err := nilSink.EmitDurable(SecretAuditEvent{}); err == nil {
		t.Fatal("nil durable emit succeeded")
	}
	if err := nilSink.Sync(); err != nil {
		t.Fatalf("nil sync = %v", err)
	}
	nilSink.Close()
	if err := nilSink.Prune(time.Now()); err != nil {
		t.Fatalf("nil prune = %v", err)
	}
	if err := nilSink.pruneWithGuards(time.Now(), "", ""); err != nil {
		t.Fatalf("nil prune guards = %v", err)
	}
	if nilSink.drainSpill() || nilSink.appendSpill(SecretAuditEvent{}) == nil {
		t.Fatal("nil spill helpers succeeded")
	}
	head, id := nilSink.chainTip()
	if head != "" || id != "" {
		t.Fatalf("nil tip = %q %q", head, id)
	}
	nilSink.persistGapState(1)
	if err := writeFileAtomicDurable(" ", []byte("x"), 0o600); err == nil {
		t.Fatal("empty durable sidecar path was accepted")
	}
	if err := persistSpillOffset("", 1); err == nil {
		t.Fatal("empty spill offset was accepted")
	}
	if loadSpillOffset("") != 0 || loadGapCount(filepath.Join(t.TempDir(), "missing")) != 0 {
		t.Fatal("missing sidecars must be zero")
	}
	persistGapCount("", 1)
	clearGapCount("")
	persistChainTip("", "head", "id")
	if err := persistChainTipErr("", "head", "id"); err != nil {
		t.Fatal(err)
	}

	sink, err := newFileAuditSink(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	if cap(sink.ch) != defaultSecretAuditBuffer {
		t.Fatalf("default buffer = %d", cap(sink.ch))
	}
	if err := sink.writeEventBatch(nil, true, true); err != nil {
		t.Fatal(err)
	}
	if err := sink.pruneLocked(time.Time{}, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sink.spillPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if sink.drainSpill() {
		t.Fatal("empty spill segment should not report work")
	}
	line, _ := json.Marshal(SecretAuditEvent{EventID: "spill-resume", Result: secretAuditResultSuccess})
	if err := os.WriteFile(sink.spillWorkingPath, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	// Assert the INVARIANT — an interrupted working file is resumed into the
	// authoritative log — not which goroutine did the resuming. The sink's
	// writer calls drainSpill() at the top of every loop iteration, so it can
	// legitimately consume the working file between the WriteFile above and a
	// direct call here; the direct call then returns false for a resume that
	// did happen. That race is what made this test flaky on CI.
	deadline := time.Now().Add(10 * time.Second)
	resumed := false
	for time.Now().Before(deadline) {
		if sink.drainSpill() {
			resumed = true
			break
		}
		if raw, err := os.ReadFile(sink.path); err == nil && bytes.Contains(raw, []byte(`"spill-resume"`)) {
			resumed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !resumed {
		t.Fatal("interrupted spill working file was not resumed")
	}
	if err := persistSpillOffset(filepath.Join(t.TempDir(), "off"), 12); err != nil {
		t.Fatal(err)
	}
	if got := loadSpillOffset(filepath.Join(t.TempDir(), "missing")); got != 0 {
		t.Fatalf("missing offset = %d", got)
	}

	if err := sink.EmitDurable(SecretAuditEvent{EventID: "close-me", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	sink.Close()
	sink.Emit(SecretAuditEvent{EventID: "after-close"})
	if err := sink.EmitDurable(SecretAuditEvent{EventID: "after-close-d"}); err == nil {
		t.Fatal("closed durable emit succeeded")
	}
	if err := sink.Sync(); err != nil {
		t.Fatalf("closed sync = %v", err)
	}
	if err := sink.pruneWithGuards(time.Now(), "", ""); err != nil {
		t.Fatalf("closed prune = %v", err)
	}
	sink.Close()

	svc := &Service{cfg: config.Config{
		DBPath: filepath.Join(t.TempDir(), "state.db"), EnterpriseMode: true,
	}}
	t.Cleanup(svc.CloseSecretAuditSink)
	got := svc.secretAuditSink().(*fileAuditSink)
	if !got.spillEnabled || cap(got.ch) != enterpriseSecretAuditBuffer {
		t.Fatalf("enterprise sink spill=%v cap=%d", got.spillEnabled, cap(got.ch))
	}
	if err := svc.ValidateSecretAuditSink(); err != nil {
		t.Fatalf("validate enterprise sink: %v", err)
	}
	svc.startSecretAuditPruneTicker()

	(*Service)(nil).ensureSecretAuditSink()
	(*Service)(nil).CloseSecretAuditSink()
	if (*Service)(nil).secretAuditSink() != nil || (*Service)(nil).auditActor() != "" {
		t.Fatal("nil service leaked audit state")
	}
	if secretAuditDataDir(" ") != "" || secretAuditDataDir("/tmp/state.db") != "/tmp" {
		t.Fatalf("audit data dir = %q", secretAuditDataDir("/tmp/state.db"))
	}
}

func TestSecretAuditQueryAndClassifyRemaining(t *testing.T) {
	if _, _, err := (*Service)(nil).ListSecretAuditLocal(context.Background(), "sb", SecretAuditQuery{}); err != nil {
		t.Fatal(err)
	}
	if err := (*Service)(nil).PruneSecretAudit(nil); err != nil {
		t.Fatal(err)
	}
	page, err := (&Service{}).ListSecretAudit(nil, "sb", SecretAuditQuery{})
	if err != nil || page.Events != nil {
		t.Fatalf("storeless list = %+v %v", page, err)
	}

	held := cap(secretAuditLocalQuerySlots)
	for range held {
		secretAuditLocalQuerySlots <- struct{}{}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, cancelErr := (&Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "x.db")}}).ListSecretAuditLocal(cancelled, "sb", SecretAuditQuery{})
	for range held {
		<-secretAuditLocalQuerySlots
	}
	if !errors.Is(cancelErr, context.Canceled) {
		t.Fatalf("cancelled local list = %v", cancelErr)
	}

	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(svc.CloseSecretAuditSink)
	if _, _, err := svc.ListSecretAuditLocal(context.Background(), " ", SecretAuditQuery{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ListSecretAuditLocal(context.Background(), "sb", SecretAuditQuery{Cursor: "not-a-time\x1fkey"}); err == nil {
		t.Fatal("malformed cursor was accepted")
	}
	sink := svc.secretAuditSink().(*fileAuditSink)
	if err := sink.EmitDurable(SecretAuditEvent{
		EventID: "kind-open", SandboxID: "sb-kind", Kind: secretAuditKindSecretOpen, Result: secretAuditResultSuccess,
	}); err != nil {
		t.Fatal(err)
	}
	events, _, err := svc.ListSecretAuditLocal(context.Background(), "sb-kind", SecretAuditQuery{Limit: maxSecretAuditLimit + 10, Kind: secretAuditKindEgress})
	if err != nil || len(events) != 0 {
		t.Fatalf("kind filter = %+v err=%v", events, err)
	}

	if ctx := ContextWithSecretAuditCorrelation(nil, "id"); ctx != nil {
		t.Fatal("nil context was rewritten")
	}
	if ctx := ContextWithSecretAuditCorrelation(context.Background(), " "); ctx != context.Background() {
		t.Fatal("blank correlation attached a value")
	}
	ctx := ContextWithSecretAuditCorrelation(context.Background(), "corr-28")
	if got := correlationIDFromContext(ctx); got != "corr-28" {
		t.Fatalf("correlation = %q", got)
	}
	if correlationIDFromContext(nil) != "" || correlationIDFromContext(context.Background()) != "" {
		t.Fatal("empty correlation leaked")
	}

	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.New("row not found"), secretAuditReasonNotFound},
		{errors.New("recipient is not allowed to open"), secretAuditReasonRecipientDenied},
		{errors.New("envelope version mismatch"), secretAuditReasonVersionMismatch},
		{errors.New("sealed blob is truncated"), secretAuditReasonDecryptFailed},
		{errors.New("cipher: auth failed"), secretAuditReasonDecryptFailed},
	} {
		if got := classifySecretAuditReason(tc.err); got != tc.want {
			t.Fatalf("classify(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
	if registryAuditRef("sb") != "registry:sb" || mountsAuditRef("sb") != "mounts:sb" || envAuditRef("sb") != "env:sb" {
		t.Fatal("audit ref helpers")
	}
	if sandboxIDFromSecretRef("cluster-secret://sandbox/sb-x/i/inc/v1") != "sb-x" {
		t.Fatal("sandbox id parse")
	}

	fan := &Service{
		cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")},
		cluster: &stubMembersCluster{
			Noop: cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{
				{NodeID: "self", Alive: true},
				{NodeID: "ingress", Alive: true, Role: config.NodeRoleIngress, InternalURL: "https://ingress"},
				{NodeID: "dead", Alive: false, InternalURL: "https://dead"},
				{NodeID: "blank", Alive: true},
				{NodeID: "peer", Alive: true, InternalURL: "https://peer"},
			},
			placement: cluster.Placement{
				SandboxID: "sb-fan", OwnerNodeID: "self", IncarnationID: "inc-fan",
				AuditNodeIDs: []string{"self", "peer", "dead", "missing-node"},
			},
		},
	}
	t.Cleanup(fan.CloseSecretAuditSink)
	page, err = fan.ListSecretAudit(context.Background(), "sb-fan", SecretAuditQuery{IncarnationID: "inc-fan"})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Coverage.Partial {
		t.Fatalf("fetcherless coverage = %+v", page.Coverage)
	}
}

func TestSecretAuditWitnessAndExportRemaining(t *testing.T) {
	if _, err := (*Service)(nil).requireCurrentSecretAuditWitness(context.Background()); err == nil {
		t.Fatal("nil require witness succeeded")
	}
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	svc.ensureSecretAuditSink()
	t.Cleanup(svc.CloseSecretAuditSink)
	if _, err := svc.requireCurrentSecretAuditWitness(context.Background()); err == nil {
		t.Fatal("missing external witness was accepted")
	}
	w := &stubWitness{shipErr: errors.New("offline")}
	svc.auditWitness = w
	if err := svc.shipSecretAuditHead(nil); err != nil {
		t.Fatalf("empty-head ship = %v", err)
	}
	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{EventID: "need-witness", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.requireCurrentSecretAuditWitness(nil); err == nil {
		t.Fatal("ship failure was ignored")
	}
	w.shipErr = nil
	head, err := svc.requireCurrentSecretAuditWitness(context.Background())
	if err != nil || head == "" {
		t.Fatalf("current witness = %q %v", head, err)
	}
	svc.auditWitness = &mismatchWitness{}
	if _, err := svc.requireCurrentSecretAuditWitness(context.Background()); err == nil || !strings.Contains(err.Error(), "not witnessed") {
		t.Fatalf("stale remote head = %v", err)
	}
	svc.auditWitness = &mismatchWitness{remoteErr: errors.New("read failed")}
	if _, err := svc.requireCurrentSecretAuditWitness(context.Background()); err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("remote read = %v", err)
	}

	if ok, err := svc.secretAuditFullyExported(); ok || err != nil {
		t.Fatalf("unexported = %v %v", ok, err)
	}
	if n, err := svc.exportSecretAuditBatchOnce(context.Background()); n != 0 || err != nil {
		t.Fatalf("exporterless batch = %d %v", n, err)
	}

	scan, err := recomputeChain(filepath.Join(t.TempDir(), "missing.jsonl"))
	if err != nil || scan.head == "" || scan.eventID != "" || scan.records != 0 || scan.found != nil {
		t.Fatalf("missing chain = %+v %v", scan, err)
	}
}

func TestWriteEventBatchRecomputesEmptyTipAndNilMemSink(t *testing.T) {
	sink, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	if err := sink.EmitDurable(SecretAuditEvent{EventID: "tip-seed", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	sink.chainMu.Lock()
	sink.chainHead = ""
	sink.chainMu.Unlock()
	if err := sink.writeEvent(SecretAuditEvent{EventID: "after-recompute", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}

	var mem *memSecretAuditSink
	mem.Emit(SecretAuditEvent{EventID: "ignored"})
	if evs := mem.Events(); evs != nil {
		t.Fatalf("nil mem events = %v", evs)
	}
	mem = &memSecretAuditSink{}
	mem.Emit(SecretAuditEvent{})
	if len(mem.Events()) != 1 {
		t.Fatal("mem sink dropped an event")
	}

	egress := &Service{cfg: config.Config{EgressAttributionEnabled: true, DBPath: t.TempDir() + "/state.db"}}
	t.Cleanup(egress.CloseSecretAuditSink)
	obs := egress.EgressAuditObserver()
	obs("sb-e", "tcp", "example.com:443")
}

func TestWriteEventBatchPoisonRecomputeAndTipFail(t *testing.T) {
	sink, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	sink.chainMu.Lock()
	sink.writePoison = errors.New("injected poison")
	sink.chainMu.Unlock()
	if err := sink.writeEventBatch([]SecretAuditEvent{{EventID: "poisoned", Result: secretAuditResultSuccess}}, true, true); err == nil {
		t.Fatal("poisoned writer succeeded")
	}

	ok, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ok.Close)
	if err := os.WriteFile(ok.path, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok.chainMu.Lock()
	ok.chainHead = ""
	ok.chainMu.Unlock()
	if err := ok.writeEvent(SecretAuditEvent{EventID: "after-corrupt", Result: secretAuditResultSuccess}); err == nil {
		t.Fatal("corrupt recompute succeeded")
	}

	tip, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tip.Close)
	_ = os.Remove(tip.tipPath)
	if err := os.Mkdir(tip.tipPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := tip.writeEventBatch([]SecretAuditEvent{{EventID: "tip-dir", Result: secretAuditResultSuccess}}, true, false); err != nil {
		t.Fatalf("durable write with tip dir: %v", err)
	}
}

func TestPruneLockedMalformedChainAndGuards(t *testing.T) {
	sink, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	if err := os.WriteFile(sink.path, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sink.pruneLocked(time.Now().UTC(), "", ""); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed prune = %v", err)
	}

	broken, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(broken.Close)
	now := time.Now().UTC()
	first := SecretAuditEvent{Time: now.Add(-2 * time.Hour), EventID: "first", Result: secretAuditResultSuccess}
	auditlog.LinkEvent(auditlog.GenesisPrevHash, &first)
	second := SecretAuditEvent{Time: now.Add(-time.Hour), EventID: "second", Result: secretAuditResultSuccess}
	auditlog.LinkEvent("not-the-prev", &second)
	line1, _ := json.Marshal(first)
	line2, _ := json.Marshal(second)
	if err := os.WriteFile(broken.path, append(append(line1, '\n'), append(line2, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := broken.pruneLocked(now, "", ""); err == nil || !strings.Contains(err.Error(), "invalid chain") {
		t.Fatalf("broken chain prune = %v", err)
	}

	guard, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(guard.Close)
	if err := guard.EmitDurable(SecretAuditEvent{Time: now.Add(-2 * time.Hour), EventID: "old", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	cursorPath := filepath.Join(t.TempDir(), "cursor.json")
	if err := persistAuditExportCursor(cursorPath, auditExportCursor{Generation: "other-gen", Offset: 0, Head: "head"}); err != nil {
		t.Fatal(err)
	}
	if err := guard.pruneLocked(now, cursorPath, ""); !errors.Is(err, errSecretAuditPruneGuardChanged) {
		t.Fatalf("export cursor guard = %v", err)
	}
	if err := guard.pruneLocked(now.Add(time.Hour), "", "not-the-verified-head"); !errors.Is(err, errSecretAuditPruneGuardChanged) {
		t.Fatalf("witnessed-head guard = %v", err)
	}

	ok, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ok.Close)
	called := make(chan struct{}, 1)
	ok.afterPrune = func() { called <- struct{}{} }
	if err := ok.EmitDurable(SecretAuditEvent{Time: now.Add(-3 * time.Hour), EventID: "drop-me", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := ok.EmitDurable(SecretAuditEvent{Time: now, EventID: "keep-me", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := ok.pruneLocked(now.Add(-time.Hour), "", ""); err != nil {
		t.Fatalf("prefix prune: %v", err)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("afterPrune was not scheduled")
	}
}

func TestValidateSinkStrictAndSpillOverflow(t *testing.T) {
	if err := (*Service)(nil).ValidateSecretAuditSink(); err != nil {
		t.Fatal(err)
	}
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db"), SecretAuditStrictBoot: true}}
	t.Cleanup(svc.CloseSecretAuditSink)
	if err := svc.ValidateSecretAuditSink(); err != nil {
		t.Fatalf("fresh strict sink: %v", err)
	}
	svc.secretAuditInitErr = errors.New("init failed")
	if err := svc.ValidateSecretAuditSink(); err == nil || !strings.Contains(err.Error(), "initialize") {
		t.Fatalf("strict init = %v", err)
	}

	sink, err := newFileAuditSinkOpts(t.TempDir(), 1, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	block := make(chan struct{})
	sink.writeHook = func() { <-block }
	done := make(chan error, 1)
	go func() {
		done <- sink.EmitDurable(SecretAuditEvent{EventID: "block", Result: secretAuditResultSuccess})
	}()
	time.Sleep(50 * time.Millisecond)
	for i := range 8 {
		sink.Emit(SecretAuditEvent{EventID: "overflow-" + string(rune('a'+i)), Result: secretAuditResultSuccess})
	}
	close(block)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked durable emit did not finish")
	}

	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistWitnessReceipt("", filepath.Join(blocked, "tip.json"), witnessReceiptRecord{HeadHex: "h"}); err == nil {
		t.Fatal("witness tip under a file succeeded")
	}
}

func TestExpandResealStopsWithoutPeerTransport(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	cl := &stubMembersCluster{
		Noop: cluster.NewNoop("node-a", "http://a", ""),
		members: []cluster.Member{
			{NodeID: "node-a", Alive: true},
			{NodeID: "node-b", Alive: true},
		},
	}
	svc := &Service{
		cfg:   config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		store: st, cipher: cipher, secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster: cl, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handle, err := svc.SealAndDistribute(ctx, "sb-reseal-tx", models.CreateSandboxRequest{
		Image: "alpine", Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	placement := cluster.Placement{
		SandboxID: "sb-reseal-tx", OwnerNodeID: "node-a", IncarnationID: handle.IncarnationID,
		SecretRef: handle.Ref, SecretVersion: handle.Version, SecretSealGeneration: handle.SealGeneration,
		SecretRecipients: []string{"node-a", "node-dead"},
	}
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, cl, placement); err == nil || !strings.Contains(err.Error(), "peer transport") {
		t.Fatalf("transportless reseal = %v", err)
	}

	block := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// appendSpill's parent-dir check does not need a live writer loop.
	blocked := &fileAuditSink{spillPath: filepath.Join(block, "secrets.spill.jsonl")}
	if err := blocked.appendSpill(SecretAuditEvent{EventID: "spill-dir", Result: secretAuditResultSuccess}); err == nil {
		t.Fatal("spill under a file succeeded")
	}
	if err := (&fileAuditSink{}).appendSpill(SecretAuditEvent{}); err == nil {
		t.Fatal("empty spill path succeeded")
	}
}

func TestRemainingEasyGuardsWave31(t *testing.T) {
	ctx := context.Background()
	(*Service)(nil).emitEgressAudit("sb", "tcp", "dst")
	(&Service{}).emitEgressAudit("sb", "tcp", "dst")
	disabled := &Service{cfg: config.Config{EgressAttributionEnabled: false}}
	if disabled.EgressAuditObserver() == nil {
		t.Fatal("disabled observer")
	}
	disabled.emitEgressAudit("", "tcp", "dst")
	enabled := &Service{cfg: config.Config{EgressAttributionEnabled: true, DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(enabled.CloseSecretAuditSink)
	enabled.emitEgressAudit(" ", "tcp", "dst")
	enabled.emitEgressAudit("sb", "tcp", " ")
	enabled.EgressAuditObserver()("sb-e31", "tcp", "example.com:443")

	if (*Service)(nil).secretPeerPusher() != nil {
		t.Fatal("nil pusher")
	}
	if (&Service{}).secretPeerPusher() != nil {
		t.Fatal("detached pusher")
	}

	empty, err := (*Service)(nil).putClusterSecretsForRecipientsAndIncarnation(ctx, "sb", models.CreateSandboxRequest{Image: "alpine"}, nil, "")
	if err != nil || empty.Ref != "" {
		t.Fatalf("empty bag = %+v %v", empty, err)
	}
	if _, err := (&Service{cipher: newTestCipher(t)}).putClusterSecretsForRecipientsAndIncarnation(ctx, "sb", models.CreateSandboxRequest{
		Image: "alpine", Registry: &models.RegistryAuth{Password: "p"},
	}, []string{"node-a"}, "inc-a"); err == nil {
		t.Fatal("providerless put succeeded")
	}
	if _, err := (&Service{}).putClusterSecretsForRecipientsAndIncarnation(ctx, "sb", models.CreateSandboxRequest{
		Image: "alpine", Registry: &models.RegistryAuth{Password: "p"},
	}, []string{"node-a"}, "inc-a"); err == nil {
		t.Fatal("cipherless put succeeded")
	}

	st := openSealTestStore(t)
	if blob, err := (&Service{store: st}).loadSecretBlob(ctx, secrets.FormatRef("missing", "inc", secrets.RefVersion)); blob != nil || err == nil {
		t.Fatalf("missing blob = %v %v", blob, err)
	}
	_ = st.Close()
	if _, err := (&Service{store: st}).loadSecretBlob(ctx, secrets.FormatRef("sb", "inc", secrets.RefVersion)); err == nil {
		t.Fatal("closed loadSecretBlob succeeded")
	}

	(*Service)(nil).runWasmOrphanStateKVSweep(ctx)
	closedKV := openSealTestStore(t)
	kv := &Service{store: closedKV, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_ = closedKV.Close()
	kv.runWasmOrphanStateKVSweep(ctx)

	block := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomicDurable(filepath.Join(block, "tip"), []byte("h"), 0o600); err == nil {
		t.Fatal("durable write under a file succeeded")
	}
	if err := persistWitnessReceipt(filepath.Join(block, "receipts.jsonl"), "", witnessReceiptRecord{HeadHex: "h"}); err == nil {
		t.Fatal("witness receipt under a file succeeded")
	}

	if _, _, err := (&Service{}).openSecretAuditSnapshot(filepath.Join(t.TempDir(), "missing.jsonl")); err == nil {
		t.Fatal("missing snapshot opened")
	}
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(svc.CloseSecretAuditSink)
	_ = svc.secretAuditSink()
	if _, _, err := svc.openSecretAuditSnapshot(svc.secretAuditFile.path); err != nil {
		t.Fatalf("open snapshot: %v", err)
	}

	(&Service{store: openSealTestStore(t)}).reconcileSecretDeleteOutboxIncarnationWithPlacements(ctx, "missing", "inc", nil)
	if id := newSecretAuditCorrelationID(); id == "" {
		t.Fatal("empty correlation id")
	}

	if err := (*Service)(nil).attachWasmRegistryAuth(nil); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{}).attachWasmRegistryAuth(&models.Sandbox{ID: "sb", RegistryAuthSealed: []byte("bad")}); err == nil {
		t.Fatal("bad wasm registry unseal succeeded")
	}

	cipher := newTestCipher(t)
	prov := secrets.NewLocalProvider(cipher, newSecretBlobStore(openSealTestStore(t)))
	if _, err := (&Service{
		cipher: cipher, secretProvider: prov, cluster: cluster.NewNoop("node-a", "http://a", ""),
	}).putClusterSecretsForRecipientsAndIncarnation(ctx, "sb-peers31", models.CreateSandboxRequest{
		Image: "alpine", Registry: &models.RegistryAuth{Password: "p"},
	}, []string{"node-a", "node-b"}, "inc-a"); err == nil || !strings.Contains(err.Error(), "put-outbox") {
		t.Fatalf("storeless put-outbox = %v", err)
	}

	st2 := openSealTestStore(t)
	retired := []string{"node-b"}
	if _, err := st2.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-delauth31", "inc-a", secrets.RefVersion),
		SandboxID: "sb-delauth31", Version: secrets.RefVersion,
		Recipients: []string{"node-a", "node-c"}, RetireRecipients: &retired,
		SealedPayload: []byte("sealed"), SealGeneration: 2,
	}); err != nil {
		t.Fatal(err)
	}
	del := &Service{
		cfg: config.Config{EnableCluster: true}, store: st2,
		cluster:              &wave30AuthCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), err: errors.New("raft down")},
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		testSecretPeerPusher: &fakePeerPusher{},
	}
	del.reconcileSecretDeleteOutboxIncarnation(ctx, "sb-delauth31", "inc-a")
	rec, err := st2.GetSecretDeleteOutboxForIncarnation(ctx, "sb-delauth31", "inc-a")
	if err != nil || rec == nil {
		t.Fatalf("staged delete missing: %v", err)
	}
	_ = st2.Close()
	del.reconcileSecretDeleteOutboxRecord(ctx, rec, map[string]cluster.Placement{
		"sb-delauth31": {SandboxID: "sb-delauth31", IncarnationID: "inc-a", SecretSealGeneration: 2},
	})
}

func TestWriteEventBatchAndPruneLockedIOWave32(t *testing.T) {
	genesis, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(genesis.Close)
	genesis.writeHook = func() {}
	genesis.chainMu.Lock()
	genesis.chainHead = ""
	genesis.chainMu.Unlock()
	if err := genesis.writeEventBatch([]SecretAuditEvent{{EventID: "genesis32", Result: secretAuditResultSuccess}}, false, false); err != nil {
		t.Fatalf("genesis non-durable: %v", err)
	}

	ro, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ro.Close)
	ro.Close()
	readonly, err := os.Open(ro.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = readonly.Close() })
	ro.file = readonly
	// A read-only descriptor makes append fail and Truncate fail, which is the
	// only portable way to poison the writer without filling the disk.
	if err := ro.writeEventBatch([]SecretAuditEvent{{EventID: "ro32", Result: secretAuditResultSuccess}}, true, true); err == nil {
		t.Fatal("read-only append succeeded")
	}

	denied, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(denied.Close)
	if err := os.Chmod(denied.path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied.path, 0o600) })
	if err := denied.pruneLocked(time.Now().UTC(), "", ""); err == nil {
		t.Fatal("chmod-000 prune succeeded")
	}

	tmpDir, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tmpDir.Close)
	now := time.Now().UTC()
	if err := tmpDir.EmitDurable(SecretAuditEvent{Time: now.Add(-3 * time.Hour), EventID: "drop-tmp32", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := tmpDir.EmitDurable(SecretAuditEvent{Time: now, EventID: "keep-tmp32", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tmpDir.path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir.path + ".tmp") })
	if err := tmpDir.pruneLocked(now.Add(-time.Hour), "", ""); err == nil {
		t.Fatal("tmp-as-directory prune succeeded")
	}

	empty, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(empty.Close)
	if err := empty.pruneLocked(now, "", ""); err != nil {
		t.Fatalf("nothing-to-drop prune: %v", err)
	}

	// Point spill at a file no writer loop is draining so chmod cannot
	// race a rename/remove of secrets.spill.jsonl.
	manualSpill := filepath.Join(t.TempDir(), "manual.spill")
	if err := os.WriteFile(manualSpill, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(manualSpill, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(manualSpill, 0o600) })
	detached := &fileAuditSink{spillPath: manualSpill}
	if err := detached.appendSpill(SecretAuditEvent{EventID: "spill-chmod32"}); err == nil {
		t.Fatal("chmod-000 spill succeeded")
	}

	block := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistAuditExportCursor(filepath.Join(block, "cursor.json"), auditExportCursor{Generation: "g", Offset: 1, Head: "h"}); err == nil {
		t.Fatal("export cursor under a file succeeded")
	}
}

func TestWave33AuditHelpersAndGuards(t *testing.T) {
	if err := writeFileAtomicDurable("", []byte("x"), 0o600); err == nil {
		t.Fatal("empty durable path")
	}
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomicDurable(filepath.Join(blocker, "tip"), []byte("x"), 0o600); err == nil {
		t.Fatal("durable write under a file parent")
	}
	okPath := filepath.Join(t.TempDir(), "cursor.json")
	if err := persistAuditExportCursor(okPath, auditExportCursor{Offset: 3, Generation: "g1", Head: "h1"}); err != nil {
		t.Fatal(err)
	}

	if _, err := newFileAuditSinkOpts(filepath.Join(blocker, "audit"), 0, true); err == nil {
		t.Fatal("mkdir under file must fail")
	}
	dir := t.TempDir()
	sink, err := newFileAuditSinkOpts(dir, 0, true)
	if err != nil || sink == nil {
		t.Fatalf("sink = %v %v", sink, err)
	}
	t.Cleanup(sink.Close)
	if err := sink.appendSpill(SecretAuditEvent{Result: "ok", SandboxID: "sb-1"}); err != nil {
		t.Fatal(err)
	}
	if !sink.drainSpill() {
		t.Fatal("expected spill drain to find work")
	}
	if err := (*fileAuditSink)(nil).appendSpill(SecretAuditEvent{}); err == nil {
		t.Fatal("nil appendSpill")
	}
	if (*fileAuditSink)(nil).drainSpill() {
		t.Fatal("nil drainSpill")
	}

	lockAsDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(lockAsDir, secretAuditLockName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := newFileAuditSinkOpts(lockAsDir, 1, false); err == nil {
		t.Fatal("lock-as-directory must fail")
	}
	dataAsDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dataAsDir, secretAuditFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := newFileAuditSinkOpts(dataAsDir, 1, false); err == nil {
		t.Fatal("jsonl-as-directory must fail")
	}
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, secretAuditFileName), []byte("{not-jsonl\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newFileAuditSinkOpts(broken, 1, false); err == nil {
		t.Fatal("tampered jsonl must fail chain verify")
	}

	if err := (*Service)(nil).ValidateSecretAuditSink(); err != nil {
		t.Fatal(err)
	}
	svc := &Service{cfg: config.Config{SecretAuditStrictBoot: true}, secretAuditInitErr: os.ErrPermission}
	if err := svc.ValidateSecretAuditSink(); err == nil {
		t.Fatal("strict boot must surface init error")
	}
	(*Service)(nil).ConfigureHTTPAuditExporter()
	(&Service{}).ConfigureHTTPAuditExporter()
	(&Service{cfg: config.Config{SecretAuditExportURL: "http://127.0.0.1:9/export"}}).ConfigureHTTPAuditExporter()
	if (*Service)(nil).EgressAuditObserver() == nil {
		t.Fatal("nil observer")
	}
	_ = newSecretAuditCorrelationID()
	if tok, err := newAuditIngestToken(); err != nil || tok == "" {
		t.Fatalf("ingest token = %q %v", tok, err)
	}

	if blob, err := (*Service)(nil).loadSecretBlob(context.Background(), "ref"); blob != nil || err != nil {
		t.Fatalf("nil load = %v %v", blob, err)
	}
	if blob, err := (&Service{}).loadSecretBlob(context.Background(), ""); blob != nil || err != nil {
		t.Fatalf("empty ref load = %v %v", blob, err)
	}

	if wasmPathUnderDir("", "/x") || wasmPathUnderDir("/x", "") {
		t.Fatal("empty wasm path")
	}
	root := t.TempDir()
	if !wasmPathUnderDir(root, root) || !wasmPathUnderDir(root, filepath.Join(root, "mod.wasm")) {
		t.Fatal("in-dir wasm path")
	}
	if wasmPathUnderDir(root, filepath.Join(t.TempDir(), "outside.wasm")) {
		t.Fatal("outside wasm path")
	}

	if got := OwnerRefForCreate(controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "acme"},
	})); got != "acme" {
		t.Fatalf("owner = %q", got)
	}
	_ = time.Now()
}
