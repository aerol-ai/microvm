package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// seedSealedRows writes one sandbox with every server-key-sealed value: a
// toolbox token, registry auth, mounts, env, plus a local cluster-secret
// copy and the egress CA.
func seedSealedRows(t *testing.T, svc *Service, id string) string {
	t.Helper()
	ctx := context.Background()
	sb := &models.Sandbox{ID: id, Image: "alpine", Status: models.SandboxStatusStarted, CPU: 1, MemoryMB: 64, DiskGB: 1,
		AuditIncarnationID: "inc-" + id, ToolboxEnabled: true, ToolboxToken: "tok-" + id,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), LastActiveAt: time.Now().UTC()}
	reg, err := svc.sealRegistry(&models.RegistryAuth{Server: "r.example", Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	sb.RegistryAuthSealed = reg
	if err := svc.store.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	env, err := svc.cipher.EncryptWithAAD([]byte(`{"K":"v"}`), secrets.EnvAAD(id, sb.AuditIncarnationID))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.store.PutEnv(ctx, id, env); err != nil {
		t.Fatal(err)
	}
	mounts, err := svc.sealMounts([]models.MountSpec{{Type: "s3", Target: "/data"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.store.PutMounts(ctx, id, mounts); err != nil {
		t.Fatal(err)
	}
	ref := secrets.FormatRef(id, sb.AuditIncarnationID, secrets.RefVersion)
	binding := secrets.SealBinding{SandboxID: id, IncarnationID: sb.AuditIncarnationID, Ref: ref, Version: secrets.RefVersion, Generation: 1}
	sealed, err := secrets.SealRawEnvelopeBound(svc.cipher, []byte(`{"env":{"K":"v"}}`), []string{"node-a"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := svc.store.PutClusterSecret(ctx, store.ClusterSecretRecord{Ref: ref, SandboxID: id, Version: 1, Recipients: []string{"node-a"}, SealedPayload: sealed, SealGeneration: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return ref
}

// tempDataDir points the node's data directory (audit state, egress CA)
// at a temp dir: these harnesses leave DBPath empty.
func tempDataDir(t *testing.T, svc *Service) {
	t.Helper()
	svc.cfg.DBPath = filepath.Join(t.TempDir(), "state.db")
	svc.egressCA.Store(nil)
}

func ringGauge(t *testing.T, m *expvar.Map) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(m.String()), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func rotationKinds(sink *fakeDurableSink) []string {
	var kinds []string
	for _, ev := range sink.durable {
		if strings.HasPrefix(ev.Kind, "key_rotation_") {
			kinds = append(kinds, ev.Kind+" "+ev.Reason)
		}
	}
	return kinds
}

// TestServerKeyRotationWrapped (eng D26) runs stage → promote → reseal →
// retire on a wrapped-custody node through its re-check, with a revoke and
// recovery in the middle: each step reaches the Cipher without a restart,
// is recorded once, and every sealed value still opens at the end.
func TestServerKeyRotationWrapped(t *testing.T) {
	svc, kms, _, _, _ := revokeHarness(t)
	tempDataDir(t, svc)
	sink := &fakeDurableSink{}
	svc.secretAudit = sink
	ctx := context.Background()
	if _, err := svc.ensureEgressCA(); err != nil {
		t.Fatal(err)
	}
	refs := []string{seedSealedRows(t, svc, "sb-1"), seedSealedRows(t, svc, "sb-2")}
	// A key-store row: not the server key's to move.
	kmsRef := secrets.FormatRef("sb-k", "inc", secrets.RefVersion)
	kb := secrets.SealBinding{SandboxID: "sb-k", IncarnationID: "inc", Ref: kmsRef, Version: secrets.RefVersion, Generation: 1}
	kmsRow, _ := secrets.SealRawEnvelopeWrappedBound([]byte(`{}`), []string{"node-a"}, kb, func(dek []byte) ([]byte, error) {
		return kms.Wrap(ctx, dek, secrets.EncryptionContextForBinding(kb))
	})
	now := time.Now().UTC()
	if _, err := svc.store.PutClusterSecret(ctx, store.ClusterSecretRecord{Ref: kmsRef, SandboxID: "sb-k", Version: 1, Recipients: []string{"node-a"}, SealedPayload: kmsRow, SealGeneration: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}

	// Boot: the legacy key alone, recorded as this node's ring.
	entries, err := svc.serverKeyRing()
	if err != nil {
		t.Fatal(err)
	}
	svc.noteServerKeyRing(entries)
	if counts, err := svc.ResealServerKeyRows(ctx); err != nil || counts != nil {
		t.Fatalf("one-key ring scanned rows: %v %v", counts, err)
	}

	edit := func(step func([]secrets.RingEntry) []secrets.RingEntry) {
		t.Helper()
		f, err := secrets.ReadWrappedKeyFile(svc.cfg.CredentialKeyWrappedPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.SetEntries(step(f.Entries())); err != nil {
			t.Fatal(err)
		}
		if err := secrets.WriteWrappedKeyFile(svc.cfg.CredentialKeyWrappedPath, f); err != nil {
			t.Fatal(err)
		}
		if got := svc.RecheckServerKey(ctx); got != recheckOK {
			t.Fatalf("re-check = %s", got)
		}
	}

	// Stage: key 1 decrypt-only; nothing moves yet.
	edit(func(e []secrets.RingEntry) []secrets.RingEntry {
		staged, err := secrets.NewRingEntry(ctx, 1, kms)
		if err != nil {
			t.Fatal(err)
		}
		out, err := secrets.StageRingKey(e, staged)
		if err != nil {
			t.Fatal(err)
		}
		return out
	})
	if svc.cipher.CurrentKeyID() != 0 || len(svc.cipher.KeyIDs()) != 2 {
		t.Fatalf("after stage: current %d ids %v", svc.cipher.CurrentKeyID(), svc.cipher.KeyIDs())
	}
	if g := ringGauge(t, serverKeyRingGauge); g["1"] == nil || g["1"].(map[string]any)["decrypt"] != float64(1) {
		t.Fatalf("ring gauge = %v", g)
	}
	counts, err := svc.ResealServerKeyRows(ctx)
	// 2 sandboxes × (token, registry, mounts, env, local cluster secret) + the CA.
	if err != nil || counts["0"] != 11 || counts["1"] != 0 {
		t.Fatalf("staged counts = %v %v", counts, err)
	}

	// Promote: new seals use key 1 and the pass moves every value.
	edit(func(e []secrets.RingEntry) []secrets.RingEntry {
		out, _, _, err := secrets.PromoteRingKey(e)
		if err != nil {
			t.Fatal(err)
		}
		return out
	})
	if svc.cipher.CurrentKeyID() != 1 {
		t.Fatal("promote not taken")
	}
	before := keyRowsResealed.Value()
	counts, err = svc.ResealServerKeyRows(ctx)
	if err != nil || counts["1"] != 11 || counts["0"] != 0 || keyRowsResealed.Value()-before != 11 {
		t.Fatalf("promoted counts = %v %v", counts, err)
	}
	if g := ringGauge(t, serverKeyRowsGauge); g["1"] != float64(11) {
		t.Fatalf("rows gauge = %v", g)
	}
	before = keyRowsResealed.Value()
	if counts, _ = svc.ResealServerKeyRows(ctx); counts["1"] != 11 || keyRowsResealed.Value() != before {
		t.Fatal("a second pass moved values again")
	}
	if rec, _ := svc.store.GetClusterSecret(ctx, kmsRef); string(rec.SealedPayload) != string(kmsRow) {
		t.Fatal("the key-store row was touched")
	}

	// Revoke drops both keys; recovery brings both back.
	kms.set(secrets.ErrKeyRevoked)
	for i := 0; i < 3; i++ {
		svc.RecheckServerKey(ctx)
	}
	if !svc.KeyRevoked() || svc.cipher.KeyIDs() != nil {
		t.Fatal("revoke kept ring keys")
	}
	if counts, err := svc.ResealServerKeyRows(ctx); err != nil || counts != nil {
		t.Fatal("a revoked node resealed")
	}
	kms.set(nil)
	if svc.RecheckServerKey(ctx) != recheckOK || svc.KeyRevoked() || len(svc.cipher.KeyIDs()) != 2 || svc.cipher.CurrentKeyID() != 1 {
		t.Fatalf("recovery = ids %v current %d", svc.cipher.KeyIDs(), svc.cipher.CurrentKeyID())
	}

	// Retire key 0: the ring is key 1 alone and everything still opens.
	edit(func(e []secrets.RingEntry) []secrets.RingEntry {
		out, err := secrets.RetireRingKey(e, 0)
		if err != nil {
			t.Fatal(err)
		}
		return out
	})
	if svc.cipher.Rotating() || svc.cipher.CurrentKeyID() != 1 {
		t.Fatal("retire not taken")
	}
	if counts, _ := svc.ResealServerKeyRows(ctx); counts != nil || ringGauge(t, serverKeyRowsGauge)["1"] != nil {
		t.Fatal("rows gauge kept after the rotation ended")
	}
	for _, id := range []string{"sb-1", "sb-2"} {
		sb, err := svc.store.Get(ctx, id)
		if err != nil || sb.ToolboxToken != "tok-"+id {
			t.Fatalf("%s token: %v", id, err)
		}
		if auth, err := svc.UnsealRegistry(ctx, id, sb.RegistryAuthSealed); err != nil || auth.Password != "p" {
			t.Fatalf("%s registry: %v", id, err)
		}
		if m, err := svc.loadMounts(ctx, id); err != nil || len(m) != 1 {
			t.Fatalf("%s mounts: %v", id, err)
		}
		blob, err := svc.store.GetEnv(ctx, id)
		if _, kid, oerr := svc.cipher.OpenWithKeyID(blob, secrets.EnvAAD(id, "inc-"+id)); err != nil || oerr != nil || kid != 1 {
			t.Fatalf("%s env: %v %v", id, err, oerr)
		}
	}
	for _, ref := range refs {
		rec, _ := svc.store.GetClusterSecret(ctx, ref)
		if _, _, _, err := secrets.ResealLocalEnvelope(rec.SealedPayload, svc.cipher); err != nil {
			t.Fatalf("cluster secret %s: %v", ref, err)
		}
	}
	svc.egressCA.Store(nil)
	if _, ok, err := svc.loadEgressCA(); err != nil || !ok {
		t.Fatalf("egress CA after retire: %v", err)
	}

	want := []string{"key_rotation_staged key=1", "key_rotation_promoted from=0 to=1", "key_rotation_retired key=0"}
	if got := rotationKinds(sink); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("rotation records = %v", got)
	}
}

// TestServerKeyRotationFileCustody: custody=file re-reads its ring file; a
// ring that swaps a known key is refused and the node keeps its ring.
func TestServerKeyRotationFileCustody(t *testing.T) {
	svc, _, _ := newEgressHarness(t)
	tempDataDir(t, svc)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "credential_encryption.key")
	svc.cfg.CredentialKeyCustody = secrets.CustodyFile
	svc.cfg.CredentialEncryptionKeyPath = keyPath
	k0, _ := secrets.NewServerKey()
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(k0)), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := secrets.NewCipher("", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	svc.cipher = c
	svc.store.SetSecretCipher(c)
	sink := &fakeDurableSink{}
	svc.secretAudit = sink

	// No ring file: nothing to read, the ring is the legacy key.
	svc.reloadKeyRingFile()
	if entries, err := svc.serverKeyRing(); err != nil || secrets.RingSummary(entries) != "0:current" {
		t.Fatalf("legacy ring = %v %v", entries, err)
	}
	svc.noteServerKeyRing([]secrets.RingEntry{{ID: 0, State: secrets.RingStateCurrent}})

	staged, _ := secrets.NewRingEntry(context.Background(), 1, nil)
	ring, _ := secrets.StageRingKey([]secrets.RingEntry{secrets.LegacyRingEntry(k0)}, staged)
	ring, _, _, _ = secrets.PromoteRingKey(ring)
	if err := secrets.WriteKeyRingFile(svc.cfg.KeyRingPath(), secrets.KeyRingFile{Ring: ring}); err != nil {
		t.Fatal(err)
	}
	svc.reloadKeyRingFile()
	if c.CurrentKeyID() != 1 || len(c.KeyIDs()) != 2 {
		t.Fatalf("file ring not taken: %d %v", c.CurrentKeyID(), c.KeyIDs())
	}
	if got := rotationKinds(sink); len(got) != 2 {
		// Staged and promoted in one copy: both steps are recorded.
		t.Fatalf("records = %v", got)
	}

	// A ring whose key 0 is another key is refused.
	other, _ := secrets.NewServerKey()
	bad := []secrets.RingEntry{secrets.LegacyRingEntry(other), staged}
	bad[1].State = secrets.RingStateDecrypt
	bad[0].State = secrets.RingStateCurrent
	if err := secrets.WriteKeyRingFile(svc.cfg.KeyRingPath(), secrets.KeyRingFile{Ring: bad}); err != nil {
		t.Fatal(err)
	}
	svc.reloadKeyRingFile()
	if c.CurrentKeyID() != 1 {
		t.Fatal("a swapped key replaced the ring")
	}
	if err := os.WriteFile(svc.cfg.KeyRingPath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc.reloadKeyRingFile()
	if _, err := svc.serverKeyRing(); err == nil {
		t.Fatal("read a broken ring file")
	}
	if c.CurrentKeyID() != 1 {
		t.Fatal("a broken ring file changed the ring")
	}
}

// TestNoteServerKeyRingRetriesUnrecordedStep: a step whose audit record
// fails is not remembered, so the next re-read records it.
func TestNoteServerKeyRingRetriesUnrecordedStep(t *testing.T) {
	svc, _, _ := newEgressHarness(t)
	tempDataDir(t, svc)
	sink := &fakeDurableSink{err: errors.New("disk full")}
	svc.secretAudit = sink
	one := []secrets.RingEntry{{ID: 0, State: secrets.RingStateCurrent}}
	two := []secrets.RingEntry{{ID: 0, State: secrets.RingStateCurrent}, {ID: 1, State: secrets.RingStateDecrypt}}
	svc.noteServerKeyRing(one)
	svc.noteServerKeyRing(two)
	sink.err = nil
	sink.durable = nil
	svc.noteServerKeyRing(two)
	if got := rotationKinds(sink); len(got) != 1 || got[0] != "key_rotation_staged key=1" {
		t.Fatalf("retry = %v", got)
	}
	svc.noteServerKeyRing(two)
	if len(rotationKinds(sink)) != 1 {
		t.Fatal("a recorded step was recorded again")
	}
	// No sink and no data dir: the gauge still publishes.
	svc.secretAudit = nil
	svc.noteServerKeyRing(one)
	svc.cfg.DBPath = ""
	svc.noteServerKeyRing(two)
	if g := ringGauge(t, serverKeyRingGauge); g["1"] == nil {
		t.Fatalf("gauge = %v", g)
	}
	if !svc.emitDurableKeyEvent(KindKeyRotationStaged, "x") {
		t.Fatal("no sink is nothing to retry")
	}
	svc.secretAudit = &memSecretAuditSink{}
	if !svc.emitDurableKeyEvent(KindKeyRotationStaged, "x") {
		t.Fatal("a plain sink")
	}
}

// TestResealPassEdges: an unopenable value is counted, a corrupt CA record
// stops the pass, and the loop picks a ring change up on its own.
func TestResealPassEdges(t *testing.T) {
	svc, kms, _, _, _ := revokeHarness(t)
	tempDataDir(t, svc)
	ctx := context.Background()
	seedSealedRows(t, svc, "sb-1")
	k1, _ := secrets.NewServerKey()
	if err := svc.cipher.SetRing([]secrets.RingKey{{ID: 0}, {ID: 1, Key: k1, Current: true}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.PutMounts(ctx, "sb-1", []byte("not sealed")); err != nil {
		t.Fatal(err)
	}
	counts, err := svc.ResealServerKeyRows(ctx)
	if err != nil || counts[rowsUnopenable] != 1 || counts["1"] != 4 {
		t.Fatalf("counts = %v %v", counts, err)
	}
	if err := os.MkdirAll(svc.egressCADir(), 0o700); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(svc.egressCADir(), "ca.json")
	if err := os.WriteFile(ca, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ResealServerKeyRows(ctx); err == nil {
		t.Fatal("a corrupt CA record did not stop the pass")
	}
	// A pass that stopped early publishes the old key as unknown, never
	// as gone (what a retire waits for) or as a partial count.
	if g := ringGauge(t, serverKeyRowsGauge); len(g) != 1 || g["0"] != float64(-1) {
		t.Fatalf("rows gauge after a stopped pass = %v", g)
	}
	svc.resealTick(ctx)
	raw, _ := json.Marshal(egressCARecord{CertPEM: "x", SealedKey: []byte("junk")})
	if err := os.WriteFile(ca, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if counts, err := svc.ResealServerKeyRows(ctx); err != nil || counts[rowsUnopenable] != 2 {
		t.Fatalf("unopenable CA = %v %v", counts, err)
	}

	// The loop: a staged ring file reaches the node with no call from here.
	svc2, kms2, _, _, _ := revokeHarness(t)
	tempDataDir(t, svc2)
	_ = kms
	svc2.cfg.SecretProviderRecheckInterval = 20 * time.Millisecond
	f, _ := secrets.ReadWrappedKeyFile(svc2.cfg.CredentialKeyWrappedPath)
	staged, _ := secrets.NewRingEntry(ctx, 1, kms2)
	ring, _ := secrets.StageRingKey(f.Entries(), staged)
	_ = f.SetEntries(ring)
	if err := secrets.WriteWrappedKeyFile(svc2.cfg.CredentialKeyWrappedPath, f); err != nil {
		t.Fatal(err)
	}
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	svc2.StartKeyCustody(lctx)
	deadline := time.Now().Add(5 * time.Second)
	for len(svc2.cipher.KeyIDs()) != 2 {
		if time.Now().After(deadline) {
			t.Fatal("the loop did not take the staged key")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var nilSvc *Service
	nilSvc.StartKeyCustody(ctx)
	if counts, err := nilSvc.ResealServerKeyRows(ctx); counts != nil || err != nil {
		t.Fatal("nil service")
	}
}

// TestRotationRingAndPagingEdges: a staged key the key store cannot unwrap
// leaves the ring as it was (the re-check itself stays ok); the reseal pass
// pages past one page of every column and of cluster secrets.
func TestRotationRingAndPagingEdges(t *testing.T) {
	svc, kms, _, _, _ := revokeHarness(t)
	tempDataDir(t, svc)
	ctx := context.Background()
	f, _ := secrets.ReadWrappedKeyFile(svc.cfg.CredentialKeyWrappedPath)
	staged, _ := secrets.NewRingEntry(ctx, 1, kms)
	staged.Wrapped = []byte("not a wrapped key")
	ring, _ := secrets.StageRingKey(f.Entries(), staged)
	if err := f.SetEntries(ring); err != nil {
		t.Fatal(err)
	}
	if err := secrets.WriteWrappedKeyFile(svc.cfg.CredentialKeyWrappedPath, f); err != nil {
		t.Fatal(err)
	}
	if got := svc.RecheckServerKey(ctx); got != recheckOK || len(svc.cipher.KeyIDs()) != 1 {
		t.Fatalf("bad staged key = %s ids %v", got, svc.cipher.KeyIDs())
	}

	// Recovery with a ring that cannot be fully unwrapped stays revoked.
	kms.set(secrets.ErrKeyRevoked)
	for i := 0; i < 3; i++ {
		svc.RecheckServerKey(ctx)
	}
	kms.set(nil)
	if svc.RecheckServerKey(ctx); !svc.KeyRevoked() {
		t.Fatal("recovered without the whole ring")
	}

	svc2, _, _, _, _ := revokeHarness(t)
	tempDataDir(t, svc2)
	n := keySweepPage + 1
	for i := 0; i < n; i++ {
		seedSealedRows(t, svc2, fmt.Sprintf("sb-%03d", i))
	}
	k1, _ := secrets.NewServerKey()
	if err := svc2.cipher.SetRing([]secrets.RingKey{{ID: 0}, {ID: 1, Key: k1, Current: true}}); err != nil {
		t.Fatal(err)
	}
	counts, err := svc2.ResealServerKeyRows(ctx)
	if err != nil || counts["1"] != 5*n || counts["0"] != 0 {
		t.Fatalf("paged counts = %v %v", counts, err)
	}

	// The wrapped file gone: the ring cannot be read.
	_ = os.Remove(svc2.cfg.CredentialKeyWrappedPath)
	if _, err := svc2.serverKeyRing(); err == nil {
		t.Fatal("read a missing wrapped file")
	}
	lctx, cancel := context.WithCancel(ctx)
	svc2.StartKeyCustody(lctx) // the loop still starts without a readable ring
	cancel()
}
