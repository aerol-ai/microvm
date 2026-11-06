package cluster

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
)

// Regression tests for cloud identity in the FSM
// (plans/sandbox-cloud-identity.md D1.3, D1.5; CLAUDE.md rule 6).

var (
	identityTestKeysOnce sync.Once
	identityTestKeys     []*rsa.PrivateKey
)

func identityTestKey(t *testing.T, i int) *rsa.PrivateKey {
	t.Helper()
	identityTestKeysOnce.Do(func() {
		for n := 0; n < 3; n++ {
			k, err := cloudidentity.GenerateKey(rand.Reader)
			if err != nil {
				panic(err)
			}
			identityTestKeys = append(identityTestKeys, k)
		}
	})
	return identityTestKeys[i]
}

// testSeal stands in for the server-key cipher every node shares.
func testSeal(plain, aad []byte) ([]byte, error) {
	return append(append(append([]byte{}, aad...), 0), plain...), nil
}

func testOpen(t *testing.T, rec cloudidentity.KeyRecord) *rsa.PrivateKey {
	t.Helper()
	prefix := append(cloudidentity.SealAAD(rec.ID), 0)
	if !bytes.HasPrefix(rec.SealedPrivate, prefix) {
		t.Fatal("sealed key is not bound to its id")
	}
	key, err := cloudidentity.ParsePrivateKey(rec.SealedPrivate[len(prefix):])
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func identityKeyRec(t *testing.T, i int, now time.Time) cloudidentity.KeyRecord {
	t.Helper()
	rec, err := cloudidentity.NewKeyRecord(identityTestKey(t, i), now, testSeal)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func (l *profileLog) putKeys(expected int64, keys ...cloudidentity.KeyRecord) any {
	return l.apply(command{Op: opPutIdentityKeys, IdentityKeys: &IdentityKeysWrite{ExpectedGeneration: expected, Keys: keys}})
}

func (l *profileLog) putRole(owner, tag, minRole string) any {
	return l.apply(command{Op: opPutIdentityRole, StampUnixNano: int64(l.idx + 1),
		IdentityRole: &IdentityRoleRecord{Owner: owner, Tag: tag, MinRole: minRole}})
}

func (l *profileLog) delRole(owner, tag string) any {
	return l.apply(command{Op: opDeleteIdentityRole, IdentityRole: &IdentityRoleRecord{Owner: owner, Tag: tag}})
}

// The key set is replaced whole under a generation CAS: of two nodes that
// both found no key (both propose expected 0), the first in the log wins on
// every replica and the second is refused, never merged.
func TestFSMIdentityKeysCompareAndSwap(t *testing.T) {
	l := newProfileLog(t)
	now := time.Unix(1_800_000_000, 0)
	a, b := identityKeyRec(t, 0, now), identityKeyRec(t, 1, now)
	res, ok := l.putKeys(0, a).(identityKeysApplyResult)
	if !ok || res.Keys.Generation != 1 || len(res.Keys.Keys) != 1 || res.Keys.Keys[0].ID != a.ID {
		t.Fatalf("first key = %+v", res)
	}
	if err := asApplyErr(l.putKeys(0, b)); !errors.Is(err, ErrIdentityKeysConflict) {
		t.Fatalf("the losing first key = %v, want ErrIdentityKeysConflict", err)
	}
	if got := l.fsm.identityKeys(); got.Generation != 1 || got.Keys[0].ID != a.ID {
		t.Fatalf("after the loser = %+v", got)
	}
	rotated, err := l.fsm.identityKeys().Rotate(b, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if res := l.putKeys(1, rotated.Keys...).(identityKeysApplyResult); res.Keys.Generation != 2 || len(res.Keys.Keys) != 2 {
		t.Fatalf("rotation = %+v", res)
	}
	// A replay of the rotation (a retried proposal) is a stale CAS, not a
	// second rotation.
	if err := asApplyErr(l.putKeys(1, rotated.Keys...)); !errors.Is(err, ErrIdentityKeysConflict) {
		t.Fatalf("replayed rotation = %v", err)
	}
	// Invariants hold at apply: two active keys never land.
	if err := asApplyErr(l.putKeys(2, a, b)); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("two active keys = %v", err)
	}
	if err := asApplyErr(l.apply(command{Op: opPutIdentityKeys})); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("no payload = %v", err)
	}
	// The set the FSM hands out is a copy.
	got := l.fsm.identityKeys()
	got.Keys[0].SealedPrivate[0] ^= 0xff
	if again := l.fsm.identityKeys(); again.Keys[0].SealedPrivate[0] == got.Keys[0].SealedPrivate[0] {
		t.Fatal("identityKeys returned the FSM's own bytes")
	}
}

func TestFSMIdentityRoles(t *testing.T) {
	l := newProfileLog(t)
	res, ok := l.putRole("team:payments", "deploy", "runner").(identityRoleApplyResult)
	if !ok || !res.Changed || res.Role.CreatedUnixNano == 0 {
		t.Fatalf("put = %+v", res)
	}
	created := res.Role.CreatedUnixNano
	if res := l.putRole("team:payments", "deploy", "runner").(identityRoleApplyResult); res.Changed || res.Role.CreatedUnixNano != created {
		t.Fatalf("a retried put must be a no-op: %+v", res)
	}
	res = l.putRole("team:payments", "deploy", "admin").(identityRoleApplyResult)
	if !res.Changed || res.Role.MinRole != "admin" || res.Role.CreatedUnixNano != created || res.Role.UpdatedUnixNano == created {
		t.Fatalf("change = %+v", res)
	}
	l.putRole("team:payments", "build", "runner")
	l.putRole("team:other", "deploy", "runner")
	if got := l.fsm.identityRoles("team:payments", nil, "", 0); len(got) != 2 || got[0].Tag != "build" || got[1].Tag != "deploy" {
		t.Fatalf("page = %+v", got)
	}
	if got := l.fsm.identityRoles("team:payments", nil, "build", 1); len(got) != 1 || got[0].Tag != "deploy" {
		t.Fatalf("page after build = %+v", got)
	}
	if got := l.fsm.identityRoles("team:payments", []string{"deploy", "missing"}, "", 0); len(got) != 1 || got[0].MinRole != "admin" {
		t.Fatalf("point read = %+v", got)
	}
	for name, cmd := range map[string]command{
		"no role":     {Op: opPutIdentityRole},
		"bad tag":     {Op: opPutIdentityRole, IdentityRole: &IdentityRoleRecord{Tag: "Bad:Tag", MinRole: "runner"}},
		"bad role":    {Op: opPutIdentityRole, IdentityRole: &IdentityRoleRecord{Tag: "ok", MinRole: "viewer"}},
		"delete none": {Op: opDeleteIdentityRole},
	} {
		if err := asApplyErr(l.apply(cmd)); !errors.Is(err, ErrIdentityInvalid) {
			t.Errorf("%s: %v, want ErrIdentityInvalid", name, err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := asApplyErr(l.delRole("team:payments", "deploy")); err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
	}
	if got := l.fsm.identityRoles("team:payments", []string{"deploy"}, "", 0); len(got) != 0 {
		t.Fatalf("deleted role still read: %+v", got)
	}
	if got := l.fsm.identityRoles("team:other", []string{"deploy"}, "", 0); len(got) != 1 {
		t.Fatal("a delete crossed owners")
	}
	empty := newPlacementFSM()
	if got := empty.identityRoles("x", nil, "", 0); got == nil || len(got) != 0 {
		t.Fatalf("empty FSM roles = %#v", got)
	}
	if got := empty.identityKeys(); got.Generation != 0 {
		t.Fatalf("empty FSM keys = %+v", got)
	}
}

// Two replicas applying the same log, refusals included, end in the same
// state: a race between two first keys, or a rotation and a reseal,
// resolves the same way on every server.
func TestFSMIdentityReplayIsDeterministic(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	a, b, c := identityKeyRec(t, 0, now), identityKeyRec(t, 1, now), identityKeyRec(t, 2, now)
	r1, r2 := newProfileLog(t), newProfileLog(t)
	for _, l := range []*profileLog{r1, r2} {
		l.putKeys(0, a)
		if err := asApplyErr(l.putKeys(0, b)); !errors.Is(err, ErrIdentityKeysConflict) {
			t.Fatalf("racing first key: %v", err)
		}
		set, err := cloudidentity.KeySet{Generation: 1, Keys: []cloudidentity.KeyRecord{a}}.Rotate(c, now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		l.putKeys(1, set.Keys...)
		l.putRole("team:p", "deploy", "runner")
		l.putRole("team:p", "deploy", "admin")
		l.delRole("team:p", "missing")
	}
	if !reflect.DeepEqual(r1.fsm.identity, r2.fsm.identity) {
		t.Fatal("replicas diverged")
	}
}

// A token signed with the key one replica holds verifies with the JWKS
// another replica serves: the cluster check of section 5.
func TestFSMIdentityTokenSignedOnOneNodeVerifiesOnAnother(t *testing.T) {
	now := time.Now()
	nodeA, nodeB := newProfileLog(t), newProfileLog(t)
	first := identityKeyRec(t, 0, now)
	for _, l := range []*profileLog{nodeA, nodeB} {
		l.putKeys(0, first)
	}
	active, ok := nodeA.fsm.identityKeys().Active()
	if !ok {
		t.Fatal("no active key on node A")
	}
	signer := cloudidentity.Signer{KeyID: active.ID, Key: testOpen(t, active)}
	tok, err := signer.Issue(cloudidentity.IssueRequest{Issuer: "https://api.example.com", OwnerRef: "team:p", SandboxID: "sb-1",
		RoleTag: "deploy", Audience: cloudidentity.DefaultAudience, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := cloudidentity.JWKS(nodeB.fsm.identityKeys().Published(now))
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := cloudidentity.Verify(tok.Raw, jwks, now); err != nil || claims.Subject != "team:p:role:deploy" {
		t.Fatalf("verify on node B = %+v %v", claims, err)
	}
	// After a rotation replicated to B, the old token still verifies for
	// the overlap, and a new token from A verifies too.
	rotated, _ := nodeA.fsm.identityKeys().Rotate(identityKeyRec(t, 1, now), now)
	for _, l := range []*profileLog{nodeA, nodeB} {
		l.putKeys(1, rotated.Keys...)
	}
	jwks, _ = cloudidentity.JWKS(nodeB.fsm.identityKeys().Published(now.Add(time.Hour)))
	if _, err := cloudidentity.Verify(tok.Raw, jwks, now.Add(59*time.Minute)); err != nil {
		t.Fatalf("pre-rotation token after rotation: %v", err)
	}
	next, _ := nodeA.fsm.identityKeys().Active()
	tok2, _ := cloudidentity.Signer{KeyID: next.ID, Key: testOpen(t, next)}.Issue(cloudidentity.IssueRequest{
		Issuer: "https://api.example.com", OwnerRef: "team:p", SandboxID: "sb-1", RoleTag: "deploy", Audience: "a", Now: now})
	if _, err := cloudidentity.Verify(tok2.Raw, jwks, now); err != nil {
		t.Fatalf("post-rotation token: %v", err)
	}
}

func TestFSMIdentitySnapshotRestore(t *testing.T) {
	l := newProfileLog(t)
	now := time.Unix(1_800_000_000, 0)
	l.putKeys(0, identityKeyRec(t, 0, now))
	l.putRole("team:p", "deploy", "runner")
	l.putRole("", "ops", "admin")
	snap, err := l.fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.identity, l.fsm.identity) {
		t.Fatalf("identity did not survive the snapshot:\n got %+v\nwant %+v", restored.identity, l.fsm.identity)
	}
	// A restored replica keeps applying the log where the snapshot left
	// it: the next CAS names generation 1.
	rl := &profileLog{t: t, fsm: restored, idx: l.idx}
	rotated, _ := restored.identityKeys().Rotate(identityKeyRec(t, 1, now), now)
	if res, ok := rl.putKeys(1, rotated.Keys...).(identityKeysApplyResult); !ok || res.Keys.Generation != 2 {
		t.Fatalf("apply after restore = %+v", res)
	}

	// A snapshot from a build without identity restores to none.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(fsmSnapshotPayload{Version: 1}); err != nil {
		t.Fatal(err)
	}
	old := newPlacementFSM()
	old.putIdentityForTest()
	if err := old.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatal(err)
	}
	if got := old.identityKeys(); got.Generation != 0 || len(old.identityRoles("team:p", nil, "", 0)) != 0 {
		t.Fatalf("old snapshot restored to %+v", got)
	}
	// A snapshot of an FSM that never saw an identity write carries none.
	fresh := newPlacementFSM()
	if keys, roles := fresh.identitySnapshotLocked(); keys != nil || roles != nil {
		t.Fatal("an untouched FSM snapshotted identity state")
	}
}

// putIdentityForTest leaves state a restore must replace.
func (f *placementFSM) putIdentityForTest() {
	f.identityLocked().roles[IdentityRoleKey{"team:p", "stale"}] = &IdentityRoleRecord{Owner: "team:p", Tag: "stale", MinRole: "runner"}
}

func TestIdentityCommandShapes(t *testing.T) {
	role := &IdentityRoleRecord{Owner: "o", Tag: "t", MinRole: "runner"}
	for name, tc := range map[string]struct {
		req  IdentityWriteRequest
		op   opCode
		fail bool
	}{
		"keys":        {IdentityWriteRequest{Keys: &IdentityKeysWrite{}}, opPutIdentityKeys, false},
		"put role":    {IdentityWriteRequest{Role: role}, opPutIdentityRole, false},
		"delete role": {IdentityWriteRequest{Role: role, DeleteRole: true}, opDeleteIdentityRole, false},
		"nothing":     {IdentityWriteRequest{}, 0, true},
		"both":        {IdentityWriteRequest{Keys: &IdentityKeysWrite{}, Role: role}, 0, true},
		"keys+delete": {IdentityWriteRequest{Keys: &IdentityKeysWrite{}, DeleteRole: true}, 0, true},
	} {
		cmd, err := identityCommand(tc.req)
		if (err != nil) != tc.fail || (!tc.fail && cmd.Op != tc.op) {
			t.Errorf("%s: op=%d err=%v", name, cmd.Op, err)
		}
	}
}
