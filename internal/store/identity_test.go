package store

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
	"github.com/aerol-ai/microvm/pkg/models"
)

func identityKeyRecord(t *testing.T, now time.Time) cloudidentity.KeyRecord {
	t.Helper()
	key, err := cloudidentity.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := cloudidentity.NewKeyRecord(key, now, func(plain, _ []byte) ([]byte, error) {
		return append([]byte("sealed:"), plain...), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// The key set is replaced whole under a generation CAS: two writers that
// both read generation 0 cannot both make the first key.
func TestIdentityKeysCompareAndSwap(t *testing.T) {
	st := openEgressProfileStore(t)
	ctx := context.Background()
	set, err := st.ReadIdentityKeys(ctx)
	if err != nil || set.Generation != 0 || len(set.Keys) != 0 {
		t.Fatalf("empty read = %+v %v", set, err)
	}
	now := time.Now()
	a, b := identityKeyRecord(t, now), identityKeyRecord(t, now)
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i, rec := range []cloudidentity.KeyRecord{a, b} {
		wg.Add(1)
		go func(i int, rec cloudidentity.KeyRecord) {
			defer wg.Done()
			_, results[i] = st.WriteIdentityKeys(ctx, 0, []cloudidentity.KeyRecord{rec})
		}(i, rec)
	}
	wg.Wait()
	wins := 0
	for _, err := range results {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, ErrIdentityKeysConflict):
			t.Fatalf("loser error = %v, want ErrIdentityKeysConflict", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d writers made the first key, want 1", wins)
	}
	set, err = st.ReadIdentityKeys(ctx)
	if err != nil || set.Generation != 1 || len(set.Keys) != 1 {
		t.Fatalf("after first key = %+v %v", set, err)
	}
	rotated, err := set.Rotate(identityKeyRecord(t, now), now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.WriteIdentityKeys(ctx, 1, rotated.Keys)
	if err != nil || got.Generation != 2 || len(got.Keys) != 2 {
		t.Fatalf("rotate write = %+v %v", got, err)
	}
	if _, err := st.WriteIdentityKeys(ctx, 1, rotated.Keys); !errors.Is(err, ErrIdentityKeysConflict) {
		t.Fatalf("stale write = %v", err)
	}
	// An invalid set never reaches the table.
	if _, err := st.WriteIdentityKeys(ctx, 2, []cloudidentity.KeyRecord{a, b}); !errors.Is(err, cloudidentity.ErrKeySetInvalid) {
		t.Fatalf("two active keys = %v", err)
	}
	reread, err := st.ReadIdentityKeys(ctx)
	if err != nil || reread.Generation != 2 || string(reread.Keys[0].SealedPrivate) != string(got.Keys[0].SealedPrivate) {
		t.Fatalf("reread = %+v %v", reread.Generation, err)
	}
}

func TestIdentityRoleCRUD(t *testing.T) {
	st := openEgressProfileStore(t)
	ctx := context.Background()
	now := time.Now()
	r, changed, err := st.PutIdentityRole(ctx, "team:payments", "deploy", "runner", now)
	if err != nil || !changed || r.MinRole != "runner" || !r.CreatedAt.Equal(now.UTC()) {
		t.Fatalf("put = %+v %v %v", r, changed, err)
	}
	if r, changed, _ = st.PutIdentityRole(ctx, "team:payments", "deploy", "runner", now.Add(time.Second)); changed || !r.UpdatedAt.Equal(now.UTC()) {
		t.Fatalf("same body must be a no-op: %+v %v", r, changed)
	}
	if r, changed, _ = st.PutIdentityRole(ctx, "team:payments", "deploy", "admin", now.Add(time.Second)); !changed || r.MinRole != "admin" || !r.CreatedAt.Equal(now.UTC()) {
		t.Fatalf("update = %+v %v", r, changed)
	}
	if _, err := st.GetIdentityRole(ctx, "team:other", "deploy"); !errors.Is(err, ErrIdentityRoleNotFound) {
		t.Fatalf("other owner sees the tag: %v", err)
	}
	for _, tag := range []string{"a", "b", "c"} {
		if _, _, err := st.PutIdentityRole(ctx, "team:payments", tag, "runner", now); err != nil {
			t.Fatal(err)
		}
	}
	page, err := st.ListIdentityRoles(ctx, "team:payments", "a", 2)
	if err != nil || len(page) != 2 || page[0].Tag != "b" || page[1].Tag != "c" {
		t.Fatalf("page = %+v %v", page, err)
	}
	if empty, err := st.ListIdentityRoles(ctx, "team:none", "", 10); err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty list = %#v %v", empty, err)
	}
	for i := 0; i < 2; i++ {
		if err := st.DeleteIdentityRole(ctx, "team:payments", "deploy"); err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
	}
	if _, err := st.GetIdentityRole(ctx, "team:payments", "deploy"); !errors.Is(err, ErrIdentityRoleNotFound) {
		t.Fatalf("deleted tag still there: %v", err)
	}
}

func TestSandboxIdentityRowsAndRefresherSelection(t *testing.T) {
	st := openEgressProfileStore(t)
	ctx := context.Background()
	for _, sb := range []*models.Sandbox{
		{ID: "sb-run", Status: models.SandboxStatusStarted, OwnerRef: "team:payments"},
		{ID: "sb-fresh", Status: models.SandboxStatusStarted, OwnerRef: "team:payments"},
		{ID: "sb-stopped", Status: models.SandboxStatusStopped, OwnerRef: "team:payments"},
		{ID: "sb-plain", Status: models.SandboxStatusStarted},
	} {
		sb.Image = "alpine"
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"sb-run", "sb-fresh", "sb-stopped"} {
		if err := st.PutSandboxIdentity(ctx, SandboxIdentity{SandboxID: id, OwnerRef: "team:payments", RoleTag: "deploy",
			Audience: "sts.amazonaws.com", AWSRoleARN: "arn:aws:iam::123456789012:role/x"}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	if err := st.RecordIdentityTokenPushed(ctx, "sb-fresh", "kid-1", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	due, err := st.SandboxIdentitiesDue(ctx, now.Add(30*time.Minute), IdentityDueCursor{}, 10)
	if err != nil || len(due) != 1 || due[0].SandboxID != "sb-run" {
		t.Fatalf("due = %+v %v (want only the running sandbox with no token)", due, err)
	}
	// Close to expiry, the fresh one is due too.
	due, _ = st.SandboxIdentitiesDue(ctx, now.Add(61*time.Minute), IdentityDueCursor{}, 10)
	if len(due) != 2 || due[0].SandboxID != "sb-run" || due[1].SandboxID != "sb-fresh" {
		t.Fatalf("due near expiry = %+v", due)
	}
	// Paging: one row a page walks both, in order, then stops.
	cur := IdentityDueCursor{}
	var walked []string
	for {
		page, err := st.SandboxIdentitiesDue(ctx, now.Add(61*time.Minute), cur, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		walked = append(walked, page[0].SandboxID)
		cur = cur.Next(page)
	}
	if len(walked) != 2 || walked[0] != "sb-run" || walked[1] != "sb-fresh" {
		t.Fatalf("paged walk = %v", walked)
	}
	if same := cur.Next(nil); same != cur {
		t.Fatal("Next of an empty page moved the cursor")
	}
	if err := st.RecordIdentityTokenFailed(ctx, "sb-run", "toolbox unreachable"); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, "sb-run")
	if err != nil || got.Identity == nil || got.Identity.LastError != "toolbox unreachable" || got.Identity.TokenExpiresAt != nil ||
		got.Identity.Subject != "team:payments:role:deploy" || got.Identity.TokenFile != cloudidentity.TokenFile {
		t.Fatalf("view = %+v %v", got.Identity, err)
	}
	fresh, _ := st.Get(ctx, "sb-fresh")
	if fresh.Identity == nil || fresh.Identity.TokenExpiresAt == nil || fresh.Identity.TokenExpiresAt.Unix() != now.Add(time.Hour).Unix() {
		t.Fatalf("fresh view = %+v", fresh.Identity)
	}
	if plain, _ := st.Get(ctx, "sb-plain"); plain.Identity != nil {
		t.Fatalf("sandbox without identity shows one: %+v", plain.Identity)
	}
	list, err := st.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	withIdentity := 0
	for _, sb := range list {
		if sb.Identity != nil {
			withIdentity++
		}
	}
	if withIdentity != 3 {
		t.Fatalf("list attached %d identities, want 3", withIdentity)
	}
	// A recreate with the same id clears the token state.
	if err := st.PutSandboxIdentity(ctx, SandboxIdentity{SandboxID: "sb-fresh", OwnerRef: "team:payments", RoleTag: "deploy", Audience: "a"}); err != nil {
		t.Fatal(err)
	}
	if row, err := st.GetSandboxIdentity(ctx, "sb-fresh"); err != nil || row.TokenExpiresUnix != 0 || row.Audience != "a" {
		t.Fatalf("after replace = %+v %v", row, err)
	}
	long := make([]byte, 600)
	for i := range long {
		long[i] = 'x'
	}
	if err := st.RecordIdentityTokenFailed(ctx, "sb-fresh", string(long)); err != nil {
		t.Fatal(err)
	}
	if row, _ := st.GetSandboxIdentity(ctx, "sb-fresh"); len(row.LastError) != 512 {
		t.Fatalf("reason not capped: %d", len(row.LastError))
	}
	// Rows go with their sandbox.
	if err := st.Delete(ctx, "sb-run"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSandboxIdentity(ctx, "sb-run"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("identity row outlived its sandbox: %v", err)
	}
	if err := st.RecordIdentityTokenPushed(ctx, "sb-run", "k", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update of a gone row = %v", err)
	}
}

func TestAttachIdentitiesReadsAllRowsForBigPages(t *testing.T) {
	st := openEgressProfileStore(t)
	ctx := context.Background()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-1", Image: "alpine", Status: models.SandboxStatusStarted}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSandboxIdentity(ctx, SandboxIdentity{SandboxID: "sb-1", RoleTag: "r", Audience: "a"}); err != nil {
		t.Fatal(err)
	}
	byID := map[string]*models.Sandbox{}
	for i := 0; i <= identityAttachInLimit; i++ {
		byID[string(rune(0x1000+i))] = &models.Sandbox{}
	}
	byID["sb-1"] = &models.Sandbox{ID: "sb-1"}
	if err := st.attachIdentities(ctx, byID); err != nil {
		t.Fatal(err)
	}
	if byID["sb-1"].Identity == nil || byID["sb-1"].Identity.Subject != "operator:role:r" {
		t.Fatalf("big page attach = %+v", byID["sb-1"].Identity)
	}
	if err := st.attachIdentities(ctx, nil); err != nil {
		t.Fatal(err)
	}
}
