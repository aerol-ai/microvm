package store

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func seedPushSnapshot(t *testing.T, st *Store, owner, name string, createdAt time.Time, state string) {
	t.Helper()
	if err := st.CreateSnapshot(context.Background(), &models.SandboxSnapshot{
		Name: name, Image: "aerolvm-snapshot/" + name, SourceSandboxID: "sb", OwnerRef: owner,
		CreatedAt: createdAt, ImageDistributionMode: models.ImageDistributionLocalOnly, PushState: state,
	}); err != nil {
		t.Fatalf("CreateSnapshot %s/%s: %v", owner, name, err)
	}
}

func listAllPendingPush(t *testing.T, st *Store) []string {
	t.Helper()
	rows, err := st.ListSnapshotsPendingPushPage(context.Background(), SnapshotPushCursor{}, maxSnapshotPushPage)
	if err != nil {
		t.Fatalf("ListSnapshotsPendingPushPage: %v", err)
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, row.OwnerRef+"/"+row.Name)
	}
	return names
}

func ageSnapshotClaim(t *testing.T, st *Store, name string) {
	t.Helper()
	expired := time.Now().UTC().Add(-PushClaimLease - time.Minute)
	if _, err := st.db.Exec(`UPDATE sandbox_snapshots SET push_claimed_at = ? WHERE name = ?`, expired, name); err != nil {
		t.Fatalf("age the claim: %v", err)
	}
}

// Of two workers holding the same listed row, exactly one claims it; the
// other walks away without an error. The claim returns the row as claimed.
func TestClaimSnapshotPushIsExclusive(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedPushSnapshot(t, st, "acme", "snap", time.Now().UTC(), models.SnapshotPushStatePending)

	got, stamp, ok, err := st.ClaimSnapshotPush(ctx, "acme", "snap")
	if err != nil || !ok || stamp.IsZero() || got == nil || got.Image != "aerolvm-snapshot/snap" || got.PushState != models.SnapshotPushStatePushing {
		t.Fatalf("first claim = %+v, %v, %v, %v", got, stamp, ok, err)
	}
	if again, _, ok, err := st.ClaimSnapshotPush(ctx, "acme", "snap"); err != nil || ok || again != nil {
		t.Fatalf("second claim = %+v, %v, %v; want none", again, ok, err)
	}
	if names := listAllPendingPush(t, st); len(names) != 0 {
		t.Fatalf("a live claim is still queued: %v", names)
	}
	if _, _, ok, err := st.ClaimSnapshotPush(ctx, "acme", "missing"); err != nil || ok {
		t.Fatalf("claim of a missing row = %v, %v", ok, err)
	}
}

// The lease and the fence together: an expired claim is queued again and
// can be taken over, and from then on only the new claim's completion or
// release applies. The stale worker's writes match nothing.
func TestSnapshotPushClaimLeaseAndFence(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedPushSnapshot(t, st, "", "snap-lease", time.Now().UTC(), models.SnapshotPushStatePending)

	_, stale, ok, err := st.ClaimSnapshotPush(ctx, "", "snap-lease")
	if err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	ageSnapshotClaim(t, st, "snap-lease")
	if names := listAllPendingPush(t, st); !slices.Equal(names, []string{"/snap-lease"}) {
		t.Fatalf("expired claim not queued again: %v", names)
	}
	_, fresh, ok, err := st.ClaimSnapshotPush(ctx, "", "snap-lease")
	if err != nil || !ok {
		t.Fatalf("takeover claim: %v %v", ok, err)
	}

	for name, write := range map[string]func(time.Time) (bool, error){
		"complete": func(at time.Time) (bool, error) {
			return st.CompleteSnapshotPush(ctx, "", "snap-lease", at, models.ImageDistributionAOCR, "aocr/ref:latest", "sha256:old")
		},
		"release": func(at time.Time) (bool, error) {
			return st.ReleaseSnapshotPush(ctx, "", "snap-lease", at, models.SnapshotPushStateError, "late")
		},
	} {
		if applied, err := write(stale); err != nil || applied {
			t.Fatalf("stale %s applied = %v, %v; want fenced off", name, applied, err)
		}
	}
	if applied, err := st.CompleteSnapshotPush(ctx, "", "snap-lease", fresh, models.ImageDistributionAOCR, "aocr/ref:latest", "sha256:new"); err != nil || !applied {
		t.Fatalf("current completion = %v, %v", applied, err)
	}
	got, err := st.GetSnapshot(ctx, "", "snap-lease")
	if err != nil {
		t.Fatal(err)
	}
	if got.PushState != models.SnapshotPushStateActive || got.ImageDistributionMode != models.ImageDistributionAOCR ||
		got.ImageRegistryRef != "aocr/ref:latest" || got.ImageDigest != "sha256:new" || got.ImageVerifiedAt == nil || got.PushError != "" {
		t.Fatalf("completed row = %+v", got)
	}
	// Completed: nothing left to claim, and the old stamp fences everything.
	if _, _, ok, _ := st.ClaimSnapshotPush(ctx, "", "snap-lease"); ok {
		t.Fatal("an active row was claimed")
	}
	if applied, _ := st.ReleaseSnapshotPush(ctx, "", "snap-lease", fresh, models.SnapshotPushStateError, "x"); applied {
		t.Fatal("a release applied after completion")
	}
}

// A release ends the claim without a registry copy: 'error' keeps the reason
// and is queued for the next sweep, 'active' takes the row out of the queue.
// A release may not leave the row in 'pushing'.
func TestReleaseSnapshotPush(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedPushSnapshot(t, st, "", "snap", time.Now().UTC(), models.SnapshotPushStatePending)

	_, stamp, _, _ := st.ClaimSnapshotPush(ctx, "", "snap")
	if applied, err := st.ReleaseSnapshotPush(ctx, "", "snap", stamp, models.SnapshotPushStateError, "registry 502"); err != nil || !applied {
		t.Fatalf("release error = %v, %v", applied, err)
	}
	got, _ := st.GetSnapshot(ctx, "", "snap")
	if got.PushState != models.SnapshotPushStateError || got.PushError != "registry 502" || got.ImageDistributionMode != models.ImageDistributionLocalOnly {
		t.Fatalf("released row = %+v", got)
	}
	if names := listAllPendingPush(t, st); !slices.Equal(names, []string{"/snap"}) {
		t.Fatalf("an errored row must be retried: %v", names)
	}
	_, stamp, _, _ = st.ClaimSnapshotPush(ctx, "", "snap")
	if got, _ := st.GetSnapshot(ctx, "", "snap"); got.PushError != "" {
		t.Fatalf("a fresh claim keeps the old error %q", got.PushError)
	}
	if _, err := st.ReleaseSnapshotPush(ctx, "", "snap", stamp, models.SnapshotPushStatePushing, ""); err == nil {
		t.Fatal("a release to 'pushing' was accepted")
	}
	if applied, err := st.ReleaseSnapshotPush(ctx, "", "snap", stamp, models.SnapshotPushStateActive, ""); err != nil || !applied {
		t.Fatalf("release active = %v, %v", applied, err)
	}
	if names := listAllPendingPush(t, st); len(names) != 0 {
		t.Fatalf("an active row is queued: %v", names)
	}
}

// A backlog is read in bounded pages, oldest first, the primary key breaking
// ties, and every queued row comes back exactly once while rows ahead of the
// cursor change state.
func TestListSnapshotsPendingPushPageWalksTheQueueOnce(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	base := time.Now().UTC().Add(-time.Hour)
	var want []string
	for i, owner := range []string{"b", "a", "", "a", "c", "b", "a"} {
		name := fmt.Sprintf("snap-%d", i)
		at := base.Add(time.Duration(i/2) * time.Second) // pairs share a timestamp
		seedPushSnapshot(t, st, owner, name, at, models.SnapshotPushStatePending)
		want = append(want, owner+"/"+name)
	}
	seedPushSnapshot(t, st, "a", "done", base, models.SnapshotPushStateActive)
	seedPushSnapshot(t, st, "a", "claimed", base, models.SnapshotPushStatePending)
	if _, _, ok, _ := st.ClaimSnapshotPush(ctx, "a", "claimed"); !ok {
		t.Fatal("claim")
	}
	// Expected order: created_at, then owner_ref, then name.
	slices.SortFunc(want, func(x, y string) int {
		ix, iy := snapIndex(x), snapIndex(y)
		if ix/2 != iy/2 {
			return ix/2 - iy/2
		}
		return strings.Compare(x, y)
	})

	var got []string
	cursor := SnapshotPushCursor{}
	for pages := 0; ; pages++ {
		if pages > len(want) {
			t.Fatal("paging does not terminate")
		}
		page, err := st.ListSnapshotsPendingPushPage(ctx, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page {
			got = append(got, row.OwnerRef+"/"+row.Name)
			// Work done on a row behind the cursor must not shift the walk.
			if _, stamp, ok, _ := st.ClaimSnapshotPush(ctx, row.OwnerRef, row.Name); ok {
				_, _ = st.ReleaseSnapshotPush(ctx, row.OwnerRef, row.Name, stamp, models.SnapshotPushStateError, "retry")
			}
		}
		if len(page) < 2 {
			break
		}
		cursor = SnapshotPushCursorAfter(page[len(page)-1])
	}
	if !slices.Equal(got, want) {
		t.Fatalf("walk = %v\nwant   %v", got, want)
	}
	if _, err := st.ListSnapshotsPendingPushPage(ctx, SnapshotPushCursor{}, 0); err == nil {
		t.Fatal("a zero limit was accepted")
	}
}

func snapIndex(key string) int {
	var i int
	_, _ = fmt.Sscanf(key[strings.Index(key, "snap-")+len("snap-"):], "%d", &i)
	return i
}

// A page is a range scan of the partial queue index, never a walk of the
// whole catalogue: steady state holds thousands of finished snapshots and
// an empty queue.
func TestSnapshotPushPageSeeksTheQueueIndex(t *testing.T) {
	st := newTestStore(t)
	query, args := snapshotPushPageSQL(SnapshotPushCursor{}, 10, time.Now().UTC())
	plan := queryPlan(t, st, query, args)
	if !strings.Contains(plan, "idx_sandbox_snapshots_push_queue") {
		t.Fatalf("plan = %s, want the push queue index", plan)
	}
	if strings.Contains(plan, "TEMP B-TREE") {
		t.Fatalf("plan = %s, sorts instead of walking the index in order", plan)
	}
}

func TestSnapshotPushQueueClosedStore(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	_ = st.Close()
	if _, err := st.ListSnapshotsPendingPushPage(ctx, SnapshotPushCursor{}, 1); err == nil {
		t.Error("list on a closed store")
	}
	if _, _, _, err := st.ClaimSnapshotPush(ctx, "", "x"); err == nil {
		t.Error("claim on a closed store")
	}
	if _, err := st.CompleteSnapshotPush(ctx, "", "x", time.Now(), "", "", ""); err == nil {
		t.Error("complete on a closed store")
	}
	if _, err := st.ReleaseSnapshotPush(ctx, "", "x", time.Now(), models.SnapshotPushStateError, ""); err == nil {
		t.Error("release on a closed store")
	}
	if _, _, _, err := st.ClaimTemplatePush(ctx, "x"); err == nil {
		t.Error("template claim on a closed store")
	}
	if _, err := st.CompleteTemplatePush(ctx, "x", time.Now(), "", ""); err == nil {
		t.Error("template complete on a closed store")
	}
	if _, err := st.ReleaseTemplatePush(ctx, "x", time.Now(), models.TemplatePushStateError, ""); err == nil {
		t.Error("template release on a closed store")
	}
}

// Templates share the protocol: one claimer, an expiring lease, and fenced
// completion that lands the registry ref, digest and 'active' together.
func TestTemplatePushClaimLeaseAndFence(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC().Round(time.Second)
	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl", Image: "docker://alpine:3.19", Status: models.TemplateStatusReady,
		CreatedAt: now, UpdatedAt: now, PushState: models.TemplatePushStatePending,
	}); err != nil {
		t.Fatal(err)
	}
	got, stale, ok, err := st.ClaimTemplatePush(ctx, "tpl")
	if err != nil || !ok || got.ID != "tpl" || got.PushState != models.TemplatePushStatePushing {
		t.Fatalf("claim = %+v, %v, %v", got, ok, err)
	}
	if _, _, ok, _ := st.ClaimTemplatePush(ctx, "tpl"); ok {
		t.Fatal("a live template claim was taken twice")
	}
	if rows, _ := st.ListTemplatesPendingPush(ctx); len(rows) != 0 {
		t.Fatalf("a live claim is listed: %d rows", len(rows))
	}
	if _, err := st.db.Exec(`UPDATE firecracker_templates SET push_claimed_at = ? WHERE id = 'tpl'`, time.Now().UTC().Add(-PushClaimLease-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if rows, _ := st.ListTemplatesPendingPush(ctx); len(rows) != 1 {
		t.Fatalf("an expired claim is not listed: %d rows", len(rows))
	}
	_, fresh, ok, err := st.ClaimTemplatePush(ctx, "tpl")
	if err != nil || !ok {
		t.Fatalf("takeover: %v %v", ok, err)
	}
	if applied, err := st.CompleteTemplatePush(ctx, "tpl", stale, "ref:old", "sha256:old"); err != nil || applied {
		t.Fatalf("stale completion applied = %v, %v", applied, err)
	}
	if applied, err := st.ReleaseTemplatePush(ctx, "tpl", stale, models.TemplatePushStateError, "late"); err != nil || applied {
		t.Fatalf("stale release applied = %v, %v", applied, err)
	}
	if applied, err := st.ReleaseTemplatePush(ctx, "tpl", fresh, models.TemplatePushStateError, "registry 502"); err != nil || !applied {
		t.Fatalf("release = %v, %v", applied, err)
	}
	row, _ := st.GetTemplate(ctx, "tpl")
	if row.PushState != models.TemplatePushStateError || row.PushError != "registry 502" {
		t.Fatalf("released template = %+v", row)
	}
	_, fresh, ok, _ = st.ClaimTemplatePush(ctx, "tpl")
	if !ok {
		t.Fatal("an errored template must be claimable")
	}
	if _, err := st.ReleaseTemplatePush(ctx, "tpl", fresh, models.TemplatePushStatePushing, ""); err == nil {
		t.Fatal("a release to 'pushing' was accepted")
	}
	if applied, err := st.CompleteTemplatePush(ctx, "tpl", fresh, "registry/tpl:latest", "sha256:new"); err != nil || !applied {
		t.Fatalf("completion = %v, %v", applied, err)
	}
	row, _ = st.GetTemplate(ctx, "tpl")
	if row.PushState != models.TemplatePushStateActive || row.RegistryRef != "registry/tpl:latest" || row.PushDigest != "sha256:new" || row.PushError != "" {
		t.Fatalf("completed template = %+v", row)
	}
	if _, _, ok, err := st.ClaimTemplatePush(ctx, "missing"); ok || err != nil {
		t.Fatalf("missing template claim = %v, %v", ok, err)
	}
}
