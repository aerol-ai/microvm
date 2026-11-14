package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

const retireTemplateRef = "aocr.test/cluster/c/templates/tpl-1:latest"

// Deleting a template records the obligation to retire the copy it pushed,
// in the delete's own transaction, as for a snapshot.
func TestDeleteTemplateRetiringRegistryCopy(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name        string
		ref, digest string
		want        bool
	}{
		{name: "pushed copy", ref: retireTemplateRef, digest: retireOld, want: true},
		{name: "no digest", ref: retireTemplateRef},
		{name: "never pushed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			seedPushedTemplate(t, st, "tpl-1", tc.ref, tc.digest, models.TemplatePushStateActive)
			if err := st.DeleteTemplateRetiringRegistryCopy(ctx, "tpl-1"); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if _, err := st.GetTemplate(ctx, "tpl-1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("row still there: %v", err)
			}
			due := dueRetirements(t, st)
			if got := len(due) == 1; got != tc.want {
				t.Fatalf("obligation recorded = %v (%+v), want %v", got, due, tc.want)
			}
			if tc.want && (due[0].RegistryRef != retireTemplateRef || due[0].Digest != retireOld || due[0].OwnerRef != "" || due[0].Name != "tpl-1") {
				t.Fatalf("obligation = %+v", due[0])
			}
		})
	}

	st := newTestStore(t)
	if err := st.DeleteTemplateRetiringRegistryCopy(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing row = %v", err)
	}
	_ = st.Close()
	if err := st.DeleteTemplateRetiringRegistryCopy(ctx, "tpl-1"); err == nil {
		t.Fatal("closed store")
	}
}

// The row and its obligation go together or not at all: a failed
// obligation write, or a refused delete, keeps the row.
func TestDeleteTemplateRetirementIsAtomicWithTheDelete(t *testing.T) {
	cases := []struct{ name, trigger string }{
		{"obligation write fails", `CREATE TRIGGER fail_retire BEFORE INSERT ON snapshot_registry_retirements BEGIN SELECT RAISE(ABORT, 'disk full'); END`},
		{"row delete refused", `CREATE TRIGGER keep_tpl BEFORE DELETE ON firecracker_templates BEGIN SELECT RAISE(ABORT, 'locked'); END`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st := newTestStore(t)
			seedPushedTemplate(t, st, "tpl-1", retireTemplateRef, retireOld, models.TemplatePushStateActive)
			if _, err := st.db.Exec(tc.trigger); err != nil {
				t.Fatal(err)
			}
			if err := st.DeleteTemplateRetiringRegistryCopy(ctx, "tpl-1"); err == nil {
				t.Fatal("delete succeeded")
			}
			if _, err := st.GetTemplate(ctx, "tpl-1"); err != nil {
				t.Fatalf("row = %v, want it kept", err)
			}
			if due := dueRetirements(t, st); len(due) != 0 {
				t.Fatalf("obligation without its delete: %+v", due)
			}
		})
	}
}

// A template row that names a manifest makes its obligation void, and a
// template with a push still to land makes an obligation under its id wait.
func TestSnapshotRegistryCopyInUseSeesTemplates(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	check := func(owner string, wantInUse, wantPending bool) {
		t.Helper()
		inUse, pending, err := st.SnapshotRegistryCopyInUse(ctx, retireTemplateRef, retireOld, owner, "tpl-1")
		if err != nil || inUse != wantInUse || pending != wantPending {
			t.Fatalf("owner %q: in use = %v pending = %v (%v), want %v %v", owner, inUse, pending, err, wantInUse, wantPending)
		}
	}
	check("", false, false)
	seedPushedTemplate(t, st, "tpl-1", "", "", models.TemplatePushStatePending)
	check("", false, true)
	// A snapshot obligation (it has an owner) never waits on a template.
	check("acme", false, false)
	seedPushedTemplate(t, st, "tpl-2", retireTemplateRef, retireOld, models.TemplatePushStateActive)
	check("", true, true)
}

func seedPushedTemplate(t *testing.T, st *Store, id, ref, digest, pushState string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.CreateTemplate(ctx, &models.Template{ID: id, Image: "img", Status: models.TemplateStatusReady, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE firecracker_templates SET registry_ref = ?, push_digest = ?, push_state = ? WHERE id = ?`,
		ref, digest, pushState, id); err != nil {
		t.Fatal(err)
	}
}
