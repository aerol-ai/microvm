package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestAddCustomDomain(t *testing.T) {
	ctx := context.Background()

	t.Run("first add succeeds and surfaces row", func(t *testing.T) {
		st := newTestStore(t)
		if err := st.Create(ctx, sampleSandbox("sb-a")); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := st.AddCustomDomain(ctx, "sb-a", "api.acme.com", 0); err != nil {
			t.Fatalf("AddCustomDomain: %v", err)
		}
		got, err := st.ListCustomDomains(ctx, "sb-a")
		if err != nil {
			t.Fatalf("ListCustomDomains: %v", err)
		}
		if len(got) != 1 || got[0].Hostname != "api.acme.com" {
			t.Fatalf("got %+v", got)
		}
		if got[0].Status != models.CustomDomainPendingDNS {
			t.Fatalf("status = %q, want %q", got[0].Status, models.CustomDomainPendingDNS)
		}
		if got[0].CreatedAt.IsZero() || got[0].UpdatedAt.IsZero() {
			t.Fatalf("timestamps not set: %+v", got[0])
		}
	})

	t.Run("idempotent for same (sandbox, hostname)", func(t *testing.T) {
		st := newTestStore(t)
		if err := st.Create(ctx, sampleSandbox("sb-a")); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := st.AddCustomDomain(ctx, "sb-a", "api.acme.com", 0); err != nil {
			t.Fatalf("first add: %v", err)
		}
		// Mutate status so we can prove the second add does not reset it.
		if err := st.SetCustomDomainStatus(ctx, "api.acme.com", models.CustomDomainReady, ""); err != nil {
			t.Fatalf("SetCustomDomainStatus: %v", err)
		}
		if err := st.AddCustomDomain(ctx, "sb-a", "api.acme.com", 0); err != nil {
			t.Fatalf("idempotent re-add: %v", err)
		}
		got, _ := st.ListCustomDomains(ctx, "sb-a")
		if len(got) != 1 || got[0].Status != models.CustomDomainReady {
			t.Fatalf("re-add reset status: %+v", got)
		}
	})

	t.Run("cross-sandbox conflict surfaces ErrCustomDomainConflict", func(t *testing.T) {
		st := newTestStore(t)
		if err := st.Create(ctx, sampleSandbox("sb-a")); err != nil {
			t.Fatalf("Create sb-a: %v", err)
		}
		if err := st.Create(ctx, sampleSandbox("sb-b")); err != nil {
			t.Fatalf("Create sb-b: %v", err)
		}
		if err := st.AddCustomDomain(ctx, "sb-a", "api.acme.com", 0); err != nil {
			t.Fatalf("first add: %v", err)
		}
		err := st.AddCustomDomain(ctx, "sb-b", "api.acme.com", 0)
		if !errors.Is(err, ErrCustomDomainConflict) {
			t.Fatalf("got %v, want ErrCustomDomainConflict", err)
		}
		// sb-a still owns the hostname.
		owner, err := st.ResolveCustomDomain(ctx, "api.acme.com")
		if err != nil {
			t.Fatalf("ResolveCustomDomain: %v", err)
		}
		if owner != "sb-a" {
			t.Fatalf("owner = %q, want sb-a", owner)
		}
	})

	t.Run("rejects empty inputs", func(t *testing.T) {
		st := newTestStore(t)
		if err := st.AddCustomDomain(ctx, "", "api.acme.com", 0); err == nil {
			t.Fatalf("empty sandbox id accepted")
		}
		if err := st.AddCustomDomain(ctx, "sb-a", "", 0); err == nil {
			t.Fatalf("empty hostname accepted")
		}
	})
}

func TestRemoveCustomDomain(t *testing.T) {
	ctx := context.Background()

	t.Run("known hostname removed", func(t *testing.T) {
		st := newTestStore(t)
		if err := st.Create(ctx, sampleSandbox("sb-a")); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := st.AddCustomDomain(ctx, "sb-a", "api.acme.com", 0); err != nil {
			t.Fatalf("AddCustomDomain: %v", err)
		}
		if err := st.RemoveCustomDomain(ctx, "sb-a", "api.acme.com"); err != nil {
			t.Fatalf("RemoveCustomDomain: %v", err)
		}
		if _, err := st.ResolveCustomDomain(ctx, "api.acme.com"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("post-remove resolve = %v, want ErrNotFound", err)
		}
	})

	t.Run("mismatched sandbox returns ErrNotFound and leaves row intact", func(t *testing.T) {
		st := newTestStore(t)
		if err := st.Create(ctx, sampleSandbox("sb-a")); err != nil {
			t.Fatalf("Create sb-a: %v", err)
		}
		if err := st.Create(ctx, sampleSandbox("sb-b")); err != nil {
			t.Fatalf("Create sb-b: %v", err)
		}
		if err := st.AddCustomDomain(ctx, "sb-a", "api.acme.com", 0); err != nil {
			t.Fatalf("AddCustomDomain: %v", err)
		}
		err := st.RemoveCustomDomain(ctx, "sb-b", "api.acme.com")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
		owner, _ := st.ResolveCustomDomain(ctx, "api.acme.com")
		if owner != "sb-a" {
			t.Fatalf("owner = %q, want sb-a — cross-sandbox delete bled through", owner)
		}
	})

	t.Run("unknown hostname returns ErrNotFound", func(t *testing.T) {
		st := newTestStore(t)
		if err := st.Create(ctx, sampleSandbox("sb-a")); err != nil {
			t.Fatalf("Create: %v", err)
		}
		err := st.RemoveCustomDomain(ctx, "sb-a", "ghost.example.com")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
	})
}

func TestResolveCustomDomain(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.Create(ctx, sampleSandbox("sb-a")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.AddCustomDomain(ctx, "sb-a", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}

	got, err := st.ResolveCustomDomain(ctx, "api.acme.com")
	if err != nil {
		t.Fatalf("ResolveCustomDomain: %v", err)
	}
	if got != "sb-a" {
		t.Fatalf("got %q, want sb-a", got)
	}

	if _, err := st.ResolveCustomDomain(ctx, "unknown.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown host = %v, want ErrNotFound", err)
	}
	if _, err := st.ResolveCustomDomain(ctx, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty host = %v, want ErrNotFound", err)
	}
}

func TestCustomDomainsCascadeOnSandboxDelete(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.Create(ctx, sampleSandbox("sb-a")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, h := range []string{"api.acme.com", "acme.com"} {
		if err := st.AddCustomDomain(ctx, "sb-a", h, 0); err != nil {
			t.Fatalf("AddCustomDomain %s: %v", h, err)
		}
	}
	// Delete the sandbox; FK CASCADE must remove both rows.
	if err := st.Delete(ctx, "sb-a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	rows, err := st.ListAllCustomDomains(ctx)
	if err != nil {
		t.Fatalf("ListAllCustomDomains: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("got %d rows after cascade, want 0: %+v", len(rows), rows)
	}
}

func TestSetCustomDomainStatus(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.Create(ctx, sampleSandbox("sb-a")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.AddCustomDomain(ctx, "sb-a", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}

	before, _ := st.ListCustomDomains(ctx, "sb-a")
	// SQLite stores DATETIME at second resolution; sleep just long enough to
	// guarantee the next write differs and we can prove updated_at moved.
	time.Sleep(1100 * time.Millisecond)

	if err := st.SetCustomDomainStatus(ctx, "api.acme.com", models.CustomDomainIssuing, ""); err != nil {
		t.Fatalf("SetCustomDomainStatus: %v", err)
	}
	after, _ := st.ListCustomDomains(ctx, "sb-a")
	if after[0].Status != models.CustomDomainIssuing {
		t.Fatalf("status = %q, want %q", after[0].Status, models.CustomDomainIssuing)
	}
	if !after[0].UpdatedAt.After(before[0].UpdatedAt) {
		t.Fatalf("updated_at did not advance: before=%v after=%v", before[0].UpdatedAt, after[0].UpdatedAt)
	}

	// Failed → carries LastError through.
	if err := st.SetCustomDomainStatus(ctx, "api.acme.com", models.CustomDomainFailed, "acme: rate limit"); err != nil {
		t.Fatalf("SetCustomDomainStatus failed: %v", err)
	}
	got, _ := st.ListCustomDomains(ctx, "sb-a")
	if got[0].Status != models.CustomDomainFailed || got[0].LastError != "acme: rate limit" {
		t.Fatalf("got %+v, want failed/rate limit", got[0])
	}

	// Unknown hostname → ErrNotFound.
	if err := st.SetCustomDomainStatus(ctx, "ghost.example.com", models.CustomDomainReady, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown host = %v, want ErrNotFound", err)
	}
}

func TestListAllCustomDomainsGroupsBySandbox(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	for _, id := range []string{"sb-a", "sb-b", "sb-c"} {
		if err := st.Create(ctx, sampleSandbox(id)); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	domains := map[string][]string{
		"sb-a": {"api.acme.com", "acme.com"},
		"sb-b": {"foo.example.com"},
		"sb-c": nil, // no custom domains
	}
	for sb, hosts := range domains {
		for _, h := range hosts {
			if err := st.AddCustomDomain(ctx, sb, h, 0); err != nil {
				t.Fatalf("AddCustomDomain %s %s: %v", sb, h, err)
			}
		}
	}

	rows, err := st.ListAllCustomDomains(ctx)
	if err != nil {
		t.Fatalf("ListAllCustomDomains: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3: %+v", len(rows), rows)
	}
	// Reconcile expects hostname-ordered output for stable diffs.
	want := []string{"acme.com", "api.acme.com", "foo.example.com"}
	for i, r := range rows {
		if r.Hostname != want[i] {
			t.Fatalf("rows[%d].Hostname = %q, want %q", i, r.Hostname, want[i])
		}
	}
}

func TestAttachCustomDomainsBulkInList(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	for _, id := range []string{"sb-a", "sb-b"} {
		if err := st.Create(ctx, sampleSandbox(id)); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	if err := st.AddCustomDomain(ctx, "sb-a", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain a: %v", err)
	}
	if err := st.AddCustomDomain(ctx, "sb-a", "acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain a2: %v", err)
	}
	if err := st.AddCustomDomain(ctx, "sb-b", "foo.example.com", 0); err != nil {
		t.Fatalf("AddCustomDomain b: %v", err)
	}

	sandboxes, err := st.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	bySandbox := map[string][]string{}
	for _, sb := range sandboxes {
		for _, cd := range sb.CustomDomains {
			bySandbox[sb.ID] = append(bySandbox[sb.ID], cd.Hostname)
		}
	}
	if len(bySandbox["sb-a"]) != 2 {
		t.Fatalf("sb-a got %v, want 2 hostnames", bySandbox["sb-a"])
	}
	if len(bySandbox["sb-b"]) != 1 || bySandbox["sb-b"][0] != "foo.example.com" {
		t.Fatalf("sb-b got %v, want [foo.example.com]", bySandbox["sb-b"])
	}
}

func TestGetIncludesCustomDomains(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.Create(ctx, sampleSandbox("sb-a")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.AddCustomDomain(ctx, "sb-a", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	got, err := st.Get(ctx, "sb-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.CustomDomains) != 1 || got.CustomDomains[0].Hostname != "api.acme.com" {
		t.Fatalf("Get did not hydrate CustomDomains: %+v", got.CustomDomains)
	}
}
