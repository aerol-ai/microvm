package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestListUsageRows(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	created := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		id       string
		status   models.SandboxStatus
		rollback bool
		want     bool
	}{
		{id: "sb-started", status: models.SandboxStatusStarted, want: true},
		{id: "sb-stopped", status: models.SandboxStatusStopped, want: true},
		{id: "sb-creating", status: models.SandboxStatusCreating, want: true},
		{id: "sb-destroyed", status: models.SandboxStatusDestroyed, want: false},
		{id: "sb-rollback", status: models.SandboxStatusStarted, rollback: true, want: false},
	}
	for _, tc := range cases {
		sb := sampleSandbox(tc.id)
		sb.Status = tc.status
		sb.OwnerRef = "acme"
		sb.Engine = models.ContainerEngineContainerd
		sb.CPU, sb.MemoryMB = 1.5, 768
		sb.CreatedAt, sb.UpdatedAt = created, created.Add(time.Minute)
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("Create(%s): %v", tc.id, err)
		}
		if tc.rollback {
			if err := st.MarkSandboxRollbackPending(ctx, tc.id); err != nil {
				t.Fatalf("MarkSandboxRollbackPending(%s): %v", tc.id, err)
			}
		}
	}

	rows, err := st.ListUsageRows(ctx)
	if err != nil {
		t.Fatalf("ListUsageRows() error = %v", err)
	}
	got := map[string]*models.Sandbox{}
	for _, r := range rows {
		got[r.ID] = r
	}
	for _, tc := range cases {
		r, ok := got[tc.id]
		if ok != tc.want {
			t.Fatalf("ListUsageRows() has %s = %v, want %v", tc.id, ok, tc.want)
		}
		if !ok {
			continue
		}
		if r.Status != tc.status || r.ContainerID != "container-"+tc.id || r.OwnerRef != "acme" ||
			r.CPU != 1.5 || r.MemoryMB != 768 || r.Runtime != models.RuntimeGvisor ||
			r.Engine != models.ContainerEngineContainerd || !r.CreatedAt.Equal(created) ||
			!r.UpdatedAt.Equal(created.Add(time.Minute)) {
			t.Fatalf("ListUsageRows() row %s = %+v", tc.id, r)
		}
		// Only the exporter's fields are read; the rest stay zero.
		if r.Image != "" || r.Env != nil || r.ContainerIP != "" {
			t.Fatalf("ListUsageRows() row %s carries fields it should not read: %+v", tc.id, r)
		}
	}
}

func TestListUsageRowsErrors(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		break_  func(t *testing.T, st *Store)
		wantErr string
	}{
		{
			name:    "a closed store",
			break_:  func(t *testing.T, st *Store) { _ = st.Close() },
			wantErr: "list usage rows",
		},
		{
			name: "a row that does not scan",
			break_: func(t *testing.T, st *Store) {
				sb := sampleSandbox("sb-bad")
				if err := st.Create(ctx, sb); err != nil {
					t.Fatal(err)
				}
				if _, err := st.db.ExecContext(ctx, `UPDATE sandboxes SET cpu = 'lots' WHERE id = ?`, sb.ID); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "scan usage row",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			tc.break_(t, st)
			if _, err := st.ListUsageRows(ctx); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ListUsageRows() error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}
