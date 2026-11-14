package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

type fakeOneWayMigrator struct {
	calls int
	err   error
}

func (f *fakeOneWayMigrator) RunOneWayMigrations(context.Context) error {
	f.calls++
	return f.err
}

// fakeFinalizer is a store with pending one-way migrations (or a broken
// read of them).
type fakeFinalizer struct {
	fakeOneWayMigrator
	pending    []int
	pendingErr error
}

func (f *fakeFinalizer) PendingOneWayMigrations(context.Context) ([]int, error) {
	return f.pending, f.pendingErr
}

// attachTarget records what attachOneWayMigrator handed it.
type attachTarget struct {
	*cluster.Noop
	run      cluster.OneWayMigrator
	finished bool
}

func (a *attachTarget) AttachOneWayMigrator(run cluster.OneWayMigrator, finished bool) {
	a.run, a.finished = run, finished
}

// In a cluster the store's finalize step is handed to the cluster client,
// marked finished when nothing is pending; Noop is left alone.
func TestAttachOneWayMigrator(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		db       *fakeFinalizer
		finished bool
	}{
		{"nothing pending", &fakeFinalizer{}, true},
		{"pending", &fakeFinalizer{pending: []int{13}}, false},
		{"read fails", &fakeFinalizer{pendingErr: errors.New("io")}, false},
	} {
		target := &attachTarget{Noop: cluster.NewNoop("n", "", "")}
		attachOneWayMigrator(ctx, target, tc.db)
		if target.run == nil || target.finished != tc.finished {
			t.Fatalf("%s: attached %v finished %v", tc.name, target.run != nil, target.finished)
		}
		if err := target.run(ctx); err != nil || tc.db.calls != 1 {
			t.Fatalf("%s: the attached step does not run the store's", tc.name)
		}
	}
	db := &fakeFinalizer{}
	attachOneWayMigrator(ctx, cluster.NewNoop("n", "", ""), db)
	if db.calls != 0 {
		t.Fatal("Noop ran migrations")
	}
}

// One-way migrations run at boot only with cluster mode off; in a cluster
// they wait for the rollout's finalize.
func TestRunStandaloneOneWayMigrations(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name      string
		cluster   bool
		err       error
		wantCalls int
		wantErr   bool
	}{
		{name: "standalone runs them", wantCalls: 1},
		{name: "standalone failure stops boot", err: boom, wantCalls: 1, wantErr: true},
		{name: "cluster waits for finalize", cluster: true, wantCalls: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &fakeOneWayMigrator{err: tt.err}
			err := runStandaloneOneWayMigrations(context.Background(), config.Config{EnableCluster: tt.cluster}, db)
			if db.calls != tt.wantCalls {
				t.Fatalf("calls = %d, want %d", db.calls, tt.wantCalls)
			}
			if tt.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && (!errors.Is(err, boom) || !strings.Contains(err.Error(), "one-way schema migrations")) {
				t.Fatalf("err = %v, want it to wrap boom and say what failed", err)
			}
		})
	}
}
