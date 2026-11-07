package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

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
