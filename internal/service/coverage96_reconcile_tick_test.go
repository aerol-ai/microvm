package service

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
)

// The maintenance loop waits on a 30s ticker. synctest advances that clock
// without a real sleep, so one tick runs and the goroutine still exits
// before the bubble does.
func TestCov96SecretReconcileTickOnFakeClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "state.db")
		st, err := store.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		cl := &retirementCluster{
			Noop:    cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{{NodeID: "self", Alive: true}},
		}
		svc := &Service{
			cfg:     config.Config{DBPath: dbPath, SecretTombRetentionDays: 1, AuditDeletedGrace: time.Hour},
			store:   st,
			cluster: cl,
			logger:  slog.New(slog.DiscardHandler),
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		svc.StartSecretDeleteOutboxReconcile(ctx)
		synctest.Wait() // goroutine is blocked on the ticker
		cl.mu.Lock()
		cl.members = append(cl.members, cluster.Member{NodeID: "back", Alive: true})
		cl.mu.Unlock()
		time.Sleep(31 * time.Second)
		synctest.Wait()
		cancel()
		synctest.Wait()
	})
}
