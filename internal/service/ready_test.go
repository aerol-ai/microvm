package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// contactCluster is a cluster client with a fixed control-plane contact.
type contactCluster struct {
	*cluster.Noop
	contact cluster.ControlPlaneContact
}

func (c contactCluster) ControlPlaneContact(context.Context) cluster.ControlPlaneContact {
	return c.contact
}

// C1: /ready says whether to send this node traffic (TODOS.md "A
// partitioned node keeps serving").
func TestServiceReady(t *testing.T) {
	noop := func() *cluster.Noop { return cluster.NewNoop("n1", "http://127.0.0.1:1", "127.0.0.1") }
	// contact builds the control-plane contact from the time Ready runs, not
	// from one time taken before the table: each case first builds a whole
	// service, which takes about 0.1s under -race, so a shared "now" is half
	// a second old by the fifth case and 20s ago reads as "21s".
	for _, tc := range []struct {
		name    string
		cluster bool
		client  cluster.Client
		contact func(now time.Time) cluster.ControlPlaneContact
		grace   time.Duration
		wantErr string
	}{
		{name: "single node: ready when healthy"},
		{name: "cluster client without contact reporting", cluster: true, client: noop()},
		{name: "fresh contact", cluster: true,
			contact: func(now time.Time) cluster.ControlPlaneContact {
				return cluster.ControlPlaneContact{Member: true, Last: now}
			}},
		{name: "contact inside a set grace", cluster: true, grace: 30 * time.Second,
			contact: func(now time.Time) cluster.ControlPlaneContact {
				return cluster.ControlPlaneContact{Member: true, Last: now.Add(-20 * time.Second)}
			}},
		{name: "contact older than the default grace", cluster: true,
			contact: func(now time.Time) cluster.ControlPlaneContact {
				return cluster.ControlPlaneContact{Member: true, Last: now.Add(-20 * time.Second)}
			},
			wantErr: "no contact with the control plane for 20s (more than 10s)"},
		{name: "never in contact", cluster: true,
			contact: func(time.Time) cluster.ControlPlaneContact { return cluster.ControlPlaneContact{Member: true} },
			wantErr: "no contact with the control plane yet"},
		{name: "removed from the raft configuration", cluster: true,
			contact: func(now time.Time) cluster.ControlPlaneContact {
				return cluster.ControlPlaneContact{Member: false, Last: now}
			},
			wantErr: "not in the control plane's raft configuration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}})
			svc.cfg.EnableCluster = tc.cluster
			svc.cfg.ReadyLeaderGrace = tc.grace
			if tc.client != nil {
				svc.AttachCluster(tc.client)
			}
			if tc.contact != nil {
				svc.AttachCluster(contactCluster{noop(), tc.contact(time.Now())})
			}
			err := svc.Ready(context.Background())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Ready = %v, want ready", err)
				}
				return
			}
			if !errors.Is(err, ErrNotReady) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Ready = %v, want ErrNotReady with %q", err, tc.wantErr)
			}
		})
	}
}

func TestServiceReadyFollowsHealth(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{managed: map[string]*models.SandboxRuntimeState{}})
	_ = st.Close()
	if err := svc.Ready(context.Background()); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Ready with a closed store = %v, want ErrNotReady", err)
	}
}
