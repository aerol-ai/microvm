package service

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// startReapplyRuntime records egress re-applies and can fail them.
type startReapplyRuntime struct {
	*recordingRuntime
	policies  []string
	blockErr  error
	policyErr error
}

func (r *startReapplyRuntime) ApplyNetworkBlockAll(ip string) error {
	if r.blockErr != nil {
		return r.blockErr
	}
	return r.recordingRuntime.ApplyNetworkBlockAll(ip)
}

func (r *startReapplyRuntime) ApplyEgressPolicy(ip string, _, _ []string) error {
	if r.policyErr != nil {
		return r.policyErr
	}
	r.policies = append(r.policies, ip)
	return nil
}

// TestStartEventReappliesEgress is the P0-4 regression: an out-of-band
// `docker start` must restore block-all and selective egress on the
// sandbox's (possibly new) IP instead of waiting for reconcile.
func TestStartEventReappliesEgress(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	cases := []struct {
		name       string
		blockAll   bool
		allow      []string
		blockErr   error
		policyErr  error
		wantBlock  bool
		wantPolicy bool
		wantErr    bool
	}{
		{name: "no policy is a no-op"},
		{name: "block-all reapplied", blockAll: true, wantBlock: true},
		{name: "allowlist reapplied", allow: []string{"1.1.1.1/32"}, wantPolicy: true},
		{name: "both reapplied", blockAll: true, allow: []string{"1.1.1.1/32"}, wantBlock: true, wantPolicy: true},
		{name: "block failure stops container", blockAll: true, blockErr: errors.New("nft down"), wantErr: true},
		{name: "policy failure stops container", allow: []string{"1.1.1.1/32"}, policyErr: errors.New("nft down"), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, st := newCapacityHarness(t, nil, nil)
			rt := &startReapplyRuntime{
				recordingRuntime: &recordingRuntime{inspect: map[string]*models.SandboxRuntimeState{
					"cid-1": {ContainerID: "cid-1", ContainerIP: "172.17.0.9", Status: models.SandboxStatusStarted},
				}},
				blockErr:  tc.blockErr,
				policyErr: tc.policyErr,
			}
			svc.docker = rt
			sb := &models.Sandbox{
				ID: "sb-start", Image: "img", Status: models.SandboxStatusStopped,
				ContainerID: "cid-1", ContainerIP: "172.17.0.2", Runtime: models.RuntimeDocker,
				NetworkBlockAll: tc.blockAll, NetworkAllowOut: tc.allow,
				CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
			}
			if err := st.Upsert(ctx, sb); err != nil {
				t.Fatal(err)
			}
			err := svc.handleStartEvent(ctx, sb)
			if (err != nil) != tc.wantErr {
				t.Fatalf("handleStartEvent err = %v, wantErr %v", err, tc.wantErr)
			}
			if got := slices.Contains(rt.applyNetworkBlockAllCalls, "172.17.0.9"); got != tc.wantBlock {
				t.Fatalf("block-all on new IP = %v, want %v (calls %v)", got, tc.wantBlock, rt.applyNetworkBlockAllCalls)
			}
			if got := slices.Contains(rt.policies, "172.17.0.9"); got != tc.wantPolicy {
				t.Fatalf("policy on new IP = %v, want %v", got, tc.wantPolicy)
			}
			if tc.wantErr {
				if len(rt.stopRefs) == 0 {
					t.Fatal("failed reapply must stop the container (fail closed)")
				}
				row, err := st.Get(ctx, sb.ID)
				if err != nil || row.Status != models.SandboxStatusError || row.LastError == "" {
					t.Fatalf("row after failure = %+v, %v", row, err)
				}
			}
		})
	}
}
