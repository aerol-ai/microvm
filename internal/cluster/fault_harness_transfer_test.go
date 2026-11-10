package cluster

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/raft"
)

// transferWithRetry retries only raft's transfer timeout (and the brief
// "in progress" right after one), stops when leadership moved anyway, and
// still fails a transfer that never works.
func TestTransferWithRetry(t *testing.T) {
	timeout := fmt.Errorf("leadership transfer timeout")
	cases := []struct {
		name      string
		results   []error // one per attempt
		movedAt   int     // attempt after which leadership has moved (0 = never)
		wantErr   error
		wantCalls int
	}{
		{name: "works first time", results: []error{nil}, wantCalls: 1},
		{name: "timeout, then works", results: []error{timeout, nil}, wantCalls: 2},
		{name: "timeout, in progress, then works", results: []error{timeout, raft.ErrLeadershipTransferInProgress, nil}, wantCalls: 3},
		{name: "timeout every time: fails after the bound", results: []error{timeout, timeout, timeout}, wantErr: timeout, wantCalls: 3},
		{name: "timeout but leadership moved anyway", results: []error{timeout}, movedAt: 1, wantCalls: 1},
		{name: "not the leader: no retry", results: []error{raft.ErrNotLeader}, wantErr: raft.ErrNotLeader, wantCalls: 1},
		{name: "in progress on the first try: no retry", results: []error{raft.ErrLeadershipTransferInProgress}, wantErr: raft.ErrLeadershipTransferInProgress, wantCalls: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := transferWithRetry(3, func() error {
				calls++
				return tc.results[calls-1]
			}, func() bool { return tc.movedAt != 0 && calls >= tc.movedAt }, t.Logf)
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil) != (err == nil) {
				t.Fatalf("err %v, want %v", err, tc.wantErr)
			}
			if calls != tc.wantCalls {
				t.Fatalf("%d transfer calls, want %d", calls, tc.wantCalls)
			}
		})
	}
}
