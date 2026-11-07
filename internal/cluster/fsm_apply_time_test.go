package cluster

import (
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// applyAppendedAt applies cmd as an entry the leader appended at appendedAt.
func applyAppendedAt(t *testing.T, fsm *placementFSM, cmd command, appendedAt time.Time) any {
	t.Helper()
	payload, err := encodeCommand(cmd)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return fsm.Apply(&raft.Log{Data: payload, AppendedAt: appendedAt})
}

// A follower that lags, or a server replaying its log after a restart,
// applies an entry later than the leader did. The outcome must not change:
// it is decided by the time the leader appended the entry, not by the clock
// of the server applying it. On main the replay saw the reservation as
// expired and handed the sandbox to the other router, so the servers
// disagreed on its owner.
func TestFSMApplyDecidesByTheEntryTimeNotTheClock(t *testing.T) {
	appended := time.Now().Add(-time.Hour) // the leader appended these an hour ago
	reserveB := command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "B", IncarnationID: "inc-b",
		ExpiresUnix: appended.Add(120 * time.Second).Unix()}
	reserveC := command{Op: opReserve, SandboxID: "sb1", OwnerNodeID: "C", IncarnationID: "inc-c",
		ExpiresUnix: appended.Add(150 * time.Second).Unix()}

	tests := []struct {
		name      string
		cAppended time.Time
		wantOwner string
		wantErr   error
	}{
		{"C arrives while B's reservation is live", appended.Add(30 * time.Second), "B", ErrReservationConflict},
		{"C arrives after B's reservation expired", appended.Add(121 * time.Second), "C", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Two replicas apply the same entries; neither may consult its
			// own clock, which reads an hour after both entries.
			var snapshots [2]string
			for i := range snapshots {
				fsm := newPlacementFSM()
				if got := applyAppendedAt(t, fsm, reserveB, appended); got != nil {
					t.Fatalf("reserve B = %v", got)
				}
				got := applyAppendedAt(t, fsm, reserveC, tc.cAppended)
				if tc.wantErr == nil && got != nil {
					t.Fatalf("reserve C = %v, want nil", got)
				}
				if tc.wantErr != nil {
					if err, ok := got.(error); !ok || !errors.Is(err, tc.wantErr) {
						t.Fatalf("reserve C = %v, want %v", got, tc.wantErr)
					}
				}
				p, ok := fsm.get("sb1")
				if !ok || p.OwnerNodeID != tc.wantOwner {
					t.Fatalf("owner = %q (present %v), want %q", p.OwnerNodeID, ok, tc.wantOwner)
				}
				snapshots[i] = p.OwnerNodeID + "/" + p.IncarnationID
			}
			if snapshots[0] != snapshots[1] {
				t.Fatalf("replicas disagree: %q vs %q", snapshots[0], snapshots[1])
			}
		})
	}
}

func TestApplyNowFallsBackForAnEntryWithoutATime(t *testing.T) {
	stamped := time.Unix(1_700_000_000, 0)
	if got := applyNow(&raft.Log{AppendedAt: stamped}); got != stamped.Unix() {
		t.Fatalf("applyNow(stamped) = %d, want %d", got, stamped.Unix())
	}
	before := time.Now().Unix()
	if got := applyNow(&raft.Log{}); got < before || got > time.Now().Unix() {
		t.Fatalf("applyNow(unstamped) = %d, want the local clock", got)
	}
	if got := applyNow(nil); got < before {
		t.Fatalf("applyNow(nil) = %d, want the local clock", got)
	}
}
