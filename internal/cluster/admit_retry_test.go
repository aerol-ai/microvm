package cluster

import (
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// A resend of a reservation that already committed (its first answer was
// lost, for example in a leader change) is applied by the FSM as a TTL
// refresh that adds no load. Admission must not count it on top of itself:
// on a full worker that refused the retry while the reservation kept the
// slot. Found by the offline fault harness (PR #1017, Bug A).
func TestAdmitReservationRetryOnAFullWorker(t *testing.T) {
	now := time.Now().Unix()
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}
	reserve := func(id, owner, incarnation string, expires int64) command {
		return command{Op: opReserve, SandboxID: id, OwnerNodeID: owner, Spec: spec, IncarnationID: incarnation, ExpiresUnix: expires}
	}
	held := reserve("sb-retry", "w1", "inc-1", now+120)

	cases := []struct {
		name    string
		resend  command
		wantErr error
	}{
		{"same create resent", held, nil},
		{"new incarnation of the id", reserve("sb-retry", "w1", "inc-2", now+120), ErrCapacityExceeded},
		{"a different sandbox", reserve("sb-other", "w1", "inc-3", now+120), ErrCapacityExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// One CPU: the held reservation fills the worker.
			c := slotCluster(slotWorker("w1", 1, containerAndFC))
			if err := c.admitReservationCommand(held); err != nil {
				t.Fatalf("first reserve on an empty worker: %v", err)
			}
			payload, err := encodeCommand(held)
			if err != nil {
				t.Fatal(err)
			}
			if res := c.fsm.Apply(&raft.Log{Index: 1, Type: raft.LogCommand, Data: payload, AppendedAt: time.Now()}); res != nil {
				t.Fatalf("apply first reserve: %v", res)
			}
			err = c.admitReservationCommand(tc.resend)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("resend = %v, want admitted (the FSM refreshes the TTL; it adds no load)", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("resend = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// The pending-create cap counts the same way: a resend of a held reservation
// does not add a pending create.
func TestAdmitReservationRetryAtThePendingCap(t *testing.T) {
	now := time.Now().Unix()
	held := command{Op: opReserve, SandboxID: "sb-cap", OwnerNodeID: "w1",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}, IncarnationID: "inc-1", ExpiresUnix: now + 120}
	c := slotCluster(slotWorker("w1", 8, containerAndFC))
	c.cfg.ClusterCreateMaxPendingPerWorker = 1
	payload, err := encodeCommand(held)
	if err != nil {
		t.Fatal(err)
	}
	if res := c.fsm.Apply(&raft.Log{Index: 1, Type: raft.LogCommand, Data: payload, AppendedAt: time.Now()}); res != nil {
		t.Fatalf("apply: %v", res)
	}
	if err := c.admitReservationCommand(held); err != nil {
		t.Fatalf("resend at the pending cap = %v, want admitted", err)
	}
	other := held
	other.SandboxID, other.IncarnationID = "sb-next", "inc-2"
	if err := c.admitReservationCommand(other); !errors.Is(err, ErrCreateBackpressure) {
		t.Fatalf("a new create at the pending cap = %v, want ErrCreateBackpressure", err)
	}
}

func TestWithoutLiveReservationRetries(t *testing.T) {
	now := time.Now().Unix()
	f := newPlacementFSM()
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}
	apply := func(index uint64, cmd command) {
		t.Helper()
		payload, err := encodeCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if res := f.Apply(&raft.Log{Index: index, Type: raft.LogCommand, Data: payload, AppendedAt: time.Now()}); res != nil {
			t.Fatalf("apply %d: %v", index, res)
		}
	}
	apply(1, command{Op: opReserve, SandboxID: "sb-live", OwnerNodeID: "w1", Spec: spec, IncarnationID: "inc-live", ExpiresUnix: now + 120})
	apply(2, command{Op: opReserve, SandboxID: "sb-ending", OwnerNodeID: "w1", Spec: spec, IncarnationID: "inc-end", ExpiresUnix: now + reservationRetryAdmitMargin - 1})
	apply(3, command{Op: opReserve, SandboxID: "sb-placed", OwnerNodeID: "w1", Spec: spec, IncarnationID: "inc-placed", ExpiresUnix: now + 120})
	apply(4, command{Op: opPlace, SandboxID: "sb-placed", OwnerNodeID: "w1", ExpectedIncarnationID: "inc-placed"})

	r := func(id, owner, inc string) reservationCommand {
		return reservationCommand{SandboxID: id, OwnerNodeID: owner, IncarnationID: inc, Spec: spec}
	}
	cases := []struct {
		name string
		in   reservationCommand
		drop bool
	}{
		{"live retry", r("sb-live", "w1", "inc-live"), true},
		{"other owner", r("sb-live", "w2", "inc-live"), false},
		{"other incarnation", r("sb-live", "w1", "inc-other"), false},
		{"no incarnation", r("sb-live", "w1", ""), false},
		{"expires inside the margin", r("sb-ending", "w1", "inc-end"), false},
		{"already placed", r("sb-placed", "w1", "inc-placed"), false},
		{"unknown sandbox", r("sb-new", "w1", "inc-new"), false},
	}
	for _, tc := range cases {
		got := withoutLiveReservationRetries(f, []reservationCommand{tc.in}, now)
		if dropped := len(got) == 0; dropped != tc.drop {
			t.Errorf("%s: dropped = %v, want %v", tc.name, dropped, tc.drop)
		}
	}

	// A batch keeps its order and drops only the retries.
	batch := []reservationCommand{r("sb-a", "w1", "inc-a"), r("sb-live", "w1", "inc-live"), r("sb-b", "w1", "inc-b")}
	got := withoutLiveReservationRetries(f, batch, now)
	if len(got) != 2 || got[0].SandboxID != "sb-a" || got[1].SandboxID != "sb-b" {
		t.Fatalf("batch = %+v, want sb-a then sb-b", got)
	}
	if out := withoutLiveReservationRetries(f, batch[:1], now); &out[0] != &batch[0] {
		t.Fatal("a batch with no retry must be returned as is, without a copy")
	}
	if got := withoutLiveReservationRetries(nil, batch, now); len(got) != 3 {
		t.Fatalf("nil FSM dropped reservations: %+v", got)
	}
}
