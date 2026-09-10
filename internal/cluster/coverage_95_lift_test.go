package cluster

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestNoopZeroCoverageMethods(t *testing.T) {
	n := NewNoop("self", "http://self", "")
	ctx := context.Background()
	n.AttachInternalHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	got, err := n.AuthoritativePlacementsByIDs(ctx, []string{"sb-1"})
	if err != nil || len(got) != 0 {
		t.Fatalf("AuthoritativePlacementsByIDs = %v %v", got, err)
	}
	if err := n.BeginDeletePlacementExact(ctx, "sb-1", "self", "inc-1"); err != nil {
		t.Fatalf("BeginDeletePlacementExact = %v", err)
	}

	d := &gossipDelegate{}
	d.NotifyMsg([]byte("x"))
	d.MergeRemoteState([]byte("y"), false)

	(&voterAutoJoinDelegate{}).NotifyUpdate(nil)
	if expiry := placementDeleteExpiryUnix(); expiry <= 0 {
		t.Fatalf("placementDeleteExpiryUnix = %d", expiry)
	}
}

func TestBeginDeletePlacementExactGuards(t *testing.T) {
	ctx := context.Background()
	var c *Cluster
	if err := c.BeginDeletePlacementExact(ctx, "sb", "owner", "inc"); err != nil {
		t.Fatalf("nil cluster = %v", err)
	}
	empty := &Cluster{}
	if err := empty.BeginDeletePlacementExact(ctx, "", "owner", "inc"); err != nil {
		t.Fatalf("empty sandbox = %v", err)
	}
	// fsm == nil short-circuits before the owner/incarnation guard.
	if err := empty.BeginDeletePlacementExact(ctx, "sb", "", "inc"); err != nil {
		t.Fatalf("nil fsm = %v", err)
	}

	a := &Agent{}
	if err := a.BeginDeletePlacementExact(ctx, "", "owner", "inc"); err != nil {
		t.Fatalf("agent empty sandbox = %v", err)
	}
	if err := a.BeginDeletePlacementExact(ctx, "sb", "", ""); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("agent missing owner/incarnation = %v", err)
	}
}
