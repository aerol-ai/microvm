package service

// template_capacity_test.go pins the Phase 6 PR-D service-layer side of
// template-aware placement: the LocalReadyTemplateIDs cache + the
// Capacity() overlay that gossips IDs to peers.

import (
	"context"
	"testing"
	"time"
)

// TestLocalReadyTemplateIDs_CachesForTTL is the heartbeat-protection
// invariant. The capacity-lease loop calls this every gossip tick; an
// uncached implementation would hammer SQLite at every tick, starving
// the create path on its single writer. The cache TTL is 5s — matches
// the gossip interval.
func TestLocalReadyTemplateIDs_CachesForTTL(t *testing.T) {
	svc, st, templatesDir := newHealthHarness(t)
	// Seed one ready template so the first call returns a non-empty list.
	_ = seedReadyTemplate(t, st, templatesDir, "tpl-cached-1")

	first := svc.LocalReadyTemplateIDs(context.Background())
	if len(first) != 1 || first[0] != "tpl-cached-1" {
		t.Fatalf("first call ids = %v, want [tpl-cached-1]", first)
	}
	// Insert a SECOND row. If the cache is honouring its TTL, the next
	// call must NOT see it — only the next call after TTL expiry would.
	_ = seedReadyTemplate(t, st, templatesDir, "tpl-cached-2")
	second := svc.LocalReadyTemplateIDs(context.Background())
	if len(second) != 1 {
		t.Fatalf("second call ids = %v, want [tpl-cached-1] (cached, second insert not visible)", second)
	}
	// Force-expire the cache. A real test wouldn't sleep 5s; we reach
	// into the internal expiry directly because the cache TTL is the
	// invariant under test, not the wall-clock.
	svc.localReadyTemplateIDsMu.Lock()
	svc.localReadyTemplateIDsExpires = time.Now().Add(-1 * time.Second)
	svc.localReadyTemplateIDsMu.Unlock()
	third := svc.LocalReadyTemplateIDs(context.Background())
	if len(third) != 2 {
		t.Fatalf("third call (post-expiry) ids = %v, want both rows visible", third)
	}
}

// TestLocalReadyTemplateIDs_ReturnsDefensiveCopy pins the placement-
// safety invariant: the gossip overlay mutates the snapshot it gets,
// and the cached slice must not be reachable from outside the cache or
// a peer mutation would race the cached read on the next tick. Same
// defensive-copy contract Service.Capacity() relies on.
func TestLocalReadyTemplateIDs_ReturnsDefensiveCopy(t *testing.T) {
	svc, st, templatesDir := newHealthHarness(t)
	_ = seedReadyTemplate(t, st, templatesDir, "tpl-defensive")
	first := svc.LocalReadyTemplateIDs(context.Background())
	if len(first) != 1 {
		t.Fatalf("first ids = %v, want one row", first)
	}
	// Mutate the returned slice in place.
	first[0] = "MUTATED"
	second := svc.LocalReadyTemplateIDs(context.Background())
	if second[0] == "MUTATED" {
		t.Fatal("cache returned shared backing array — caller's mutation leaked into the cache")
	}
}

// TestCapacity_OverlaysLocalTemplateIDs proves Capacity() picks up the
// PR-D inventory. This is what /v1/capacity returns to peers, so an
// empty overlay here would silently disable template-aware placement
// for any remote node fetching our heartbeat.
func TestCapacity_OverlaysLocalTemplateIDs(t *testing.T) {
	svc, st, templatesDir := newHealthHarness(t)
	_ = seedReadyTemplate(t, st, templatesDir, "tpl-cap-1")
	_ = seedReadyTemplate(t, st, templatesDir, "tpl-cap-2")
	snap := svc.Capacity()
	if !snap.LocalTemplateInventoryKnown {
		t.Fatal("Capacity should mark template inventory authoritative")
	}
	if len(snap.LocalTemplateIDs) != 2 {
		t.Fatalf("Capacity.LocalTemplateIDs = %v, want 2 ids", snap.LocalTemplateIDs)
	}
}

func TestCapacity_EmptyTemplateInventoryIsStillAuthoritative(t *testing.T) {
	svc, _, _ := newHealthHarness(t)
	snap := svc.Capacity()
	if !snap.LocalTemplateInventoryKnown {
		t.Fatal("empty template inventory should still be marked authoritative")
	}
	if len(snap.LocalTemplateIDs) != 0 {
		t.Fatalf("Capacity.LocalTemplateIDs = %v, want empty inventory", snap.LocalTemplateIDs)
	}
}
