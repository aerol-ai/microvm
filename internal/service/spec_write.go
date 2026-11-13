package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// specWriteAttempts bounds how many times writeReplicatedSpec reads the spec
// when a read turns out to be older than this node's own last write, or the
// leader refuses a write as based on an old copy. A worker's read can reach
// a follower that has not yet heard that the last write committed. With no
// new entries the leader tells it after one to two raft CommitTimeouts (50
// to 100 ms with the defaults this daemon runs), so five reads spaced 10,
// 20, 40 and 80 ms apart outlast that, and each read picks a server at
// random, so most retries reach a fresh one sooner.
const specWriteAttempts = 5

// specWriteRetryDelay is the wait before the first re-read; it doubles each
// time.
const specWriteRetryDelay = 10 * time.Millisecond

// writeReplicatedSpec is the one read-change-write of a sandbox's replicated
// spec that every spec write-through uses. edit gets the spec as read (nil
// when the cluster holds none), changes it in place, and reports whether
// there is anything to write.
//
// A spec write replaces the whole spec, so a write based on an old copy puts
// back whatever changed since: a tags change right after a resize put back
// the old size. And a decision not to write, made on an old copy, can skip
// a change: tags set and then set straight back matched the old copy, so
// the second change was never written. On a client that reports versions
// (cluster.VersionedSpecClient, spec_version_fence.go) two checks close both:
//
//   - A read older than this node's last write of the spec (specReadFloors)
//     is read again before edit sees it.
//   - The write lands only while the spec is still the one edit saw; when
//     the leader refuses it (cluster.ErrSpecVersionConflict), this reads
//     again and calls edit again on the new copy.
//
// So edit must be safe to call more than once, each time on a fresh copy.
// Any other client (Noop, test doubles) reads and writes once, as before.
//
// The caller holds the sandbox's spec lock (lockSpec), so the retries race
// only a stale read or another node's write, never this node's own. ctx
// bounds the writes and the waits between them.
func (s *Service) writeReplicatedSpec(ctx context.Context, c cluster.Client, id string, edit func(*models.CreateSandboxRequest) (bool, error)) error {
	vc, ok := c.(cluster.VersionedSpecClient)
	if !ok {
		spec := c.SpecOf(id)
		write, err := edit(spec)
		if err != nil || !write {
			return err
		}
		return c.UpsertSpec(ctx, id, spec, cluster.PlacementSecrets{})
	}
	delay := specWriteRetryDelay
	for attempt := 1; ; attempt++ {
		spec, version := vc.SpecAndVersionOf(id)
		var err error
		if floor := s.specFloors.get(id); version != 0 && version < floor {
			err = fmt.Errorf("%w: read %s at version %d, this node wrote it past %d", cluster.ErrSpecVersionConflict, id, version, floor-1)
		} else {
			write, editErr := edit(spec)
			if editErr != nil || !write {
				return editErr
			}
			err = vc.UpsertSpecIfVersion(ctx, id, spec, version)
			if err == nil {
				if version != 0 {
					// The write landed at a later Raft index than version.
					s.specFloors.raise(id, version+1)
				}
				return nil
			}
			if !errors.Is(err, cluster.ErrSpecVersionConflict) {
				return err
			}
		}
		if attempt == specWriteAttempts {
			return err
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return err
		case <-t.C:
		}
		delay *= 2
	}
}

// specFloorTTL is how long a node remembers the version its own spec write
// moved a sandbox past. A follower that far behind has lost contact with the
// leader and refuses reads (cluster.PlacementViewStale, 2 s by default), so
// an older floor protects nothing.
const specFloorTTL = 10 * time.Second

// specFloorSweepAt is the map size at which raise drops expired floors.
const specFloorSweepAt = 1024

// specReadFloors is, per sandbox, the lowest Placement.Version a spec read
// may return on this node: one past the version its last spec write was
// based on. A read below it is a copy from before that write. The zero
// value is ready to use.
type specReadFloors struct {
	mu sync.Mutex
	m  map[string]specReadFloor
}

type specReadFloor struct {
	version uint64
	at      time.Time
}

// get returns id's floor, 0 when there is none.
func (f *specReadFloors) get(id string) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	floor, ok := f.m[id]
	if !ok {
		return 0
	}
	if time.Since(floor.at) > specFloorTTL {
		delete(f.m, id)
		return 0
	}
	return floor.version
}

// raise records that a read of id below version is stale. Floors only move
// up. When the map holds specFloorSweepAt entries it drops the expired ones
// first, so it stays as small as the sandboxes this node wrote in the last
// specFloorTTL.
func (f *specReadFloors) raise(id string, version uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.m == nil {
		f.m = make(map[string]specReadFloor)
	}
	if len(f.m) >= specFloorSweepAt {
		for k, v := range f.m {
			if now.Sub(v.at) > specFloorTTL {
				delete(f.m, k)
			}
		}
	}
	if cur, ok := f.m[id]; ok && cur.version > version {
		version = cur.version
	}
	f.m[id] = specReadFloor{version: version, at: now}
}
