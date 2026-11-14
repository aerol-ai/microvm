package cluster

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Regression tests for the agent-sandbox API's warm-pool depths in the FSM
// (C17; CLAUDE.md "Cluster mode is fragile").

func (l *warmPoolLog) setKube(set ...KubeWarmDepth) any {
	return l.apply(command{Op: opSetKubeWarmDepths, StampUnixNano: int64(1000 + l.idx), KubeWarm: set})
}

func TestFSMKubeWarmDepthsReplaceTheSet(t *testing.T) {
	l := newWarmPoolLog(t)
	l.put("python:3.12", 2)
	if res, ok := l.setKube(KubeWarmDepth{Image: "python:3.12", Runtime: "gvisor", Depth: 3}, KubeWarmDepth{Image: "alpine:3.20", Runtime: "gvisor", Depth: 1}).(kubeWarmApplyResult); !ok || !res.Changed {
		t.Fatalf("first set = %+v", res)
	}
	read := l.read(0)
	if read.Version != 2 || len(read.Pools) != 1 || len(read.Kube) != 2 || read.Kube[0].Image != "alpine:3.20" {
		t.Fatalf("read = %+v (the set is ordered by image and moves the shared version)", read)
	}
	// The same set again, in another order, changes nothing.
	if res := l.setKube(KubeWarmDepth{Image: "alpine:3.20", Runtime: "gvisor", Depth: 1}, KubeWarmDepth{Image: "python:3.12", Runtime: "gvisor", Depth: 3}).(kubeWarmApplyResult); res.Changed {
		t.Fatal("the same set changed something")
	}
	if !l.read(2).Unchanged {
		t.Fatal("a reader at the version must get Unchanged")
	}
	// A smaller set replaces it: what it leaves out is gone.
	l.setKube(KubeWarmDepth{Image: "python:3.12", Runtime: "runc", Depth: 1})
	if read := l.read(2); read.Unchanged || len(read.Kube) != 1 || read.Kube[0].Runtime != "runc" || len(read.Pools) != 1 {
		t.Fatalf("after a replace = %+v", read)
	}
	l.setKube()
	if read := l.read(0); len(read.Kube) != 0 || len(read.Pools) != 1 {
		t.Fatalf("an empty set = %+v; the operator's entries stay", read)
	}
}

func TestFSMKubeWarmDepthsRefusals(t *testing.T) {
	tooMany := make([]KubeWarmDepth, maxKubeWarmDepths+1)
	for i := range tooMany {
		tooMany[i] = KubeWarmDepth{Image: "img-" + strconv.Itoa(i), Runtime: "gvisor", Depth: 1}
	}
	for name, set := range map[string][]KubeWarmDepth{
		"no image":      {{Runtime: "gvisor", Depth: 1}},
		"no runtime":    {{Image: "a", Depth: 1}},
		"depth 0":       {{Image: "a", Runtime: "gvisor"}},
		"depth too big": {{Image: "a", Runtime: "gvisor", Depth: models.MaxWarmPoolDepth + 1}},
		"twice":         {{Image: "a", Runtime: "gvisor", Depth: 1}, {Image: "a", Runtime: "gvisor", Depth: 2}},
		"too many":      tooMany,
	} {
		l := newWarmPoolLog(t)
		l.setKube(KubeWarmDepth{Image: "kept", Runtime: "gvisor", Depth: 1})
		if err := asApplyErr(l.setKube(set...)); !errors.Is(err, ErrKubeWarmDepths) {
			t.Errorf("%s = %v", name, err)
		}
		if read := l.read(0); len(read.Kube) != 1 || read.Kube[0].Image != "kept" {
			t.Errorf("%s: a refused set changed the held one: %+v", name, read.Kube)
		}
	}
}

func TestFSMKubeWarmDepthsSnapshotRestore(t *testing.T) {
	l := newWarmPoolLog(t)
	l.setKube(KubeWarmDepth{Image: "python:3.12", Runtime: "gvisor", Depth: 2})
	snap, err := l.fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatal(err)
	}
	if read := restored.readWarmPools(WarmPoolReadRequest{}); len(read.Kube) != 1 || read.Kube[0].Depth != 2 {
		t.Fatalf("restored = %+v", read)
	}
	// The log after the snapshot applies on top.
	data, _ := encodeCommand(command{Op: opSetKubeWarmDepths, KubeWarm: []KubeWarmDepth{{Image: "python:3.12", Runtime: "gvisor", Depth: 4}}})
	if res, ok := restored.Apply(&raft.Log{Index: 2, Data: data}).(kubeWarmApplyResult); !ok || !res.Changed {
		t.Fatalf("apply after restore = %+v", res)
	}
	// A snapshot from before the op restores to none.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(fsmSnapshotPayload{Version: 7}); err != nil {
		t.Fatal(err)
	}
	if err := restored.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatal(err)
	}
	if len(restored.kubeWarm) != 0 {
		t.Fatalf("an old snapshot left %+v", restored.kubeWarm)
	}
	// A bad set in a snapshot is dropped, never half-loaded.
	restored.restoreKubeWarmLocked([]KubeWarmDepth{{Image: "a", Runtime: "gvisor", Depth: 0}})
	if restored.kubeWarm != nil {
		t.Fatal("a bad set restored")
	}
}

// The leader writes the set once every Raft server applies the op, and
// refuses a bad one before proposing it.
func TestKubeWarmWritesGate(t *testing.T) {
	c, cleanup := newTestCluster(t, "kw-gate-a", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	write := func(depths ...KubeWarmDepth) (WarmPoolWriteResponse, error) {
		return c.WriteWarmPool(ctx, WarmPoolWriteRequest{Kube: &KubeWarmSet{Depths: depths}})
	}
	set := KubeWarmDepth{Image: "python:3.12", Runtime: "gvisor", Depth: 2}
	if resp, err := write(set); err != nil || !resp.Changed {
		t.Fatalf("a one-server cluster: %+v %v", resp, err)
	}
	if resp, err := write(set); err != nil || resp.Changed {
		t.Fatalf("the same set again: %+v %v", resp, err)
	}
	if _, err := write(KubeWarmDepth{Image: "", Runtime: "gvisor", Depth: 1}); !errors.Is(err, ErrKubeWarmDepths) {
		t.Fatalf("a bad set = %v", err)
	}
	if err := c.raft.raft.AddNonvoter("kw-gate-b", "127.0.0.1:1", 0, 0).Error(); err != nil {
		t.Fatal(err)
	}
	c.gossip.currentMemberIndex().upsert(Member{NodeID: "kw-gate-b", Alive: false, FSMOpsVersion: kubeWarmFSMOpsVersion - 1})
	if _, err := write(); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("a server on the previous build = %v", err)
	}
	if read, _ := c.ReadWarmPools(ctx, WarmPoolReadRequest{}); len(read.Kube) != 1 {
		t.Fatalf("a refused write changed the set: %+v", read.Kube)
	}
	if kubeWarmFSMOpsVersion > fsmOpsVersion {
		t.Fatal("this build must advertise the version its own op needs")
	}
}
