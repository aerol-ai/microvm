package gate

// Regression tests from the gate-speed review (2026-11-21): the memo's
// answer for a container must not outlive a delete of it, and a delete of
// one container must not keep the answers of checks of others out.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// specmemo.go: "A Containers.Delete drops the ID's entry, and a check that
// began before any delete does not put its answer in after it, so an
// entry never outlives a delete of its container." The drop runs when the
// gate checks the delete, before containerd acts on it; a Tasks.Create
// checked in between reads the still-stored record and puts its answer
// back, and the entry then outlives the container.
func TestReviewMemoEntryOutlivesDelete(t *testing.T) {
	r := newRig(t, testPolicy())
	c := goodContainer(t)
	if _, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: c}); err != nil {
		t.Fatal(err)
	}
	stored := true
	var mu sync.Mutex
	r.fake.on("/containerd.services.containers.v1.Containers/Get", func(context.Context, proto.Message) ([]proto.Message, error) {
		mu.Lock()
		defer mu.Unlock()
		if !stored {
			return nil, status.Error(codes.NotFound, "gone")
		}
		return []proto.Message{&containersapi.GetContainerResponse{Container: c}}, nil
	})
	inDelete := make(chan struct{})
	finish := make(chan struct{})
	r.fake.on(cDelete, func(context.Context, proto.Message) ([]proto.Message, error) {
		close(inDelete)
		<-finish
		mu.Lock()
		stored = false
		mu.Unlock()
		return []proto.Message{&emptypb.Empty{}}, nil
	})
	delErr := make(chan error, 1)
	go func() {
		_, err := r.invoke(nsCtx(), cDelete, &containersapi.DeleteContainerRequest{ID: testID})
		delErr <- err
	}()
	<-inDelete // the gate has checked (and dropped) the delete; containerd is deleting
	task := &tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: overlayRootfs()}
	_, _ = r.invoke(nsCtx(), tCreate, task)
	close(finish)
	if err := <-delErr; err != nil {
		t.Fatal(err)
	}
	if facts, _ := r.gate.specs.get(testID, sha256.Sum256(c.GetSpec().GetValue())); facts != nil {
		t.Fatalf("the memo holds %s's spec after containerd deleted it (%d entries)", testID, r.gate.specs.entries())
	}
}

// A global delete counter: any delete, of any container, voids every
// check in flight. An agent that deletes (even unknown IDs) keeps the memo
// empty; normal churn costs hits. Hit-rate only, never a wrong answer.
func TestReviewMemoVoidedByUnrelatedDelete(t *testing.T) {
	raw := specBytes(t, testID, nil)
	sum := sha256.Sum256(raw)
	m2 := newSpecMemo(testPolicy(), 8, memoEntryBytes)
	_, drops := m2.get(testID, sum)
	facts, err := rootpolicy.CheckSpecFacts(m2.policy, testID, raw) // the in-flight decode
	if err != nil || facts == nil {
		t.Fatal(err)
	}
	m2.drop("some-other-container")
	m2.put(testID, sum, facts, drops)
	if m2.entries() != 1 {
		t.Fatalf("a delete of another container voided %s's answer (%d entries)", testID, m2.entries())
	}
}

// TestSpecMemoInflightEnds: the per-ID record of checks in flight lives
// only while one runs, whatever the check's outcome (kept, refused, too
// big to keep, voided by a delete), and a delete of an ID with no check in
// flight leaves none behind.
func TestSpecMemoInflightEnds(t *testing.T) {
	m := newSpecMemo(testPolicy(), 2, memoEntryBytes)
	good := specBytes(t, testID, nil)
	big := specBytes(t, testID, func(s *specs.Spec) {
		for i := range 200 {
			withBind(fmt.Sprintf("mount-%03d", i))(s)
		}
	})
	for _, raw := range [][]byte{good, specBytes(t, testID, noSeccomp), big, good} {
		_, _ = m.check(testID, raw)
	}
	_, gen := m.get("sb-2", sha256.Sum256(good))
	m.drop("sb-2")
	m.put("sb-2", sha256.Sum256(good), &rootpolicy.SpecFacts{}, gen)
	for i := range 10 {
		m.drop(fmt.Sprintf("never-made-%d", i))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.inflight) != 0 {
		t.Fatalf("%d IDs still counted as decoding", len(m.inflight))
	}
}
