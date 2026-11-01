package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

// TestPrepareBlockSets: a disabled manager has nothing to prepare; one whose
// backend has no sets stays on the per-address rules and is reported as
// served (its prepare is a no-op, not a failure).
func TestPrepareBlockSets(t *testing.T) {
	if prepareBlockSets(nil, "x", testLogger()) {
		t.Fatal("nil manager prepared")
	}
	off, _ := netrules.New(false)
	if prepareBlockSets(off, "x", testLogger()) {
		t.Fatal("disabled manager prepared")
	}
	on := netrules.NewWithBackend(noopRuleBackend{})
	if !prepareBlockSets(on, "x", testLogger()) {
		t.Fatal("enabled manager not prepared")
	}
}

// TestStartBlockSetReassert: the loop ticks and stops; a nil manager is a
// no-op.
func TestStartBlockSetReassert(t *testing.T) {
	old := blockSetReassertInterval
	blockSetReassertInterval = 5 * time.Millisecond
	defer func() { blockSetReassertInterval = old }()
	startBlockSetReassert(context.Background(), nil, testLogger())()
	stop := startBlockSetReassert(context.Background(), netrules.NewWithBackend(noopRuleBackend{}), testLogger())
	time.Sleep(30 * time.Millisecond)
	stop()
}

type noopRuleBackend struct{}

func (noopRuleBackend) Exists(string, string, ...string) (bool, error) { return false, nil }
func (noopRuleBackend) Insert(string, string, int, ...string) error    { return nil }
func (noopRuleBackend) Delete(string, string, ...string) error         { return nil }
