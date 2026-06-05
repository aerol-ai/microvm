package firecracker

import (
	"context"
	"errors"
	"github.com/aerol-ai/microvm/pkg/firecracker"
	"strings"
	"testing"
)

type dummyClient struct {
	fakeClient
	infoErr error
}

func (c *dummyClient) InstanceInfo(ctx context.Context) (*firecracker.InstanceInfo, error) {
	if c.infoErr != nil {
		return nil, c.infoErr
	}
	return &firecracker.InstanceInfo{State: "Paused"}, nil
}

func TestDriver_ExtraCoverage(t *testing.T) {
	d := New(Config{}, nil)

	// Inspect missing
	state, err := d.Inspect(context.Background(), "no-exist")
	if err != nil || state != nil {
		t.Errorf("expected nil, nil for missing Inspect, got %v, %v", state, err)
	}

	client := &dummyClient{infoErr: errors.New("info error")}
	d.mu.Lock()
	d.clients["test-sb"] = client
	d.mu.Unlock()

	// Inspect error
	if _, err := d.Inspect(context.Background(), "test-sb"); err == nil || !strings.Contains(err.Error(), "info error") {
		t.Errorf("expected info error, got %v", err)
	}

	// ListManaged with error logs and continues
	client2 := &dummyClient{infoErr: nil}
	d.mu.Lock()
	d.clients["test-sb2"] = client2
	d.mu.Unlock()

	states, err := d.ListManaged(context.Background())
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(states) != 1 {
		t.Errorf("expected 1 state, got %d", len(states))
	}
	if states["test-sb2"] == nil || states["test-sb2"].Status != "stopped" {
		t.Errorf("expected stopped state for test-sb2, got %v", states["test-sb2"])
	}
}
