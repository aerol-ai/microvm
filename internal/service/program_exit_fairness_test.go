package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Review 2 finding 11 (#940, destroy after exit): the bounded exit probes
// must reach every sandbox eventually, whatever the agents ahead of it do
// (sweep_rotation.go).

type review923ExitTransport struct{ tail atomic.Int32 }

func (r *review923ExitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Hostname() == "192.0.2.99" {
		r.tail.Add(1)
		return nil, errors.New("tail reached")
	}
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// TestReview923ExitProbeMustEventuallyReachTail is the reviewer's
// reproducer for finding 11, moved from review_923_regression_test.go as it
// was: 40 rows whose agent never answers ahead of one that does.
func TestReview923ExitProbeMustEventuallyReachTail(t *testing.T) {
	h := newExitHarness(t)
	transport := &review923ExitTransport{}
	h.svc.programExitHTTP = &http.Client{Transport: transport}
	var rows []*models.Sandbox
	for i := 0; i < 40; i++ {
		rows = append(rows, &models.Sandbox{ID: "blocked", Status: models.SandboxStatusStarted, ContainerIP: "192.0.2.1", Lifecycle: models.Lifecycle{DestroyAfterExitFor: time.Second}})
	}
	rows = append(rows, &models.Sandbox{ID: "tail", Status: models.SandboxStatusStarted, ContainerIP: "192.0.2.99", Lifecycle: models.Lifecycle{DestroyAfterExitFor: time.Second}})
	for i := 0; i < 2; i++ {
		h.svc.probeProgramExits(context.Background(), rows)
	}
	if transport.tail.Load() == 0 {
		t.Fatal("healthy tail never probed across repeated sweeps")
	}
}

// probeCounter answers for one address and blocks (or fails) the rest,
// counting the asks per address.
type probeCounter struct {
	healthy string
	fast    bool // the others fail at once instead of hanging
	mu      sync.Mutex
	asks    map[string]int
}

func (p *probeCounter) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	p.mu.Lock()
	p.asks[host]++
	p.mu.Unlock()
	if host == p.healthy {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"main_program":{"state":"running"}}`))}, nil
	}
	if p.fast {
		return nil, errors.New("connection refused")
	}
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func (p *probeCounter) count(host string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.asks[host]
}

// probeRows is 40 sandboxes with distinct agents that do not answer, newest
// first as the store lists them, and an older one whose agent answers.
func probeRows() []*models.Sandbox {
	var rows []*models.Sandbox
	for i := 0; i < 40; i++ {
		rows = append(rows, &models.Sandbox{ID: fmt.Sprintf("dead-%02d", i), Status: models.SandboxStatusStarted,
			ContainerIP: fmt.Sprintf("192.0.2.%d", i+1), Lifecycle: models.Lifecycle{DestroyAfterExitFor: time.Minute}})
	}
	return append(rows, &models.Sandbox{ID: "healthy", Status: models.SandboxStatusStarted,
		ContainerIP: "198.51.100.7", Lifecycle: models.Lifecycle{DestroyAfterExitFor: time.Minute}})
}

// TestProgramExitProbesRotatePastAgentsThatNeverAnswer: 40 distinct agents
// that hang until the pass's deadline, ahead of a healthy one. Each pass has
// room for 8 asks; the healthy sandbox is asked by pass 6 (ceil(40/8) + 1).
// Before, every pass asked the same first 8 and it was never asked. The
// asks the deadline cut short are not counted against the agents.
func TestProgramExitProbesRotatePastAgentsThatNeverAnswer(t *testing.T) {
	h := newExitHarness(t)
	probes := &probeCounter{healthy: "198.51.100.7", asks: map[string]int{}}
	h.svc.programExitHTTP = &http.Client{Transport: probes}
	rows := probeRows()
	pass := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
		h.svc.probeProgramExits(ctx, rows)
		cancel()
	}
	// Passes 1-5 ask the 40 dead agents, 8 a pass, each once.
	for i := 0; i < 5; i++ {
		pass()
	}
	for i := 0; i < 40; i++ {
		if n := probes.count(fmt.Sprintf("192.0.2.%d", i+1)); n != 1 {
			t.Fatalf("dead agent %d asked %d times in 5 passes, want once", i, n)
		}
	}
	if n := probes.count("198.51.100.7"); n != 0 {
		t.Fatalf("the healthy sandbox was asked %d times before the dead agents ahead of it", n)
	}
	// Pass 6: never asked, so it goes first.
	pass()
	if n := probes.count("198.51.100.7"); n != 1 {
		t.Fatalf("the healthy sandbox was asked %d times in pass 6, want once", n)
	}
	h.svc.programExitRotation.mu.Lock()
	failures := h.svc.programExitRotation.records["dead-00"].failures
	h.svc.programExitRotation.mu.Unlock()
	if failures != 0 {
		t.Fatalf("an ask the pass deadline cut short counted as %d failures", failures)
	}
}

// TestProgramExitProbesBackOffAgentsThatFail: an agent that fails is asked
// less and less often (passes 1, 2, 4, 8), while one that answers is asked
// every pass.
func TestProgramExitProbesBackOffAgentsThatFail(t *testing.T) {
	h := newExitHarness(t)
	probes := &probeCounter{healthy: "198.51.100.7", fast: true, asks: map[string]int{}}
	h.svc.programExitHTTP = &http.Client{Transport: probes}
	rows := probeRows()
	for pass := 0; pass < 8; pass++ {
		h.svc.probeProgramExits(context.Background(), rows)
	}
	if n := probes.count("198.51.100.7"); n != 8 {
		t.Fatalf("the answering agent was asked %d times in 8 passes, want 8", n)
	}
	if n := probes.count("192.0.2.1"); n != 4 {
		t.Fatalf("a failing agent was asked %d times in 8 passes, want 4", n)
	}
}
