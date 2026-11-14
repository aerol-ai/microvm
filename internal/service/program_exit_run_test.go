package service

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Review 2 finding 10 (#940, destroy after exit): an exit read from one run
// of a sandbox must not land on the next run.

type review923ExitResponse struct {
	entered chan struct{}
	release chan struct{}
}

func (r *review923ExitResponse) RoundTrip(req *http.Request) (*http.Response, error) {
	close(r.entered)
	<-r.release
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"main_program":{"state":"exited","exit_code":0}}`))}, nil
}

// TestReview923OldExitResponseMustNotApplyToRestartedProgram is the
// reviewer's reproducer for finding 10, moved from
// review_923_regression_test.go as it was. Run A's /health reply says
// "exited" but comes back only after the sandbox was stopped and started as
// run B. Before, the store wrote it by id alone and run B was marked exited
// (and destroy_after_exit_for could delete it while it ran). Now the write
// needs the run the probe read the row in (run_generation).
func TestReview923OldExitResponseMustNotApplyToRestartedProgram(t *testing.T) {
	h := newExitHarness(t)
	ctx := context.Background()
	h.seed(t, "sb-old-exit", models.SandboxStatusStarted, models.RuntimeDocker, time.Second, nil)
	response := &review923ExitResponse{entered: make(chan struct{}), release: make(chan struct{})}
	h.svc.programExitHTTP = &http.Client{Transport: response}
	old, _ := h.st.Get(ctx, "sb-old-exit")
	done := make(chan struct{})
	go func() { h.svc.probeProgramExit(ctx, old); close(done) }()
	<-response.entered
	if _, err := h.svc.StopSandbox(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.StartSandbox(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	close(response.release)
	<-done
	current, _ := h.st.Get(ctx, old.ID)
	if current.ProgramExitedAt != nil {
		t.Fatal("previous run's delayed health response marked the newly started program exited")
	}
}
