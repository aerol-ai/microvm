package runloop

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
)

// A devbox that stops while an exec is being submitted (the toolbox took the
// command, then the sandbox went away before it answered) ends the submit at
// once with 409 "devbox is not running", not a gateway error once the
// connection times out. The command may have run, so its claim stays, and a
// retry of the same command id never runs it again.
func TestExecSubmitEndsWhenDevboxStops(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	ctx := context.Background()
	// The toolbox takes the command, then the sandbox dies: from that
	// moment no request is answered, ever (a real dead sandbox's address
	// goes silent). Without this the fake would keep answering, and the
	// facade's lost-reply check (getSession) could find the command and
	// rightly report the submit as done.
	submitted := make(chan struct{})
	var dead atomic.Bool
	var once sync.Once
	env.toolbox.setBeforeServe(func(r *http.Request) {
		if dead.Load() {
			// Consume the body so the client hanging up ends r.Context().
			_, _ = io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			// The fake serves the request after this hook; nothing may run.
			env.toolbox.setFailNext(r.URL.Path, http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/exec") {
			once.Do(func() {
				env.toolbox.serveSession(httptest.NewRecorder(), r, strings.TrimPrefix(r.URL.Path, "/process/session/"))
				dead.Store(true)
				close(submitted)
				<-r.Context().Done()
				env.toolbox.setFailNext(r.URL.Path, http.StatusServiceUnavailable)
			})
		}
	})

	errc := make(chan error, 1)
	go func() {
		_, err := env.h.startExecution(ctx, devbox.ID, "echo side-effect", "", "dies")
		errc <- err
	}()
	select {
	case <-submitted:
	case <-time.After(5 * time.Second):
		t.Fatal("the command never reached the toolbox")
	}
	if _, err := env.svc.StopSandbox(ctx, devbox.ID); err != nil {
		t.Fatalf("StopSandbox: %v", err)
	}
	var err error
	select {
	case err = <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("the submit is still waiting on a stopped devbox")
	}
	if !errors.Is(err, service.ErrSandboxNotRunning) {
		t.Fatalf("submit = %v, want the devbox-stopped error", err)
	}
	rec := httptest.NewRecorder()
	writeStoreAwareError(nil, rec, err)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "devbox is not running") {
		t.Fatalf("answered %d %s, want 409 devbox is not running", rec.Code, rec.Body.String())
	}

	ref := execRef{session: plainSession(devbox.ID, "dies")}
	if _, err := env.svc.GetIdempotentRequest(ctx, service.ExecLedgerScope, ledgerKey(devbox.ID, ref)); err != nil {
		t.Fatalf("the claim of a command that may have run was dropped: %v", err)
	}
	if _, err := env.h.startExecution(ctx, devbox.ID, "echo side-effect", "", "dies"); err == nil {
		t.Fatal("a retry on the stopped devbox succeeded")
	}
	if got := env.toolbox.execCount(); got != 1 {
		t.Fatalf("the command ran %d times; want 1", got)
	}
}
