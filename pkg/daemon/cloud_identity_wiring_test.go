package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

type fakeIdentityBootstrapper struct {
	failures int
	calls    int
}

func (f *fakeIdentityBootstrapper) EnsureIdentityKeysReady(context.Context) error {
	f.calls++
	if f.calls <= f.failures {
		return errors.New("no leader yet")
	}
	return nil
}

func TestBootstrapCloudIdentity(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	for _, tc := range []struct {
		name      string
		failures  int
		want      bool
		wantCalls int
	}{
		{"ready at once", 0, true, 1},
		{"ready after a leader election", 2, true, 3},
		{"never ready: the latch is left for the first caller", 100, false, cloudIdentityBootAttempts},
	} {
		f := &fakeIdentityBootstrapper{failures: tc.failures}
		if got := bootstrapCloudIdentity(ctx, f, logger, time.Microsecond); got != tc.want || f.calls != tc.wantCalls {
			t.Errorf("%s: ready=%v calls=%d, want %v %d", tc.name, got, f.calls, tc.want, tc.wantCalls)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	f := &fakeIdentityBootstrapper{failures: 100}
	if bootstrapCloudIdentity(cancelled, f, logger, time.Hour) || f.calls != 1 {
		t.Fatalf("a cancelled boot kept trying: calls=%d", f.calls)
	}
}

func TestWireCloudIdentityOffStartsNothing(t *testing.T) {
	// With no issuer URL nothing is touched, so a nil service is safe.
	wireCloudIdentity(context.Background(), config.Config{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
}
