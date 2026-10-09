package gatewayd

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// operatorPoll is how often a changed operator file is noticed without a
// SIGHUP; the same as sandboxd's. Tests shorten it so a reload is observable
// without waiting out the production interval.
var operatorPoll = 10 * time.Second

// fromOperatorFile builds the dial guard and the upstream chain from path
// (tests; the gateway itself watches the file, fromOperator).
func fromOperatorFile(path string) (egresspolicy.DialGuard, *egresspolicy.Upstream, error) {
	return fromOperator(path, operator.NewWatcher(path, nil, nil))
}

// fromOperator builds the dial guard and the upstream chain from the watched
// file. Without an operator file the guard is the zero value (the
// container-gateway posture, §5.5) and there is no upstream. The private-cloud
// operator file (§5.10) adds the internal zone, the deny floor and the
// upstream proxy; a file that is missing or invalid at start, or an upstream
// whose credentials can't be read, stops the gateway rather than running it
// without them.
func fromOperator(path string, w *operator.Watcher) (egresspolicy.DialGuard, *egresspolicy.Upstream, error) {
	if path == "" {
		return egresspolicy.DialGuard{}, nil, nil
	}
	if err := w.BootError(); err != nil {
		return egresspolicy.DialGuard{}, nil, err
	}
	op := w.Current()
	if op == nil {
		return egresspolicy.DialGuard{}, nil, fmt.Errorf("egress operator file %s: %w", path, fs.ErrNotExist)
	}
	up, err := op.UpstreamDialer()
	if err != nil {
		return egresspolicy.DialGuard{}, nil, err
	}
	return op.Guard(), up, nil
}

// reloadOnHUP reloads the operator file on SIGHUP.
func reloadOnHUP(ctx context.Context, w *operator.Watcher) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			_ = w.Reload()
		}
	}
}
