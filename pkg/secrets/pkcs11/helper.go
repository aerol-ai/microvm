package pkcs11

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// parentPoll is how often the helper checks that sandboxd is still alive.
const parentPoll = time.Second

// RunHelper is `sandboxd --pkcs11-helper`: it opens the token and serves the
// socket until sandboxd exits or signals it. args are what ExecStarter
// passes.
func RunHelper(args []string) error {
	return runHelper(args, openBackend)
}

func runHelper(args []string, open func(TokenConfig) (closingBackend, error)) error {
	fs := flag.NewFlagSet(HelperFlag, flag.ContinueOnError)
	socket := fs.String("socket", "", "Unix socket to serve")
	parent := fs.Int("parent", 0, "exit when this process is gone")
	var cfg TokenConfig
	fs.StringVar(&cfg.Module, "module", "", "")
	fs.StringVar(&cfg.TokenLabel, "token-label", "", "")
	fs.StringVar(&cfg.PINFile, "pin-file", "", "")
	fs.StringVar(&cfg.KeyLabel, "key-label", "", "")
	decrypt := fs.String("decrypt-key-labels", "", "")
	fs.StringVar(&cfg.IVMode, "gcm-iv", IVAuto, "")
	fs.IntVar(&cfg.Sessions, "sessions", 1, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *socket == "" {
		return errors.New("pkcs11 helper: --socket is required")
	}
	for _, l := range strings.Split(*decrypt, ",") {
		if l = strings.TrimSpace(l); l != "" {
			cfg.DecryptLabels = append(cfg.DecryptLabels, l)
		}
	}
	b, err := open(cfg)
	if err != nil {
		return fmt.Errorf("pkcs11 helper: %w", err)
	}
	defer b.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if *parent > 0 {
		go watchParent(ctx, cancel, *parent)
	}
	ln, err := listen(*socket)
	if err != nil {
		return err
	}
	return serve(ctx, ln, b)
}

// listen serves on a socket only its owner can use. sandboxd made the
// directory 0700 before starting the helper, so no other user reaches the
// socket even before the chmod.
func listen(path string) (net.Listener, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 helper: listen %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("pkcs11 helper: chmod %s: %w", path, err)
	}
	return ln, nil
}

// watchParent ends the helper when sandboxd is gone (re-parented), so a
// crashed daemon never leaves a logged-in helper behind.
func watchParent(ctx context.Context, cancel context.CancelFunc, parent int) {
	t := time.NewTicker(parentPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if os.Getppid() != parent {
				cancel()
				return
			}
		}
	}
}

// closingBackend is a backend the helper closes on exit.
type closingBackend interface {
	backend
	Close()
}
