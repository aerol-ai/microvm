package pkcs11

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// The helper protocol: one JSON request and one JSON reply per connection on
// a 0600 Unix socket (eng D5). One connection per call keeps a stuck call from
// blocking the next, and the helper's session pool, not the socket, bounds how
// many run at once.

// OpDeadline bounds every helper op. A vendor C_Encrypt can block inside the
// helper; past this deadline sandboxd kills and replaces the helper, which
// frees any session stuck in a C call (eng D25).
const OpDeadline = 5 * time.Second

// opDeadlineOverride, when set, replaces OpDeadline (tests only). Atomic
// because server goroutines read it while a test restores it.
var opDeadlineOverride atomic.Int64

func opDeadline() time.Duration {
	if d := opDeadlineOverride.Load(); d > 0 {
		return time.Duration(d)
	}
	return OpDeadline
}

const maxMessageBytes = 64 << 10

const (
	opWrap   = "wrap"
	opUnwrap = "unwrap"
	opPing   = "ping"
	opInfo   = "info"
)

type request struct {
	Op      string `json:"op"`
	Data    []byte `json:"data,omitempty"` // DEK (wrap) or wrapped key (unwrap)
	AAD     []byte `json:"aad,omitempty"`
	Timeout int64  `json:"timeout_ms,omitempty"`
}

type reply struct {
	Data  []byte `json:"data,omitempty"`
	Class string `json:"class,omitempty"` // "" = ok
	Error string `json:"error,omitempty"`
	Info  *Info  `json:"info,omitempty"`
}

// IV modes (SB_SECRET_PKCS11_GCM_IV).
const (
	IVAuto   = "auto"
	IVHSM    = "hsm"
	IVCaller = "caller"
)

// TokenConfig is the SB_SECRET_PKCS11_* settings, handed to the helper as
// flags so it never re-reads sandboxd's configuration.
type TokenConfig struct {
	Module        string
	TokenLabel    string
	PINFile       string
	KeyLabel      string
	DecryptLabels []string
	IVMode        string
	// Sessions is the session pool: the foreground cap plus the background
	// slots (eng D13), so background work never takes a session a create
	// needs.
	Sessions int
}

// Info describes the token the helper opened, for the hardware-slot rule and
// the custody report.
type Info struct {
	HardwareSlot  bool     `json:"hardware_slot"`
	TokenLabel    string   `json:"token_label"`
	Manufacturer  string   `json:"manufacturer"`
	Model         string   `json:"model"`
	KeyLabel      string   `json:"key_label"`
	DecryptLabels []string `json:"decrypt_labels,omitempty"`
	IVMode        string   `json:"iv_mode"`
}

// Error classes on the wire. They name the pkg/secrets sentinels, so a revoke
// in the helper is still a revoke in sandboxd.
var classes = []struct {
	name string
	err  error
}{
	{"revoked", secrets.ErrKeyRevoked},
	{"retired", secrets.ErrKeyVersionRetired},
	{"denied", secrets.ErrProviderDenied},
	{"throttled", secrets.ErrProviderThrottled},
	{"decrypt_failed", secrets.ErrDecryptFailed},
	{"unavailable", secrets.ErrProviderUnavailable},
}

func classOf(err error) string {
	for _, c := range classes {
		if errors.Is(err, c.err) {
			return c.name
		}
	}
	return "unavailable"
}

func errFromReply(r reply) error {
	if r.Class == "" {
		return nil
	}
	for _, c := range classes {
		if c.name == r.Class {
			return fmt.Errorf("%w: pkcs11 helper: %s", c.err, r.Error)
		}
	}
	return fmt.Errorf("%w: pkcs11 helper: %s", secrets.ErrProviderUnavailable, r.Error)
}

func readJSON(r io.Reader, v any) error {
	return json.NewDecoder(io.LimitReader(r, maxMessageBytes)).Decode(v)
}

// backend is what the helper serves: the HSM itself (token.go), or a fake in
// tests.
type backend interface {
	Wrap(ctx context.Context, dek, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
	Ping(ctx context.Context) error
	Info() Info
}

// serve answers requests on ln until ctx ends or ln closes.
func serve(ctx context.Context, ln net.Listener, b backend) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handle(ctx, conn, b)
	}
}

func handle(ctx context.Context, conn net.Conn, b backend) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opDeadline()))
	var req request
	if err := readJSON(conn, &req); err != nil {
		return
	}
	timeout := opDeadline()
	if req.Timeout > 0 && time.Duration(req.Timeout)*time.Millisecond < timeout {
		timeout = time.Duration(req.Timeout) * time.Millisecond
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var out reply
	var err error
	switch req.Op {
	case opWrap:
		out.Data, err = b.Wrap(cctx, req.Data, req.AAD)
	case opUnwrap:
		out.Data, err = b.Unwrap(cctx, req.Data, req.AAD)
	case opPing:
		err = b.Ping(cctx)
	case opInfo:
		info := b.Info()
		out.Info = &info
	default:
		err = fmt.Errorf("%w: unknown op %q", secrets.ErrProviderUnavailable, req.Op)
	}
	if err != nil {
		// The message names the op and the PKCS#11 return code; it never
		// carries key material.
		out = reply{Class: classOf(err), Error: err.Error()}
	}
	_ = json.NewEncoder(conn).Encode(out)
}
