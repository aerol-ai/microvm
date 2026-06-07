// Package clonegen publishes a monotonic "clone generation" token readers can
// poll to detect that a sandbox was resumed from a snapshot — i.e. that it is a
// clone. Shared between in-guest toolboxd (file + HTTP endpoint) and the WASM
// driver's checkpoint fencing (§4.8).
package clonegen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultPath is the well-known in-guest file pollers read. It lives on tmpfs
// (/run) so reads are cheap and the value never outlives a boot.
const DefaultPath = "/run/aerolvm/clone-generation"

// Generation holds the current generation token. Safe for concurrent use.
type Generation struct {
	mu        sync.RWMutex
	token     string
	resumedAt int64 // host wall-clock unix-ns of the last resume; 0 = never
	path      string
	logger    *slog.Logger
}

// New seeds an initial token and writes it to path. The initial token is the
// baseline an in-guest process records at startup; it stays put until Bump
// rotates it, so a sandbox that is never cloned correctly reports "no clone."
// The file write is best-effort — a guest without a writable /run still
// serves the token over HTTP.
func New(path string, logger *slog.Logger) *Generation {
	if logger == nil {
		logger = slog.Default()
	}
	if path == "" {
		path = DefaultPath
	}
	c := &Generation{
		token:  randomToken(0),
		path:   path,
		logger: logger,
	}
	c.writeFile(c.token)
	return c
}

// Bump rotates the token and records the resume time. Nil-safe.
func (c *Generation) Bump(resumedAtUnixNs int64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	nextToken := randomToken(resumedAtUnixNs)
	c.token = nextToken
	c.resumedAt = resumedAtUnixNs
	c.writeFileLocked(nextToken)
	c.mu.Unlock()
}

// Current returns the token and the last resume time. Nil-safe: a nil receiver
// reports the baseline "never cloned" state instead of panicking.
func (c *Generation) Current() (token string, resumedAt int64) {
	if c == nil {
		return "", 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token, c.resumedAt
}

func (c *Generation) writeFile(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeFileLocked(token)
}

func (c *Generation) writeFileLocked(token string) {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		c.logger.Debug("clone-generation: mkdir failed", "path", c.path, "error", err)
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".clone-generation-*")
	if err != nil {
		c.logger.Debug("clone-generation: temp file create failed", "path", c.path, "error", err)
		return
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write([]byte(token + "\n")); err != nil {
		c.logger.Debug("clone-generation: temp write failed", "path", c.path, "error", err)
		return
	}
	if err := tmp.Chmod(0o644); err != nil {
		c.logger.Debug("clone-generation: temp chmod failed", "path", c.path, "error", err)
		return
	}
	if err := tmp.Close(); err != nil {
		c.logger.Debug("clone-generation: temp close failed", "path", c.path, "error", err)
		return
	}
	if err := os.Rename(tmpName, c.path); err != nil {
		c.logger.Debug("clone-generation: rename failed", "path", c.path, "error", err)
	}
}

var fallbackCounter atomic.Uint64

// RandRead is the entropy source for randomToken. Tests may replace it.
var RandRead = rand.Read

func randomToken(resumeUnixNs int64) string {
	var b [16]byte
	if _, err := RandRead(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d-%d-%d", resumeUnixNs, time.Now().UnixNano(), fallbackCounter.Add(1))
	}
	return hex.EncodeToString(b[:])
}
