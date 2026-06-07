package main

// clonegen.go publishes a "clone generation" token the guest can read to
// detect that it was resumed from a snapshot — i.e. that it is a clone.
//
// Why this exists: a Firecracker snapshot-clone duplicates the whole VM
// memory image, including the seed state of every userspace PRNG inside a
// long-lived process (a preloaded `python` with `numpy`/`random` already
// imported is the canonical case). Two clones of the same template would
// then draw identical "random" streams. The kernel CSPRNG is force-reseeded
// on resume (see quiesce_linux.go), which covers every freshly-spawned
// process — but toolboxd is a *separate* process and cannot reach into a
// foreign heap to reseed an already-running interpreter's PRNG.
//
// The fix is cooperative: toolboxd changes this token on every post_resume,
// and a long-lived in-guest process reads it (via the well-known file or the
// GET /clone-generation endpoint) and reseeds its own PRNGs when the token
// changes. The token only needs to *change* on clone — it need not be
// globally unique, because the reseed itself pulls fresh entropy from the
// (already-reseeded) kernel, which is clone-distinct.

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// defaultCloneGenPath is the well-known file in-guest readers poll. It lives
// on tmpfs (/run) so reads are cheap and the value never outlives a boot.
const defaultCloneGenPath = "/run/aerolvm/clone-generation"

// cloneGeneration holds the current generation token. Safe for concurrent
// use: the post_resume handler bumps it while HTTP readers and in-guest
// pollers read it.
type cloneGeneration struct {
	mu        sync.RWMutex
	token     string
	resumedAt int64 // host wall-clock unix-ns of the last resume; 0 = never
	path      string
	logger    *slog.Logger
}

// newCloneGeneration seeds an initial token and writes it to path. The
// initial token is the baseline an in-guest process records at startup; it
// stays put until a post_resume bumps it, so a sandbox that is never cloned
// correctly reports "no clone." The file write is best-effort — a guest
// without a writable /run still serves the token over HTTP.
func newCloneGeneration(path string, logger *slog.Logger) *cloneGeneration {
	if logger == nil {
		logger = slog.Default()
	}
	if path == "" {
		path = defaultCloneGenPath
	}
	c := &cloneGeneration{
		token:  randomToken(),
		path:   path,
		logger: logger,
	}
	c.writeFile()
	return c
}

// bump rotates the token and records the resume time. Called from the vsock
// post_resume handler after the kernel RNG reseed. Last-writer-wins under
// the mutex; concurrent post_resume calls (the host sends at most one per
// resume) would simply leave the most recent token.
func (c *cloneGeneration) bump(resumedAtUnixNs int64) {
	c.mu.Lock()
	c.token = randomToken()
	c.resumedAt = resumedAtUnixNs
	c.mu.Unlock()
	c.writeFile()
}

// current returns the token and the last resume time for HTTP responses.
func (c *cloneGeneration) current() (token string, resumedAt int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token, c.resumedAt
}

// writeFile persists the current token to the well-known path. Best-effort:
// failures are logged at Debug and swallowed so a read-only/missing /run
// never breaks the sandbox — the HTTP endpoint remains the source of truth.
func (c *cloneGeneration) writeFile() {
	token, _ := c.current()
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		c.logger.Debug("clone-generation: mkdir failed", "path", c.path, "error", err)
		return
	}
	// Trailing newline so `cat` / shell `$(<file)` reads are clean.
	if err := os.WriteFile(c.path, []byte(token+"\n"), 0o644); err != nil {
		c.logger.Debug("clone-generation: write failed", "path", c.path, "error", err)
	}
}

// randomToken returns 16 bytes of crypto entropy as hex. crypto/rand reads
// the OS CSPRNG, which the resume path reseeds before bump() is ever called,
// so successive clones get distinct tokens.
func randomToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read effectively never fails on a booted Linux guest;
		// if it somehow does, fall back to an empty-but-distinct marker so
		// callers still see *a* value. The kernel reseed is the real
		// guarantee; this token is only a change signal.
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}
