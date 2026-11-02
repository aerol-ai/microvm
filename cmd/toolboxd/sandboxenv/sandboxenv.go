// Package sandboxenv holds the environment a sandbox was created with, for a
// guest whose agent cannot inherit it.
//
// A container runtime starts toolboxd with the sandbox's env already in its
// own process environment, so every exec, session and terminal inherits it
// through os.Environ(). A Firecracker guest boots from a rootfs or a template
// snapshot that never saw the create request, so the host pushes the env over
// vsock once the agent is up (the set_env op) and toolboxd keeps it here.
//
// The env is how users pass secrets, so this package keeps it in memory only:
// nothing here writes it to a file or logs it, and errors never quote a key
// or a value. toolboxd is PID 1 in a Firecracker guest (toolboxd-init execs
// it), so there is no in-guest restart that could come back without it: if
// toolboxd exits the guest kernel panics and the VM is gone.
package sandboxenv

import (
	"errors"
	"maps"
	"sort"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/cmd/toolboxd/loginshell"
)

// ErrInvalid is returned for an env the guest cannot apply: an empty key, or
// a key or value the kernel's environ format cannot carry. The message names
// neither the key nor the value, since either could be a secret pasted into
// the wrong field.
var ErrInvalid = errors.New("sandbox env has an empty key, a key containing '=', or a NUL byte")

// Validate reports whether env can be laid over a process environment. Keys
// may not be empty or contain '=' (the environ separator); neither keys nor
// values may contain NUL (the environ terminator).
func Validate(env map[string]string) error {
	for k, v := range env {
		if k == "" || strings.ContainsAny(k, "=\x00") || strings.ContainsRune(v, 0) {
			return ErrInvalid
		}
	}
	return nil
}

// Store is the sandbox env of one guest. The zero value is an empty store,
// ready to use. Safe for concurrent use: Replace swaps the whole map under
// the lock, so a reader sees either the old env or the new one, never half.
type Store struct {
	mu  sync.RWMutex
	env map[string]string // never mutated after Replace stores it
}

// Replace sets the sandbox env to exactly env, dropping any key the previous
// env had and env does not. Replace, not merge, is what makes a re-delivered
// push converge: sending the same env twice leaves the store as one push
// did, and a retried push after a lost ack cannot append duplicates.
// It reports whether the env changed.
func (s *Store) Replace(env map[string]string) (bool, error) {
	if err := Validate(env); err != nil {
		return false, err
	}
	var next map[string]string
	if len(env) > 0 {
		next = maps.Clone(env)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if maps.Equal(s.env, next) {
		return false, nil
	}
	s.env = next
	return true, nil
}

// Len is the number of keys in the sandbox env.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.env)
}

// Environ lays the sandbox env over base (a process environment, normally
// os.Environ()) and returns a new slice; base is not modified.
//
// The precedence is the container one: the image's env, then the sandbox
// env, then whatever a request adds on top (callers append per-request env
// after this, and os/exec keeps the last value of a repeated key). A key the
// sandbox env sets is dropped from base rather than repeated, so a child's
// /proc/<pid>/environ shows each key once. A sandbox env that sets PATH also
// sets the PATH login shells put back (loginshell.Env), as a container
// started with that PATH records it.
func (s *Store) Environ(base []string) []string {
	s.mu.RLock()
	env := s.env
	s.mu.RUnlock()
	if len(env) == 0 {
		return append([]string(nil), base...)
	}
	extra := loginshell.EnvFor(env)
	out := make([]string, 0, len(base)+len(env)+len(extra))
	for _, kv := range base {
		key, _, _ := strings.Cut(kv, "=")
		if _, ok := env[key]; ok {
			continue
		}
		if key == loginshell.Env && len(extra) > 0 {
			continue
		}
		out = append(out, kv)
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return append(out, extra...)
}
