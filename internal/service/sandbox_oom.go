package service

import (
	"expvar"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// An "oom" event is not an exit.
//
// Docker's "oom" and containerd's /tasks/oom both fire when the kernel
// OOM-kills ANY process in the container's cgroup: containerd's shim
// publishes TaskOOM whenever the cgroup's memory.events oom_kill counter goes
// up (containerd pkg/oom/v2), and Docker relays it as "oom". A command run in
// a sandbox that outgrows the sandbox's memory is killed on its own; the
// sandbox, its init and toolboxd keep running. The event handler used to run
// the stop path on it: the row went to stopped (every later call answered
// "sandbox is not running"), the admitter slot and the routes were released,
// and the sandbox's egress enforcement (block-all, CIDR rules, the hostname
// allowlist) was removed from a sandbox that was still running. Any tenant
// could open its own egress with a memory spike.
//
// So an oom event only records that it happened. When the sandbox's init is
// the process killed, the container exits and its die event (TaskExit of the
// init) runs the stop path as for any exit; that die is then known to be an
// OOM kill (the row's last error says so, and the stop is involuntary however
// it was requested). The events arrive in either order: a die that comes
// before its oom event is recorded with its exit code.

// oomExitWindow is how long an oom event explains a following exit. The
// kernel counts the kill and the init exits at the same moment, so the two
// events arrive within milliseconds; the window allows for a loaded node
// without letting a child's OOM long ago label a later, unrelated exit.
const oomExitWindow = 30 * time.Second

// sandboxOOMEventsTotal counts oom events for managed sandboxes: processes
// OOM-killed inside a sandbox, whether or not the sandbox exited after.
var sandboxOOMEventsTotal = expvar.NewInt("aerolvm_sandbox_oom_events_total")

// sandboxOOMTracker remembers each sandbox's latest oom event for
// oomExitWindow. The zero value is ready: tests build &Service{} directly.
type sandboxOOMTracker struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time // test seam; nil means time.Now
}

func (t *sandboxOOMTracker) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// note records an oom event for id now, and drops entries past the window
// so the map holds only recent OOMs.
func (t *sandboxOOMTracker) note(id string) {
	now := t.clock()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen == nil {
		t.seen = make(map[string]time.Time)
	}
	for other, at := range t.seen {
		if now.Sub(at) > oomExitWindow {
			delete(t.seen, other)
		}
	}
	t.seen[id] = now
}

// take reports whether id had an oom event within the window, and forgets it.
func (t *sandboxOOMTracker) take(id string) bool {
	now := t.clock()
	t.mu.Lock()
	defer t.mu.Unlock()
	at, ok := t.seen[id]
	delete(t.seen, id)
	return ok && now.Sub(at) <= oomExitWindow
}

// forget drops id's record: the sandbox started again or is gone.
func (t *sandboxOOMTracker) forget(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.seen, id)
}

// noteSandboxOOM handles an oom event: record it, count it, log it, and
// change nothing else. The row, the warm cache, the admitter slot, the
// routes, the egress rules and in-flight toolbox requests are left as they
// are, because the sandbox may well be running.
func (s *Service) noteSandboxOOM(sandbox *models.Sandbox) {
	s.sandboxOOMs.note(sandbox.ID)
	sandboxOOMEventsTotal.Add(1)
	if s.logger != nil {
		s.logger.Warn("a process in the sandbox was OOM-killed; the sandbox is stopped only if it exits",
			"sandbox_id", sandbox.ID, "memory_mb", sandbox.MemoryMB, "status", string(sandbox.Status))
	}
}
