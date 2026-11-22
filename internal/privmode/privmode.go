// Package privmode is sandboxd's privilege mode (plans/security-gaps-m1-m4.md
// §1 and §3.3, eng review D5 and D22): the lasting setting
// SB_PRIVILEGE_MODE=split|single.
//
//   - single is today's one process: sandboxd runs as root and does the
//     root work itself. It is the mode when the setting is absent, so an
//     agent that lands on a node set up before the setting existed (an
//     in-place agent upgrade onto an old pod) keeps working as it did.
//   - split runs sandboxd with no rights: the root helper (internal/rootd)
//     does the root work, reached over its socket (internal/rootclient).
//
// The split is built one step at a time (plan §3.5, M1 PRs 4 to 9). A step
// whose helper calls are not built yet fails in split mode with a Gap that
// names it; it never falls back to doing the work as root. single is never
// touched by this package beyond its name.
package privmode

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Mode is a privilege mode.
type Mode string

const (
	Single Mode = "single"
	Split  Mode = "split"
)

// Parse reads SB_PRIVILEGE_MODE. Empty is single; anything but the two
// names is an error, never a guess: the setting decides whether tenant
// input is parsed as root.
func Parse(raw string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(raw))) {
	case "", Single:
		return Single, nil
	case Split:
		return Split, nil
	}
	return "", fmt.Errorf("SB_PRIVILEGE_MODE=%q: want split or single", raw)
}

// Step is root work split mode does through the helper, or does not yet.
type Step string

// The steps split mode does not cover yet, each with the helper calls it
// waits for (plan §3.5).
const (
	StepImageUser     Step = "image_user"
	StepDiskQuota     Step = "disk_quota"
	StepHostProcesses Step = "host_processes"
	StepContainerFile Step = "container_files"
	StepWarmPool      Step = "warm_pool"
	StepMoves         Step = "gvisor_moves"
)

// steps say what each step is, for the operator who meets the error.
var steps = map[Step]string{
	StepImageUser:     "reading an image's users from its root filesystem",
	StepDiskQuota:     "the disk quota on a sandbox's writable layer",
	StepHostProcesses: "the WASM, V8-isolate and Firecracker runtimes' host processes",
	StepContainerFile: "the files root opens for a container (host files, ready socket, task output, runsc config) and the containerd gate",
	StepWarmPool:      "the containerd warm pool's parked sandboxes",
	StepMoves:         "gVisor checkpoint moves",
}

// Gap is root work this build's split mode cannot do yet. It matches
// models.ErrRuntimeNotImplemented, so the API answers 501: the node's
// setting, not the request, and retrying will not help.
type Gap struct {
	Steps []Step
	// What is what was asked: a create, sandboxd's start.
	What string
}

// NotYet is the Gap for what, naming each step. Nil when there is none.
func NotYet(what string, s ...Step) error {
	if len(s) == 0 {
		return nil
	}
	return &Gap{Steps: s, What: what}
}

func (g *Gap) Error() string {
	var parts []string
	for _, s := range g.Steps {
		d := steps[s]
		if d == "" {
			d = string(s)
		}
		parts = append(parts, d)
	}
	return fmt.Sprintf("privilege mode split cannot %s yet: the root helper does not yet do %s; "+
		"run this node with SB_PRIVILEGE_MODE=single until it does", g.What, strings.Join(parts, "; "))
}

// Is matches ErrGap and models.ErrRuntimeNotImplemented.
func (g *Gap) Is(target error) bool {
	return target == ErrGap || target == models.ErrRuntimeNotImplemented
}

// ErrGap matches every Gap.
var ErrGap = errors.New("privilege mode split does not cover this yet")
