package nodeops

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
)

// PodHost is Host in a Kubernetes server pod held in maintenance mode (C22,
// plans/kubernetes-v2-architecture.md §14). There is no systemd in a pod, so
// "is sandboxd running" cannot ask systemctl (SystemHost.UnitActive): it
// looks for the daemon's process directly. In maintenance mode the operator
// recreates the server's pod with its volume and a holding entrypoint in
// place of sandboxd, and a person runs `sandboxd backup`, `restore` or
// `recover-quorum` in it with `kubectl exec`.
//
// Stopping and starting are the operator's job there, by the
// aerolvm.io/maintenance annotation on the server's AerolNode, so StopUnit
// and StartUnit refuse with that instruction instead of doing anything.
type PodHost struct {
	nodeupgrade.SystemHost
	// ProcRoot is /proc; tests point it at a fake.
	ProcRoot string
	// Self is this process's PID, which never counts as the daemon.
	Self int
	// IsDaemon says whether a sandboxd command line runs the daemon. The
	// binary knows its own subcommands (cmd/sandboxd); nil counts only a
	// bare "sandboxd".
	IsDaemon func(argv []string) bool
}

var _ Host = (*PodHost)(nil)

// errPodUnit is StopUnit's and StartUnit's answer in a pod.
var errPodUnit = errors.New("in a Kubernetes pod sandboxd is stopped and started by maintenance mode: set (or remove) the annotation aerolvm.io/maintenance=true on this server's AerolNode, then run this again")

// NewPodHost is PodHost for this process.
func NewPodHost() *PodHost {
	return &PodHost{ProcRoot: "/proc", Self: os.Getpid()}
}

// UnitActive reports whether a sandboxd daemon runs in this pod: a process
// whose program is sandboxd and whose command line IsDaemon says runs the
// daemon. The tool asking (`sandboxd recover-quorum`, ...) has a
// subcommand, and so do sandboxd's own helper processes (`sandboxd
// --wasm-worker`), so neither counts.
func (h *PodHost) UnitActive(_ context.Context, unit string) bool {
	if unit != sandboxdUnit {
		return false
	}
	root := h.ProcRoot
	if root == "" {
		root = "/proc"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		// Unreadable /proc: say it runs, so a tool that must not race a
		// live daemon refuses rather than guesses.
		return true
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == h.Self {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, e.Name(), "cmdline"))
		if err != nil || len(raw) == 0 {
			continue // gone already, or a kernel thread
		}
		argv := bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0})
		if filepath.Base(string(argv[0])) != "sandboxd" {
			continue
		}
		args := make([]string, len(argv))
		for i, a := range argv {
			args[i] = string(a)
		}
		if h.IsDaemon != nil && h.IsDaemon(args) || h.IsDaemon == nil && len(args) == 1 {
			return true
		}
	}
	return false
}

// stopHint is how a person stops sandboxd in a pod.
const podStopHint = "put this server in maintenance mode: kubectl annotate aerolnode <this server> aerolvm.io/maintenance=true"

// StopHint says how to stop sandboxd here.
func (h *PodHost) StopHint() string { return podStopHint }

// StopUnit refuses: in a pod, maintenance mode stops sandboxd.
func (h *PodHost) StopUnit(context.Context, string) error { return errPodUnit }

// StartUnit refuses: in a pod, leaving maintenance mode starts sandboxd.
func (h *PodHost) StartUnit(context.Context, string) error { return errPodUnit }

// InPod reports whether these tools run in a Kubernetes container: kubelet
// gives every container KUBERNETES_SERVICE_HOST (kubectl exec keeps it), and
// a container has no systemd, which marks a booted system with
// /run/systemd/system (sd_booted(3)). No systemd alone is not enough: a
// plain container or a VM without systemd is not a server pod, and there
// the systemd host's errors say what is missing.
func InPod() bool {
	return inPod(os.Getenv, func(p string) error { _, err := os.Stat(p); return err })
}

func inPod(getenv func(string) string, stat func(string) error) bool {
	return getenv("KUBERNETES_SERVICE_HOST") != "" && stat("/run/systemd/system") != nil
}
