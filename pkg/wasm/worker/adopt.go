package worker

import (
	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// FoundWorker is a process a previous sandboxd left in the workers' cgroup.
// Socket is empty when the process is not a worker (a stray); the caller
// stops it.
type FoundWorker struct {
	PID int
	// Resident is a resident-module host (--wasm-resident-host); otherwise
	// a per-sandbox worker (--wasm-worker).
	Resident bool
	Socket   string
	Proc     hostproc.Process
}

// Host seams, replaced in tests.
var (
	openWorkerPID = func(pid int) (hostproc.Process, error) {
		p, _, err := hostproc.OpenPID(pid)
		return p, err
	}
	workerCmdline = hostproc.Cmdline
)

// FindWorkers lists the processes in cg and holds each by a pidfd. The
// cgroup is the proof a process is ours: only this package starts
// processes there. A worker is known by its last two arguments, the mode
// flag and its socket, which is all a restarted sandboxd needs to talk to
// it again. A process that exits while it is being listed is left out.
func FindWorkers(cg *hostproc.Cgroup) ([]FoundWorker, error) {
	pids, err := cg.PIDs()
	if err != nil {
		return nil, err
	}
	out := make([]FoundWorker, 0, len(pids))
	for _, pid := range pids {
		argv, err := workerCmdline(pid)
		if err != nil {
			continue // gone
		}
		proc, err := openWorkerPID(pid)
		if err != nil {
			continue // gone, or its pid already names another process
		}
		found := FoundWorker{PID: pid, Proc: proc}
		if n := len(argv); n >= 3 && argv[n-1] != "" {
			switch argv[n-2] {
			case WorkerFlag:
				found.Socket = argv[n-1]
			case ResidentHostFlag:
				found.Resident, found.Socket = true, argv[n-1]
			}
		}
		out = append(out, found)
	}
	return out, nil
}
