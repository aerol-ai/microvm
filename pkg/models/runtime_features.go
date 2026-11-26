package models

import (
	"fmt"
	"strings"
)

// The runtime feature table (plans/security-gaps-m1-m4.md §11): what each
// runtime name a create accepts can do. It is the one place this is
// written down. GET /v1/runtimes reads it today; the create error that
// names the offered runtimes and the docs comparison table are meant to
// read it too, so the API, the errors and the docs cannot drift apart.
// TestRuntimeTableCoversValidRuntimes fails when a name ValidRuntime
// accepts has no row here.
//
// Each value is what the code does today, not what a plan promises. A
// value that depends on an operator switch says so on its row.

// Isolation kinds: what stands between a sandbox and the server.
const (
	// IsolationContainer: namespaces, cgroups and seccomp on the server's
	// own kernel.
	IsolationContainer = "container"
	// IsolationUserSpaceKernel: gVisor's kernel in user space answers the
	// sandbox's system calls, so few reach the server's kernel.
	IsolationUserSpaceKernel = "user-space-kernel"
	// IsolationHardwareVM: a virtual machine with its own kernel, walled
	// off by the CPU's virtualization support.
	IsolationHardwareVM = "hardware-vm"
	// IsolationWasm: a WebAssembly module in its own worker process; the
	// module reaches only what the host hands it.
	IsolationWasm = "wasm"
	// IsolationV8Isolate: a V8 isolate in a per-tenant workerd process.
	IsolationV8Isolate = "v8-isolate"
)

// What a sandbox keeps when the cluster moves it to another node (a drain or
// a decommission). A failover=recreate sandbox is rebuilt from its image on
// any runtime; that keeps no state and is not a move in this sense.
const (
	// MovesMemory: running programs and memory move with it.
	MovesMemory = "memory"
	// MovesDisk: its files move, its memory does not. No runtime does this
	// yet; the value is reserved so a later runtime can say so.
	MovesDisk = "disk"
	// MovesNone: nothing moves; it is stopped, or rebuilt fresh by recreate.
	MovesNone = "none"
)

// How a create can start warm.
const (
	// WarmPoolKindSnapshot: a VM restored from a pre-booted memory snapshot.
	WarmPoolKindSnapshot = "snapshot"
	// WarmPoolKindParked: a sandbox (or worker process) started ahead of
	// time and handed to the create.
	WarmPoolKindParked = "parked"
	// WarmPoolKindNone: every create starts cold.
	WarmPoolKindNone = "none"
)

// RuntimeFeatures is what a runtime can do. The warm pool is what the
// runtime can use; the operator decides whether one runs.
type RuntimeFeatures struct {
	// Snapshots: POST /v1/sandboxes/{id}/snapshot saves the sandbox as a
	// named image new sandboxes start from.
	Snapshots bool `json:"snapshots"`
	// Pause: a stop keeps memory and running programs, and the next start
	// resumes them.
	Pause bool `json:"pause"`
	// Moves is one of MovesMemory, MovesDisk, MovesNone.
	Moves string `json:"moves"`
	// WarmPool is one of WarmPoolKindSnapshot, WarmPoolKindParked,
	// WarmPoolKindNone.
	WarmPool string `json:"warm_pool"`
	// Confidential: memory is sealed from the host (an enclave or a
	// confidential VM). No runtime offers it yet.
	Confidential bool `json:"confidential"`
}

// RuntimeLimits are fixed limits a runtime has whatever the operator sets.
// Zero means no such limit.
type RuntimeLimits struct {
	// MaxCheckpointMemoryMB: the most memory a checkpoint can restore. A
	// bigger sandbox still runs, but cannot come back from a passivation or
	// a move.
	MaxCheckpointMemoryMB int `json:"max_checkpoint_memory_mb,omitempty"`
}

// RuntimeInfo is one row of the table.
type RuntimeInfo struct {
	Name      string
	Isolation string
	// Backend names the hardware a VM runtime runs on ("kvm", "nitro").
	// Empty for runtimes that are not VMs.
	Backend  string
	Features RuntimeFeatures
	Limits   *RuntimeLimits
	// Reserved: ValidRuntime accepts the name but every create refuses it
	// (ErrRuntimeNotImplemented). It is never available, even on a node
	// that lists it in SB_HOST_RUNTIMES.
	Reserved bool
}

// runtimeTable is in ValidRuntime's order. Read it through RuntimeTable or
// LookupRuntime, which return copies.
var runtimeTable = []RuntimeInfo{
	{
		// Snapshots commit the container (pkg/docker, containerd
		// snapshot.go). Stop ends its programs. Decommission moves no
		// container (internal/cluster placementWantsSnapshotMove). Both
		// engines can park started containers (internal/pool/dockerpool,
		// containerdpool; SB_DOCKER_POOL_ENABLED / SB_CONTAINERD_POOL_ENABLED).
		Name:      RuntimeDocker,
		Isolation: IsolationContainer,
		Features:  RuntimeFeatures{Snapshots: true, Moves: MovesNone, WarmPool: WarmPoolKindParked},
	},
	{
		// Snapshots: not advertised. The snapshot call runs the same engine
		// commit as docker, but gVisor keeps a sandbox's file writes in its
		// own overlay, so the committed image may not hold them, and no live
		// test proves it does. Flip this only after one does. A plain stop
		// does not checkpoint. Moves keep memory between workers that run
		// SB_GVISOR_CHECKPOINT_MOVES (C21; on in the Helm chart, off in
		// install.sh). Parked slots are keyed by runtime, so gVisor parks too.
		Name:      RuntimeGvisor,
		Isolation: IsolationUserSpaceKernel,
		Features:  RuntimeFeatures{Moves: MovesMemory, WarmPool: WarmPoolKindParked},
	},
	{
		// Reserved for Kata Containers: a VM per sandbox, not built yet.
		Name:      RuntimeKata,
		Isolation: IsolationHardwareVM,
		Features:  RuntimeFeatures{Moves: MovesNone, WarmPool: WarmPoolKindNone},
		Reserved:  true,
	},
	{
		// Stop writes a memory snapshot and start resumes it
		// (firecracker driver Stop/Start). Snapshots export the disk
		// (snapshot_export.go). Moves carry the memory snapshot
		// (internal/cluster/snapshot_move.go). The warm-VMM pool restores
		// pre-booted snapshots (internal/pool/vmm, SB_FIRECRACKER_VMM_POOL_ENABLED).
		Name:      RuntimeFirecracker,
		Isolation: IsolationHardwareVM,
		Backend:   "kvm",
		Features:  RuntimeFeatures{Snapshots: true, Pause: true, Moves: MovesMemory, WarmPool: WarmPoolKindSnapshot},
	},
	{
		// Firecracker through Nitro Sandboxes (plans/security-gaps-m1-m4.md
		// §4.3): the same driver on SB_FIRECRACKER_BACKEND=nitro nodes. AWS
		// gives a Nitro VM no memory snapshots and no paused state, so no
		// snapshots, no pause and no memory moves; no warm pool yet. Stop
		// keeps the disk and Start boots it again (firecracker nitro.go).
		Name:      RuntimeFirecrackerNitro,
		Isolation: IsolationHardwareVM,
		Backend:   "nitro",
		Features:  RuntimeFeatures{Moves: MovesNone, WarmPool: WarmPoolKindNone},
	},
	{
		// A snapshot is a checkpoint file, not an image a create can start
		// from, so no snapshots here. Stop does not keep memory; only
		// passivation at shutdown does. A drain moves passivatable and
		// durable sandboxes with their memory (service wasm_migrate.go).
		// The pool holds pre-spawned workers (internal/pool/wasm). Restore
		// decodes at most 1 GiB of memory (pkg/wasm maxSnapshotMemoryBytes).
		Name:      RuntimeWasm,
		Isolation: IsolationWasm,
		Features:  RuntimeFeatures{Moves: MovesMemory, WarmPool: WarmPoolKindParked},
		Limits:    &RuntimeLimits{MaxCheckpointMemoryMB: 1024},
	},
	{
		// V8 cannot serialize a running isolate, so no snapshots and no
		// memory moves (isolate driver CreateSnapshot). The pool holds
		// blank workerd hosts (internal/pool/isolate).
		Name:      RuntimeIsolate,
		Isolation: IsolationV8Isolate,
		Features:  RuntimeFeatures{Moves: MovesNone, WarmPool: WarmPoolKindParked},
	},
}

// RuntimeTable returns every row, in ValidRuntime's order. The slice and its
// limits are copies: a caller cannot change the table.
func RuntimeTable() []RuntimeInfo {
	out := make([]RuntimeInfo, len(runtimeTable))
	for i, row := range runtimeTable {
		out[i] = row.clone()
	}
	return out
}

// LookupRuntime returns name's row.
func LookupRuntime(name string) (RuntimeInfo, bool) {
	for _, row := range runtimeTable {
		if row.Name == name {
			return row.clone(), true
		}
	}
	return RuntimeInfo{}, false
}

func (r RuntimeInfo) clone() RuntimeInfo {
	if r.Limits != nil {
		limits := *r.Limits
		r.Limits = &limits
	}
	return r
}

// RuntimeBackend is the backend a sandbox of this runtime runs on, from the
// table: "kvm" for firecracker, "nitro" for firecracker-nitro, "" for
// runtimes that are not VMs and for names the table does not hold.
func RuntimeBackend(name string) string {
	for _, row := range runtimeTable {
		if row.Name == name {
			return row.Backend
		}
	}
	return ""
}

// WarmStartKind is the Sandbox.Warm value for a create of runtime that a
// warm pool served (warm) or not: the table's warm-pool kind for the
// runtime, or WarmPoolKindNone. A runtime the table says has no warm pool
// but that was still served warm is reported as parked: something was
// running before the create asked for it.
func WarmStartKind(runtime string, warm bool) string {
	if !warm {
		return WarmPoolKindNone
	}
	for _, row := range runtimeTable {
		if row.Name == runtime && row.Features.WarmPool != WarmPoolKindNone {
			return row.Features.WarmPool
		}
	}
	return WarmPoolKindParked
}

// RuntimeNotOfferedError is a refused create that asked for a runtime this
// deployment does not offer now (plans/security-gaps-m1-m4.md §11, R18).
// It names the runtimes that are offered, so the caller can pick one;
// nothing is swapped for them. Offered holds names only: never a node or a
// count. It unwraps to the refusal it explains, so the HTTP status and every
// errors.Is check stay what they were.
type RuntimeNotOfferedError struct {
	Runtime string
	// Offered is every available runtime, in the table's order.
	Offered []string
	Err     error
}

// Error puts the offered runtimes first: some refusals are cut to 200
// characters on the way out (apihttp.Classify), and the list is the part a
// caller acts on.
func (e *RuntimeNotOfferedError) Error() string {
	offered := "none"
	if len(e.Offered) > 0 {
		offered = strings.Join(e.Offered, ", ")
	}
	if e.Err == nil {
		return fmt.Sprintf("runtime %q is not offered here (offered: %s)", e.Runtime, offered)
	}
	return fmt.Sprintf("runtime %q is not offered here (offered: %s): %v", e.Runtime, offered, e.Err)
}

func (e *RuntimeNotOfferedError) Unwrap() error { return e.Err }

// OfferedRuntimes is the names ListRuntimes marks available for offers, in
// the table's order.
func OfferedRuntimes(offers map[string]int) []string {
	var out []string
	for _, entry := range ListRuntimes(offers, false).Runtimes {
		if entry.Available {
			out = append(out, entry.Name)
		}
	}
	return out
}

// RuntimeListEntry is one runtime in GET /v1/runtimes.
type RuntimeListEntry struct {
	Name      string          `json:"name"`
	Isolation string          `json:"isolation"`
	Backend   string          `json:"backend,omitempty"`
	Features  RuntimeFeatures `json:"features"`
	Limits    *RuntimeLimits  `json:"limits,omitempty"`
	// Available: at least one node that can run sandboxes offers it now.
	Available bool `json:"available"`
	// Nodes is how many such nodes offer it. Fleet admins only: for anyone
	// else it is left out, as GET /v1/capacity leaves out pool details.
	Nodes *int `json:"nodes,omitempty"`
}

// ListRuntimesResponse is the body of GET /v1/runtimes.
type ListRuntimesResponse struct {
	Runtimes []RuntimeListEntry `json:"runtimes"`
}

// ListRuntimes joins the table with offers, the number of nodes offering
// each runtime name. withNodes adds those counts (fleet admins). A name in
// offers with no row is ignored: SB_HOST_RUNTIMES is free text, and a name
// no create accepts is not a runtime anyone can ask for.
func ListRuntimes(offers map[string]int, withNodes bool) ListRuntimesResponse {
	out := ListRuntimesResponse{Runtimes: make([]RuntimeListEntry, 0, len(runtimeTable))}
	for _, row := range RuntimeTable() {
		nodes := offers[row.Name]
		if row.Reserved || nodes < 0 {
			nodes = 0
		}
		entry := RuntimeListEntry{
			Name:      row.Name,
			Isolation: row.Isolation,
			Backend:   row.Backend,
			Features:  row.Features,
			Limits:    row.Limits,
			Available: nodes > 0,
		}
		if withNodes {
			entry.Nodes = &nodes
		}
		out.Runtimes = append(out.Runtimes, entry)
	}
	return out
}
