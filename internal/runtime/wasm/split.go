package wasm

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// Privilege mode split (plans/security-gaps-m1-m4.md, M1 PR 9): the root
// helper starts and holds every worker and resident host, as the worker
// user, serving a socket in a folder of its own for this sandboxd's group
// (Config.HelperSockets). This sandboxd is not root, so it cannot give a
// folder to the worker user as single mode does (workerfs.go): it shares
// by group instead. It is a member of the worker user's group; each
// sandbox's /work, compile cache and toolbox upload is its own, setgid to
// that group and open to it, and the worker shares what its guest writes
// with the group too (pkg/wasm ShareFilesWithGroup). No other worker can
// reach a /work: its parent is this sandboxd's alone (closeRunDir), and a
// worker gets its own /work only as an open folder.
//
// What a worker writes for sandboxd to read back as its own, a checkpoint
// (passivation, a move, a snapshot), stays the worker user's file, which
// sandboxd cannot take back: sandboxd copies it out instead
// (split_checkpoint_unix.go, M1 PR 15).

// split reports whether the root helper holds the workers.
func (d *Driver) split() bool { return d.cfg.HelperSockets != "" }

// helperSocket is the socket the helper serves a host on ("" for an id it
// would refuse).
func (d *Driver) helperSocket(kind rootpolicy.HostKind, id string) string {
	p, err := rootpolicy.WasmHostSocket(d.cfg.HelperSockets, kind, id)
	if err != nil {
		return ""
	}
	return p
}

// socketsHome is the folder per-sandbox workers' sockets are in.
func (d *Driver) socketsHome() string {
	if d.split() {
		return d.cfg.HelperSockets
	}
	return d.cfg.RunDir
}

// parseResidentSocket reads a resident host's bucket and index back from
// its socket.
func (d *Driver) parseResidentSocket(socket string) (string, int, bool) {
	if !d.split() {
		return parseResidentSocket(d.cfg.RunDir, socket)
	}
	if filepath.Dir(socket) != filepath.Clean(d.cfg.HelperSockets) {
		return "", 0, false
	}
	name, ok := strings.CutPrefix(filepath.Base(socket), "r-")
	if !ok {
		return "", 0, false
	}
	// The name after "r-" is single mode's resident socket name.
	return parseResidentSocket(d.cfg.RunDir, filepath.Join(d.cfg.RunDir, "resident", name))
}

// slotFromSocket reads a warm-pool slot's id back from its worker's socket.
// In single mode the socket is in the slot's folder (wasmpool
// SlotFromSocket). In split the root helper serves it, w-<slot id>.sock in
// its folder (the pool's SetSocketFor): only a slot id's shape is a slot's,
// so no sandbox's own worker passes for one.
func (d *Driver) slotFromSocket(socket string) (string, bool) {
	if !d.split() {
		return wasmpool.SlotFromSocket(d.cfg.RunDir, socket)
	}
	name, ok := strings.CutPrefix(filepath.Base(socket), "w-")
	if !ok {
		return "", false
	}
	id, ok := strings.CutSuffix(name, ".sock")
	if !ok || !wasmpool.IsSlotID(id) || d.helperSocket(rootpolicy.HostWasmWorker, id) != socket {
		return "", false
	}
	return id, true
}

// warmSlotFolder is the folder of the warm-pool slot an instance took,
// removed with the sandbox: its socket's folder in single mode; in split,
// where the socket is the helper's, the slot's own folder, found again by
// its id and the module's digest (wasmpool SlotDirIn). "" when the socket
// names no slot.
func (d *Driver) warmSlotFolder(inst *sandboxInstance) string {
	if !d.split() {
		return filepath.Dir(inst.socketPath)
	}
	id, ok := d.slotFromSocket(inst.socketPath)
	if !ok || inst.moduleDigest == "" {
		return ""
	}
	// The digest is the record's: cleaned and seen to stay in the pool's
	// folder before anything is removed.
	pool := filepath.Join(filepath.Clean(d.cfg.RunDir), "pool") + string(filepath.Separator)
	dir := filepath.Clean(wasmpool.SlotDirIn(d.cfg.RunDir, inst.moduleDigest, id))
	if !strings.HasPrefix(dir, pool) {
		return ""
	}
	return dir
}

// handToWorker gives a folder sandboxd made to the worker: to its uid in
// single mode; in split to its group, setgid so what is made in it stays
// the group's, mode 2770.
func (d *Driver) handToWorker(dir string) error {
	if !d.split() {
		return os.Lchown(dir, d.cfg.Worker.UID, d.cfg.Worker.GID)
	}
	if err := os.Lchown(dir, -1, d.cfg.Worker.GID); err != nil {
		return err
	}
	return os.Chmod(dir, os.ModeSetgid|0o770)
}

// SetWorkerLister makes boot adoption list the running workers through
// list (privilege mode split: the root helper's ListHosts) instead of the
// workers' cgroup.
func (d *Driver) SetWorkerLister(list func(context.Context) ([]worker.FoundWorker, error)) {
	d.workerLister = list
}

// CacheName is a compile cache folder's name under the cache root, as the
// helper takes it (rootpolicy.CheckWasmCache): "operator", "owner-<hash>"
// or "slots/<hash>/cache". "" for a folder outside the root.
func CacheName(root, dir string) string {
	if root == "" || dir == "" {
		return ""
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(dir))
	if err != nil {
		return ""
	}
	if name, ok := strings.CutPrefix(rel, "owners"+string(filepath.Separator)); ok {
		rel = name
	}
	if rootpolicy.CheckWasmCache(filepath.ToSlash(rel)) != nil {
		return ""
	}
	return filepath.ToSlash(rel)
}
