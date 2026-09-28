package wasm

import "errors"

// ErrNoSlot means the warm pool has no ready worker for the requested module digest.
var ErrNoSlot = errors.New("wasm warm pool: no slot available")

// ErrPoolClosed means the daemon is shutting down and no new warm workers may
// be started or admitted into the ready queue.
var ErrPoolClosed = errors.New("wasm warm pool: closed")
