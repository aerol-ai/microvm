package wasm

import "errors"

// ErrNoSlot means the warm pool has no ready worker for the requested module digest.
var ErrNoSlot = errors.New("wasm warm pool: no slot available")
