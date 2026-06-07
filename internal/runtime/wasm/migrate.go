package wasm

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/models"
)

// MigrateSandbox is reserved for live WASM migration (plans/wasm-runtime.md Phase 7).
func (d *Driver) MigrateSandbox(context.Context, *models.Sandbox, string) error {
	return d.notImplemented("MigrateSandbox")
}
