package worker

import (
	"testing"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// TestNetMediatorAddBlocksNeverLifts: caps-carried blocks are additive, so a
// re-instantiation without them can't undo a quota block (P0-1).
func TestNetMediatorAddBlocksNeverLifts(t *testing.T) {
	m := newNetMediator()
	m.SetBlocks("sb", true, false)
	m.AddBlocks("sb", false, true)
	if !m.ingressBlocked("sb") || !m.egressBlocked("sb") {
		t.Fatal("AddBlocks must OR into the existing state")
	}
	m.AddBlocks("sb", false, false)
	if !m.ingressBlocked("sb") || !m.egressBlocked("sb") {
		t.Fatal("AddBlocks with no blocks must not lift anything")
	}
	m.AddBlocks("", true, true)
	if m.egressBlocked("") {
		t.Fatal("empty sandbox id must be ignored")
	}
}

// TestResidentServer_InstantiateAppliesCapBlocks: a block carried in caps is
// in force before the module runs.
func TestResidentServer_InstantiateAppliesCapBlocks(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	srv := &ResidentServer{}
	client, _ := serveResidentWith(t, srv)
	if _, err := client.LoadModule("host", modPath, 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	caps := nonListenCaps("wasm")
	caps.NetworkBlockEgress = true
	if err := client.Instantiate("sb-blocked", caps); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if !srv.mediator().egressBlocked("sb-blocked") {
		t.Fatal("caps-carried egress block not applied at instantiate")
	}
	if srv.mediator().egressBlocked("sb-other") {
		t.Fatal("block leaked to another sandbox")
	}
}
