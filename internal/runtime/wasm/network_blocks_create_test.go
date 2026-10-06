package wasm

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// TestCreateCarriesNetworkBlockAll pins P0-1: network_block_all reaches the
// worker inside the first instantiation's caps, so the guest's first dial is
// refused, and a later Start re-instantiation keeps carrying it.
func TestCreateCarriesNetworkBlockAll(t *testing.T) {
	for _, blockAll := range []bool{false, true} {
		dir := t.TempDir()
		modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
		client := &recordingWorkerClient{}
		d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir}, nil)
		d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
		d.SetWorkerSupervisor(&fakeSupervisor{})
		d.SetWorkerClientFactory(func(string) WorkerClient { return client })

		if _, err := d.Create(context.Background(), models.CreateSandboxRequest{
			Image: "demo.wasm", NetworkBlockAll: blockAll,
		}, "sb-1", "tok", nil); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if len(client.instantiateCaps) != 1 {
			t.Fatalf("instantiate calls = %d", len(client.instantiateCaps))
		}
		caps := client.instantiateCaps[0]
		if caps.NetworkBlockEgress != blockAll || caps.NetworkBlockIngress != blockAll {
			t.Fatalf("blockAll=%v: caps blocks = (%v,%v)", blockAll, caps.NetworkBlockIngress, caps.NetworkBlockEgress)
		}
		if err := d.Stop(context.Background(), "sb-1"); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Start(context.Background(), "sb-1"); err != nil {
			t.Fatal(err)
		}
		last := client.instantiateCaps[len(client.instantiateCaps)-1]
		if last.NetworkBlockEgress != blockAll {
			t.Fatalf("blockAll=%v: start re-instantiation lost the block", blockAll)
		}
	}
}

func TestSandboxNetworkBlocks(t *testing.T) {
	cases := []struct {
		name    string
		sb      *models.Sandbox
		in, out bool
	}{
		{"nil", nil, false, false},
		{"open", &models.Sandbox{}, false, false},
		{"block all", &models.Sandbox{NetworkBlockAll: true}, true, true},
		{"out quota", &models.Sandbox{NetworkBytesOutLimit: 10, NetworkBytesOut: 10}, false, true},
		{"in quota", &models.Sandbox{NetworkBytesInLimit: 10, NetworkBytesIn: 11}, true, false},
		{"under quota", &models.Sandbox{NetworkBytesOutLimit: 10, NetworkBytesOut: 9}, false, false},
	}
	for _, tc := range cases {
		in, out := sandboxNetworkBlocks(tc.sb)
		if in != tc.in || out != tc.out {
			t.Fatalf("%s: got (%v,%v) want (%v,%v)", tc.name, in, out, tc.in, tc.out)
		}
	}
	var d *Driver
	d.seedNetworkBlocks("x", true, true) // nil-safe
	d.bindNetworkBlocks("x", nil)
}

// TestCreateCarriesEgressPolicy covers P1-6: the egress lists ride in every
// instantiation's caps, marked as set.
func TestCreateCarriesEgressPolicy(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	client := &policyWorkerClient{recordingWorkerClient: &recordingWorkerClient{}}
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "demo.wasm", NetworkAllowOut: []string{"pypi.org"},
	}, "sb-1", "tok", nil); err != nil {
		t.Fatal(err)
	}
	caps := client.instantiateCaps[0]
	if !caps.EgressPolicySet || len(caps.EgressAllowOut) != 1 || caps.EgressAllowOut[0] != "pypi.org" {
		t.Fatalf("caps policy = %+v", caps)
	}
	if err := d.SetEgressPolicy("sb-1", []string{"github.com"}, nil); err != nil {
		t.Fatal(err)
	}
	if len(client.updates) != 1 || client.updates[0] != "github.com" {
		t.Fatalf("live update = %v", client.updates)
	}
	if err := d.Stop(context.Background(), "sb-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Start(context.Background(), "sb-1"); err != nil {
		t.Fatal(err)
	}
	last := client.instantiateCaps[len(client.instantiateCaps)-1]
	if len(last.EgressAllowOut) != 1 || last.EgressAllowOut[0] != "github.com" {
		t.Fatalf("restart must carry the updated policy: %+v", last.EgressAllowOut)
	}
	// A stopped sandbox just records the update; nil driver is a no-op.
	if err := d.Stop(context.Background(), "sb-1"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetEgressPolicy("sb-1", nil, nil); err != nil {
		t.Fatal(err)
	}
	var nilD *Driver
	if nilD.SetEgressPolicy("x", nil, nil) != nil {
		t.Fatal("nil driver")
	}
}

type policyWorkerClient struct {
	*recordingWorkerClient
	updates []string
}

func (c *policyWorkerClient) SetEgressPolicy(_ string, allow, _ []string) error {
	c.updates = append(c.updates, allow...)
	return nil
}

func TestSetEgressPolicyNeedsCapableClient(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-2", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := d.SetEgressPolicy("sb-2", []string{"pypi.org"}, nil); err == nil {
		t.Fatal("a worker client without the hook must error")
	}
}
