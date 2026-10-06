package wasm

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
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
	if err := d.SetEgressPolicy("sb-1", []string{"github.com"}, nil, false); err != nil {
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
	if err := d.SetEgressPolicy("sb-1", nil, nil, false); err != nil {
		t.Fatal(err)
	}
	var nilD *Driver
	if nilD.SetEgressPolicy("x", nil, nil, false) != nil {
		t.Fatal("nil driver")
	}
}

type policyWorkerClient struct {
	*recordingWorkerClient
	updates []string
	learn   bool
}

func (c *policyWorkerClient) SetEgressPolicy(_ string, allow, _ []string, learn bool) error {
	c.updates = append(c.updates, allow...)
	c.learn = learn
	return nil
}

func (c *policyWorkerClient) EgressLearned(string) (egresspolicy.Learned, error) {
	return egresspolicy.Learned{Entries: []egresspolicy.LearnedEntry{{Host: "pypi.org"}}}, nil
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
	if err := d.SetEgressPolicy("sb-2", []string{"pypi.org"}, nil, false); err == nil {
		t.Fatal("a worker client without the hook must error")
	}
}

// TestWasmLearnMode (P2-7): learn mode rides the caps at create and the
// live update, and the recording is read from the running worker.
func TestWasmLearnMode(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	client := &policyWorkerClient{recordingWorkerClient: &recordingWorkerClient{}}
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm", NetworkEgressMode: "learn"}, "sb-l", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if caps := client.instantiateCaps[0]; !caps.EgressLearn || !caps.EgressPolicySet {
		t.Fatalf("caps = %+v", caps)
	}
	l, err := d.EgressLearned("sb-l")
	if err != nil || len(l.Entries) != 1 {
		t.Fatalf("learned = %+v %v", l, err)
	}
	if err := d.SetEgressPolicy("sb-l", []string{"pypi.org"}, nil, false); err != nil || client.learn {
		t.Fatalf("switch to enforce: %v learn=%v", err, client.learn)
	}
	if l, err := d.EgressLearned("missing"); err != nil || len(l.Entries) != 0 {
		t.Fatalf("no instance = %+v %v", l, err)
	}
	var nilD *Driver
	if _, err := nilD.EgressLearned("x"); err != nil {
		t.Fatal(err)
	}
	plain := New(Config{RunDir: filepath.Join(dir, "run2"), ModulesDir: dir}, nil)
	plain.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	plain.SetWorkerSupervisor(&fakeSupervisor{})
	plain.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
	if _, err := plain.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-p", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.EgressLearned("sb-p"); err == nil {
		t.Fatal("a worker client without the read must error")
	}
}
