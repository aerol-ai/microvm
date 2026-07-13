package cni

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRenderBridgeConflistDefaultsAndNAT(t *testing.T) {
	body, err := RenderBridgeConflist(ConflistOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var top struct {
		CNIVersion string `json:"cniVersion"`
		Name       string `json:"name"`
		Plugins    []struct {
			Type   string `json:"type"`
			Bridge string `json:"bridge"`
			IPMasq bool   `json:"ipMasq"`
			MTU    int    `json:"mtu"`
			IPAM   struct {
				Type   string `json:"type"`
				Subnet string `json:"subnet"`
			} `json:"ipam"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("rendered conflist is not valid JSON: %v", err)
	}
	if top.Name != "aerolvm" || len(top.Plugins) != 1 {
		t.Fatalf("unexpected conflist: %s", body)
	}
	p := top.Plugins[0]
	if p.Type != "bridge" || p.Bridge != "aerolvm0" {
		t.Fatalf("bridge plugin defaults wrong: %+v", p)
	}
	if !p.IPMasq {
		t.Fatal("ipMasq must be true (outbound NAT parity with dockerd)")
	}
	if p.MTU != DefaultBridgeMTU {
		t.Fatalf("MTU = %d, want default %d", p.MTU, DefaultBridgeMTU)
	}
	if p.IPAM.Type != "host-local" || p.IPAM.Subnet == "" {
		t.Fatalf("ipam wrong: %+v", p.IPAM)
	}
}

func TestRenderBridgeConflistHonorsMTU(t *testing.T) {
	body, err := RenderBridgeConflist(ConflistOptions{MTU: 9001, Subnet: "10.99.0.0/16", Bridge: "br9"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, want := range []string{`"mtu": 9001`, `"10.99.0.0/16"`, `"br9"`} {
		if !contains(s, want) {
			t.Fatalf("rendered conflist missing %q: %s", want, s)
		}
	}
}

func TestEnsureBridgeConflistWritesThenNoClobber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "net.d", "aerolvm.conflist")
	if err := EnsureBridgeConflist(path, ConflistOptions{}); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("conflist not written: %v", err)
	}
	// Second call with different opts must NOT clobber an existing file.
	if err := EnsureBridgeConflist(path, ConflistOptions{Bridge: "different0"}); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("EnsureBridgeConflist clobbered an existing conflist")
	}
}

func TestEnsureBridgeConflistRequiresPath(t *testing.T) {
	if err := EnsureBridgeConflist("", ConflistOptions{}); err == nil {
		t.Fatal("want error for empty path")
	}
}

func TestUplinkMTUDoesNotPanic(t *testing.T) {
	// On darwin it returns 0 (stub); on linux it reads /proc/net/route. Either
	// way it must be non-negative and not panic.
	if got := UplinkMTU(); got < 0 {
		t.Fatalf("UplinkMTU = %d, want >= 0", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
