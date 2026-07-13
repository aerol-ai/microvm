package cni

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultBridgeSubnet is the host-local IPAM subnet for the aerolvm0 bridge.
// Shared so the netrules FORWARD-accept rules target the same CIDR the conflist
// hands out.
const DefaultBridgeSubnet = "10.88.0.0/16"

// ConflistOptions parameterizes the generated bridge+host-local conflist.
type ConflistOptions struct {
	Name    string // network name, e.g. "aerolvm"
	Bridge  string // host bridge interface, e.g. "aerolvm0"
	Subnet  string // host-local IPAM subnet, e.g. "10.88.0.0/16"
	Gateway string // optional explicit gateway; host-local derives .1 if empty
	MTU     int    // bridge/veth MTU; <=0 falls back to DefaultBridgeMTU
}

// EnsureBridgeConflist writes a bridge+host-local CNI conflist to path if it is
// absent, so the containerd netns pool has a network to realize. This is the
// §4 owner for items dockerd's libnetwork used to provide: the bridge, IPAM,
// and outbound NAT (`ipMasq: true`). It never overwrites an operator-provided
// conflist. Returns the effective path.
//
// NOTE: the generated JSON is validated offline (schema + round-trip), but the
// plugins that consume it run only on a live host with /opt/cni/bin populated —
// exercised by the containerd integration suite, not `make test`.
func EnsureBridgeConflist(path string, opts ConflistOptions) error {
	if path == "" {
		return fmt.Errorf("cni conflist path is required")
	}
	if _, err := os.Stat(path); err == nil {
		return nil // operator- or previously-generated; do not clobber
	}
	body, err := RenderBridgeConflist(opts)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create cni conf dir: %w", err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return fmt.Errorf("write cni conflist %q: %w", path, err)
	}
	return nil
}

// RenderBridgeConflist produces the conflist JSON. Kept separate from the file
// write so it is unit-testable without touching disk.
func RenderBridgeConflist(opts ConflistOptions) ([]byte, error) {
	if opts.Name == "" {
		opts.Name = "aerolvm"
	}
	if opts.Bridge == "" {
		opts.Bridge = "aerolvm0"
	}
	if opts.Subnet == "" {
		opts.Subnet = DefaultBridgeSubnet
	}
	mtu := opts.MTU
	if mtu <= 0 {
		mtu = DefaultBridgeMTU
	}
	ipam := map[string]any{
		"type":   "host-local",
		"subnet": opts.Subnet,
		"routes": []map[string]string{{"dst": "0.0.0.0/0"}},
	}
	if opts.Gateway != "" {
		ipam["gateway"] = opts.Gateway
	}
	conflist := map[string]any{
		"cniVersion": "1.0.0",
		"name":       opts.Name,
		"plugins": []map[string]any{
			{
				"type":        "bridge",
				"bridge":      opts.Bridge,
				"isGateway":   true,
				"ipMasq":      true, // outbound NAT — dockerd's POSTROUTING MASQUERADE
				"hairpinMode": true,
				"mtu":         mtu,
				"ipam":        ipam,
			},
		},
	}
	body, err := json.MarshalIndent(conflist, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render cni conflist: %w", err)
	}
	return append(body, '\n'), nil
}
