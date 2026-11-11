package cni

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
)

// BridgeSubnet is the IPv4 range the conflist at path hands sandboxes: the
// host-local IPAM "subnet" of the plugin the runner invokes, or the first
// IPv4 "ranges" entry (host-local's newer form). The node's firewall rules
// and the egress gateway must name this same range (C3), so it is read
// from the file CNI really uses, which an operator may have written.
func BridgeSubnet(path string) (netip.Prefix, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("read cni conf %q: %w", path, err)
	}
	conf, err := singlePluginNetconf(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	var plugin struct {
		IPAM struct {
			Subnet string `json:"subnet"`
			Ranges [][]struct {
				Subnet string `json:"subnet"`
			} `json:"ranges"`
		} `json:"ipam"`
	}
	if err := json.Unmarshal(conf, &plugin); err != nil {
		return netip.Prefix{}, fmt.Errorf("parse cni plugin: %w", err)
	}
	candidates := []string{plugin.IPAM.Subnet}
	for _, set := range plugin.IPAM.Ranges {
		for _, r := range set {
			candidates = append(candidates, r.Subnet)
		}
	}
	for _, c := range candidates {
		if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is4() {
			return p.Masked(), nil
		}
	}
	return netip.Prefix{}, errors.New("cni conf " + path + ": no IPv4 ipam subnet")
}
