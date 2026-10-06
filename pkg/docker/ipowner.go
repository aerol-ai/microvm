package docker

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/aerol-ai/microvm/internal/runtime"
)

var _ runtime.IPOwnerResolver = (*Client)(nil)

// IPOwner reports which sandbox currently holds ip on the sandbox network, by
// reading dockerd's live network attachment list. It exists for the P0-6
// owner check: dockerd assigns the IP at start, before the new sandbox's row
// is persisted, so the store alone can't see a fresh owner.
func (c *Client) IPOwner(ctx context.Context, ip string) (string, error) {
	network := c.network
	if network == "" {
		network = "bridge"
	}
	var resp struct {
		Containers map[string]struct {
			Name        string `json:"Name"`
			IPv4Address string `json:"IPv4Address"`
		} `json:"Containers"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/networks/"+url.PathEscape(network), nil, nil, nil, &resp); err != nil {
		return "", err
	}
	for _, ct := range resp.Containers {
		addr, _, _ := strings.Cut(ct.IPv4Address, "/")
		if addr == ip {
			return ipOwnerFromContainerName(ct.Name), nil
		}
	}
	return "", nil
}

// ipOwnerFromContainerName maps a container name on the sandbox network to the
// sandbox that owns its IP. Sandbox containers are named by sandbox id; an
// adopted pause-netns slot carries the id after its prefix. Free pause slots
// and parked warm slots belong to no sandbox yet.
func ipOwnerFromContainerName(name string) string {
	name = sandboxIDFromContainerName(name)
	if id, ok := strings.CutPrefix(name, netnsAdoptedPrefix); ok {
		return id
	}
	if strings.HasPrefix(name, netnsFreePrefix) || strings.HasPrefix(name, "park-") {
		return ""
	}
	return name
}

var _ runtime.EgressHolder = (*Client)(nil)

// SetEgressFloor installs the operator's node-wide deny floor for the
// sandbox network's subnet (§5.10 PC-2).
func (c *Client) SetEgressFloor(ctx context.Context, cidrs []netip.Prefix) error {
	if c.networkRules == nil || !c.networkRules.Enabled() {
		return nil
	}
	sn, err := c.SandboxBridge(ctx)
	if err != nil {
		return err
	}
	return c.networkRules.SetFloor(sn.Subnet, cidrs)
}

// ApplyEgressHold installs the fail-closed hold DROP (CEO D16).
func (c *Client) ApplyEgressHold(containerIP string) error {
	return c.networkRules.HoldEgress(containerIP)
}

// ClearEgressHold lifts the hold after a successful gateway attach.
func (c *Client) ClearEgressHold(containerIP string) error {
	return c.networkRules.ClearHoldEgress(containerIP)
}

// SandboxNetwork is the sandbox network's bridge as the egress gateway needs
// it: where to listen (Gateway on Name) and which sources the node-wide
// floor and control-port guard cover (Subnet, §5.10 PC-2).
type SandboxNetwork struct {
	Name    string
	Gateway netip.Addr
	Subnet  netip.Prefix
}

// SandboxBridge returns the Linux bridge, gateway IP and subnet of the
// sandbox network (SB_DOCKER_NETWORK, default "bridge" → docker0). sandboxd
// hands it to the egress gateway, which has no docker socket access (plans/
// egress-domain-filtering.md S5, CEO D21).
func (c *Client) SandboxBridge(ctx context.Context) (SandboxNetwork, error) {
	network := c.network
	if network == "" {
		network = "bridge"
	}
	var resp struct {
		ID      string            `json:"Id"`
		Options map[string]string `json:"Options"`
		IPAM    struct {
			Config []struct {
				Subnet  string `json:"Subnet"`
				Gateway string `json:"Gateway"`
			} `json:"Config"`
		} `json:"IPAM"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/networks/"+url.PathEscape(network), nil, nil, nil, &resp); err != nil {
		return SandboxNetwork{}, err
	}
	name := resp.Options["com.docker.network.bridge.name"]
	if name == "" {
		if network == "bridge" {
			name = "docker0"
		} else if len(resp.ID) >= 12 {
			name = "br-" + resp.ID[:12]
		}
	}
	for _, cfg := range resp.IPAM.Config {
		gw, err := netip.ParseAddr(cfg.Gateway)
		if err == nil && gw.Is4() {
			sn := SandboxNetwork{Name: name, Gateway: gw}
			if p, err := netip.ParsePrefix(cfg.Subnet); err == nil && p.Addr().Is4() {
				sn.Subnet = p.Masked()
			}
			return sn, nil
		}
	}
	return SandboxNetwork{Name: name}, fmt.Errorf("docker network %s has no IPv4 gateway", network)
}
