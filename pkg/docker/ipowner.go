package docker

import (
	"context"
	"net/http"
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
