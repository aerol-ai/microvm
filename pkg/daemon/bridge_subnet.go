package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/cni"
)

// resolveContainerdBridgeSubnet settles the containerd sandboxes' address
// range at boot (C3), so the CNI conflist, the firewall rules and the egress
// gateway all name one range:
//
//   - A conflist already at SB_CONTAINERD_CNI_CONF_PATH is what CNI really
//     hands out. With SB_CONTAINERD_BRIDGE_SUBNET unset, its range is used,
//     which also stops the rules naming 10.88.0.0/16 whatever an operator's
//     conflist said. Set to another range, the boot stops: sandboxd never
//     rewrites a conflist (sandboxes may hold its addresses), so the
//     setting could not take effect, and rules for the wrong range would
//     guard nothing.
//   - With no conflist yet, the setting, else 10.88.0.0/16; sandboxd writes
//     the conflist with it.
func resolveContainerdBridgeSubnet(cfg config.Config, logger *slog.Logger) (string, error) {
	want, path := cfg.ContainerdBridgeSubnet, cfg.ContainerdCNIConfPath
	have, err := cni.BridgeSubnet(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if want == "" {
			want = cni.DefaultBridgeSubnet
		}
		return want, nil
	case err != nil:
		if want != "" {
			return "", fmt.Errorf("SB_CONTAINERD_BRIDGE_SUBNET is %s, but the CNI config's range cannot be read: %w", want, err)
		}
		logger.Warn("containerd: cannot read the sandbox range from the CNI config; the firewall rules use the default range",
			"path", path, "subnet", cni.DefaultBridgeSubnet, "error", err)
		return cni.DefaultBridgeSubnet, nil
	case want == "":
		if have.String() != cni.DefaultBridgeSubnet {
			logger.Info("containerd: sandbox range taken from the CNI config", "path", path, "subnet", have.String())
		}
		return have.String(), nil
	case have != netip.MustParsePrefix(want):
		return "", fmt.Errorf("SB_CONTAINERD_BRIDGE_SUBNET is %s, but the CNI config at %s hands out %s; "+
			"sandboxd never rewrites that file, since sandboxes may hold its addresses. "+
			"With no sandboxes on this node, remove the file and restart; or set SB_CONTAINERD_BRIDGE_SUBNET=%s",
			want, path, have, have)
	}
	return want, nil
}

// containerdBridgeSubnet is the resolved range, or the default for a config
// built without the boot resolution (tests, and the docker engine).
func containerdBridgeSubnet(cfg config.Config) string {
	if cfg.ContainerdBridgeSubnet != "" {
		return cfg.ContainerdBridgeSubnet
	}
	return cni.DefaultBridgeSubnet
}

// bridgeHosts is how many sandbox addresses a range holds: all but the
// network address, the gateway (the bridge) and the broadcast address.
func bridgeHosts(subnet string) int {
	p, err := netip.ParsePrefix(subnet)
	if err != nil || !p.Addr().Is4() || p.Bits() > 30 {
		return 0
	}
	return 1<<(32-p.Bits()) - 3
}
