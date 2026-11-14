package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/cni"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
)

// C3: one sandbox range for the conflist, the firewall rules and the egress
// gateway, settled at boot against the conflist CNI really uses.
func TestResolveContainerdBridgeSubnet(t *testing.T) {
	conflist := func(t *testing.T, subnet string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "aerolvm.conflist")
		body, err := cni.RenderBridgeConflist(cni.ConflistOptions{Subnet: subnet})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	missing := func(t *testing.T) string { return filepath.Join(t.TempDir(), "none.conflist") }
	broken := func(t *testing.T) string {
		p := filepath.Join(t.TempDir(), "broken.conflist")
		if err := os.WriteFile(p, []byte("{"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		name    string
		path    func(*testing.T) string
		setting string
		want    string
		wantErr string
		wantLog string
	}{
		{name: "no conflist, not set: the default", path: missing, want: "10.88.0.0/16"},
		{name: "no conflist, set: the setting", path: missing, setting: "10.200.0.0/16", want: "10.200.0.0/16"},
		{name: "default conflist, not set", path: func(t *testing.T) string { return conflist(t, "10.88.0.0/16") }, want: "10.88.0.0/16"},
		{name: "an operator's conflist, not set: its range", path: func(t *testing.T) string { return conflist(t, "172.30.0.0/20") }, want: "172.30.0.0/20", wantLog: "taken from the CNI config"},
		{name: "conflist and setting agree", path: func(t *testing.T) string { return conflist(t, "10.200.0.0/16") }, setting: "10.200.0.0/16", want: "10.200.0.0/16"},
		{name: "conflist and setting disagree: refuse", path: func(t *testing.T) string { return conflist(t, "10.88.0.0/16") }, setting: "10.200.0.0/16", wantErr: "hands out 10.88.0.0/16; sandboxd never rewrites that file"},
		{name: "unreadable conflist, not set: the default, with a warning", path: broken, want: "10.88.0.0/16", wantLog: "cannot read the sandbox range"},
		{name: "unreadable conflist, set: refuse", path: broken, setting: "10.200.0.0/16", wantErr: "range cannot be read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			got, err := resolveContainerdBridgeSubnet(config.Config{ContainerdBridgeSubnet: tc.setting, ContainerdCNIConfPath: tc.path(t)}, logger)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("= %q %v, want %q", got, err, tc.want)
			}
			if tc.wantLog != "" && !strings.Contains(logs.String(), tc.wantLog) {
				t.Fatalf("log %q, want %q", logs.String(), tc.wantLog)
			}
		})
	}
}

func TestBridgeHosts(t *testing.T) {
	for subnet, want := range map[string]int{
		"10.88.0.0/16":   65533,
		"192.168.7.0/24": 253,
		"10.0.0.0/30":    1,
		"10.0.0.0/31":    0,
		"fd00::/64":      0,
		"nonsense":       0,
	} {
		if got := bridgeHosts(subnet); got != want {
			t.Errorf("bridgeHosts(%s) = %d, want %d", subnet, got, want)
		}
	}
	if containerdBridgeSubnet(config.Config{}) != cni.DefaultBridgeSubnet {
		t.Fatal("an unresolved config is not the default range")
	}
}

// The conflist sandboxd writes carries the resolved range, and a pool larger
// than the range is warned about.
func TestNetnsPoolWritesTheResolvedRange(t *testing.T) {
	st := openDaemonTestStore(t)
	work := t.TempDir()
	origSysctls := ensureForwardingSysctls
	ensureForwardingSysctls = func() error { return nil }
	t.Cleanup(func() { ensureForwardingSysctls = origSysctls })
	cfg := config.Config{
		ContainerEngine:                   "containerd",
		ContainerdNativeNetnsPoolEnabled:  true,
		ContainerdNetnsPoolSize:           300,
		ContainerdNetnsPoolRefillInterval: 10,
		ContainerdCNIPluginDir:            filepath.Join(work, "cni-bin"),
		ContainerdCNIConfPath:             filepath.Join(work, "cni", "aerolvm.conflist"),
		ContainerdBridgeSubnet:            "192.168.7.0/24",
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	pool, err := wireContainerdNativeNetnsPool(context.Background(), cfg, logger, st, cntr.New(cntr.FromDaemonConfig(cfg), nil, logger))
	if err != nil {
		t.Fatal(err)
	}
	pool.Stop()
	got, err := cni.BridgeSubnet(cfg.ContainerdCNIConfPath)
	if err != nil || got.String() != "192.168.7.0/24" {
		t.Fatalf("conflist range = %v %v, want 192.168.7.0/24", got, err)
	}
	if !strings.Contains(logs.String(), "larger than the sandbox range holds") {
		t.Fatalf("no warning for 300 slots in a /24: %s", logs.String())
	}
}
