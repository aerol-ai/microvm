package cni

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBridgeName(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	generated := filepath.Join(dir, "aerolvm.conflist")
	if err := EnsureBridgeConflist(generated, ConflistOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, want string
		wantErr          bool
	}{
		{name: "generated conflist", path: generated, want: "aerolvm0"},
		// containerd's stock 10-containerd-net.conflist names cni0 itself;
		// one that names nothing gets the plugin's default, also cni0.
		{name: "named bridge", path: write("named.conflist", `{"cniVersion":"1.0.0","name":"x","plugins":[{"type":"bridge","bridge":"cni0"},{"type":"portmap"}]}`), want: "cni0"},
		{name: "plugin default", path: write("default.conflist", `{"cniVersion":"1.0.0","name":"x","plugins":[{"type":"bridge"}]}`), want: DefaultPluginBridge},
		{name: "bare conf", path: write("bare.conf", `{"cniVersion":"1.0.0","name":"x","type":"bridge","bridge":"sbx0"}`), want: "sbx0"},
		{name: "first plugin is not a bridge", path: write("ptp.conflist", `{"plugins":[{"type":"ptp"}]}`), wantErr: true},
		{name: "no plugins", path: write("empty.conflist", `{"plugins":[]}`), wantErr: true},
		{name: "not json", path: write("bad.conf", `{`), wantErr: true},
		{name: "plugin not an object", path: write("weird.conflist", `{"plugins":[{"type":"bridge","bridge":7}]}`), wantErr: true},
		{name: "missing file", path: filepath.Join(dir, "absent.conflist"), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BridgeName(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("BridgeName = %q, want an error", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("BridgeName = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
