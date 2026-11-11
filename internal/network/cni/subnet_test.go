package cni

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBridgeSubnet(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	generated, err := RenderBridgeConflist(ConflistOptions{Subnet: "10.200.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body, want, wantErr string
	}{
		{name: "the conflist sandboxd writes", body: string(generated), want: "10.200.0.0/16"},
		{name: "a bare plugin config", body: `{"type":"bridge","ipam":{"type":"host-local","subnet":"172.30.0.0/20"}}`, want: "172.30.0.0/20"},
		{name: "host-local ranges, IPv6 first", body: `{"plugins":[{"type":"bridge","ipam":{"type":"host-local","ranges":[[{"subnet":"fd00::/64"}],[{"subnet":"10.9.0.0/24"}]]}}]}`, want: "10.9.0.0/24"},
		{name: "an unmasked subnet is masked", body: `{"plugins":[{"type":"bridge","ipam":{"subnet":"10.88.3.4/16"}}]}`, want: "10.88.0.0/16"},
		{name: "no IPv4 range", body: `{"plugins":[{"type":"bridge","ipam":{"ranges":[[{"subnet":"fd00::/64"}]]}}]}`, wantErr: "no IPv4 ipam subnet"},
		{name: "not JSON", body: `{`, wantErr: "parse cni conf"},
		{name: "a bad ipam", body: `{"plugins":[{"type":"bridge","ipam":"x"}]}`, wantErr: "parse cni plugin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BridgeSubnet(write(strings.ReplaceAll(tc.name, " ", "_")+".conflist", tc.body))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got.String() != tc.want {
				t.Fatalf("= %v %v, want %s", got, err, tc.want)
			}
		})
	}
	if _, err := BridgeSubnet(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: %v, want a not-exist error", err)
	}
}
