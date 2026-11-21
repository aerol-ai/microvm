package rootpolicy

import (
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// TestHelperFileBinds: a helper file root accepts only a read-only bind of
// one file the helper makes, at exactly <root>/<id>/<name>. Only root can
// write the helper's folders, and that is what keeps a name in them from
// being swapped for a link before runc's mount; a bind of a folder, or a
// writable one, would hand that to a sandbox, which runs as uid 0.
func TestHelperFileBinds(t *testing.T) {
	ro := []string{"rbind", "ro"}
	for _, tc := range []struct {
		name string
		src  string
		opts []string
		ok   bool
	}{
		{"resolv.conf", testHelperHosts + "/sb-1/resolv.conf", ro, true},
		{"hosts", testHelperHosts + "/sb-1/hosts", ro, true},
		{"hostname", testHelperHosts + "/sb-1/hostname", []string{"bind", "ro", "nosuid"}, true},
		{"the egress CA", testHelperHosts + "/sb-1/egress-ca.pem", ro, true},
		{"a create's ready socket", testHelperReady + "/sb-1/0a1b2c3d.sock", ro, true},
		{"a park socket", testHelperReady + "/park-0a1b/ready.sock", ro, true},

		{"a container's host files folder", testHelperHosts + "/sb-1", ro, false},
		{"a container's ready folder", testHelperReady + "/sb-1", []string{"rbind", "rw"}, false},
		{"the root itself", testHelperHosts, ro, false},
		{"a file read-write", testHelperHosts + "/sb-1/resolv.conf", []string{"rbind", "rw"}, false},
		{"a file with no ro", testHelperHosts + "/sb-1/resolv.conf", []string{"rbind"}, false},
		{"ro undone by rw", testHelperHosts + "/sb-1/hosts", []string{"rbind", "ro", "rw"}, false},
		{"the ready socket writable", testHelperReady + "/sb-1/0a1b.sock", []string{"rbind"}, false},
		{"a name deeper down", testHelperHosts + "/sb-1/x/resolv.conf", ro, false},
		{"a name the helper does not make", testHelperHosts + "/sb-1/shadow", ro, false},
		{"a temporary name", testHelperHosts + "/sb-1/.resolv.conf.0123456789abcdef", ro, false},
		{"a nonce in capitals", testHelperReady + "/sb-1/0A1B.sock", ro, false},
		{"an odd-length nonce", testHelperReady + "/sb-1/abc.sock", ro, false},
		{"a nonce too long", testHelperReady + "/sb-1/" + strings.Repeat("ab", 33) + ".sock", ro, false},
		{"no nonce", testHelperReady + "/sb-1/.sock", ro, false},
		{"an ID that is no ID", testHelperHosts + "/sb.1/resolv.conf", ro, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := baselineSpec(t)
			s.Mounts = append(s.Mounts, specs.Mount{Type: "bind", Source: tc.src, Destination: "/x", Options: tc.opts})
			err := CheckSpec(testPolicy(), testID, s)
			if tc.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			wantRule(t, err, RuleMount)
		})
	}
}

func TestCheckReadyNonce(t *testing.T) {
	for n, ok := range map[string]bool{
		"0a1b": true, strings.Repeat("ab", 32): true,
		"": false, "abc": false, "AB": false, "zz": false, "../x": false, strings.Repeat("ab", 33): false,
	} {
		if err := CheckReadyNonce(n); (err == nil) != ok {
			t.Errorf("CheckReadyNonce(%q) = %v, want ok=%v", n, err, ok)
		}
	}
	if ReadySocketFile("") != ParkSocketFile || ReadySocketFile("0a1b") != "0a1b.sock" {
		t.Fatal("ReadySocketFile")
	}
}
