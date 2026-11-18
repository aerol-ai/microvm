package sshgateway

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
	"golang.org/x/crypto/ssh"
)

// The gateway's check of a key for a sandbox another node owns, and the
// key it names on every bridged call (node certificates get only what
// their role needs: the owner sends a node no key, and serves a node's
// bridged call only for the sandbox's key).
func TestRemoteKeyCheckNamesTheKey(t *testing.T) {
	signer, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "o"))
	if err != nil {
		t.Fatal(err)
	}
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	var offered string
	answer := func(match string, key string) *Gateway {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			offered = r.Header.Get(auditlog.SSHOfferedKeyHeader)
			if match != "" {
				w.Header().Set(auditlog.SSHKeyMatchHeader, match)
			}
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb-1", Status: models.SandboxStatusStarted, SSHPublicKey: key})
		}))
		t.Cleanup(srv.Close)
		return &Gateway{remoteBaseURL: srv.URL, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	}
	authorized := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	for name, tc := range map[string]struct {
		match, key string
		want       bool
	}{
		"an owner that answers yes, no key sent": {"true", "", true},
		"an owner that answers no":               {"false", authorized, false},
		"an older owner that sends the key":      {"", authorized, true},
		"an older owner, another key":            {"", string(ssh.MarshalAuthorizedKey(other.PublicKey())), false},
		"no answer and no key":                   {"", "", false},
	} {
		g := answer(tc.match, tc.key)
		perms, ok := g.authorizeRemoteSSH(context.Background(), "sb-1", "shell", "", signer.PublicKey())
		if ok != tc.want {
			t.Errorf("%s: %v", name, ok)
			continue
		}
		if offered != fp {
			t.Errorf("%s: offered %q, want %q", name, offered, fp)
		}
		if ok && perms.Extensions["key_fp"] != fp {
			t.Errorf("%s: permissions name %q", name, perms.Extensions["key_fp"])
		}
	}
	// Every bridged call names it.
	b := (&Gateway{}).bridgeSession(withBridgeKey(context.Background(), fp), "sb-1", "shell", "")
	h := http.Header{}
	b.attest(h)
	call, ok := TakeBridgedCall(h, "sb-1")
	if !ok || call.KeyFingerprint != fp {
		t.Fatalf("attested %+v %v", call, ok)
	}
}
