//go:build integration

package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestVaultLive runs the vault provider against a real Vault or OpenBao
// (plans/customer-key-custody.md Phase 2; the Phase 6 CI job reuses it). It
// skips unless SB_TEST_VAULT_ADDR and SB_TEST_VAULT_ROOT_TOKEN name a dev
// server; the root token only sets up keys and policies here, never reaches
// the provider. SB_TEST_VAULT_AGENT_ADDR, when set, is a Vault Agent API proxy
// whose auto-auth token has the update-only policy "aerolvm-itest".
func TestVaultLive(t *testing.T) {
	addr, root := os.Getenv("SB_TEST_VAULT_ADDR"), os.Getenv("SB_TEST_VAULT_ROOT_TOKEN")
	if addr == "" || root == "" {
		t.Skip("SB_TEST_VAULT_ADDR / SB_TEST_VAULT_ROOT_TOKEN not set; skipping live Vault")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin := vaultAdmin{t: t, addr: addr, token: root}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	key := "aerolvm-itest-" + hex.EncodeToString(suffix)
	admin.do("POST", "sys/mounts/transit", map[string]any{"type": "transit"}, true)
	admin.do("POST", "transit/keys/"+key, map[string]any{"type": "aes256-gcm96"}, false)
	admin.do("PUT", "sys/policies/acl/aerolvm-itest-"+key, map[string]any{"policy": fmt.Sprintf(
		`path "transit/encrypt/%[1]s" { capabilities = ["update"] }
path "transit/decrypt/%[1]s" { capabilities = ["update"] }
path "transit/keys/%[1]s" { capabilities = ["read"] }
path "sys/capabilities-self" { capabilities = ["update"] }`, key)}, false)
	admin.do("PUT", "sys/policies/acl/aerolvm-itest-broad-"+key, map[string]any{"policy": fmt.Sprintf(
		`path "transit/encrypt/%[1]s" { capabilities = ["create", "update"] }
path "transit/decrypt/%[1]s" { capabilities = ["update"] }
path "sys/capabilities-self" { capabilities = ["update"] }`, key)}, false)
	narrow := admin.newToken("aerolvm-itest-" + key)
	broad := admin.newToken("aerolvm-itest-broad-" + key)

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	writeToken := func(tok string) {
		if err := os.WriteFile(tokenPath, []byte(tok), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	newWrapper := func(o VaultOptions) DataKeyWrapper {
		w, err := NewWrapper(ctx, ProviderOptions{Name: ProviderVault, Vault: o})
		if err != nil {
			t.Fatalf("NewWrapper: %v", err)
		}
		return w
	}

	writeToken(narrow)
	w := newWrapper(VaultOptions{Addr: addr, KeyName: key, TokenFile: tokenPath, NodeID: "itest"})
	if err := CanaryWrapUnwrap(ctx, w); err != nil {
		t.Fatalf("canary with the update-only token: %v", err)
	}
	encCtx := map[string]string{"aerolvm.ref": "itest"}
	v1, err := w.Wrap(ctx, []byte("data-key-v1"), encCtx)
	if err != nil || WrappedKeyBackend(v1) != ProviderVault {
		t.Fatalf("Wrap = %q %v", v1, err)
	}
	if _, err := w.Unwrap(ctx, v1, map[string]string{"aerolvm.ref": "other"}); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("wrong associated data = %v, want ErrDecryptFailed", err)
	}

	for name, tok := range map[string]string{"root": root, "create": broad} {
		writeToken(tok)
		if _, err := NewWrapper(ctx, ProviderOptions{Name: ProviderVault, Vault: VaultOptions{Addr: addr, KeyName: key, TokenFile: tokenPath}}); !IsVaultPolicyError(err) {
			t.Fatalf("%s token at boot = %v, want the policy refusal", name, err)
		}
	}
	writeToken(narrow)

	if agent := os.Getenv("SB_TEST_VAULT_AGENT_ADDR"); agent != "" {
		viaAgent := newWrapper(VaultOptions{Addr: agent, KeyName: key})
		got, err := viaAgent.Unwrap(ctx, v1, encCtx)
		if err != nil || string(got) != "data-key-v1" {
			t.Fatalf("through the Agent proxy with no token in sandboxd = %q %v", got, err)
		}
	}

	// Rotate, then retire version 1: a stale row, not a revoke.
	admin.do("POST", "transit/keys/"+key+"/rotate", nil, false)
	v2, err := w.Wrap(ctx, []byte("data-key-v2"), encCtx)
	if err != nil {
		t.Fatal(err)
	}
	admin.do("POST", "transit/keys/"+key+"/config", map[string]any{"min_decryption_version": 2}, false)
	if _, err := w.Unwrap(ctx, v1, encCtx); !errors.Is(err, ErrKeyVersionRetired) {
		t.Fatalf("retired version = %v, want ErrKeyVersionRetired", err)
	}

	// The key owner deletes the key: a revoke, and the update-only token
	// cannot recreate it on encrypt.
	admin.do("POST", "transit/keys/"+key+"/config", map[string]any{"deletion_allowed": true}, false)
	admin.do("DELETE", "transit/keys/"+key, nil, false)
	if _, err := w.Unwrap(ctx, v2, encCtx); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("deleted key = %v, want ErrKeyRevoked", err)
	}
	if _, err := w.Wrap(ctx, []byte("x"), nil); !errors.Is(err, ErrProviderDenied) {
		t.Fatalf("encrypt after delete = %v, want ErrProviderDenied", err)
	}
	if status := admin.do("GET", "transit/keys/"+key, nil, true); status != http.StatusNotFound {
		t.Fatalf("key after an encrypt attempt: status %d, want 404 (not recreated)", status)
	}
}

type vaultAdmin struct {
	t     *testing.T
	addr  string
	token string
}

// do calls Vault as root; with tolerate set it returns any status instead of
// failing on a non-2xx.
func (a vaultAdmin) do(method, path string, body any, tolerate bool) int {
	a.t.Helper()
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	req, err := http.NewRequest(method, a.addr+"/v1/"+path, bytes.NewReader(payload))
	if err != nil {
		a.t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", a.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer res.Body.Close()
	if !tolerate && res.StatusCode/100 != 2 {
		a.t.Fatalf("%s %s: %d", method, path, res.StatusCode)
	}
	return res.StatusCode
}

func (a vaultAdmin) newToken(policy string) string {
	a.t.Helper()
	payload, _ := json.Marshal(map[string]any{"policies": []string{policy}, "no_default_policy": true, "ttl": "10m"})
	req, _ := http.NewRequest("POST", a.addr+"/v1/auth/token/create", bytes.NewReader(payload))
	req.Header.Set("X-Vault-Token", a.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer res.Body.Close()
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil || out.Auth.ClientToken == "" {
		a.t.Fatalf("create token for %s: %v", policy, err)
	}
	return out.Auth.ClientToken
}
