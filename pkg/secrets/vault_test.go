package secrets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
)

// scriptedVault answers each call with the next scripted reply, after
// recording the path and body.
type scriptedVault struct {
	replies []scriptedReply
	paths   []string
	bodies  []map[string]any
}

type scriptedReply struct {
	status int
	resp   vaultResponse
	err    error
}

func (s *scriptedVault) call(_ context.Context, path string, body any) (int, vaultResponse, error) {
	s.paths = append(s.paths, path)
	b, _ := body.(map[string]any)
	s.bodies = append(s.bodies, b)
	if len(s.replies) == 0 {
		return 0, vaultResponse{}, errors.New("no scripted reply")
	}
	r := s.replies[0]
	s.replies = s.replies[1:]
	return r.status, r.resp, r.err
}

func capsReply(enc, dec []string) scriptedReply {
	toAny := func(in []string) []any {
		out := make([]any, len(in))
		for i, s := range in {
			out[i] = s
		}
		return out
	}
	return scriptedReply{status: 200, resp: vaultResponse{Data: map[string]any{
		"transit/encrypt/k": toAny(enc), "transit/decrypt/k": toAny(dec),
	}}}
}

func TestVaultWrapChecksPolicyOnce(t *testing.T) {
	api := &scriptedVault{replies: []scriptedReply{
		capsReply([]string{"update"}, []string{"update"}),
		{status: 200, resp: vaultResponse{Data: map[string]any{"ciphertext": "vault:v1:abc"}}},
		{status: 200, resp: vaultResponse{Data: map[string]any{"ciphertext": "vault:v2:def"}}},
	}}
	v := newVaultWithAPI(api, "transit", "k")
	ctx := context.Background()
	encCtx := map[string]string{"aerolvm.ref": "r1"}
	got, err := v.Wrap(ctx, []byte("dek"), encCtx)
	if err != nil || string(got) != "vault:v1:abc" {
		t.Fatalf("Wrap = %q %v", got, err)
	}
	if _, err := v.Wrap(ctx, []byte("dek"), nil); err != nil {
		t.Fatal(err)
	}
	want := []string{"sys/capabilities-self", "transit/encrypt/k", "transit/encrypt/k"}
	if strings.Join(api.paths, ",") != strings.Join(want, ",") {
		t.Fatalf("paths = %v, want %v (policy checked once)", api.paths, want)
	}
	if api.bodies[1]["plaintext"] != base64.StdEncoding.EncodeToString([]byte("dek")) ||
		api.bodies[1]["associated_data"] != base64.StdEncoding.EncodeToString(encryptionContextAAD(encCtx)) {
		t.Fatalf("encrypt body = %v", api.bodies[1])
	}
	if _, ok := api.bodies[2]["associated_data"]; ok {
		t.Fatal("an empty encryption context must send no associated_data")
	}
}

// Phase 0: with create on the encrypt path Transit recreates a deleted key,
// which would undo a revoke. Such a token never reaches encrypt.
func TestVaultPolicyRefusals(t *testing.T) {
	cases := []struct {
		name     string
		enc, dec []string
		want     string
	}{
		{"create", []string{"create", "update"}, []string{"update"}, `"create"`},
		{"sudo", []string{"update", "sudo"}, []string{"update"}, `"sudo"`},
		{"root", []string{"root"}, []string{"root"}, `"root"`},
		{"no update on encrypt", []string{"read"}, []string{"update"}, `needs "update"`},
		{"no update on decrypt", []string{"update"}, nil, `needs "update"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := &scriptedVault{replies: []scriptedReply{capsReply(tc.enc, tc.dec)}}
			_, err := newVaultWithAPI(api, "transit", "k").Wrap(context.Background(), []byte("dek"), nil)
			if !IsVaultPolicyError(err) || !errors.Is(err, ErrProviderDenied) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v", err)
			}
			if len(api.paths) != 1 {
				t.Fatalf("encrypt ran after a policy refusal: %v", api.paths)
			}
		})
	}
}

// A policy check that could not reach Vault is not remembered.
func TestVaultPolicyRetriedAfterOutage(t *testing.T) {
	api := &scriptedVault{replies: []scriptedReply{
		{err: ErrProviderUnavailable},
		{status: 503, resp: vaultResponse{Errors: []string{"Vault is sealed"}}},
		capsReply([]string{"update"}, []string{"update"}),
		{status: 200, resp: vaultResponse{Data: map[string]any{"ciphertext": "vault:v1:x"}}},
	}}
	v := newVaultWithAPI(api, "transit", "k")
	for i, want := range []error{ErrProviderUnavailable, ErrProviderUnavailable, nil} {
		if _, err := v.Wrap(context.Background(), []byte("d"), nil); !errors.Is(err, want) || (want == nil && err != nil) {
			t.Fatalf("attempt %d = %v, want %v", i, err, want)
		}
	}
}

func TestClassifyVault(t *testing.T) {
	cases := []struct {
		op     string
		status int
		errs   []string
		want   error
	}{
		{"decrypt", 429, nil, ErrProviderThrottled},
		{"encrypt", 403, []string{"permission denied"}, ErrProviderDenied},
		{"decrypt", 400, []string{"encryption key not found"}, ErrKeyRevoked},
		{"encrypt", 400, []string{"encryption key not found"}, ErrKeyRevoked},
		{"decrypt", 400, []string{"ciphertext or signature version is disallowed by policy (too old)"}, ErrKeyVersionRetired},
		{"decrypt", 400, []string{"cipher: message authentication failed"}, ErrDecryptFailed},
		{"encrypt", 400, []string{"invalid request"}, ErrProviderUnavailable},
		{"decrypt", 503, []string{"Vault is sealed"}, ErrProviderUnavailable},
		{"decrypt", 404, nil, ErrProviderUnavailable},
		{"encrypt", 307, nil, ErrProviderUnavailable},
	}
	for _, tc := range cases {
		if err := classifyVault(tc.op, tc.status, tc.errs); !errors.Is(err, tc.want) {
			t.Fatalf("%s %d %v = %v, want %v", tc.op, tc.status, tc.errs, err, tc.want)
		}
	}
	long := classifyVault("decrypt", 500, []string{strings.Repeat("x", 500)})
	if len(long.Error()) > vaultErrorTextMax+80 {
		t.Fatalf("error text not bounded: %d bytes", len(long.Error()))
	}
}

func TestVaultUnwrap(t *testing.T) {
	ctx := context.Background()
	encCtx := map[string]string{"aerolvm.ref": "r1"}
	api := &scriptedVault{replies: []scriptedReply{
		{status: 200, resp: vaultResponse{Data: map[string]any{"plaintext": base64.StdEncoding.EncodeToString([]byte("dek"))}}},
		{status: 200, resp: vaultResponse{Data: map[string]any{"plaintext": "%%%"}}},
		{status: 400, resp: vaultResponse{Errors: []string{"encryption key not found"}}},
		{err: ErrProviderUnavailable},
	}}
	v := newVaultWithAPI(api, "transit", "k")
	if got, err := v.Unwrap(ctx, []byte("vault:v1:abc"), encCtx); err != nil || string(got) != "dek" {
		t.Fatalf("Unwrap = %q %v", got, err)
	}
	if api.paths[0] != "transit/decrypt/k" || api.bodies[0]["ciphertext"] != "vault:v1:abc" || api.bodies[0]["associated_data"] == nil {
		t.Fatalf("decrypt call = %v %v", api.paths, api.bodies[0])
	}
	if _, err := v.Unwrap(ctx, []byte("vault:v1:abc"), nil); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("bad plaintext = %v", err)
	}
	if _, err := v.Unwrap(ctx, []byte("vault:v1:abc"), nil); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("deleted key = %v", err)
	}
	if _, err := v.Unwrap(ctx, []byte("vault:v1:abc"), nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("transport error = %v", err)
	}
	if _, err := v.Unwrap(ctx, []byte("p11:1:abc"), nil); !errors.Is(err, ErrDecryptFailed) || len(api.paths) != 4 {
		t.Fatalf("non-vault ciphertext = %v (calls %d)", err, len(api.paths))
	}
}

func TestVaultWrapRejectsOddReplies(t *testing.T) {
	v := newVaultWithAPI(&scriptedVault{replies: []scriptedReply{
		capsReply([]string{"update"}, []string{"update"}),
		{status: 200, resp: vaultResponse{Data: map[string]any{"ciphertext": "not-vault"}}},
		{status: 403, resp: vaultResponse{Errors: []string{"permission denied"}}},
		{err: ErrProviderThrottled},
	}}, "transit", "k")
	for _, want := range []error{ErrProviderUnavailable, ErrProviderDenied, ErrProviderThrottled} {
		if _, err := v.Wrap(context.Background(), []byte("d"), nil); !errors.Is(err, want) {
			t.Fatalf("Wrap = %v, want %v", err, want)
		}
	}
}

func TestNewVaultValidation(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(notPEM, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		opts VaultOptions
		want string
	}{
		{"no addr", VaultOptions{KeyName: "k"}, "SB_SECRET_VAULT_ADDR is required"},
		{"plain http to a remote host", VaultOptions{Addr: "http://vault.example:8200", KeyName: "k"}, "non-loopback"},
		{"other scheme", VaultOptions{Addr: "ftp://vault.example", KeyName: "k"}, "must use https"},
		{"credentials in url", VaultOptions{Addr: "https://u:p@vault.example", KeyName: "k"}, "no credentials"},
		{"no host", VaultOptions{Addr: "https://", KeyName: "k"}, "with a host"},
		{"bad key name", VaultOptions{Addr: "https://vault.example", KeyName: "a/b"}, "SB_SECRET_VAULT_KEY_NAME"},
		{"dot-dot mount", VaultOptions{Addr: "https://vault.example", KeyName: "k", Mount: "../sys"}, "SB_SECRET_VAULT_TRANSIT_MOUNT"},
		{"empty segment mount", VaultOptions{Addr: "https://vault.example", KeyName: "k", Mount: "a//b"}, "SB_SECRET_VAULT_TRANSIT_MOUNT"},
		{"missing ca file", VaultOptions{Addr: "https://vault.example", KeyName: "k", CACert: filepath.Join(dir, "none.pem")}, "read SB_SECRET_VAULT_CACERT"},
		{"ca file without a cert", VaultOptions{Addr: "https://vault.example", KeyName: "k", CACert: notPEM}, "holds no PEM certificate"},
	}
	for _, tc := range cases {
		if _, err := NewVault(tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	for _, addr := range []string{"http://127.0.0.1:8200", "http://localhost:8100/", "http://[::1]:8200", "https://vault.example:8200/prefix"} {
		v, err := NewVault(VaultOptions{Addr: addr, KeyName: "k", Mount: "/team/transit/"})
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		if v.encPath != "team/transit/encrypt/k" {
			t.Fatalf("encPath = %q", v.encPath)
		}
	}
	if (VaultOptions{}).Configured() || !(VaultOptions{KeyName: "k"}).Configured() {
		t.Fatal("Configured")
	}
}

// fakeTransit is a Vault Transit server for tests: AES-GCM is not needed, a
// map from ciphertext id to (plaintext, aad) proves the client's wire format.
type fakeTransit struct {
	t         *testing.T
	mu        sync.Mutex
	rows      map[string][2]string
	deleted   bool
	caps      []any
	tokens    map[string]bool
	headers   []http.Header
	redirect  bool
	forbidden int
}

func newFakeTransit(t *testing.T) *fakeTransit {
	return &fakeTransit{t: t, rows: map[string][2]string{}, caps: []any{"update"}, tokens: map[string]bool{}}
}

func (f *fakeTransit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headers = append(f.headers, r.Header.Clone())
	reply := func(status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	if f.redirect {
		http.Redirect(w, r, "https://elsewhere.example/v1/x", http.StatusTemporaryRedirect)
		return
	}
	if len(f.tokens) > 0 && !f.tokens[r.Header.Get("X-Vault-Token")] {
		f.forbidden++
		reply(403, map[string]any{"errors": []string{"permission denied"}})
		return
	}
	var body map[string]string
	if r.URL.Path != "/v1/sys/capabilities-self" {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	switch r.URL.Path {
	case "/v1/sys/capabilities-self":
		reply(200, map[string]any{"data": map[string]any{"transit/encrypt/k": f.caps, "transit/decrypt/k": []any{"update"}}})
	case "/v1/transit/encrypt/k":
		if f.deleted {
			reply(403, map[string]any{"errors": []string{"permission denied"}})
			return
		}
		id := make([]byte, 8)
		_, _ = rand.Read(id)
		ct := "vault:v1:" + hex.EncodeToString(id)
		f.rows[ct] = [2]string{body["plaintext"], body["associated_data"]}
		reply(200, map[string]any{"data": map[string]any{"ciphertext": ct}})
	case "/v1/transit/decrypt/k":
		row, ok := f.rows[body["ciphertext"]]
		switch {
		case f.deleted:
			reply(400, map[string]any{"errors": []string{"encryption key not found"}})
		case !ok || row[1] != body["associated_data"]:
			reply(400, map[string]any{"errors": []string{"cipher: message authentication failed"}})
		default:
			reply(200, map[string]any{"data": map[string]any{"plaintext": row[0]}})
		}
	default:
		w.WriteHeader(404)
		_, _ = w.Write([]byte("<html>not found</html>"))
	}
}

// startTransit serves f over TLS and returns options trusting its cert.
func startTransit(t *testing.T, f *fakeTransit) VaultOptions {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return VaultOptions{Addr: srv.URL, KeyName: "k", CACert: ca, Namespace: "team-a", NodeID: "node-1"}
}

func TestVaultOverHTTPS(t *testing.T) {
	f := newFakeTransit(t)
	opts := startTransit(t, f)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("tok-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts.TokenFile = tokenPath
	f.tokens["tok-1"] = true
	v, err := NewVault(opts)
	if err != nil {
		t.Fatal(err)
	}
	encCtx := map[string]string{"aerolvm.ref": "r1"}
	ctx := auditlog.ContextWithCorrelationID(context.Background(), "corr-123")
	wrapped, err := v.Wrap(ctx, []byte("data-key"), encCtx)
	if err != nil || WrappedKeyBackend(wrapped) != ProviderVault {
		t.Fatalf("Wrap = %q %v", wrapped, err)
	}
	got, err := v.Unwrap(ctx, wrapped, encCtx)
	if err != nil || string(got) != "data-key" {
		t.Fatalf("Unwrap = %q %v", got, err)
	}
	if _, err := v.Unwrap(ctx, wrapped, map[string]string{"aerolvm.ref": "other"}); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("wrong context = %v", err)
	}
	h := f.headers[len(f.headers)-1]
	if h.Get("X-Vault-Token") != "tok-1" || h.Get("X-Vault-Namespace") != "team-a" || h.Get(CorrelationHeader) != "corr-123" || h.Get("X-Vault-Request") != "true" {
		t.Fatalf("headers = %v", h)
	}

	// Agent renews the token: the next call reads the new file.
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(tokenPath, []byte("tok-2-renewed"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.tokens = map[string]bool{"tok-2-renewed": true}
	f.mu.Unlock()
	if _, err := v.Unwrap(ctx, wrapped, encCtx); err != nil {
		t.Fatalf("after token renewal = %v", err)
	}

	// The key owner deletes the key: a revoke, not a decrypt failure.
	f.mu.Lock()
	f.deleted = true
	f.mu.Unlock()
	if _, err := v.Unwrap(ctx, wrapped, encCtx); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("deleted key = %v", err)
	}
}

// A 403 reads the token file once more; a changed token gets one more try,
// an unchanged one is reported as denied after a single request.
func TestVaultTokenReloadOn403(t *testing.T) {
	f := newFakeTransit(t)
	opts := startTransit(t, f)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts.TokenFile = tokenPath
	v, err := NewVault(opts)
	if err != nil {
		t.Fatal(err)
	}
	f.tokens["new"] = true
	h := v.api.(*vaultHTTP)
	if _, err := h.token.get(false); err != nil { // cache "old" with its mtime
		t.Fatal(err)
	}
	// Same size and a restored mtime: only the forced read after a 403 sees it.
	fi, _ := os.Stat(tokenPath)
	if err := os.WriteFile(tokenPath, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tokenPath, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	status, _, err := h.call(context.Background(), "transit/decrypt/k", map[string]any{"ciphertext": "vault:v1:none"})
	if err != nil || status != 400 || f.forbidden != 1 {
		t.Fatalf("after reload status %d err %v forbidden %d", status, err, f.forbidden)
	}
	f.tokens = map[string]bool{"other": true}
	status, _, err = h.call(context.Background(), "transit/decrypt/k", map[string]any{"ciphertext": "x"})
	if err != nil || status != 403 || f.forbidden != 2 {
		t.Fatalf("unchanged token: status %d err %v forbidden %d (want one request)", status, err, f.forbidden)
	}
}

func TestVaultHTTPEdges(t *testing.T) {
	f := newFakeTransit(t)
	opts := startTransit(t, f)
	v, err := NewVault(opts)
	if err != nil {
		t.Fatal(err)
	}
	h := v.api.(*vaultHTTP)
	ctx := ContextWithBackgroundPurpose(context.Background(), "recheck")

	// No token file: Agent's proxy adds the token, sandboxd sends none.
	if status, _, err := h.call(ctx, "transit/encrypt/k", map[string]any{"plaintext": "AA=="}); err != nil || status != 200 {
		t.Fatalf("proxy mode = %d %v", status, err)
	}
	last := f.headers[len(f.headers)-1]
	if last.Get("X-Vault-Token") != "" || last.Get(CorrelationHeader) != "aerolvm-background:recheck:node-1" {
		t.Fatalf("headers = %v", last)
	}
	// A caller-supplied id that a header must not carry is dropped.
	bad := auditlog.ContextWithCorrelationID(context.Background(), "a b\tc")
	if _, _, err := h.call(bad, "transit/encrypt/k", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if got := f.headers[len(f.headers)-1].Get(CorrelationHeader); got != "" {
		t.Fatalf("unsafe correlation id forwarded: %q", got)
	}
	// A non-JSON reply still classifies by status.
	if status, resp, err := h.call(context.Background(), "nope", map[string]any{}); err != nil || status != 404 || len(resp.Errors) != 0 {
		t.Fatalf("html 404 = %d %v %v", status, resp, err)
	}
	// Redirects are not followed: X-Vault-Token must not travel to them.
	f.mu.Lock()
	f.redirect = true
	f.mu.Unlock()
	if status, _, err := h.call(context.Background(), "transit/encrypt/k", map[string]any{}); err != nil || status != http.StatusTemporaryRedirect {
		t.Fatalf("redirect = %d %v", status, err)
	}
	// A body that cannot be encoded never reaches the wire.
	if _, _, err := h.call(context.Background(), "x", map[string]any{"c": make(chan int)}); err == nil {
		t.Fatal("unencodable body accepted")
	}
	// Nothing listening.
	down, err := NewVault(VaultOptions{Addr: "http://127.0.0.1:1", KeyName: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := down.Unwrap(context.Background(), []byte("vault:v1:x"), nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("connection refused = %v", err)
	}
}

func TestVaultTokenFileErrors(t *testing.T) {
	dir := t.TempDir()
	missing := &tokenFile{path: filepath.Join(dir, "none")}
	if _, err := missing.get(false); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("missing token file = %v", err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&tokenFile{path: empty}).get(false); !errors.Is(err, ErrProviderUnavailable) || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("empty token file = %v", err)
	}
	unreadable := filepath.Join(dir, "dir")
	if err := os.Mkdir(unreadable, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := (&tokenFile{path: unreadable}).get(false); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("directory as token file = %v", err)
	}
	v := &vaultHTTP{token: &tokenFile{path: filepath.Join(dir, "none")}}
	if _, _, err := v.call(context.Background(), "x", nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("call without a token file = %v", err)
	}
}

// Through NewWrapper: a vault node seals and opens through the router and the
// limiter; a token that may create keys stops the boot; a Vault that is down
// at boot does not.
func TestNewWrapperVault(t *testing.T) {
	ctx := context.Background()
	f := newFakeTransit(t)
	opts := startTransit(t, f)
	w, err := NewWrapper(ctx, ProviderOptions{Name: "vault", Vault: opts})
	if err != nil {
		t.Fatal(err)
	}
	if err := CanaryWrapUnwrap(ctx, w); err != nil {
		t.Fatalf("canary = %v", err)
	}
	f.mu.Lock()
	f.caps = []any{"create", "update"}
	f.mu.Unlock()
	if _, err := NewWrapper(ctx, ProviderOptions{Name: "vault", Vault: opts}); !IsVaultPolicyError(err) {
		t.Fatalf("create capability at boot = %v", err)
	}
	if _, err := NewWrapper(ctx, ProviderOptions{Name: "vault", Vault: VaultOptions{Addr: "http://127.0.0.1:1", KeyName: "k"}}); err != nil {
		t.Fatalf("vault down at boot must not stop NewWrapper: %v", err)
	}
	if _, err := NewWrapper(ctx, ProviderOptions{Name: "vault"}); err == nil {
		t.Fatal("vault without an address must fail")
	}
}

// Step 1 of a switch from AWS KMS to Vault: the node still seals with AWS KMS
// but already has Vault settings, so it opens a row a switched node sealed
// with Vault (§12, eng D8).
func TestNewWrapperOpensOtherBackend(t *testing.T) {
	ctx := ContextWithIncarnationID(context.Background(), "inc-1")
	f := newFakeTransit(t)
	opts := startTransit(t, f)
	switched, err := NewWrapper(ctx, ProviderOptions{Name: "vault", Vault: opts})
	if err != nil {
		t.Fatal(err)
	}
	blobs := newMemBlobStore()
	h, err := NewKMSProvider(switched, blobs).Put(ctx, "sb", Secrets{Registry: &models.RegistryAuth{Password: "p"}}, []string{"n"})
	if err != nil {
		t.Fatal(err)
	}
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	notYet, err := NewWrapper(ctx, ProviderOptions{Name: "awskms", Wrapper: fake, Vault: opts})
	if err != nil {
		t.Fatal(err)
	}
	bag, err := NewKMSProvider(notYet, blobs).Open(ctx, "sb", h, "n")
	if err != nil || bag.Registry == nil || bag.Registry.Password != "p" {
		t.Fatalf("awskms node opening a vault row = %+v %v", bag, err)
	}
	// Without Vault settings the same node names what is missing.
	bare, err := NewWrapper(ctx, ProviderOptions{Name: "awskms", Wrapper: fake})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKMSProvider(bare, blobs).Open(ctx, "sb", h, "n"); !errors.Is(err, ErrProviderUnavailable) || !strings.Contains(err.Error(), "no vault settings") {
		t.Fatalf("no vault settings = %v", err)
	}
	if _, err := NewWrapper(ctx, ProviderOptions{Name: "awskms", Wrapper: fake, Vault: VaultOptions{KeyName: "k"}}); err == nil {
		t.Fatal("partial vault settings must fail")
	}
}
