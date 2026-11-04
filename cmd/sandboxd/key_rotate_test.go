package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// TestKeyRotateWrapped walks stage → promote → retire on a wrapped key
// migrated from plaintext: each step edits the file, the plaintext-era
// notice clears when its key is retired, and rewrap and unwrap keep the
// ring.
func TestKeyRotateWrapped(t *testing.T) {
	dir, env, _ := keyEnv(t, map[string]string{"SB_CREDENTIAL_KEY_CUSTODY": "wrapped"})
	keyPath := filepath.Join(dir, "credential_encryption.key")
	key, _ := secrets.NewServerKey()
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runKey(t, "wrap", "--env-file", env); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(keyPath)
	steps := []struct {
		args []string
		out  string
		ring string
	}{
		{[]string{"--stage"}, "staged: key 1", "0=current 1=decrypt"},
		{[]string{"--promote"}, "promoted: key 1 is current, key 0", "0=decrypt 1=current"},
		{[]string{"--retire", "0"}, "retired: key 0", "0=retired 1=current"},
	}
	for _, st := range steps {
		out, err := runKey(t, append([]string{"rotate", "--env-file", env}, st.args...)...)
		if err != nil || !strings.Contains(out, st.out) || !strings.Contains(out, "ciphertext") {
			t.Fatalf("%v = %q %v", st.args, out, err)
		}
		status, err := runKey(t, "status", "--check", "--env-file", env)
		if err != nil || !strings.Contains(status, "server keys: "+st.ring) {
			t.Fatalf("%v status = %q %v", st.args, status, err)
		}
		if st.args[0] == "--stage" {
			if !strings.Contains(status, "migrated from plaintext") {
				t.Fatal("the plaintext-era notice cleared before its key was retired")
			}
			if _, err := runKey(t, "rotate", "--stage", "--env-file", env); !errors.Is(err, secrets.ErrRotationInProgress) {
				t.Fatalf("second stage = %v", err)
			}
		}
		if st.args[0] == "--retire" && strings.Contains(status, "migrated from plaintext") {
			t.Fatal("retiring the plaintext-era key kept the notice")
		}
	}
	if _, err := runKey(t, "rotate", "--retire", "1", "--env-file", env); err == nil || !strings.Contains(err.Error(), "is current") {
		t.Fatalf("retire current = %v", err)
	}
	if out, err := runKey(t, "rewrap", "--env-file", env); err != nil || !strings.Contains(out, "rewrapped") {
		t.Fatalf("rewrap ring = %q %v", out, err)
	}
	if out, err := runKey(t, "verify", "--env-file", env); err != nil || !strings.Contains(out, "ok:") {
		t.Fatalf("verify ring = %q %v", out, err)
	}
	out, err := runKey(t, "unwrap", "--to-file", "--i-understand-plaintext", "--env-file", env)
	if err != nil || !strings.Contains(out, "server-key ring in plaintext") {
		t.Fatalf("unwrap ring = %q %v", out, err)
	}
	ring, err := secrets.ReadKeyRingFile(keyPath + ".ring")
	if err != nil || secrets.RingSummary(ring.Ring) != "0:retired,1:current" {
		t.Fatalf("plaintext ring = %v", err)
	}
	if _, err := runKey(t, "unwrap", "--to-file", "--i-understand-plaintext", "--env-file", env); err == nil || !strings.Contains(err.Error(), "existing ring file") {
		t.Fatalf("second unwrap = %v", err)
	}
	if _, err := runKey(t, "rotate", "--stage", "--env-file", env); err != nil {
		// The wrapped file is still there and still rotates.
		t.Fatal(err)
	}
}

// TestKeyRotateFileCustody: with custody=file the ring file is written
// next to the key file and the retire of key 0 says to remove the key.
func TestKeyRotateFileCustody(t *testing.T) {
	dir, env, _ := keyEnv(t, nil)
	keyPath := filepath.Join(dir, "credential_encryption.key")
	if _, err := runKey(t, "rotate", "--stage", "--env-file", env); err == nil || !strings.Contains(err.Error(), "no server key to rotate") {
		t.Fatalf("no key = %v", err)
	}
	key, _ := secrets.NewServerKey()
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runKey(t, "rotate", "--stage", "--env-file", env); err != nil || !strings.Contains(out, "plaintext") {
		t.Fatalf("stage = %q %v", out, err)
	}
	if _, err := runKey(t, "rotate", "--promote", "--env-file", env); err != nil {
		t.Fatal(err)
	}
	if _, err := runKey(t, "rotate", "--promote", "--env-file", env); err == nil {
		t.Fatal("promoted with nothing staged")
	}
	out, err := runKey(t, "rotate", "--retire", "0", "--env-file", env)
	if err != nil || !strings.Contains(out, "remove the retired key itself") {
		t.Fatalf("retire 0 = %q %v", out, err)
	}
	status, err := runKey(t, "status", "--env-file", env)
	if err != nil || !strings.Contains(status, "keys: 0=retired 1=current") {
		t.Fatalf("status = %q %v", status, err)
	}
	// Migrating a rotated plaintext key wraps the whole ring.
	if out, err := runKey(t, "wrap", "--env-file", env); err != nil || !strings.Contains(out, "server-key ring") {
		t.Fatalf("wrap ring = %q %v", out, err)
	}
	f, err := secrets.ReadWrappedKeyFile(filepath.Join(dir, "credential_encryption.key.wrapped"))
	if err != nil || secrets.RingSummary(f.Entries()) != "0:retired,1:current" || !f.MigratedFromPlaintext {
		t.Fatalf("wrapped ring = %v", err)
	}
	if _, err := runKey(t, "wrap", "--env-file", env); err == nil || !strings.Contains(err.Error(), "refusing to replace") {
		t.Fatalf("second wrap = %v", err)
	}
	if err := os.WriteFile(keyPath+".ring", []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, _ := runKey(t, "status", "--env-file", env); !strings.Contains(status, "server-key ring file:") {
		t.Fatalf("broken ring status = %q", status)
	}
	for _, args := range [][]string{{"rotate", "--stage"}, {"wrap"}} {
		if _, err := runKey(t, append(args, "--env-file", env)...); err == nil {
			t.Fatalf("%v with a broken ring", args)
		}
	}
}

func TestKeyRotateArgs(t *testing.T) {
	_, env, _ := keyEnv(t, nil)
	for _, args := range [][]string{
		{"rotate"},
		{"rotate", "--stage", "--promote"},
		{"rotate", "--retire", "99999999999"},
	} {
		if _, err := runKey(t, append(args, "--env-file", env)...); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
	if err := keyRotate(context.Background(), config.Config{CredentialEncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}, "spin", 0, &strings.Builder{}); err == nil {
		t.Fatal("unknown step")
	}
	if got := ringLines([]secrets.RingEntry{{ID: 0, State: "current"}, {ID: 2, State: "decrypt"}}); got != "0=current 2=decrypt" {
		t.Fatal(got)
	}
	if entryByID(nil, 3).State != "" {
		t.Fatal("entryByID")
	}
}

// TestKeyRotateStageGate (eng D26): in cluster mode the stage waits for
// every live member to read a ring, as the local daemon's gossip gate says.
func TestKeyRotateStageGate(t *testing.T) {
	_, env, _ := keyEnv(t, map[string]string{
		"SB_ENABLE_CLUSTER":         "true",
		"SB_CLUSTER_BOOTSTRAP":      "true",
		"SB_GOSSIP_SECRET_KEY":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"SB_CLUSTER_TLS_DIR":        "/tmp/tls",
		"SB_CREDENTIAL_KEY_CUSTODY": "wrapped",
	})
	if _, err := runKey(t, "wrap", "--generate", "--seed", "--env-file", env); err != nil {
		t.Fatal(err)
	}
	orig := fetchRingGate
	t.Cleanup(func() { fetchRingGate = orig })
	cases := []struct {
		ready, known bool
		lagging      []string
		err          error
		want         string
	}{
		{err: errors.New("connection refused"), want: "cannot ask the local sandboxd"},
		{known: false, want: "predates server-key rotation"},
		{known: true, lagging: []string{"wrk-1 (fv 3)"}, want: "wrk-1 (fv 3)"},
		{known: true, ready: false, want: "has not rejoined"},
	}
	for _, tc := range cases {
		fetchRingGate = func(context.Context, config.Config) (bool, bool, []string, error) {
			return tc.ready, tc.known, tc.lagging, tc.err
		}
		if _, err := runKey(t, "rotate", "--stage", "--env-file", env); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
	fetchRingGate = func(context.Context, config.Config) (bool, bool, []string, error) { return true, true, nil, nil }
	if out, err := runKey(t, "rotate", "--stage", "--env-file", env); err != nil || !strings.Contains(out, "staged: key 1") {
		t.Fatalf("gate open = %q %v", out, err)
	}
}

// TestFetchRingGate reads the members API the way the CLI does.
func TestFetchRingGate(t *testing.T) {
	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/cluster/members" || r.Header.Get("Authorization") != "Bearer pat" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	p, _ := strconv.Atoi(port)
	cfg := config.Config{APIHost: host, APIPort: p, PATToken: "pat"}
	ctx := context.Background()

	status, body = 200, `{"members":[{"node_id":"a","alive":true,"fsm_ops_version":4},{"node_id":"b","alive":true,"fsm_ops_version":3},{"node_id":"c","alive":false,"fsm_ops_version":1}],"server_key_ring_ready":false}`
	ready, known, lagging, err := fetchRingGate(ctx, cfg)
	if err != nil || ready || !known || len(lagging) != 1 || lagging[0] != "b (fv 3)" {
		t.Fatalf("lagging = %v %v %v %v", ready, known, lagging, err)
	}
	status, body = 200, `{"members":[]}`
	if _, known, _, err := fetchRingGate(ctx, cfg); err != nil || known {
		t.Fatalf("old daemon = %v %v", known, err)
	}
	status, body = 500, "boom"
	if _, _, _, err := fetchRingGate(ctx, cfg); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("500 = %v", err)
	}
	status, body = 200, "{"
	if _, _, _, err := fetchRingGate(ctx, cfg); err == nil {
		t.Fatal("bad json")
	}
	srv.Close()
	if _, _, _, err := fetchRingGate(ctx, cfg); err == nil {
		t.Fatal("closed server")
	}
	// A wildcard bind is asked on loopback.
	if _, _, _, err := fetchRingGate(ctx, config.Config{APIHost: "0.0.0.0", APIPort: 1}); err == nil {
		t.Fatal("nothing listens on port 1")
	}
	if _, _, _, err := fetchRingGate(ctx, config.Config{APIHost: "bad host\x7f", APIPort: 1}); err == nil {
		t.Fatal("bad host")
	}
	if err := checkRingGate(ctx, config.Config{}); err != nil {
		t.Fatal("single node waits for no one")
	}
}
