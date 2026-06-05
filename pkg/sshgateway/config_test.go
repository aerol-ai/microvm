package sshgateway

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestLoadOrGenerateHostKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host_key")

	signer1, err := LoadOrGenerateHostKey(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if signer1 == nil {
		t.Fatal("nil signer returned")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat host key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("host key mode = %v, want 0600", info.Mode().Perm())
	}

	signer2, err := LoadOrGenerateHostKey(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !bytes.Equal(signer1.PublicKey().Marshal(), signer2.PublicKey().Marshal()) {
		t.Fatal("second load returned a different key")
	}
}

func TestLoadOrGenerateHostKeyErrors(t *testing.T) {
	// Empty path
	if _, err := LoadOrGenerateHostKey(""); err == nil {
		t.Error("expected error for empty path")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "host_key")

	// Read error (directory as a file)
	if _, err := LoadOrGenerateHostKey(dir); err == nil {
		t.Error("expected error reading a directory as a file")
	}

	// Parse error (invalid private key format)
	os.WriteFile(path, []byte("not a valid key"), 0o600)
	if _, err := LoadOrGenerateHostKey(path); err == nil {
		t.Error("expected error parsing invalid key")
	}

	// Unwritable directory
	readonlyDir := filepath.Join(dir, "readonly")
	os.MkdirAll(readonlyDir, 0o500)
	unwritablePath := filepath.Join(readonlyDir, "new_dir", "host_key")
	if _, err := LoadOrGenerateHostKey(unwritablePath); err == nil {
		t.Error("expected error creating directory in unwritable parent")
	}
}

func TestParseAuthorizedKey(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{
			name:    "empty",
			raw:     "  ",
			wantErr: true,
		},
		{
			name:    "garbage",
			raw:     "not a key",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAuthorizedKey(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseAuthorizedKey err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseAuthorizedKeyAcceptsGenerated(t *testing.T) {
	// Round-trip a freshly generated host key as an authorized public key to
	// avoid hard-coding a specific OpenSSH-format string in the test.
	dir := t.TempDir()
	signer, err := LoadOrGenerateHostKey(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	authorized := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	pub, err := ParseAuthorizedKey(authorized)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	if !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
		t.Fatal("parsed key does not match generated key")
	}
}
