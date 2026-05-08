package sshgateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// LoadOrGenerateHostKey returns an ssh.Signer for the host private key at
// path. If the file does not exist, an ed25519 key is generated and persisted
// with 0600 permissions. The parent directory is created with 0700 if needed.
func LoadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if path == "" {
		return nil, errors.New("ssh host key path is empty")
	}

	if data, err := os.ReadFile(path); err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse ssh host key %s: %w", path, err)
		}
		return signer, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read ssh host key %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create ssh host key directory: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "AerolVM host key")
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}
	encoded := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("write ssh host key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("parse generated ssh host key: %w", err)
	}
	return signer, nil
}

// ParseAuthorizedKey parses a single OpenSSH-format public key. Trailing
// comments and whitespace are tolerated.
func ParseAuthorizedKey(raw string) (ssh.PublicKey, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("authorized key is empty")
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return nil, fmt.Errorf("parse authorized key: %w", err)
	}
	return key, nil
}
