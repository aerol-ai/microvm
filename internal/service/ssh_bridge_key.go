package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

// The SSH gateway on another node bridges a session to this owner's
// sessions API as itself (node certificates get only what their role
// needs). The x/crypto/ssh server never hands the client's signature to
// the gateway, so the gateway cannot pass proof of the key on. What it can
// pass is which key the client proved it holds, and only a node that saw
// that key (the gateway the client connected to) can name it, because the
// sandbox's key never leaves its owner to a node:
//
//	gateway  GET /v1/sandboxes/{id} with the offered key's fingerprint
//	owner    answers whether it is the sandbox's key (X-Aerol-Ssh-Key-Match)
//	         and, to a node, sends no key
//	gateway  every bridged sessions call names the fingerprint
//	owner    serves a node's bridged call only for the sandbox's key
//
// Until every member runs a build that does this (servers sign, so the
// active cluster version is 22: server_signing.go), an older gateway reads
// the key and names none, and is served as before.

// ErrSSHBridgeKey is a bridged sessions call that does not name the
// sandbox's SSH key (403).
var ErrSSHBridgeKey = errors.New("ssh bridge: the call does not name this sandbox's key")

// sshKeyFingerprint is the SHA256 fingerprint of an authorized key line, or
// "" when there is none or it does not parse.
func sshKeyFingerprint(authorized string) string {
	if strings.TrimSpace(authorized) == "" {
		return ""
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(key)
}

// SSHKeyMatches reports whether fingerprint is the SHA256 fingerprint of
// the sandbox's key, read from this node's row.
func (s *Service) SSHKeyMatches(ctx context.Context, sandboxID, fingerprint string) (bool, error) {
	sb, err := s.store.Get(ctx, strings.TrimSpace(sandboxID))
	if err != nil {
		return false, err
	}
	want := sshKeyFingerprint(sb.SSHPublicKey)
	fingerprint = strings.TrimSpace(fingerprint)
	return want != "" && fingerprint != "" && subtle.ConstantTimeCompare([]byte(want), []byte(fingerprint)) == 1, nil
}

// CheckSSHBridgeKey refuses a bridged call that does not name the
// sandbox's key, once every member runs a build that names it.
func (s *Service) CheckSSHBridgeKey(ctx context.Context, sandboxID, fingerprint string) error {
	if strings.TrimSpace(fingerprint) == "" && !s.ServerSigningOn() {
		return nil
	}
	ok, err := s.SSHKeyMatches(ctx, sandboxID, fingerprint)
	if err != nil {
		return err
	}
	if !ok {
		return ErrSSHBridgeKey
	}
	return nil
}

// KeepsSSHKeyFrom reports whether a node caller's sandbox read keeps the
// sandbox's SSH key: only an older gateway's, which checks the key itself,
// while one may still be running (offered says the caller is new).
func (s *Service) KeepsSSHKeyFrom(offered bool) bool {
	return !offered && !s.ServerSigningOn()
}
