package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Worker and ingress nodes without the operator PAT.
//
// The operator PAT is an admin credential that works from anywhere. A
// worker or ingress node does not need it: it calls its peers with its
// node cert alone, and it only has to check the PAT an operator sends it.
// So a node the join service joins without the PAT gets the PAT's SHA-256
// instead (SB_PAT_TOKEN_SHA256). A copy of that node's files then gives an
// attacker no admin credential, while the node still accepts the PAT.
//
// install.sh always writes some SB_PAT_TOKEN. On such a node it is a
// random token of its own, which this node accepts only from a local tool
// (a loopback caller, pkg/api/auth.go) and never sends to a peer.

// PATSHA256 is the lowercase hex SHA-256 of a token: the form
// SB_PAT_TOKEN_SHA256 holds. An operator can make it with
// `printf %s "$SB_PAT_TOKEN" | sha256sum`.
func PATSHA256(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// PATMatchesSHA256 reports whether token's SHA-256 is one of hashes. Each
// compare runs in constant time and every hash is compared, so the time
// taken says nothing about which one matched.
func PATMatchesSHA256(token string, hashes []string) bool {
	if token == "" {
		return false
	}
	got := PATSHA256(token)
	match := 0
	for _, h := range hashes {
		match |= subtle.ConstantTimeCompare([]byte(got), []byte(h))
	}
	return match == 1
}

// parsePATSHA256 reads SB_PAT_TOKEN_SHA256: hex SHA-256 values separated by
// commas, upper or lower case. Duplicates are dropped; order is kept, so the
// first value stays the current PAT's.
func parsePATSHA256(raw string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		h := strings.ToLower(strings.TrimSpace(part))
		if h == "" {
			continue
		}
		if len(h) != sha256.Size*2 {
			return nil, fmt.Errorf("SB_PAT_TOKEN_SHA256: %q is not a SHA-256 (64 hex characters)", part)
		}
		if _, err := hex.DecodeString(h); err != nil {
			return nil, fmt.Errorf("SB_PAT_TOKEN_SHA256: %q is not a SHA-256 (64 hex characters)", part)
		}
		seen := false
		for _, o := range out {
			seen = seen || o == h
		}
		if !seen {
			out = append(out, h)
		}
	}
	return out, nil
}

// loadPATVerifier reads SB_PAT_TOKEN_SHA256. On a node whose own
// SB_PAT_TOKEN is not the operator PAT it also pins the operator volume
// scope when nothing else did: the legacy scope is "op-" and the first 16
// hex characters of the PAT's SHA-256, so the first listed hash (the
// current PAT) names it, and operator volumes stay where the nodes that
// hold the PAT put them.
func (cfg *Config) loadPATVerifier() error {
	hashes, err := parsePATSHA256(os.Getenv("SB_PAT_TOKEN_SHA256"))
	if err != nil {
		return err
	}
	cfg.PATTokenSHA256 = hashes
	if cfg.OperatorVolumeScope == "" && cfg.PATIsNodeLocal() {
		cfg.OperatorVolumeScope = "op-" + hashes[0][:16]
	}
	return nil
}

// PATIsNodeLocal reports whether this node's SB_PAT_TOKEN is a token of its
// own rather than the operator PAT: SB_PAT_TOKEN_SHA256 is set and does not
// list it.
func (c Config) PATIsNodeLocal() bool {
	return len(c.PATTokenSHA256) > 0 && !PATMatchesSHA256(c.PATToken, c.PATTokenSHA256)
}

// ClusterPeerPAT is the bearer this node puts on its own calls to peers:
// the operator PAT when it holds it, as every node did before, and nothing
// when it does not. Peers then know it by its node cert alone; a node-local
// token would only be refused there.
func (c Config) ClusterPeerPAT() string {
	if c.PATIsNodeLocal() {
		return ""
	}
	return c.PATToken
}

// OperatorPATSHA256 lists the hashes of every operator PAT this node
// accepts, current first: its own PAT and previous PAT when it holds them,
// then SB_PAT_TOKEN_SHA256. The join service hands this list to a node it
// joins without the PAT.
func (c Config) OperatorPATSHA256() []string {
	var raw []string
	if c.PATToken != "" && !c.PATIsNodeLocal() {
		raw = append(raw, PATSHA256(c.PATToken))
	}
	if c.PATTokenPrevious != "" {
		raw = append(raw, PATSHA256(c.PATTokenPrevious))
	}
	raw = append(raw, c.PATTokenSHA256...)
	out, _ := parsePATSHA256(strings.Join(raw, ","))
	return out
}
