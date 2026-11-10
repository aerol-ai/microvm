package nodejoin

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

// What a join does with the operator PAT (internal/config/pat_verifier.go).
//
//	answer carries       sandboxd.env SB_PAT_TOKEN       cluster.env
//	pat_token            the cluster's PAT               SB_PAT_TOKEN_SHA256 dropped
//	pat_sha256           a token of this node's own      SB_PAT_TOKEN_SHA256, SB_OPERATOR_VOLUME_SCOPE
//	neither (old server) left as it is                   left as it is
//
// A node joined without the PAT must not keep holding it: when the token
// install.sh left is the PAT (an install with --pat-token, or a node that
// held it and joins again), it is replaced with a random one. The node's
// own tools keep reading SB_PAT_TOKEN and work on this node only. A token
// that is already this node's own is kept, so a re-run changes nothing.

// patSettings adds the answer's PAT hashes and operator volume scope to
// cluster.env's settings, or drops the hashes when the answer carries the
// PAT itself.
func patSettings(set *envSet, resp cluster.JoinResponse) {
	switch {
	case resp.PATToken != "":
		set.set("SB_PAT_TOKEN_SHA256", "")
	case len(resp.PATSHA256) > 0:
		set.set("SB_PAT_TOKEN_SHA256", strings.Join(resp.PATSHA256, ","))
		if resp.OperatorVolumeScope != "" {
			set.set("SB_OPERATOR_VOLUME_SCOPE", resp.OperatorVolumeScope)
		}
	}
}

// joinPAT returns the SB_PAT_TOKEN this node must hold after the join, and
// whether that differs from current.
func joinPAT(current string, resp cluster.JoinResponse) (string, bool, error) {
	switch {
	case resp.PATToken != "":
		return resp.PATToken, current != resp.PATToken, nil
	case len(resp.PATSHA256) > 0 && (current == "" || config.PATMatchesSHA256(current, resp.PATSHA256)):
		local, err := newLocalToken()
		return local, err == nil, err
	}
	return current, false, nil
}

// newLocalToken makes a node-local token like install.sh's
// (`openssl rand -hex 24`). A variable so tests can pin it.
var newLocalToken = func() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
