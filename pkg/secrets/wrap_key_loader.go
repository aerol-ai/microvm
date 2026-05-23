package secrets

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// UpstreamWrapKey is one key in the rotation ring. `ID` is a short, human-
// readable identifier surfaced in metrics and logs; the cryptographic
// material is `Bytes`. The wire format on AOCR's side and ours must agree
// exactly: 32-byte AES-256 keys, base64 (standard alphabet), optionally
// prefixed with `<id>:`.
type UpstreamWrapKey struct {
	ID    string
	Bytes []byte
}

// UpstreamWrapKeyRing holds the ordered list of wrap keys. The first entry
// is the *current* key used for wrapping new tokens; all entries are kept
// available for unwrap (here only as a future-proofing detail — sandboxd
// only wraps, never unwraps — but matching AOCR's structure keeps the two
// sides interchangeable).
//
// Rotation policy: prepend a new key (`new:<b64>,old:<b64>`) on every node,
// wait one full token lifetime so any in-flight wrapped credentials have
// expired on the AOCR side, then drop the old entry. See the
// `rotate-upstream-wrap-key.yml` playbook for the operator flow.
type UpstreamWrapKeyRing struct {
	Keys []UpstreamWrapKey
}

// Current returns the active wrap key. Callers should not cache the
// returned key across reloads.
func (r *UpstreamWrapKeyRing) Current() (UpstreamWrapKey, bool) {
	if r == nil || len(r.Keys) == 0 {
		return UpstreamWrapKey{}, false
	}
	return r.Keys[0], true
}

// LoadUpstreamWrapKeyRing reads the wrap key file at `path` and parses it
// into a key ring. The file must be mode 0400 (owner-readable only); any
// looser mode is refused at load time to prevent operator-mistake leaks via
// world-readable home directories or `cp -p` from a wide-mode source.
//
// The file body is a comma-separated list of `<b64>` or `<id>:<b64>`
// entries — same format as the AOCR side's `UPSTREAM_AUTH_WRAP_KEYS`
// env var. Whitespace around commas is tolerated. Malformed entries are
// silently dropped (matching AOCR behavior) so a partial-bad rotation
// does not break the node entirely, but the final ring must have at least
// one valid key or LoadUpstreamWrapKeyRing returns an error.
//
// If the file does not exist, LoadUpstreamWrapKeyRing returns
// `os.ErrNotExist` wrapped so callers can fall through to "wrap keys not
// configured" without treating it as fatal — the daemon may still run for
// public images.
func LoadUpstreamWrapKeyRing(path string) (*UpstreamWrapKeyRing, error) {
	if path == "" {
		return nil, errors.New("upstream wrap key path is empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	// The mode check is intentionally strict: any group/world read or any
	// write bit at all is rejected. Owner-execute is allowed but irrelevant
	// (regular files shouldn't have it; we don't enforce its absence).
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return nil, fmt.Errorf("upstream wrap key file %s has insecure mode %#o; want 0400", path, mode)
	}
	if mode&0o200 != 0 {
		return nil, fmt.Errorf("upstream wrap key file %s is writable (%#o); want 0400", path, mode)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read upstream wrap key %s: %w", path, err)
	}
	ring := ParseUpstreamWrapKeyRing(string(body))
	if len(ring.Keys) == 0 {
		return nil, fmt.Errorf("upstream wrap key file %s contained no usable keys", path)
	}
	return ring, nil
}

// ParseUpstreamWrapKeyRing parses the comma-separated wrap-key format.
// Public so callers (tests, config validators) can validate a string
// without writing it to disk.
func ParseUpstreamWrapKeyRing(raw string) *UpstreamWrapKeyRing {
	ring := &UpstreamWrapKeyRing{}
	if strings.TrimSpace(raw) == "" {
		return ring
	}
	for i, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Accept both `<b64>` and `<id>:<b64>`. `id` length cap matches
		// AOCR's parser (<16 chars) so the wire-format check stays
		// symmetric across implementations.
		id := fmt.Sprintf("k%d", i)
		b64 := entry
		if colon := strings.IndexByte(entry, ':'); colon > 0 && colon < 16 {
			id = entry[:colon]
			b64 = entry[colon+1:]
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		if len(decoded) != 32 {
			continue
		}
		ring.Keys = append(ring.Keys, UpstreamWrapKey{ID: id, Bytes: decoded})
	}
	return ring
}
