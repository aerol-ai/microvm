package secrets

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// digestKeyInfo is the HKDF label of the key a server key's digests use. It
// differs from serverKeyCheck's label, so the key-check value printed in the
// key file says nothing about it; it is one-way, so it says nothing about the
// server key either.
const digestKeyInfo = "aerolvm-keyed-digest/v1"

// KeyedDigest is a keyed digest of some data under one ring key.
type KeyedDigest struct {
	KeyID uint32
	Sum   []byte
}

// String is the digest as it is stored or recorded: "hmac:<key id>:<hex>".
// The key id says which server key made it, so a reader can tell digests of
// two key epochs apart rather than take them for two different inputs.
func (d KeyedDigest) String() string {
	return "hmac:" + strconv.FormatUint(uint64(d.KeyID), 10) + ":" + hex.EncodeToString(d.Sum)
}

func deriveDigestKey(key []byte) ([]byte, error) {
	digestKey, err := hkdf.Key(sha256.New, key, nil, digestKeyInfo, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("derive digest key: %w", err)
	}
	return digestKey, nil
}

// Digests returns HMAC-SHA256 digests of data under a key derived from each
// server key the Cipher holds, the current key's first.
//
// A keyed digest is what a stored or logged value derived from secrets needs
// (an idempotency fingerprint over a create's env, say): it is stable for as
// long as the server key is, the same on every node that shares the key, and
// useless for checking a guessed value offline without the key. The keys
// after the first are those of a rotation in progress, so a caller can still
// match what it stored under the previous key. purpose separates uses: the
// same data under two purposes gives unrelated digests.
func (c *Cipher) Digests(purpose string, data []byte) ([]KeyedDigest, error) {
	if purpose == "" || strings.ContainsRune(purpose, 0) {
		return nil, errors.New("digest purpose must be non-empty and contain no NUL")
	}
	r, err := c.activeRing()
	if err != nil {
		return nil, err
	}
	ids := make([]uint32, 0, len(r.digestKeys))
	for id := range r.digestKeys {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if (ids[i] == r.current) != (ids[j] == r.current) {
			return ids[i] == r.current
		}
		return ids[i] < ids[j]
	})
	out := make([]KeyedDigest, 0, len(ids))
	for _, id := range ids {
		mac := hmac.New(sha256.New, r.digestKeys[id])
		mac.Write([]byte(purpose))
		mac.Write([]byte{0})
		mac.Write(data)
		out = append(out, KeyedDigest{KeyID: id, Sum: mac.Sum(nil)})
	}
	return out, nil
}
