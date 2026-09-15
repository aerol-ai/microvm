package cluster

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// MintIncarnationID returns a 16-byte random hex string that uniquely tags a
// sandbox placement lifetime. Reassign preserves the value; every fresh
// reserve or unreserved placement mints a new one.
func MintIncarnationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("cluster: mint incarnation id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
