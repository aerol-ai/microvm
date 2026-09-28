package auditlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// GenesisPrevHash is the prev_hash of the first event in a chain.
const GenesisPrevHash = "0"

// HashEvent returns SHA-256 hex of prevHash || canonical JSON of ev with
// EventHash cleared (so the hash does not depend on itself).
func HashEvent(prevHash string, ev Event) string {
	ev.EventHash = ""
	ev.PrevHash = prevHash
	raw, err := json.Marshal(ev)
	if err != nil {
		sum := sha256.Sum256([]byte(prevHash + "|" + ev.EventID + "|" + ev.Result))
		return hex.EncodeToString(sum[:])
	}
	h := sha256.New()
	_, _ = h.Write([]byte(prevHash))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

// LinkEvent sets PrevHash/EventHash on ev given the previous tip hash.
func LinkEvent(prevHash string, ev *Event) {
	if ev == nil {
		return
	}
	if prevHash == "" {
		prevHash = GenesisPrevHash
	}
	ev.PrevHash = prevHash
	ev.EventHash = HashEvent(prevHash, *ev)
}
