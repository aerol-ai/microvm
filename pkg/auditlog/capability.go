package auditlog

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// CapabilitySep separates HMAC capability fields.
	CapabilitySep = "|"
	// DefaultCapabilityTTL bounds how long a worker may emit egress events
	// with a given capability without refresh.
	DefaultCapabilityTTL = 24 * time.Hour
)

// MintEgressCapability returns HMAC(sandboxID|incarnationID|expiry, key)
// hex-encoded as sandboxID|incarnationID|expiryUnix|mac. key is typically
// SB_AUDIT_INGEST_TOKEN (or a derived key). The mac binds the sandbox so a
// stolen capability for one sandbox cannot forge another sandbox's events.
func MintEgressCapability(key, sandboxID, incarnationID string, expiry time.Time) (string, error) {
	key = strings.TrimSpace(key)
	sandboxID = strings.TrimSpace(sandboxID)
	incarnationID = strings.TrimSpace(incarnationID)
	if key == "" || sandboxID == "" {
		return "", fmt.Errorf("auditlog: capability requires key and sandbox_id")
	}
	if expiry.IsZero() {
		expiry = time.Now().UTC().Add(DefaultCapabilityTTL)
	}
	expUnix := expiry.UTC().Unix()
	mac := hmacEgressCapability(key, sandboxID, incarnationID, expUnix)
	return strings.Join([]string{sandboxID, incarnationID, strconv.FormatInt(expUnix, 10), mac}, CapabilitySep), nil
}

// ParseAndVerifyEgressCapability checks the HMAC and expiry. On success it
// returns the bound sandboxID and incarnationID (never trust client body for
// those fields when a capability is present).
func ParseAndVerifyEgressCapability(key, capability string, now time.Time) (sandboxID, incarnationID string, err error) {
	key = strings.TrimSpace(key)
	capability = strings.TrimSpace(capability)
	if key == "" || capability == "" {
		return "", "", fmt.Errorf("auditlog: missing capability")
	}
	parts := strings.Split(capability, CapabilitySep)
	if len(parts) != 4 {
		return "", "", fmt.Errorf("auditlog: malformed capability")
	}
	sandboxID = strings.TrimSpace(parts[0])
	incarnationID = strings.TrimSpace(parts[1])
	expUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || sandboxID == "" {
		return "", "", fmt.Errorf("auditlog: malformed capability")
	}
	want := hmacEgressCapability(key, sandboxID, incarnationID, expUnix)
	if !hmac.Equal([]byte(want), []byte(parts[3])) {
		return "", "", fmt.Errorf("auditlog: capability mac mismatch")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Unix() > expUnix {
		return "", "", fmt.Errorf("auditlog: capability expired")
	}
	return sandboxID, incarnationID, nil
}

func hmacEgressCapability(key, sandboxID, incarnationID string, expUnix int64) string {
	msg := sandboxID + CapabilitySep + incarnationID + CapabilitySep + strconv.FormatInt(expUnix, 10)
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}
