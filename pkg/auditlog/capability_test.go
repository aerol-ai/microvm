package auditlog

import (
	"testing"
	"time"
)

func TestMintAndVerifyEgressCapability(t *testing.T) {
	cap, err := MintEgressCapability("secret-key", "sb-1", "inc-a", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	sid, inc, err := ParseAndVerifyEgressCapability("secret-key", cap, time.Now().UTC())
	if err != nil || sid != "sb-1" || inc != "inc-a" {
		t.Fatalf("verify = %q %q err=%v", sid, inc, err)
	}
	if _, _, err := ParseAndVerifyEgressCapability("wrong", cap, time.Now().UTC()); err == nil {
		t.Fatal("expected mac mismatch")
	}
	// Capability for sb-1 must not verify as a different sandbox claim — the
	// mac binds the embedded sandbox id.
	parts := splitCap(cap)
	parts[0] = "sb-other"
	forged := joinCap(parts)
	if _, _, err := ParseAndVerifyEgressCapability("secret-key", forged, time.Now().UTC()); err == nil {
		t.Fatal("expected forged sandbox capability to fail")
	}
}

func splitCap(c string) []string {
	var out []string
	start := 0
	for i := 0; i < len(c); i++ {
		if c[i] == '|' {
			out = append(out, c[start:i])
			start = i + 1
		}
	}
	out = append(out, c[start:])
	return out
}

func joinCap(parts []string) string {
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += "|" + parts[i]
	}
	return out
}
