package auditlog

import "testing"

func TestSSHGatewayCallKeyFingerprint(t *testing.T) {
	c := SSHGatewayCall{SandboxID: "sb-1", Open: true, Session: "main", KeyFingerprint: "SHA256:abc"}
	got, ok := ParseSSHGatewayCall(c.Encode())
	if !ok || got != c {
		t.Fatalf("round trip = %+v %v", got, ok)
	}
	if got, ok := ParseSSHGatewayCall((SSHGatewayCall{SandboxID: "sb-1"}).Encode()); !ok || got.KeyFingerprint != "" {
		t.Fatalf("no key = %+v %v", got, ok)
	}
	if _, ok := ParseSSHGatewayCall("sandbox=sb-1&key=a&key=b"); ok {
		t.Fatal("a call naming two keys parsed")
	}
}
