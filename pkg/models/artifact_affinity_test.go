package models

import "testing"

func TestJSBundleNodeRefRoundTrip(t *testing.T) {
	ref := JSBundleRefForNode("sha256:abcdef", "worker-a")
	nodeID, local, ok := ParseJSBundleNodeRef(ref)
	if !ok || nodeID != "worker-a" || local != "sha256:abcdef" {
		t.Fatalf("ParseJSBundleNodeRef(%q) = %q, %q, %v", ref, nodeID, local, ok)
	}
	if _, _, ok := ParseJSBundleNodeRef("node:not-base32:sha256:abc"); ok {
		t.Fatal("malformed node binding was accepted")
	}
	bad, ok := EncodeNodeAffinity("worker|forged")
	if ok || bad != "" {
		t.Fatal("node affinity accepted a protocol delimiter")
	}
	encoded := "o5xxe23foj6gm33sm5swi" // base32("worker|forged")
	if _, ok := DecodeNodeAffinity(encoded); ok {
		t.Fatal("decoded node affinity accepted a protocol delimiter")
	}
}

func TestTemplateIDValidationRejectsPathSegments(t *testing.T) {
	for _, id := range []string{"tpl-safe", "Template_01", "a.b"} {
		if !ValidTemplateID(id) {
			t.Fatalf("ValidTemplateID(%q) = false", id)
		}
	}
	for _, id := range []string{"", "../escape", ".", "contains/slash", " space"} {
		if ValidTemplateID(id) {
			t.Fatalf("ValidTemplateID(%q) = true", id)
		}
	}
}
