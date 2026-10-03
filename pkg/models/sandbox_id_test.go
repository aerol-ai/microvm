package models

import "testing"

func TestValidateSandboxID(t *testing.T) {
	good := []string{
		"sb-0123456789abcdef", // generateSandboxID output
		"fc-jailer",
		"wasm-abc_DEF-123",
		"a",
		"sb-x",
	}
	for _, id := range good {
		if err := ValidateSandboxID(id); err != nil {
			t.Errorf("ValidateSandboxID(%q) = %v, want nil", id, err)
		}
	}

	bad := []struct {
		name, id string
	}{
		{"empty", ""},
		{"dotdot", "../../etc/cron.d/x"},
		{"single dot segment", "sb-./x"},
		{"slash", "sb/evil"},
		{"backslash", `sb\evil`},
		{"leading dotdot", ".."},
		{"dot", "sb.snap"}, // '.' is disallowed: it is what enables traversal
		{"space", "sb id"},
		{"newline", "sb\nid"},
		{"null", "sb\x00id"},
		{"colon", "sb:id"},
		{"tilde home", "~"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateSandboxID(tc.id); err == nil {
				t.Fatalf("ValidateSandboxID(%q) = nil, want error", tc.id)
			}
		})
	}

	// 128 bytes is the boundary: accepted at 128, rejected at 129.
	id128 := make([]byte, 128)
	for i := range id128 {
		id128[i] = 'a'
	}
	if err := ValidateSandboxID(string(id128)); err != nil {
		t.Errorf("128-char id rejected: %v", err)
	}
	if err := ValidateSandboxID(string(id128) + "a"); err == nil {
		t.Error("129-char id accepted, want rejected")
	}
}
