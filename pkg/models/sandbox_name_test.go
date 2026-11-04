package models

import (
	"errors"
	"testing"
)

func TestValidateSandboxName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "empty is an unnamed sandbox", input: ""},
		{name: "whitespace only is empty", input: "   "},
		{name: "plain name", input: "my-agent"},
		{name: "name containing owner later", input: "my-owner:x"},
		{name: "sb prefix but not id shaped", input: "sb-build"},
		{name: "sb prefix with 15 hex", input: "sb-0123456789abcde"},
		{name: "sb prefix with 17 hex", input: "sb-0123456789abcdef0"},
		{name: "uppercase hex is not generated shape", input: "sb-0123456789ABCDEF"},
		{name: "reserved owner prefix", input: "owner:abc/name", wantErr: true},
		{name: "reserved owner prefix after trim", input: "  owner:x", wantErr: true},
		{name: "generated id shape", input: "sb-0123456789abcdef", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSandboxName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateSandboxName(%q) = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidSandboxName) {
				t.Fatalf("ValidateSandboxName(%q) error %v does not wrap ErrInvalidSandboxName", tt.input, err)
			}
		})
	}
}

func TestIsGeneratedSandboxID(t *testing.T) {
	for ref, want := range map[string]bool{
		"sb-0123456789abcdef":  true,
		"sb-ffffffffffffffff":  true,
		"sb-0123456789abcde":   false,
		"sb-0123456789abcdefa": false,
		"sb-0123456789abcdeg":  false,
		"my-agent":             false,
		"":                     false,
		" sb-0123456789abcdef": false,
	} {
		if got := IsGeneratedSandboxID(ref); got != want {
			t.Errorf("IsGeneratedSandboxID(%q) = %v, want %v", ref, got, want)
		}
	}
}
