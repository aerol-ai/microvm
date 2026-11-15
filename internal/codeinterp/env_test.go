package codeinterp

import (
	"errors"
	"testing"
)

func TestValidateEnv(t *testing.T) {
	cases := []struct {
		env map[string]string
		ok  bool
	}{
		{nil, true},
		{map[string]string{"A": "x", "B_2": "", "LONG": "a=b"}, true},
		{map[string]string{"": "x"}, false},
		{map[string]string{"A=B": "C"}, false},
		{map[string]string{"A\x00": "C"}, false},
		{map[string]string{"A": "x\x00y"}, false},
	}
	for _, tc := range cases {
		err := ValidateEnv(tc.env)
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrInvalidEnv)) {
			t.Fatalf("ValidateEnv(%q) = %v, want ok=%v", tc.env, err, tc.ok)
		}
	}
}
