package containerd

import (
	"testing"
)

func TestAssertSupportedContainerdVersion(t *testing.T) {
	cases := []struct {
		in    string
		isErr bool
	}{
		{"1.7.29", false},
		{"1.6.36", false},
		{"2.0.0", false},
		{"1.5.0", true},
		{"3.0.0", true},
		{"", true},
		{"bogus", true},
		{"v1.7.29", false},
	}
	for _, tc := range cases {
		err := assertSupportedContainerdVersion(tc.in)
		if tc.isErr && err == nil {
			t.Errorf("%q: want error", tc.in)
		}
		if !tc.isErr && err != nil {
			t.Errorf("%q: %v", tc.in, err)
		}
	}
}
