package docker

import (
	"reflect"
	"testing"
)

func TestSandboxHostConfigCapDrop(t *testing.T) {
	cases := []struct {
		name       string
		privileged bool
		wantDrop   []string
	}{
		{name: "unprivileged drops NET_RAW", privileged: false, wantDrop: []string{"NET_RAW"}},
		{name: "privileged sends no drop", privileged: true, wantDrop: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			binds := []string{"/a:/b:ro"}
			hc := sandboxHostConfig(tc.privileged, binds)
			if hc["Privileged"] != tc.privileged {
				t.Fatalf("Privileged = %v, want %v", hc["Privileged"], tc.privileged)
			}
			if !reflect.DeepEqual(hc["Binds"], binds) {
				t.Fatalf("Binds = %v, want %v", hc["Binds"], binds)
			}
			got, _ := hc["CapDrop"].([]string)
			if !reflect.DeepEqual(got, tc.wantDrop) {
				t.Fatalf("CapDrop = %v, want %v", got, tc.wantDrop)
			}
		})
	}
	// The returned slice must not alias the package default.
	hc := sandboxHostConfig(false, nil)
	hc["CapDrop"].([]string)[0] = "MUTATED"
	if sandboxCapDrop[0] != "NET_RAW" {
		t.Fatal("sandboxHostConfig leaked the package-level CapDrop slice")
	}
}
