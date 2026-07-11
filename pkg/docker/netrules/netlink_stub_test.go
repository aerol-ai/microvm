//go:build !linux

package netrules

import "testing"

func TestNewNetlinkBackendStub(t *testing.T) {
	t.Parallel()
	b, err := NewNetlinkBackend()
	if b != nil || err == nil {
		t.Fatalf("stub NewNetlinkBackend = (%v, %v), want (nil, err)", b, err)
	}
}

func TestNewWithOptionsOffLinux(t *testing.T) {
	t.Parallel()
	m, err := NewWithOptions(true, BackendNetlink)
	if err != nil {
		t.Fatal(err)
	}
	if m.Enabled() {
		t.Fatal("Manager must be disabled off linux")
	}
	m, err = NewWithOptions(true, "not-a-backend")
	if err != nil {
		t.Fatal(err)
	}
	if m.Enabled() {
		t.Fatal("unknown backend still disabled off linux (GOOS gate first)")
	}
}
