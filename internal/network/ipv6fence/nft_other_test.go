//go:build !linux

package ipv6fence

import (
	"errors"
	"testing"
)

func TestUnsupportedBackend(t *testing.T) {
	be := NewBackend()
	if err := be.Apply(nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Apply = %v", err)
	}
	if ok, err := be.Check(nil); ok || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Check = %v, %v", ok, err)
	}
}
