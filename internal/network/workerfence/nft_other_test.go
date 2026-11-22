//go:build !linux

package workerfence

import (
	"errors"
	"testing"
)

func TestUnsupportedBackend(t *testing.T) {
	be := NewBackend()
	if err := be.Apply(nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Apply = %v", err)
	}
	if _, err := be.Check(nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Check = %v", err)
	}
	if err := be.Remove(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Remove = %v", err)
	}
}
