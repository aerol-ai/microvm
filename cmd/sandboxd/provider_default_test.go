//go:build !itestwitness

package main

import "testing"

// The SHIPPED binary must pass a nil provider factory, so daemon.Run uses
// controlplane.Noop() and enterprise mode correctly refuses to boot without a
// real witness. If this ever becomes non-nil without the itestwitness tag,
// a release build would silently carry a test seam into production.
func TestShippedBuildHasNoProviderFactory(t *testing.T) {
	if providerFactory != nil {
		t.Fatal("providerFactory is non-nil in an untagged build; the shipped daemon must use controlplane.Noop()")
	}
}
