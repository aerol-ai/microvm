//go:build !itestwitness

package main

// The shipped build leaves providerFactory nil, so daemon.Run uses
// controlplane.Noop(). This file exists to make that explicit and to give the
// tagged alternative something to be the alternative TO — without it, the
// difference between a release binary and a harness binary would be invisible
// in the package.
func init() { providerFactory = nil }
