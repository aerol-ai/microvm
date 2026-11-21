//go:build !unix

package wasm

import "errors"

// No grants are held off unix (hostproc.ConfinedProcFD is ""), so these are
// never reached there.
func dupCloexec(uintptr) (uintptr, error) { return 0, errors.New("unsupported") }

func closeFD(uintptr) {}
