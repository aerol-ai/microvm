//go:build !linux

package gate

import "github.com/aerol-ai/microvm/internal/rootpolicy"

func defaultStdioChecker() StdioChecker { return offLinux{} }
func defaultBindChecker() BindChecker   { return offLinux{} }
func defaultReadChecker() ReadChecker   { return offLinux{} }

// offLinux refuses every host path: the checks need openat2, and the gate
// only runs on Linux.
type offLinux struct{}

func (offLinux) CheckStdio(p string) error {
	return stdioViolation(p, "stdio paths are checked only on Linux")
}

func (offLinux) CheckBind(_, src string) error {
	return bindViolation(src, "bind sources are checked only on Linux")
}

func (offLinux) CheckRead(r rootpolicy.RootRead) error {
	return readViolation(r, "paths root reads are checked only on Linux")
}
