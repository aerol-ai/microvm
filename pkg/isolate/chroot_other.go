//go:build !linux

package isolate

import "os"

// Device nodes need mknod(2) with Linux major/minor numbers. Off Linux the
// base tree is still built (tests, dev machines) without them; the jail is
// never realized here anyway.
func makeDevNodes(string) error { return nil }

func cloneDevNode(string, string) error { return nil }

func runningAsRoot() bool { return os.Geteuid() == 0 }

func mountNoexecTmpfs(string, int, int) error {
	return errNotRoot
}

func unmountNoexecMounts([]string) {}
