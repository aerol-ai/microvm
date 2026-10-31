//go:build !unix

package secrets

import "sync"

var keyFileLocks sync.Map

// lockKeyFile serializes key-file writers within this process; sandboxd
// and its key tool only run on unix, where the lock is cross-process.
func lockKeyFile(path string) (func(), error) {
	v, _ := keyFileLocks.LoadOrStore(path, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock, nil
}
