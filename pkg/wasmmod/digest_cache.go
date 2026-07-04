package wasmmod

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
)

const (
	moduleDigestModeOnce   = "once"
	moduleDigestModeAlways = "always"
)

type fileIdentity struct {
	path        string
	dev         uint64
	inode       uint64
	size        int64
	modUnixNano int64
}

type digestCacheEntry struct {
	done   chan struct{}
	digest string
	size   int64
	err    error
}

type digestCache struct {
	mu    sync.Mutex
	mode  string
	byKey map[fileIdentity]*digestCacheEntry
}

func newDigestCache(mode string) *digestCache {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = moduleDigestModeOnce
	}
	return &digestCache{
		mode:  mode,
		byKey: make(map[fileIdentity]*digestCacheEntry),
	}
}

func (c *digestCache) digestFor(path string) (hexDigest string, size int64, err error) {
	if c == nil || strings.EqualFold(c.mode, moduleDigestModeAlways) {
		return fileDigest(path)
	}
	key, err := fileIdentityFor(path)
	if err != nil {
		return fileDigest(path)
	}

	c.mu.Lock()
	if c.byKey == nil {
		c.byKey = make(map[fileIdentity]*digestCacheEntry)
	}
	if entry := c.byKey[key]; entry != nil {
		c.mu.Unlock()
		<-entry.done
		return entry.digest, entry.size, entry.err
	}
	entry := &digestCacheEntry{done: make(chan struct{})}
	c.byKey[key] = entry
	c.mu.Unlock()

	digest, size, hashErr := fileDigest(path)

	c.mu.Lock()
	entry.digest = digest
	entry.size = size
	entry.err = hashErr
	if hashErr != nil {
		delete(c.byKey, key)
	}
	close(entry.done)
	c.mu.Unlock()
	return digest, size, hashErr
}

// dropPath removes cached digests for path (best-effort on module delete/replace).
func (c *digestCache) dropPath(path string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.byKey {
		if key.path == path {
			delete(c.byKey, key)
		}
	}
}

func fileIdentityFor(path string) (fileIdentity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileIdentity{}, err
	}
	var dev, inode uint64
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		dev = uint64(st.Dev)
		inode = uint64(st.Ino)
	}
	return fileIdentity{
		path:        path,
		dev:         dev,
		inode:       inode,
		size:        info.Size(),
		modUnixNano: info.ModTime().UnixNano(),
	}, nil
}

// fileDigestHasher is the SHA-256 seam for digest_cache tests.
var fileDigestHasher = func(path string) (hexDigest string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func fileDigest(path string) (hexDigest string, size int64, err error) {
	return fileDigestHasher(path)
}
