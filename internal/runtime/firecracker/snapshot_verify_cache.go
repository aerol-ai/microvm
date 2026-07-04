package firecracker

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

const (
	snapshotVerifyModeOnce   = "once"
	snapshotVerifyModeAlways = "always"
)

type snapshotVerifierFunc func(memPath, statePath, expected string) error

type snapshotFileIdentity struct {
	path        string
	dev         uint64
	inode       uint64
	size        int64
	modUnixNano int64
}

type snapshotVerifyKey struct {
	checksum string
	memory   snapshotFileIdentity
	state    snapshotFileIdentity
}

type snapshotVerifyEntry struct {
	done chan struct{}
	err  error
}

func (d *Driver) verifySnapshotForLoad(templateID, memPath, statePath, expected string) error {
	if !d.cfg.SnapshotVerifyOnLoad || expected == "" {
		return nil
	}
	if strings.EqualFold(d.cfg.SnapshotVerifyMode, snapshotVerifyModeAlways) {
		return d.runSnapshotVerifier(memPath, statePath, expected)
	}

	key, err := snapshotVerifyKeyFor(memPath, statePath, expected)
	if err != nil {
		// Preserve the verifier's existing error shape for missing or
		// transiently unreadable files instead of inventing a stat-only
		// variant on the hot path.
		return d.runSnapshotVerifier(memPath, statePath, expected)
	}

	d.verifyMu.Lock()
	if d.verifiedSnapshots == nil {
		d.verifiedSnapshots = make(map[snapshotVerifyKey]*snapshotVerifyEntry)
	}
	if entry := d.verifiedSnapshots[key]; entry != nil {
		d.verifyMu.Unlock()
		<-entry.done
		return entry.err
	}
	entry := &snapshotVerifyEntry{done: make(chan struct{})}
	d.verifiedSnapshots[key] = entry
	d.verifyMu.Unlock()

	verifyErr := d.runSnapshotVerifier(memPath, statePath, expected)

	d.verifyMu.Lock()
	entry.err = verifyErr
	if verifyErr != nil {
		delete(d.verifiedSnapshots, key)
	} else if templateID != "" {
		if d.verifiedTemplates == nil {
			d.verifiedTemplates = make(map[string]snapshotVerifyKey)
		}
		if oldKey, ok := d.verifiedTemplates[templateID]; ok && oldKey != key {
			delete(d.verifiedSnapshots, oldKey)
		}
		d.verifiedTemplates[templateID] = key
	}
	close(entry.done)
	d.verifyMu.Unlock()
	return verifyErr
}

func (d *Driver) runSnapshotVerifier(memPath, statePath, expected string) error {
	if d.snapshotVerifier == nil {
		return verifySnapshotChecksum(memPath, statePath, expected)
	}
	return d.snapshotVerifier(memPath, statePath, expected)
}

func (d *Driver) invalidateSnapshotVerifyCacheForTemplate(templateID string) {
	if templateID == "" {
		return
	}
	d.verifyMu.Lock()
	defer d.verifyMu.Unlock()
	key, ok := d.verifiedTemplates[templateID]
	if !ok {
		return
	}
	delete(d.verifiedTemplates, templateID)
	delete(d.verifiedSnapshots, key)
}

func snapshotVerifyKeyFor(memPath, statePath, expected string) (snapshotVerifyKey, error) {
	memory, err := snapshotFileIdentityFor(memPath)
	if err != nil {
		return snapshotVerifyKey{}, fmt.Errorf("snapshot verify cache: stat memory: %w", err)
	}
	state, err := snapshotFileIdentityFor(statePath)
	if err != nil {
		return snapshotVerifyKey{}, fmt.Errorf("snapshot verify cache: stat state: %w", err)
	}
	return snapshotVerifyKey{
		checksum: expected,
		memory:   memory,
		state:    state,
	}, nil
}

func snapshotFileIdentityFor(path string) (snapshotFileIdentity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return snapshotFileIdentity{}, err
	}
	var dev, inode uint64
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		dev = uint64(st.Dev)
		inode = uint64(st.Ino)
	}
	return snapshotFileIdentity{
		path:        path,
		dev:         dev,
		inode:       inode,
		size:        info.Size(),
		modUnixNano: info.ModTime().UnixNano(),
	}, nil
}
