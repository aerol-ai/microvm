//go:build !linux

package main

import "testing"

func TestOtherQuiesceOpsSyncFilesystemsIsLinuxOnly(t *testing.T) {
	if err := (otherQuiesceOps{}).SyncFilesystems(); err == nil {
		t.Fatal("SyncFilesystems off Linux returned nil")
	}
}
