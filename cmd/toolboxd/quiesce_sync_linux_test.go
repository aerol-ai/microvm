//go:build linux

package main

import "testing"

func TestLinuxQuiesceOpsSyncFilesystems(t *testing.T) {
	if err := (linuxQuiesceOps{}).SyncFilesystems(); err != nil {
		t.Fatalf("SyncFilesystems: %v", err)
	}
}
