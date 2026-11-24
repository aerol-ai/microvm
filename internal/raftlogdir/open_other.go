//go:build !unix

package raftlogdir

import "os"

// openRecord: privilege mode split runs on Linux only; elsewhere the record
// is opened as Recorded opens it.
func openRecord(path string) (*os.File, error) { return os.Open(path) }
