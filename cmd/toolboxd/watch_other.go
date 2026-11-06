//go:build !linux

package main

// watch_other.go: toolboxd only runs on Linux, but builds and runs its unit
// tests on darwin. Off Linux there is no inotify, so a watch never starts
// (the runtime gate already refuses it there: no Firecracker command line,
// no gVisor kernel).

var newDirWatcherFn dirWatcherFactory = func(string, bool, *watchBatch, *watchBudget, int) (dirWatcher, error) {
	return nil, errFileWatchUnsupported
}
