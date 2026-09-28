//go:build !linux

package hostport

func platformEnableIPForward() error { return nil }
