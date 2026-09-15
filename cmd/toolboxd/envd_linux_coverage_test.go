//go:build linux

package main

import (
	"testing"
)

func TestLinuxIsSupportedEnvdUserMatch(t *testing.T) {
	t.Setenv("USER", "cov95user")
	t.Setenv("LOGNAME", "")
	if !isSupportedEnvdUser("cov95user") {
		t.Fatal("expected USER match")
	}
	t.Setenv("USER", "")
	t.Setenv("LOGNAME", "cov95log")
	if !isSupportedEnvdUser("cov95log") {
		t.Fatal("expected LOGNAME match")
	}
}
