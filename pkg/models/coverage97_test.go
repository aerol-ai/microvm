package models

import (
	"strings"
	"testing"
)

func TestCoverage97EdgeInputs(t *testing.T) {
	if _, err := NormalizeCustomDomain(".", ""); err == nil {
		t.Fatal("a bare dot is an empty hostname after trimming")
	}
	if _, err := NormalizeCustomDomain("foo..bar.com", ""); err == nil || !strings.Contains(err.Error(), "empty label") {
		t.Fatalf("empty label: %v", err)
	}
	if got := dnsRecordName("svc.team.corp"); got != "svc" {
		t.Fatalf("dns name = %q", got)
	}
	if err := (*MountSpec)(nil).Validate(""); err == nil {
		t.Fatal("nil mount")
	}
	if err := (&MountSpec{Type: MountTypeS3, Target: "/data/..hidden"}).Validate(""); err == nil || !strings.Contains(err.Error(), "..") {
		t.Fatalf("dotdot target: %v", err)
	}
	if _, ok := rcloneConnectionStringCredential("nocolon"); ok {
		t.Fatal("connection string without a colon has no parameters")
	}
	if _, err := NormalizeCreateDurability("nope", RuntimeDocker); err == nil {
		t.Fatal("unknown durability")
	}
	if got := JSBundleRefForNode("", "node-a"); got != "" {
		t.Fatalf("empty local ref = %q", got)
	}
	if got := JSBundleRefForNode("main.js", "bad id"); got != "main.js" {
		t.Fatalf("invalid node kept ref = %q", got)
	}
	if _, _, ok := ParseJSBundleNodeRef("main.js"); ok {
		t.Fatal("plain ref parsed as a node ref")
	}
	bound := JSBundleRefForNode("main.js", "node-a")
	if _, local, ok := ParseJSBundleNodeRef(strings.TrimSuffix(bound, "main.js")); ok || local == "" {
		t.Fatalf("ref missing the local part parsed ok=%v local=%q", ok, local)
	}
}
