package cni

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeFakeCNIPlugin drops an executable plugin named pluginType into dir. The
// script ENFORCES the CNI exec protocol — it fails unless CNI_COMMAND /
// CNI_CONTAINERID / CNI_NETNS are set in the environment and a netconf arrives
// on stdin — so a regression back to positional-argv invocation is caught. On
// ADD it prints bodyADD; it exits exitCode.
func writeFakeCNIPlugin(t *testing.T, dir, pluginType, bodyADD string, exitCode int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake CNI plugin is a POSIX shell script")
	}
	script := "#!/bin/sh\n" +
		"[ -n \"$CNI_COMMAND\" ] || { echo 'missing CNI_COMMAND' >&2; exit 3; }\n" +
		"[ -n \"$CNI_CONTAINERID\" ] || { echo 'missing CNI_CONTAINERID' >&2; exit 3; }\n" +
		"[ -n \"$CNI_NETNS\" ] || { echo 'missing CNI_NETNS' >&2; exit 3; }\n" +
		// Real plugins reject unknown CNI_ARGS keys unless IgnoreUnknown is set;
		// the K8S_POD_* keys we pass are unknown to bridge/host-local.
		"case \"$CNI_ARGS\" in IgnoreUnknown=true*) ;; *) echo 'CNI_ARGS missing IgnoreUnknown=true' >&2; exit 3;; esac\n" +
		"conf=$(cat)\n" +
		"[ -n \"$conf\" ] || { echo 'empty stdin netconf' >&2; exit 3; }\n" +
		"if [ \"$CNI_COMMAND\" = ADD ]; then printf '%s' '" + bodyADD + "'; fi\n" +
		"exit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(filepath.Join(dir, pluginType), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake plugin: %v", err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func writeConflist(t *testing.T, dir string) string {
	t.Helper()
	conf := filepath.Join(dir, "aerolvm.conflist")
	body := `{"cniVersion":"1.0.0","name":"aerolvm","plugins":[{"type":"bridge","bridge":"aerolvm0","ipam":{"type":"host-local","subnet":"10.88.0.0/16"}}]}`
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		t.Fatalf("write conflist: %v", err)
	}
	return conf
}

func newExecRunnerWithFake(t *testing.T, bodyADD string, exitCode int) *ExecRunner {
	t.Helper()
	dir := t.TempDir()
	writeFakeCNIPlugin(t, dir, "bridge", bodyADD, exitCode)
	conf := writeConflist(t, dir)
	r, err := NewExecRunner(Config{PluginDir: dir, ConfPath: conf})
	if err != nil {
		t.Fatalf("NewExecRunner: %v", err)
	}
	return r
}

func TestExecRunnerAddSpeaksCNIProtocol(t *testing.T) {
	// The fake plugin exits non-zero unless the CNI_* env + stdin netconf are
	// present, so a successful parse proves protocol conformance.
	r := newExecRunnerWithFake(t, `{"ips":[{"version":"6","address":"fd00::2/64"},{"version":"4","address":"10.88.0.7/24"}]}`, 0)
	res, err := r.Add(context.Background(), "/run/netns/sb-1", "sb-1")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if res.IP4 != "10.88.0.7" {
		t.Fatalf("IP4 = %q, want 10.88.0.7 (CIDR stripped, ipv6 skipped)", res.IP4)
	}
}

func TestExecRunnerDelSucceeds(t *testing.T) {
	r := newExecRunnerWithFake(t, "", 0)
	if err := r.Del(context.Background(), "/run/netns/sb-1", "sb-1"); err != nil {
		t.Fatalf("Del: %v", err)
	}
}

func TestExecRunnerAddPluginExitNonZero(t *testing.T) {
	r := newExecRunnerWithFake(t, "", 1)
	if _, err := r.Add(context.Background(), "/run/netns/sb-1", "sb-1"); err == nil {
		t.Fatal("want error when plugin exits non-zero")
	}
}

func TestExecRunnerAddBadJSON(t *testing.T) {
	r := newExecRunnerWithFake(t, "not-json", 0)
	if _, err := r.Add(context.Background(), "/run/netns/sb-1", "sb-1"); err == nil {
		t.Fatal("want decode error on non-JSON plugin output")
	}
}

func TestExecRunnerAddNoIPv4(t *testing.T) {
	r := newExecRunnerWithFake(t, `{"ips":[{"version":"6","address":"fd00::2/64"}]}`, 0)
	if _, err := r.Add(context.Background(), "/run/netns/sb-1", "sb-1"); err == nil {
		t.Fatal("want error when result carries no ipv4")
	}
}

func TestExecRunnerResolveMissingConfFile(t *testing.T) {
	dir := t.TempDir()
	writeFakeCNIPlugin(t, dir, "bridge", "", 0)
	r, err := NewExecRunner(Config{PluginDir: dir, ConfPath: filepath.Join(dir, "absent.conflist")})
	if err != nil {
		t.Fatalf("NewExecRunner: %v", err)
	}
	if _, err := r.Add(context.Background(), "/n", "c"); err == nil {
		t.Fatal("want missing-conf error")
	}
}

func TestExecRunnerResolveMissingPluginBinary(t *testing.T) {
	dir := t.TempDir()
	conf := writeConflist(t, dir) // references type "bridge" but no bridge binary
	r, err := NewExecRunner(Config{PluginDir: dir, ConfPath: conf})
	if err != nil {
		t.Fatalf("NewExecRunner: %v", err)
	}
	if _, err := r.Add(context.Background(), "/n", "c"); err == nil {
		t.Fatal("want missing-plugin-binary error")
	}
}

func TestExecRunnerConfWithoutTypeRejected(t *testing.T) {
	dir := t.TempDir()
	writeFakeCNIPlugin(t, dir, "bridge", "", 0)
	conf := filepath.Join(dir, "notype.conf")
	if err := os.WriteFile(conf, []byte(`{"cniVersion":"1.0.0","name":"aerolvm"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := NewExecRunner(Config{PluginDir: dir, ConfPath: conf})
	if err != nil {
		t.Fatalf("NewExecRunner: %v", err)
	}
	if _, err := r.Add(context.Background(), "/n", "c"); err == nil {
		t.Fatal("want error for conf with no plugin type")
	}
}

func TestSinglePluginNetconfExtractsFromConflist(t *testing.T) {
	raw := []byte(`{"cniVersion":"1.0.0","name":"aerolvm","plugins":[{"type":"bridge","bridge":"aerolvm0"}]}`)
	out, err := singlePluginNetconf(raw)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["type"] != "bridge" || m["cniVersion"] != "1.0.0" || m["name"] != "aerolvm" {
		t.Fatalf("plugin conf missing injected fields: %v", m)
	}
	if _, hasPlugins := m["plugins"]; hasPlugins {
		t.Fatal("extracted plugin conf should not carry the conflist plugins array")
	}
}

func TestSinglePluginNetconfEmptyPlugins(t *testing.T) {
	if _, err := singlePluginNetconf([]byte(`{"cniVersion":"1.0.0","plugins":[]}`)); err == nil {
		t.Fatal("want error for empty plugins array")
	}
}

func TestSinglePluginNetconfBareConf(t *testing.T) {
	raw := []byte(`{"cniVersion":"1.0.0","type":"bridge"}`)
	out, err := singlePluginNetconf(raw)
	if err != nil || !strings.Contains(string(out), `"bridge"`) {
		t.Fatalf("bare conf should pass through: out=%s err=%v", out, err)
	}
}
