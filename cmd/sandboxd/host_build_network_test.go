package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/network/buildnet"
	"github.com/aerol-ai/microvm/internal/network/netns"
)

type nopNetnsHost struct{}

func (nopNetnsHost) Realize(context.Context, netns.Slot) (string, string, error) { return "", "", nil }
func (nopNetnsHost) Remove(context.Context, netns.Slot) error                    { return nil }
func (nopNetnsHost) IPv4Addrs(context.Context, netns.Slot) ([]string, error)     { return nil, nil }

// buildNetworkSeams swaps the command's host-touching parts for recorders.
type buildNetworkSeams struct {
	conf, plugins string
	cfg           buildnet.Config
	up, down      int
	hostErr       error
	subnetErr     error
	upErr         error
	downErr       error
	built         bool
}

func stubBuildNetwork(t *testing.T) *buildNetworkSeams {
	t.Helper()
	s := &buildNetworkSeams{built: true}
	oh, os_, ou, od := buildNetworkHost, buildNetworkSubnet, buildNetworkUp, buildNetworkDown
	t.Cleanup(func() { buildNetworkHost, buildNetworkSubnet, buildNetworkUp, buildNetworkDown = oh, os_, ou, od })
	buildNetworkHost = func(conf, plugins string) (buildnet.Host, error) {
		s.conf, s.plugins = conf, plugins
		return nopNetnsHost{}, s.hostErr
	}
	buildNetworkSubnet = func(string) (netip.Prefix, error) { return netip.MustParsePrefix("10.88.0.0/16"), s.subnetErr }
	buildNetworkUp = func(_ context.Context, cfg buildnet.Config) (buildnet.Result, error) {
		s.up++
		s.cfg = cfg
		return buildnet.Result{Path: "/run/netns/" + buildnet.Name, IP: netip.MustParseAddr("10.88.0.3"), Built: s.built}, s.upErr
	}
	buildNetworkDown = func(_ context.Context, cfg buildnet.Config) error {
		s.down++
		s.cfg = cfg
		return s.downErr
	}
	return s
}

func TestHostBuildNetworkUp(t *testing.T) {
	s := stubBuildNetwork(t)
	t.Setenv("SB_CONTAINERD_CNI_CONF_PATH", "/etc/cni/net.d/custom.conflist")
	t.Setenv("SB_CONTAINERD_CNI_PLUGIN_DIR", "")
	var stdout, stderr bytes.Buffer
	if code := runHostCLI([]string{"build-network", "up"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if s.conf != "/etc/cni/net.d/custom.conflist" || s.plugins != "/opt/cni/bin" {
		t.Fatalf("CNI settings %q %q: want sandboxd's own, from its environment", s.conf, s.plugins)
	}
	if s.up != 1 || s.cfg.Subnet != netip.MustParsePrefix("10.88.0.0/16") || s.cfg.ResolvConf != buildnet.DefaultResolvConf {
		t.Fatalf("up %d with %+v", s.up, s.cfg)
	}
	if !strings.Contains(stdout.String(), "aerolvm.build built") || !strings.Contains(stdout.String(), "10.88.0.3") {
		t.Fatalf("stdout %q", stdout.String())
	}
	s.built = false
	stdout.Reset()
	if code := runHostCLI([]string{"build-network", "up", "--cni-conf", "/x.conflist", "--cni-plugin-dir", "/p", "--resolv-conf", "/r"}, &stdout, io.Discard); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if s.conf != "/x.conflist" || s.plugins != "/p" || s.cfg.ResolvConf != "/r" || !strings.Contains(stdout.String(), "kept") {
		t.Fatalf("flags not honored: %q %q %+v %q", s.conf, s.plugins, s.cfg, stdout.String())
	}
}

func TestHostBuildNetworkDown(t *testing.T) {
	s := stubBuildNetwork(t)
	var stdout bytes.Buffer
	if code := runHostCLI([]string{"build-network", "down"}, &stdout, io.Discard); code != 0 || s.down != 1 || s.up != 0 {
		t.Fatalf("exit %d, down %d up %d", code, s.down, s.up)
	}
	if !strings.Contains(stdout.String(), "removed") {
		t.Fatalf("stdout %q", stdout.String())
	}
}

func TestHostBuildNetworkErrors(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name string
		args []string
		set  func(*buildNetworkSeams)
		code int
		want string
	}{
		{"no verb", []string{"build-network"}, nil, 2, "want up, down or guard"},
		{"an unknown verb", []string{"build-network", "sideways"}, nil, 2, "want up, down or guard"},
		{"an unknown flag", []string{"build-network", "up", "--bogus"}, nil, 2, "flag provided but not defined"},
		{"an extra argument", []string{"build-network", "down", "now"}, nil, 2, `unexpected argument "now"`},
		{"no CNI runner", []string{"build-network", "up"}, func(s *buildNetworkSeams) { s.hostErr = boom }, 1, "boom"},
		{"no range", []string{"build-network", "up"}, func(s *buildNetworkSeams) { s.subnetErr = boom }, 1, "the sandboxes' range"},
		{"up fails", []string{"build-network", "up"}, func(s *buildNetworkSeams) { s.upErr = boom }, 1, "boom"},
		{"down fails", []string{"build-network", "down"}, func(s *buildNetworkSeams) { s.downErr = boom }, 1, "boom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := stubBuildNetwork(t)
			if tc.set != nil {
				tc.set(s)
			}
			var stderr bytes.Buffer
			if code := runHostCLI(tc.args, io.Discard, &stderr); code != tc.code || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("exit %d, %s; want %d, %q", code, stderr.String(), tc.code, tc.want)
			}
		})
	}
	for _, help := range [][]string{{"build-network", "--help"}, {"build-network", "up", "-h"}} {
		var stdout bytes.Buffer
		if code := runHostCLI(help, &stdout, io.Discard); code != 0 || !strings.Contains(stdout.String(), "build-network up|down") {
			t.Errorf("%v: exit %d", help, code)
		}
	}
}

// The real host seam builds an exec CNI runner over the given files.
func TestBuildNetworkHostSeam(t *testing.T) {
	h, err := buildNetworkHost("/etc/cni/net.d/aerolvm.conflist", t.TempDir())
	if err != nil {
		t.Fatalf("buildNetworkHost: %v", err)
	}
	if _, ok := h.(*netns.Host); !ok {
		t.Fatalf("host %T", h)
	}
}

// guardSeams records the guard subcommand's calls: the guard, then the
// exec that replaces the process.
type guardSeams struct {
	cfg              buildnet.GuardConfig
	order            []string
	ownErr, guardErr error
	lookErr, execErr error
	execPath         string
	execArgs         []string
}

func stubGuard(t *testing.T) *guardSeams {
	t.Helper()
	s := &guardSeams{execErr: errors.New("exec stub")}
	og, oo, oe, ol := buildNetworkGuard, buildNetworkOwn, buildNetworkExec, buildNetworkLook
	t.Cleanup(func() { buildNetworkGuard, buildNetworkOwn, buildNetworkExec, buildNetworkLook = og, oo, oe, ol })
	buildNetworkOwn = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.88.0.2")}, s.ownErr }
	buildNetworkGuard = func(_ context.Context, cfg buildnet.GuardConfig) error {
		s.order = append(s.order, "guard")
		s.cfg = cfg
		return s.guardErr
	}
	buildNetworkLook = func(name string) (string, error) { return "/usr/local/bin/" + name, s.lookErr }
	buildNetworkExec = func(path string, argv, _ []string) error {
		s.order = append(s.order, "exec")
		s.execPath, s.execArgs = path, argv
		return s.execErr
	}
	return s
}

// guard closes the steps' namespace first and only then replaces itself
// with buildkitd, so buildkitd never runs with the namespace open.
func TestHostBuildNetworkGuard(t *testing.T) {
	s := stubGuard(t)
	t.Setenv("ROOTLESSKIT_STATE_DIR", "/run/aerolvm-buildkit/rootlesskit")
	var stderr bytes.Buffer
	code := runHostCLI([]string{"build-network", "guard", "--", "buildkitd", "--config", "/etc/aerolvm-buildkit/buildkitd.toml"}, io.Discard, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "exec stub") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if strings.Join(s.order, ",") != "guard,exec" {
		t.Fatalf("order %v, want the guard before the exec", s.order)
	}
	if s.cfg.Netns != "/run/aerolvm-buildkit/rootlesskit/netns" || s.cfg.Steps.String() != buildnet.StepRange ||
		s.cfg.Uplink.String() != buildnet.UplinkRange || len(s.cfg.Own) != 1 {
		t.Fatalf("guard config %+v", s.cfg)
	}
	if s.execPath != "/usr/local/bin/buildkitd" || strings.Join(s.execArgs, " ") != "buildkitd --config /etc/aerolvm-buildkit/buildkitd.toml" {
		t.Fatalf("exec %q %q", s.execPath, s.execArgs)
	}
}

func TestHostBuildNetworkGuardErrors(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name string
		args []string
		set  func(*guardSeams)
		code int
		want string
		exec bool
	}{
		{"no command", []string{"build-network", "guard"}, nil, 2, "name the command", false},
		{"a bad range", []string{"build-network", "guard", "--steps", "nope", "--", "buildkitd"}, nil, 2, "nope", false},
		{"an unknown flag", []string{"build-network", "guard", "--bogus", "--", "buildkitd"}, nil, 2, "flag provided but not defined", false},
		{"no addresses", []string{"build-network", "guard", "--", "buildkitd"}, func(s *guardSeams) { s.ownErr = boom }, 1, "boom", false},
		{"the guard fails", []string{"build-network", "guard", "--", "buildkitd"}, func(s *guardSeams) { s.guardErr = boom }, 1, "boom", false},
		{"no such command", []string{"build-network", "guard", "--", "buildkitd"}, func(s *guardSeams) { s.lookErr = boom }, 1, "boom", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := stubGuard(t)
			if tc.set != nil {
				tc.set(s)
			}
			var stderr bytes.Buffer
			if code := runHostCLI(tc.args, io.Discard, &stderr); code != tc.code || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("exit %d, %s; want %d, %q", code, stderr.String(), tc.code, tc.want)
			}
			if got := len(s.order) > 0 && s.order[len(s.order)-1] == "exec"; got != tc.exec {
				t.Fatalf("exec ran: %v, want %v", got, tc.exec)
			}
		})
	}
	var stdout bytes.Buffer
	if code := runHostCLI([]string{"build-network", "guard", "-h"}, &stdout, io.Discard); code != 0 || !strings.Contains(stdout.String(), "build-network guard") {
		t.Fatalf("help: exit %d", code)
	}
}
