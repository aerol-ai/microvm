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
		{"no verb", []string{"build-network"}, nil, 2, "want up or down"},
		{"an unknown verb", []string{"build-network", "sideways"}, nil, 2, "want up or down"},
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
