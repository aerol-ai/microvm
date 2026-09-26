package docker

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

// failOnSecondDeleteBackend fails the second Delete call so ClearNetworkRules'
// ingress-clear path surfaces an error after egress clears successfully.
// failOnSecondDeleteBackend fails the second Delete call so ClearNetworkRules'
// ingress-clear path surfaces an error after egress clears successfully.
type failOnSecondDeleteBackend struct {
	memRuleBackend
	deletes int
}

func (b *failOnSecondDeleteBackend) Delete(table, chain string, spec ...string) error {
	b.deletes++
	if b.deletes >= 2 {
		return errors.New("ingress clear failed")
	}
	return b.memRuleBackend.Delete(table, chain, spec...)
}

type failOnFirstDeleteBackend struct {
	memRuleBackend
}

func (b *failOnFirstDeleteBackend) Delete(table, chain string, spec ...string) error {
	return errors.New("egress clear failed")
}

func TestCoverage95ClearNetworkRulesEgressFailure(t *testing.T) {
	rules := netrules.NewWithBackend(&failOnFirstDeleteBackend{})
	c := &Client{networkRules: rules}
	if err := c.ApplyNetworkBlockAll("10.0.0.2"); err != nil {
		t.Fatal(err)
	}
	if err := c.ClearNetworkRules("10.0.0.2"); err == nil || !strings.Contains(err.Error(), "egress clear failed") {
		t.Fatalf("ClearNetworkRules() = %v", err)
	}
}

func TestCoverage95ResolveContainerIPFromNetnsOwner(t *testing.T) {
	ownerIP := "172.30.0.5"
	c := &Client{
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if strings.Contains(r.URL.Path, "/containers/pause-owner/json") {
				return textResponse(http.StatusOK, inspectBody("pause-owner", "/pause", ownerIP, true, "running", 1)), nil
			}
			return textResponse(http.StatusNotFound, "missing"), nil
		})},
	}
	inspect := containerInspect{}
	inspect.HostConfig.NetworkMode = "container:pause-owner"
	if got := c.resolveContainerIP(context.Background(), inspect); got != ownerIP {
		t.Fatalf("resolveContainerIP() = %q, want %q", got, ownerIP)
	}
}

func TestCoverage95WaitForToolboxReadySocketAndFallback(t *testing.T) {
	t.Run("socket_hit", func(t *testing.T) {
		ln, err := NewReadyListener(coverageReadyDir(t), "sb", "token", "nonce")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			conn, dialErr := net.Dial("unix", ln.HostSocketPath())
			if dialErr != nil {
				return
			}
			defer conn.Close()
			_ = readyproto.Encode(conn, readyproto.ReadySignal{
				Event: readyproto.EventReady, SandboxID: "sb", Token: "token", Nonce: "nonce",
			})
		}()
		c := &Client{
			logger:             slog.Default(),
			toolboxWaitTimeout: time.Second,
			toolboxPort:        2280,
		}
		source, err := c.waitForToolboxReady(context.Background(), "127.0.0.1", ln)
		if err != nil || source != "socket" {
			t.Fatalf("waitForToolboxReady() = %q, %v", source, err)
		}
	})

	t.Run("health_fallback", func(t *testing.T) {
		ln, err := NewReadyListener(coverageReadyDir(t), "sb", "token", "nonce")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		ip, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		defer closeFn()
		c := &Client{
			logger:             slog.Default(),
			toolboxClient:      &http.Client{Timeout: time.Second},
			toolboxPort:        port,
			toolboxWaitTimeout: 300 * time.Millisecond,
		}
		source, err := c.waitForToolboxReady(context.Background(), ip, ln)
		if err != nil || source != "health" {
			t.Fatalf("waitForToolboxReady() = %q, %v", source, err)
		}
	})
}

func TestCoverage95WaitForToolboxReadyLogsInvalidAttempts(t *testing.T) {
	ln, err := NewReadyListener(coverageReadyDir(t), "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ip, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer closeFn()
	go func() {
		conn, dialErr := net.Dial("unix", ln.HostSocketPath())
		if dialErr != nil {
			return
		}
		defer conn.Close()
		_ = readyproto.Encode(conn, readyproto.ReadySignal{
			Event: readyproto.EventReady, SandboxID: "sb", Token: "wrong", Nonce: "nonce",
		})
	}()
	c := &Client{
		logger:             slog.Default(),
		toolboxClient:      &http.Client{Timeout: time.Second},
		toolboxPort:        port,
		toolboxWaitTimeout: 400 * time.Millisecond,
	}
	source, err := c.waitForToolboxReady(context.Background(), ip, ln)
	if err != nil || source != "health" {
		t.Fatalf("waitForToolboxReady() = %q, %v", source, err)
	}
	if n, _ := ln.InvalidAttempts(); n == 0 {
		t.Fatal("expected invalid socket attempts before health fallback")
	}
}

func TestCoverage95PollToolboxHealthRetries(t *testing.T) {
	calls := 0
	ip, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer closeFn()
	c := &Client{
		toolboxClient:      &http.Client{Timeout: time.Second},
		toolboxPort:        port,
		toolboxWaitTimeout: time.Second,
	}
	if err := c.pollToolboxHealth(context.Background(), ip); err != nil {
		t.Fatalf("pollToolboxHealth() = %v", err)
	}
	if calls < 2 {
		t.Fatalf("health polls = %d, want retry", calls)
	}
}

func TestCoverage95WaitForContainerRunningCancelled(t *testing.T) {
	c := &Client{
		waitTimeout: time.Second,
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, inspectBody("cid", "/sb", "", false, "created", 0)), nil
		})},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := c.waitForContainerRunning(ctx, "cid"); err == nil {
		t.Fatal("expected cancelled context error")
	}
}

func TestCoverage95ResolveContainerIPInspectFailure(t *testing.T) {
	c := &Client{
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusNotFound, "missing"), nil
		})},
	}
	inspect := containerInspect{}
	inspect.HostConfig.NetworkMode = "container:missing"
	if got := c.resolveContainerIP(context.Background(), inspect); got != "" {
		t.Fatalf("resolveContainerIP() = %q, want empty on inspect failure", got)
	}
}

func TestCoverage95ClearNetworkRulesIngressFailure(t *testing.T) {
	backend := &failOnSecondDeleteBackend{}
	rules := netrules.NewWithBackend(backend)
	c := &Client{networkRules: rules}
	if err := c.ApplyNetworkBlockAll("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := c.ApplyNetworkBlockIngress("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := c.ClearNetworkRules("10.0.0.1"); err == nil || !strings.Contains(err.Error(), "ingress clear failed") {
		t.Fatalf("ClearNetworkRules() = %v, want ingress clear failure", err)
	}
}

func TestCoverage95ReadySocketPathOwnership(t *testing.T) {
	dir := coverageReadyDir(t)
	c := &Client{readyDir: dir}
	inside := filepath.Join(dir, "sb.nonce.sock")
	if !c.readySocketPathOwnedByDir(inside) {
		t.Fatal("socket inside ready dir should be owned")
	}
	if !c.readySocketPathOwnedByDir(dir) {
		t.Fatal("ready dir itself should count as owned")
	}
	if c.readySocketPathOwnedByDir(filepath.Join(dir, "..", "other.sock")) {
		t.Fatal("path outside ready dir must not be owned")
	}
	if c.readySocketPathOwnedByDir("") {
		t.Fatal("empty path must not be owned")
	}
	if (&Client{}).readySocketPathOwnedByDir(inside) {
		t.Fatal("empty readyDir must not claim ownership")
	}
}

func TestCoverage95ReadySocketBindSourcesFromMounts(t *testing.T) {
	dir := coverageReadyDir(t)
	sock := filepath.Join(dir, "mount.sock")
	inspect := containerInspect{}
	inspect.HostConfig.Binds = []string{sock + ":" + GuestReadySocketPath + ":rw"}
	inspect.Mounts = []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	}{{Source: sock, Destination: GuestReadySocketPath}}
	sources := readySocketBindSourcesFromInspect(inspect)
	if len(sources) != 2 || sources[0] != sock || sources[1] != sock {
		t.Fatalf("bind sources = %v", sources)
	}
	if _, ok := readySocketSourceFromBind(""); ok {
		t.Fatal("empty bind must not parse")
	}
	if _, ok := readySocketSourceFromBind(":/run/aerol/ready.sock"); ok {
		t.Fatal("bind without source must not parse")
	}
}

func TestCoverage95SweepOrphanReadySocketsClientErrors(t *testing.T) {
	dir := coverageReadyDir(t)
	c := &Client{
		readyDir: dir,
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "list failed"), nil
		})},
	}
	if err := c.SweepOrphanReadySockets(context.Background()); err == nil {
		t.Fatal("expected list failure")
	}

	c.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/containers/json" {
			return jsonResponse(http.StatusOK, []containerSummary{
				{ID: "managed", Labels: map[string]string{managedLabelKey: "true"}},
			}), nil
		}
		return textResponse(http.StatusInternalServerError, "inspect failed"), nil
	})}
	if err := c.SweepOrphanReadySockets(context.Background()); err == nil {
		t.Fatal("expected inspect failure")
	}
}

func TestCoverage95ClientReadySocketListUnmanaged(t *testing.T) {
	dir := coverageReadyDir(t)
	c := &Client{
		readyDir: dir,
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.Path {
			case "/containers/json":
				return jsonResponse(http.StatusOK, []containerSummary{
					{ID: "unmanaged", Labels: map[string]string{}},
					{ID: "managed", Labels: map[string]string{managedLabelKey: "true"}},
				}), nil
			case "/containers/managed/json":
				return textResponse(http.StatusOK, `{"HostConfig":{"Binds":[]},"Mounts":[]}`), nil
			default:
				return textResponse(http.StatusNotFound, "missing"), nil
			}
		})},
	}
	keep, err := c.readySocketBindSources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keep) != 0 {
		t.Fatalf("unmanaged-only list should not keep sockets: %v", keep)
	}
}
