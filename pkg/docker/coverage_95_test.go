package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

func TestCoverage95NetworkPolicyAndReadySocketHelpers(t *testing.T) {
	c := &Client{networkRules: disabledRules(t)}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"apply empty", func() error { return c.ApplyEgressPolicy("", nil, nil) }},
		{"apply policy", func() error {
			return c.ApplyEgressPolicy("172.17.0.2", []string{"10.0.0.0/8"}, []string{"192.168.0.0/16"})
		}},
		{"clear policy", func() error { return c.ClearEgressPolicy("172.17.0.2", nil, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err != nil {
				t.Fatal(err)
			}
		})
	}

	if err := EnsureReadyDir(""); err == nil {
		t.Fatal("empty ready dir unexpectedly succeeded")
	}
	dir := filepath.Join(t.TempDir(), "ready")
	if err := EnsureReadyDir(dir); err != nil {
		t.Fatalf("EnsureReadyDir: %v", err)
	}
	nonce, err := MintReadyNonce()
	if err != nil || len(nonce) != 32 {
		t.Fatalf("MintReadyNonce() = %q, %v", nonce, err)
	}
	if (*ReadyListener)(nil).HostSocketPath() != "" {
		t.Fatal("nil listener reported a socket path")
	}
}

func TestCoverage95ReadyListenerVerificationAndCleanup(t *testing.T) {
	dir := coverageReadyDir(t)
	ln, err := NewReadyListener(dir, "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	for _, signal := range []readyproto.ReadySignal{
		{SandboxID: "wrong", Token: "token", Nonce: "nonce"},
		{SandboxID: "sb", Token: "token", Nonce: "wrong"},
		{SandboxID: "sb", Token: "wrong", Nonce: "nonce"},
	} {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- ln.readAndVerify(server) }()
		if err := readyproto.Encode(client, signal); err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		if err := <-done; err == nil {
			t.Fatalf("signal %+v unexpectedly verified", signal)
		}
	}

	ln.recordInvalidAttempt("manual")
	if n, reason := ln.InvalidAttempts(); n != 1 || reason != "manual" {
		t.Fatalf("InvalidAttempts() = (%d,%q)", n, reason)
	}
	if n, reason := (*ReadyListener)(nil).InvalidAttempts(); n != 0 || reason != "" {
		t.Fatalf("nil InvalidAttempts() = (%d,%q)", n, reason)
	}

	parkPath := filepath.Join(dir, "parked.sock")
	parked, err := net.Listen("unix", parkPath)
	if err != nil {
		t.Fatal(err)
	}
	parkedReadySockets.Store(parkPath, parked)
	closeParkedReadySocket(parkPath)
	if _, ok := parkedReadySockets.Load(parkPath); ok {
		t.Fatal("parked listener remained registered")
	}

	activePath := ln.HostSocketPath()
	RemoveReadySocketsForSandbox(dir, "")
	if _, err := os.Stat(activePath); err != nil {
		t.Fatalf("empty cleanup removed active socket: %v", err)
	}
	RemoveReadySocketsForSandbox("", "sb")

	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ln.ParkBindSource(); err != nil {
		t.Fatal(err)
	}
	if err := ln.ParkBindSource(); err != nil {
		t.Fatal(err)
	}
	RemoveReadySocketsForSandbox(dir, "sb")
	if _, err := os.Stat(activePath); !os.IsNotExist(err) {
		t.Fatalf("parked socket was not removed: %v", err)
	}
}

func TestCoverage95ReadyListenerWaitRejectsInvalidThenSucceeds(t *testing.T) {
	ln, err := NewReadyListener(coverageReadyDir(t), "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for _, token := range []string{"wrong", "token"} {
			conn, dialErr := net.Dial("unix", ln.HostSocketPath())
			if dialErr != nil {
				return
			}
			_ = readyproto.Encode(conn, readyproto.ReadySignal{
				Event: readyproto.EventReady, SandboxID: "sb", Token: token, Nonce: "nonce",
			})
			_ = conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := ln.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if n, reason := ln.InvalidAttempts(); n != 1 || !strings.Contains(reason, "token") {
		t.Fatalf("invalid attempts = (%d,%q)", n, reason)
	}
}

func TestCoverage95ReadySocketSweepAndTimeoutPaths(t *testing.T) {
	dir := coverageReadyDir(t)
	active, err := NewReadyListener(dir, "active", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = active.Close() })
	orphan := filepath.Join(dir, "dead.nonce.sock")
	if err := os.WriteFile(orphan, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SweepOrphanReadySockets(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan remained: %v", err)
	}
	if _, err := os.Stat(active.HostSocketPath()); err != nil {
		t.Fatalf("active socket removed: %v", err)
	}
	if err := SweepOrphanReadySockets(""); err != nil {
		t.Fatal(err)
	}
	if err := SweepOrphanReadySockets(filepath.Join(dir, "missing")); err != nil {
		t.Fatal(err)
	}

	timeout, err := NewReadyListener(dir, "timeout", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = timeout.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := timeout.Wait(ctx); err == nil {
		t.Fatal("wait without a client unexpectedly succeeded")
	}
	for _, id := range []string{"", "../invalid", strings.Repeat("a", 129)} {
		if err := validateReadySandboxID(id); err == nil {
			t.Fatalf("invalid sandbox ID %q accepted", id)
		}
	}
}

func TestCoverage95ClientReadySocketSweepAndMetrics(t *testing.T) {
	dir := coverageReadyDir(t)
	keep := filepath.Join(dir, "keep.sock")
	orphan := filepath.Join(dir, "orphan.sock")
	for _, path := range []string{keep, orphan} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := &Client{
		readyDir: dir,
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.Path {
			case "/containers/json":
				return jsonResponse(http.StatusOK, []containerSummary{
					{ID: "managed", Labels: map[string]string{managedLabelKey: "true"}},
					{ID: "unmanaged", Labels: map[string]string{}},
				}), nil
			case "/containers/managed/json":
				return textResponse(http.StatusOK, `{"HostConfig":{"Binds":["`+keep+`:`+GuestReadySocketPath+`"]}}`), nil
			}
			return textResponse(http.StatusNotFound, "missing"), nil
		})},
	}
	if err := c.SweepOrphanReadySockets(context.Background()); err != nil {
		t.Fatalf("SweepOrphanReadySockets: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("kept socket removed: %v", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan socket remained: %v", err)
	}
	if c.readySocketPathOwnedByDir(filepath.Join(dir, "..", "outside.sock")) {
		t.Fatal("path outside ready directory was accepted")
	}
	if err := (&Client{}).SweepOrphanReadySockets(context.Background()); err != nil {
		t.Fatalf("empty ready dir: %v", err)
	}

	recordReadySocketHit(17)
	recordReadySocketFallback(23)
	recordReadySocketTimeout()
	recordReadySocketInvalid()
	if got := ReadyWaitMS(); got != 23 {
		t.Fatalf("ReadyWaitMS() = %d, want 23", got)
	}
}

func TestCoverage95ParkContainerHappyPath(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	c := newPoolClient(t, d, func(c *Client) {
		c.readyDir = coverageReadyDir(t)
		c.network = "custom"
		c.parkDiskGB = 2
		c.waitTimeout = time.Second
	})
	guestDone := make(chan struct{})
	t.Cleanup(func() { close(guestDone) })
	d.start = func() *http.Response {
		var request struct {
			Env []string `json:"Env"`
		}
		if err := json.Unmarshal(d.createBodies[len(d.createBodies)-1], &request); err != nil {
			t.Fatalf("decode park create request: %v", err)
		}
		var token, nonce string
		for _, env := range request.Env {
			switch {
			case strings.HasPrefix(env, "SB_TOOLBOX_TOKEN="):
				token = strings.TrimPrefix(env, "SB_TOOLBOX_TOKEN=")
			case strings.HasPrefix(env, "SB_READY_NONCE="):
				nonce = strings.TrimPrefix(env, "SB_READY_NONCE=")
			}
		}
		go func() {
			for i := 0; i < 100; i++ {
				entries, err := os.ReadDir(c.readyDir)
				if err == nil {
					for _, entry := range entries {
						if !strings.HasSuffix(entry.Name(), ".sock") {
							continue
						}
						conn, dialErr := net.Dial("unix", filepath.Join(c.readyDir, entry.Name()))
						if dialErr != nil {
							continue
						}
						_ = readyproto.EncodeParked(conn, readyproto.ParkedSignal{
							Event: readyproto.EventParked, Token: token, Nonce: nonce,
						})
						<-guestDone
						_ = conn.Close()
						return
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
		return textResponse(http.StatusNoContent, "")
	}

	slot, err := c.parkContainer(context.Background(), "park-coverage", dockerpool.Key{
		Image: "alpine:3.20", Runtime: models.RuntimeDocker,
	})
	if err != nil {
		t.Fatalf("parkContainer: %v", err)
	}
	if slot.ContainerID != "cid-park" || slot.ContainerIP != "172.17.0.9" || slot.ImageID != "sha256:img1" {
		t.Fatalf("parked slot = %+v", slot)
	}
	if err := c.destroyParked(context.Background(), slot); err != nil {
		t.Fatalf("destroyParked: %v", err)
	}
}

func TestCoverage95NetnsPoolSpawnAndAdopt(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	c := newPoolClient(t, d, func(c *Client) { c.network = "custom-net" })
	pool := newNetnsPool(slogDefault(), c, 1, "pause:latest", time.Second)
	slot, err := pool.spawnPause(context.Background())
	if err != nil {
		t.Fatalf("spawnPause: %v", err)
	}
	if slot.containerID != "cid-park" || slot.ip != "172.17.0.9" {
		t.Fatalf("spawned slot = %+v", slot)
	}
	pool.free = append(pool.free, slot)
	adopted, ok := pool.Adopt(context.Background(), "sandbox")
	if !ok || adopted.containerID != slot.containerID {
		t.Fatalf("Adopt() = %+v, %v", adopted, ok)
	}
	if _, ok := pool.Adopt(context.Background(), "other"); ok {
		t.Fatal("empty pool unexpectedly adopted a slot")
	}
	pool.ReleaseAdopted(context.Background(), adopted)
}

func TestCoverage95ParkedListenerValidationPaths(t *testing.T) {
	for _, args := range []struct {
		dir, slot, token, nonce string
	}{
		{dir: coverageReadyDir(t), token: "token", nonce: "nonce"},
		{dir: coverageReadyDir(t), slot: "slot", nonce: "nonce"},
		{dir: coverageReadyDir(t), slot: "slot", token: "token"},
		{slot: "slot", token: "token", nonce: "nonce"},
	} {
		if _, err := NewParkedListener(args.dir, args.slot, args.token, args.nonce); err == nil {
			t.Fatalf("NewParkedListener(%+v) unexpectedly succeeded", args)
		}
	}
	if err := (*ParkedListener)(nil).WaitParked(context.Background()); err == nil {
		t.Fatal("nil WaitParked unexpectedly succeeded")
	}
	if (*ParkedListener)(nil).Alive() {
		t.Fatal("nil parked listener reported alive")
	}
	if err := (*ParkedListener)(nil).Adopt(context.Background(), "sb", "token", "nonce"); err == nil {
		t.Fatal("nil Adopt unexpectedly succeeded")
	}

	pl, err := NewParkedListener(coverageReadyDir(t), "slot", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })
	for _, signal := range []readyproto.ParkedSignal{
		{Event: readyproto.EventParked, Token: "token", Nonce: "wrong"},
		{Event: readyproto.EventParked, Token: "wrong", Nonce: "nonce"},
	} {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- pl.verifyParked(server) }()
		if err := readyproto.EncodeParked(client, signal); err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		if err := <-done; err == nil {
			t.Fatalf("invalid parked signal %+v verified", signal)
		}
	}
}

func TestCoverage95ReadyListenerValidationAndInvalidLimit(t *testing.T) {
	for _, args := range []struct {
		dir, sandboxID, token, nonce string
	}{
		{dir: coverageReadyDir(t), token: "token", nonce: "nonce"},
		{dir: coverageReadyDir(t), sandboxID: "sandbox", nonce: "nonce"},
		{dir: coverageReadyDir(t), sandboxID: "sandbox", token: "token"},
		{sandboxID: "sandbox", token: "token", nonce: "nonce"},
	} {
		if _, err := NewReadyListener(args.dir, args.sandboxID, args.token, args.nonce); err == nil {
			t.Fatalf("NewReadyListener(%+v) unexpectedly succeeded", args)
		}
	}
	if err := (*ReadyListener)(nil).Wait(context.Background()); err == nil {
		t.Fatal("nil Wait unexpectedly succeeded")
	}

	ln, err := NewReadyListener(coverageReadyDir(t), "sandbox", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for i := 0; i < maxInvalidReadyAttempts; i++ {
			conn, dialErr := net.Dial("unix", ln.HostSocketPath())
			if dialErr != nil {
				return
			}
			_ = readyproto.Encode(conn, readyproto.ReadySignal{
				Event: readyproto.EventReady, SandboxID: "sandbox", Token: "wrong", Nonce: "nonce",
			})
			_ = conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := ln.Wait(ctx); err == nil {
		t.Fatal("Wait accepted too many invalid signals")
	}
}

func coverageReadyDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

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

// failInsertBackend fails the first Insert to exercise applyAdoptNetworkPolicy's
// rollback path when selective egress cannot be installed.
type failInsertBackend struct {
	memRuleBackend
	inserts int
}

func (b *failInsertBackend) Insert(table, chain string, pos int, spec ...string) error {
	b.inserts++
	if b.inserts == 1 {
		return errors.New("egress policy insert failed")
	}
	return b.memRuleBackend.Insert(table, chain, pos, spec...)
}

type failBlockAllEgressBackend struct {
	memRuleBackend
}

func (b *failBlockAllEgressBackend) Insert(table, chain string, pos int, spec ...string) error {
	if len(spec) >= 4 && spec[0] == "-s" && spec[len(spec)-1] == "DROP" {
		return errors.New("block all egress failed")
	}
	return b.memRuleBackend.Insert(table, chain, pos, spec...)
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

func TestCoverage95ResolveImageIDCachedRecordsTiming(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	c := newPoolClient(t, d, func(c *Client) {
		c.imageIDs = newImageIDCache(time.Minute)
	})
	ctx, timing := createtiming.With(context.Background())
	id, err := c.resolveImageIDCached(ctx, "alpine:3.20")
	if err != nil || id != "sha256:img1" {
		t.Fatalf("resolveImageIDCached() = %q, %v", id, err)
	}
	var found bool
	for _, st := range timing.Stages() {
		if st.Name == "docker_image" && st.Desc == "resolve" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected docker_image resolve stage")
	}
}

func TestCoverage95BuildImageLockedConcurrentDedup(t *testing.T) {
	var builds atomic.Int32
	c := &Client{
		streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			builds.Add(1)
			time.Sleep(50 * time.Millisecond)
			return textResponse(http.StatusOK, `{"stream":"ok"}`), nil
		})},
	}
	req := BuildImageRequest{Tag: "aerolvm-build/dedup:latest", DockerfileContent: "FROM scratch"}
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { errCh <- c.BuildImage(context.Background(), req) }()
	}
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("BuildImage() = %v", err)
		}
	}
	if got := builds.Load(); got != 1 {
		t.Fatalf("build calls = %d, want 1 (deduped)", got)
	}
}

func TestCoverage95AssembleBuildContextNonZeroTrailer(t *testing.T) {
	extra := makeTar(t, map[string]string{"ctx.txt": "data"})
	out, err := assembleBuildContext("FROM scratch\n", extra)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty tar")
	}
}

func TestCoverage95NewReadyListenerStalePathBlocksCreate(t *testing.T) {
	dir := coverageReadyDir(t)
	path := readySocketHostPath(dir, "sb", "nonce")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "block"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewReadyListener(dir, "sb", "token", "nonce")
	if err == nil || !strings.Contains(err.Error(), "unlink stale ready socket") {
		t.Fatalf("NewReadyListener() = %v", err)
	}
}

func TestCoverage95NewParkedListenerPathTooLong(t *testing.T) {
	dir := coverageReadyDir(t)
	if _, err := NewParkedListener(dir, strings.Repeat("p", 90), "tok", "nonce"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("NewParkedListener() = %v, want path length error", err)
	}
}

func TestCoverage95AOCRPullAuthEdgePaths(t *testing.T) {
	dir := coverageReadyDir(t)
	emptyPAT := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyPAT, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Client{logger: slog.Default()}
	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai", "aocr.aerol.ai"}, "cluster-1", emptyPAT)
	if got := c.resolveAOCRPullAuth("aocr.aerol.ai/cluster/cluster-1/templates/x:latest"); got != nil {
		t.Fatalf("empty PAT should resolve to nil auth, got %+v", got)
	}

	c.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "cluster-1", filepath.Join(dir, "missing"))
	if got := c.resolveAOCRPullAuth("aocr.aerol.ai/cluster/cluster-1/templates/x:latest"); got != nil {
		t.Fatalf("missing PAT should resolve to nil auth, got %+v", got)
	}
	if c.aocrPullAuth == nil {
		t.Fatal("expected configured auth object")
	}
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

func TestCoverage95ParkContainerReinspectAfterPullFails(t *testing.T) {
	pulled := false
	d := &poolFakeDaemon{t: t}
	d.imageInspect = func() *http.Response {
		if !pulled {
			return textResponse(http.StatusNotFound, "missing")
		}
		return textResponse(http.StatusNotFound, "still missing")
	}
	d.pull = func() *http.Response {
		pulled = true
		return textResponse(http.StatusOK, "{}")
	}
	c := newPoolClient(t, d, func(c *Client) {
		c.pulls = make(map[string]*imagePull)
		c.readyDir = coverageReadyDir(t)
	})
	_, err := c.parkContainer(context.Background(), "park-reinspect", dockerpool.Key{
		Image: "alpine:3.20", Runtime: models.RuntimeDocker,
	})
	if err == nil || !strings.Contains(err.Error(), "inspect image") {
		t.Fatalf("err = %v", err)
	}
}

func TestCoverage95AdoptParkedUpdateFailure(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	d.update = func() *http.Response {
		return textResponse(http.StatusInternalServerError, "update failed")
	}
	c := newPoolClient(t, d, nil)
	pl, err := NewParkedListener(coverageReadyDir(t), "park-upd", "boot", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })
	go func() {
		conn, dialErr := net.Dial("unix", pl.HostSocketPath())
		if dialErr != nil {
			return
		}
		defer conn.Close()
		_ = readyproto.EncodeParked(conn, readyproto.ParkedSignal{
			Event: readyproto.EventParked, Token: "boot", Nonce: "nonce",
		})
		frame, decodeErr := readyproto.DecodeAdopt(bufio.NewReader(conn))
		if decodeErr != nil {
			return
		}
		_ = readyproto.Encode(conn, readyproto.ReadySignal{
			Event: readyproto.EventReady, SandboxID: frame.SandboxID, Token: frame.Token, Nonce: frame.Nonce,
		})
	}()
	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := pl.WaitParked(waitCtx); err != nil {
		t.Fatalf("WaitParked: %v", err)
	}
	slot := &dockerpool.ParkedSlot{
		ID: "park-upd", ContainerID: "cid-park", ContainerIP: "172.17.0.9", Handle: pl,
	}
	_, err = c.adoptParked(context.Background(), models.CreateSandboxRequest{CPU: 2, MemoryMB: 2048}, "sb-upd", "tok", slot)
	if err == nil || !strings.Contains(err.Error(), "update failed") {
		t.Fatalf("adoptParked() = %v", err)
	}
}

func TestCoverage95RemoveReadySocketsSkipsActive(t *testing.T) {
	dir := coverageReadyDir(t)
	ln, err := NewReadyListener(dir, "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	path := ln.HostSocketPath()
	RemoveReadySocketsForSandbox(dir, "sb")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("active socket removed: %v", err)
	}
	_ = ln.Close()
	RemoveReadySocketsForSandbox(dir, "sb")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("closed socket not removed: %v", err)
	}
}

func TestCoverage95ParkContainerMissingToolbox(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	c := newPoolClient(t, d, func(c *Client) {
		c.toolboxBinaryPath = filepath.Join(coverageReadyDir(t), "missing-toolbox")
		c.readyDir = coverageReadyDir(t)
	})
	_, err := c.parkContainer(context.Background(), "park-toolbox", dockerpool.Key{
		Image: "alpine:3.20", Runtime: models.RuntimeDocker,
	})
	if err == nil || !strings.Contains(err.Error(), "toolbox binary not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestCoverage95TryWarmAdoptMissRecordsTiming(t *testing.T) {
	pool := dockerpool.New(slog.Default())
	c := newPoolClient(t, &poolFakeDaemon{t: t}, func(c *Client) {
		c.SetWarmPool(pool)
		c.readyEnabled = true
	})
	ctx, timing := createtiming.With(context.Background())
	_, err := c.tryWarmAdopt(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, dockerpool.ErrNoSlot) {
		t.Fatalf("err = %v", err)
	}
	var poolStage *createtiming.Stage
	for _, st := range timing.Stages() {
		if st.Name == "docker_pool" {
			poolStage = &st
			break
		}
	}
	if poolStage == nil || poolStage.Desc != "miss" {
		t.Fatalf("docker_pool stage = %+v, want miss", poolStage)
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

func TestCoverage95PushImageDecodeErrorDetail(t *testing.T) {
	validAuth := models.RegistryAuth{Username: "u", Password: "p", Server: "ghcr.io"}
	c := &Client{
		logger:     slog.Default(),
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return textResponse(http.StatusOK, "{}"), nil })},
		streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, `{"errorDetail":{"message":"denied"}}`), nil
		})},
	}
	_, err := c.PushImage(context.Background(), PushImageRequest{
		SourceTag: "src:latest", DestRef: "ghcr.io/org/img:v1", Auth: validAuth,
	})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("PushImage() = %v", err)
	}
}

func TestCoverage95ResolveImageIDCachedHit(t *testing.T) {
	c := &Client{imageIDs: newImageIDCache(time.Minute)}
	c.imageIDs.Put("alpine:3.20", "sha256:cached")
	id, err := c.resolveImageIDCached(context.Background(), "alpine:3.20")
	if err != nil || id != "sha256:cached" {
		t.Fatalf("resolveImageIDCached() = %q, %v", id, err)
	}
}

func TestCoverage95ParkBindSourceNilSafe(t *testing.T) {
	var ln *ReadyListener
	if err := ln.ParkBindSource(); err != nil {
		t.Fatalf("nil ParkBindSource() = %v", err)
	}
}

func TestCoverage95NewParkedListenerMkdirFailure(t *testing.T) {
	dir := coverageReadyDir(t)
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewParkedListener(blocker, "slot", "tok", "nonce")
	if err == nil || !strings.Contains(err.Error(), "mkdir ready dir") {
		t.Fatalf("NewParkedListener() = %v", err)
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

func TestCoverage95ReadyListenerWaitAcceptTimeoutRetry(t *testing.T) {
	ln, err := NewReadyListener(coverageReadyDir(t), "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := ln.Wait(ctx); err == nil {
		t.Fatal("expected timeout without valid ready push")
	}
}

func TestCoverage95ParkContainerRuntimeWaitFailure(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	d.containerGet = func() *http.Response {
		return textResponse(http.StatusOK, inspectBody("cid-park", "/park", "", false, "exited", 0))
	}
	c := newPoolClient(t, d, func(c *Client) {
		c.readyDir = coverageReadyDir(t)
		c.waitTimeout = 50 * time.Millisecond
		c.toolboxWaitTimeout = time.Second
	})
	guestDone := make(chan struct{})
	t.Cleanup(func() { close(guestDone) })
	d.start = func() *http.Response {
		var request struct {
			Env []string `json:"Env"`
		}
		_ = json.Unmarshal(d.createBodies[len(d.createBodies)-1], &request)
		var token, nonce string
		for _, env := range request.Env {
			switch {
			case strings.HasPrefix(env, "SB_TOOLBOX_TOKEN="):
				token = strings.TrimPrefix(env, "SB_TOOLBOX_TOKEN=")
			case strings.HasPrefix(env, "SB_READY_NONCE="):
				nonce = strings.TrimPrefix(env, "SB_READY_NONCE=")
			}
		}
		go func() {
			for i := 0; i < 100; i++ {
				entries, readErr := os.ReadDir(c.readyDir)
				if readErr == nil {
					for _, entry := range entries {
						if !strings.HasSuffix(entry.Name(), ".sock") {
							continue
						}
						conn, dialErr := net.Dial("unix", filepath.Join(c.readyDir, entry.Name()))
						if dialErr != nil {
							continue
						}
						_ = readyproto.EncodeParked(conn, readyproto.ParkedSignal{
							Event: readyproto.EventParked, Token: token, Nonce: nonce,
						})
						<-guestDone
						_ = conn.Close()
						return
					}
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
		return textResponse(http.StatusNoContent, "")
	}
	_, err := c.parkContainer(context.Background(), "park-runtime", dockerpool.Key{
		Image: "alpine:3.20", Runtime: models.RuntimeDocker,
	})
	if err == nil || !strings.Contains(err.Error(), "timed out waiting for sandbox runtime") {
		t.Fatalf("err = %v", err)
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

func TestCoverage95SweepOrphanReadySocketsExceptKeepsPaths(t *testing.T) {
	dir := coverageReadyDir(t)
	keepPath := filepath.Join(dir, "keep.sock")
	parkedPath := filepath.Join(dir, "parked.sock")
	activePath := filepath.Join(dir, "active.sock")
	if err := os.WriteFile(keepPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", activePath)
	if err != nil {
		t.Fatal(err)
	}
	activeReadySockets.Store(activePath, struct{}{})
	parkedLn, err := net.Listen("unix", parkedPath)
	if err != nil {
		t.Fatal(err)
	}
	parkedReadySockets.Store(parkedPath, parkedLn)

	if err := SweepOrphanReadySocketsExcept(dir, map[string]struct{}{keepPath: {}}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{keepPath, parkedPath, activePath} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("path %s was removed: %v", path, statErr)
		}
	}
	orphan := filepath.Join(dir, "gone.sock")
	if err := os.WriteFile(orphan, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SweepOrphanReadySocketsExcept(dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan remained: %v", err)
	}
	_ = ln.Close()
	_ = parkedLn.Close()
	activeReadySockets.Delete(activePath)
	parkedReadySockets.Delete(parkedPath)
}

func TestCoverage95NewReadyListenerPathTooLong(t *testing.T) {
	dir := coverageReadyDir(t)
	longID := strings.Repeat("a", 90)
	if _, err := NewReadyListener(dir, longID, "token", "nonce"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("NewReadyListener() = %v, want path length error", err)
	}
}

func TestCoverage95ParkBindSourceAlreadyParked(t *testing.T) {
	dir := coverageReadyDir(t)
	ln, err := NewReadyListener(dir, "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	path := ln.HostSocketPath()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ln.ParkBindSource(); err != nil {
		t.Fatal(err)
	}
	if err := ln.ParkBindSource(); err != nil {
		t.Fatalf("second ParkBindSource() = %v", err)
	}
	if _, ok := parkedReadySockets.Load(path); !ok {
		t.Fatal("parked socket was not registered")
	}
	closeParkedReadySocket(path)
}

func TestCoverage95ReadyListenerWaitAcceptError(t *testing.T) {
	dir := coverageReadyDir(t)
	ln, err := NewReadyListener(dir, "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := ln.listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := ln.Wait(ctx); err == nil || !strings.Contains(err.Error(), "ready socket accept") {
		t.Fatalf("Wait() = %v, want accept error", err)
	}
}

func TestCoverage95ApplyAdoptNetworkPolicyEgressFailure(t *testing.T) {
	backend := &failInsertBackend{}
	rules := netrules.NewWithBackend(backend)
	c := &Client{networkRules: rules}
	req := models.CreateSandboxRequest{NetworkAllowOut: []string{"10.0.0.0/8"}}
	if err := c.applyAdoptNetworkPolicy("172.17.0.2", req); err == nil || !strings.Contains(err.Error(), "egress policy insert failed") {
		t.Fatalf("applyAdoptNetworkPolicy() = %v", err)
	}
}

func TestCoverage95AdoptParkedInspectsWhenIPMissing(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	c := newPoolClient(t, d, nil)
	pl, err := NewParkedListener(coverageReadyDir(t), "park-ip", "boot", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })

	done := make(chan struct{})
	go func() {
		conn, dialErr := net.Dial("unix", pl.HostSocketPath())
		if dialErr != nil {
			return
		}
		defer conn.Close()
		_ = readyproto.EncodeParked(conn, readyproto.ParkedSignal{
			Event: readyproto.EventParked, Token: "boot", Nonce: "nonce",
		})
		frame, decodeErr := readyproto.DecodeAdopt(bufio.NewReader(conn))
		if decodeErr != nil {
			return
		}
		_ = readyproto.Encode(conn, readyproto.ReadySignal{
			Event: readyproto.EventReady, SandboxID: frame.SandboxID, Token: frame.Token, Nonce: frame.Nonce,
		})
		close(done)
	}()
	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := pl.WaitParked(waitCtx); err != nil {
		t.Fatalf("WaitParked: %v", err)
	}

	slot := &dockerpool.ParkedSlot{
		ID: "park-ip", ContainerID: "cid-park", ContainerIP: "",
		Handle: pl,
	}
	rt, err := c.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb-ip", "tok", slot)
	if err != nil {
		t.Fatalf("adoptParked: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("guest adopt handshake did not complete")
	}
	if rt.ContainerIP != "172.17.0.9" || d.containerGetCalls == 0 {
		t.Fatalf("runtime = %+v, inspect calls = %d", rt, d.containerGetCalls)
	}
}

func TestCoverage95ResolveImageIDAndCachedMiss(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	c := newPoolClient(t, d, func(c *Client) {
		c.imageIDs = newImageIDCache(time.Minute)
	})
	id, err := c.resolveImageID(context.Background(), "alpine:3.20")
	if err != nil || id != "sha256:img1" {
		t.Fatalf("resolveImageID() = %q, %v", id, err)
	}
	if got, ok := c.imageIDs.Get("alpine:3.20"); !ok || got != "sha256:img1" {
		t.Fatalf("cache = %q, %v", got, ok)
	}

	d.imageInspect = func() *http.Response {
		return textResponse(http.StatusNotFound, "missing")
	}
	if _, err := c.resolveImageID(context.Background(), "missing:latest"); err == nil {
		t.Fatal("expected inspect failure")
	}
}

func TestCoverage95ParkContainerFailurePaths(t *testing.T) {
	readyDir := func(t *testing.T) string {
		t.Helper()
		return coverageReadyDir(t)
	}

	t.Run("invalid_runtime", func(t *testing.T) {
		d := &poolFakeDaemon{t: t}
		c := newPoolClient(t, d, nil)
		_, err := c.parkContainer(context.Background(), "park-bad-rt", dockerpool.Key{
			Image: "alpine:3.20", Runtime: "not-a-runtime",
		})
		if err == nil || !strings.Contains(err.Error(), "runtime") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("pull_failure", func(t *testing.T) {
		d := &poolFakeDaemon{t: t}
		d.imageInspect = func() *http.Response {
			return textResponse(http.StatusNotFound, "missing")
		}
		d.pull = func() *http.Response {
			return textResponse(http.StatusInternalServerError, "pull denied")
		}
		c := newPoolClient(t, d, func(c *Client) {
			c.pulls = make(map[string]*imagePull)
			c.readyDir = readyDir(t)
		})
		_, err := c.parkContainer(context.Background(), "park-pull", dockerpool.Key{
			Image: "alpine:3.20", Runtime: models.RuntimeDocker,
		})
		if err == nil || !strings.Contains(err.Error(), "pull image for park") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("start_failure", func(t *testing.T) {
		d := &poolFakeDaemon{t: t}
		d.start = func() *http.Response {
			return textResponse(http.StatusInternalServerError, "start failed")
		}
		c := newPoolClient(t, d, func(c *Client) {
			c.readyDir = readyDir(t)
		})
		_, err := c.parkContainer(context.Background(), "park-start", dockerpool.Key{
			Image: "alpine:3.20", Runtime: models.RuntimeDocker,
		})
		if err == nil || !strings.Contains(err.Error(), "park start") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("park_ready_timeout", func(t *testing.T) {
		d := &poolFakeDaemon{t: t}
		c := newPoolClient(t, d, func(c *Client) {
			c.toolboxWaitTimeout = 50 * time.Millisecond
			c.readyDir = readyDir(t)
		})
		_, err := c.parkContainer(context.Background(), "park-wait", dockerpool.Key{
			Image: "alpine:3.20", Runtime: models.RuntimeDocker,
		})
		if err == nil || !strings.Contains(err.Error(), "park ready") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("egress_block_failure", func(t *testing.T) {
		backend := &failBlockAllEgressBackend{}
		rules := netrules.NewWithBackend(backend)
		d := &poolFakeDaemon{t: t}
		c := newPoolClient(t, d, func(c *Client) {
			c.networkRules = rules
			c.toolboxWaitTimeout = time.Second
			c.waitTimeout = time.Second
			c.readyDir = readyDir(t)
		})
		guestDone := make(chan struct{})
		t.Cleanup(func() { close(guestDone) })
		d.start = func() *http.Response {
			var request struct {
				Env []string `json:"Env"`
			}
			if err := json.Unmarshal(d.createBodies[len(d.createBodies)-1], &request); err != nil {
				t.Fatalf("decode park create request: %v", err)
			}
			var token, nonce string
			for _, env := range request.Env {
				switch {
				case strings.HasPrefix(env, "SB_TOOLBOX_TOKEN="):
					token = strings.TrimPrefix(env, "SB_TOOLBOX_TOKEN=")
				case strings.HasPrefix(env, "SB_READY_NONCE="):
					nonce = strings.TrimPrefix(env, "SB_READY_NONCE=")
				}
			}
			go func() {
				for i := 0; i < 100; i++ {
					entries, readErr := os.ReadDir(c.readyDir)
					if readErr == nil {
						for _, entry := range entries {
							if !strings.HasSuffix(entry.Name(), ".sock") {
								continue
							}
							conn, dialErr := net.Dial("unix", filepath.Join(c.readyDir, entry.Name()))
							if dialErr != nil {
								continue
							}
							_ = readyproto.EncodeParked(conn, readyproto.ParkedSignal{
								Event: readyproto.EventParked, Token: token, Nonce: nonce,
							})
							<-guestDone
							_ = conn.Close()
							return
						}
					}
					time.Sleep(5 * time.Millisecond)
				}
			}()
			return textResponse(http.StatusNoContent, "")
		}
		_, err := c.parkContainer(context.Background(), "park-egress", dockerpool.Key{
			Image: "alpine:3.20", Runtime: models.RuntimeDocker,
		})
		if err == nil || !strings.Contains(err.Error(), "park egress block") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestCoverage95ParkedListenerExtraPaths(t *testing.T) {
	t.Run("agent_version_mismatch", func(t *testing.T) {
		pl, err := NewParkedListener(coverageReadyDir(t), "park-ver", "tok", "nonce")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pl.Close() })
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- pl.verifyParked(server) }()
		_ = readyproto.EncodeParked(client, readyproto.ParkedSignal{
			Event: readyproto.EventParked, Token: "tok", Nonce: "nonce", AgentVersion: "other",
		})
		_ = client.Close()
		if err := <-done; err == nil || !strings.Contains(err.Error(), "agent version mismatch") {
			t.Fatalf("verifyParked() = %v", err)
		}
	})

	t.Run("adopt_dead_connection", func(t *testing.T) {
		pl, err := NewParkedListener(coverageReadyDir(t), "park-dead", "tok", "nonce")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pl.Close() })
		server, client := net.Pipe()
		pl.connMu.Lock()
		pl.conn = server
		pl.monitorDone = make(chan struct{})
		pl.connMu.Unlock()
		go pl.monitorParked(server)
		_ = client.Close()
		deadline := time.Now().Add(time.Second)
		for pl.Alive() && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if pl.Alive() {
			t.Fatal("parked connection still alive after guest closed pipe")
		}
		// Adopt blocks on monitorDone without honoring ctx — guard against hangs.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		adoptDone := make(chan error, 1)
		go func() { adoptDone <- pl.Adopt(ctx, "sb", "tok", "nonce") }()
		select {
		case err := <-adoptDone:
			if err == nil || !strings.Contains(err.Error(), "dead") {
				t.Fatalf("Adopt() = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Adopt hung waiting for monitor goroutine")
		}
	})

	t.Run("remove_park_socket_empty", func(t *testing.T) {
		RemoveParkSocket("")
		RemoveParkSocket("   ")
	})
}

func TestCoverage95RemoveNetnsPausePaths(t *testing.T) {
	c := &Client{logger: slog.Default()}
	c.removeNetnsPauseForSandbox(context.Background(), "")
	c.removeNetnsPauseForSandbox(context.Background(), "   ")

	d := newNetnsFakeDaemon()
	client := newNetnsClient(t, d)
	client.logger = slog.Default()
	client.removeNetnsPauseForSandbox(context.Background(), "sb-missing")

	d.mu.Lock()
	d.containers["pause-err"] = &netnsFakeContainer{id: "pause-err", name: netnsAdoptedName("sb-err")}
	d.mu.Unlock()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodDelete {
			return textResponse(http.StatusInternalServerError, "remove failed"), nil
		}
		return d.transport()(r)
	})}
	client.removeNetnsPauseForSandbox(context.Background(), "sb-err")
}

func TestCoverage95NetnsPoolRefillCancellation(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsClient(t, d)
	p := newTestNetnsPool(c, 2)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.refill(ctx)

	stopCh := make(chan struct{})
	close(stopCh)
	p.stopCh = stopCh
	p.refill(context.Background())
}

func TestCoverage95ExecStartOKStatus(t *testing.T) {
	dir, err := os.MkdirTemp("", "ex")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "e.sock")
	sock = execSocketServerAt(t, sock, "HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	c := &Client{socketPath: sock}
	sess, err := c.ExecStart(context.Background(), "exec-ok", false)
	if err != nil {
		t.Fatalf("ExecStart() = %v", err)
	}
	if sess.ID != "exec-ok" {
		t.Fatalf("session ID = %q", sess.ID)
	}
	_ = sess.Close()
}

func execSocketServerAt(t *testing.T, sock, response string) string {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		_, _ = conn.Write([]byte(response))
		time.Sleep(50 * time.Millisecond)
	}()
	return sock
}

func TestCoverage95ReadyListenerRecordInvalidNil(t *testing.T) {
	var ln *ReadyListener
	ln.recordInvalidAttempt("ignored")
}

func TestCoverage95ParkedListenerHostSocketPathNil(t *testing.T) {
	if (*ParkedListener)(nil).HostSocketPath() != "" {
		t.Fatal("nil parked listener must return empty path")
	}
}

func TestCoverage95ReadySocketSweepReadDirError(t *testing.T) {
	if err := SweepOrphanReadySocketsExcept(filepath.Join(t.TempDir(), "missing-parent", "ready"), nil); err != nil {
		t.Fatalf("missing dir should be ignored: %v", err)
	}
	dir := coverageReadyDir(t)
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := SweepOrphanReadySocketsExcept(dir, nil); err == nil {
		t.Fatal("expected readdir error")
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

func TestCoverage95ParkContainerGvisorSkipsDisk(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	d.create = func() *http.Response {
		return textResponse(http.StatusInternalServerError, "stop-after-create-body")
	}
	c := newPoolClient(t, d, func(c *Client) {
		c.parkDiskGB = 10
		c.readyDir = coverageReadyDir(t)
	})
	_, err := c.parkContainer(context.Background(), "park-gvisor", dockerpool.Key{
		Image: "alpine:3.20", Runtime: models.RuntimeGvisor,
	})
	if err == nil {
		t.Fatal("expected create failure")
	}
	if len(d.createBodies) != 1 {
		t.Fatalf("create bodies = %d", len(d.createBodies))
	}
	var body struct {
		HostConfig map[string]any `json:"HostConfig"`
	}
	if err := json.Unmarshal(d.createBodies[0], &body); err != nil {
		t.Fatal(err)
	}
	if body.HostConfig["StorageOpt"] != nil {
		t.Fatal("gvisor park must not set StorageOpt")
	}
}

func TestCoverage95ParkedListenerAdoptAckMismatch(t *testing.T) {
	pl, err := NewParkedListener(coverageReadyDir(t), "park-ack", "tok", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })

	go func() {
		conn, dialErr := net.Dial("unix", pl.HostSocketPath())
		if dialErr != nil {
			return
		}
		defer conn.Close()
		_ = readyproto.EncodeParked(conn, readyproto.ParkedSignal{
			Event: readyproto.EventParked, Token: "tok", Nonce: "nonce",
		})
		frame, decodeErr := readyproto.DecodeAdopt(bufio.NewReader(conn))
		if decodeErr != nil {
			return
		}
		_ = readyproto.Encode(conn, readyproto.ReadySignal{
			Event: readyproto.EventReady, SandboxID: frame.SandboxID, Token: "wrong", Nonce: frame.Nonce,
		})
	}()

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := pl.WaitParked(waitCtx); err != nil {
		t.Fatalf("WaitParked: %v", err)
	}
	adoptCtx, adoptCancel := context.WithTimeout(context.Background(), time.Second)
	defer adoptCancel()
	if err := pl.Adopt(adoptCtx, "sb-ack", "tok", "nonce"); err == nil || !strings.Contains(err.Error(), "token mismatch") {
		t.Fatalf("Adopt() = %v", err)
	}
}
