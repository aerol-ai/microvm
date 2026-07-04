package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

func requireLinuxUnix(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("unix ready socket tests require linux")
	}
}

func fakeCreateDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	return &fakeDaemon{
		t: t,
		imageInspect: func() *http.Response {
			return jsonResponse(http.StatusOK, map[string]any{
				"Config": map[string]any{"WorkingDir": "/", "Entrypoint": []string{}, "Cmd": []string{}},
			})
		},
		create: func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
		start:  func() *http.Response { return textResponse(http.StatusNoContent, "") },
	}
}

func shortReadyDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestCreate_WiresReadySocketWhenEnabled(t *testing.T) {
	requireLinuxUnix(t)
	readyDir := shortReadyDir(t)
	var captured map[string]any
	d := fakeCreateDaemon(t)
	base := d.transport()
	wrapped := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.URL.Path == "/containers/create" && r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &captured)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		return base(r)
	})

	c := newCreateClient(t, d, true, func(c *Client) {
		c.readyEnabled = true
		c.readyDir = readyDir
		c.httpClient = &http.Client{Transport: wrapped, Timeout: c.httpClient.Timeout}
		c.streamClient = &http.Client{Transport: wrapped}
	})

	_, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb-create", "tok", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	hostCfg, _ := captured["HostConfig"].(map[string]any)
	binds, _ := hostCfg["Binds"].([]any)
	foundBind := false
	for _, b := range binds {
		s, _ := b.(string)
		if strings.Contains(s, GuestReadySocketPath) {
			foundBind = true
		}
	}
	if !foundBind {
		t.Fatalf("binds missing ready socket: %v", binds)
	}
	envs, _ := captured["Env"].([]any)
	var hasSocket, hasNonce bool
	for _, e := range envs {
		s, _ := e.(string)
		if strings.HasPrefix(s, readySocketEnv+"=") {
			hasSocket = true
		}
		if strings.HasPrefix(s, readyNonceEnv+"=") {
			hasNonce = true
		}
	}
	if !hasSocket || !hasNonce {
		t.Fatalf("env missing ready vars: socket=%v nonce=%v env=%v", hasSocket, hasNonce, envs)
	}
}

func TestCreate_RetainsReadySocketBindSourceForRestart(t *testing.T) {
	requireLinuxUnix(t)
	readyDir := shortReadyDir(t)
	d := fakeCreateDaemon(t)
	c := newCreateClient(t, d, true, func(c *Client) {
		c.readyEnabled = true
		c.readyDir = readyDir
	})

	if _, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb-restart", "tok", nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(readyDir, "sb-restart.*.sock"))
	if err != nil {
		t.Fatalf("glob ready socket: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("ready socket bind source count = %d, want 1 (%v)", len(matches), matches)
	}
	RemoveReadySocketsForSandbox(readyDir, "sb-restart")
	if _, err := os.Stat(matches[0]); !os.IsNotExist(err) {
		t.Fatalf("ready socket survived sandbox cleanup: %v", err)
	}
}

func TestCreate_RemovesReadySocketOnStartFailure(t *testing.T) {
	requireLinuxUnix(t)
	readyDir := shortReadyDir(t)
	d := fakeCreateDaemon(t)
	d.start = func() *http.Response { return textResponse(http.StatusInternalServerError, "boom") }
	c := newCreateClient(t, d, true, func(c *Client) {
		c.readyEnabled = true
		c.readyDir = readyDir
	})

	if _, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb-fail", "tok", nil); err == nil {
		t.Fatal("create expected start failure")
	}
	matches, err := filepath.Glob(filepath.Join(readyDir, "sb-fail.*.sock"))
	if err != nil {
		t.Fatalf("glob ready socket: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("failed create leaked ready socket bind source: %v", matches)
	}
}

func TestCreate_SocketPushWinsOverHealthPoll(t *testing.T) {
	requireLinuxUnix(t)
	readyDir := t.TempDir()
	healthHits := 0
	ip, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) {
		healthHits++
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	t.Cleanup(closeFn)

	d := fakeCreateDaemon(t)
	c := newCreateClient(t, d, false, func(c *Client) {
		c.readyEnabled = true
		c.readyDir = readyDir
		c.toolboxPort = port
		c.readinessPollInit = 5 * time.Millisecond
		c.readinessPollMax = 10 * time.Millisecond
		c.toolboxWaitTimeout = 2 * time.Second
	})
	d.containerGet = func() *http.Response {
		return textResponse(http.StatusOK, inspectBody("cid", "/sb-race", ip, true, "running", 7))
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			matches, _ := filepath.Glob(filepath.Join(readyDir, "sb-race.*.sock"))
			if len(matches) == 0 {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			conn, err := net.Dial("unix", matches[0])
			if err != nil {
				return
			}
			defer conn.Close()
			base := filepath.Base(matches[0])
			parts := strings.Split(strings.TrimSuffix(base, ".sock"), ".")
			if len(parts) < 2 {
				return
			}
			nonce := parts[1]
			_ = readyproto.Encode(conn, readyproto.ReadySignal{
				Event: readyproto.EventReady, SandboxID: "sb-race", Token: "tok", Nonce: nonce,
			})
			return
		}
	}()

	ctx, timing := WithCreateTiming(context.Background())
	_, err := c.Create(ctx, models.CreateSandboxRequest{Image: "img"}, "sb-race", "tok", nil)
	wg.Wait()
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if timing.Source != "socket" {
		t.Fatalf("source = %q, want socket", timing.Source)
	}
	if healthHits > 0 {
		t.Fatalf("health poll ran %d times on socket win", healthHits)
	}
}

// TestCreate_SocketErrorFallsBackToHealth is the regression guard for the race
// fix: an in-container process spamming the ready socket with invalid frames
// trips listener.Wait's maxInvalidReadyAttempts and returns an error. That
// error must NOT win the race and fail the create — the health poll is the
// safety net and the (healthy) sandbox must still come up via "health".
// Pre-fix, the socket error short-circuited the create.
func TestCreate_SocketErrorFallsBackToHealth(t *testing.T) {
	requireLinuxUnix(t)
	readyDir := t.TempDir()

	// Slow-but-eventually-ready health endpoint: 503 until a few polls in, then
	// 200. This guarantees the socket error (fast invalid spam) lands before
	// the health success, so we exercise the "socket errored first" path.
	var mu sync.Mutex
	var hits int
	ip, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		n := hits
		mu.Unlock()
		if n >= 3 {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	t.Cleanup(closeFn)

	d := fakeCreateDaemon(t)
	c := newCreateClient(t, d, false, func(c *Client) {
		c.readyEnabled = true
		c.readyDir = readyDir
		c.toolboxPort = port
		c.readinessPollInit = 5 * time.Millisecond
		c.readinessPollMax = 10 * time.Millisecond
		c.toolboxWaitTimeout = 2 * time.Second
	})
	d.containerGet = func() *http.Response {
		return textResponse(http.StatusOK, inspectBody("cid", "/sb-err", ip, true, "running", 7))
	}

	// Spam invalid frames (wrong nonce) until the listener trips its invalid cap.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			matches, _ := filepath.Glob(filepath.Join(readyDir, "sb-err.*.sock"))
			if len(matches) == 0 {
				time.Sleep(2 * time.Millisecond)
				continue
			}
			for i := 0; i < maxInvalidReadyAttempts+2; i++ {
				conn, err := net.Dial("unix", matches[0])
				if err != nil {
					return
				}
				_ = readyproto.Encode(conn, readyproto.ReadySignal{
					Event: readyproto.EventReady, SandboxID: "sb-err", Token: "tok", Nonce: "wrong-nonce",
				})
				_ = conn.Close()
			}
			return
		}
	}()

	ctx, timing := WithCreateTiming(context.Background())
	_, err := c.Create(ctx, models.CreateSandboxRequest{Image: "img"}, "sb-err", "tok", nil)
	wg.Wait()
	if err != nil {
		t.Fatalf("create must survive a socket error via health fallback: %v", err)
	}
	if timing.Source != "health" {
		t.Fatalf("source = %q, want health (socket errored, health backstopped)", timing.Source)
	}
}

func TestCreate_FallbackWhenPushDisabled(t *testing.T) {
	d := fakeCreateDaemon(t)
	c := newCreateClient(t, d, true, func(c *Client) {
		c.readyEnabled = false
	})
	ctx, timing := WithCreateTiming(context.Background())
	_, err := c.Create(ctx, models.CreateSandboxRequest{Image: "img"}, "sb-fb", "tok", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if timing.Source != "health" {
		t.Fatalf("source = %q, want health", timing.Source)
	}
}

func TestPollToolboxHealth_SlowReadyStillSucceeds(t *testing.T) {
	var hits int
	var mu sync.Mutex
	_, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		n := hits
		mu.Unlock()
		if n >= 3 {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	t.Cleanup(closeFn)

	c := newCreateClient(t, &fakeDaemon{t: t}, true, func(c *Client) {
		c.readyEnabled = false
		c.toolboxPort = port
		c.readinessPollInit = 10 * time.Millisecond
		c.readinessPollMax = 20 * time.Millisecond
		c.toolboxWaitTimeout = 2 * time.Second
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.pollToolboxHealth(ctx, "127.0.0.1"); err != nil {
		t.Fatalf("poll: %v", err)
	}
}
