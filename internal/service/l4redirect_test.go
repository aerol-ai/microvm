package service

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A REDIRECTed connection is routed by its original host port (no PROXY
// header) to the exposure's sandbox, and spliced both ways.
func TestL4RedirectListenerRoutesByOriginalDst(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-rd", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.9.0.2", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{SandboxID: "sb-rd", Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 41300, PublicURL: "tcp://x:41300", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{SandboxID: "sb-rd", Port: 8080, Protocol: "http", HostPort: 41301, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}

	var (
		mu      sync.Mutex
		dialled []string
	)
	setDialL4UpstreamForTest(t, func(_ context.Context, target string, _ time.Duration) (net.Conn, error) {
		mu.Lock()
		dialled = append(dialled, target)
		mu.Unlock()
		a, b := net.Pipe()
		go func() { // upper-casing echo upstream
			defer b.Close()
			buf := make([]byte, 64)
			n, _ := b.Read(buf)
			for i := range buf[:n] {
				if buf[i] >= 'a' && buf[i] <= 'z' {
					buf[i] -= 32
				}
			}
			_, _ = b.Write(buf[:n])
		}()
		return a, nil
	})
	orig := map[string]int{}
	var origMu sync.Mutex
	svc.testOriginalDstPort = (func(c net.Conn) (int, error) {
		origMu.Lock()
		defer origMu.Unlock()
		if p, ok := orig[c.RemoteAddr().String()]; ok {
			return p, nil
		}
		return 0, errors.New("not redirected")
	})

	ln, err := svc.StartL4RedirectListener(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dial := func(hostPort int) net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		origMu.Lock()
		if hostPort != 0 {
			orig[c.LocalAddr().String()] = hostPort
		}
		origMu.Unlock()
		return c
	}
	closedPromptly := func(c net.Conn) bool {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := c.Read(make([]byte, 1))
		return err == io.EOF
	}

	c := dial(41300)
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "PING" {
		t.Fatalf("spliced reply = %q, %v", got, err)
	}
	_ = c.Close()
	mu.Lock()
	if len(dialled) != 1 || dialled[0] != "10.9.0.2:5432" {
		t.Fatalf("dialled %v, want the exposure's sandbox port", dialled)
	}
	mu.Unlock()

	// Not an exposure, an http exposure, and an unreadable original
	// destination are all closed without dialling anything.
	for name, hp := range map[string]int{"unknown": 41999, "http": 41301, "direct": 0} {
		if !closedPromptly(dial(hp)) {
			t.Fatalf("%s: connection not closed", name)
		}
	}
	mu.Lock()
	if len(dialled) != 1 {
		t.Fatalf("dialled %v after refused connections", dialled)
	}
	mu.Unlock()

	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := net.Dial("tcp", ln.Addr().String()); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener survived ctx cancel")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStartL4RedirectListenerBadAddr(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	if _, err := svc.StartL4RedirectListener(context.Background(), "256.0.0.1:x"); err == nil {
		t.Fatal("want listen error")
	}
}
