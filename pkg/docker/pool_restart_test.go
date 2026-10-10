package docker

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/readyproto"
)

// restartDaemon is a Docker engine holding one stopped container, ref "sb".
// Starting it runs onStart, which plays the container's toolboxd.
type restartDaemon struct {
	t         *testing.T
	env       []string
	binds     []string
	ip        string
	onStart   func()
	mu        sync.Mutex
	starts    int
	stops     int
	inspectOK bool
}

func (d *restartDaemon) transport() roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/containers/sb/json":
			if !d.inspectOK {
				return textResponse(http.StatusNotFound, "no such container"), nil
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"Id": "cid", "Name": "/sb",
				"Config":          map[string]any{"Env": d.env},
				"HostConfig":      map[string]any{"Binds": d.binds},
				"State":           map[string]any{"Running": true, "Status": "running", "Pid": 7},
				"NetworkSettings": map[string]any{"Networks": map[string]any{"bridge": map[string]any{"IPAddress": d.ip}}},
			}), nil
		case r.Method == http.MethodPost && r.URL.Path == "/containers/sb/start":
			d.mu.Lock()
			d.starts++
			d.mu.Unlock()
			if d.onStart != nil {
				go d.onStart()
			}
			return textResponse(http.StatusNoContent, ""), nil
		case r.Method == http.MethodPost && r.URL.Path == "/containers/sb/stop":
			d.mu.Lock()
			d.stops++
			d.mu.Unlock()
			return textResponse(http.StatusNoContent, ""), nil
		}
		d.t.Errorf("unexpected engine call %s %s", r.Method, r.URL.Path)
		return textResponse(http.StatusNotFound, "no such endpoint"), nil
	}
}

func (d *restartDaemon) counts() (starts, stops int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.starts, d.stops
}

// parkedGuest plays a restarted pool container's toolboxd: it sends its
// parked hello on the slot socket, takes the adopt frame and acks it, and
// reports the identity it was handed.
func parkedGuest(socket, token, nonce string, adopted chan<- readyproto.AdoptFrame) func() {
	return func() {
		var conn net.Conn
		var err error
		for range 50 { // the host listens before the start; dial like toolboxd does
			if conn, err = net.Dial("unix", socket); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			return
		}
		defer conn.Close()
		if readyproto.EncodeParked(conn, readyproto.ParkedSignal{Event: readyproto.EventParked, Token: token, Nonce: nonce}) != nil {
			return
		}
		frame, err := readyproto.DecodeAdopt(bufio.NewReader(conn))
		if err != nil {
			return
		}
		adopted <- frame
		_ = readyproto.Encode(conn, readyproto.ReadySignal{Event: readyproto.EventReady, SandboxID: frame.SandboxID, Token: frame.Token, Nonce: frame.Nonce})
	}
}

func restartClient(t *testing.T, d *restartDaemon, readyDir string, toolboxPort int) *Client {
	return &Client{
		httpClient:         &http.Client{Transport: d.transport()},
		toolboxClient:      &http.Client{Timeout: 2 * time.Second},
		toolboxPort:        toolboxPort,
		waitTimeout:        2 * time.Second,
		toolboxWaitTimeout: 2 * time.Second,
		readyEnabled:       true,
		readyDir:           readyDir,
	}
}

// A container adopted from the warm pool keeps the pool's env, so after a
// stop its toolboxd boots parked and serves nothing but /health. Starting it
// must adopt it again with the sandbox's own identity, or every call after
// the start is 503 "sandbox not adopted" (UC-206/207/227 live).
func TestStartWithIdentityReadoptsAWarmPoolContainer(t *testing.T) {
	ip, port, closeHealth := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer closeHealth()
	dir := shortParkTestDir(t)
	socket := filepath.Join(dir, "park-abc.sock")
	poolEnv := []string{"SB_TOOLBOX_TOKEN=boot-tok", poolParkedEnv + "=1", readySocketEnv + "=" + GuestReadySocketPath, readyNonceEnv + "=boot-nonce"}
	poolBinds := []string{"/opt/toolboxd:/usr/local/bin/toolboxd:ro", socket + ":" + GuestReadySocketPath + ":rw"}

	t.Run("adopted again with the sandbox's identity", func(t *testing.T) {
		adopted := make(chan readyproto.AdoptFrame, 1)
		d := &restartDaemon{t: t, env: poolEnv, binds: poolBinds, ip: ip, inspectOK: true,
			onStart: parkedGuest(socket, "boot-tok", "boot-nonce", adopted)}
		rt, err := restartClient(t, d, dir, port).StartWithIdentity(context.Background(), "sb", "sb-1", "sandbox-token")
		if err != nil {
			t.Fatalf("StartWithIdentity: %v", err)
		}
		select {
		case frame := <-adopted:
			if frame.SandboxID != "sb-1" || frame.Token != "sandbox-token" || frame.Nonce == "" {
				t.Fatalf("adopt frame = %+v, want the sandbox's own identity", frame)
			}
		default:
			t.Fatal("the restarted container was never adopted")
		}
		if rt.ContainerIP != ip || rt.Status != "started" {
			t.Fatalf("runtime = %+v", rt)
		}
		if starts, stops := d.counts(); starts != 1 || stops != 0 {
			t.Fatalf("starts=%d stops=%d", starts, stops)
		}
	})

	t.Run("a hello with the wrong bootstrap token is not adopted", func(t *testing.T) {
		adopted := make(chan readyproto.AdoptFrame, 1)
		d := &restartDaemon{t: t, env: poolEnv, binds: poolBinds, ip: ip, inspectOK: true,
			onStart: parkedGuest(socket, "not-the-boot-tok", "boot-nonce", adopted)}
		c := restartClient(t, d, dir, port)
		c.toolboxWaitTimeout = 300 * time.Millisecond
		if _, err := c.StartWithIdentity(context.Background(), "sb", "sb-1", "sandbox-token"); err == nil || !strings.Contains(err.Error(), "re-adopt") {
			t.Fatalf("StartWithIdentity = %v, want a re-adopt failure", err)
		}
		if len(adopted) != 0 {
			t.Fatal("a guest presenting the wrong bootstrap token was handed the sandbox's token")
		}
		if _, stops := d.counts(); stops != 1 {
			t.Fatalf("a container that couldn't be adopted was left running (stops=%d)", stops)
		}
	})

	t.Run("a guest that never parks fails the start and is stopped", func(t *testing.T) {
		d := &restartDaemon{t: t, env: poolEnv, binds: poolBinds, ip: ip, inspectOK: true}
		c := restartClient(t, d, dir, port)
		c.toolboxWaitTimeout = 200 * time.Millisecond
		if _, err := c.StartWithIdentity(context.Background(), "sb", "sb-1", "sandbox-token"); err == nil {
			t.Fatal("a start whose container never parked succeeded")
		}
		if _, stops := d.counts(); stops != 1 {
			t.Fatalf("stops=%d, want 1", stops)
		}
	})

	t.Run("a container not from the pool starts as before", func(t *testing.T) {
		d := &restartDaemon{t: t, env: []string{"SB_TOOLBOX_TOKEN=sandbox-token", poolParkedEnv + "="}, ip: ip, inspectOK: true}
		rt, err := restartClient(t, d, dir, port).StartWithIdentity(context.Background(), "sb", "sb-1", "sandbox-token")
		if err != nil || rt.ContainerIP != ip {
			t.Fatalf("StartWithIdentity = %+v, %v", rt, err)
		}
	})

	t.Run("a park socket outside the ready dir is refused before the start", func(t *testing.T) {
		d := &restartDaemon{t: t, env: poolEnv, binds: []string{"/elsewhere/park-abc.sock:" + GuestReadySocketPath + ":rw"}, ip: ip, inspectOK: true}
		if _, err := restartClient(t, d, dir, port).StartWithIdentity(context.Background(), "sb", "sb-1", "sandbox-token"); err == nil || !strings.Contains(err.Error(), "no park socket") {
			t.Fatalf("StartWithIdentity = %v", err)
		}
		if starts, _ := d.counts(); starts != 0 {
			t.Fatal("started a container it could not adopt")
		}
	})

	t.Run("inspect fails", func(t *testing.T) {
		d := &restartDaemon{t: t, ip: ip}
		if _, err := restartClient(t, d, dir, port).StartWithIdentity(context.Background(), "sb", "sb-1", "sandbox-token"); err == nil {
			t.Fatal("want an inspect error")
		}
	})
}

// A snapshot copies the container's env into the image; a warm-pool
// container's carries SB_POOL_PARKED=1. Both ends drop it: the commit, and
// every cold create (for snapshots already made).
func TestSnapshotsDoNotCarryTheParkedFlag(t *testing.T) {
	var commit url.Values
	c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/commit" {
			commit = r.URL.Query()
			return jsonResponse(http.StatusCreated, map[string]string{"Id": "sha256:snap"}), nil
		}
		return textResponse(http.StatusNotFound, fmt.Sprintf("unexpected %s", r.URL.Path)), nil
	})}}
	if _, err := c.CreateSnapshot(context.Background(), "sb", "snap:v1"); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if got := commit["changes"]; len(got) != 1 || got[0] != "ENV "+poolParkedEnv+"=" {
		t.Fatalf("commit changes = %q, want the parked flag cleared", got)
	}
}
