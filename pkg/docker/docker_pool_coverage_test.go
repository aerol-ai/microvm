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
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

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

// failInsertBackend fails the first Insert to exercise applyAdoptNetworkPolicy's
// rollback path when selective egress cannot be installed.
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

func TestCoverage95ResolveImageIDCachedHit(t *testing.T) {
	c := &Client{imageIDs: newImageIDCache(time.Minute)}
	c.imageIDs.Put("alpine:3.20", "sha256:cached")
	id, err := c.resolveImageIDCached(context.Background(), "alpine:3.20")
	if err != nil || id != "sha256:cached" {
		t.Fatalf("resolveImageIDCached() = %q, %v", id, err)
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
