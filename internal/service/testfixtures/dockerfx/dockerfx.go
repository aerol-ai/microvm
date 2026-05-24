//go:build e2e

// Package dockerfx is a tiny Docker container fixture for end-to-end tests.
// It speaks the Docker daemon HTTP API directly over the Unix socket — same
// transport pattern as pkg/docker/client.go — so the e2e build tag does not
// pull in any new module dependency. The fixture is intentionally limited
// to what custom_domains_e2e_test.go needs: pull-if-missing, create with
// env / port bindings / network, start, wait for ready, log tail, stop+rm.
package dockerfx

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	defaultSocketPath = "/var/run/docker.sock"
	readyBudget       = 30 * time.Second
	readyTick         = 200 * time.Millisecond
	stopTimeoutSecs   = 5
)

// Spec is the minimal container shape the fixture supports.
type Spec struct {
	Image       string
	Name        string   // optional; auto-generated when empty
	Env         []string // "KEY=value"
	Cmd         []string // overrides image CMD
	ExposePorts []string // "443/tcp"; mapped to ephemeral host ports
	HostBinds   []string // "hostPath:containerPath[:ro]"
	ExtraHosts  []string // "host.docker.internal:host-gateway"
	Network     string   // user-defined bridge to attach to
	ReadyProbe  func(*Container) error
}

// Container is a started container with its inspected runtime details.
type Container struct {
	ID    string
	Name  string
	IP    string            // IP on the user-defined network (empty if Network unset)
	Ports map[string]string // "container/tcp" -> "host" (e.g. "443/tcp" -> "32891")

	client *Client
}

// Client is a lightweight Docker daemon client. Tests get one via Require.
type Client struct {
	socketPath string
	http       *http.Client
}

// Require returns a Docker client or t.Skip's if the daemon is unreachable.
// The fixture is opt-in: no test should ever hard-require Docker on every
// developer machine — that's what the e2e build tag is for.
func Require(t testing.TB) *Client {
	t.Helper()
	socket := defaultSocketPath
	if v := strings.TrimPrefix(strings.TrimSpace(os.Getenv("DOCKER_HOST")), "unix://"); v != "" {
		socket = v
	}
	if _, err := os.Stat(socket); err != nil {
		t.Skipf("dockerfx: socket %s unreachable (%v) — start Docker or see setup/multi-node-cert-sharing.md", socket, err)
	}
	c := &Client{
		socketPath: socket,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socket)
				},
			},
		},
	}
	if _, err := c.do(context.Background(), http.MethodGet, "/info", nil, nil); err != nil {
		t.Skipf("dockerfx: GET /info failed (%v) — Docker daemon not responding", err)
	}
	return c
}

// EnsureNetwork creates a user-defined bridge if it doesn't already exist.
// Idempotent — repeated calls within or across tests are safe.
func (c *Client) EnsureNetwork(t testing.TB, name string) {
	t.Helper()
	if _, err := c.do(context.Background(), http.MethodGet, "/networks/"+url.PathEscape(name), nil, nil); err == nil {
		return
	}
	body := map[string]any{
		"Name":           name,
		"Driver":         "bridge",
		"CheckDuplicate": true,
	}
	if _, err := c.do(context.Background(), http.MethodPost, "/networks/create", body, nil); err != nil {
		t.Fatalf("dockerfx: create network %s: %v", name, err)
	}
}

// Start pulls the image if missing, creates the container, starts it, and
// blocks until the ReadyProbe passes (30s budget). Registers a t.Cleanup
// that stops and removes the container regardless of test outcome.
func (c *Client) Start(t testing.TB, s Spec) *Container {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := c.ensureImage(ctx, s.Image); err != nil {
		t.Fatalf("dockerfx: pull %s: %v", s.Image, err)
	}

	portBindings := map[string][]map[string]string{}
	exposedPorts := map[string]struct{}{}
	for _, p := range s.ExposePorts {
		portBindings[p] = []map[string]string{{"HostIP": "127.0.0.1", "HostPort": ""}}
		exposedPorts[p] = struct{}{}
	}
	body := map[string]any{
		"Image":        s.Image,
		"Env":          s.Env,
		"ExposedPorts": exposedPorts,
		"HostConfig": map[string]any{
			"PortBindings": portBindings,
			"Binds":        s.HostBinds,
			"ExtraHosts":   s.ExtraHosts,
			"NetworkMode":  s.Network,
			"AutoRemove":   false,
		},
	}
	if len(s.Cmd) > 0 {
		body["Cmd"] = s.Cmd
	}
	if s.Network != "" {
		body["NetworkingConfig"] = map[string]any{
			"EndpointsConfig": map[string]any{s.Network: map[string]any{}},
		}
	}

	q := url.Values{}
	if s.Name != "" {
		q.Set("name", s.Name)
	}
	var created struct {
		ID string `json:"Id"`
	}
	if _, err := c.do(ctx, http.MethodPost, "/containers/create?"+q.Encode(), body, &created); err != nil {
		t.Fatalf("dockerfx: create %s: %v", s.Image, err)
	}
	cont := &Container{ID: created.ID, Name: s.Name, client: c}
	t.Cleanup(func() { c.stopAndRemove(cont.ID) })

	if _, err := c.do(ctx, http.MethodPost, "/containers/"+cont.ID+"/start", nil, nil); err != nil {
		t.Fatalf("dockerfx: start %s: %v", cont.ID[:12], err)
	}
	if err := c.inspect(ctx, cont, s.Network); err != nil {
		t.Fatalf("dockerfx: inspect %s: %v", cont.ID[:12], err)
	}

	if s.ReadyProbe != nil {
		deadline := time.Now().Add(readyBudget)
		var lastErr error
		for time.Now().Before(deadline) {
			if err := s.ReadyProbe(cont); err == nil {
				return cont
			} else {
				lastErr = err
			}
			time.Sleep(readyTick)
		}
		tail := cont.LogTail(200)
		t.Fatalf("dockerfx: %s not ready after %s: %v\nlast logs:\n%s", s.Image, readyBudget, lastErr, tail)
	}
	return cont
}

// HostPort returns the host-side port for a container port spec like "443/tcp".
// Returns "" if the container isn't binding that port.
func (c *Container) HostPort(containerPort string) string { return c.Ports[containerPort] }

// LogTail returns the last n bytes of combined stdout+stderr from the container.
// Used in t.Fatal diagnostics — never on the happy path.
func (c *Container) LogTail(n int) string {
	q := url.Values{}
	q.Set("stdout", "1")
	q.Set("stderr", "1")
	q.Set("tail", fmt.Sprintf("%d", n))
	resp, err := c.client.http.Get("http://docker/containers/" + c.ID + "/logs?" + q.Encode())
	if err != nil {
		return fmt.Sprintf("<log fetch failed: %v>", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return demuxDockerLog(raw)
}

// LogContains returns the count of occurrences of needle in the container's
// combined stdout+stderr. Used to assert ACME issuance counts from Pebble.
func (c *Container) LogContains(needle string) int {
	body := c.LogTail(100000)
	return strings.Count(body, needle)
}

// Stop sends SIGTERM with a 5s timeout, then forces removal.
func (c *Container) Stop() {
	if c == nil || c.ID == "" {
		return
	}
	c.client.stopAndRemove(c.ID)
	c.ID = ""
}

// --- internals -------------------------------------------------------------

func (c *Client) ensureImage(ctx context.Context, image string) error {
	q := url.Values{}
	q.Set("fromImage", image)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/images/create?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Docker streams progress JSON; we just drain it and check status.
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("pull returned %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) inspect(ctx context.Context, cont *Container, network string) error {
	var out struct {
		NetworkSettings struct {
			Ports    map[string][]struct{ HostPort string }
			Networks map[string]struct{ IPAddress string }
		}
	}
	if _, err := c.do(ctx, http.MethodGet, "/containers/"+cont.ID+"/json", nil, &out); err != nil {
		return err
	}
	cont.Ports = map[string]string{}
	for containerPort, bindings := range out.NetworkSettings.Ports {
		if len(bindings) > 0 {
			cont.Ports[containerPort] = bindings[0].HostPort
		}
	}
	if network != "" {
		if ep, ok := out.NetworkSettings.Networks[network]; ok {
			cont.IP = ep.IPAddress
		}
	}
	return nil
}

func (c *Client) stopAndRemove(id string) {
	if id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _ = c.do(ctx, http.MethodPost, fmt.Sprintf("/containers/%s/stop?t=%d", id, stopTimeoutSecs), nil, nil)
	_, _ = c.do(ctx, http.MethodDelete, "/containers/"+id+"?force=1&v=1", nil, nil)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = strings.NewReader(string(buf))
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, reqBody)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return raw, fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return raw, fmt.Errorf("decode response: %w (body=%s)", err, raw)
		}
	}
	return raw, nil
}

// demuxDockerLog strips Docker's 8-byte stream framing header. Each frame:
//
//	[stream(1) | reserved(3) | size(4 BE) | payload(size)]
//
// stream=1 → stdout, 2 → stderr. We merge both into one string in arrival
// order — sufficient for the grep-for-"Signing certificate" assertions.
// If the bytes don't look framed (TTY mode), return them as-is.
func demuxDockerLog(raw []byte) string {
	if len(raw) < 8 {
		return string(raw)
	}
	// Heuristic: in framed mode, byte 0 is 0/1/2 and bytes 1-3 are zero.
	if raw[0] > 2 || raw[1] != 0 || raw[2] != 0 || raw[3] != 0 {
		return string(raw)
	}
	var sb strings.Builder
	for i := 0; i+8 <= len(raw); {
		size := int(binary.BigEndian.Uint32(raw[i+4 : i+8]))
		end := i + 8 + size
		if end > len(raw) {
			break
		}
		sb.Write(raw[i+8 : end])
		i = end
	}
	return sb.String()
}

// ErrNotReady is the canonical error a ReadyProbe should return while waiting.
// Distinguishing it from an unexpected error helps with logging.
var ErrNotReady = errors.New("not ready")
