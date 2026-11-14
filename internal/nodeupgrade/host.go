package nodeupgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
)

// Host is every effect the upgrader has on the machine outside the files it
// owns. SystemHost is the real one; tests pass a fake.
type Host interface {
	// UnitActive reports whether a systemd unit is active.
	UnitActive(ctx context.Context, unit string) bool
	StopUnit(ctx context.Context, unit string) error
	StartUnit(ctx context.Context, unit string) error
	RestartUnit(ctx context.Context, unit string) error
	// UnitControlGroup is the unit's cgroup path under the cgroup root.
	UnitControlGroup(ctx context.Context, unit string) string
	// LookPath finds an executable on PATH.
	LookPath(name string) (string, error)
	// FreeBytes is the space an unprivileged write may still use on the
	// file system holding path, and that file system's device, so needs on
	// one file system are added up.
	FreeBytes(path string) (free uint64, device uint64, err error)
	// Run runs a program with separate arguments and returns its combined
	// output.
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	// Fetch opens a URL for streaming. size is -1 when unknown.
	Fetch(ctx context.Context, url string) (body io.ReadCloser, size int64, err error)
	// HealthVersion asks sandboxd's /health and returns the version it
	// reports.
	HealthVersion(ctx context.Context, url string) (string, error)
	// GatewayProtocol asks the running egress gateway its protocol version.
	GatewayProtocol(ctx context.Context, socket string) (int, error)
	// StartDrain starts a process, in its own session, that reads path
	// until EOF, and returns its PID (keepFirecrackerVMsRunning).
	StartDrain(path string) (int, error)
}

// SystemHost is Host on a real systemd machine.
type SystemHost struct {
	// Systemctl is the binary; empty means systemctl on PATH.
	Systemctl string
	// HTTP downloads release files. Nil uses a client with connect and
	// header timeouts and no overall one, since a file can be large.
	HTTP *http.Client
}

var _ Host = (*SystemHost)(nil)

func (h *SystemHost) systemctl() string {
	if h.Systemctl != "" {
		return h.Systemctl
	}
	return "systemctl"
}

func (h *SystemHost) UnitActive(ctx context.Context, unit string) bool {
	return exec.CommandContext(ctx, h.systemctl(), "is-active", "--quiet", unit).Run() == nil
}

func (h *SystemHost) unitCmd(ctx context.Context, verb, unit string) error {
	out, err := exec.CommandContext(ctx, h.systemctl(), verb, unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %w: %s", verb, unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (h *SystemHost) StopUnit(ctx context.Context, unit string) error {
	return h.unitCmd(ctx, "stop", unit)
}

func (h *SystemHost) StartUnit(ctx context.Context, unit string) error {
	return h.unitCmd(ctx, "start", unit)
}

func (h *SystemHost) RestartUnit(ctx context.Context, unit string) error {
	return h.unitCmd(ctx, "restart", unit)
}

func (h *SystemHost) UnitControlGroup(ctx context.Context, unit string) string {
	out, err := exec.CommandContext(ctx, h.systemctl(), "show", "-p", "ControlGroup", "--value", unit).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (h *SystemHost) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (h *SystemHost) FreeBytes(path string) (uint64, uint64, error) {
	// The directory may not exist yet (the staging directory); its nearest
	// existing parent is on the same file system.
	p := path
	for {
		if _, err := os.Stat(p); err == nil {
			break
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(p, &st); err != nil {
		return 0, 0, fmt.Errorf("statfs %s: %w", p, err)
	}
	var dev uint64
	if fi, err := os.Stat(p); err == nil {
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
			dev = uint64(sys.Dev)
		}
	}
	return uint64(st.Bavail) * uint64(st.Bsize), dev, nil
}

func (h *SystemHost) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (h *SystemHost) client() *http.Client {
	if h.HTTP != nil {
		return h.HTTP
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}}
}

func (h *SystemHost) Fetch(ctx context.Context, rawURL string) (io.ReadCloser, int64, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, 0, err
	}
	switch u.Scheme {
	case "file":
		// A mirror on a mounted file system. The version and file name
		// are path-escaped into the URL, and parsing decodes %2F back to
		// "/", so refuse ".." rather than open a file outside the mirror.
		if strings.Contains(u.Path, "..") {
			return nil, 0, fmt.Errorf("release URL %s: a file:// path must not contain \"..\"", rawURL)
		}
		f, err := os.Open(u.Path)
		if err != nil {
			return nil, 0, err
		}
		st, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, 0, err
		}
		return f, st.Size(), nil
	case "http", "https":
	default:
		return nil, 0, fmt.Errorf("release URL %s: scheme must be https, http or file", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, 0, fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	return resp.Body, resp.ContentLength, nil
}

func (h *SystemHost) HealthVersion(ctx context.Context, rawURL string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	var body struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("GET %s: %w", rawURL, err)
	}
	if body.Version == "" {
		return "", errors.New("health answer carries no version")
	}
	return body.Version, nil
}

func (h *SystemHost) GatewayProtocol(ctx context.Context, socket string) (int, error) {
	return egress.ProbeGatewayProtocol(ctx, socket)
}

func (h *SystemHost) StartDrain(path string) (int, error) {
	cmd := exec.Command("cat", path)
	// Stdin, stdout and stderr stay nil: /dev/null. Its own session, so it
	// outlives the upgrader's systemd-run unit once moved out of it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	// Reaped when it exits, if the upgrader is still alive then.
	go func() { _ = cmd.Wait() }()
	return pid, nil
}
