package docker

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// failRuleBackend makes every iptables probe fail so Create's fail-closed
// network paths run without a host firewall.
type failRuleBackend struct{}

func (failRuleBackend) Exists(string, string, ...string) (bool, error) {
	return false, errors.New("iptables unavailable")
}
func (failRuleBackend) Insert(string, string, int, ...string) error {
	return errors.New("iptables unavailable")
}
func (failRuleBackend) Delete(string, string, ...string) error {
	return errors.New("iptables unavailable")
}

func coverage97ImagePresent() *http.Response {
	return jsonResponse(http.StatusOK, map[string]any{
		"Config": map[string]any{"WorkingDir": "/", "Entrypoint": []string{"/e"}, "Cmd": []string{}},
	})
}

func TestCoverage97CreateReadyAndNetruleFailures(t *testing.T) {
	t.Run("ready dir is a file", func(t *testing.T) {
		readyFile := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(readyFile, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		d := &fakeDaemon{t: t, imageInspect: coverage97ImagePresent}
		c := newCreateClient(t, d, true, func(c *Client) {
			c.readyEnabled = true
			c.readyDir = readyFile
		})
		_, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb", "tok", nil)
		if err == nil || !strings.Contains(err.Error(), "ready listener") {
			t.Fatalf("Create() = %v", err)
		}
	})

	t.Run("create error cleans the ready socket", func(t *testing.T) {
		d := &fakeDaemon{
			t:            t,
			imageInspect: coverage97ImagePresent,
			create:       func() *http.Response { return textResponse(http.StatusInternalServerError, "boom") },
		}
		c := newCreateClient(t, d, true, func(c *Client) {
			c.readyEnabled = true
			c.readyDir = shortReadyDir(t)
		})
		_, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb", "tok", nil)
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("Create() = %v", err)
		}
	})

	t.Run("block-all failure tears the container down", func(t *testing.T) {
		d := &fakeDaemon{
			t:            t,
			imageInspect: coverage97ImagePresent,
			create:       func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
			start:        func() *http.Response { return textResponse(http.StatusNoContent, "") },
		}
		c := newCreateClient(t, d, true, nil)
		c.networkRules = netrules.NewWithBackend(failRuleBackend{})
		_, err := c.Create(context.Background(), models.CreateSandboxRequest{
			Image: "img", NetworkBlockAll: true,
		}, "sb", "tok", nil)
		if err == nil || !strings.Contains(err.Error(), "apply network block") {
			t.Fatalf("Create() = %v", err)
		}
		if d.removeCalls == 0 {
			t.Fatal("fail-closed block did not remove the container")
		}
	})

	t.Run("egress policy failure tears the container down", func(t *testing.T) {
		d := &fakeDaemon{
			t:            t,
			imageInspect: coverage97ImagePresent,
			create:       func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
			start:        func() *http.Response { return textResponse(http.StatusNoContent, "") },
		}
		c := newCreateClient(t, d, true, nil)
		c.networkRules = netrules.NewWithBackend(failRuleBackend{})
		_, err := c.Create(context.Background(), models.CreateSandboxRequest{
			Image: "img", NetworkDenyOut: []string{"10.0.0.0/8"},
		}, "sb", "tok", nil)
		if err == nil || !strings.Contains(err.Error(), "apply egress policy") {
			t.Fatalf("Create() = %v", err)
		}
		if d.removeCalls == 0 {
			t.Fatal("fail-closed egress did not remove the container")
		}
	})
}
