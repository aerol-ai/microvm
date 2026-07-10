package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ---------------------------------------------------------------------------
// Shared test plumbing
// ---------------------------------------------------------------------------

// jsonResponse builds a 200/whatever response carrying a JSON body.
func jsonResponse(status int, v any) *http.Response {
	data, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(string(data))),
		Header:     make(http.Header),
	}
}

// textResponse builds a response carrying a raw (non-JSON) body.
func textResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// inspectBody is a literal helper producing the JSON the daemon returns for
// GET /containers/{id}/json. Marshalling a containerInspect value directly is
// awkward because of its anonymous nested structs, so we build the wire JSON.
func inspectBody(id, name, ip string, running bool, status string, pid int) string {
	return fmt.Sprintf(`{"Id":%q,"Name":%q,"State":{"Running":%t,"Status":%q,"Pid":%d},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":%q}}}}`,
		id, name, running, status, pid, ip)
}

// disabledRules returns a no-op netrules manager (BlockAll/Clear all return
// nil). On non-linux hosts netrules.New always yields a disabled manager, but
// passing false makes the intent explicit and host-independent.
func disabledRules(t *testing.T) *netrules.Manager {
	t.Helper()
	rules, err := netrules.New(false)
	if err != nil {
		t.Fatalf("netrules.New: %v", err)
	}
	return rules
}

// ---------------------------------------------------------------------------
// Ping
// ---------------------------------------------------------------------------

func TestPing(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/_ping" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			return textResponse(http.StatusOK, "OK"), nil
		})}}
		if err := c.Ping(context.Background()); err != nil {
			t.Fatalf("Ping() = %v", err)
		}
	})

	t.Run("error_status", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "boom"), nil
		})}}
		if err := c.Ping(context.Background()); err == nil {
			t.Fatal("Ping() expected error on 500")
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("dial fail")
		})}}
		if err := c.Ping(context.Background()); err == nil {
			t.Fatal("Ping() expected transport error")
		}
	})
}

// ---------------------------------------------------------------------------
// Network rule wrappers + ContainerPID
// ---------------------------------------------------------------------------

func TestNetworkRuleWrappers(t *testing.T) {
	c := &Client{networkRules: disabledRules(t)}

	// Empty IP short-circuits before touching the manager.
	if err := c.ClearNetworkRules(""); err != nil {
		t.Fatalf("ClearNetworkRules(\"\") = %v", err)
	}
	if err := c.ApplyNetworkBlockAll(""); err != nil {
		t.Fatalf("ApplyNetworkBlockAll(\"\") = %v", err)
	}
	if err := c.ApplyNetworkBlockIngress(""); err != nil {
		t.Fatalf("ApplyNetworkBlockIngress(\"\") = %v", err)
	}
	if err := c.ClearNetworkBlockIngress(""); err != nil {
		t.Fatalf("ClearNetworkBlockIngress(\"\") = %v", err)
	}
	if err := c.ClearNetworkBlockEgress(""); err != nil {
		t.Fatalf("ClearNetworkBlockEgress(\"\") = %v", err)
	}

	// Non-empty IP drives into the (disabled, no-op) manager.
	const ip = "172.17.0.9"
	if err := c.ClearNetworkRules(ip); err != nil {
		t.Fatalf("ClearNetworkRules(ip) = %v", err)
	}
	if err := c.ApplyNetworkBlockAll(ip); err != nil {
		t.Fatalf("ApplyNetworkBlockAll(ip) = %v", err)
	}
	if err := c.ApplyNetworkBlockIngress(ip); err != nil {
		t.Fatalf("ApplyNetworkBlockIngress(ip) = %v", err)
	}
	if err := c.ClearNetworkBlockIngress(ip); err != nil {
		t.Fatalf("ClearNetworkBlockIngress(ip) = %v", err)
	}
	if err := c.ClearNetworkBlockEgress(ip); err != nil {
		t.Fatalf("ClearNetworkBlockEgress(ip) = %v", err)
	}
}

func TestContainerPID(t *testing.T) {
	t.Run("running_pid", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, inspectBody("cid", "/sb", "172.17.0.2", true, "running", 4321)), nil
		})}}
		pid, err := c.ContainerPID(context.Background(), "sb")
		if err != nil || pid != 4321 {
			t.Fatalf("ContainerPID() = %d, %v", pid, err)
		}
	})

	t.Run("nil_state_zero", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, `{"Id":"cid","Name":"/sb"}`), nil
		})}}
		pid, err := c.ContainerPID(context.Background(), "sb")
		if err != nil || pid != 0 {
			t.Fatalf("ContainerPID() = %d, %v", pid, err)
		}
	})

	t.Run("inspect_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusNotFound, "nope"), nil
		})}}
		if _, err := c.ContainerPID(context.Background(), "sb"); err == nil {
			t.Fatal("ContainerPID() expected inspect error")
		}
	})
}

// ---------------------------------------------------------------------------
// Stop / Destroy / CreateSnapshot / Resize / Inspect / ListManaged / RemoveImage
// ---------------------------------------------------------------------------

func TestStop(t *testing.T) {
	c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(r.URL.Path, "/stop") {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return textResponse(http.StatusNoContent, ""), nil
	})}}
	if err := c.Stop(context.Background(), "sb"); err != nil {
		t.Fatalf("Stop() = %v", err)
	}
}

func TestDestroy(t *testing.T) {
	t.Run("nil_sandbox", func(t *testing.T) {
		c := &Client{networkRules: disabledRules(t)}
		if err := c.Destroy(context.Background(), nil); err != nil {
			t.Fatalf("Destroy(nil) = %v", err)
		}
	})

	t.Run("missing_container_id", func(t *testing.T) {
		c := &Client{networkRules: disabledRules(t)}
		if err := c.Destroy(context.Background(), &models.Sandbox{ContainerIP: "172.17.0.2"}); err == nil {
			t.Fatal("Destroy() expected error for empty container ID")
		}
	})

	t.Run("success", func(t *testing.T) {
		c := &Client{
			networkRules: disabledRules(t),
			httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodDelete {
					t.Fatalf("unexpected method %s", r.Method)
				}
				return textResponse(http.StatusNoContent, ""), nil
			})},
		}
		sb := &models.Sandbox{ContainerID: "cid", ContainerIP: "172.17.0.2"}
		if err := c.Destroy(context.Background(), sb); err != nil {
			t.Fatalf("Destroy() = %v", err)
		}
	})
}

func TestCreateSnapshot(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/commit" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			if got := r.URL.Query().Get("tag"); got != "v1" {
				t.Fatalf("tag query = %q", got)
			}
			return jsonResponse(http.StatusCreated, map[string]string{"Id": "img-sha"}), nil
		})}}
		id, err := c.CreateSnapshot(context.Background(), "cid", "snap-alpha:v1")
		if err != nil || id != "img-sha" {
			t.Fatalf("CreateSnapshot() = %q, %v", id, err)
		}
	})

	t.Run("invalid_ref", func(t *testing.T) {
		c := &Client{}
		if _, err := c.CreateSnapshot(context.Background(), "cid", "bad@sha256:x"); err == nil {
			t.Fatal("CreateSnapshot() expected ref error")
		}
	})

	t.Run("commit_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "boom"), nil
		})}}
		if _, err := c.CreateSnapshot(context.Background(), "cid", "snap-alpha"); err == nil {
			t.Fatal("CreateSnapshot() expected commit error")
		}
	})
}

func TestResize(t *testing.T) {
	t.Run("limits_off_noop", func(t *testing.T) {
		c := &Client{resourceLimitsOff: true}
		if err := c.Resize(context.Background(), "cid", models.ResizeSandboxRequest{CPU: 2}); err != nil {
			t.Fatalf("Resize() = %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if !strings.HasSuffix(r.URL.Path, "/update") {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			return textResponse(http.StatusOK, "{}"), nil
		})}}
		if err := c.Resize(context.Background(), "cid", models.ResizeSandboxRequest{CPU: 2, MemoryMB: 512}); err != nil {
			t.Fatalf("Resize() = %v", err)
		}
	})

	t.Run("update_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "boom"), nil
		})}}
		if err := c.Resize(context.Background(), "cid", models.ResizeSandboxRequest{CPU: 1}); err == nil {
			t.Fatal("Resize() expected update error")
		}
	})
}

func TestInspect(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, inspectBody("cid", "/sb-7", "172.17.0.5", true, "running", 9)), nil
		})}}
		rt, err := c.Inspect(context.Background(), "sb-7")
		if err != nil {
			t.Fatalf("Inspect() = %v", err)
		}
		if rt.SandboxID != "sb-7" || rt.ContainerID != "cid" || rt.ContainerIP != "172.17.0.5" {
			t.Fatalf("Inspect() runtime = %+v", rt)
		}
		if rt.Status != models.SandboxStatusStarted {
			t.Fatalf("Inspect() status = %q", rt.Status)
		}
	})

	t.Run("error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusNotFound, "missing"), nil
		})}}
		if _, err := c.Inspect(context.Background(), "sb"); err == nil {
			t.Fatal("Inspect() expected error")
		}
	})
}

func TestListManaged(t *testing.T) {
	t.Run("filters_and_inspects", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch {
			case r.URL.Path == "/containers/json":
				return jsonResponse(http.StatusOK, []map[string]any{
					{"Id": "managed", "Labels": map[string]string{managedLabelKey: "true"}},
					{"Id": "unmanaged", "Labels": map[string]string{}},
					{"Id": "inspect-fails", "Labels": map[string]string{managedLabelKey: "true"}},
					// Warm-pool park: managed label + park label. Must not
					// appear in ListManaged or reconcile will destroy it.
					{"Id": "parked", "Labels": map[string]string{
						managedLabelKey:  "true",
						poolParkLabelKey: poolParkLabelValue,
					}},
				}), nil
			case r.URL.Path == "/containers/managed/json":
				return textResponse(http.StatusOK, inspectBody("managed", "/sb-managed", "172.17.0.2", true, "running", 1)), nil
			case r.URL.Path == "/containers/inspect-fails/json":
				return textResponse(http.StatusInternalServerError, "boom"), nil
			case r.URL.Path == "/containers/parked/json":
				t.Fatal("ListManaged must not inspect park-labeled containers")
				return nil, nil
			default:
				t.Fatalf("unexpected path %s", r.URL.Path)
				return nil, nil
			}
		})}}
		result, err := c.ListManaged(context.Background())
		if err != nil {
			t.Fatalf("ListManaged() = %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("ListManaged() returned %d entries, want 1", len(result))
		}
		if _, ok := result["sb-managed"]; !ok {
			t.Fatalf("ListManaged() missing sb-managed: %+v", result)
		}
		if _, ok := result["park-d316b60bc106a6f6"]; ok {
			t.Fatal("ListManaged() must exclude parked containers")
		}
	})

	t.Run("excludes_park_name_without_label", func(t *testing.T) {
		// Defense in depth: even if the park label is missing, a park-*
		// container name must not enter the orphan set.
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch {
			case r.URL.Path == "/containers/json":
				return jsonResponse(http.StatusOK, []map[string]any{
					{"Id": "parked-nolabel", "Labels": map[string]string{managedLabelKey: "true"}},
				}), nil
			case r.URL.Path == "/containers/parked-nolabel/json":
				return textResponse(http.StatusOK, inspectBody("parked-nolabel", "/park-aabbccddeeff0011", "172.17.0.9", true, "running", 1)), nil
			default:
				t.Fatalf("unexpected path %s", r.URL.Path)
				return nil, nil
			}
		})}}
		result, err := c.ListManaged(context.Background())
		if err != nil {
			t.Fatalf("ListManaged() = %v", err)
		}
		if len(result) != 0 {
			t.Fatalf("ListManaged() = %+v, want empty (park-* name excluded)", result)
		}
	})

	t.Run("list_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "boom"), nil
		})}}
		if _, err := c.ListManaged(context.Background()); err == nil {
			t.Fatal("ListManaged() expected list error")
		}
	})
}

func TestRemoveImage(t *testing.T) {
	t.Run("empty_noop", func(t *testing.T) {
		c := &Client{}
		if err := c.RemoveImage(context.Background(), "  "); err != nil {
			t.Fatalf("RemoveImage(empty) = %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodDelete {
				t.Fatalf("unexpected method %s", r.Method)
			}
			return jsonResponse(http.StatusOK, []map[string]string{{"Deleted": "sha"}}), nil
		})}}
		if err := c.RemoveImage(context.Background(), "repo/img:latest"); err != nil {
			t.Fatalf("RemoveImage() = %v", err)
		}
	})

	t.Run("benign_409", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusConflict, "image is in use"), nil
		})}}
		if err := c.RemoveImage(context.Background(), "repo/img:latest"); err != nil {
			t.Fatalf("RemoveImage() 409 should be benign, got %v", err)
		}
	})

	t.Run("real_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "boom"), nil
		})}}
		if err := c.RemoveImage(context.Background(), "repo/img:latest"); err == nil {
			t.Fatal("RemoveImage() expected 500 to propagate")
		}
	})
}

// ---------------------------------------------------------------------------
// PushAllowedPorts (toolbox client)
// ---------------------------------------------------------------------------

func TestPushAllowedPorts(t *testing.T) {
	t.Run("empty_ip", func(t *testing.T) {
		c := &Client{}
		if err := c.PushAllowedPorts(context.Background(), "", "tok", []int{1}); err == nil {
			t.Fatal("PushAllowedPorts() expected empty-IP error")
		}
	})

	t.Run("success_and_nil_ports", func(t *testing.T) {
		ip, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/admin/allowed-ports" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer tok" {
				t.Errorf("auth header = %q", got)
			}
			w.WriteHeader(http.StatusOK)
		})
		defer closeFn()
		c := &Client{toolboxClient: &http.Client{}, toolboxPort: port}
		if err := c.PushAllowedPorts(context.Background(), ip, "tok", nil); err != nil {
			t.Fatalf("PushAllowedPorts(nil ports) = %v", err)
		}
		if err := c.PushAllowedPorts(context.Background(), ip, "tok", []int{8080}); err != nil {
			t.Fatalf("PushAllowedPorts() = %v", err)
		}
	})

	t.Run("non_200", func(t *testing.T) {
		ip, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
		defer closeFn()
		c := &Client{toolboxClient: &http.Client{}, toolboxPort: port}
		if err := c.PushAllowedPorts(context.Background(), ip, "", []int{1}); err == nil {
			t.Fatal("PushAllowedPorts() expected non-200 error")
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		// Port 1 on 127.0.0.1 refuses connections → Do() returns an error.
		c := &Client{toolboxClient: &http.Client{Timeout: time.Second}, toolboxPort: 1}
		if err := c.PushAllowedPorts(context.Background(), "127.0.0.1", "tok", []int{1}); err == nil {
			t.Fatal("PushAllowedPorts() expected transport error")
		}
	})
}

// toolboxServer spins up an httptest server and returns the loopback IP + port
// the toolbox client should dial.
func toolboxServer(t *testing.T, handler http.HandlerFunc) (ip string, port int, closeFn func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	hostPort := strings.TrimPrefix(server.URL, "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		server.Close()
		t.Fatalf("split host port: %v", err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		server.Close()
		t.Fatalf("parse port: %v", err)
	}
	return host, p, server.Close
}

// ---------------------------------------------------------------------------
// New + ensureToolboxBinary
// ---------------------------------------------------------------------------

func TestNew(t *testing.T) {
	t.Run("requires_toolbox_binary", func(t *testing.T) {
		if _, err := New(slog.Default(), config.Config{}, nil); err == nil {
			t.Fatal("New() expected error for empty toolbox binary path")
		}
	})

	t.Run("success_with_docker_host_and_pull_cap", func(t *testing.T) {
		t.Setenv("DOCKER_HOST", "unix:///tmp/custom-docker.sock")
		cfg := config.Config{
			ToolboxBinaryPath:      "/usr/local/bin/toolboxd",
			ImagePullMaxConcurrent: 2,
		}
		c, err := New(slog.Default(), cfg, disabledRules(t))
		if err != nil {
			t.Fatalf("New() = %v", err)
		}
		if c.socketPath != "/tmp/custom-docker.sock" {
			t.Fatalf("socketPath = %q", c.socketPath)
		}
		if c.pullSlots == nil || cap(c.pullSlots) != 2 {
			t.Fatalf("pullSlots cap = %v", c.pullSlots)
		}
	})
}

func TestEnsureToolboxBinary(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		c := &Client{toolboxBinaryPath: "/nonexistent/toolboxd-xyz"}
		if err := c.ensureToolboxBinary(); err == nil {
			t.Fatal("ensureToolboxBinary() expected not-found error")
		}
	})

	t.Run("is_directory", func(t *testing.T) {
		c := &Client{toolboxBinaryPath: t.TempDir()}
		if err := c.ensureToolboxBinary(); err == nil {
			t.Fatal("ensureToolboxBinary() expected directory error")
		}
	})

	t.Run("relative_path", func(t *testing.T) {
		// A relative path that exists (created under the temp working dir).
		dir := t.TempDir()
		rel := "toolboxd-rel"
		if err := os.WriteFile(filepath.Join(dir, rel), []byte("x"), 0o755); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Chdir(dir)
		c := &Client{toolboxBinaryPath: rel}
		if err := c.ensureToolboxBinary(); err == nil {
			t.Fatal("ensureToolboxBinary() expected absolute-path error")
		}
	})

	t.Run("valid", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "toolboxd")
		if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
			t.Fatalf("write: %v", err)
		}
		c := &Client{toolboxBinaryPath: bin}
		if err := c.ensureToolboxBinary(); err != nil {
			t.Fatalf("ensureToolboxBinary() = %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// doRequest white-box error branches
// ---------------------------------------------------------------------------

func TestDoRequestErrorBranches(t *testing.T) {
	t.Run("marshal_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{}}
		// channels are not JSON-marshalable → json.Marshal fails before any I/O.
		_, err := c.doRequest(context.Background(), http.MethodPost, "/x", nil, map[string]any{"bad": make(chan int)}, nil)
		if err == nil {
			t.Fatal("doRequest() expected marshal error")
		}
	})

	t.Run("bad_method", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{}}
		// A method string with a space is rejected by http.NewRequestWithContext.
		_, err := c.doRequest(context.Background(), "BAD METHOD", "/x", nil, nil, nil)
		if err == nil {
			t.Fatal("doRequest() expected request-construction error")
		}
	})
}
