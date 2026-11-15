package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// unroutableContainerIP is TEST-NET-1: never routable, so a loopback test
// only passes if sandboxd dialed the 127.0.0.1 binding, not the container IP.
const unroutableContainerIP = "192.0.2.10"

// loopbackInspectBody is inspectBody plus one toolbox port binding.
func loopbackInspectBody(hostIP string, hostPort int) string {
	return fmt.Sprintf(`{"Id":"cid","Name":"/sb","State":{"Running":true,"Status":"running","Pid":7},`+
		`"NetworkSettings":{"Networks":{"bridge":{"IPAddress":%q}},"Ports":{"2280/tcp":[{"HostIp":%q,"HostPort":"%d"}]}}}`,
		unroutableContainerIP, hostIP, hostPort)
}

func okToolbox(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

func captureCreateBody(t *testing.T, c *Client, dst *[]byte) {
	t.Helper()
	base := c.httpClient.Transport
	c.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.URL.Path == "/containers/create" {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read create body: %v", err)
			}
			*dst = b
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		return base.RoundTrip(r)
	})
}

type publishedShape struct {
	ExposedPorts map[string]json.RawMessage `json:"ExposedPorts"`
	HostConfig   struct {
		PortBindings map[string][]portBinding `json:"PortBindings"`
	} `json:"HostConfig"`
}

func imagePresent() *http.Response {
	return jsonResponse(http.StatusOK, map[string]any{
		"Config": map[string]any{"WorkingDir": "/", "Entrypoint": []string{}, "Cmd": []string{"/bin/sh"}},
	})
}

func TestCreate_ToolboxLoopbackPublishesOnlyTheToolboxPortOnLoopback(t *testing.T) {
	_, hostPort, closeFn := toolboxServer(t, okToolbox)
	defer closeFn()
	d := &fakeDaemon{
		t:            t,
		imageInspect: imagePresent,
		create:       func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
		start:        func() *http.Response { return textResponse(http.StatusNoContent, "") },
		containerGet: func() *http.Response {
			return textResponse(http.StatusOK, loopbackInspectBody(toolboxLoopbackHost, hostPort))
		},
	}
	c := newCreateClient(t, d, true, func(c *Client) {
		c.toolboxLoopback = true
		c.toolboxPort = 2280
	})
	var createBody []byte
	captureCreateBody(t, c, &createBody)

	rt, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "registry.example/app:v1"}, "sb", "tok", nil)
	if err != nil {
		t.Fatalf("Create() = %v (toolbox must be reached via 127.0.0.1:%d, not the container IP)", err, hostPort)
	}
	if rt.ContainerIP != unroutableContainerIP {
		t.Fatalf("Create() ContainerIP = %q, want the container's own IP %q", rt.ContainerIP, unroutableContainerIP)
	}

	var body publishedShape
	if err := json.Unmarshal(createBody, &body); err != nil {
		t.Fatalf("create body: %v", err)
	}
	if len(body.ExposedPorts) != 1 || body.ExposedPorts["2280/tcp"] == nil {
		t.Fatalf("ExposedPorts = %v, want exactly 2280/tcp", body.ExposedPorts)
	}
	got := body.HostConfig.PortBindings
	want := []portBinding{{HostIP: "127.0.0.1", HostPort: ""}}
	if len(got) != 1 || len(got["2280/tcp"]) != 1 || got["2280/tcp"][0] != want[0] {
		t.Fatalf("PortBindings = %+v, want only 2280/tcp on 127.0.0.1 with a daemon-assigned port", got)
	}
}

func TestCreate_ToolboxLoopbackOffPublishesNothing(t *testing.T) {
	d := &fakeDaemon{
		t:            t,
		imageInspect: imagePresent,
		// Failing the create keeps the test off the start/wait path; the
		// request body is already captured by then.
		create: func() *http.Response {
			return textResponse(http.StatusInternalServerError, `{"message":"stop here"}`)
		},
	}
	c := newCreateClient(t, d, true, nil)
	var createBody []byte
	captureCreateBody(t, c, &createBody)

	if _, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "registry.example/app:v1"}, "sb", "tok", nil); err == nil {
		t.Fatal("Create() expected injected create failure")
	}
	var body publishedShape
	if err := json.Unmarshal(createBody, &body); err != nil {
		t.Fatalf("create body: %v", err)
	}
	if body.ExposedPorts != nil || body.HostConfig.PortBindings != nil {
		t.Fatalf("loopback off must publish nothing, got ExposedPorts=%v PortBindings=%v", body.ExposedPorts, body.HostConfig.PortBindings)
	}
}

// A container that never asked for the loopback binding fails at once, with
// no re-inspect: waiting cannot make Docker publish it. (A requested binding
// with no host port yet is the Docker Desktop race, which waits; see
// TestToolboxLoopbackWaitsForDockerToPublishThePort.)
func TestCreate_ToolboxLoopbackWithoutLoopbackBindingFails(t *testing.T) {
	for name, inspect := range map[string]string{
		"no_binding":           inspectBody("cid", "/sb", unroutableContainerIP, true, "running", 7),
		"all_interfaces":       loopbackInspectBody("0.0.0.0", 49153),
		"other_container_port": strings.Replace(loopbackInspectBody(toolboxLoopbackHost, 49153), `"2280/tcp"`, `"8080/tcp"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			inspects := 0
			d := &fakeDaemon{
				t:            t,
				imageInspect: imagePresent,
				create:       func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
				start:        func() *http.Response { return textResponse(http.StatusNoContent, "") },
				containerGet: func() *http.Response { inspects++; return textResponse(http.StatusOK, inspect) },
			}
			c := newCreateClient(t, d, true, func(c *Client) {
				c.toolboxLoopback = true
				c.toolboxPort = 2280
			})
			_, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "registry.example/app:v1"}, "sb", "tok", nil)
			if err == nil || !strings.Contains(err.Error(), "is not published on 127.0.0.1") || !strings.Contains(err.Error(), "created without that binding") {
				t.Fatalf("Create() error = %v, want unpublished-toolbox error naming the missing binding", err)
			}
			if inspects != 1 {
				t.Fatalf("container inspected %d times, want 1: a binding never requested is not waited for", inspects)
			}
			if d.removeCalls != 1 {
				t.Fatalf("container must be removed on failure, removeCalls = %d", d.removeCalls)
			}
		})
	}
}

func TestStart_ToolboxLoopback(t *testing.T) {
	_, hostPort, closeFn := toolboxServer(t, okToolbox)
	defer closeFn()
	newClient := func(inspect string) *Client {
		d := &fakeDaemon{
			t:            t,
			start:        func() *http.Response { return textResponse(http.StatusNoContent, "") },
			containerGet: func() *http.Response { return textResponse(http.StatusOK, inspect) },
		}
		return &Client{
			httpClient:         &http.Client{Transport: d.transport()},
			toolboxClient:      &http.Client{Timeout: 2 * time.Second},
			toolboxPort:        2280,
			toolboxLoopback:    true,
			waitTimeout:        2 * time.Second,
			toolboxWaitTimeout: 2 * time.Second,
		}
	}

	t.Run("dials_current_loopback_binding", func(t *testing.T) {
		rt, err := newClient(loopbackInspectBody(toolboxLoopbackHost, hostPort)).Start(context.Background(), "sb")
		if err != nil {
			t.Fatalf("Start() = %v", err)
		}
		if rt.ContainerIP != unroutableContainerIP {
			t.Fatalf("Start() ContainerIP = %q", rt.ContainerIP)
		}
	})

	t.Run("missing_binding", func(t *testing.T) {
		_, err := newClient(inspectBody("cid", "/sb", unroutableContainerIP, true, "running", 7)).Start(context.Background(), "sb")
		if err == nil || !strings.Contains(err.Error(), "is not published on 127.0.0.1") {
			t.Fatalf("Start() error = %v, want unpublished-toolbox error", err)
		}
	})
}

// requestedLoopbackInspectBody is a container created with the loopback
// binding (HostConfig.PortBindings, as Docker echoes it back), whose live
// NetworkSettings.Ports entry for the toolbox port is ports. With ports
// "[]" and running true it is what Docker Desktop reports for a moment
// after start (the Nov 15 Inspect run: 1 create in 6 failed on it).
func requestedLoopbackInspectBody(running bool, ports string) string {
	return fmt.Sprintf(`{"Id":"cid","Name":"/sb","State":{"Running":%t,"Status":"running","Pid":7},`+
		`"NetworkSettings":{"Networks":{"bridge":{"IPAddress":%q}},"Ports":{"2280/tcp":%s}},`+
		`"HostConfig":{"PortBindings":{"2280/tcp":[{"HostIp":"127.0.0.1","HostPort":"0"}]}}}`,
		running, unroutableContainerIP, ports)
}

// inspectStep is one answer of a container inspect sequence; status 0 is 200.
type inspectStep struct {
	status int
	body   string
}

// inspectSequence answers successive container inspects with steps in order,
// repeating the last one, and counts the calls.
func inspectSequence(steps []inspectStep, calls *int) func() *http.Response {
	return func() *http.Response {
		step := steps[min(*calls, len(steps)-1)]
		*calls++
		if step.status == 0 {
			step.status = http.StatusOK
		}
		return textResponse(step.status, step.body)
	}
}

// Docker Desktop can report a just-started container as running before it
// has published the requested 127.0.0.1 toolbox port. The create and start
// paths re-inspect briefly instead of failing on the first read, and pay
// nothing extra when the first inspect already shows the port.
func TestToolboxLoopbackWaitsForDockerToPublishThePort(t *testing.T) {
	_, hostPort, closeFn := toolboxServer(t, okToolbox)
	defer closeFn()
	published := loopbackInspectBody(toolboxLoopbackHost, hostPort)
	race := requestedLoopbackInspectBody(true, `[]`)

	for _, tc := range []struct {
		name         string
		start        bool // Start (waitForRuntime) instead of Create
		steps        []inspectStep
		wantErr      string
		wantInspects int // 0: at least 2 (only checked on success)
	}{
		{name: "published_at_once_no_extra_inspect", steps: []inspectStep{{body: published}}, wantInspects: 1},
		{name: "empty_port_list_then_published", steps: []inspectStep{{body: race}, {body: race}, {body: published}}, wantInspects: 3},
		{
			name: "placeholder_port_then_published",
			steps: []inspectStep{
				{body: requestedLoopbackInspectBody(true, `[{"HostIp":"127.0.0.1","HostPort":"0"}]`)},
				{body: requestedLoopbackInspectBody(true, `[{"HostIp":"127.0.0.1","HostPort":""}]`)},
				{body: published},
			},
			wantInspects: 3,
		},
		{
			// An engine that leaves HostConfig out is recognized by the
			// exposed-but-unbound port alone.
			name:         "exposed_without_host_config_then_published",
			steps:        []inspectStep{{body: strings.Replace(race, `,"HostConfig":{"PortBindings":{"2280/tcp":[{"HostIp":"127.0.0.1","HostPort":"0"}]}}`, "", 1)}, {body: published}},
			wantInspects: 2,
		},
		{name: "start_empty_port_list_then_published", start: true, steps: []inspectStep{{body: race}, {body: published}}, wantInspects: 2},
		{name: "never_published_is_bounded", steps: []inspectStep{{body: race}}, wantErr: "docker has not published toolbox port 2280/tcp of running container cid on 127.0.0.1 after waiting 60ms"},
		{name: "stops_while_waiting", steps: []inspectStep{{body: race}, {body: requestedLoopbackInspectBody(false, `[]`)}}, wantErr: "the container is not running"},
		{name: "reinspect_fails", steps: []inspectStep{{body: race}, {status: http.StatusNotFound, body: `{"message":"no such container"}`}}, wantErr: "inspect container"},
		{name: "start_never_published", start: true, steps: []inspectStep{{body: race}}, wantErr: "has not published toolbox port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inspects := 0
			d := &fakeDaemon{
				t:            t,
				imageInspect: imagePresent,
				create:       func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
				start:        func() *http.Response { return textResponse(http.StatusNoContent, "") },
				containerGet: inspectSequence(tc.steps, &inspects),
			}
			c := newCreateClient(t, d, true, func(c *Client) {
				c.toolboxLoopback = true
				c.toolboxPort = 2280
				c.toolboxPublishWait = 60 * time.Millisecond
				c.readinessPollInit = 5 * time.Millisecond
				c.readinessPollMax = 10 * time.Millisecond
			})

			var err error
			if tc.start {
				_, err = c.Start(context.Background(), "sb")
			} else {
				_, err = c.Create(context.Background(), models.CreateSandboxRequest{Image: "registry.example/app:v1"}, "sb", "tok", nil)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				if !tc.start && d.removeCalls != 1 {
					t.Fatalf("a create that cannot reach its toolbox must remove the container, removeCalls = %d", d.removeCalls)
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v (toolbox must be reached via 127.0.0.1:%d once Docker publishes it)", err, hostPort)
			}
			if inspects != tc.wantInspects {
				t.Fatalf("container inspected %d times, want %d", inspects, tc.wantInspects)
			}
			if d.removeCalls != 0 {
				t.Fatalf("removeCalls = %d on success", d.removeCalls)
			}
		})
	}
}

// The wait honors the caller's context, and a container that is not running
// fails without one.
func TestToolboxAddrLoopbackWaitStops(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		inspect string
		wantErr error
		wantMsg string
	}{
		{name: "context_cancelled", ctx: cancelled, inspect: requestedLoopbackInspectBody(true, `[]`), wantErr: context.Canceled},
		{name: "not_running", ctx: context.Background(), inspect: requestedLoopbackInspectBody(false, `null`), wantMsg: "toolbox port 2280/tcp is not published on 127.0.0.1 for container cid: the container is not running"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{
				toolboxPort:     2280,
				toolboxLoopback: true,
				httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					t.Fatalf("unexpected docker call %s %s", r.Method, r.URL.Path)
					return nil, nil
				})},
			}
			var inspect containerInspect
			if err := json.Unmarshal([]byte(tc.inspect), &inspect); err != nil {
				t.Fatalf("inspect body: %v", err)
			}
			_, err := c.toolboxAddr(tc.ctx, "", inspect, "")
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("toolboxAddr() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantMsg != "" && (err == nil || err.Error() != tc.wantMsg) {
				t.Fatalf("toolboxAddr() error = %v, want %q", err, tc.wantMsg)
			}
		})
	}
	if got := (&Client{}).toolboxPublishWaitLimit(); got != defaultToolboxPublishWait {
		t.Fatalf("zero toolboxPublishWait = %s, want the %s default", got, defaultToolboxPublishWait)
	}
}

func TestToolboxAddress(t *testing.T) {
	for _, tc := range []struct {
		name     string
		loopback bool
		sandbox  *models.Sandbox
		inspect  *http.Response
		wantPath string
		want     string
		wantErr  string
	}{
		{name: "nil_sandbox", sandbox: nil, wantErr: "sandbox is nil"},
		{name: "default_container_ip", sandbox: &models.Sandbox{ContainerIP: "10.0.0.5"}, want: "10.0.0.5:2280"},
		{name: "default_no_ip", sandbox: &models.Sandbox{}, wantErr: "container IP is not available"},
		{
			name: "loopback_by_container_id", loopback: true,
			sandbox:  &models.Sandbox{ID: "sb-1", ContainerID: "cid", ContainerIP: unroutableContainerIP},
			inspect:  textResponse(http.StatusOK, loopbackInspectBody(toolboxLoopbackHost, 49153)),
			wantPath: "/containers/cid/json", want: "127.0.0.1:49153",
		},
		{
			name: "loopback_falls_back_to_sandbox_id", loopback: true,
			sandbox:  &models.Sandbox{ID: "sb-1"},
			inspect:  textResponse(http.StatusOK, loopbackInspectBody(toolboxLoopbackHost, 49154)),
			wantPath: "/containers/sb-1/json", want: "127.0.0.1:49154",
		},
		{
			name: "loopback_inspect_error", loopback: true,
			sandbox: &models.Sandbox{ContainerID: "cid"},
			inspect: textResponse(http.StatusNotFound, `{"message":"no such container"}`),
			wantErr: "inspect container",
		},
		{
			name: "loopback_unpublished", loopback: true,
			sandbox: &models.Sandbox{ContainerID: "cid"},
			inspect: textResponse(http.StatusOK, inspectBody("cid", "/sb", unroutableContainerIP, true, "running", 7)),
			wantErr: "is not published on 127.0.0.1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath string
			c := &Client{
				toolboxPort:     2280,
				toolboxLoopback: tc.loopback,
				httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					gotPath = r.URL.Path
					if tc.inspect == nil {
						t.Fatalf("unexpected docker call %s %s", r.Method, r.URL.Path)
					}
					return tc.inspect, nil
				})},
			}
			got, err := c.ToolboxAddress(context.Background(), tc.sandbox)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ToolboxAddress() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ToolboxAddress() = %q, %v; want %q", got, err, tc.want)
			}
			if gotPath != tc.wantPath {
				t.Fatalf("inspected %q, want %q", gotPath, tc.wantPath)
			}
		})
	}
}

func TestPushAllowedPorts_ToolboxLoopback(t *testing.T) {
	var pushed []byte
	_, hostPort, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/allowed-ports" || r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		pushed, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	defer closeFn()
	listing := fmt.Sprintf(`[
		{"Ports":[{"IP":"127.0.0.1","PrivatePort":2280,"PublicPort":1,"Type":"tcp"}],"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"192.0.2.99"}}}},
		{"Ports":[{"IP":"0.0.0.0","PrivatePort":2280,"PublicPort":2,"Type":"tcp"},
		          {"IP":"127.0.0.1","PrivatePort":8080,"PublicPort":3,"Type":"tcp"},
		          {"IP":"127.0.0.1","PrivatePort":2280,"PublicPort":%d,"Type":"tcp"}],
		 "NetworkSettings":{"Networks":{"bridge":{"IPAddress":%q}}}}
	]`, hostPort, unroutableContainerIP)
	newClient := func(list *http.Response) *Client {
		return &Client{
			toolboxPort:     2280,
			toolboxLoopback: true,
			toolboxClient:   &http.Client{Timeout: 2 * time.Second},
			httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/containers/json" || !strings.Contains(r.URL.Query().Get("filters"), "aerolvm.managed=true") {
					t.Fatalf("unexpected docker call %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
				}
				return list, nil
			})},
		}
	}

	t.Run("resolves_loopback_binding_by_ip", func(t *testing.T) {
		if err := newClient(textResponse(http.StatusOK, listing)).PushAllowedPorts(context.Background(), unroutableContainerIP, "tok", []int{8080}); err != nil {
			t.Fatalf("PushAllowedPorts() = %v", err)
		}
		if string(pushed) != `{"ports":[8080]}` {
			t.Fatalf("pushed body = %s", pushed)
		}
	})

	t.Run("no_container_with_ip", func(t *testing.T) {
		err := newClient(textResponse(http.StatusOK, listing)).PushAllowedPorts(context.Background(), "192.0.2.50", "tok", nil)
		if err == nil || !strings.Contains(err.Error(), "no running sandbox container at 192.0.2.50") {
			t.Fatalf("PushAllowedPorts() error = %v", err)
		}
	})

	t.Run("list_error", func(t *testing.T) {
		err := newClient(textResponse(http.StatusInternalServerError, `{"message":"boom"}`)).PushAllowedPorts(context.Background(), unroutableContainerIP, "tok", nil)
		if err == nil || !strings.Contains(err.Error(), "list managed containers") {
			t.Fatalf("PushAllowedPorts() error = %v", err)
		}
	})
}
