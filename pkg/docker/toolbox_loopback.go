package docker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// toolboxLoopbackHost is the only host address the toolbox port is ever
// published on. Nothing else about the sandbox is published.
const toolboxLoopbackHost = "127.0.0.1"

// portBinding is one entry of an inspect NetworkSettings.Ports list.
type portBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

func (c *Client) toolboxPortKey() string {
	return strconv.Itoa(c.toolboxPort) + "/tcp"
}

// containerToolboxAddr is the default toolbox address: the container's own
// IP on the Docker network.
func (c *Client) containerToolboxAddr(containerIP string) string {
	return net.JoinHostPort(containerIP, strconv.Itoa(c.toolboxPort))
}

// publishToolboxLoopback asks Docker to publish the toolbox port on
// 127.0.0.1 with a daemon-assigned host port. It is a no-op unless
// SB_DOCKER_TOOLBOX_LOOPBACK is on. Docker hands out a fresh host port on
// every container start, so the port is read back from the live container
// (toolboxAddr / ToolboxAddress) and never stored.
func (c *Client) publishToolboxLoopback(createRequest, hostConfig map[string]any) {
	if !c.toolboxLoopback {
		return
	}
	key := c.toolboxPortKey()
	createRequest["ExposedPorts"] = map[string]any{key: map[string]any{}}
	hostConfig["PortBindings"] = map[string]any{
		key: []portBinding{{HostIP: toolboxLoopbackHost, HostPort: ""}},
	}
}

// defaultToolboxPublishWait bounds how long toolboxAddr re-inspects a running
// container whose requested 127.0.0.1 binding Docker has not reported yet.
// Docker Desktop can report a just-started container as running while its
// port list is still empty ({"2280/tcp":[]}) and fill the host port in a
// moment later; reading the ports once at that instant failed about one
// create in six. Only that race waits: a container whose first inspect shows
// the port pays nothing extra, and one that never asked for the binding, or
// is not running, fails at once.
const defaultToolboxPublishWait = 2 * time.Second

// toolboxPublishWaitLimit is the wait's cap: Client.toolboxPublishWait
// (tests shorten it), or defaultToolboxPublishWait when that is zero.
func (c *Client) toolboxPublishWaitLimit() time.Duration {
	if c.toolboxPublishWait > 0 {
		return c.toolboxPublishWait
	}
	return defaultToolboxPublishWait
}

// loopbackToolboxAddr is the container's current 127.0.0.1 toolbox binding,
// when Docker reports one. "0" is the "any port" placeholder Docker echoes
// from the request, not a bound port.
func (c *Client) loopbackToolboxAddr(inspect containerInspect) (string, bool) {
	for _, b := range inspect.NetworkSettings.Ports[c.toolboxPortKey()] {
		if b.HostIP == toolboxLoopbackHost && b.HostPort != "" && b.HostPort != "0" {
			return net.JoinHostPort(toolboxLoopbackHost, b.HostPort), true
		}
	}
	return "", false
}

// requestsToolboxLoopback reports whether the container was created to
// publish the toolbox port on 127.0.0.1 (publishToolboxLoopback). Then a
// missing host port means Docker has not bound it yet, not that the
// container predates SB_DOCKER_TOOLBOX_LOOPBACK. Docker keeps the request in
// HostConfig.PortBindings. NetworkSettings.Ports shows it too, before the
// bind, as an empty list or a 127.0.0.1 entry with no port; an engine that
// leaves HostConfig out is still recognized by that.
func (c *Client) requestsToolboxLoopback(inspect containerInspect) bool {
	key := c.toolboxPortKey()
	for _, b := range inspect.HostConfig.PortBindings[key] {
		if b.HostIP == toolboxLoopbackHost {
			return true
		}
	}
	live, exposed := inspect.NetworkSettings.Ports[key]
	if exposed && len(live) == 0 {
		return true
	}
	for _, b := range live {
		if b.HostIP == toolboxLoopbackHost {
			return true
		}
	}
	return false
}

func containerNotRunning(inspect containerInspect) bool {
	return inspect.State != nil && !inspect.State.Running
}

// toolboxAddr resolves the host:port sandboxd dials to reach toolboxd in the
// inspected container. ref is the name or ID the caller inspected; it is
// inspected again while Docker has yet to publish a requested binding.
func (c *Client) toolboxAddr(ctx context.Context, ref string, inspect containerInspect, containerIP string) (string, error) {
	if !c.toolboxLoopback {
		return c.containerToolboxAddr(containerIP), nil
	}
	if addr, ok := c.loopbackToolboxAddr(inspect); ok {
		return addr, nil
	}
	if !c.requestsToolboxLoopback(inspect) {
		return "", fmt.Errorf("toolbox port %s is not published on %s for container %s: the container was created without that binding (before SB_DOCKER_TOOLBOX_LOOPBACK was enabled?); recreate the sandbox",
			c.toolboxPortKey(), toolboxLoopbackHost, inspect.ID)
	}
	if containerNotRunning(inspect) {
		return "", c.toolboxNotRunningErr(inspect.ID)
	}
	if ref == "" {
		ref = inspect.ID
	}
	limit := c.toolboxPublishWaitLimit()
	deadline := time.Now().Add(limit)
	sleep := c.readinessPollInterval()
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		timer := time.NewTimer(min(sleep(), remaining))
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
		next, err := c.inspectContainer(ctx, ref)
		if err != nil {
			return "", fmt.Errorf("inspect container: %w", err)
		}
		if addr, ok := c.loopbackToolboxAddr(next); ok {
			return addr, nil
		}
		if containerNotRunning(next) {
			return "", c.toolboxNotRunningErr(inspect.ID)
		}
	}
	return "", fmt.Errorf("docker has not published toolbox port %s of running container %s on %s after waiting %s",
		c.toolboxPortKey(), inspect.ID, toolboxLoopbackHost, limit)
}

func (c *Client) toolboxNotRunningErr(containerID string) error {
	return fmt.Errorf("toolbox port %s is not published on %s for container %s: the container is not running",
		c.toolboxPortKey(), toolboxLoopbackHost, containerID)
}

// ToolboxAddress returns the host:port at which sandboxd reaches the
// sandbox's toolboxd. By default that is ContainerIP:ToolboxPort. With
// SB_DOCKER_TOOLBOX_LOOPBACK it is the container's current 127.0.0.1
// binding, read with one inspect per call because the port changes on every
// start (more only while Docker has yet to publish a just-started
// container's port; see defaultToolboxPublishWait).
func (c *Client) ToolboxAddress(ctx context.Context, sandbox *models.Sandbox) (string, error) {
	if sandbox == nil {
		return "", errors.New("sandbox is nil")
	}
	if !c.toolboxLoopback {
		if sandbox.ContainerIP == "" {
			return "", errors.New("sandbox container IP is not available")
		}
		return c.containerToolboxAddr(sandbox.ContainerIP), nil
	}
	ref := sandbox.ContainerID
	if ref == "" {
		ref = sandbox.ID
	}
	inspect, err := c.inspectContainer(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("inspect container: %w", err)
	}
	return c.toolboxAddr(ctx, ref, inspect, "")
}

// toolboxAddrForIP is toolboxAddr for callers that only hold the container
// IP (the ContainerRuntime network-rule methods). With loopback on it finds
// the running managed container with that IP and reads its toolbox binding.
func (c *Client) toolboxAddrForIP(ctx context.Context, containerIP string) (string, error) {
	if !c.toolboxLoopback {
		return c.containerToolboxAddr(containerIP), nil
	}
	query := url.Values{}
	query.Set("filters", `{"label":["`+managedLabelKey+`=true"]}`)
	var containers []struct {
		Ports []struct {
			IP          string `json:"IP"`
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/containers/json", query, nil, nil, &containers); err != nil {
		return "", fmt.Errorf("list managed containers: %w", err)
	}
	for _, ctr := range containers {
		owns := false
		for _, network := range ctr.NetworkSettings.Networks {
			if network.IPAddress == containerIP {
				owns = true
				break
			}
		}
		if !owns {
			continue
		}
		for _, p := range ctr.Ports {
			if p.PrivatePort == c.toolboxPort && p.Type == "tcp" && p.IP == toolboxLoopbackHost && p.PublicPort > 0 {
				return net.JoinHostPort(toolboxLoopbackHost, strconv.Itoa(p.PublicPort)), nil
			}
		}
	}
	return "", fmt.Errorf("no running sandbox container at %s publishes toolbox port %s on %s", containerIP, c.toolboxPortKey(), toolboxLoopbackHost)
}
