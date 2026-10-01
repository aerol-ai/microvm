package docker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"

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

// toolboxAddr resolves the host:port sandboxd dials to reach toolboxd in the
// inspected container.
func (c *Client) toolboxAddr(inspect containerInspect, containerIP string) (string, error) {
	if !c.toolboxLoopback {
		return c.containerToolboxAddr(containerIP), nil
	}
	for _, b := range inspect.NetworkSettings.Ports[c.toolboxPortKey()] {
		if b.HostIP == toolboxLoopbackHost && b.HostPort != "" {
			return net.JoinHostPort(toolboxLoopbackHost, b.HostPort), nil
		}
	}
	return "", fmt.Errorf("toolbox port %s is not published on %s for container %s (created before SB_DOCKER_TOOLBOX_LOOPBACK was enabled? recreate the sandbox)",
		c.toolboxPortKey(), toolboxLoopbackHost, inspect.ID)
}

// ToolboxAddress returns the host:port at which sandboxd reaches the
// sandbox's toolboxd. By default that is ContainerIP:ToolboxPort. With
// SB_DOCKER_TOOLBOX_LOOPBACK it is the container's current 127.0.0.1
// binding, read with one inspect per call because the port changes on every
// start.
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
	return c.toolboxAddr(inspect, "")
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
