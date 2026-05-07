package docker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

const managedLabelKey = "sandbox-library.managed"

type SandboxRuntime struct {
	SandboxID   string
	ContainerID string
	ContainerIP string
	Status      models.SandboxStatus
}

type Client struct {
	logger             *slog.Logger
	socketPath         string
	network            string
	toolboxBinaryPath  string
	toolboxMountPath   string
	toolboxPort        int
	privileged         bool
	resourceLimitsOff  bool
	httpClient         *http.Client
	streamClient       *http.Client
	toolboxClient      *http.Client
	networkRules       *netrules.Manager
	waitTimeout        time.Duration
	toolboxWaitTimeout time.Duration
}

func New(logger *slog.Logger, cfg config.Config, rules *netrules.Manager) (*Client, error) {
	if cfg.ToolboxBinaryPath == "" {
		return nil, errors.New("SB_TOOLBOX_BINARY_PATH is required")
	}

	socketPath := "/var/run/docker.sock"
	if rawDockerHost := strings.TrimSpace(os.Getenv("DOCKER_HOST")); strings.HasPrefix(rawDockerHost, "unix://") {
		socketPath = strings.TrimPrefix(rawDockerHost, "unix://")
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}

	return &Client{
		logger:             logger,
		socketPath:         socketPath,
		network:            cfg.DockerNetwork,
		toolboxBinaryPath:  cfg.ToolboxBinaryPath,
		toolboxMountPath:   cfg.ToolboxMountPath,
		toolboxPort:        cfg.ToolboxPort,
		privileged:         cfg.ContainerPrivileged,
		resourceLimitsOff:  cfg.ResourceLimitsOff,
		httpClient:         &http.Client{Timeout: cfg.HTTPClientTimeout, Transport: transport},
		streamClient:       &http.Client{Transport: transport},
		toolboxClient:      &http.Client{Timeout: cfg.HTTPClientTimeout},
		networkRules:       rules,
		waitTimeout:        cfg.DockerRuntimeWaitTimeout,
		toolboxWaitTimeout: cfg.ToolboxWaitTimeout,
	}, nil
}

// ClearNetworkRules releases any per-IP network rules previously attached to a
// sandbox. Used by the event-driven path when a container exits or is destroyed
// out-of-band, since Destroy() handles this for us during normal teardown.
func (c *Client) ClearNetworkRules(containerIP string) error {
	if containerIP == "" {
		return nil
	}
	return c.networkRules.ClearBlockAllEgress(containerIP)
}

func (c *Client) Ping(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/_ping", nil)
	if err != nil {
		return err
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return fmt.Errorf("docker ping failed with status %d", response.StatusCode)
	}
	return nil
}

// Create provisions and starts a managed container. The caller chooses the
// sandbox ID up-front; we set it as the container's Docker name so the name
// is the canonical sandbox identifier end-to-end (the container ID is an
// internal detail). Host-side mounts are passed as bind sources prepared by
// the mounts manager; sandboxd never writes a mounts.json into the container.
func (c *Client) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID string, toolboxToken string, hostMounts []mounts.ContainerBind) (*SandboxRuntime, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil, errors.New("sandbox ID is required")
	}
	if err := c.ensureToolboxBinary(); err != nil {
		return nil, err
	}

	if err := c.pullImage(ctx, req.Image, req.Registry); err != nil {
		return nil, err
	}

	imageInspect, err := c.inspectImage(ctx, req.Image)
	if err != nil {
		return nil, fmt.Errorf("inspect image: %w", err)
	}

	workingDir := strings.TrimSpace(imageInspect.Config.WorkingDir)
	if workingDir == "" {
		workingDir = "/"
	}

	envValues := make([]string, 0, len(req.Env)+3)
	envValues = append(envValues,
		fmt.Sprintf("SB_TOOLBOX_PORT=%d", c.toolboxPort),
		"SB_TOOLBOX_TOKEN="+toolboxToken,
	)
	for key, value := range req.Env {
		envValues = append(envValues, key+"="+value)
	}
	sort.Strings(envValues)

	labels := map[string]string{
		managedLabelKey: "true",
	}

	userCommand := req.ContainerCommand
	if len(userCommand) == 0 {
		userCommand = append(append([]string{}, imageInspect.Config.Entrypoint...), imageInspect.Config.Cmd...)
	}

	createRequest := map[string]any{
		"Image":      req.Image,
		"WorkingDir": workingDir,
		"Entrypoint": []string{c.toolboxMountPath},
		"Cmd":        userCommand,
		"Env":        envValues,
		"Labels":     labels,
	}

	binds := []string{
		fmt.Sprintf("%s:%s:ro", c.toolboxBinaryPath, c.toolboxMountPath),
	}
	for _, m := range hostMounts {
		entry := fmt.Sprintf("%s:%s", m.HostPath, m.ContainerPath)
		if m.ReadOnly {
			entry += ":ro"
		}
		binds = append(binds, entry)
	}

	hostConfig := map[string]any{
		"Privileged": c.privileged,
		"Binds":      binds,
	}

	if c.network != "" && c.network != "bridge" {
		hostConfig["NetworkMode"] = c.network
	}

	if !c.resourceLimitsOff {
		resources := map[string]any{}
		if req.CPU > 0 {
			resources["CpuPeriod"] = int64(100000)
			resources["CpuQuota"] = int64(req.CPU) * 100000
		}
		if req.MemoryMB > 0 {
			resources["Memory"] = int64(req.MemoryMB) * 1024 * 1024
			resources["MemorySwap"] = int64(req.MemoryMB) * 1024 * 1024
		}
		if req.DiskGB > 0 {
			hostConfig["StorageOpt"] = map[string]string{"size": fmt.Sprintf("%dG", req.DiskGB)}
		}
		hostConfig["Resources"] = resources
	}
	createRequest["HostConfig"] = hostConfig

	var created struct {
		ID string `json:"Id"`
	}
	createQuery := url.Values{}
	createQuery.Set("name", sandboxID)
	err = c.doJSON(ctx, http.MethodPost, "/containers/create", createQuery, createRequest, nil, &created)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}

	if err := c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(created.ID)+"/start", nil, nil, nil, nil); err != nil {
		_ = c.removeContainer(ctx, created.ID, true)
		return nil, fmt.Errorf("start container: %w", err)
	}

	runtime, err := c.waitForRuntime(ctx, created.ID)
	if err != nil {
		_ = c.removeContainer(ctx, created.ID, true)
		return nil, err
	}

	if req.NetworkBlockAll {
		if err := c.networkRules.BlockAllEgress(runtime.ContainerIP); err != nil {
			c.logger.Warn("failed to apply network rule", "sandbox_id", runtime.SandboxID, "error", err)
		}
	}

	runtime.SandboxID = sandboxID
	return runtime, nil
}

func (c *Client) Start(ctx context.Context, containerRef string) (*SandboxRuntime, error) {
	if err := c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerRef)+"/start", nil, nil, nil, nil); err != nil {
		return nil, fmt.Errorf("start container: %w", err)
	}
	return c.waitForRuntime(ctx, containerRef)
}

func (c *Client) Stop(ctx context.Context, containerRef string) error {
	return c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerRef)+"/stop", queryValues(map[string]string{"t": "10"}), nil, nil, nil)
}

func (c *Client) Destroy(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox != nil {
		_ = c.networkRules.ClearBlockAllEgress(sandbox.ContainerIP)
	}
	if sandbox == nil {
		return nil
	}
	containerRef := strings.TrimSpace(sandbox.ContainerID)
	if containerRef == "" {
		return errors.New("sandbox container ID is not available")
	}
	return c.removeContainer(ctx, containerRef, true)
}

func (c *Client) Resize(ctx context.Context, containerRef string, req models.ResizeSandboxRequest) error {
	if c.resourceLimitsOff {
		return nil
	}

	updateRequest := map[string]any{}
	if req.CPU > 0 {
		updateRequest["CpuPeriod"] = int64(100000)
		updateRequest["CpuQuota"] = int64(req.CPU) * 100000
	}
	if req.MemoryMB > 0 {
		updateRequest["Memory"] = int64(req.MemoryMB) * 1024 * 1024
		updateRequest["MemorySwap"] = int64(req.MemoryMB) * 1024 * 1024
	}

	if err := c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerRef)+"/update", nil, updateRequest, nil, nil); err != nil {
		return fmt.Errorf("resize container: %w", err)
	}
	return nil
}

// PushAllowedPorts updates the toolbox's in-memory allowlist of ports that
// /proxy/<port>/... is permitted to reach. The list should match the sandbox's
// currently exposed ports. Best-effort: callers log on failure.
func (c *Client) PushAllowedPorts(ctx context.Context, containerIP, toolboxToken string, ports []int) error {
	if containerIP == "" {
		return errors.New("container IP is empty")
	}
	if ports == nil {
		ports = []int{}
	}
	body, err := json.Marshal(map[string]any{"ports": ports})
	if err != nil {
		return fmt.Errorf("marshal ports: %w", err)
	}

	target := fmt.Sprintf("http://%s:%d/admin/allowed-ports", containerIP, c.toolboxPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if toolboxToken != "" {
		req.Header.Set("Authorization", "Bearer "+toolboxToken)
	}

	resp, err := c.toolboxClient.Do(req)
	if err != nil {
		return fmt.Errorf("push allowed ports: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("push allowed ports: status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) Inspect(ctx context.Context, containerRef string) (*SandboxRuntime, error) {
	inspect, err := c.inspectContainer(ctx, containerRef)
	if err != nil {
		return nil, fmt.Errorf("inspect container: %w", err)
	}
	return &SandboxRuntime{
		SandboxID:   sandboxIDFromContainerName(inspect.Name),
		ContainerID: inspect.ID,
		ContainerIP: getContainerIP(inspect, c.network),
		Status:      containerStatus(inspect),
	}, nil
}

func (c *Client) ListManaged(ctx context.Context) (map[string]*SandboxRuntime, error) {
	query := queryValues(map[string]string{"all": "1"})
	var containers []containerSummary
	err := c.doJSON(ctx, http.MethodGet, "/containers/json", query, nil, nil, &containers)
	if err != nil {
		return nil, fmt.Errorf("list managed containers: %w", err)
	}

	result := make(map[string]*SandboxRuntime, len(containers))
	for _, summary := range containers {
		if summary.Labels[managedLabelKey] != "true" {
			continue
		}
		inspect, err := c.inspectContainer(ctx, summary.ID)
		if err != nil {
			continue
		}
		runtime := &SandboxRuntime{
			SandboxID:   sandboxIDFromContainerName(inspect.Name),
			ContainerID: inspect.ID,
			ContainerIP: getContainerIP(inspect, c.network),
			Status:      containerStatus(inspect),
		}
		if runtime.SandboxID != "" {
			result[runtime.SandboxID] = runtime
		}
	}

	return result, nil
}

func (c *Client) ensureToolboxBinary() error {
	info, err := os.Stat(c.toolboxBinaryPath)
	if err != nil {
		return fmt.Errorf("toolbox binary not found at %s: %w", c.toolboxBinaryPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("toolbox binary path is a directory: %s", c.toolboxBinaryPath)
	}
	if !filepath.IsAbs(c.toolboxBinaryPath) {
		return fmt.Errorf("toolbox binary path must be absolute: %s", c.toolboxBinaryPath)
	}
	return nil
}

func (c *Client) pullImage(ctx context.Context, imageRef string, auth *models.RegistryAuth) error {
	headers := map[string]string{}
	if auth != nil && auth.Username != "" {
		encoded, err := json.Marshal(map[string]string{
			"username":      auth.Username,
			"password":      auth.Password,
			"serveraddress": auth.Server,
		})
		if err != nil {
			return fmt.Errorf("marshal registry auth: %w", err)
		}
		headers["X-Registry-Auth"] = base64.StdEncoding.EncodeToString(encoded)
	}

	query := queryValues(map[string]string{"fromImage": imageRef})
	response, err := c.doRequest(ctx, http.MethodPost, "/images/create", query, nil, headers)
	if err != nil {
		return fmt.Errorf("pull image: %w", err)
	}
	defer response.Body.Close()

	// Docker's /images/create streams NDJSON progress. Errors are reported in
	// the body (e.g. {"errorDetail":{"message":"manifest unknown"}}) with the
	// HTTP status still 200, so we have to scan the stream.
	decoder := json.NewDecoder(response.Body)
	for {
		var msg struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := decoder.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode pull stream: %w", err)
		}
		if msg.ErrorDetail.Message != "" {
			return fmt.Errorf("pull image %s: %s", imageRef, msg.ErrorDetail.Message)
		}
		if msg.Error != "" {
			return fmt.Errorf("pull image %s: %s", imageRef, msg.Error)
		}
	}
}

func (c *Client) waitForRuntime(ctx context.Context, containerRef string) (*SandboxRuntime, error) {
	deadline := time.Now().Add(c.waitTimeout)
	for time.Now().Before(deadline) {
		inspect, err := c.inspectContainer(ctx, containerRef)
		if err != nil {
			return nil, fmt.Errorf("inspect container: %w", err)
		}

		containerIP := getContainerIP(inspect, c.network)
		if inspect.State != nil && inspect.State.Running && containerIP != "" {
			if err := c.waitForToolbox(ctx, containerIP); err != nil {
				return nil, err
			}
			return &SandboxRuntime{
				SandboxID:   sandboxIDFromContainerName(inspect.Name),
				ContainerID: inspect.ID,
				ContainerIP: containerIP,
				Status:      models.SandboxStatusStarted,
			}, nil
		}

		time.Sleep(300 * time.Millisecond)
	}

	return nil, fmt.Errorf("timed out waiting for sandbox runtime: %s", containerRef)
}

func (c *Client) waitForToolbox(ctx context.Context, containerIP string) error {
	target := fmt.Sprintf("http://%s:%d/health", containerIP, c.toolboxPort)
	deadline := time.Now().Add(c.toolboxWaitTimeout)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return err
		}
		resp, err := c.toolboxClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("toolbox did not become healthy on %s", target)
}

func (c *Client) inspectContainer(ctx context.Context, id string) (containerInspect, error) {
	var inspect containerInspect
	err := c.doJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, nil, nil, &inspect)
	return inspect, err
}

func (c *Client) inspectImage(ctx context.Context, imageRef string) (imageInspect, error) {
	var inspect imageInspect
	err := c.doJSON(ctx, http.MethodGet, "/images/"+url.PathEscape(imageRef)+"/json", nil, nil, nil, &inspect)
	return inspect, err
}

func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, requestBody any, headers map[string]string, responseBody any) error {
	response, err := c.doRequest(ctx, method, path, query, requestBody, headers)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if responseBody == nil || response.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	return json.NewDecoder(response.Body).Decode(responseBody)
}

func (c *Client) doRequest(ctx context.Context, method, path string, query url.Values, requestBody any, headers map[string]string) (*http.Response, error) {
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}

	target := "http://docker" + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf("docker API %s %s failed with status %d: %s", method, path, response.StatusCode, strings.TrimSpace(string(data)))
	}
	return response, nil
}

func getContainerIP(inspect containerInspect, preferredNetwork string) string {
	if preferredNetwork != "" {
		if endpoint, ok := inspect.NetworkSettings.Networks[preferredNetwork]; ok && endpoint.IPAddress != "" {
			return endpoint.IPAddress
		}
	}

	for _, endpoint := range inspect.NetworkSettings.Networks {
		if endpoint.IPAddress != "" {
			return endpoint.IPAddress
		}
	}

	return ""
}

func containerStatus(inspect containerInspect) models.SandboxStatus {
	if inspect.State == nil {
		return models.SandboxStatusError
	}
	if inspect.State.Running {
		return models.SandboxStatusStarted
	}
	if inspect.State.Status == "exited" || inspect.State.Status == "created" {
		return models.SandboxStatusStopped
	}
	return models.SandboxStatusError
}

type imageInspect struct {
	Config struct {
		WorkingDir string   `json:"WorkingDir"`
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
	} `json:"Config"`
}

type containerInspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State *struct {
		Running bool   `json:"Running"`
		Status  string `json:"Status"`
	} `json:"State"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

type containerSummary struct {
	ID     string            `json:"Id"`
	Labels map[string]string `json:"Labels"`
}

func queryValues(values map[string]string) url.Values {
	if len(values) == 0 {
		return nil
	}
	query := url.Values{}
	for key, value := range values {
		query.Set(key, value)
	}
	return query
}

func (c *Client) removeContainer(ctx context.Context, containerRef string, force bool) error {
	query := url.Values{}
	if force {
		query.Set("force", "1")
	}
	return c.doJSON(ctx, http.MethodDelete, "/containers/"+url.PathEscape(containerRef), query, nil, nil, nil)
}

// sandboxIDFromContainerName extracts the sandbox ID from Docker's container
// name field. Docker stores names with a leading slash (e.g. "/abc123def456");
// we trim it. The sandbox ID is the canonical identifier we set as the
// container's name at create time.
func sandboxIDFromContainerName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "/")
	return name
}
