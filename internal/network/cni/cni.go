// Package cni wraps the bridge+host-local CNI plugin for containerd sandboxes.
// Our topology is a single bridge plugin with host-local IPAM embedded in its
// config, so ADD/DEL invoke that one plugin over the standard CNI exec protocol
// (CNI_* env vars + the plugin netconf on stdin) rather than chaining a plugin
// list. DEL is idempotent by the CNI contract (DEL on a missing allocation is a
// no-op); ADD is NOT idempotent at this layer — callers must not re-ADD the
// same container into the same netns or host-local allocates a second IP.
package cni

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Result is the subset of CNI ADD output the netns pool needs.
type Result struct {
	IP4 string
}

// Runner executes CNI ADD/DEL for a container in a network namespace.
type Runner interface {
	Add(ctx context.Context, netnsPath, containerID string) (Result, error)
	Del(ctx context.Context, netnsPath, containerID string) error
}

// Config locates plugin binaries and the bridge conf on disk.
type Config struct {
	// PluginDir is typically /opt/cni/bin.
	PluginDir string
	// ConfPath is a .conflist or .conf consumed by the plugin.
	ConfPath string
	// IfName is the interface created inside the netns; defaults to eth0.
	IfName string
}

// ExecRunner shells out to the CNI plugin binary referenced by ConfPath's
// `type`, speaking the CNI exec protocol.
type ExecRunner struct {
	cfg Config
}

func NewExecRunner(cfg Config) (*ExecRunner, error) {
	if strings.TrimSpace(cfg.PluginDir) == "" {
		return nil, errors.New("cni plugin dir is required")
	}
	if strings.TrimSpace(cfg.ConfPath) == "" {
		return nil, errors.New("cni conf path is required")
	}
	if strings.TrimSpace(cfg.IfName) == "" {
		cfg.IfName = "eth0"
	}
	return &ExecRunner{cfg: cfg}, nil
}

type cniAddResult struct {
	IPs []struct {
		Version string `json:"version"`
		Address string `json:"address"`
	} `json:"ips"`
}

func (r *ExecRunner) Add(ctx context.Context, netnsPath, containerID string) (Result, error) {
	netnsPath = strings.TrimSpace(netnsPath)
	containerID = strings.TrimSpace(containerID)
	if netnsPath == "" || containerID == "" {
		return Result{}, errors.New("cni add: netns path and container id are required")
	}
	out, err := r.runPlugin(ctx, "ADD", netnsPath, containerID)
	if err != nil {
		return Result{}, err
	}
	var parsed cniAddResult
	if err := json.Unmarshal(out, &parsed); err != nil {
		return Result{}, fmt.Errorf("decode cni add result: %w", err)
	}
	for _, ip := range parsed.IPs {
		if strings.Contains(ip.Address, ".") {
			addr, _, _ := strings.Cut(ip.Address, "/")
			return Result{IP4: addr}, nil
		}
	}
	return Result{}, errors.New("cni add: no ipv4 in result")
}

func (r *ExecRunner) Del(ctx context.Context, netnsPath, containerID string) error {
	netnsPath = strings.TrimSpace(netnsPath)
	containerID = strings.TrimSpace(containerID)
	if netnsPath == "" || containerID == "" {
		return nil
	}
	_, err := r.runPlugin(ctx, "DEL", netnsPath, containerID)
	return err
}

// runPlugin invokes the CNI plugin over the exec protocol: the operation and
// container identity go in CNI_* environment variables and the network config
// is piped on stdin (NOT positional argv, which real plugins ignore).
func (r *ExecRunner) runPlugin(ctx context.Context, cmd, netnsPath, containerID string) ([]byte, error) {
	plugin, netconf, err := r.resolve()
	if err != nil {
		return nil, err
	}
	ifName := strings.TrimSpace(r.cfg.IfName)
	if ifName == "" {
		ifName = "eth0"
	}
	cniArgs := fmt.Sprintf("K8S_POD_NAMESPACE=aerolvm;K8S_POD_NAME=%s;K8S_POD_INFRA_CONTAINER_ID=%s", containerID, containerID)
	invoke := exec.CommandContext(ctx, plugin)
	invoke.Stdin = bytes.NewReader(netconf)
	invoke.Env = append(os.Environ(),
		"CNI_COMMAND="+cmd,
		"CNI_CONTAINERID="+containerID,
		"CNI_NETNS="+netnsPath,
		"CNI_IFNAME="+ifName,
		"CNI_PATH="+r.cfg.PluginDir,
		"CNI_ARGS="+cniArgs,
	)
	var stdout, stderr bytes.Buffer
	invoke.Stdout = &stdout
	invoke.Stderr = &stderr
	if err := invoke.Run(); err != nil {
		// CNI plugins report failures as a JSON error object on STDOUT (and
		// commonly write nothing to stderr), so fall back to stdout or the real
		// cause is lost as a bare "exit status 1".
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		return nil, fmt.Errorf("cni %s %s: %w: %s", cmd, containerID, err, detail)
	}
	return stdout.Bytes(), nil
}

// resolve reads the netconf, reduces a .conflist to its single bridge plugin
// config (our topology embeds host-local IPAM inside the bridge plugin, so
// there is exactly one plugin to invoke), and locates that plugin's binary by
// its declared `type`.
func (r *ExecRunner) resolve() (plugin string, netconf []byte, err error) {
	raw, err := os.ReadFile(r.cfg.ConfPath)
	if err != nil {
		return "", nil, fmt.Errorf("read cni conf %q: %w", r.cfg.ConfPath, err)
	}
	netconf, err = singlePluginNetconf(raw)
	if err != nil {
		return "", nil, err
	}
	pluginType, err := netconfType(netconf)
	if err != nil {
		return "", nil, err
	}
	plugin = filepath.Join(r.cfg.PluginDir, pluginType)
	if _, err := os.Stat(plugin); err != nil {
		return "", nil, fmt.Errorf("cni plugin %q: %w", plugin, err)
	}
	return plugin, netconf, nil
}

// singlePluginNetconf returns the netconf to pipe to the plugin. For a
// .conflist it extracts plugins[0] and injects the list's cniVersion+name
// (each plugin config must carry them); a bare .conf is used as-is.
func singlePluginNetconf(raw []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("parse cni conf: %w", err)
	}
	plugins, ok := top["plugins"]
	if !ok {
		return raw, nil
	}
	var list []json.RawMessage
	if err := json.Unmarshal(plugins, &list); err != nil {
		return nil, fmt.Errorf("parse cni conflist plugins: %w", err)
	}
	if len(list) == 0 {
		return nil, errors.New("cni conflist has no plugins")
	}
	var plugin map[string]json.RawMessage
	if err := json.Unmarshal(list[0], &plugin); err != nil {
		return nil, fmt.Errorf("parse cni plugin[0]: %w", err)
	}
	if v, ok := top["cniVersion"]; ok {
		plugin["cniVersion"] = v
	}
	if n, ok := top["name"]; ok {
		plugin["name"] = n
	}
	return json.Marshal(plugin)
}

func netconfType(conf []byte) (string, error) {
	var m struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(conf, &m); err != nil {
		return "", fmt.Errorf("parse cni plugin type: %w", err)
	}
	if strings.TrimSpace(m.Type) == "" {
		return "", errors.New("cni plugin config has no type")
	}
	return m.Type, nil
}
