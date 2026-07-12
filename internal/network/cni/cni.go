// Package cni wraps the bridge+host-local CNI plugin pair for containerd
// sandboxes. ADD/DEL are idempotent at the call-site: Del on a missing
// allocation is a no-op; Add on an already-configured netns returns the
// existing result when the fake/production runner detects prior state.
package cni

import (
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

// Config locates plugin binaries and the bridge conflist on disk.
type Config struct {
	// PluginDir is typically /opt/cni/bin.
	PluginDir string
	// ConfPath is a .conflist or .conf consumed by the plugins.
	ConfPath string
}

// ExecRunner shells out to the CNI plugin binaries referenced by ConfPath.
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
			addr := strings.Split(ip.Address, "/")[0]
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

func (r *ExecRunner) runPlugin(ctx context.Context, cmd, netnsPath, containerID string) ([]byte, error) {
	plugin, conf, err := r.resolve(cmd)
	if err != nil {
		return nil, err
	}
	cniArgs := fmt.Sprintf("K8S_POD_NAMESPACE=aerolvm;K8S_POD_NAME=%s;K8S_POD_INFRA_CONTAINER_ID=%s", containerID, containerID)
	invoke := exec.CommandContext(ctx, plugin,
		cmd,
		conf,
		netnsPath,
		containerID,
		"IGNORED",
		"IGNORED",
		cniArgs,
	)
	invoke.Env = append(os.Environ(), "CNI_PATH="+r.cfg.PluginDir)
	out, err := invoke.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("cni %s %s: %w: %s", cmd, containerID, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (r *ExecRunner) resolve(cmd string) (plugin string, conf string, err error) {
	conf = r.cfg.ConfPath
	base := filepath.Base(conf)
	switch {
	case strings.HasSuffix(base, ".conflist"), strings.HasSuffix(base, ".conf"):
		// bridge plugin is the conventional first hop for our topology.
		plugin = filepath.Join(r.cfg.PluginDir, "bridge")
	default:
		return "", "", fmt.Errorf("unsupported cni conf %q", conf)
	}
	if _, err := os.Stat(plugin); err != nil {
		return "", "", fmt.Errorf("cni plugin %q: %w", plugin, err)
	}
	if _, err := os.Stat(conf); err != nil {
		return "", "", fmt.Errorf("cni conf %q: %w", conf, err)
	}
	_ = cmd
	return plugin, conf, nil
}
