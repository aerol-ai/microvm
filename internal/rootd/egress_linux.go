//go:build linux

package rootd

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"strconv"
	"sync"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/procid"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// kernelEgress is the helper's EgressHost: the probe network sandboxd
// builds in single mode (egress.NewProbeNet), and procfs.
type kernelEgress struct {
	pn  egress.ProbeNet
	res procid.Resolver

	mu   sync.Mutex
	envs map[int]egress.ProbeEnv
}

func newEgressHost() EgressHost {
	return &kernelEgress{pn: egress.NewProbeNet(), envs: map[int]egress.ProbeEnv{}}
}

func (k *kernelEgress) ProbeSetup(ctx context.Context, slot int, bridge string, gateway netip.Addr, subnet netip.Prefix) (bool, error, error) {
	// A slot set up again replaces what it had (a self-test cut short).
	_ = k.ProbeClose(slot)
	env, err := k.pn.Setup(ctx, egress.Bridge{Name: bridge, GatewayIP: gateway, Subnet: subnet}, egress.ProbeSource(slot), slot)
	switch {
	case errors.Is(err, egress.ErrBridgeAbsent):
		return true, nil, nil
	case errors.Is(err, egress.ErrSelfTest):
		return false, err, nil
	case err != nil:
		return false, nil, err
	}
	k.mu.Lock()
	k.envs[slot] = env
	k.mu.Unlock()
	return false, nil, nil
}

func (k *kernelEgress) ProbeSend(ctx context.Context, slot int) error {
	k.mu.Lock()
	env := k.envs[slot]
	k.mu.Unlock()
	if env == nil {
		return errors.New("no probe network for this slot; set it up first")
	}
	return env.Send(ctx)
}

func (k *kernelEgress) ProbeClose(slot int) error {
	k.mu.Lock()
	env := k.envs[slot]
	delete(k.envs, slot)
	k.mu.Unlock()
	if env == nil {
		return nil
	}
	return env.Close()
}

func (k *kernelEgress) ProcCgroup(pid int) (string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if errors.Is(err, fs.ErrNotExist) {
		return "", errProcessGone
	}
	return string(b), err
}

func (k *kernelEgress) Match(m rootpolicy.ProcessMatch) ([]string, bool, error) {
	is, err := k.res.Matcher(m.PID, m.Local, m.Remote)
	if errors.Is(err, procid.ErrNotFound) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	var matched []string
	for _, p := range m.Paths {
		if is(p) {
			matched = append(matched, p)
		}
	}
	return matched, false, nil
}
