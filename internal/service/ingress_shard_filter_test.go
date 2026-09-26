package service

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

type localIngressTopology struct {
	*cluster.Noop
	local        []cluster.Member
	membersCalls int
}

func (c *localIngressTopology) LocalMembers() []cluster.Member { return c.local }
func (c *localIngressTopology) Members() []cluster.Member      { c.membersCalls++; return c.Noop.Members() }

func TestIngressShardFilterPrefersGossipAndFallsBackAtBootstrap(t *testing.T) {
	c := &localIngressTopology{Noop: cluster.NewNoop("self", "http://self", ""), local: []cluster.Member{{NodeID: "self", Alive: true, Role: config.NodeRoleIngress}}}
	s := &Service{}
	for range 3 {
		s.clusterIngressShardFilter(c, "self")
	}
	if c.membersCalls != 0 {
		t.Fatal("steady-state filter requested control-plane membership")
	}
	c.local = nil
	s.clusterIngressShardFilter(c, "self")
	if c.membersCalls != 1 {
		t.Fatal("bootstrap did not fall back to control-plane membership")
	}
}
