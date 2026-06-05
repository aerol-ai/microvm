package cluster

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCustomDomains(t *testing.T) {
	c := &Cluster{}
	c.fsm = newPlacementFSM()
	c.fsm.recoveryStore = newPlacementRecoveryMemoryStore()

	// 0% functions
	c.RemoveCustomDomain(context.Background(), "", "")
	c.AddCustomDomain(context.Background(), "", "")
	if len(c.CustomDomainsOf("sb1")) != 0 {
		t.Errorf("expected 0")
	}
	_, ok := c.ResolveCustomDomain("foo.com")
	if ok {
		t.Errorf("expected false")
	}
}

func TestIngressTargets(t *testing.T) {
	c := &Cluster{}
	it := c.IngressTargets()
	if it.Source != models.IngressTargetSourceUnknown {
		t.Errorf("expected unknown source")
	}

	c.gossip = &gossipNode{
		memberIndex: &gossipMemberIndex{
			members: map[string]Member{
				"node1": {NodeID: "node1", Alive: true, Role: "ingress", PublicHost: "host1"},
			},
		},
	}
	it2 := c.IngressTargets()
	if it2.Source != models.IngressTargetSourceHostname {
		t.Errorf("expected hostname source")
	}
}

func TestSetLocalTemplateIDsProvider(t *testing.T) {
	c := &Cluster{}
	// nil capacityLeases should not panic
	c.SetLocalTemplateIDsProvider(func() ([]string, bool) { return nil, false })
}

func TestHealthyForReads(t *testing.T) {
	c := &Cluster{}
	if c.HealthyForReads() {
		t.Errorf("expected false without raft")
	}
}

func TestDoLeaderApply(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := &Cluster{}
	err := c.doLeaderApply(context.Background(), ts.Client(), ts.URL, []byte("payload"))
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("too many"))
	}))
	defer ts2.Close()

	err = c.doLeaderApply(context.Background(), ts2.Client(), ts2.URL, []byte("payload"))
	if err == nil {
		t.Errorf("expected error")
	}

	ts3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(ErrCapacityExceeded.Error()))
	}))
	defer ts3.Close()

	err = c.doLeaderApply(context.Background(), ts3.Client(), ts3.URL, []byte("payload"))
	if err == nil {
		t.Errorf("expected error")
	}

	ts4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(ErrNoPlacementTarget.Error()))
	}))
	defer ts4.Close()

	err = c.doLeaderApply(context.Background(), ts4.Client(), ts4.URL, []byte("payload"))
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestClientNilChecks(t *testing.T) {
	c := &Cluster{}
	if c.IsNodeDrained("node1") {
		t.Errorf("expected false")
	}
	if c.Members() != nil {
		t.Errorf("expected nil members")
	}
	if len(c.Placements()) != 0 {
		t.Errorf("expected 0")
	}
	if len(c.PlacementsForShards(PlacementShardFilter{})) != 0 {
		t.Errorf("expected 0")
	}
	if c.PlacementPage(PlacementPageRequest{}).NextPageToken != "" {
		t.Errorf("expected empty token")
	}
	_, ok := c.PlacementOf("sb1")
	if ok {
		t.Errorf("expected false")
	}
	if c.PlacementVersion() != 0 {
		t.Errorf("expected 0")
	}
	if c.SubscribePlacement(context.Background()) != nil {
		t.Errorf("expected nil")
	}
}
