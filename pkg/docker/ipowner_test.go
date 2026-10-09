package docker

import (
	"context"

	"encoding/json"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestIPOwner(t *testing.T) {
	networks := map[string]any{"Containers": map[string]any{
		"c1": map[string]string{"Name": "sb-live", "IPv4Address": "172.17.0.2/16"},
		"c2": map[string]string{"Name": netnsAdoptedPrefix + "sb-adopted", "IPv4Address": "172.17.0.3/16"},
		"c3": map[string]string{"Name": netnsFreePrefix + "7", "IPv4Address": "172.17.0.4/16"},
		"c4": map[string]string{"Name": "park-0011223344556677", "IPv4Address": "172.17.0.5/16"},
	}}
	var gotPath string
	c := &Client{network: "", httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotPath = r.URL.Path
		payload, _ := json.Marshal(networks)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(payload))), Header: make(http.Header)}, nil
	})}}
	cases := map[string]string{
		"172.17.0.2": "sb-live",
		"172.17.0.3": "sb-adopted",
		"172.17.0.4": "",
		"172.17.0.5": "",
		"172.17.0.9": "",
	}
	for ip, want := range cases {
		got, err := c.IPOwner(context.Background(), ip)
		if err != nil || got != want {
			t.Fatalf("IPOwner(%s) = %q, %v; want %q", ip, got, err, want)
		}
	}
	if gotPath != "/networks/bridge" {
		t.Fatalf("default network path = %q", gotPath)
	}
	c.network = "aerolnet"
	if _, err := c.IPOwner(context.Background(), "172.17.0.2"); err != nil || gotPath != "/networks/aerolnet" {
		t.Fatalf("custom network path = %q err=%v", gotPath, err)
	}
	failing := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("boom")), Header: make(http.Header)}, nil
	})}}
	if _, err := failing.IPOwner(context.Background(), "172.17.0.2"); err == nil {
		t.Fatal("want error from failing dockerd")
	}
}

func TestSandboxBridge(t *testing.T) {
	respond := func(body string) *Client {
		return &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}}
	}
	sn, err := respond(`{"Id":"abc","IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}`).SandboxBridge(context.Background())
	if err != nil || sn.Name != "docker0" || sn.Gateway.String() != "172.17.0.1" || sn.Subnet.String() != "172.17.0.0/16" {
		t.Fatalf("default bridge = %+v %v", sn, err)
	}
	c := respond(`{"Id":"0123456789abcdef","IPAM":{"Config":[{"Gateway":"fd00::1"},{"Gateway":"10.5.0.1"}]}}`)
	c.network = "aerolnet"
	sn, err = c.SandboxBridge(context.Background())
	if err != nil || sn.Name != "br-0123456789ab" || sn.Gateway.String() != "10.5.0.1" || sn.Subnet.IsValid() {
		t.Fatalf("user network = %+v %v", sn, err)
	}
	c = respond(`{"Id":"x","Options":{"com.docker.network.bridge.name":"sbx0"},"IPAM":{"Config":[]}}`)
	if sn, err := c.SandboxBridge(context.Background()); err == nil || sn.Name != "sbx0" {
		t.Fatalf("no gateway: %+v %v", sn, err)
	}
	failing := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("x")), Header: make(http.Header)}, nil
	})}}
	if _, err := failing.SandboxBridge(context.Background()); err == nil {
		t.Fatal("dockerd error must surface")
	}
}

func TestEgressHoldDisabledRules(t *testing.T) {
	rules, err := netrules.New(false)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{networkRules: rules}
	if c.ApplyEgressHold("10.0.0.1") != nil || c.ClearEgressHold("10.0.0.1") != nil {
		t.Fatal("disabled rules: hold is a no-op")
	}
}

func TestSetEgressFloorDisabledRules(t *testing.T) {
	rules, err := netrules.New(false)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{networkRules: rules}
	if err := c.SetEgressFloor(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}); err != nil {
		t.Fatal("disabled rules: the floor is a no-op")
	}
}

type floorRecorder struct {
	rules   []string
	flushed int
}

func (f *floorRecorder) Exists(string, string, ...string) (bool, error) { return false, nil }
func (f *floorRecorder) Insert(_, chain string, _ int, spec ...string) error {
	f.rules = append(f.rules, chain+" "+strings.Join(spec, " "))
	return nil
}
func (f *floorRecorder) Delete(string, string, ...string) error { return nil }
func (f *floorRecorder) EnsureJumpChain(string, string) error   { return nil }
func (f *floorRecorder) FlushChain(string) error                { f.flushed++; f.rules = nil; return nil }

// TestSetEgressFloorUsesTheSandboxSubnet: the floor is scoped to the
// sandbox network's subnet as dockerd reports it.
func TestSetEgressFloorUsesTheSandboxSubnet(t *testing.T) {
	be := &floorRecorder{}
	c := &Client{networkRules: netrules.NewWithBackend(be), httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"Id":"abc","IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}`))}, nil
	})}}
	if err := c.SetEgressFloor(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if be.flushed != 1 || len(be.rules) != 1 || !strings.Contains(be.rules[0], "-s 172.17.0.0/16 -d 10.20.0.0/16 -j DROP") {
		t.Fatalf("floor = %v", be.rules)
	}
	failing := &Client{networkRules: netrules.NewWithBackend(be), httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("x")), Header: make(http.Header)}, nil
	})}}
	if err := failing.SetEgressFloor(context.Background(), nil); err == nil {
		t.Fatal("bridge discovery errors surface")
	}
}
