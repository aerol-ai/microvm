package docker

import (
	"context"

	"encoding/json"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"io"
	"net/http"
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
	name, gw, err := respond(`{"Id":"abc","IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}`).SandboxBridge(context.Background())
	if err != nil || name != "docker0" || gw.String() != "172.17.0.1" {
		t.Fatalf("default bridge = %s %s %v", name, gw, err)
	}
	c := respond(`{"Id":"0123456789abcdef","IPAM":{"Config":[{"Gateway":"fd00::1"},{"Gateway":"10.5.0.1"}]}}`)
	c.network = "aerolnet"
	name, gw, err = c.SandboxBridge(context.Background())
	if err != nil || name != "br-0123456789ab" || gw.String() != "10.5.0.1" {
		t.Fatalf("user network = %s %s %v", name, gw, err)
	}
	c = respond(`{"Id":"x","Options":{"com.docker.network.bridge.name":"sbx0"},"IPAM":{"Config":[]}}`)
	if name, _, err := c.SandboxBridge(context.Background()); err == nil || name != "sbx0" {
		t.Fatalf("no gateway: %s %v", name, err)
	}
	failing := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("x")), Header: make(http.Header)}, nil
	})}}
	if _, _, err := failing.SandboxBridge(context.Background()); err == nil {
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
