package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/release"
)

func planHarness(t *testing.T, cluster bool, running string) (*harness, *fakeUpgrade, *fakeReleases) {
	r := newFakeReleases(t)
	publishStd(r)
	f := newFakeUpgrade(t, cluster, running)
	h := upgradeHarness(t, f)
	h.env["AEROLVM_RELEASE_URL"] = r.base()
	return h, f, r
}

func TestUpgradePlanCluster(t *testing.T) {
	h, f, _ := planHarness(t, true, "v0.6.12")
	stdFleet(f, "v0.6.12")
	// wkr-2 is down; wkr-3 already runs the target; the leader is srv-a.
	f.members[5]["alive"] = false
	f.members[6]["version"] = "v0.6.13"
	f.members = append(f.members, map[string]any{"node_id": "wkr-4", "role": "worker", "alive": true, "version": "v0.6.12"},
		map[string]any{"node_id": "wkr-5", "role": "worker", "alive": true, "version": "v0.6.12"})
	for _, tc := range []struct {
		args   []string
		golden string
	}{
		{[]string{"upgrade", "plan", "v0.6.13", "--batch", "2", "--pause-after", "1"}, "plan-cluster.golden"},
		{[]string{"upgrade", "plan", "v0.6.13", "-o", "json"}, "plan-cluster-json.golden"},
		{[]string{"upgrade", "plan", "v0.6.13", "--output", "yaml", "--arch", "amd64"}, "plan-cluster-yaml.golden"},
	} {
		code := h.run(tc.args...)
		if code != exitOK {
			t.Fatalf("%v = %d %s", tc.args, code, h.stderr.String())
		}
		checkGoldenIn(t, "upgrade", tc.golden, h.cleanTranscript(code, h.env["AEROLVM_RELEASE_URL"], "<releases>"))
	}
	var p upgradePlan
	if code := h.run("upgrade", "plan", "v0.6.13", "--json"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	h.jsonOut(&p)
	// The leader goes last of the servers; workers in batches of 10%, at least 1.
	order := map[string]int{}
	for _, n := range p.Nodes {
		order[n.NodeID] = n.Order
	}
	if order["srv-a"] != 3 || order["srv-b"] != 1 || order["ing-1"] != 4 || order["wkr-2"] != 0 || order["wkr-3"] != 0 || p.BatchSize != 1 ||
		p.HostSetup != "changes" || p.EgressGateway != "stays up" || p.RollbackAfterFinalize || p.OneWayMigrations[0] != 7 || !p.Allowed {
		t.Fatalf("plan = %+v", p)
	}
}

func TestUpgradePlanSingleNodeAndRefusals(t *testing.T) {
	h, _, r := planHarness(t, false, "v0.6.12")
	code := h.run("upgrade", "plan", "v0.6.13")
	if code != exitOK {
		t.Fatal(h.stderr.String())
	}
	checkGoldenIn(t, "upgrade", "plan-single.golden", h.cleanTranscript(code, h.env["AEROLVM_RELEASE_URL"], "<releases>"))

	// A node three releases back: refused, with the releases to step
	// through (v0.6.11 has no release.json, so the walk stops there).
	r.publish("v0.6.14", releaseFiles("v0.6.14", releaseMeta("v0.6.14", "v0.6.13", "install-13", []int{2}), "amd64"), true)
	h2, _, _ := planHarness(t, false, "v0.6.10")
	h2.env["AEROLVM_RELEASE_URL"] = r.base()
	code = h2.run("upgrade", "plan", "v0.6.14")
	if code != exitError {
		t.Fatalf("skew = %d", code)
	}
	checkGoldenIn(t, "upgrade", "plan-skew.golden", h2.cleanTranscript(code, r.base(), "<releases>"))

	// A downgrade is a rollback, not an apply.
	h3, _, _ := planHarness(t, false, "v0.6.13")
	if code := h3.run("upgrade", "plan", "v0.6.12"); code != exitError || !strings.Contains(h3.stdout.String(), "going back is: aerolvm upgrade rollback") {
		t.Fatalf("downgrade = %d %q", code, h3.stdout.String())
	}
	// Already on the target: nothing to do.
	if code := h3.run("upgrade", "plan", "v0.6.13"); code != exitOK || !strings.Contains(h3.stdout.String(), "skip: already on the target") ||
		!strings.Contains(h3.stdout.String(), "nothing to do") {
		t.Fatalf("on target = %d %q", code, h3.stdout.String())
	}
}

func TestUpgradePlanNeedsNetworkAndUnversioned(t *testing.T) {
	h, f, r := planHarness(t, true, "v0.6.12")
	f.members = []map[string]any{{"node_id": "only", "role": "server", "alive": true, "version": "v0.6.12", "voter": true, "leader": true}}
	m := releaseMeta("v0.6.13", "v0.6.12", "install-13", []int{1})
	m.HostSetupNeedsNetwork = true
	r.publish("v0.6.13", releaseFiles("v0.6.13", m, "amd64"), true)
	out := filepath.Join(t.TempDir(), "b.tgz")
	if code := h.run("release", "pull", "v0.6.13", "-o", out); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	// From the release URL it is fine; from a bundle it is refused.
	if code := h.run("upgrade", "plan", "v0.6.13"); code != exitOK || !strings.Contains(h.stdout.String(), "needs packages or network access") ||
		!strings.Contains(h.stdout.String(), "one Raft server") {
		t.Fatalf("online = %d %q", code, h.stdout.String())
	}
	if code := h.run("upgrade", "plan", "v0.6.13", "--from", out); code != exitError || !strings.Contains(h.stdout.String(), "can't be applied from --from or a bundle") {
		t.Fatalf("bundle = %d %q", code, h.stdout.String())
	}
	if code := h.run("upgrade", "apply", "v0.6.13", "--from", out); code != exitError || !strings.Contains(h.stderr.String(), "host_setup") && !strings.Contains(h.stderr.String(), "can't be applied from --from") {
		t.Fatalf("apply bundle = %d %q", code, h.stderr.String())
	}
	if f.sawCall("POST /v1/cluster/upgrade") != 0 {
		t.Fatal("apply sent a refused bundle")
	}
	// A dev build: no release.json, versions can't be ordered.
	dir, _ := distDir(t, "itest-abc-b", false)
	f.members[0]["version"] = "itest-abc"
	if code := h.run("upgrade", "plan", "itest-abc-b", "--from", dir); code != exitUsage {
		t.Fatal("an unversioned target without the flag")
	}
	if code := h.run("upgrade", "plan", "itest-abc-b", "--from", dir, "--allow-unversioned"); code != exitOK ||
		!strings.Contains(h.stdout.String(), "has no release.json") || !strings.Contains(h.stdout.String(), "can't be checked for itest-abc") {
		t.Fatalf("dev build = %d %q", code, h.stdout.String())
	}
	// Two of three servers down: no server can restart.
	f.members = []map[string]any{
		{"node_id": "s1", "role": "server", "alive": true, "version": "v0.6.12", "voter": true, "leader": true},
		{"node_id": "s2", "role": "server", "alive": false, "version": "v0.6.12", "voter": true},
		{"node_id": "s3", "alive": true, "version": "v0.6.12", "voter": true},
	}
	if code := h.run("upgrade", "plan", "v0.6.13"); code != exitOK || !strings.Contains(h.stdout.String(), "1 of 3 Raft servers are down") ||
		!strings.Contains(h.stdout.String(), " mixed ") {
		t.Fatalf("quorum = %d %q", code, h.stdout.String())
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"upgrade", "plan"}, exitUsage, "plan needs one version"},
		{[]string{"upgrade", "plan", "v0.6.13", "--batch", "0"}, exitUsage, "would never upgrade"},
		{[]string{"upgrade", "plan", "v0.6.13", "--pause-after", "-2"}, exitUsage, "must not be negative"},
		{[]string{"upgrade", "plan", "v0.6.13", "-o", "wide"}, exitUsage, "-o must be json or yaml"},
		{[]string{"upgrade", "plan", "v0.6.13", "--arch", "A"}, exitUsage, "not a CPU type"},
		{[]string{"upgrade", "plan", "v0.6.13", "--nope"}, exitUsage, "nope"},
		{[]string{"upgrade", "plan", "v9.9.9"}, exitError, "not published"},
	} {
		if code := h.run(tc.args...); code != tc.code || !strings.Contains(h.stderr.String(), tc.want) {
			t.Errorf("%v = %d %q", tc.args, code, h.stderr.String())
		}
	}
	// The members route failing ends plan.
	f.members = nil
	f.noRoutes = false
	if code := h.run("upgrade", "plan", "v0.6.13", "--json"); code != exitOK {
		t.Fatalf("empty fleet = %d %s", code, h.stderr.String())
	}
	var p upgradePlan
	if err := json.Unmarshal([]byte(h.stdout.String()), &p); err != nil || len(p.Nodes) != 0 {
		t.Fatalf("empty plan = %+v", p)
	}
}

type metaMap map[string]*release.Metadata

func (m metaMap) meta(_ context.Context, version, _ string) (*release.Metadata, error) {
	if v, ok := m[version]; ok {
		return v, nil
	}
	return nil, errors.New("offline")
}

func TestStepChain(t *testing.T) {
	ms := metaMap{
		"v0.8.0":  releaseMeta("v0.8.0", "v0.7.0", "x", []int{1}),
		"v0.7.0":  releaseMeta("v0.7.0", "v0.6.12", "x", []int{1}),
		"v0.6.12": releaseMeta("v0.6.12", "v0.6.11", "x", []int{1}),
	}
	target := releaseMeta("v0.9.0", "v0.8.0", "x", []int{1})
	if got := strings.Join(stepChain(context.Background(), ms, target, "v0.6.11"), ","); got != "v0.6.12,v0.7.0,v0.8.0" {
		t.Fatalf("chain = %s", got)
	}
	if got := strings.Join(stepChain(context.Background(), ms, target, "v0.7.5"), ","); got != "v0.8.0" {
		t.Fatalf("short chain = %s", got)
	}
	// A loop in the metadata does not spin.
	loop := metaMap{"v1.0.0": releaseMeta("v1.0.0", "v1.0.0", "x", []int{1})}
	if got := stepChain(context.Background(), loop, releaseMeta("v2.0.0", "v1.0.0", "x", []int{1}), "v0.1.0"); len(got) != 1 {
		t.Fatalf("loop = %v", got)
	}
	if lowest([]string{"v0.6.12", "v0.6.9", "v0.7.0"}) != "v0.6.9" {
		t.Fatal("lowest")
	}
	if tierOf("") != tierServers || tierOf("mixed") != tierServers || tierOf("ingress") != tierIngress {
		t.Fatal("tierOf")
	}
}
