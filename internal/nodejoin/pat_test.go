package nodejoin

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

// A worker joined without the PAT: install.sh's random token stays its
// own, cluster.env gets the PAT's hash and the operator volume scope, the
// member wait uses its own token, and a re-run changes nothing.
func TestJoinWorkerWithoutThePAT(t *testing.T) {
	r := newJoinRig(t)
	r.srv.patFree = true
	tok := r.srv.token(cluster.JoinRoleWorker)
	if _, err := r.run(t, JoinOptions{Token: tok, CACertHash: cluster.CACertHash(r.srv.ca.Certificate())}); err != nil {
		t.Fatalf("join: %v\n%s", err, r.out.String())
	}
	env, _ := readEnvFile(r.paths.ClusterEnv)
	if env["SB_PAT_TOKEN_SHA256"] != config.PATSHA256("cluster-pat") || env["SB_OPERATOR_VOLUME_SCOPE"] != "op-cluster" {
		t.Fatalf("cluster.env = %v", env)
	}
	if base, _ := readEnvFile(r.paths.EnvFile); base["SB_PAT_TOKEN"] != "node-pat" {
		t.Fatalf("sandboxd.env SB_PAT_TOKEN = %q, want install.sh's own token kept", base["SB_PAT_TOKEN"])
	}
	if r.api.auth[len(r.api.auth)-1] != "Bearer node-pat" {
		t.Fatalf("member wait auth = %v", r.api.auth)
	}
	if !strings.Contains(r.out.String(), "does not hold the admin token, only a fingerprint (hash) to check it") {
		t.Fatalf("output:\n%s", r.out.String())
	}
	before, restarts := readFile(t, r.paths.ClusterEnv)+readFile(t, r.paths.EnvFile), r.host.restarts
	if _, err := r.run(t, JoinOptions{Token: tok}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, r.paths.ClusterEnv)+readFile(t, r.paths.EnvFile) != before || r.host.restarts != restarts {
		t.Fatal("a re-run without the PAT changed files or restarted sandboxd")
	}
}

// A worker that held the PAT (installed with --pat-token, or joined while
// the cluster still handed it out) gives it up on a join without it.
func TestJoinWithoutThePATReplacesAHeldPAT(t *testing.T) {
	r := newJoinRig(t)
	mustWrite(t, r.paths.EnvFile, strings.Replace(readFile(t, r.paths.EnvFile), "SB_PAT_TOKEN=node-pat", "SB_PAT_TOKEN=cluster-pat", 1))
	restore := newLocalToken
	t.Cleanup(func() { newLocalToken = restore })
	newLocalToken = func() (string, error) { return "fresh-local", nil }
	r.srv.patFree = true
	if _, err := r.run(t, JoinOptions{Token: r.srv.token(cluster.JoinRoleIngress), CACertHash: cluster.CACertHash(r.srv.ca.Certificate())}); err != nil {
		t.Fatalf("join: %v\n%s", err, r.out.String())
	}
	if base, _ := readEnvFile(r.paths.EnvFile); base["SB_PAT_TOKEN"] != "fresh-local" {
		t.Fatalf("sandboxd.env SB_PAT_TOKEN = %q, want the PAT replaced", base["SB_PAT_TOKEN"])
	}
	if r.api.auth[len(r.api.auth)-1] != "Bearer fresh-local" {
		t.Fatalf("member wait auth = %v", r.api.auth)
	}
}

// A server's answer carries the PAT: it is written and any hash line a
// past join left is dropped.
func TestJoinServerDropsAStalePATHash(t *testing.T) {
	r := newJoinRig(t)
	mustWrite(t, r.paths.ClusterEnv, "SB_PAT_TOKEN_SHA256="+config.PATSHA256("old")+"\n")
	r.srv.patFree = true
	if _, err := r.run(t, JoinOptions{Token: r.srv.token(cluster.JoinRoleServer), CACertHash: cluster.CACertHash(r.srv.ca.Certificate())}); err != nil {
		t.Fatalf("join: %v\n%s", err, r.out.String())
	}
	env, _ := readEnvFile(r.paths.ClusterEnv)
	base, _ := readEnvFile(r.paths.EnvFile)
	if _, ok := env["SB_PAT_TOKEN_SHA256"]; ok || base["SB_PAT_TOKEN"] != "cluster-pat" {
		t.Fatalf("cluster.env %v, sandboxd.env PAT %q", env, base["SB_PAT_TOKEN"])
	}
}

// joinPAT and patSettings, case by case.
func TestJoinPATRules(t *testing.T) {
	restore := newLocalToken
	t.Cleanup(func() { newLocalToken = restore })
	newLocalToken = func() (string, error) { return "fresh", nil }
	hashes := []string{config.PATSHA256("pat")}
	cases := []struct {
		name    string
		current string
		resp    cluster.JoinResponse
		want    string
		changed bool
		set     map[string]string
	}{
		{"the PAT, new", "local", cluster.JoinResponse{PATToken: "pat"}, "pat", true, map[string]string{"SB_PAT_TOKEN_SHA256": ""}},
		{"the PAT, already held", "pat", cluster.JoinResponse{PATToken: "pat"}, "pat", false, map[string]string{"SB_PAT_TOKEN_SHA256": ""}},
		{"hashes, own token kept", "local", cluster.JoinResponse{PATSHA256: hashes}, "local", false, map[string]string{"SB_PAT_TOKEN_SHA256": hashes[0]}},
		{"hashes, the PAT replaced", "pat", cluster.JoinResponse{PATSHA256: hashes, OperatorVolumeScope: "op-x"}, "fresh", true,
			map[string]string{"SB_PAT_TOKEN_SHA256": hashes[0], "SB_OPERATOR_VOLUME_SCOPE": "op-x"}},
		{"hashes, no token yet", "", cluster.JoinResponse{PATSHA256: hashes}, "fresh", true, map[string]string{"SB_PAT_TOKEN_SHA256": hashes[0]}},
		{"an older server sends neither", "local", cluster.JoinResponse{}, "local", false, map[string]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed, err := joinPAT(tc.current, tc.resp)
			if err != nil || got != tc.want || changed != tc.changed {
				t.Fatalf("joinPAT = %q %v %v, want %q %v", got, changed, err, tc.want, tc.changed)
			}
			var set envSet
			patSettings(&set, tc.resp)
			if !slices.Equal(set.keys, mapKeys(tc.set, set.keys)) {
				t.Fatalf("settings keys = %v, want %v", set.keys, tc.set)
			}
			for k, v := range tc.set {
				if set.values[k] != v {
					t.Fatalf("setting %s = %q, want %q", k, set.values[k], v)
				}
			}
		})
	}
	newLocalToken = func() (string, error) { return "", errors.New("no entropy") }
	if _, _, err := joinPAT("pat", cluster.JoinResponse{PATSHA256: hashes}); err == nil {
		t.Fatal("a failed token draw was not reported")
	}
	if tok, err := restore(); err != nil || len(tok) != 48 {
		t.Fatalf("a local token = %q %v, want 48 hex characters like install.sh's", tok, err)
	}
}

// mapKeys returns want's keys in the order got lists them, so a set
// with the same keys compares equal.
func mapKeys(want map[string]string, got []string) []string {
	out := []string{}
	for _, k := range got {
		if _, ok := want[k]; ok {
			out = append(out, k)
		}
	}
	if len(out) != len(want) {
		return append(out, "<missing>")
	}
	return out
}
