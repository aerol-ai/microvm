package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootd"
)

// TestAgentFoldersCode: the one-shot sandboxd.service runs as root before
// sandboxd starts (M1 PR 10). The walk itself is internal/rootd's; here
// are the command line, the folders it names and its exit codes.
func TestAgentFoldersCode(t *testing.T) {
	var got rootd.AgentFolders
	giveToAgent = func(f rootd.AgentFolders) (rootd.AgentFolderResult, error) {
		got = f
		return rootd.AgentFolderResult{Changed: 3, Walked: 9}, nil
	}
	t.Cleanup(func() { giveToAgent = rootd.GiveToAgent })
	env := map[string]string{"SB_CLUSTER_TLS_DIR": "/etc/sandboxd/tls"}
	getenv := func(k string) string { return env[k] }

	for _, tc := range []struct {
		name string
		args []string
		code int
		out  string
	}{
		{"gives the folders", []string{"--user", "65531"}, 0, "changed=3"},
		{"no user", nil, 1, "name the agent's user"},
		{"root", []string{"--user", "0"}, 1, "must not be root"},
		{"a stray argument", []string{"--user", "65531", "now"}, 2, "unexpected argument"},
		{"an unknown flag", []string{"--uid", "1"}, 2, "flag provided but not defined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := agentFoldersCode(tc.args, getenv, &out); code != tc.code {
				t.Fatalf("code %d, want %d: %s", code, tc.code, out.String())
			}
			if !strings.Contains(out.String(), tc.out) {
				t.Fatalf("output %q, want %q", out.String(), tc.out)
			}
		})
	}
	if strings.Join(got.Dirs, ",") != "/etc/sandboxd/cluster-ca,/etc/sandboxd/tls,/run/sandboxd,/var/lib/sandboxd" || got.UID != 65531 {
		t.Fatalf("walked %+v", got)
	}

	// A walk that fails fails the unit's start, and sandboxd with it.
	giveToAgent = func(rootd.AgentFolders) (rootd.AgentFolderResult, error) {
		return rootd.AgentFolderResult{Changed: 1}, errors.New("chown: read-only file system")
	}
	var out bytes.Buffer
	if code := agentFoldersCode([]string{"--user", "65531"}, getenv, &out); code != 1 || !strings.Contains(out.String(), "read-only") {
		t.Fatalf("code %d: %s", code, out.String())
	}
	// Nothing left to move: nothing said.
	giveToAgent = func(rootd.AgentFolders) (rootd.AgentFolderResult, error) {
		return rootd.AgentFolderResult{Walked: 4}, nil
	}
	out.Reset()
	if code := agentFoldersCode([]string{"--user", "65531"}, getenv, &out); code != 0 || out.Len() != 0 {
		t.Fatalf("code %d: %q", code, out.String())
	}
}
