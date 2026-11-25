package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"

	"github.com/aerol-ai/microvm/internal/rootd"
)

// agentFoldersCommand is the one-shot that gives the agent its folders
// (rootd.GiveToAgent). install.sh's privilege mode split unit runs it as
// root before every sandboxd start:
//
//	ExecStartPre=+/usr/local/lib/aerolvm-rootd/aerolvm-rootd agent-folders --user sandboxd
//
// The folders come from sandboxd's own settings, which that unit's
// environment holds (sandboxd.env and cluster.env); the user from the
// unit's command line.
const agentFoldersCommand = "agent-folders"

// giveToAgent is rootd.GiveToAgent; tests replace it.
var giveToAgent = rootd.GiveToAgent

// agentFoldersCode runs the one-shot and returns its exit code: 0 when every
// folder is the agent's, 1 when one could not be given, 2 for a usage
// error.
func agentFoldersCode(args []string, getenv func(string) string, stderr io.Writer) int {
	fs := flag.NewFlagSet("aerolvm-rootd agent-folders", flag.ContinueOnError)
	fs.SetOutput(stderr)
	who := fs.String("user", "", "the agent's user: a name or a uid")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "aerolvm-rootd agent-folders: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	f, err := rootd.AgentFoldersFromEnv(getenv, *who)
	if err != nil {
		log.Error("cannot give the agent its folders", "error", err)
		return 1
	}
	res, err := giveToAgent(f)
	if err != nil {
		log.Error("cannot give the agent its folders", "error", err, "changed_so_far", res.Changed)
		return 1
	}
	if res.ForgottenCaches > 0 {
		log.Info("removed the WASM compile caches privilege mode single left; split makes its own", "caches", res.ForgottenCaches,
			"cache_root", f.WasmCacheRoot)
	}
	for _, e := range res.CacheErrors {
		log.Warn("left a WASM compile cache privilege mode single made; its workers compile without it", "error", e)
	}
	// Quiet once there is nothing left to move: this runs at every start.
	if res.Changed > 0 || res.SkippedLinks > 0 {
		log.Info("gave root's files in the agent's folders to the agent", "uid", f.UID, "gid", f.GID,
			"changed", res.Changed, "walked", res.Walked, "left_with_a_second_name", res.SkippedLinks,
			"other_file_systems", res.SkippedMounts, "folders", f.Dirs)
	}
	return 0
}
