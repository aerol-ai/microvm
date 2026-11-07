package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/version"
)

// `sandboxd version` says which build is installed
// (plans/kubectl-style-cluster-ops.md §3.1, Phase 0). Before it existed,
// `sandboxd --version` fell through to the daemon boot, so Ansible's
// update-sandboxd.yml started a second daemon on a live node's state
// directory every time it asked. It reads nothing but the binary itself:
// no env file, no database, no network.
const versionSubcommand = "version"

// isVersionArg reports whether arg asks for the version. The flag spellings
// are there because they are what operators and tools type first.
func isVersionArg(arg string) bool {
	switch arg {
	case versionSubcommand, "--version", "-version", "-v":
		return true
	}
	return false
}

// buildInfo is what `sandboxd version -o json` prints. fsm_ops_version is
// the cluster op set this build applies: two builds with the same release
// tag but different values cannot both lead a rolling upgrade safely, so it
// is printed beside the tag.
type buildInfo struct {
	Version       string `json:"version"`
	Commit        string `json:"commit,omitempty"`
	FSMOpsVersion int    `json:"fsm_ops_version"`
	GoVersion     string `json:"go_version"`
	Platform      string `json:"platform"`
}

// readBuildInfo is debug.ReadBuildInfo; tests replace it.
var readBuildInfo = debug.ReadBuildInfo

func currentBuildInfo() buildInfo {
	return buildInfo{
		Version:       version.Version,
		Commit:        buildCommit(),
		FSMOpsVersion: cluster.FSMOpsVersion(),
		GoVersion:     runtime.Version(),
		Platform:      runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// buildCommit is the VCS revision the go tool stamped into the binary. The
// release builds from a git checkout, so it is there; a build from a
// source tarball, or with -buildvcs=false, has none and prints no commit.
func buildCommit() string {
	info, ok := readBuildInfo()
	if !ok {
		return ""
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev != "" && dirty {
		rev += "-dirty"
	}
	return rev
}

const versionUsage = `usage: sandboxd version [-o text|json]
       sandboxd --version

Prints this binary's release version, commit, the cluster FSM op version it
applies, and its Go version and platform. It never starts the daemon.
`

// runVersionCLI runs `sandboxd version` with the args after it.
func runVersionCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("sandboxd version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	output := fs.String("o", "text", "output format: text or json")
	fs.StringVar(output, "output", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(out, versionUsage)
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	info := currentBuildInfo()
	switch *output {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	case "text":
		// The first line is "sandboxd <version>" alone, so a script can
		// take the version with `head -n1` without parsing the rest.
		fmt.Fprintf(out, "sandboxd %s\n", info.Version)
		if info.Commit != "" {
			fmt.Fprintf(out, "commit:          %s\n", info.Commit)
		}
		fmt.Fprintf(out, "fsm ops version: %d\n", info.FSMOpsVersion)
		fmt.Fprintf(out, "go:              %s\n", info.GoVersion)
		fmt.Fprintf(out, "platform:        %s\n", info.Platform)
		return nil
	default:
		return fmt.Errorf("-o must be text or json, got %q", *output)
	}
}
