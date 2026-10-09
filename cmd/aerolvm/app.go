package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/internal/version"
)

// Exit codes (§5.2 rule 5). exec passes the remote command's code through
// and uses execFailure for its own failures; every other verb uses
// exitOK / exitError / exitUsage.
const (
	exitOK      = 0
	exitError   = 1
	exitUsage   = 2
	execFailure = 125
)

// app holds the process's I/O so tests drive the CLI in-process.
type app struct {
	stdin       io.Reader
	stdout      io.Writer
	stderr      io.Writer
	getenv      func(string) string
	stdinIsTTY  bool
	stdoutIsTTY bool
	term        terminal
	// notifySignals returns a context cancelled by SIGINT/SIGTERM and the
	// signal that cancelled it.
	notifySignals func(context.Context) (context.Context, func() os.Signal, func())
	newTools      func(agenttools.Config) (*agenttools.Tools, error)
}

func newApp() *app {
	return &app{
		stdin:         os.Stdin,
		stdout:        os.Stdout,
		stderr:        os.Stderr,
		getenv:        os.Getenv,
		stdinIsTTY:    isTerminal(os.Stdin),
		stdoutIsTTY:   isTerminal(os.Stdout),
		term:          osTerminal{},
		notifySignals: notifyInterrupts,
		newTools:      agenttools.New,
	}
}

type verb struct {
	name    string
	summary string
	help    string
	run     func(ctx context.Context, a *app, args []string) int
}

// verbGroup is a heading in the overview.
type verbGroup struct {
	title string
	verbs []verb
}

// verbGroups orders the overview by what people open the CLI for: getting
// into a sandbox they already have comes first, managing sandboxes second.
func (a *app) verbGroups() []verbGroup {
	return []verbGroup{
		{"Work in a sandbox", []verb{
			{"shell", "Open an interactive shell in a sandbox", shellHelp, runShell},
			{"exec", "Run a command in a sandbox", execHelp, runExec},
			{"cp", "Copy a file between this machine and a sandbox", cpHelp, runCp},
			{"ls", "List a directory in a sandbox", lsHelp, runLs},
			{"logs", "Print a background command's output", logsHelp, runLogs},
			{"expose", "Publish a sandbox port and print its URL", exposeHelp, runExpose},
		}},
		{"Manage sandboxes", []verb{
			{"list", "List sandboxes", listHelp, runList},
			{"get", "Show one sandbox", getHelp, runGet},
			{"create", "Create a sandbox, or return the existing one with that name", createHelp, runCreate},
			{"start", "Start stopped sandboxes", startHelp, runStart},
			{"stop", "Stop sandboxes (files are kept)", stopHelp, runStop},
			{"destroy", "Destroy sandboxes", destroyHelp, runDestroy},
			{"snapshot", "Snapshot a sandbox as a reusable image", snapshotHelp, runSnapshot},
		}},
		{"Setup", []verb{
			{"health", "Check that sandboxd is reachable", healthHelp, runHealth},
			{"version", "Print the aerolvm version", versionHelp, runVersion},
			{"mcp", "Run the MCP server over stdio, or print client setup", mcpHelp, runMCP},
		}},
	}
}

func (a *app) verbs() []verb {
	var all []verb
	for _, g := range a.verbGroups() {
		all = append(all, g.verbs...)
	}
	return all
}

func (a *app) run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, a.overview())
		return exitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		if len(args) > 1 && args[0] == "help" {
			for _, v := range a.verbs() {
				if v.name == args[1] {
					fmt.Fprint(a.stdout, v.help)
					return exitOK
				}
			}
		}
		fmt.Fprint(a.stdout, a.overview())
		return exitOK
	case "--version":
		return runVersion(ctx, a, nil)
	}
	for _, v := range a.verbs() {
		if v.name == args[0] {
			for _, arg := range args[1:] {
				if arg == "--" {
					break
				}
				if arg == "-h" || arg == "--help" {
					fmt.Fprint(a.stdout, v.help)
					return exitOK
				}
			}
			return v.run(ctx, a, args[1:])
		}
	}
	fmt.Fprintf(a.stderr, "aerolvm: unknown command %q\n\n%s", args[0], a.overview())
	return exitUsage
}

func (a *app) overview() string {
	var b strings.Builder
	b.WriteString(overviewHead)
	for _, g := range a.verbGroups() {
		fmt.Fprintf(&b, "\n%s:\n", g.title)
		for _, v := range g.verbs {
			fmt.Fprintf(&b, "  %-9s %s\n", v.name, v.summary)
		}
	}
	b.WriteString(overviewTail)
	return b.String()
}

// commonFlags are on every verb.
type commonFlags struct {
	json  bool
	debug bool
}

func (a *app) newFlagSet(name string) (*flag.FlagSet, *commonFlags) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	c := &commonFlags{}
	jsonDefault := strings.EqualFold(strings.TrimSpace(a.getenv("AEROLVM_OUTPUT")), "json")
	fs.BoolVar(&c.json, "json", jsonDefault, "print JSON on stdout (default when AEROLVM_OUTPUT=json)")
	fs.BoolVar(&c.debug, "debug", false, "log API requests to stderr (the token is redacted)")
	return fs, c
}

// parseArgs parses flags anywhere among the positional arguments, the way
// agents write commands ("exec sb --cwd /app -- make"). Everything after the
// first bare "--" is returned as rest, never parsed as flags.
func parseArgs(fs *flag.FlagSet, args []string) (positional, rest []string, err error) {
	for i, arg := range args {
		if arg == "--" {
			rest = append([]string{}, args[i+1:]...)
			args = args[:i]
			break
		}
	}
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	return positional, rest, nil
}

// usageError prints a usage problem and returns exit code 2.
func (a *app) usageError(c *commonFlags, verbName, format string, args ...any) int {
	msg := fmt.Sprintf(format, args...)
	if c != nil && c.json {
		a.writeErrorJSON(&agenttools.Error{Code: "usage", Message: msg, Hint: "run `aerolvm " + verbName + " --help`"})
	} else {
		fmt.Fprintf(a.stderr, "aerolvm %s: %s\nrun `aerolvm %s --help` for usage\n", verbName, msg, verbName)
	}
	return exitUsage
}

// flagError maps a flag-parse failure onto a usage error.
func (a *app) flagError(c *commonFlags, verbName string, err error) int {
	return a.usageError(c, verbName, "%s", strings.TrimPrefix(err.Error(), "flag provided but not defined: "))
}

// fail reports err and returns code. With --json the error envelope goes to
// stderr: {"error":{"code","message","http_status","retryable","hint"}}.
func (a *app) fail(c *commonFlags, err error, code int) int {
	e := agenttools.Classify(err)
	if c != nil && c.json {
		a.writeErrorJSON(e)
	} else {
		fmt.Fprintf(a.stderr, "aerolvm: %s\n", e.Message)
		if e.Hint != "" {
			fmt.Fprintf(a.stderr, "hint: %s\n", e.Hint)
		}
	}
	return code
}

func (a *app) writeErrorJSON(e *agenttools.Error) {
	enc := json.NewEncoder(a.stderr)
	_ = enc.Encode(map[string]any{"error": e})
}

func (a *app) printJSON(v any) {
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	// Output goes to shells, jq and models, never into HTML: keep "&&" and
	// "<token>" readable instead of \u0026 and \u003c.
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// note writes a human notice to stderr; stdout stays data-only.
func (a *app) note(format string, args ...any) {
	fmt.Fprintf(a.stderr, format+"\n", args...)
}

// tools builds the agenttools layer for a CLI verb.
func (a *app) tools(c *commonFlags) (*agenttools.Tools, error) {
	cfg := agenttools.Config{
		APIURL: a.getenv("SB_API_URL"),
		Token:  a.getenv("SB_PAT_TOKEN"),
		Source: agenttools.SourceCLI,
		Warn:   func(s string) { a.note("aerolvm: %s", s) },
	}
	if c != nil && c.debug {
		cfg.HTTPClient = debugHTTPClient(a.stderr)
	}
	return a.newTools(cfg)
}

// kvList is a repeatable K=V flag.
type kvList map[string]string

func (l kvList) String() string {
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+l[k])
	}
	return strings.Join(parts, ",")
}

func (l kvList) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || strings.TrimSpace(k) == "" {
		return fmt.Errorf("expected KEY=VALUE, got %q", s)
	}
	l[strings.TrimSpace(k)] = v
	return nil
}

func (l kvList) orNil() map[string]string {
	if len(l) == 0 {
		return nil
	}
	return l
}

// notifyInterrupts cancels ctx on SIGINT or SIGTERM and reports which one.
func notifyInterrupts(ctx context.Context) (context.Context, func() os.Signal, func()) {
	ctx, cancel := context.WithCancel(ctx)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	var got os.Signal
	done := make(chan struct{})
	go func() {
		select {
		case got = <-ch:
			cancel()
		case <-done:
		}
	}()
	stop := func() {
		signal.Stop(ch)
		close(done)
		cancel()
	}
	return ctx, func() os.Signal { return got }, stop
}

// signalExit is the conventional 128+n exit code for a local signal.
func signalExit(sig os.Signal) int {
	if s, ok := sig.(syscall.Signal); ok {
		return 128 + int(s)
	}
	return execFailure
}

func versionString() string { return version.Version }
