package agentmcp

import (
	"context"
	"errors"
	"flag"
	"io"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestStdioAndRemoteParsersAgree is the RT4 proof (required by CEO review
// CF1): every remote query parameter has a stdio flag of the same name, and
// the same input through either parser gives the same Options (Remote aside)
// or the same error naming the same option.
func TestStdioAndRemoteParsersAgree(t *testing.T) {
	cases := []map[string]string{
		{"sandbox": "my-agent"},
		{"sandbox": "my-agent", "create_if_missing": "true", "image": "python:3.12", "runtime": "wasm"},
		{"sandbox": "my-agent", "toolsets": "files,process", "read_only": "true"},
		{"sandbox": "my-agent", "toolsets": "all"},
		{"sandbox": "my-agent", "toolsets": "nope"},
		{"sandbox": "my-agent", "runtime": "isolate", "create_if_missing": "true"},
		{"sandbox": "sb-0123456789abcdef", "create_if_missing": "true"},
		{"sandbox": "my-agent", "image": "alpine"},
	}
	for _, c := range cases {
		q := url.Values{}
		var args []string
		for k, v := range c {
			q.Set(k, v)
			args = append(args, "--"+strings.ReplaceAll(k, "_", "-")+"="+v)
		}
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		parse := BindFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("%v: flags: %v", c, err)
		}
		stdio, stdioErr := parse()
		remote, remoteErr := ParseQuery(q)
		var se, re *OptionError
		if errors.As(stdioErr, &se) != errors.As(remoteErr, &re) {
			t.Fatalf("%v: stdio err %v, remote err %v", c, stdioErr, remoteErr)
		}
		if se != nil {
			if se.Param != re.Param {
				t.Fatalf("%v: stdio names %s, remote names %s", c, se.Param, re.Param)
			}
			continue
		}
		// Stdio-only knobs keep their flag defaults; compare the shared ones.
		remote.Remote = false
		stdioShared := Options{Sandbox: stdio.Sandbox, CreateIfMissing: stdio.CreateIfMissing, Image: stdio.Image, Runtime: stdio.Runtime, Toolsets: stdio.Toolsets, ReadOnly: stdio.ReadOnly}
		if !reflect.DeepEqual(stdioShared, remote) {
			t.Fatalf("%v:\nstdio  %+v\nremote %+v", c, stdioShared, remote)
		}
	}
	// Every remote parameter is also a flag.
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	BindFlags(fs)
	for _, p := range RemoteParams {
		if fs.Lookup(strings.ReplaceAll(p, "_", "-")) == nil {
			t.Fatalf("remote parameter %s has no stdio flag", p)
		}
	}
}

func TestParseQueryRejects(t *testing.T) {
	for raw, param := range map[string]string{
		"":                                 "sandbox",
		"sandbox=a&create-if-missing=true": "create-if-missing",
		"sandbox=a&ephemeral=true":         "ephemeral",
		"sandbox=a&sandbox=b":              "sandbox",
		"sandbox=a&read_only=maybe":        "read_only",
		"sandbox=a&create_if_missing=yes":  "create_if_missing",
		"sandbox=a&toolsets=core,shell":    "toolsets",
	} {
		q, _ := url.ParseQuery(raw)
		_, err := ParseQuery(q)
		var oe *OptionError
		if !errors.As(err, &oe) || oe.Param != param {
			t.Fatalf("ParseQuery(%q) = %v, want an error naming %s", raw, err, param)
		}
	}
	opts, err := ParseQuery(url.Values{"sandbox": {"a"}, "create_if_missing": {"1"}, "read_only": {"false"}})
	if err != nil || !opts.Remote || !opts.CreateIfMissing || opts.ReadOnly {
		t.Fatalf("ParseQuery = %+v, %v", opts, err)
	}
}

func TestInstrumentWrapsEveryCall(t *testing.T) {
	type call struct {
		tool, sandbox string
		err           error
	}
	var calls []call
	fake := newEnv(t, Options{}).fake
	tools, err := agenttools.New(agenttools.Config{APIURL: fake.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	fake.AddSandbox(models.Sandbox{Name: "box"})
	srv, err := New(tools, Options{Sandbox: "box", Remote: true}, "t", WithInstrument(func(ctx context.Context, tool string) (context.Context, func(string, error)) {
		return ctx, func(sandboxID string, err error) { calls = append(calls, call{tool, sandboxID, err}) }
	}))
	if err != nil {
		t.Fatal(err)
	}
	e := connectServer(t, srv)
	e.call("exec", map[string]any{"command": "echo"})
	e.call("read_file", map[string]any{"path": "/missing"})
	if len(calls) != 2 || calls[0].tool != "exec" || calls[0].sandbox == "" || calls[0].err != nil || calls[1].err == nil {
		t.Fatalf("instrumented calls = %+v", calls)
	}
}

func TestInputSchemaCacheIsCopyOnWrite(t *testing.T) {
	a := inputSchema[createIn]("sandbox_create")
	delete(a.Properties, "name")
	a.Properties["runtime"].Enum = []any{"x"}
	b := inputSchema[createIn]("sandbox_create")
	if _, ok := b.Properties["name"]; !ok || len(b.Properties["runtime"].Enum) != 0 {
		t.Fatal("editing one copy changed the cached schema")
	}
}
