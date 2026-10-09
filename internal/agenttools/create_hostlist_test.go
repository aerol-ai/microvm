package agenttools

import (
	"flag"
	"io"
	"slices"
	"testing"
)

// TestHostListFlag: repeated flags and comma lists parse to the same list,
// and String prints it back in the comma form a client config carries.
func TestHostListFlag(t *testing.T) {
	var hosts HostList
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(&hosts, "allow-host", "")
	if err := fs.Parse([]string{"--allow-host", "pypi.org", "--allow-host", " github.com , ,*.npmjs.org:443,"}); err != nil {
		t.Fatal(err)
	}
	want := HostList{"pypi.org", "github.com", "*.npmjs.org:443"}
	if !slices.Equal(hosts, want) {
		t.Fatalf("hosts = %q", hosts)
	}
	if got := hosts.String(); got != "pypi.org,github.com,*.npmjs.org:443" {
		t.Fatalf("String() = %q", got)
	}
	var back HostList
	if err := back.Set(hosts.String()); err != nil || !slices.Equal(back, want) {
		t.Fatalf("round trip = %q %v", back, err)
	}
}
