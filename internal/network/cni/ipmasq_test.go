package cni

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Golden values computed outside Go (python hashlib.sha512) to pin parity
// with containernetworking/plugins pkg/utils FormatChainName: if these drift,
// the teardown would look for a chain the bridge plugin never created.
func TestIPMasqChainMatchesBridgePlugin(t *testing.T) {
	for _, tc := range []struct{ network, id, want string }{
		{"aerolvm", "aerol-netns-0", "CNI-4406104858726949999988fc"},
		{"aerolvm", "sb-0123456789abcdef", "CNI-a40dcffee60f47a8f5830653"},
	} {
		if got := IPMasqChain(tc.network, tc.id); got != tc.want {
			t.Fatalf("IPMasqChain(%q, %q) = %q, want %q", tc.network, tc.id, got, tc.want)
		}
	}
	if got := IPMasqComment("aerolvm", "aerol-netns-0"); got != `name: "aerolvm" id: "aerol-netns-0"` {
		t.Fatalf("comment = %s", got)
	}
}

// fakeNAT is an in-memory nat table: chains plus POSTROUTING rules in
// `iptables -S` form.
type fakeNAT struct {
	chains      map[string]bool
	postrouting []string
	deleted     [][]string
	cleared     []string

	existsErr, listErr, deleteErr, clearErr error
}

func (f *fakeNAT) ChainExists(_, chain string) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}
	return f.chains[chain], nil
}

func (f *fakeNAT) List(_, _ string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]string{"-P POSTROUTING ACCEPT"}, f.postrouting...), nil
}

func (f *fakeNAT) Delete(_, _ string, rulespec ...string) error {
	f.deleted = append(f.deleted, rulespec)
	return f.deleteErr
}

func (f *fakeNAT) ClearAndDeleteChain(_, chain string) error {
	if f.clearErr != nil {
		return f.clearErr
	}
	f.cleared = append(f.cleared, chain)
	delete(f.chains, chain)
	return nil
}

func masqRule(src, chain, id string) string {
	return `-A POSTROUTING -s ` + src + ` -m comment --comment "name: \"aerolvm\" id: \"` + id + `\"" -j ` + chain
}

// The teardown deletes only this container's POSTROUTING jumps (every
// source, so a leftover from an earlier ADD of the same id goes too) and its
// chain, never another container's.
func TestTeardownIPMasqDeletesOnlyThisContainersRules(t *testing.T) {
	mine := IPMasqChain("aerolvm", "aerol-netns-3")
	other := IPMasqChain("aerolvm", "aerol-netns-4")
	nat := &fakeNAT{
		chains: map[string]bool{mine: true, other: true},
		postrouting: []string{
			masqRule("10.88.0.9/32", mine, "aerol-netns-3"),
			masqRule("10.88.0.10/32", other, "aerol-netns-4"),
			masqRule("10.88.0.30/32", mine, "aerol-netns-3"),
			"-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE",
		},
	}
	if err := teardownIPMasq(nat, "aerolvm", "aerol-netns-3"); err != nil {
		t.Fatal(err)
	}
	comment := `name: "aerolvm" id: "aerol-netns-3"`
	want := [][]string{
		{"-s", "10.88.0.9/32", "-j", mine, "-m", "comment", "--comment", comment},
		{"-s", "10.88.0.30/32", "-j", mine, "-m", "comment", "--comment", comment},
	}
	if !reflect.DeepEqual(nat.deleted, want) {
		t.Fatalf("deleted %v, want %v", nat.deleted, want)
	}
	if !reflect.DeepEqual(nat.cleared, []string{mine}) || !nat.chains[other] {
		t.Fatalf("cleared %v (other chain kept: %v)", nat.cleared, nat.chains[other])
	}
}

// The runc fast path: the plugin's own DEL already removed the chain, so the
// teardown costs one existence check and touches nothing.
func TestTeardownIPMasqNoChainIsNoop(t *testing.T) {
	nat := &fakeNAT{chains: map[string]bool{}}
	if err := teardownIPMasq(nat, "aerolvm", "sb-x"); err != nil {
		t.Fatal(err)
	}
	if len(nat.deleted) != 0 || len(nat.cleared) != 0 {
		t.Fatalf("touched rules: deleted=%v cleared=%v", nat.deleted, nat.cleared)
	}
}

func TestTeardownIPMasqErrors(t *testing.T) {
	chain := IPMasqChain("aerolvm", "sb-x")
	rule := masqRule("10.88.0.2/32", chain, "sb-x")
	for _, tc := range []struct {
		name string
		nat  *fakeNAT
		want string
	}{
		{"exists check", &fakeNAT{existsErr: errors.New("xtables lock")}, "xtables lock"},
		{"list", &fakeNAT{chains: map[string]bool{chain: true}, listErr: errors.New("list boom")}, "list boom"},
		{"delete", &fakeNAT{chains: map[string]bool{chain: true}, postrouting: []string{rule}, deleteErr: errors.New("delete boom")}, "delete boom"},
		{"chain", &fakeNAT{chains: map[string]bool{chain: true}, clearErr: errors.New("Too many links")}, "Too many links"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := teardownIPMasq(tc.nat, "aerolvm", "sb-x")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want %q", err, tc.want)
			}
		})
	}
	// "already gone" answers are success.
	gone := &fakeNAT{chains: map[string]bool{chain: true}, postrouting: []string{rule},
		deleteErr: errors.New("iptables: Bad rule (does a matching rule exist in that chain?)."),
		clearErr:  errors.New("iptables: No chain/target/match by that name.")}
	if err := teardownIPMasq(gone, "aerolvm", "sb-x"); err != nil {
		t.Fatalf("not-exist answers must be ignored: %v", err)
	}
}

func TestMasqJumpSource(t *testing.T) {
	chain := IPMasqChain("aerolvm", "sb-x")
	if src, ok := masqJumpSource(masqRule("10.88.0.2/32", chain, "sb-x"), chain); !ok || src != "10.88.0.2/32" {
		t.Fatalf("src=%q ok=%v", src, ok)
	}
	for _, rule := range []string{
		"-P POSTROUTING ACCEPT",
		masqRule("10.88.0.2/32", IPMasqChain("aerolvm", "sb-y"), "sb-y"),
		"-A POSTROUTING -m comment --comment x -j " + chain, // no -s
	} {
		if _, ok := masqJumpSource(rule, chain); ok {
			t.Fatalf("matched %q", rule)
		}
	}
}

func writeConf(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "net.conflist")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExecRunnerTeardownIPMasq(t *testing.T) {
	ctx := context.Background()
	body, err := RenderBridgeConflist(ConflistOptions{})
	if err != nil {
		t.Fatal(err)
	}
	chain := IPMasqChain("aerolvm", "aerol-netns-0")
	nat := &fakeNAT{chains: map[string]bool{chain: true}, postrouting: []string{masqRule("10.88.0.2/32", chain, "aerol-netns-0")}}
	builds := 0
	orig := newNATTable
	newNATTable = func() (natTable, error) { builds++; return nat, nil }
	t.Cleanup(func() { newNATTable = orig })

	r := &ExecRunner{cfg: Config{ConfPath: writeConf(t, string(body))}}
	if err := r.TeardownIPMasq(ctx, "aerol-netns-0", "10.88.0.2"); err != nil {
		t.Fatal(err)
	}
	if len(nat.deleted) != 1 || len(nat.cleared) != 1 {
		t.Fatalf("deleted=%v cleared=%v", nat.deleted, nat.cleared)
	}
	if err := r.TeardownIPMasq(ctx, "aerol-netns-0", "10.88.0.2"); err != nil {
		t.Fatalf("second teardown must be a no-op: %v", err)
	}
	if builds != 1 {
		t.Fatalf("iptables handle built %d times, want once", builds)
	}
	if err := r.TeardownIPMasq(ctx, " ", ""); err != nil {
		t.Fatalf("empty id: %v", err)
	}
}

func TestExecRunnerTeardownIPMasqConfigCases(t *testing.T) {
	ctx := context.Background()
	orig := newNATTable
	t.Cleanup(func() { newNATTable = orig })
	newNATTable = func() (natTable, error) { t.Fatal("must not touch iptables"); return nil, nil }

	noMasq := &ExecRunner{cfg: Config{ConfPath: writeConf(t, `{"cniVersion":"1.0.0","name":"n","plugins":[{"type":"bridge","ipMasq":false}]}`)}}
	if err := noMasq.TeardownIPMasq(ctx, "sb-x", ""); err != nil {
		t.Fatalf("ipMasq=false must be a no-op: %v", err)
	}
	missing := &ExecRunner{cfg: Config{ConfPath: filepath.Join(t.TempDir(), "absent.conflist")}}
	if err := missing.TeardownIPMasq(ctx, "sb-x", ""); err == nil {
		t.Fatal("want missing-conf error")
	}
	bad := &ExecRunner{cfg: Config{ConfPath: writeConf(t, `{`)}}
	if err := bad.TeardownIPMasq(ctx, "sb-x", ""); err == nil {
		t.Fatal("want parse error")
	}
	badPlugin := &ExecRunner{cfg: Config{ConfPath: writeConf(t, `{"name":"n","plugins":["x"]}`)}}
	if err := badPlugin.TeardownIPMasq(ctx, "sb-x", ""); err == nil {
		t.Fatal("want plugin parse error")
	}
	badField := &ExecRunner{cfg: Config{ConfPath: writeConf(t, `{"name":"n","type":"bridge","ipMasq":"yes"}`)}}
	if err := badField.TeardownIPMasq(ctx, "sb-x", ""); err == nil {
		t.Fatal("want field type error")
	}
}

// A failed iptables handle is retried on the next teardown, not cached.
func TestExecRunnerTeardownIPMasqHandleError(t *testing.T) {
	body, _ := RenderBridgeConflist(ConflistOptions{})
	r := &ExecRunner{cfg: Config{ConfPath: writeConf(t, string(body))}}
	orig := newNATTable
	t.Cleanup(func() { newNATTable = orig })
	newNATTable = func() (natTable, error) { return nil, errors.New("iptables not found") }
	if err := r.TeardownIPMasq(context.Background(), "sb-x", ""); err == nil || !strings.Contains(err.Error(), "iptables not found") {
		t.Fatalf("err=%v", err)
	}
	newNATTable = func() (natTable, error) { return &fakeNAT{chains: map[string]bool{}}, nil }
	if err := r.TeardownIPMasq(context.Background(), "sb-x", ""); err != nil {
		t.Fatalf("retry after a failed handle: %v", err)
	}
}

func TestFakeRunnerMasqTeardown(t *testing.T) {
	f := NewFakeRunner()
	var _ IPMasqTeardown = f
	var _ IPMasqTeardown = (*ExecRunner)(nil)
	if err := f.TeardownIPMasq(context.Background(), "sb-x", "10.88.0.2"); err != nil {
		t.Fatal(err)
	}
	if got := f.MasqTeardowns(); len(got) != 1 || got[0] != (MasqCall{ContainerID: "sb-x", ContainerIP: "10.88.0.2"}) {
		t.Fatalf("got %+v", got)
	}
	f.SetMasqError(errors.New("boom"))
	if err := f.TeardownIPMasq(context.Background(), "sb-y", ""); err == nil {
		t.Fatal("want error")
	}
}
