package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/egress/inspect"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// TLS inspection's node CA and the inspect create path (P3-1).

var inspectRules = []models.EgressRule{{Host: "api.example.org", Inspect: true, Methods: []string{"GET"}}}

func newInspectHarness(t *testing.T) (*Service, *fakeGateway, *policyRuntime) {
	t.Helper()
	svc, gw, rt := newPolicyHarness(t)
	svc.cfg.DBPath = filepath.Join(t.TempDir(), "state.db")
	return svc, gw, rt
}

func TestCreateWithInspectRules(t *testing.T) {
	svc, gw, rt := newInspectHarness(t)
	ctx := ownerCtx("acct")
	env := map[string]string{"PIP_CERT": "/mine.pem", "APP": "1"}
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", Env: env, NetworkAllowOut: []string{"api.example.org"}, NetworkEgressRules: inspectRules})
	if err != nil {
		t.Fatal(err)
	}
	// The gateway got the CA before any traffic, and it is a real CA.
	if len(gw.inspectCA) != 1 {
		t.Fatalf("CA pushes = %d", len(gw.inspectCA))
	}
	if _, err := inspect.New(gw.inspectCA[0].CertPEM, gw.inspectCA[0].KeyPEM, nil); err != nil {
		t.Fatalf("pushed CA: %v", err)
	}
	// The sandbox got the CA file, the bundle's tmpfs and the environment;
	// a variable the create set wins, and the caller's map is untouched.
	binds := rt.lastCreateMounts
	if !slices.ContainsFunc(binds, func(b mounts.ContainerBind) bool {
		return b.ContainerPath == inspectCAPath && b.ReadOnly && b.HostPath == svc.egressCACertPath()
	}) || !slices.ContainsFunc(binds, func(b mounts.ContainerBind) bool { return b.ContainerPath == inspectBundleDir && b.Tmpfs }) {
		t.Fatalf("mounts = %+v", binds)
	}
	got := rt.lastCreateReq.Env
	if got["SSL_CERT_FILE"] != inspectBundlePath || got["NODE_EXTRA_CA_CERTS"] != inspectCAPath || got["PIP_CERT"] != "/mine.pem" || got["APP"] != "1" {
		t.Fatalf("env = %v", got)
	}
	if _, set := env["SSL_CERT_FILE"]; set {
		t.Fatal("the caller's env map must not be modified")
	}
	if pem, err := os.ReadFile(svc.egressCACertPath()); err != nil || string(pem) != string(gw.inspectCA[0].CertPEM) {
		t.Fatalf("mounted CA file: %v", err)
	}
	if es, _ := svc.store.GetEgressState(ctx, resp.ID); !es.InspectCA {
		t.Fatal("inspect_ca must be recorded")
	}
	if spec := gw.attached[resp.ID]; len(spec.Rules) != 1 || !spec.Rules[0].Inspect {
		t.Fatalf("gateway rules = %+v", spec.Rules)
	}

	// A second create reuses the CA and doesn't push it again.
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"api.example.org"}, NetworkEgressRules: inspectRules}); err != nil {
		t.Fatal(err)
	}
	if len(gw.inspectCA) != 1 {
		t.Fatalf("CA pushed again: %d", len(gw.inspectCA))
	}
	// Adding more inspection to a sandbox that trusts the CA is fine.
	more := append(slices.Clone(inspectRules), models.EgressRule{Host: "api.example.org", Inspect: true, Methods: []string{"POST"}, Paths: []string{"/upload"}})
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"api.example.org"}, NetworkEgressRules: more}); err != nil {
		t.Fatalf("more inspection on a CA sandbox: %v", err)
	}
}

// TestEgressCAAcrossRestarts: the CA survives a sandboxd restart sealed,
// and a gateway that reconnects gets it again before its Sync.
func TestEgressCAAcrossRestarts(t *testing.T) {
	svc, gw, _ := newInspectHarness(t)
	if err := svc.resyncEgressCA(context.Background()); err != nil || len(gw.inspectCA) != 0 {
		t.Fatalf("a node that never inspected has nothing to send: %v %d", err, len(gw.inspectCA))
	}
	ca, err := svc.ensureEgressCA()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(svc.egressCADir(), "ca.json"))
	if len(raw) == 0 || strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("the key must be sealed at rest")
	}
	// A fresh process loads it.
	svc.egressCA.Store(nil)
	_ = os.Remove(svc.egressCACertPath())
	again, err := svc.ensureEgressCA()
	if err != nil || string(again.CertPEM) != string(ca.CertPEM) || string(again.KeyPEM) != string(ca.KeyPEM) {
		t.Fatalf("reload = %v", err)
	}
	if _, err := os.Stat(svc.egressCACertPath()); err != nil {
		t.Fatal("the mounted certificate must be rewritten on load")
	}
	// Gateway restart: the readiness latch drops and the next sync resends.
	svc.egressCAPushed.Store(true)
	svc.egressReady.Store(false)
	if err := svc.EnsureEgressGatewayReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(gw.inspectCA) != 1 {
		t.Fatalf("resync must resend the CA: %d", len(gw.inspectCA))
	}
}

// TestInspectFailsClosed: no cipher, a corrupt record, or a gateway that
// won't take the CA all refuse the create rather than run it unchecked.
func TestInspectCreateFailsClosed(t *testing.T) {
	ctx := ownerCtx("acct")
	req := models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"api.example.org"}, NetworkEgressRules: inspectRules}

	svc, gw, _ := newInspectHarness(t)
	gw.inspectErr = errors.New("gateway says no")
	if _, err := svc.CreateSandbox(ctx, req); !errors.Is(err, ErrEgressGatewayUnavailable) {
		t.Fatalf("push refused: %v", err)
	}

	svc, _, _ = newInspectHarness(t)
	svc.cipher = nil
	if _, err := svc.CreateSandbox(ctx, req); !errors.Is(err, ErrEgressGatewayUnavailable) {
		t.Fatalf("no cipher: %v", err)
	}

	svc, _, _ = newInspectHarness(t)
	if err := os.MkdirAll(svc.egressCADir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(svc.egressCADir(), "ca.json"), []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateSandbox(ctx, req); !errors.Is(err, ErrEgressGatewayUnavailable) {
		t.Fatalf("corrupt record: %v", err)
	}
	if err := svc.resyncEgressCA(ctx); err == nil {
		t.Fatal("a corrupt record must fail the resync")
	}
	if err := os.WriteFile(filepath.Join(svc.egressCADir(), "ca.json"), []byte(`{"cert_pem":"x","sealed_key":"AAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.loadEgressCA(); err == nil {
		t.Fatal("a key that won't open must fail")
	}
	svc.cipher = nil
	if _, _, err := svc.loadEgressCA(); err == nil {
		t.Fatal("no cipher, no key")
	}
}

var injectRules = []models.EgressRule{{Host: "api.example.org", Inspect: true, Paths: []string{"/repos/**"},
	Inject: &models.EgressInject{Header: "Authorization", SecretRef: "env:GITHUB_TOKEN"}}}

// TestCreateWithInjectRule (EF-54, P3-2): the sandbox holds a placeholder,
// the gateway the value; the withheld key is recorded; after a gateway
// restart the value comes back from the sealed env.
func TestCreateWithInjectRule(t *testing.T) {
	svc, gw, rt := newInspectHarness(t)
	ctx := ownerCtx("acct")
	env := map[string]string{"GITHUB_TOKEN": "Bearer ghp_real", "APP": "1"}
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", Env: env, NetworkAllowOut: []string{"api.example.org"}, NetworkEgressRules: injectRules})
	if err != nil {
		t.Fatal(err)
	}
	if got := rt.lastCreateReq.Env["GITHUB_TOKEN"]; got != "aerolvm-placeholder:GITHUB_TOKEN" || rt.lastCreateReq.Env["APP"] != "1" {
		t.Fatalf("sandbox env = %v", rt.lastCreateReq.Env)
	}
	if env["GITHUB_TOKEN"] != "Bearer ghp_real" {
		t.Fatal("the caller's env must keep the value")
	}
	if got := gw.attached[resp.ID].Secrets["GITHUB_TOKEN"]; got != "Bearer ghp_real" {
		t.Fatalf("gateway secret = %q", got)
	}
	if es, _ := svc.store.GetEgressState(ctx, resp.ID); !slices.Equal(es.Withheld, []string{"GITHUB_TOKEN"}) {
		t.Fatalf("withheld = %v", es.Withheld)
	}
	specs, err := svc.localEgressSpecs(context.Background())
	if err != nil || len(specs) != 1 || specs[0].Secrets["GITHUB_TOKEN"] != "Bearer ghp_real" {
		t.Fatalf("resync specs = %+v %v", specs, err)
	}

	// Live: keeping the withheld key is fine and re-reads the sealed env; a
	// key the sandbox holds in clear is 409.
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"api.example.org"}, NetworkEgressRules: append(slices.Clone(injectRules),
		models.EgressRule{Host: "api.example.org", Inspect: true, Methods: []string{"GET"}})}); err != nil {
		t.Fatal(err)
	}
	if got := gw.attached[resp.ID].Secrets["GITHUB_TOKEN"]; got != "Bearer ghp_real" {
		t.Fatalf("secret after PUT = %q", got)
	}
	clear := []models.EgressRule{{Host: "api.example.org", Inspect: true, Inject: &models.EgressInject{Header: "X-Key", SecretRef: "env:APP"}}}
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"api.example.org"}, NetworkEgressRules: clear}); !errors.Is(err, ErrEgressInjectRecreate) {
		t.Fatalf("inject a key held in clear: %v", err)
	}

	// The key must be in the create's env.
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"api.example.org"}, NetworkEgressRules: injectRules}); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("missing env key: %v", err)
	}
}

// TestIsolateInject: an isolate never sees its env, so nothing is withheld;
// the host gets the value from the sealed env, which must hold the key.
func TestIsolateInject(t *testing.T) {
	svc, _, _ := newInspectHarness(t)
	iso := newMediator()
	svc.isolate = iso
	svc.cfg.EgressFQDNEnabled = false
	ctx := context.Background()
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-iso", Runtime: models.RuntimeIsolate, AuditIncarnationID: "inc-iso"})
	req := models.NetworkPolicyRequest{NetworkAllowOut: []string{"api.example.org"}, NetworkEgressRules: injectRules}
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-iso", req); err == nil {
		t.Fatal("no sealed env with the key: refused")
	}
	row, _ := svc.store.Get(ctx, "sb-iso")
	putEnv := func(env map[string]string) {
		t.Helper()
		sealed, err := svc.sealEnv(row.ID, row.AuditIncarnationID, env)
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.store.PutEnv(ctx, row.ID, sealed); err != nil {
			t.Fatal(err)
		}
	}
	putEnv(map[string]string{"GITHUB_TOKEN": "Bearer iso"})
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-iso", req); err != nil {
		t.Fatal(err)
	}
	if got := iso.secrets["sb-iso"]["GITHUB_TOKEN"]; got != "Bearer iso" {
		t.Fatalf("isolate secret = %q", got)
	}
	putEnv(map[string]string{"OTHER": "x"})
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-iso", models.NetworkPolicyRequest{NetworkAllowOut: []string{"api.example.org"}, NetworkEgressRules: injectRules}); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("key gone from the env: %v", err)
	}
	// An unreadable env leaves the value out: the host refuses those
	// requests rather than send the placeholder.
	if got := svc.egressSecrets(ctx, &models.Sandbox{ID: "missing", NetworkEgressRules: injectRules}); len(got) != 0 {
		t.Fatalf("secrets for an unreadable env = %v", got)
	}
}

// TestEgressSpecReplication: a live policy change replicates every egress
// field, and an env key withheld for an inject rule stays withheld after
// the rule is removed, through the spec a failover replays (P3-2).
func TestEgressSpecReplication(t *testing.T) {
	svc, _, rt := newInspectHarness(t)
	ctx := ownerCtx("acct")
	env := map[string]string{"GITHUB_TOKEN": "Bearer ghp_real"}
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", Env: env, NetworkAllowOut: []string{"api.example.org"}, NetworkEgressRules: injectRules})
	if err != nil {
		t.Fatal(err)
	}
	putProfile(t, svc, ctx, "extra", "pypi.org")
	stub := &specWriteThroughCluster{Noop: cluster.NewNoop("self", "http://self", ""), spec: &models.CreateSandboxRequest{Image: "alpine", Env: env,
		NetworkAllowOut: []string{"api.example.org"}, NetworkEgressRules: injectRules}}
	svc.AttachCluster(stub)
	plain := []models.EgressRule{{Host: "api.example.org", Inspect: true, Methods: []string{"GET"}}}
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"api.example.org"},
		EgressProfiles: []string{"extra"}, NetworkEgressRules: plain}); err != nil {
		t.Fatal(err)
	}
	calls := stub.calls()
	if len(calls) != 1 {
		t.Fatalf("replicated specs = %d", len(calls))
	}
	spec := calls[0]
	if !slices.Equal(spec.EgressProfiles, []string{"extra"}) || len(spec.NetworkEgressRules) != 1 || spec.NetworkEgressRules[0].Inject != nil ||
		!slices.Equal(spec.EgressWithheldEnv, []string{"GITHUB_TOKEN"}) {
		t.Fatalf("replicated spec = %+v", spec)
	}

	// The failover replay of that spec: the key is still a placeholder.
	svc.AttachCluster(nil)
	replay := spec
	replay.Env = env
	if _, err := svc.CreateSandboxWithID(contextWithStoredSpecReplay(ctx), replay, "sb-recreated"); err != nil {
		t.Fatal(err)
	}
	if got := rt.lastCreateReq.Env["GITHUB_TOKEN"]; got != "aerolvm-placeholder:GITHUB_TOKEN" {
		t.Fatalf("recreated sandbox env = %q", got)
	}
	if es, _ := svc.store.GetEgressState(ctx, "sb-recreated"); !slices.Equal(es.Withheld, []string{"GITHUB_TOKEN"}) {
		t.Fatalf("withheld on the new node = %v", es.Withheld)
	}
	row, _ := svc.store.Get(ctx, "sb-recreated")
	if got, err := svc.specFromSandbox(ctx, row); err != nil || !slices.Equal(got.EgressWithheldEnv, []string{"GITHUB_TOKEN"}) {
		t.Fatalf("ownership replay spec = %+v %v", got, err)
	}
	if got := withholdEnv(nil, []string{"MISSING"}); len(got) != 0 {
		t.Fatalf("a key the env lacks is not invented: %v", got)
	}
}
