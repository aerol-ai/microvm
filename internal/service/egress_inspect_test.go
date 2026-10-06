package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/egress/inspect"
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
