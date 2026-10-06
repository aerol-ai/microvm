package microvm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestClientAndSandboxWrappers(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	var policyBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes":
			_ = json.NewEncoder(w).Encode([]models.Sandbox{{ID: "sb1", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/mounts":
			_ = json.NewEncoder(w).Encode(map[string]any{"mounts": []models.MountSpecRedacted{{Type: models.MountTypeS3, Target: "/workspace", Source: "bucket/path"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/network/policy/check":
			var req models.NetworkPolicyCheckRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(models.NetworkPolicyCheckResponse{Allowed: req.Destination == "api.github.com", MatchedRule: "*.github.com", DefaultVerdict: "deny"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/audit":
			q := r.URL.Query()
			if q.Get("kind") != "egress" || q.Get("limit") != "50" || q.Get("cursor") != "c1" || q.Get("incarnation_id") != "inc-1" {
				http.Error(w, "bad query "+r.URL.RawQuery, http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"events":[{"time":"2026-10-06T10:00:00Z","kind":"egress","result":"failure","reason":"host_not_allowed","destination":"evil.example:443","event_id":"ae-1"}],"coverage":{"answered":["n1"],"missing":[],"partial":false},"next_cursor":"c2"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/network/usage":
			_ = json.NewEncoder(w).Encode(models.NetworkUsage{SandboxID: "sb1", BytesIn: 10, BytesOut: 20})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/sandboxes/sb1/network/policy":
			policyBody, _ = io.ReadAll(r.Body)
			var req models.NetworkPolicyRequest
			_ = json.Unmarshal(policyBody, &req)
			_ = json.NewEncoder(w).Encode(models.NetworkPolicy{NetworkBlockAll: req.NetworkBlockAll, NetworkAllowOut: req.NetworkAllowOut, NetworkDenyOut: req.NetworkDenyOut, NetworkEgressRules: req.NetworkEgressRules, EgressStatus: "active"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/network/learned":
			_ = json.NewEncoder(w).Encode(models.NetworkLearned{Mode: "learn", Entries: []models.NetworkLearnedEntry{{Host: "pypi.org", Ports: []uint16{443}}}})
		case r.URL.Path == "/v1/egress-profiles/python" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/egress-profiles/python":
			_ = json.NewEncoder(w).Encode(models.EgressProfile{Name: "python", AllowOut: []string{"pypi.org"}, Generation: 2})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/egress-profiles":
			if r.URL.Query().Get("cursor") != "a" || r.URL.Query().Get("limit") != "5" {
				http.Error(w, "bad query "+r.URL.RawQuery, http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"profiles":null,"next_cursor":"z"}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/sandboxes/sb1/network/limits":
			_ = json.NewEncoder(w).Encode(models.NetworkUsage{SandboxID: "sb1", BytesInLimit: 100})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/start":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", Status: models.SandboxStatusStarted})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/stop":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", Status: models.SandboxStatusStopped})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/sb1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/resize":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", CPU: 2})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/sandboxes/sb1/lifecycle":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", Lifecycle: models.Lifecycle{StopIfIdleFor: time.Minute}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/admin/reconcile":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/ingress/dns":
			_ = json.NewEncoder(w).Encode(models.IngressTarget{Source: "hostname", Hostname: "example.test"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/toolbox/process/execute":
			_ = json.NewEncoder(w).Encode(sdktypes.ExecResult{ExitCode: 0})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/toolbox/files/upload":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/toolbox/files/download":
			_, _ = w.Write([]byte("file-data"))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/toolbox/clone-generation":
			_ = json.NewEncoder(w).Encode(map[string]any{"generation": "2d0d8c69", "resumed_at": 1700000000000000000})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/ports/8080":
			_ = json.NewEncoder(w).Encode(models.ExposePortResponse{Protocol: "http", PublicURL: "https://example.test"})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/sb1/ports/8080":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/custom-domains":
			_ = json.NewEncoder(w).Encode(map[string]any{"custom_domains": []models.CustomDomain{{Hostname: "api.example.test"}}})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/sb1/custom-domains/api.example.test":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/custom-domains":
			_ = json.NewEncoder(w).Encode(map[string]any{"custom_domains": []models.CustomDomain{{Hostname: "api.example.test"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/custom-domains/dns":
			_ = json.NewEncoder(w).Encode(models.CustomDomainDNSRecords{})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/snapshot":
			_ = json.NewEncoder(w).Encode(models.SandboxSnapshot{Name: "snap-1", CreatedAt: now})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL})
	if err != nil {
		t.Fatalf("NewClientWithConfig() error = %v", err)
	}

	if _, err := client.List(ctx); err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if _, err := client.Get(ctx, "sb1"); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if _, err := client.Mounts(ctx, "sb1"); err != nil {
		t.Fatalf("Mounts() error = %v", err)
	}
	if gen, err := client.CloneGeneration(ctx, "sb1"); err != nil {
		t.Fatalf("CloneGeneration() error = %v", err)
	} else if gen.Generation != "2d0d8c69" || gen.ResumedAt != 1700000000000000000 {
		t.Fatalf("CloneGeneration() = %+v, want {2d0d8c69 1700000000000000000}", gen)
	}
	if _, err := client.GetNetworkUsage(ctx, "sb1"); err != nil {
		t.Fatalf("GetNetworkUsage() error = %v", err)
	}
	limit := int64(100)
	if _, err := client.SetNetworkLimits(ctx, "sb1", sdktypes.SetNetworkLimitsOptions{NetworkBytesInLimit: &limit}); err != nil {
		t.Fatalf("SetNetworkLimits() error = %v", err)
	}
	if _, err := client.Start(ctx, "sb1"); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := client.Stop(ctx, "sb1"); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if err := client.Destroy(ctx, "sb1"); err != nil {
		t.Fatalf("Destroy() error = %v", err)
	}
	if _, err := client.Resize(ctx, "sb1", sdktypes.ResizeSandboxOptions{CPU: 2}); err != nil {
		t.Fatalf("Resize() error = %v", err)
	}
	if _, err := client.UpdateLifecycle(ctx, "sb1", sdktypes.Lifecycle{StopIfIdleFor: time.Minute}); err != nil {
		t.Fatalf("UpdateLifecycle() error = %v", err)
	}
	if err := client.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if _, err := client.Health(ctx); err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if _, err := client.DNSTarget(ctx); err != nil {
		t.Fatalf("DNSTarget() error = %v", err)
	}

	sb := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb1"}, client: client}
	if err := sb.Refresh(ctx); err != nil {
		t.Fatalf("Sandbox.Refresh() error = %v", err)
	}
	if _, err := sb.Exec(ctx, sdktypes.ExecRequest{Command: "echo hi"}); err != nil {
		t.Fatalf("Sandbox.Exec() error = %v", err)
	}
	if _, err := sb.ExecCommand(ctx, "echo hi"); err != nil {
		t.Fatalf("Sandbox.ExecCommand() error = %v", err)
	}
	if err := sb.UploadFile(ctx, "/tmp/f.txt", []byte("x")); err != nil {
		t.Fatalf("Sandbox.UploadFile() error = %v", err)
	}
	if _, err := sb.DownloadFile(ctx, "/tmp/f.txt"); err != nil {
		t.Fatalf("Sandbox.DownloadFile() error = %v", err)
	}
	if _, err := sb.ExposePort(ctx, 8080, WithProtocol(sdktypes.ExposeProtocolHTTP)); err != nil {
		t.Fatalf("Sandbox.ExposePort() error = %v", err)
	}
	if err := sb.UnexposePort(ctx, 8080); err != nil {
		t.Fatalf("Sandbox.UnexposePort() error = %v", err)
	}
	if _, err := sb.AddCustomDomain(ctx, "api.example.test", WithTargetPort(3000)); err != nil {
		t.Fatalf("Sandbox.AddCustomDomain() error = %v", err)
	}
	if err := sb.RemoveCustomDomain(ctx, "api.example.test"); err != nil {
		t.Fatalf("Sandbox.RemoveCustomDomain() error = %v", err)
	}
	if _, err := sb.ListCustomDomains(ctx); err != nil {
		t.Fatalf("Sandbox.ListCustomDomains() error = %v", err)
	}
	if _, err := sb.CustomDomainDNS(ctx); err != nil {
		t.Fatalf("Sandbox.CustomDomainDNS() error = %v", err)
	}
	if _, err := sb.CreateSnapshot(ctx, "snap-1"); err != nil {
		t.Fatalf("Sandbox.CreateSnapshot() error = %v", err)
	}
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("Sandbox.Start() error = %v", err)
	}
	if err := sb.Stop(ctx); err != nil {
		t.Fatalf("Sandbox.Stop() error = %v", err)
	}
	if err := sb.Resize(ctx, sdktypes.ResizeSandboxOptions{CPU: 2}); err != nil {
		t.Fatalf("Sandbox.Resize() error = %v", err)
	}
	if _, err := sb.GetNetworkUsage(ctx); err != nil {
		t.Fatalf("Sandbox.GetNetworkUsage() error = %v", err)
	}
	check, err := client.CheckNetworkPolicy(ctx, sdktypes.NetworkPolicyCheckOptions{NetworkAllowOut: []string{"*.github.com"}, Destination: "api.github.com"})
	if err != nil || !check.Allowed || check.MatchedRule != "*.github.com" || check.DefaultVerdict != "deny" {
		t.Fatalf("CheckNetworkPolicy() = %+v, %v", check, err)
	}
	page, err := sb.Audit(ctx, sdktypes.AuditOptions{Kind: "egress", Limit: 50, Cursor: "c1", IncarnationID: "inc-1"})
	if err != nil || len(page.Events) != 1 || page.Events[0].Reason != "host_not_allowed" || page.Events[0].EventID != "ae-1" ||
		page.NextCursor != "c2" || page.Coverage.Answered[0] != "n1" {
		t.Fatalf("Sandbox.Audit() = %+v, %v", page, err)
	}
	if _, err := sb.SetNetworkLimits(ctx, sdktypes.SetNetworkLimitsOptions{NetworkBytesInLimit: &limit}); err != nil {
		t.Fatalf("Sandbox.SetNetworkLimits() error = %v", err)
	}
	policy, err := client.SetNetworkPolicy(ctx, "sb1", sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{"pypi.org"}})
	if err != nil || len(policy.NetworkAllowOut) != 1 || policy.EgressStatus != "active" {
		t.Fatalf("SetNetworkPolicy() = %+v, %v", policy, err)
	}
	if _, err := sb.SetNetworkPolicy(ctx, sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{"pypi.org"}, NetworkDenyOut: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatalf("Sandbox.SetNetworkPolicy() error = %v", err)
	}
	if sb.EgressStatus != "active" || len(sb.NetworkDenyOut) != 1 || sb.NetworkAllowOut[0] != "pypi.org" {
		t.Fatalf("Sandbox fields after SetNetworkPolicy = %+v", sb.Sandbox)
	}
	rule := sdktypes.EgressRule{Host: "api.github.com", Methods: []string{"GET"}, Paths: []string{"/repos/acme/**"}, Inspect: true}
	if _, err := sb.SetNetworkPolicy(ctx, sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{"api.github.com"}, NetworkEgressRules: []sdktypes.EgressRule{rule}}); err != nil {
		t.Fatalf("Sandbox.SetNetworkPolicy(rules) error = %v", err)
	}
	if len(sb.NetworkEgressRules) != 1 || sb.NetworkEgressRules[0].Host != "api.github.com" || !sb.NetworkEgressRules[0].Inspect || sb.NetworkEgressRules[0].Paths[0] != "/repos/acme/**" {
		t.Fatalf("Sandbox rules after SetNetworkPolicy = %+v", sb.NetworkEgressRules)
	}
	if strings.Contains(string(policyBody), `"inject"`) {
		t.Fatalf("a rule without inject must not send one: %s", policyBody)
	}
	rule.Inject = &sdktypes.EgressInject{Header: "Authorization", SecretRef: "env:GITHUB_TOKEN"}
	if _, err := sb.SetNetworkPolicy(ctx, sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{"api.github.com"}, NetworkEgressRules: []sdktypes.EgressRule{rule}}); err != nil {
		t.Fatalf("Sandbox.SetNetworkPolicy(inject) error = %v", err)
	}
	if !strings.Contains(string(policyBody), `"inject":{"header":"Authorization","secret_ref":"env:GITHUB_TOKEN"}`) {
		t.Fatalf("inject on the wire = %s", policyBody)
	}
	if got := sb.NetworkEgressRules[0].Inject; got == nil || got.Header != "Authorization" || got.SecretRef != "env:GITHUB_TOKEN" {
		t.Fatalf("Sandbox rule inject after SetNetworkPolicy = %+v", got)
	}
	if _, err := sb.SetNetworkPolicy(ctx, sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{"api.github.com"}}); err != nil || sb.NetworkEgressRules != nil {
		t.Fatalf("a policy without rules must clear them: %+v, %v", sb.NetworkEgressRules, err)
	}
	learned, err := sb.Learned(ctx)
	if err != nil || learned.Mode != "learn" || len(learned.Entries) != 1 {
		t.Fatalf("Sandbox.Learned() = %+v, %v", learned, err)
	}
	profile, err := client.PutEgressProfile(ctx, "python", sdktypes.EgressProfileOptions{AllowOut: []string{"pypi.org"}})
	if err != nil || profile.Generation != 2 {
		t.Fatalf("PutEgressProfile() = %+v, %v", profile, err)
	}
	if profile, err := client.GetEgressProfile(ctx, "python"); err != nil || profile.Name != "python" {
		t.Fatalf("GetEgressProfile() = %+v, %v", profile, err)
	}
	profiles, err := client.ListEgressProfiles(ctx, sdktypes.ListEgressProfilesOptions{Cursor: "a", Limit: 5})
	if err != nil || profiles.Profiles == nil || profiles.NextCursor != "z" {
		t.Fatalf("ListEgressProfiles() = %+v, %v", profiles, err)
	}
	if err := client.DeleteEgressProfile(ctx, "python"); err != nil {
		t.Fatalf("DeleteEgressProfile() error = %v", err)
	}
	if err := sb.UpdateLifecycle(ctx, sdktypes.Lifecycle{StopIfIdleFor: time.Minute}); err != nil {
		t.Fatalf("Sandbox.UpdateLifecycle() error = %v", err)
	}
	if err := sb.Destroy(ctx); err != nil {
		t.Fatalf("Sandbox.Destroy() error = %v", err)
	}
}
