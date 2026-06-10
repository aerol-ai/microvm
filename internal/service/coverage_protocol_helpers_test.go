package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/miekg/dns"
)

type recordingToolboxCall struct {
	SandboxID string
	Token     string
	Path      string
	RawQuery  string
	Headers   http.Header
}

type recordingToolboxHost struct {
	wasmRecordingRuntime

	mu    sync.Mutex
	calls []recordingToolboxCall
}

func (r *recordingToolboxHost) ServeToolbox(_ context.Context, sandboxID string, token string, w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.calls = append(r.calls, recordingToolboxCall{
		SandboxID: sandboxID,
		Token:     token,
		Path:      req.URL.Path,
		RawQuery:  req.URL.RawQuery,
		Headers:   req.Header.Clone(),
	})
	r.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("wasm-toolbox"))
}

func (r *recordingToolboxHost) lastCall() recordingToolboxCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		return recordingToolboxCall{}
	}
	return r.calls[len(r.calls)-1]
}

func TestLeafHelperCoverage(t *testing.T) {
	t.Run("dns resolver", func(t *testing.T) {
		mux := dns.NewServeMux()
		mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
			msg := new(dns.Msg)
			msg.SetReply(r)
			msg.Authoritative = true
			if len(r.Question) > 0 {
				qname := r.Question[0].Name
				msg.Answer = []dns.RR{
					&dns.TXT{
						Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
						Txt: []string{"aerol-verify=api.acme.com"},
					},
				}
			}
			_ = w.WriteMsg(msg)
		})

		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		defer pc.Close()

		srv := &dns.Server{PacketConn: pc, Handler: mux}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = srv.ActivateAndServe()
		}()
		t.Cleanup(func() {
			_ = srv.Shutdown()
			<-done
		})

		oldResolver := net.DefaultResolver
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return net.Dial("udp", pc.LocalAddr().String())
			},
		}
		t.Cleanup(func() { net.DefaultResolver = oldResolver })

		got, err := (&DefaultDNSResolver{}).LookupTXT(context.Background(), "api.acme.com.")
		if err != nil {
			t.Fatalf("LookupTXT: %v", err)
		}
		if len(got) != 1 || got[0] != "aerol-verify=api.acme.com" {
			t.Fatalf("LookupTXT = %v, want TXT payload", got)
		}
	})

	t.Run("image distribution", func(t *testing.T) {
		provider := newDefaultImageDistributionProvider("")
		meta, err := provider.ClassifyImage(context.Background(), "  ")
		if err != nil {
			t.Fatalf("ClassifyImage(empty): %v", err)
		}
		if !meta.IsZero() {
			t.Fatalf("empty image classified as %+v", meta)
		}

		meta, err = normalizeImageDistributionMetadata("ghcr.io/org/img:latest", models.ImageDistributionMetadata{})
		if err != nil {
			t.Fatalf("normalizeImageDistributionMetadata(external): %v", err)
		}
		if meta.Mode != models.ImageDistributionExternalRegistry || meta.RegistryRef != "ghcr.io/org/img:latest" {
			t.Fatalf("external normalize = %+v", meta)
		}

		meta, err = normalizeImageDistributionMetadata("aocr.aerol.ai/team/app:latest", models.ImageDistributionMetadata{
			Mode:        models.ImageDistributionAOCR,
			RegistryRef: "   ",
			Digest:      "  sha256:abc  ",
		})
		if err != nil {
			t.Fatalf("normalizeImageDistributionMetadata(aocr): %v", err)
		}
		if meta.RegistryRef != "aocr.aerol.ai/team/app:latest" || meta.Digest != "sha256:abc" {
			t.Fatalf("aocr normalize = %+v", meta)
		}

		if _, err := normalizeImageDistributionMetadata("img", models.ImageDistributionMetadata{Mode: "bogus"}); err == nil {
			t.Fatal("invalid distribution mode accepted")
		}

		if got := imageRegistryHost("localhost:5000/team/app:latest"); got != "localhost:5000" {
			t.Fatalf("imageRegistryHost(localhost) = %q", got)
		}
		if got := imageRegistryHost("docker.io/library/alpine:3.19"); got != "docker.io" {
			t.Fatalf("imageRegistryHost(docker.io) = %q", got)
		}
		if got := imageRegistryHost("alpine:3.19"); got != "" {
			t.Fatalf("imageRegistryHost(bare) = %q, want empty", got)
		}
		if !ImageRequiresLocalPlacement(models.CreateSandboxRequest{
			Image:                 docker.BuiltImageNamespace + "/abc:latest",
			ImageDistributionMode: models.ImageDistributionLocalOnly,
		}) {
			t.Fatal("local-only image must require local placement")
		}
	})

	t.Run("toolbox proxy", func(t *testing.T) {
		ctx := context.Background()
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.ToolboxPort = 4321
		svc.cfg.EnableWasm = true

		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-toolbox",
			Runtime:      models.RuntimeWasm,
			Status:       models.SandboxStatusStarted,
			ContainerIP:  "127.0.0.1",
			ToolboxToken: "token-123",
			CreatedAt:    now,
			UpdatedAt:    now,
		}); err != nil {
			t.Fatalf("Create sandbox: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/toolbox?q=1", nil)
		rec := httptest.NewRecorder()

		if err := svc.ServeToolboxReverseProxy(ctx, "sb-toolbox", rec, req, "/toolbox"); err == nil || !strings.Contains(err.Error(), "driver not registered") {
			t.Fatalf("ServeToolboxReverseProxy without wasm runtime = %v", err)
		}

		svc.SetWasmRuntime(&recordingRuntime{})
		if err := svc.ServeToolboxReverseProxy(ctx, "sb-toolbox", rec, req, "/toolbox"); err == nil || !strings.Contains(err.Error(), "toolbox host") {
			t.Fatalf("ServeToolboxReverseProxy without host = %v", err)
		}

		host := &recordingToolboxHost{}
		svc.SetWasmRuntime(host)
		resp, err := svc.RoundTripToolbox(ctx, "sb-toolbox", http.MethodPost, "api/v1", url.Values{"q": {"1"}}, strings.NewReader("payload"), http.Header{"X-Test": {"abc"}})
		if err != nil {
			t.Fatalf("RoundTripToolbox wasm: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("RoundTripToolbox status = %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != "wasm-toolbox" {
			t.Fatalf("RoundTripToolbox body = %q", string(body))
		}
		call := host.lastCall()
		if call.Path != "/api/v1" || call.RawQuery != "q=1" {
			t.Fatalf("wasm toolbox request = %+v", call)
		}
		if got := call.Headers.Get("X-Test"); got != "abc" {
			t.Fatalf("X-Test header = %q", got)
		}
		if got := call.Headers.Get("Authorization"); got != "Bearer token-123" {
			t.Fatalf("Authorization header = %q", got)
		}

		netServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Path; got != "/toolbox/api" {
				t.Fatalf("network toolbox path = %q", got)
			}
			if got := r.URL.RawQuery; got != "a=1&b=2" {
				t.Fatalf("network toolbox query = %q", got)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer token-123" {
				t.Fatalf("network Authorization = %q", got)
			}
			if got := r.Header.Get("X-Trace"); got != "xyz" {
				t.Fatalf("network header = %q", got)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("network-toolbox"))
		}))
		defer netServer.Close()

		port := strings.Split(netServer.URL, ":")[2]
		var portInt int
		if _, err := fmt.Sscanf(port, "%d", &portInt); err != nil {
			t.Fatalf("parse port: %v", err)
		}
		svc.cfg.ToolboxPort = portInt
		svc.SetWasmRuntime(&recordingRuntime{})

		if _, err := svc.RoundTripToolbox(ctx, "sb-toolbox", http.MethodGet, "toolbox/api", url.Values{"a": {"1"}, "b": {"2"}}, nil, http.Header{"X-Trace": {"xyz"}}); err == nil {
			t.Fatal("expected wasm toolbox host failure for non-host runtime")
		}

		now = time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-net-toolbox",
			Runtime:      models.RuntimeDocker,
			Status:       models.SandboxStatusStarted,
			ContainerIP:  "127.0.0.1",
			ToolboxToken: "token-123",
			CreatedAt:    now,
			UpdatedAt:    now,
		}); err != nil {
			t.Fatalf("Create docker sandbox: %v", err)
		}

		if resp, err := svc.RoundTripToolbox(ctx, "sb-net-toolbox", http.MethodGet, "toolbox/api", url.Values{"a": {"1"}, "b": {"2"}}, nil, http.Header{"X-Trace": {"xyz"}}); err != nil {
			t.Fatalf("RoundTripToolbox network: %v", err)
		} else {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if string(body) != "network-toolbox" {
				t.Fatalf("network body = %q", string(body))
			}
		}
	})

	t.Run("wasm custom domains", func(t *testing.T) {
		ctx := context.Background()
		driver := wasmruntime.New(wasmruntime.Config{ModulesDir: t.TempDir()}, nil)
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.cfg.EnableCustomDomains = true
		svc.cfg.Domain = "sandbox.test"
		svc.cfg.ToolboxPort = 4321
		svc.cfg.EnableCaddy = true
		fake := newRouteAdminCaddyFake()
		server := httptest.NewServer(fake.handler(t))
		defer server.Close()
		svc.cfg.CaddyAdminURL = server.URL
		svc.cfg.CaddyServerID = "srv0"
		svc.cfg.HTTPClientTimeout = time.Second
		svc.caddy = caddy.New(svc.cfg)
		svc.SetWasmRuntime(driver)

		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:           "sb-wasm-cd",
			Runtime:      models.RuntimeWasm,
			Status:       models.SandboxStatusStarted,
			ContainerIP:  "127.0.0.1",
			ToolboxToken: "token-123",
			CreatedAt:    now,
			UpdatedAt:    now,
		}); err != nil {
			t.Fatalf("Create sandbox: %v", err)
		}

		sb, err := st.Get(ctx, "sb-wasm-cd")
		if err != nil {
			t.Fatalf("Get sandbox: %v", err)
		}

		sb.ExposedPorts = []models.ExposedPort{
			{Port: 8080, Protocol: models.ExposedPortProtocolHTTP},
			{Port: 8081},
			{Port: 9090, Protocol: models.ExposedPortProtocolTCP},
		}

		ports := wasmExposedHTTPPorts(sb)
		if len(ports) != 2 || ports[0] != 8080 || ports[1] != 8081 {
			t.Fatalf("wasmExposedHTTPPorts = %#v", ports)
		}
		if err := svc.validateWasmCustomDomainTargetPort(sb, 8080); err != nil {
			t.Fatalf("validateWasmCustomDomainTargetPort(8080): %v", err)
		}
		if err := svc.validateWasmCustomDomainTargetPort(sb, 9999); !errors.Is(err, ErrWasmCustomDomainPortNotExposed) {
			t.Fatalf("validateWasmCustomDomainTargetPort(9999) = %v", err)
		}
		if dial, err := svc.wasmCustomDomainDial(ctx, sb, 0); err != nil || dial != "127.0.0.1:4321" {
			t.Fatalf("wasmCustomDomainDial(toolbox) = (%q, %v)", dial, err)
		}
		if dial, err := svc.wasmCustomDomainDial(ctx, sb, 8080); err != nil || dial == "" {
			t.Fatalf("wasmCustomDomainDial(port) = (%q, %v)", dial, err)
		}

		if _, err := svc.ExposePort(ctx, "sb-wasm-cd", 8080, "http"); err != nil {
			t.Fatalf("ExposePort: %v", err)
		}
		sandbox, err := st.Get(ctx, "sb-wasm-cd")
		if err != nil {
			t.Fatalf("Get sandbox after add: %v", err)
		}
		sandbox.CustomDomains = []models.CustomDomain{
			{Hostname: "api.acme.com", TargetPort: 8080},
			{Hostname: "", TargetPort: 8080},
		}
		if err := svc.syncWasmCustomDomainRoutes(ctx, sandbox); err != nil {
			t.Fatalf("syncWasmCustomDomainRoutes: %v", err)
		}
		if !fake.hasHTTPRoute(caddy.IngressCustomDomainHTTPRouteID("sb-wasm-cd", "api.acme.com")) {
			t.Fatal("expected custom-domain HTTP route to be installed")
		}
	})

	t.Run("wasm port gateway", func(t *testing.T) {
		svc := &Service{}
		if _, err := svc.wasmPortGateway(); err == nil || !strings.Contains(err.Error(), "driver not registered") {
			t.Fatalf("wasmPortGateway missing runtime = %v", err)
		}
		svc.SetWasmRuntime(&recordingRuntime{})
		if _, err := svc.wasmPortGateway(); err == nil || !strings.Contains(err.Error(), "port gateway not available") {
			t.Fatalf("wasmPortGateway without gateway = %v", err)
		}
	})
}
