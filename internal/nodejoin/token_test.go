package nodejoin

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// TestTokenMaker is `sandboxd join-command`, kubeadm's `kubeadm token create
// --print-join-command` on a control-plane node: only on a server in a
// cluster, as root, through this server's own API with its operator token.
func TestTokenMaker(t *testing.T) {
	ctx := context.Background()
	p := testPaths(t)
	api := newFakeLocalAPI(t)
	h := newFakeHost()
	var notes bytes.Buffer
	m := &TokenMaker{Paths: p, Host: h, Printer: Printer{Out: &notes}, LocalAPI: api.srv.URL}

	h.notRoot = true
	if _, err := m.Run(ctx, TokenOptions{}); err == nil || !strings.Contains(err.Error(), "as root") {
		t.Fatalf("join-command without root = %v", err)
	}
	h.notRoot = false
	if _, err := m.Run(ctx, TokenOptions{Role: "boss"}); err == nil || !strings.Contains(err.Error(), "--role must be") {
		t.Fatalf("a bad role = %v", err)
	}
	if _, err := m.Run(ctx, TokenOptions{}); err == nil {
		t.Fatal("join-command ran with no sandboxd.env")
	}
	mustWrite(t, p.EnvFile, "SB_PAT_TOKEN=operator-pat\n")
	if _, err := m.Run(ctx, TokenOptions{}); err == nil || !strings.Contains(err.Error(), "not in a cluster") {
		t.Fatalf("join-command off-cluster = %v", err)
	}
	// A worker or ingress node: the cluster would refuse a server token
	// asked through it (J1), so it does not try.
	for _, role := range []string{"worker", "ingress"} {
		clusterNode(t, p, role)
		if _, err := m.Run(ctx, TokenOptions{Role: "server"}); !errors.Is(err, ErrJoinCommandNotOnServer) {
			t.Fatalf("join-command on a %s = %v", role, err)
		}
	}
	clusterNode(t, p, "bogus")
	if _, err := m.Run(ctx, TokenOptions{}); err == nil {
		t.Fatal("a bogus role made a token")
	}
	if len(api.tokens) != 0 {
		t.Fatalf("a refused join-command reached the API: %+v", api.tokens)
	}

	// On a server: the token comes from this server's API, with its PAT.
	clusterNode(t, p, "server")
	if _, err := m.Run(ctx, TokenOptions{Role: "server"}); err == nil || !strings.Contains(err.Error(), "no join URL") {
		t.Fatalf("a cluster with no join URL = %v", err)
	}
	api.joinURLs, api.caHash = []string{"https://10.0.0.5:7003", "https://10.0.0.6:7003"}, "sha256:abcd"
	notes.Reset()
	res, err := m.Run(ctx, TokenOptions{Role: "Server", TTL: " 2h ", Reusable: true})
	if err != nil {
		t.Fatal(err)
	}
	got := api.tokens[len(api.tokens)-1]
	if got.Role != "server" || got.TTL != "2h" || !got.Reusable || got.CreatedBy != "sandboxd join-command on node-a" {
		t.Fatalf("token request = %+v", got)
	}
	if a := api.tokenAuth[len(api.tokenAuth)-1]; a != "Bearer operator-pat" {
		t.Fatalf("token call auth = %q, want the operator PAT from sandboxd.env", a)
	}
	want := "curl -fsSL " + DefaultInstallerURL + " | sudo bash -s -- join https://10.0.0.5:7003 --token " + res.Token + " --ca-cert-hash sha256:abcd"
	if res.Command != want {
		t.Fatalf("command = %q\nwant      %q", res.Command, want)
	}
	for _, w := range []string{"server token " + res.ID + " expires at", "works for any number of machines", "aerolvm delete jointoken " + res.ID} {
		if !strings.Contains(notes.String(), w) {
			t.Fatalf("notes lack %q:\n%s", w, notes.String())
		}
	}
	if strings.Contains(notes.String(), res.Token) {
		t.Fatalf("the notes print the secret:\n%s", notes.String())
	}

	// The defaults: a worker token, single use; a never-expiring one warns;
	// --installer-url changes the printed line.
	notes.Reset()
	res, err = m.Run(ctx, TokenOptions{TTL: "0", InstallerURL: "https://mirror.example"})
	if err != nil || api.tokens[len(api.tokens)-1].Role != "worker" || !strings.HasPrefix(res.Command, "curl -fsSL https://mirror.example |") {
		t.Fatalf("default join-command = %+v %v", res, err)
	}
	if !strings.Contains(notes.String(), "works for one machine") || !strings.Contains(notes.String(), "never expires") || !strings.Contains(notes.String(), "warning: ") {
		t.Fatalf("notes for a never-expiring token:\n%s", notes.String())
	}
	// --role mixed asks for a server token, and the line adds --role mixed.
	// With a domain, the line carries this node's --domain and DNS options,
	// and the notes say to set the Cloudflare token on the new machine.
	mustWrite(t, p.EnvFile, "SB_PAT_TOKEN=operator-pat\nSB_DOMAIN=cluster.example.com\n")
	notes.Reset()
	res, err = m.Run(ctx, TokenOptions{Role: "mixed"})
	if err != nil || api.tokens[len(api.tokens)-1].Role != "server" {
		t.Fatalf("join-command --role mixed = %+v %v", res, err)
	}
	want = "curl -fsSL " + DefaultInstallerURL + ` | sudo bash -s -- --domain cluster.example.com --dns-provider cloudflare --dns-api-token "$CLOUDFLARE_API_TOKEN" join https://10.0.0.5:7003 --token ` + res.Token + " --ca-cert-hash sha256:abcd --role mixed"
	if res.Command != want {
		t.Fatalf("command = %q\nwant      %q", res.Command, want)
	}
	if !strings.Contains(notes.String(), "export CLOUDFLARE_API_TOKEN=<token>") {
		t.Fatalf("notes lack the Cloudflare step:\n%s", notes.String())
	}
	if _, err := m.Run(ctx, TokenOptions{Role: "mixed,worker"}); err == nil || !strings.Contains(err.Error(), "--role must be") {
		t.Fatalf("mixed in a list = %v", err)
	}

	// The API's refusal is the error.
	api.tokenErr = http.StatusForbidden
	if _, err := m.Run(ctx, TokenOptions{Role: "server"}); err == nil || !strings.Contains(err.Error(), "no tokens today") {
		t.Fatalf("a refused token = %v", err)
	}
}

// TestJoinLine pins the printed line: the installer options that give a new
// machine the cluster's public setup come before join, its flags after.
func TestJoinLine(t *testing.T) {
	base := JoinLine{Installer: "https://i.example", JoinURL: "https://10.0.0.5:7003", Token: "abc123.x", CACertHash: "sha256:9a"}
	with := func(f func(*JoinLine)) JoinLine { l := base; f(&l); return l }
	const tail = " join https://10.0.0.5:7003 --token abc123.x --ca-cert-hash sha256:9a"
	for _, tc := range []struct {
		name string
		line JoinLine
		want string
		dns  bool
	}{
		{"no domain", base, "curl -fsSL https://i.example | sudo bash -s --" + tail, false},
		{"default installer", with(func(l *JoinLine) { l.Installer = "" }), "curl -fsSL " + DefaultInstallerURL + " | sudo bash -s --" + tail, false},
		{"a domain", with(func(l *JoinLine) { l.Domain = "c.example.com" }),
			`curl -fsSL https://i.example | sudo bash -s -- --domain c.example.com --dns-provider cloudflare --dns-api-token "$CLOUDFLARE_API_TOKEN"` + tail, true},
		{"Caddy's own issuer needs no DNS provider", with(func(l *JoinLine) { l.Domain, l.TLSIssuer = "c.example.com", "internal" }),
			"curl -fsSL https://i.example | sudo bash -s -- --domain c.example.com --tls-issuer internal" + tail, false},
		{"the ingress host is left out when it is the domain", with(func(l *JoinLine) { l.Domain, l.IngressHost = "c.example.com", "C.example.com" }),
			`curl -fsSL https://i.example | sudo bash -s -- --domain c.example.com --dns-provider cloudflare --dns-api-token "$CLOUDFLARE_API_TOKEN"` + tail, true},
		{"another ingress host and a role", with(func(l *JoinLine) { l.IngressHost, l.NodeRole = "in.example.com", "worker,ingress" }),
			"curl -fsSL https://i.example | sudo bash -s --" + tail + " --role worker,ingress --ingress-advertise-host in.example.com", false},
		{"no hash", with(func(l *JoinLine) { l.CACertHash = "" }), "curl -fsSL https://i.example | sudo bash -s -- join https://10.0.0.5:7003 --token abc123.x", false},
	} {
		if got := tc.line.String(); got != tc.want || tc.line.NeedsDNSToken() != tc.dns {
			t.Fatalf("%s:\n got %q (dns %v)\nwant %q (dns %v)", tc.name, got, tc.line.NeedsDNSToken(), tc.want, tc.dns)
		}
	}
}

func TestNodeRoleForJoin(t *testing.T) {
	for _, tc := range []struct{ in, token, node string }{
		{"", "worker", ""},
		{"worker", "worker", ""},
		{" Server ", "server", ""},
		{"ingress", "ingress", ""},
		{"mixed", "server", "mixed"},
		{"server, worker", "server", "server,worker"},
		{"worker,ingress", "worker", "worker,ingress"},
	} {
		token, node, err := NodeRoleForJoin(tc.in)
		if err != nil || token != tc.token || node != tc.node {
			t.Fatalf("%q = %q %q %v, want %q %q", tc.in, token, node, err, tc.token, tc.node)
		}
	}
	for _, bad := range []string{"boss", "mixed,worker", "worker,"} {
		if _, _, err := NodeRoleForJoin(bad); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}

// TestIngressHostFor: the flag wins; an operator's own setting in
// sandboxd.env is never overridden; an earlier value is kept; else the domain.
func TestIngressHostFor(t *testing.T) {
	env := func(base, clusterEnv map[string]string) nodeEnv { return nodeEnv{base: base, cluster: clusterEnv} }
	for _, tc := range []struct {
		name string
		env  nodeEnv
		flag string
		want string
	}{
		{"the flag", env(map[string]string{"SB_DOMAIN": "d.example"}, nil), "flag.example", "flag.example"},
		{"the domain", env(map[string]string{"SB_DOMAIN": "d.example"}, nil), "", "d.example"},
		{"sandboxd.env already sets it", env(map[string]string{"SB_DOMAIN": "d.example", "SB_INGRESS_ADVERTISE_HOST": "own.example"}, nil), "", ""},
		{"an earlier init or join", env(map[string]string{"SB_DOMAIN": "d.example"}, map[string]string{"SB_INGRESS_ADVERTISE_HOST": "old.example"}), "", "old.example"},
		{"no domain", env(map[string]string{}, nil), "", ""},
	} {
		if got := ingressHostFor(tc.env, tc.flag); got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.name, got, tc.want)
		}
	}
}
