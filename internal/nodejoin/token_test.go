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
	if !strings.Contains(notes.String(), "works once") || !strings.Contains(notes.String(), "never expires") || !strings.Contains(notes.String(), "warning: ") {
		t.Fatalf("notes for a never-expiring token:\n%s", notes.String())
	}
	// The API's refusal is the error.
	api.tokenErr = http.StatusForbidden
	if _, err := m.Run(ctx, TokenOptions{Role: "server"}); err == nil || !strings.Contains(err.Error(), "no tokens today") {
		t.Fatalf("a refused token = %v", err)
	}
}
