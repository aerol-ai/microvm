package v1

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"golang.org/x/crypto/ssh"
)

// A node's sandbox read carries no SSH key, only the answer for the key it
// offers; a node's bridged sessions call is served only for the sandbox's
// key once servers sign.
func TestSSHBridgeKeyRoutes(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ciph, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, logger, st, nil, nil, nil, ciph, nil, nil)
	srv := &signingServerCluster{Noop: cluster.NewNoop("own-1", "http://own-1", "")}
	svc.AttachCluster(srv)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(pub)
	fp := ssh.FingerprintSHA256(key)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{ID: "sb-ssh", Image: "alpine", Status: models.SandboxStatusStarted,
		SSHPublicKey: string(ssh.MarshalAuthorizedKey(key)), CPU: 1, MemoryMB: 64, DiskGB: 1, OSUser: "root",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
	node := controlplane.ContextWithAccess(context.Background(), controlplane.NodeAccess("gw-1", controlplane.NodeRoleIngress))
	get := func(ctx context.Context, offered string) (models.Sandbox, string) {
		r := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-ssh", nil).WithContext(ctx)
		r.SetPathValue("id", "sb-ssh")
		if offered != "" {
			r.Header.Set(auditlog.SSHOfferedKeyHeader, offered)
		}
		rr := httptest.NewRecorder()
		h.getSandbox(rr, r)
		var sb models.Sandbox
		_ = json.Unmarshal(rr.Body.Bytes(), &sb)
		return sb, rr.Header().Get(auditlog.SSHKeyMatchHeader)
	}
	if sb, match := get(node, fp); sb.SSHPublicKey != "" || match != "true" {
		t.Fatalf("a new gateway's read: key %q match %q", sb.SSHPublicKey, match)
	}
	if _, match := get(node, "SHA256:other"); match != "false" {
		t.Fatalf("another key: match %q", match)
	}
	if sb, _ := get(node, ""); sb.SSHPublicKey == "" {
		t.Fatal("before servers sign, an older gateway's read lost the key it checks")
	}
	if sb, _ := get(controlplane.ContextWithAccess(context.Background(), controlplane.OperatorAccess()), fp); sb.SSHPublicKey == "" {
		t.Fatal("the operator's read lost the key")
	}
	// Servers sign: no node reads the key.
	if err := svc.UpkeepServerSigning(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sb, _ := get(node, ""); sb.SSHPublicKey != "" {
		t.Fatal("a node read the key once servers sign")
	}
	sessions := func(call *auditlog.SSHGatewayCall) int {
		ctx := node
		if call != nil {
			ctx = auditlog.ContextWithSSHGatewayCall(ctx, *call)
		}
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-ssh/sessions", nil).WithContext(ctx)
		r.SetPathValue("id", "sb-ssh")
		rr := httptest.NewRecorder()
		h.sessionsProxy(rr, r)
		return rr.Code
	}
	if got := sessions(&auditlog.SSHGatewayCall{SandboxID: "sb-ssh"}); got != http.StatusForbidden {
		t.Fatalf("a bridged call naming no key = %d", got)
	}
	if got := sessions(&auditlog.SSHGatewayCall{SandboxID: "sb-ssh", KeyFingerprint: "SHA256:other"}); got != http.StatusForbidden {
		t.Fatalf("a bridged call naming another key = %d", got)
	}
	if got := sessions(&auditlog.SSHGatewayCall{SandboxID: "sb-ssh", KeyFingerprint: fp}); got == http.StatusForbidden {
		t.Fatalf("a bridged call naming the key = %d", got)
	}
	// A sandbox this node does not hold answers as the store does.
	r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-none/sessions", nil).
		WithContext(auditlog.ContextWithSSHGatewayCall(node, auditlog.SSHGatewayCall{SandboxID: "sb-none", KeyFingerprint: fp}))
	r.SetPathValue("id", "sb-none")
	rr := httptest.NewRecorder()
	h.sessionsProxy(rr, r)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("an unknown sandbox = %d", rr.Code)
	}
}
