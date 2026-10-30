package secrets

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// VaultOptions configures the vault provider: Vault Transit or OpenBao
// (plans/customer-key-custody.md §1). sandboxd has no Vault login code
// (eng D10): Vault Agent either writes a token to TokenFile, or, with no
// token file, Addr points at Agent's local API proxy, which adds the token
// itself so sandboxd holds no Vault credential at all.
type VaultOptions struct {
	Addr      string // SB_SECRET_VAULT_ADDR
	Mount     string // SB_SECRET_VAULT_TRANSIT_MOUNT; "" means "transit"
	KeyName   string // SB_SECRET_VAULT_KEY_NAME
	TokenFile string // SB_SECRET_VAULT_TOKEN_FILE
	Namespace string // SB_SECRET_VAULT_NAMESPACE (X-Vault-Namespace)
	CACert    string // SB_SECRET_VAULT_CACERT, a PEM bundle path
	// NodeID names this node in the correlation id of background calls.
	NodeID string
}

// Configured reports whether any Vault setting is present, which makes the
// node able to open vault-tagged rows even when it seals with another
// provider.
func (o VaultOptions) Configured() bool {
	return strings.TrimSpace(o.Addr) != "" || strings.TrimSpace(o.KeyName) != ""
}

const (
	defaultVaultMount = "transit"
	// vaultCallTimeout is a ceiling for a caller with no deadline; the
	// caller's own deadline is normally shorter.
	vaultCallTimeout = 30 * time.Second
	// vaultPolicyCheckTimeout bounds the boot-time policy check, so a Vault
	// that is down delays boot by at most this before the canary reports it.
	vaultPolicyCheckTimeout = 5 * time.Second
	vaultMaxResponseBytes   = 1 << 20
	vaultErrorTextMax       = 200
	// CorrelationHeader carries the sandboxd secret-audit correlation id to
	// the key store, so a Vault audit entry joins to the exact sandboxd event
	// (CEO-E3). Vault records it once listed under audited request headers.
	CorrelationHeader = "X-Aerol-Correlation-ID"
)

var (
	vaultNameRE        = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	vaultMountRE       = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	safeCorrelationIDs = regexp.MustCompile(`^[A-Za-z0-9._:@+=/-]{1,128}$`)
	// errVaultPolicy marks a token that may do more than the provider needs.
	// It wraps ErrProviderDenied: the fix is the same grant change.
	errVaultPolicy = fmt.Errorf("%w: vault token policy", ErrProviderDenied)
)

// vaultResponse is the part of a Vault reply sandboxd reads. Data carries the
// plaintext DEK on a decrypt, so it never goes into a log line or an error.
type vaultResponse struct {
	Data   map[string]any `json:"data"`
	Errors []string       `json:"errors"`
}

// vaultAPI is the one call the provider makes, narrowed so tests can drive
// every status and error text without a server (the way kmsAPI narrows the
// AWS client).
type vaultAPI interface {
	call(ctx context.Context, path string, body any) (status int, resp vaultResponse, err error)
}

// Vault wraps DEKs with Vault Transit or OpenBao encrypt/decrypt. Its
// ciphertext starts with "vault:v<N>:", which is also the provider tag the
// Router reads.
type Vault struct {
	api      vaultAPI
	encPath  string
	decPath  string
	policyOK atomic.Bool
	policyMu sync.Mutex
}

// NewVault validates opts and builds the client. It makes no call; the token
// policy check runs at boot (NewWrapper) and again before the first encrypt.
func NewVault(opts VaultOptions) (*Vault, error) {
	base, err := vaultBaseURL(opts.Addr)
	if err != nil {
		return nil, err
	}
	key := strings.TrimSpace(opts.KeyName)
	if !vaultNameRE.MatchString(key) {
		return nil, fmt.Errorf("SB_SECRET_VAULT_KEY_NAME must be a Transit key name of letters, digits, '.', '_' or '-' (got %q)", opts.KeyName)
	}
	mount := strings.Trim(strings.TrimSpace(opts.Mount), "/")
	if mount == "" {
		mount = defaultVaultMount
	}
	if !vaultMountRE.MatchString(mount) || strings.Contains("/"+mount+"/", "/../") || strings.Contains("/"+mount+"/", "/./") {
		return nil, fmt.Errorf("SB_SECRET_VAULT_TRANSIT_MOUNT is not a valid mount path (got %q)", opts.Mount)
	}
	client, err := vaultHTTPClient(opts.CACert)
	if err != nil {
		return nil, err
	}
	h := &vaultHTTP{base: base, namespace: strings.TrimSpace(opts.Namespace), nodeID: strings.TrimSpace(opts.NodeID), client: client}
	if tf := strings.TrimSpace(opts.TokenFile); tf != "" {
		h.token = &tokenFile{path: tf}
	}
	return newVaultWithAPI(h, mount, key), nil
}

func newVaultWithAPI(api vaultAPI, mount, key string) *Vault {
	return &Vault{api: api, encPath: mount + "/encrypt/" + key, decPath: mount + "/decrypt/" + key}
}

// vaultBaseURL accepts https, or http only to a loopback address (Vault
// Agent's local proxy): plain http across a network would carry DEKs and
// the token in the clear.
func vaultBaseURL(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", errors.New("SB_SECRET_VAULT_ADDR is required for the vault provider")
	}
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("SB_SECRET_VAULT_ADDR must be an http(s) URL with a host and no credentials, query or fragment (got %q)", addr)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return "", fmt.Errorf("SB_SECRET_VAULT_ADDR=%s uses http to a non-loopback host; use https, or point it at a local Vault Agent proxy", addr)
		}
	default:
		return "", fmt.Errorf("SB_SECRET_VAULT_ADDR must use https (or http to loopback), got %q", u.Scheme)
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func vaultHTTPClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile = strings.TrimSpace(caFile); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read SB_SECRET_VAULT_CACERT: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("SB_SECRET_VAULT_CACERT %s holds no PEM certificate", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	// Never route DEKs through an HTTP_PROXY from the unit's environment.
	tr.Proxy = nil
	return &http.Client{
		Transport: tr,
		Timeout:   vaultCallTimeout,
		// A redirect would carry X-Vault-Token to wherever it points.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// Wrap implements DataKeyWrapper with Transit encrypt. The encryption context
// is bound as associated_data; Phase 0 confirmed decrypt rejects a wrong one
// on Vault and OpenBao.
func (v *Vault) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, error) {
	if err := v.ensurePolicy(ctx); err != nil {
		return nil, err
	}
	body := map[string]any{"plaintext": base64.StdEncoding.EncodeToString(dek)}
	if aad := encryptionContextAAD(encCtx); len(aad) > 0 {
		body["associated_data"] = base64.StdEncoding.EncodeToString(aad)
	}
	status, resp, err := v.api.call(ctx, v.encPath, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, classifyVault("encrypt", status, resp.Errors)
	}
	ct, _ := resp.Data["ciphertext"].(string)
	if !strings.HasPrefix(ct, tagVault+"v") {
		return nil, fmt.Errorf("%w: vault encrypt returned no vault ciphertext", ErrProviderUnavailable)
	}
	return []byte(ct), nil
}

// Unwrap implements DataKeyWrapper with Transit decrypt.
func (v *Vault) Unwrap(ctx context.Context, wrapped []byte, encCtx map[string]string) ([]byte, error) {
	if !bytes.HasPrefix(wrapped, []byte(tagVault)) {
		return nil, fmt.Errorf("%w: wrapped key is not vault ciphertext", ErrDecryptFailed)
	}
	body := map[string]any{"ciphertext": string(wrapped)}
	if aad := encryptionContextAAD(encCtx); len(aad) > 0 {
		body["associated_data"] = base64.StdEncoding.EncodeToString(aad)
	}
	status, resp, err := v.api.call(ctx, v.decPath, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, classifyVault("decrypt", status, resp.Errors)
	}
	pt, _ := resp.Data["plaintext"].(string)
	dek, derr := base64.StdEncoding.DecodeString(pt)
	if derr != nil || len(dek) == 0 {
		return nil, fmt.Errorf("%w: vault decrypt returned no plaintext", ErrDecryptFailed)
	}
	return dek, nil
}

// classifyVault maps a non-200 Transit reply to a provider class. The error
// texts are the ones Phase 0 recorded on Vault 1.18 and OpenBao 2.1. Only a
// deleted key is a revoke: a 403 looks the same for a revoked policy and an
// expired Agent token, and a retired version marks a stale row (§10).
func classifyVault(op string, status int, errs []string) error {
	text := strings.Join(errs, "; ")
	if len(text) > vaultErrorTextMax {
		text = text[:vaultErrorTextMax]
	}
	lower := strings.ToLower(text)
	switch {
	case status == http.StatusTooManyRequests:
		return fmt.Errorf("%w: vault %s: %d %s", ErrProviderThrottled, op, status, text)
	case status == http.StatusForbidden:
		return fmt.Errorf("%w: vault %s: %d %s", ErrProviderDenied, op, status, text)
	case status == http.StatusBadRequest && strings.Contains(lower, "encryption key not found"):
		return fmt.Errorf("%w: vault %s: %s", ErrKeyRevoked, op, text)
	case status == http.StatusBadRequest && strings.Contains(lower, "disallowed by policy"):
		return fmt.Errorf("%w: vault %s: %s", ErrKeyVersionRetired, op, text)
	case status == http.StatusBadRequest && op == "decrypt":
		// Wrong associated data, a tampered ciphertext or a malformed one.
		return fmt.Errorf("%w: vault decrypt: %s", ErrDecryptFailed, text)
	default:
		// 5xx (sealed, standby), 404 (mount gone), a redirect, or an encrypt
		// 400 nobody expects: the key store cannot do the work right now.
		return fmt.Errorf("%w: vault %s: %d %s", ErrProviderUnavailable, op, status, text)
	}
}

// ensurePolicy refuses a token that may create keys on the encrypt path.
// Transit silently recreates a deleted key on the next encrypt for such a
// token, which would undo a customer's revoke (Phase 0). It runs before the
// first encrypt and is remembered once it passes (the lazy bootstrap latch,
// CLAUDE.md rule 3); a check that could not reach Vault runs again next time.
func (v *Vault) ensurePolicy(ctx context.Context) error {
	if v.policyOK.Load() {
		return nil
	}
	v.policyMu.Lock()
	defer v.policyMu.Unlock()
	if v.policyOK.Load() {
		return nil
	}
	if err := v.checkPolicy(ctx); err != nil {
		return err
	}
	v.policyOK.Store(true)
	return nil
}

func (v *Vault) checkPolicy(ctx context.Context) error {
	status, resp, err := v.api.call(ctx, "sys/capabilities-self", map[string]any{"paths": []string{v.encPath, v.decPath}})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return classifyVault("capabilities-self", status, resp.Errors)
	}
	enc := capabilitySet(resp.Data[v.encPath])
	dec := capabilitySet(resp.Data[v.decPath])
	for _, c := range []string{"create", "sudo", "root"} {
		if enc[c] {
			return fmt.Errorf("%w: the token has %q on %s; Transit would recreate a deleted key on encrypt and undo a revoke, so grant only \"update\"", errVaultPolicy, c, v.encPath)
		}
	}
	if !enc["update"] || !dec["update"] {
		return fmt.Errorf("%w: the token needs \"update\" on %s and %s", errVaultPolicy, v.encPath, v.decPath)
	}
	return nil
}

func capabilitySet(raw any) map[string]bool {
	out := map[string]bool{}
	list, _ := raw.([]any)
	for _, c := range list {
		if s, ok := c.(string); ok {
			out[s] = true
		}
	}
	return out
}

// IsVaultPolicyError reports whether err is the boot refusal for a token with
// more than update on the Transit paths.
func IsVaultPolicyError(err error) bool { return errors.Is(err, errVaultPolicy) }

type backgroundPurposeKey struct{}

// ContextWithBackgroundPurpose names a call with no request behind it (boot,
// recheck, sweep). The key store then sees the correlation id
// "aerolvm-background:<purpose>:<node-id>", recognisable in its audit log
// though it joins to no sandboxd event.
func ContextWithBackgroundPurpose(ctx context.Context, purpose string) context.Context {
	return context.WithValue(ctx, backgroundPurposeKey{}, purpose)
}

// correlationID is the value of CorrelationHeader for ctx, or "" for none. A
// request's id comes from the caller's header, so one with characters a
// header must not carry is dropped rather than forwarded.
func correlationID(ctx context.Context, nodeID string) string {
	if id := auditlog.CorrelationIDFromContext(ctx); id != "" {
		if safeCorrelationIDs.MatchString(id) {
			return id
		}
		return ""
	}
	if p, _ := ctx.Value(backgroundPurposeKey{}).(string); p != "" {
		return "aerolvm-background:" + p + ":" + nodeID
	}
	return ""
}

// vaultHTTP is the net/http vaultAPI (eng D11: no HashiCorp client module in
// the secrets package).
type vaultHTTP struct {
	base      string
	namespace string
	nodeID    string
	client    *http.Client
	token     *tokenFile // nil: Vault Agent's proxy adds the token
}

func (h *vaultHTTP) call(ctx context.Context, path string, body any) (int, vaultResponse, error) {
	token, err := h.currentToken(false)
	if err != nil {
		return 0, vaultResponse{}, err
	}
	status, resp, err := h.once(ctx, path, body, token)
	if err == nil && status == http.StatusForbidden && h.token != nil {
		// Agent may have renewed the token since the last read: read the file
		// once more before reporting denied.
		if fresh, terr := h.currentToken(true); terr == nil && fresh != token {
			return h.once(ctx, path, body, fresh)
		}
	}
	return status, resp, err
}

func (h *vaultHTTP) currentToken(force bool) (string, error) {
	if h.token == nil {
		return "", nil
	}
	return h.token.get(force)
}

func (h *vaultHTTP) once(ctx context.Context, path string, body any, token string) (int, vaultResponse, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, vaultResponse{}, fmt.Errorf("encode vault request: %w", err)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, vaultCallTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.base+"/v1/"+path, bytes.NewReader(payload))
	if err != nil {
		return 0, vaultResponse{}, fmt.Errorf("%w: build vault request: %v", ErrProviderUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Request", "true")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if h.namespace != "" {
		req.Header.Set("X-Vault-Namespace", h.namespace)
	}
	if id := correlationID(ctx, h.nodeID); id != "" {
		req.Header.Set(CorrelationHeader, id)
	}
	res, err := h.client.Do(req)
	if err != nil {
		return 0, vaultResponse{}, fmt.Errorf("%w: vault %s: %v", ErrProviderUnavailable, path, err)
	}
	defer res.Body.Close()
	var out vaultResponse
	raw, err := io.ReadAll(io.LimitReader(res.Body, vaultMaxResponseBytes))
	if err != nil {
		return 0, vaultResponse{}, fmt.Errorf("%w: read vault %s reply: %v", ErrProviderUnavailable, path, err)
	}
	// A body that is not JSON (a proxy's HTML error page) leaves out empty;
	// the status still classifies the reply.
	_ = json.Unmarshal(raw, &out)
	return res.StatusCode, out, nil
}

// tokenFile is the token Vault Agent's auto-auth writes. It is re-read when
// the file changes, and once more after a 403 (Agent may have just renewed
// it). sandboxd never reads VAULT_TOKEN from its environment.
type tokenFile struct {
	path    string
	mu      sync.Mutex
	token   string
	modTime time.Time
	size    int64
}

func (t *tokenFile) get(force bool) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fi, err := os.Stat(t.path)
	if err != nil {
		return "", fmt.Errorf("%w: SB_SECRET_VAULT_TOKEN_FILE: %v", ErrProviderUnavailable, err)
	}
	if !force && t.token != "" && fi.ModTime().Equal(t.modTime) && fi.Size() == t.size {
		return t.token, nil
	}
	raw, err := os.ReadFile(t.path)
	if err != nil {
		return "", fmt.Errorf("%w: SB_SECRET_VAULT_TOKEN_FILE: %v", ErrProviderUnavailable, err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", fmt.Errorf("%w: SB_SECRET_VAULT_TOKEN_FILE %s is empty", ErrProviderUnavailable, t.path)
	}
	t.token, t.modTime, t.size = tok, fi.ModTime(), fi.Size()
	return tok, nil
}
