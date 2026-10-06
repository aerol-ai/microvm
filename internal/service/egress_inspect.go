package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/inspect"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// TLS inspection's node CA (plans/egress-domain-filtering.md §5.9, P3-1).
// sandboxd creates it the first time a sandbox asks for inspection, keeps
// the key sealed with the node cipher, and hands it to the gateway, which
// mints leaves from it. A sandbox created with inspect rules gets the CA
// certificate and environment that point its TLS clients at a bundle of
// its own trust store plus the CA; nothing else trusts it. A failover
// recreate builds the bundle again from the new node's CA, so trust follows
// the node that terminates TLS.

// ErrEgressInspectRecreate is a live policy change that adds an inspect
// rule to a container sandbox created without one: trusting the node's CA
// is set up at create (409).
var ErrEgressInspectRecreate = errors.New("recreate the sandbox with inspect rules: trusting the egress gateway's CA is set up at create")

// Paths inside an inspect sandbox. toolboxd builds the bundle at start, in a
// small tmpfs any user can write, from the image's own trust store and the
// CA, so the image's custom CAs keep working.
const (
	inspectCAPath     = "/etc/aerolvm/egress-ca.pem"
	inspectBundleDir  = "/run/aerolvm"
	inspectBundlePath = "/run/aerolvm/ca-bundle.pem"
)

// inspectEnv points TLS clients at the bundle. A variable the create already
// sets wins: the owner chose their own trust store (Java's is a known gap).
var inspectEnv = map[string]string{
	"SSL_CERT_FILE":            inspectBundlePath,
	"REQUESTS_CA_BUNDLE":       inspectBundlePath,
	"PIP_CERT":                 inspectBundlePath,
	"CURL_CA_BUNDLE":           inspectBundlePath,
	"NODE_EXTRA_CA_CERTS":      inspectCAPath,
	"AEROLVM_EGRESS_CA":        inspectCAPath,
	"AEROLVM_EGRESS_CA_BUNDLE": inspectBundlePath,
}

// egressCARecord is the CA at rest: the certificate in clear, the key
// sealed.
type egressCARecord struct {
	CertPEM   string `json:"cert_pem"`
	SealedKey []byte `json:"sealed_key"`
}

func (s *Service) egressCADir() string {
	return filepath.Join(filepath.Dir(s.cfg.DBPath), "egress-ca")
}

func (s *Service) egressCACertPath() string { return filepath.Join(s.egressCADir(), "node-ca.pem") }

// ensureEgressCA returns the node CA, creating it on first use. Same lazy
// single-flight shape as EnsureLayer4Ready: the pointer is the latch.
func (s *Service) ensureEgressCA() (egress.InspectCA, error) {
	if ca := s.egressCA.Load(); ca != nil {
		return *ca, nil
	}
	s.egressCAMu.Lock()
	defer s.egressCAMu.Unlock()
	if ca := s.egressCA.Load(); ca != nil {
		return *ca, nil
	}
	ca, ok, err := s.loadEgressCA()
	if err != nil {
		return egress.InspectCA{}, err
	}
	if !ok {
		if ca, err = s.createEgressCA(); err != nil {
			return egress.InspectCA{}, err
		}
	}
	s.egressCA.Store(&ca)
	return ca, nil
}

// loadEgressCA reads the CA from disk; ok is false when there is none yet.
func (s *Service) loadEgressCA() (egress.InspectCA, bool, error) {
	if ca := s.egressCA.Load(); ca != nil {
		return *ca, true, nil
	}
	raw, err := os.ReadFile(filepath.Join(s.egressCADir(), "ca.json"))
	if errors.Is(err, os.ErrNotExist) {
		return egress.InspectCA{}, false, nil
	}
	if err != nil {
		return egress.InspectCA{}, false, fmt.Errorf("egress inspection CA: %w", err)
	}
	var rec egressCARecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return egress.InspectCA{}, false, fmt.Errorf("egress inspection CA: %w", err)
	}
	if s.cipher == nil {
		return egress.InspectCA{}, false, errors.New("egress inspection CA: no node cipher to open its key")
	}
	key, err := s.cipher.Decrypt(rec.SealedKey)
	if err != nil {
		return egress.InspectCA{}, false, fmt.Errorf("egress inspection CA key: %w", err)
	}
	ca := egress.InspectCA{CertPEM: []byte(rec.CertPEM), KeyPEM: key}
	// The certificate sandboxes mount must exist even if only ca.json
	// survived (a restore, a hand-copied state dir).
	if err := writeFileAtomic(s.egressCACertPath(), ca.CertPEM, 0o644); err != nil {
		return egress.InspectCA{}, false, err
	}
	return ca, true, nil
}

func (s *Service) createEgressCA() (egress.InspectCA, error) {
	if s.cipher == nil {
		return egress.InspectCA{}, errors.New("egress inspection needs the node cipher to seal its CA key")
	}
	name := "aerolvm-node"
	if c := s.Cluster(); c != nil && c.SelfNodeID() != "" {
		name = c.SelfNodeID()
	}
	certPEM, keyPEM, err := inspect.GenerateCA("AerolVM egress inspection CA ("+name+")", time.Now())
	if err != nil {
		return egress.InspectCA{}, err
	}
	sealed, err := s.cipher.Encrypt(keyPEM)
	if err != nil {
		return egress.InspectCA{}, fmt.Errorf("seal egress inspection CA key: %w", err)
	}
	raw, _ := json.Marshal(egressCARecord{CertPEM: string(certPEM), SealedKey: sealed})
	if err := os.MkdirAll(s.egressCADir(), 0o700); err != nil {
		return egress.InspectCA{}, fmt.Errorf("egress inspection CA: %w", err)
	}
	// The certificate first: a crash between the writes leaves no record,
	// and the next create makes a fresh CA.
	if err := writeFileAtomic(s.egressCACertPath(), certPEM, 0o644); err != nil {
		return egress.InspectCA{}, err
	}
	if err := writeFileAtomic(filepath.Join(s.egressCADir(), "ca.json"), raw, 0o600); err != nil {
		return egress.InspectCA{}, err
	}
	s.logger.Info("egress: created the node's TLS inspection CA", "path", s.egressCACertPath())
	return egress.InspectCA{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("egress inspection CA: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return fmt.Errorf("egress inspection CA: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("egress inspection CA: %w", err)
	}
	return nil
}

// pushEgressCA hands the gateway the CA once per gateway connection; the
// gateway keeps it in memory only. Callers hold egressMu or run before any
// attach that needs it.
func (s *Service) pushEgressCA(ctx context.Context, ca egress.InspectCA) error {
	if s.egressCAPushed.Load() {
		return nil
	}
	if err := s.egressGateway().SetInspectCA(ctx, ca); err != nil {
		return fmt.Errorf("%w: hand the gateway its inspection CA: %v", ErrEgressGatewayUnavailable, err)
	}
	s.egressCAPushed.Store(true)
	return nil
}

// resyncEgressCA sends an existing CA to a gateway that just (re)connected,
// before its Sync, so inspect sandboxes it re-attaches are never left
// without one. A node that never inspected has nothing to send.
func (s *Service) resyncEgressCA(ctx context.Context) error {
	s.egressCAPushed.Store(false)
	ca, ok, err := s.loadEgressCA()
	if err != nil || !ok {
		return err
	}
	s.egressCA.Store(&ca)
	return s.pushEgressCA(ctx, ca)
}

// prepareInspect readies a container create with inspect rules: the CA
// exists and the gateway has it, and the sandbox gets the CA file, the
// bundle's tmpfs and the environment. Runs before the runtime create; the
// first inspect create on a node also pays the CA generation.
func (s *Service) prepareInspect(ctx context.Context, env map[string]string) ([]mounts.ContainerBind, map[string]string, error) {
	ca, err := s.ensureEgressCA()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrEgressGatewayUnavailable, err)
	}
	if err := s.EnsureEgressGatewayReady(ctx); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrEgressGatewayUnavailable, err)
	}
	if err := s.pushEgressCA(ctx, ca); err != nil {
		return nil, nil, err
	}
	out := maps.Clone(env)
	if out == nil {
		out = map[string]string{}
	}
	for k, v := range inspectEnv {
		if _, set := out[k]; !set {
			out[k] = v
		}
	}
	binds := []mounts.ContainerBind{
		{HostPath: s.egressCACertPath(), ContainerPath: inspectCAPath, ReadOnly: true},
		{ContainerPath: inspectBundleDir, Tmpfs: true},
	}
	return binds, out, nil
}
