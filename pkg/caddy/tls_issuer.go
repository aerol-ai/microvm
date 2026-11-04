package caddy

import (
	"encoding/json"
	"slices"
)

// TLSIssuer is the issuer of the on-demand TLS policy that serves custom
// domains. The zero value is public ACME (Let's Encrypt, ZeroSSL), as
// before. On a network with no route to them, an internal ACME CA (a bank
// PKI, step-ca) or Caddy's own CA issues instead
// (plans/egress-domain-filtering.md §5.10 PC-5).
type TLSIssuer struct {
	// Internal selects Caddy's own CA, for labs; CA and TrustedRoot are
	// unused.
	Internal bool
	// CA is an ACME directory URL.
	CA string
	// TrustedRoot is a PEM file Caddy trusts when it talks to CA.
	TrustedRoot string
}

// config is the issuer's Caddy JSON.
func (i TLSIssuer) config() map[string]any {
	if i.Internal {
		return map[string]any{"module": "internal"}
	}
	m := map[string]any{"module": "acme"}
	if i.CA != "" {
		m["ca"] = i.CA
	}
	if i.TrustedRoot != "" {
		m["trusted_roots_pem_files"] = []string{i.TrustedRoot}
	}
	return m
}

// matches reports whether a stored issuers list is already this issuer. It
// compares only the fields the issuer sets, so an operator's additions stay.
// A policy with no issuers uses Caddy's defaults, which are public ACME.
func (i TLSIssuer) matches(stored json.RawMessage) bool {
	var issuers []struct {
		Module       string   `json:"module"`
		CA           string   `json:"ca"`
		TrustedRoots []string `json:"trusted_roots_pem_files"`
	}
	if len(stored) == 0 || string(stored) == "null" {
		return i == TLSIssuer{}
	}
	if json.Unmarshal(stored, &issuers) != nil || len(issuers) != 1 {
		return false
	}
	got := issuers[0]
	if i.Internal {
		return got.Module == "internal"
	}
	var roots []string
	if i.TrustedRoot != "" {
		roots = []string{i.TrustedRoot}
	}
	return got.Module == "acme" && got.CA == i.CA && slices.Equal(got.TrustedRoots, roots)
}
