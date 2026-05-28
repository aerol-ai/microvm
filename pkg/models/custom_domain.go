package models

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
)

// CustomDomainStatus is the per-domain lifecycle state surfaced through the
// API + SDK so callers can render "DNS not pointed yet" vs "issuing cert" vs
// "ready" without polling Caddy. Driven entirely server-side; clients read.
type CustomDomainStatus string

const (
	// CustomDomainPendingDNS — row exists, Caddy has not yet asked for the
	// hostname. This is the state after AddCustomDomain returns and before
	// the first inbound HTTPS connection.
	CustomDomainPendingDNS CustomDomainStatus = "pending_dns"
	// CustomDomainIssuing — first ask hit, ACME flow started. Cleared on the
	// next ask that sees the cert in storage.
	CustomDomainIssuing CustomDomainStatus = "issuing"
	// CustomDomainReady — cert in shared storage, serving connections.
	CustomDomainReady CustomDomainStatus = "ready"
	// CustomDomainFailed — Caddy gave up on ACME for this host (LastError
	// carries the surfaced reason). No automatic retry beyond Caddy's own
	// backoff; the next ask will flip it back to issuing.
	CustomDomainFailed CustomDomainStatus = "failed"
)

// CustomDomain is the per-domain row returned in Sandbox.CustomDomains.
type CustomDomain struct {
	Hostname string             `json:"hostname"`
	Status   CustomDomainStatus `json:"status"`
	// TargetPort is the in-container TCP port traffic for this hostname
	// reverse-proxies to. Zero means "use the toolbox port" (the legacy
	// behavior before per-domain target ports existed). Non-zero values
	// dial straight to the user's app — e.g. an HTTP server on 3333.
	// Set once at attach time; changing it requires detach + re-add so
	// in-flight traffic can't silently redirect.
	TargetPort int       `json:"target_port,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AddCustomDomainRequest is the body for POST /v1/sandboxes/{id}/custom-domains.
// Omitting target_port (or sending 0) routes the hostname to the toolbox
// agent, preserving pre-v2 behavior.
type AddCustomDomainRequest struct {
	Hostname   string `json:"hostname"`
	TargetPort int    `json:"target_port,omitempty"`
}

// Custom-domain caps. Exported so internal/config can read SB_ env overrides
// against these defaults and the service layer can reference the canonical
// numbers from one place.
const (
	// MaxCustomDomainsPerSandbox bounds the host matcher fan-out per route.
	// 25 keeps the Caddy host-list small and matches the value documented in
	// plans/custom-domains.md.
	MaxCustomDomainsPerSandbox = 25
	// MaxCustomDomainsPerCreateRequest bounds how many hostnames a single
	// CreateSandbox call can attach. Lower than the per-sandbox cap so an
	// accidental array doesn't burn the ACME budget all at once.
	MaxCustomDomainsPerCreateRequest = 5
)

var (
	// ErrCustomDomainInvalid is the validation error returned by
	// NormalizeCustomDomain. Wrapped with context (the offending hostname /
	// reason) so the API surfaces something actionable.
	ErrCustomDomainInvalid = errors.New("invalid custom domain")
	// ErrCustomDomainPerRequestCap is returned by ValidateCustomDomainList
	// when the caller passes too many hostnames in a single create request.
	ErrCustomDomainPerRequestCap = fmt.Errorf("at most %d custom_domains per create request", MaxCustomDomainsPerCreateRequest)
	// ErrCustomDomainNotSupported is returned when a deployment cannot accept
	// custom domains at all: the feature flag is off, or the daemon is running
	// in IP mode (no SB_DOMAIN). Surfaced as HTTP 412 Precondition Failed so
	// clients can distinguish "this cluster does not do custom domains" from
	// "your input is malformed" (which is 400).
	ErrCustomDomainNotSupported = errors.New("custom domains are not enabled on this deployment")
	// ErrCustomDomainProtocolConflict is the IRON RULE violation: a sandbox
	// with custom domains attached must not also expose protocol=tcp/tls
	// ports, because the L4 listener has no way to honor a host-based match
	// — the SNI would route to the wrong sandbox. Surfaced as 409 Conflict.
	ErrCustomDomainProtocolConflict = errors.New("custom domains cannot coexist with tcp/tls exposed ports on the same sandbox")
	// ErrCustomDomainPerSandboxCap is returned by AddCustomDomain when the
	// sandbox already holds MaxCustomDomainsPerSandbox rows. Surfaced as 409.
	ErrCustomDomainPerSandboxCap = fmt.Errorf("at most %d custom domains per sandbox", MaxCustomDomainsPerSandbox)
	// ErrCustomDomainVerificationFailed is returned when the DNS TXT record check fails.
	ErrCustomDomainVerificationFailed = errors.New("custom domain TXT record verification failed")
	// ErrCustomDomainInvalidTargetPort is returned when AddCustomDomainRequest
	// carries a target_port outside [0, 65535]. Zero is the toolbox-default
	// sentinel; anything else must be a real TCP port number. Surfaced as 400.
	ErrCustomDomainInvalidTargetPort = errors.New("invalid custom domain target_port")
	// ErrCustomDomainPortMismatch is returned when an idempotent re-add of
	// an already-attached hostname carries a different target_port than the
	// existing row. We do not silently change the dial target — that would
	// redirect live traffic without the caller knowing. Surfaced as 409 so
	// the caller can detach + re-add deliberately.
	ErrCustomDomainPortMismatch = errors.New("custom domain target_port mismatch on re-add")
)

// ValidateCustomDomainTargetPort returns nil for 0 (the toolbox sentinel)
// and any 1..65535. Anything else is ErrCustomDomainInvalidTargetPort. Kept
// alongside the other custom-domain validators so the API + service layers
// reference one canonical bound.
func ValidateCustomDomainTargetPort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("%w: %d (must be 0 or 1..65535)", ErrCustomDomainInvalidTargetPort, port)
	}
	return nil
}

// NormalizeCustomDomain lowercases, strips a trailing dot, and validates the
// shape of host. baseDomain is the operator's SB_DOMAIN — empty means the
// daemon is in IP mode, in which case the caller is expected to reject the
// request at the 412 layer before reaching validation. We still validate the
// hostname shape so callers cannot rely on the IP-mode short-circuit.
//
// Returns the canonical (lowercased, dotted-trimmed) hostname on success.
//
// Rejection rules (each maps to a test in types_test.go):
//   - empty or whitespace-only
//   - any label > 63 chars
//   - total length > 253 chars
//   - non-RFC1035 label charset (letters, digits, hyphen; no leading/trailing
//     hyphen on a label)
//   - fewer than two labels (single-label is not a public hostname)
//   - IP literal (v4 or v6)
//   - "localhost" or anything ending in ".local"
//   - anything under baseDomain — wildcard already covers it; allowing a
//     custom-domain row would let one tenant steal another sandbox's URL
func NormalizeCustomDomain(host, baseDomain string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("%w: empty hostname", ErrCustomDomainInvalid)
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", fmt.Errorf("%w: empty hostname", ErrCustomDomainInvalid)
	}
	if len(host) > 253 {
		return "", fmt.Errorf("%w: %q exceeds 253 characters", ErrCustomDomainInvalid, host)
	}
	if host == "localhost" || strings.HasSuffix(host, ".local") {
		return "", fmt.Errorf("%w: %q is a reserved local name", ErrCustomDomainInvalid, host)
	}
	// net.ParseIP("::1") returns non-nil for IPv6; same for bare v4. Reject
	// before the label scan so error messages name the actual problem.
	if ip := net.ParseIP(host); ip != nil {
		return "", fmt.Errorf("%w: %q is an IP literal", ErrCustomDomainInvalid, host)
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: %q is not a public hostname (single label)", ErrCustomDomainInvalid, host)
	}
	for _, label := range labels {
		if err := validateLabel(label); err != nil {
			return "", fmt.Errorf("%w: %s", ErrCustomDomainInvalid, err.Error())
		}
	}
	if base := strings.ToLower(strings.TrimSpace(baseDomain)); base != "" {
		base = strings.TrimSuffix(base, ".")
		if host == base || strings.HasSuffix(host, "."+base) {
			return "", fmt.Errorf("%w: %q is under the deployment base domain %q (the wildcard already covers it)", ErrCustomDomainInvalid, host, base)
		}
	}
	return host, nil
}

func validateLabel(label string) error {
	if label == "" {
		return fmt.Errorf("empty label")
	}
	if len(label) > 63 {
		return fmt.Errorf("label %q exceeds 63 characters", label)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("label %q must not start or end with '-'", label)
	}
	for _, r := range label {
		if r == '-' || unicode.IsDigit(r) {
			continue
		}
		if r >= 'a' && r <= 'z' {
			continue
		}
		return fmt.Errorf("label %q contains invalid character %q", label, r)
	}
	return nil
}

// ValidateCustomDomainList normalizes every entry in hosts against baseDomain
// and enforces the per-create-request cap and intra-list uniqueness. Returns
// the canonical slice or the first error. Empty input returns nil, nil — the
// caller treats "no custom domains" the same as omitting the field.
func ValidateCustomDomainList(hosts []string, baseDomain string) ([]string, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	if len(hosts) > MaxCustomDomainsPerCreateRequest {
		return nil, ErrCustomDomainPerRequestCap
	}
	out := make([]string, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		canon, err := NormalizeCustomDomain(h, baseDomain)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[canon]; dup {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canon)
	}
	return out, nil
}
