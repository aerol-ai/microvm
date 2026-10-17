package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// The identity file (SB_IDENTITY_FILE, plans/identity-and-access.md §5.5):
// which identity providers this node trusts, and which role each provider
// group, app role or claim grants. Bindings live in a file, not in Raft, so
// they are reviewable and shipped like the egress operator file (Terraform,
// Ansible, GitOps). The schema is strict: an unknown key fails the load,
// because a typo in a security file must never silently mean "not set".

// FileVersion is the only identity-file format this build reads.
const FileVersion = 1

// Size and length caps. A 1 MiB file is roughly 10k bindings, the worst case
// the verified-token cache is sized for (eng review E8).
const (
	MaxFileBytes = 1 << 20
	// maxDisplayNameRunes caps the dashboard button label (design review
	// DR3: 1–40 characters).
	maxDisplayNameRunes = 40
	maxIssuerNameLen    = 63
	maxTeamNameLen      = 63
	// DefaultMaxTokenLifetime refuses long-lived workload tokens unless an
	// operator raises it per issuer, while fitting provider ID tokens
	// (~1 h), GitHub Actions tokens (minutes) and projected service-account
	// tokens (1 h) (CEO review finding 9.1).
	DefaultMaxTokenLifetime = 24 * time.Hour
	maxMaxTokenLifetime     = 365 * 24 * time.Hour
)

// Claim names an issuer reads when the file names none.
const (
	defaultUsernameClaim = "sub"
	defaultGroupsClaim   = "groups"
	defaultRolesClaim    = "roles"
)

var (
	// ErrEmptyFile refuses a file with no document (CEO review finding
	// 4.3). Tokens-only mode is SB_IDENTITY_FILE unset, not an empty file,
	// so an empty file is a broken deploy, never a quiet "no SSO".
	ErrEmptyFile = errors.New("identity file is empty: unset SB_IDENTITY_FILE for tokens-only mode")
	// ErrFileTooLarge refuses a file over MaxFileBytes (finding 5.5).
	ErrFileTooLarge = fmt.Errorf("identity file is larger than %d bytes", MaxFileBytes)
)

// File is the YAML document as written.
type File struct {
	Version      int           `yaml:"version"`
	Issuers      []FileIssuer  `yaml:"issuers"`
	Bindings     []FileBinding `yaml:"bindings"`
	DenySubjects []string      `yaml:"deny_subjects"`
	MCP          *FileMCP      `yaml:"mcp"`
}

// FileIssuer is one identity provider as written.
type FileIssuer struct {
	Name         string   `yaml:"name"`
	DisplayName  string   `yaml:"display_name"`
	Kind         string   `yaml:"kind"`
	URL          string   `yaml:"url"`
	JWKSFile     string   `yaml:"jwks_file"`
	Audiences    []string `yaml:"audiences"`
	MCPAudiences []string `yaml:"mcp_audiences"`
	Clients      struct {
		CLI       string `yaml:"cli"`
		Dashboard string `yaml:"dashboard"`
	} `yaml:"clients"`
	Claims struct {
		Username string `yaml:"username"`
		Groups   string `yaml:"groups"`
		Roles    string `yaml:"roles"`
	} `yaml:"claims"`
	MaxTokenLifetime string `yaml:"max_token_lifetime"`
	MCP              bool   `yaml:"mcp"`
}

// FileBinding is one binding as written: exactly one matcher (group,
// app_role or claim), the role it grants and the team it grants it on.
type FileBinding struct {
	Issuer  string            `yaml:"issuer"`
	Group   string            `yaml:"group"`
	AppRole string            `yaml:"app_role"`
	Claim   map[string]string `yaml:"claim"`
	Role    string            `yaml:"role"`
	Team    string            `yaml:"team"`
}

// FileMCP is the remote-MCP section (§5.14, task T13).
type FileMCP struct {
	Resource string `yaml:"resource"`
}

// Config is a validated identity file. It is immutable once Parse returns:
// the verifier, the discovery document and the reload diff all read it
// concurrently.
type Config struct {
	Issuers  []*Issuer
	Bindings []*Binding
	// MCPResource is the one protected-resource URL for /mcp (RFC 9728).
	MCPResource string

	deny   map[string]struct{} // "<issuer>:<sub>"
	byName map[string]*Issuer
	byURL  map[string]*Issuer
	hash   string
}

// Issuer is one trusted identity provider.
type Issuer struct {
	// Name is stable: it is part of every principal id this issuer mints
	// (oidc:<name>:<sub>).
	Name string
	// DisplayName is the dashboard button label; it falls back to Name and
	// is never used in principal ids or audit records (DR3).
	DisplayName string
	Kind        string
	// URL must equal the token's iss exactly, so it is kept as written.
	URL      string
	JWKSFile string
	// Audiences are the ID-token and workload-token audiences accepted on
	// every route. MCPAudiences are OAuth access-token audiences accepted
	// only on /mcp (T13); the two never overlap.
	Audiences        []string
	MCPAudiences     []string
	ClientCLI        string
	ClientDashboard  string
	UsernameClaim    string
	GroupsClaim      string
	RolesClaim       string
	MaxTokenLifetime time.Duration
	MCP              bool

	audiences map[string]struct{}
	// bindings are this issuer's bindings in file order, so matching a
	// token scans only its own issuer's rules.
	bindings []*Binding
}

// Binding grants Role on Team (or every team, controlplane.FleetTeam) to a
// token whose claims match it. Bindings are tried top to bottom and every
// match is kept: the first is the default, X-AerolVM-Team picks another.
type Binding struct {
	Issuer  string
	Group   string
	AppRole string
	// Claim requires every listed claim to equal its value (a list claim
	// must contain it). claimKeys is Claim's keys in sorted order.
	Claim     map[string]string
	claimKeys []string
	Role      controlplane.Role
	Team      string
}

// Load reads and validates path, refusing a file over MaxFileBytes before
// it is fully read.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("identity file: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("identity file: %w", err)
	}
	return Parse(raw)
}

// Parse validates an identity document.
func Parse(raw []byte) (*Config, error) {
	if len(raw) > MaxFileBytes {
		observeOversize(oversizeIdentityFile)
		return nil, ErrFileTooLarge
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrEmptyFile
		}
		return nil, fmt.Errorf("identity file: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("identity file: holds more than one YAML document")
	}
	if f.Version != FileVersion {
		return nil, fmt.Errorf("identity file: version %d, want %d", f.Version, FileVersion)
	}
	if len(f.Issuers) == 0 {
		return nil, errors.New("identity file: no issuers; unset SB_IDENTITY_FILE for tokens-only mode")
	}
	sum := sha256.Sum256(raw)
	c := &Config{
		deny:   map[string]struct{}{},
		byName: map[string]*Issuer{},
		byURL:  map[string]*Issuer{},
		hash:   hex.EncodeToString(sum[:]),
	}
	if f.MCP != nil {
		res := strings.TrimSpace(f.MCP.Resource)
		if res != "" {
			if err := checkHTTPSURL(res); err != nil {
				return nil, fmt.Errorf("identity file: mcp.resource: %w", err)
			}
		}
		c.MCPResource = res
	}
	for i := range f.Issuers {
		iss, err := parseIssuer(f.Issuers[i], c.MCPResource)
		if err != nil {
			return nil, fmt.Errorf("identity file: issuers[%d]: %w", i, err)
		}
		if _, dup := c.byName[iss.Name]; dup {
			return nil, fmt.Errorf("identity file: issuers[%d]: name %q is used twice", i, iss.Name)
		}
		if other, dup := c.byURL[iss.URL]; dup {
			return nil, fmt.Errorf("identity file: issuers[%d]: url %s is already issuer %q; a token's iss must name one issuer", i, iss.URL, other.Name)
		}
		c.byName[iss.Name] = iss
		c.byURL[iss.URL] = iss
		c.Issuers = append(c.Issuers, iss)
	}
	for i := range f.Bindings {
		b, err := parseBinding(f.Bindings[i], c.byName)
		if err != nil {
			return nil, fmt.Errorf("identity file: bindings[%d]: %w", i, err)
		}
		c.Bindings = append(c.Bindings, b)
		iss := c.byName[b.Issuer]
		iss.bindings = append(iss.bindings, b)
	}
	for i, raw := range f.DenySubjects {
		subject := strings.TrimSpace(raw)
		issuer, sub, ok := strings.Cut(subject, ":")
		if !ok || sub == "" {
			return nil, fmt.Errorf("identity file: deny_subjects[%d]: %q is not <issuer>:<sub>", i, raw)
		}
		if _, known := c.byName[issuer]; !known {
			return nil, fmt.Errorf("identity file: deny_subjects[%d]: unknown issuer %q", i, issuer)
		}
		c.deny[subject] = struct{}{}
	}
	return c, nil
}

func parseIssuer(fi FileIssuer, mcpResource string) (*Issuer, error) {
	iss := &Issuer{
		Name:            strings.TrimSpace(fi.Name),
		Kind:            strings.TrimSpace(fi.Kind),
		URL:             strings.TrimSpace(fi.URL),
		JWKSFile:        strings.TrimSpace(fi.JWKSFile),
		ClientCLI:       strings.TrimSpace(fi.Clients.CLI),
		ClientDashboard: strings.TrimSpace(fi.Clients.Dashboard),
		UsernameClaim:   claimName(fi.Claims.Username, defaultUsernameClaim),
		GroupsClaim:     claimName(fi.Claims.Groups, defaultGroupsClaim),
		RolesClaim:      claimName(fi.Claims.Roles, defaultRolesClaim),
		MCP:             fi.MCP,
		audiences:       map[string]struct{}{},
	}
	if !validSlug(iss.Name, maxIssuerNameLen) {
		return nil, fmt.Errorf("name %q: want 1 to %d characters of a-z, 0-9 and -", fi.Name, maxIssuerNameLen)
	}
	display, err := displayName(fi.DisplayName)
	if err != nil {
		return nil, fmt.Errorf("issuer %s: display_name: %w", iss.Name, err)
	}
	iss.DisplayName = display
	if iss.DisplayName == "" {
		iss.DisplayName = iss.Name
	}
	switch iss.Kind {
	case "":
		iss.Kind = identitywire.IssuerKindOIDC
	case identitywire.IssuerKindOIDC, identitywire.IssuerKindGoogle:
	default:
		return nil, fmt.Errorf("issuer %s: kind %q: want oidc or google", iss.Name, iss.Kind)
	}
	if err := checkHTTPSURL(iss.URL); err != nil {
		return nil, fmt.Errorf("issuer %s: url: %w", iss.Name, err)
	}
	if len(fi.Audiences) == 0 {
		return nil, fmt.Errorf("issuer %s: audiences: at least one is required", iss.Name)
	}
	for _, a := range fi.Audiences {
		a = strings.TrimSpace(a)
		if a == "" {
			return nil, fmt.Errorf("issuer %s: audiences: an audience is empty", iss.Name)
		}
		if _, dup := iss.audiences[a]; dup {
			return nil, fmt.Errorf("issuer %s: audiences: %q is listed twice", iss.Name, a)
		}
		iss.audiences[a] = struct{}{}
		iss.Audiences = append(iss.Audiences, a)
	}
	mcpSeen := map[string]struct{}{}
	for _, a := range fi.MCPAudiences {
		a = strings.TrimSpace(a)
		if a == "" {
			return nil, fmt.Errorf("issuer %s: mcp_audiences: an audience is empty", iss.Name)
		}
		// An access token is told apart from an ID token by audience alone
		// (§5.14): an overlap would let an MCP-only token act on /v1.
		if _, overlap := iss.audiences[a]; overlap {
			return nil, fmt.Errorf("issuer %s: mcp_audiences: %q is also in audiences; the two must not overlap", iss.Name, a)
		}
		if _, dup := mcpSeen[a]; dup {
			return nil, fmt.Errorf("issuer %s: mcp_audiences: %q is listed twice", iss.Name, a)
		}
		mcpSeen[a] = struct{}{}
		iss.MCPAudiences = append(iss.MCPAudiences, a)
	}
	if iss.MCP {
		if iss.Kind == identitywire.IssuerKindGoogle {
			// Google issues opaque access tokens; checking one would need
			// an introspection call per request, which L2 rules out.
			return nil, fmt.Errorf("issuer %s: mcp: Google access tokens are opaque and cannot be checked offline", iss.Name)
		}
		if len(iss.MCPAudiences) == 0 {
			return nil, fmt.Errorf("issuer %s: mcp: true needs mcp_audiences", iss.Name)
		}
		if mcpResource == "" {
			return nil, fmt.Errorf("issuer %s: mcp: true needs the top-level mcp.resource", iss.Name)
		}
	}
	// A client id is the audience of the ID tokens it receives: one that is
	// not an accepted audience would sign people in only to refuse them.
	for _, client := range []struct{ name, id string }{{"clients.cli", iss.ClientCLI}, {"clients.dashboard", iss.ClientDashboard}} {
		if client.id == "" {
			continue
		}
		if _, ok := iss.audiences[client.id]; !ok {
			return nil, fmt.Errorf("issuer %s: %s %q is not in audiences; its ID tokens would be refused", iss.Name, client.name, client.id)
		}
	}
	iss.MaxTokenLifetime = DefaultMaxTokenLifetime
	if s := strings.TrimSpace(fi.MaxTokenLifetime); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 || d > maxMaxTokenLifetime {
			return nil, fmt.Errorf("issuer %s: max_token_lifetime %q: want a duration between 1s and 8760h", iss.Name, s)
		}
		iss.MaxTokenLifetime = d
	}
	return iss, nil
}

func parseBinding(fb FileBinding, issuers map[string]*Issuer) (*Binding, error) {
	b := &Binding{
		Issuer:  strings.TrimSpace(fb.Issuer),
		Group:   strings.TrimSpace(fb.Group),
		AppRole: strings.TrimSpace(fb.AppRole),
		Role:    controlplane.Role(strings.TrimSpace(fb.Role)),
		Team:    strings.TrimSpace(fb.Team),
	}
	if _, ok := issuers[b.Issuer]; !ok {
		return nil, fmt.Errorf("unknown issuer %q", fb.Issuer)
	}
	matchers := 0
	if b.Group != "" {
		matchers++
	}
	if b.AppRole != "" {
		matchers++
	}
	if len(fb.Claim) > 0 {
		matchers++
		b.Claim = make(map[string]string, len(fb.Claim))
		for k, v := range fb.Claim {
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if k == "" || v == "" {
				return nil, errors.New("claim: every claim needs a name and a value")
			}
			b.Claim[k] = v
			b.claimKeys = append(b.claimKeys, k)
		}
		sort.Strings(b.claimKeys)
	}
	// Exactly one matcher. A binding with none would grant its role to
	// every token the issuer mints, and for a public issuer like GitHub
	// Actions that is every repository in the world.
	if matchers != 1 {
		return nil, errors.New("set exactly one of group, app_role or claim")
	}
	if !b.Role.Valid() {
		return nil, fmt.Errorf("role %q: want viewer, runner, auditor or admin", fb.Role)
	}
	switch {
	case b.Team == "" && b.Role.RequiresFleet():
		// auditor and admin see the whole fleet by definition (§5.3).
		b.Team = controlplane.FleetTeam
	case b.Team == "":
		return nil, fmt.Errorf("team: role %s needs a team, or * for every team", b.Role)
	case b.Team == controlplane.FleetTeam:
	case !validSlug(b.Team, maxTeamNameLen):
		return nil, fmt.Errorf("team %q: want 1 to %d characters of a-z, 0-9 and -, or *", fb.Team, maxTeamNameLen)
	case b.Role.RequiresFleet():
		return nil, fmt.Errorf("team: role %s is bound to every team; use team: * or leave it out", b.Role)
	}
	return b, nil
}

// Hash is the SHA-256 of the file's bytes, hex: the value the
// aerolvm_identity_file_info metric and identity_config records carry, and
// what `sha256sum` prints for the same file.
func (c *Config) Hash() string { return c.hash }

// IssuerByName returns the issuer named name.
func (c *Config) IssuerByName(name string) (*Issuer, bool) {
	iss, ok := c.byName[name]
	return iss, ok
}

// issuerForIss returns the issuer whose URL is a token's iss. Google has
// always sent some ID tokens with the scheme-less "accounts.google.com";
// go-oidc accepts that one exception, so the lookup does too.
func (c *Config) issuerForIss(iss string) (*Issuer, bool) {
	if found, ok := c.byURL[iss]; ok {
		return found, true
	}
	if iss == "accounts.google.com" {
		found, ok := c.byURL["https://accounts.google.com"]
		return found, ok
	}
	return nil, false
}

// Denied reports whether "<issuer>:<sub>" is on the emergency deny list.
func (c *Config) Denied(issuer, sub string) bool {
	_, denied := c.deny[issuer+":"+sub]
	return denied
}

// DiscoveryIssuers is the issuer list GET /.well-known/aerolvm-auth
// publishes: issuers with a CLI or dashboard client id, in file order. A
// nil Config (no good file loaded yet) publishes none.
func (c *Config) DiscoveryIssuers() []identitywire.DiscoveryIssuer {
	if c == nil {
		return nil
	}
	out := make([]identitywire.DiscoveryIssuer, 0, len(c.Issuers))
	for _, iss := range c.Issuers {
		if iss.ClientCLI == "" && iss.ClientDashboard == "" {
			continue
		}
		out = append(out, identitywire.DiscoveryIssuer{
			Name:        iss.Name,
			DisplayName: iss.DisplayName,
			Kind:        iss.Kind,
			URL:         iss.URL,
			Clients:     identitywire.DiscoveryClients{CLI: iss.ClientCLI, Dashboard: iss.ClientDashboard},
		})
	}
	return out
}

func checkHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URL", raw)
	}
	// https only, verified against the system trust store like every other
	// TLS client on the host; there is no insecure switch (finding 5.4).
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q: want an https URL with no user, query or fragment", raw)
	}
	return nil
}

// displayName strips control characters and refuses a label over 40
// characters or one with nothing printable left (DR3). It is shown on a
// button, so a newline or terminal escape must not survive.
func displayName(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	var b strings.Builder
	for _, r := range raw {
		if unicode.IsControl(r) || r == utf8.RuneError {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "", errors.New("has no printable characters")
	}
	if n := utf8.RuneCountInString(out); n > maxDisplayNameRunes {
		return "", fmt.Errorf("%d characters, at most %d", n, maxDisplayNameRunes)
	}
	return out, nil
}

func claimName(raw, def string) string {
	if s := strings.TrimSpace(raw); s != "" {
		return s
	}
	return def
}

// validSlug reports whether s is 1..max characters of a-z, 0-9 and -.
func validSlug(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
