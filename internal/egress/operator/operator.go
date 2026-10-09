// Package operator loads the private-cloud egress operator file
// (plans/egress-domain-filtering.md §5.10, SB_EGRESS_OPERATOR_FILE). Both
// sandboxd (default policy, ceiling, org profiles, built-in switch, node
// control-port guard) and the egress gateway (internal zone, deny floor,
// upstream proxy) read it. Unset means today's behavior everywhere.
package operator

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// Version is the only file format version this build accepts.
const Version = 1

// Default policy modes.
const (
	ModeOpen      = "open"
	ModeBlockAll  = "block_all"
	ModeAllowlist = "allowlist"
)

// OrgProfilePrefix marks operator-defined profiles every tenant can use.
const OrgProfilePrefix = egresspolicy.OrgProfilePrefix

// File is the YAML document.
type File struct {
	Version      int `yaml:"version"`
	InternalZone struct {
		Suffixes []string `yaml:"suffixes"`
		CIDRs    []string `yaml:"cidrs"`
		Isolate  bool     `yaml:"isolate"`
	} `yaml:"internal_zone"`
	DefaultPolicy struct {
		Mode     string   `yaml:"mode"`
		AllowOut []string `yaml:"allow_out"`
	} `yaml:"default_policy"`
	Ceiling struct {
		AllowOut []string `yaml:"allow_out"`
	} `yaml:"ceiling"`
	DenyCIDRs            []string              `yaml:"deny_cidrs"`
	NodeControlPortGuard *bool                 `yaml:"node_control_port_guard"`
	BuiltinProfiles      *bool                 `yaml:"builtin_profiles"`
	OrgProfiles          map[string]OrgProfile `yaml:"org_profiles"`
	UpstreamProxy        struct {
		URL              string   `yaml:"url"`
		AuthFile         string   `yaml:"auth_file"`
		NoProxy          []string `yaml:"no_proxy"`
		SyntheticDNSCIDR string   `yaml:"synthetic_dns_cidr"`
	} `yaml:"upstream_proxy"`
}

// OrgProfile is one operator profile body.
type OrgProfile struct {
	AllowOut    []string `yaml:"allow_out"`
	Description string   `yaml:"description"`
}

// UpstreamProxy is the validated upstream proxy chain (§5.10 PC-4).
type UpstreamProxy struct {
	URL       *url.URL
	AuthFile  string
	NoProxy   []string
	Synthetic netip.Prefix
}

// Operator is a validated operator file.
type Operator struct {
	file      File
	zone      *egresspolicy.InternalZone
	floor     []netip.Prefix
	ceiling   *egresspolicy.Ceiling
	defPolicy *egresspolicy.Policy
	profiles  map[string]*egresspolicy.Policy
	upstream  *UpstreamProxy
	proxied   *egresspolicy.Upstream // no credentials: only answers "is this name proxied?"
	hash      string
}

// Load reads and validates path. Unknown keys are errors: a typo in a
// security file must not silently mean "not configured".
func Load(path string) (*Operator, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("egress operator file: %w", err)
	}
	return Parse(raw)
}

// Parse validates an operator document.
func Parse(raw []byte) (*Operator, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("egress operator file: %w", err)
	}
	if f.Version != Version {
		return nil, fmt.Errorf("egress operator file: version %d, want %d", f.Version, Version)
	}
	o := &Operator{file: f, profiles: map[string]*egresspolicy.Policy{}}
	sum := sha256.Sum256(raw)
	o.hash = hex.EncodeToString(sum[:8])

	if len(f.InternalZone.Suffixes) > 0 || len(f.InternalZone.CIDRs) > 0 {
		z, err := egresspolicy.NewInternalZone(f.InternalZone.Suffixes, f.InternalZone.CIDRs)
		if err != nil {
			return nil, fmt.Errorf("egress operator file: internal_zone: %w", err)
		}
		o.zone = z
	}
	for _, c := range f.DenyCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("egress operator file: deny_cidrs: %q is not an IPv4 CIDR", c)
		}
		o.floor = append(o.floor, p.Masked())
	}
	c, err := egresspolicy.NewCeiling(f.Ceiling.AllowOut)
	if err != nil {
		return nil, fmt.Errorf("egress operator file: ceiling: %w", err)
	}
	o.ceiling = c

	for name, p := range f.OrgProfiles {
		if err := egresspolicy.ValidateProfileName(name); err != nil {
			return nil, fmt.Errorf("egress operator file: org profile: %w", err)
		}
		entries, err := egresspolicy.ParseAllowList("org_profiles."+name, p.AllowOut, egresspolicy.MaxProfileHostnames)
		if err != nil {
			return nil, fmt.Errorf("egress operator file: %w", err)
		}
		raw := make([]string, len(entries))
		for i, e := range entries {
			raw[i] = e.String()
		}
		pol, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: raw, MaxHostnames: egresspolicy.MaxProfileHostnames})
		if err != nil {
			return nil, fmt.Errorf("egress operator file: org profile %s: %w", name, err)
		}
		if err := c.Fits(pol); err != nil {
			return nil, fmt.Errorf("egress operator file: org profile %s exceeds the ceiling: %w", name, err)
		}
		o.profiles[OrgProfilePrefix+name] = pol
	}

	switch f.DefaultPolicy.Mode {
	case "", ModeOpen:
		if c != nil {
			return nil, fmt.Errorf("egress operator file: default_policy.mode open cannot fit a ceiling; use block_all or allowlist")
		}
		if len(f.DefaultPolicy.AllowOut) > 0 {
			return nil, fmt.Errorf("egress operator file: default_policy.allow_out needs mode allowlist")
		}
	case ModeBlockAll:
		if len(f.DefaultPolicy.AllowOut) > 0 {
			return nil, fmt.Errorf("egress operator file: default_policy.allow_out needs mode allowlist")
		}
	case ModeAllowlist:
		if len(f.DefaultPolicy.AllowOut) == 0 {
			return nil, fmt.Errorf("egress operator file: default_policy mode allowlist needs allow_out")
		}
		var inline []string
		for _, e := range f.DefaultPolicy.AllowOut {
			if strings.HasPrefix(e, OrgProfilePrefix) {
				if _, ok := o.profiles[e]; !ok {
					return nil, fmt.Errorf("egress operator file: default_policy references unknown %s", e)
				}
				continue
			}
			inline = append(inline, e)
		}
		pol, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: inline})
		if err != nil {
			return nil, fmt.Errorf("egress operator file: default_policy: %w", err)
		}
		if err := c.Fits(pol); err != nil {
			return nil, fmt.Errorf("egress operator file: default_policy exceeds the ceiling: %w", err)
		}
		o.defPolicy = pol
	default:
		return nil, fmt.Errorf("egress operator file: default_policy.mode %q: want open, block_all or allowlist", f.DefaultPolicy.Mode)
	}

	if u := strings.TrimSpace(f.UpstreamProxy.URL); u != "" {
		parsed, err := url.Parse(u)
		if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
			return nil, fmt.Errorf("egress operator file: upstream_proxy.url %q: want http://host:port", u)
		}
		up := &UpstreamProxy{URL: parsed, AuthFile: f.UpstreamProxy.AuthFile, NoProxy: f.UpstreamProxy.NoProxy}
		syn := f.UpstreamProxy.SyntheticDNSCIDR
		if syn == "" {
			syn = "198.18.0.0/15"
		}
		p, err := netip.ParsePrefix(syn)
		if err != nil || !p.Addr().Is4() || p.Bits() > 24 {
			return nil, fmt.Errorf("egress operator file: upstream_proxy.synthetic_dns_cidr %q: want an IPv4 /24 or wider", syn)
		}
		up.Synthetic = p.Masked()
		// Validate the rest of the chain now (no_proxy entries), so a typo
		// fails the load rather than the first proxied connection.
		matcher, err := egresspolicy.NewUpstream(u, "", up.NoProxy, o.zone, up.Synthetic)
		if err != nil {
			return nil, fmt.Errorf("egress operator file: upstream_proxy: %w", err)
		}
		o.upstream = up
		o.proxied = matcher
	}
	return o, nil
}

// ProxiesName reports whether name would be reached through the upstream
// proxy: there is one, and the name is neither internal-zone nor no_proxy.
func (o *Operator) ProxiesName(name string) bool {
	return o != nil && o.proxied != nil && !o.proxied.Bypass(name)
}

// UpstreamDialer builds the upstream chain, reading the credentials from
// auth_file (it must be mode 0600 or tighter: it holds a password). nil
// without an upstream_proxy.
func (o *Operator) UpstreamDialer() (*egresspolicy.Upstream, error) {
	up := o.Upstream()
	if up == nil {
		return nil, nil
	}
	auth := ""
	if up.AuthFile != "" {
		st, err := os.Stat(up.AuthFile)
		if err != nil {
			return nil, fmt.Errorf("upstream proxy auth_file: %w", err)
		}
		if st.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("upstream proxy auth_file %s: mode %v, want 0600", up.AuthFile, st.Mode().Perm())
		}
		raw, err := os.ReadFile(up.AuthFile)
		if err != nil {
			return nil, fmt.Errorf("upstream proxy auth_file: %w", err)
		}
		auth = strings.TrimSpace(string(raw))
	}
	return egresspolicy.NewUpstream(up.URL.String(), auth, up.NoProxy, o.zone, up.Synthetic)
}

// Hash identifies the file's content (aerolvm_egress_operator_config_info).
func (o *Operator) Hash() string { return o.hash }

// Guard is the container-gateway dial guard: internal zone and deny floor.
func (o *Operator) Guard() egresspolicy.DialGuard {
	if o == nil {
		return egresspolicy.DialGuard{}
	}
	return egresspolicy.DialGuard{Zone: o.zone, DenyFloor: o.floor}
}

// IsolateGuard is isolate's strict guard; the zone applies only with the
// explicit internal_zone.isolate opt-in (D15 unchanged by default).
func (o *Operator) IsolateGuard() egresspolicy.DialGuard {
	if o == nil {
		return egresspolicy.DialGuard{Strict: true}
	}
	return egresspolicy.DialGuard{Strict: true, Zone: o.zone, ZoneInStrict: o.file.InternalZone.Isolate, DenyFloor: o.floor}
}

// DenyFloor returns the operator's always-dropped CIDRs.
func (o *Operator) DenyFloor() []netip.Prefix {
	if o == nil {
		return nil
	}
	return append([]netip.Prefix(nil), o.floor...)
}

// Ceiling returns the ceiling, or nil (no ceiling).
func (o *Operator) Ceiling() *egresspolicy.Ceiling {
	if o == nil {
		return nil
	}
	return o.ceiling
}

// DefaultMode is the default policy mode for creates with no egress fields.
func (o *Operator) DefaultMode() string {
	if o == nil || o.file.DefaultPolicy.Mode == "" {
		return ModeOpen
	}
	return o.file.DefaultPolicy.Mode
}

// DefaultAllowOut is the default allowlist (mode allowlist), org references
// included verbatim.
func (o *Operator) DefaultAllowOut() []string {
	if o == nil {
		return nil
	}
	return append([]string(nil), o.file.DefaultPolicy.AllowOut...)
}

// NodeControlPortGuard defaults to on (§5.10 PC-2).
func (o *Operator) NodeControlPortGuard() bool {
	if o == nil || o.file.NodeControlPortGuard == nil {
		return true
	}
	return *o.file.NodeControlPortGuard
}

// BuiltinProfiles reports whether builtin: references are accepted.
func (o *Operator) BuiltinProfiles() bool {
	if o == nil || o.file.BuiltinProfiles == nil {
		return true
	}
	return *o.file.BuiltinProfiles
}

// OrgProfile returns an org profile's compiled policy and canonical entries.
func (o *Operator) OrgProfile(name string) (*egresspolicy.Policy, bool) {
	if o == nil {
		return nil, false
	}
	p, ok := o.profiles[name]
	return p, ok
}

// OrgProfileEntries returns an org profile's canonical allow entries and
// description, for a sandbox that references it (§5.10 PC-3).
func (o *Operator) OrgProfileEntries(ref string) ([]string, string, bool) {
	p, ok := o.OrgProfile(ref)
	if !ok {
		return nil, "", false
	}
	entries := p.AllowEntries()
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.String()
	}
	return out, o.file.OrgProfiles[strings.TrimPrefix(ref, OrgProfilePrefix)].Description, true
}

// OrgProfileNames lists the org profiles, sorted.
func (o *Operator) OrgProfileNames() []string {
	if o == nil {
		return nil
	}
	out := make([]string, 0, len(o.profiles))
	for n := range o.profiles {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Upstream returns the upstream proxy chain, or nil.
func (o *Operator) Upstream() *UpstreamProxy {
	if o == nil {
		return nil
	}
	return o.upstream
}

// InternalZone returns the zone, or nil.
func (o *Operator) InternalZone() *egresspolicy.InternalZone {
	if o == nil {
		return nil
	}
	return o.zone
}
