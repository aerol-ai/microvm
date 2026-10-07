package egresspolicy

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
)

// Egress rules (plans/egress-domain-filtering.md §5.9, P3-1): per-host
// method and path rules that refine hosts the allow list already admits. On
// port 80 the proxy reads each request anyway; on 443 a rule needs
// inspect: true, which makes the gateway terminate TLS with the node's CA.
// A host with no rule keeps the Phase 1 decision (SNI passthrough).

// FieldEgressRules names the rule list in errors.
const FieldEgressRules = "network_egress_rules"

// Rule limits keep the list inside the cluster spec's 4 KB inline cap and
// each request's check cheap.
const (
	MaxRules        = 32
	maxRuleBinaries = 16
	maxRuleMethods  = 16
	maxRulePaths    = 32
	maxRulePathLen  = 256
	maxRuleTokenLen = 32
)

// RuleSpec is one rule as written.
type RuleSpec struct {
	// Host is an exact name or a "*." wildcard, as in an allow entry,
	// without a port.
	Host string `json:"host"`
	// Ports defaults to [443] with Inspect, otherwise [80].
	Ports []uint16 `json:"ports,omitempty"`
	// Methods are exact (GET, POST, …); empty allows any.
	Methods []string `json:"methods,omitempty"`
	// Paths are globs on the request path: "*" stays within one segment,
	// "**" crosses them. Empty allows any path.
	Paths []string `json:"paths,omitempty"`
	// Inspect terminates TLS on 443 so the rule can see requests.
	Inspect bool `json:"inspect,omitempty"`
	// Inject replaces a request header with a secret the sandbox never
	// holds (P3-2). It needs an inspected rule on 443.
	Inject *InjectSpec `json:"inject,omitempty"`
	// Binaries limits the rule to connections opened by these executables,
	// absolute paths inside the sandbox (P3-3). A rule with binaries and no
	// methods, paths or inject works at connection level on any port the
	// allow list opens, 443 without inspection included.
	Binaries []string `json:"binaries,omitempty"`
}

// InjectSpec names the header a rule sets and where its value comes from.
type InjectSpec struct {
	Header string `json:"header"`
	// SecretRef is "env:<KEY>", a key in the sandbox's own sealed env
	// (CEO D13). The sandbox sees a placeholder in its place.
	SecretRef string `json:"secret_ref"`
}

// InjectEnvPrefix starts a secret_ref that names an env key.
const InjectEnvPrefix = "env:"

// InjectPlaceholder is what an injected env key holds inside the sandbox.
func InjectPlaceholder(key string) string { return "aerolvm-placeholder:" + key }

// InjectEnvKey returns the env key a secret_ref names.
func InjectEnvKey(ref string) (string, bool) {
	key, ok := strings.CutPrefix(ref, InjectEnvPrefix)
	if !ok || !isEnvKey(key) {
		return "", false
	}
	return key, true
}

func isEnvKey(k string) bool {
	if k == "" || len(k) > 128 {
		return false
	}
	for i, c := range k {
		if c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// InjectEnvKeys lists the env keys rules inject, deduplicated in order.
func InjectEnvKeys(specs []RuleSpec) []string {
	var out []string
	for _, s := range specs {
		if s.Inject == nil {
			continue
		}
		if k, ok := InjectEnvKey(s.Inject.SecretRef); ok && !containsString(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// reservedInjectHeaders can't be injected: they frame the request or route
// it, so replacing them would change what is sent, not who it authenticates.
var reservedInjectHeaders = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true, "upgrade": true,
	"te": true, "trailer": true, "keep-alive": true, "proxy-authorization": true, "proxy-connection": true,
}

// Rule is one compiled rule.
type Rule struct {
	Index    int
	host     Entry
	ports    []uint16
	methods  []string
	paths    []string
	inspect  bool
	inject   *InjectSpec
	binaries []string
}

// Inject returns the header the rule sets and its env key, if any.
func (r *Rule) Inject() (header, key string, ok bool) {
	if r == nil || r.inject == nil {
		return "", "", false
	}
	key, _ = InjectEnvKey(r.inject.SecretRef)
	return r.inject.Header, key, true
}

// Name identifies a rule in audit records and denials. An inject rule
// names its header and secret_ref, never the value.
func (r *Rule) Name() string {
	n := "rules[" + strconv.Itoa(r.Index) + "] " + r.host.String()
	if r.inject != nil {
		n += " (inject " + r.inject.Header + " from " + r.inject.SecretRef + ")"
	}
	return n
}

// Rules is a sandbox's compiled rule list. The nil *Rules has no rules.
type Rules struct {
	rules []*Rule
}

// RuleDecision is the outcome of checking one request.
type RuleDecision struct {
	// Ruled reports that some rule names this host and port, so the request
	// was held to them; false leaves the connection-level decision alone.
	Ruled   bool
	Allowed bool
	// Rule is the rule that allowed it, or "" when denied.
	Rule *Rule
}

// CompileRules validates rules. With a policy, as at the API, every rule
// must refine a host it allows on each of the rule's ports. With nil, as in
// the gateway, that check is skipped: a profile change may drop a host a
// rule names, and such a rule is inert (the host is refused anyway) rather
// than a reason to hold the sandbox.
func CompileRules(specs []RuleSpec, pol *Policy) (*Rules, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	if len(specs) > MaxRules {
		return nil, invalidf("%s has %d rules; the limit is %d", FieldEgressRules, len(specs), MaxRules)
	}
	if pol != nil && (pol.BlockAll() || pol.Mode() == ModeLearn) {
		return nil, invalidf("%s refine an allow list; they need hostname entries, not block-all or learn mode", FieldEgressRules)
	}
	out := &Rules{rules: make([]*Rule, 0, len(specs))}
	for i, s := range specs {
		r, err := compileRule(i, s, pol)
		if err != nil {
			return nil, err
		}
		out.rules = append(out.rules, r)
	}
	return out, nil
}

func compileRule(i int, s RuleSpec, pol *Policy) (*Rule, error) {
	field := fmt.Sprintf("%s[%d]", FieldEgressRules, i)
	bad := func(format string, args ...any) error {
		return invalidf("%s: %s", field, fmt.Sprintf(format, args...))
	}
	e, err := ParseEntry(s.Host)
	if err != nil || !e.IsHostname() || e.Port != 0 {
		return nil, bad("host %q must be a hostname or *. wildcard without a port", s.Host)
	}
	r := &Rule{Index: i, host: e, inspect: s.Inspect}
	if s.Inject != nil {
		h := http.CanonicalHeaderKey(strings.TrimSpace(s.Inject.Header))
		if !isHeaderToken(h) || reservedInjectHeaders[strings.ToLower(h)] {
			return nil, bad("inject header %q is not a header that can carry a credential", s.Inject.Header)
		}
		if _, ok := InjectEnvKey(s.Inject.SecretRef); !ok {
			return nil, bad("inject secret_ref %q must be env:<KEY>", s.Inject.SecretRef)
		}
		// A credential only ever travels inside the gateway's own TLS.
		if !s.Inspect {
			return nil, bad("inject needs inspect: true, so the credential is only added inside TLS")
		}
		r.inject = &InjectSpec{Header: h, SecretRef: s.Inject.SecretRef}
	}
	r.ports = append(r.ports, s.Ports...)
	if len(r.ports) == 0 {
		r.ports = []uint16{80}
		if s.Inspect {
			r.ports = []uint16{443}
		}
	}
	if len(s.Binaries) > maxRuleBinaries {
		return nil, bad("%d binaries; the limit is %d", len(s.Binaries), maxRuleBinaries)
	}
	for _, b := range s.Binaries {
		if !strings.HasPrefix(b, "/") || len(b) > maxRulePathLen || path.Clean(b) != b || strings.ContainsRune(b, 0) {
			return nil, bad("binary %q must be a clean absolute path inside the sandbox (at most %d bytes)", b, maxRulePathLen)
		}
		r.binaries = append(r.binaries, b)
	}
	// A rule that only names binaries decides whole connections, so it
	// needs no view of the requests.
	connOnly := len(s.Binaries) > 0 && len(s.Methods) == 0 && len(s.Paths) == 0 && s.Inject == nil && !s.Inspect
	for _, p := range r.ports {
		if p != 80 && p != 443 && !connOnly {
			return nil, bad("port %d: method and path rules apply to ports 80 and 443; on other ports a rule can only name binaries", p)
		}
		if p == 443 && !s.Inspect && !connOnly {
			return nil, bad("port 443 is encrypted; set inspect: true to check its requests")
		}
		if p == 80 && s.Inject != nil {
			return nil, bad("inject on port 80 would send the credential in clear; use 443")
		}
		if pol == nil {
			continue
		}
		// A wildcard is checked through a name under it.
		probe := e.Host
		if e.Kind == KindWildcard {
			probe = "aerolvm-rule." + e.Host
		}
		if ok, rule := pol.MatchHostPort(probe, p); !ok || rule == "" {
			return nil, bad("host %s on port %d is not in the allow list; rules refine allowed hosts", e.String(), p)
		}
	}
	if len(s.Methods) > maxRuleMethods {
		return nil, bad("%d methods; the limit is %d", len(s.Methods), maxRuleMethods)
	}
	for _, m := range s.Methods {
		if !isMethodToken(m) {
			return nil, bad("method %q must be an upper-case HTTP method", m)
		}
		r.methods = append(r.methods, m)
	}
	if len(s.Paths) > maxRulePaths {
		return nil, bad("%d paths; the limit is %d", len(s.Paths), maxRulePaths)
	}
	for _, p := range s.Paths {
		if !strings.HasPrefix(p, "/") || len(p) > maxRulePathLen || strings.ContainsAny(p, "?# \t%") || !validPathGlob(p) {
			return nil, bad("path %q must start with /, use ** only as a whole segment, and hold no query, fragment, escapes or spaces (at most %d bytes)", p, maxRulePathLen)
		}
		r.paths = append(r.paths, p)
	}
	return r, nil
}

func isHeaderToken(h string) bool {
	if h == "" || len(h) > 64 {
		return false
	}
	for _, c := range h {
		if !(c == '-' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}

func isMethodToken(m string) bool {
	if m == "" || len(m) > maxRuleTokenLen {
		return false
	}
	for _, c := range m {
		if (c < 'A' || c > 'Z') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// NeedsBinary reports whether a connection to host:port must be traced to
// its executable (P3-3): some rule for it names binaries.
func (rs *Rules) NeedsBinary(host string, port uint16) bool {
	return rs.anyFor(host, port, func(r *Rule) bool { return len(r.binaries) > 0 })
}

// HasBinaries reports whether any rule names binaries.
func (rs *Rules) HasBinaries() bool {
	if rs == nil {
		return false
	}
	for _, r := range rs.rules {
		if len(r.binaries) > 0 {
			return true
		}
	}
	return false
}

// Binaries lists every executable the rules name, once each: the paths a
// traced connection is checked against.
func (rs *Rules) Binaries() []string {
	if rs == nil {
		return nil
	}
	var out []string
	for _, r := range rs.rules {
		for _, b := range r.binaries {
			if !slices.Contains(out, b) {
				out = append(out, b)
			}
		}
	}
	return out
}

// BinaryPorts lists the ports, other than 80 and 443, that rules for host
// trace to executables: the gateway proxies those flows (P3-3).
func (rs *Rules) BinaryPorts(host string) []uint16 {
	if rs == nil {
		return nil
	}
	name := canonicalName(host)
	var out []uint16
	for _, r := range rs.rules {
		if len(r.binaries) == 0 || name == "" || !r.host.coversName(name) {
			continue
		}
		for _, p := range r.ports {
			if p != 80 && p != 443 && !slicesContains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

func slicesContains(list []uint16, v uint16) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// AdmitConn holds a connection to host:port to the rules' binaries: is
// reports whether the connection's process is the executable at a listed
// path. It returns the rules the connection's requests are then held to
// (those for host:port that admitted it, plus every rule for other hosts),
// and false when rules for host:port exist and none admits the process. A
// rule without binaries admits any process.
func (rs *Rules) AdmitConn(host string, port uint16, is func(path string) bool) (*Rules, bool) {
	if rs == nil {
		return nil, true
	}
	name := canonicalName(host)
	out := &Rules{rules: make([]*Rule, 0, len(rs.rules))}
	ruled, admitted := false, false
	for _, r := range rs.rules {
		if !r.covers(name, port) {
			out.rules = append(out.rules, r)
			continue
		}
		ruled = true
		if len(r.binaries) == 0 || r.admitsBinary(is) {
			admitted = true
			out.rules = append(out.rules, r)
		}
	}
	if ruled && !admitted {
		return nil, false
	}
	return out, true
}

func (r *Rule) admitsBinary(is func(path string) bool) bool {
	for _, b := range r.binaries {
		if is(b) {
			return true
		}
	}
	return false
}

// Inspects reports whether any rule needs TLS terminated (P3-1): the
// sandbox must trust the node's CA.
func (rs *Rules) Inspects() bool {
	if rs == nil {
		return false
	}
	for _, r := range rs.rules {
		if r.inspect {
			return true
		}
	}
	return false
}

// Inspected reports whether the gateway must terminate TLS for host on 443.
func (rs *Rules) Inspected(host string) bool {
	return rs.anyFor(host, 443, func(r *Rule) bool { return r.inspect })
}

// Has reports whether any rule names host on port.
func (rs *Rules) Has(host string, port uint16) bool {
	return rs.anyFor(host, port, func(*Rule) bool { return true })
}

func (rs *Rules) anyFor(host string, port uint16, pred func(*Rule) bool) bool {
	if rs == nil {
		return false
	}
	name := canonicalName(host)
	for _, r := range rs.rules {
		if r.covers(name, port) && pred(r) {
			return true
		}
	}
	return false
}

func (r *Rule) covers(name string, port uint16) bool {
	if name == "" || !r.host.coversName(name) {
		return false
	}
	for _, p := range r.ports {
		if p == port {
			return true
		}
	}
	return false
}

// Decide checks one request. Rules for the host are alternatives: the first
// that admits the method and path allows it; with rules but no match it is
// denied. A host no rule names is not ruled.
func (rs *Rules) Decide(host string, port uint16, method, path string) RuleDecision {
	if rs == nil {
		return RuleDecision{}
	}
	name := canonicalName(host)
	var d RuleDecision
	for _, r := range rs.rules {
		if !r.covers(name, port) {
			continue
		}
		d.Ruled = true
		if r.admits(method, path) {
			return RuleDecision{Ruled: true, Allowed: true, Rule: r}
		}
	}
	return d
}

func (r *Rule) admits(method, path string) bool {
	if len(r.methods) > 0 && !containsString(r.methods, method) {
		return false
	}
	if len(r.paths) == 0 {
		return true
	}
	for _, p := range r.paths {
		if matchPathGlob(p, path) {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// maxRequestPathLen bounds the path a ruled request may carry; a longer one
// is refused rather than matched.
const maxRequestPathLen = 4096

// CanonicalRequestPath returns the decoded path a rule is matched against,
// or false for a path an upstream server could read differently: "." or
// ".." segments, empty segments, an encoded "/" or "\", or one longer than
// the matcher takes. Without this, "/repos/acme/../../admin" would match
// "/repos/acme/**" and reach /admin.
func CanonicalRequestPath(rawPath string) (string, bool) {
	if rawPath == "" || rawPath[0] != '/' || len(rawPath) > maxRequestPathLen {
		return "", false
	}
	lower := strings.ToLower(rawPath)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(rawPath, "\\") {
		return "", false
	}
	decoded, err := url.PathUnescape(rawPath)
	if err != nil {
		return "", false
	}
	segs := strings.Split(decoded[1:], "/")
	for i, seg := range segs {
		// One trailing slash is the only empty segment allowed.
		if (seg == "" && i != len(segs)-1) || seg == "." || seg == ".." {
			return "", false
		}
	}
	return decoded, true
}

// validPathGlob reports whether a rule path uses "**" only as a whole
// segment, which keeps matching linear in the number of segments.
func validPathGlob(p string) bool {
	for _, seg := range strings.Split(p[1:], "/") {
		if strings.Contains(seg, "**") && seg != "**" {
			return false
		}
	}
	return true
}

// matchPathGlob matches a canonical request path against a rule path
// segment by segment: "**" is any number of whole segments, "*" within a
// segment is any run of characters, everything else is literal.
func matchPathGlob(pattern, path string) bool {
	ps := strings.Split(pattern[1:], "/")
	xs := strings.Split(path[1:], "/")
	// reach[j] reports whether the pattern so far matches the first j path
	// segments.
	reach := make([]bool, len(xs)+1)
	reach[0] = true
	for _, p := range ps {
		next := make([]bool, len(xs)+1)
		for j := 0; j <= len(xs); j++ {
			if !reach[j] {
				continue
			}
			if p == "**" {
				for k := j; k <= len(xs); k++ {
					next[k] = true
				}
				break
			}
			if j < len(xs) && matchSegment(p, xs[j]) {
				next[j+1] = true
			}
		}
		reach = next
	}
	return reach[len(xs)]
}

// matchSegment matches one segment against a pattern whose only wildcard is
// "*" (any run of characters), with the usual single-backtrack algorithm.
func matchSegment(p, s string) bool {
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case pi < len(p) && p[pi] == s[si]:
			pi++
			si++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
