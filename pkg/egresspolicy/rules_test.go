package egresspolicy

import (
	"errors"
	"strings"
	"testing"
)

func rulesPolicy(t *testing.T) *Policy {
	t.Helper()
	pol, err := Compile(Spec{AllowOut: []string{"api.github.com", "*.example.com", "plain.example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

// TestCompileRulesValidation: rules refine allowed hosts, and 443 needs
// inspection to see requests.
func TestCompileRulesValidation(t *testing.T) {
	pol := rulesPolicy(t)
	if rs, err := CompileRules(nil, pol); rs != nil || err != nil {
		t.Fatalf("no rules = %v %v", rs, err)
	}
	ok := []RuleSpec{
		{Host: "api.github.com", Inspect: true, Methods: []string{"GET"}, Paths: []string{"/repos/acme/*"}},
		{Host: "*.example.com", Inspect: true, Ports: []uint16{80, 443}},
		{Host: "plain.example.org", Methods: []string{"GET"}},
	}
	if _, err := CompileRules(ok, pol); err != nil {
		t.Fatal(err)
	}
	tooMany := make([]RuleSpec, MaxRules+1)
	for i := range tooMany {
		tooMany[i] = RuleSpec{Host: "plain.example.org"}
	}
	learn, _ := Compile(Spec{Mode: ModeLearn})
	block, _ := Compile(Spec{BlockAll: true})
	for name, tc := range map[string]struct {
		rules []RuleSpec
		pol   *Policy
	}{
		"host not allowed":     {[]RuleSpec{{Host: "evil.example.net", Inspect: true}}, pol},
		"443 without inspect":  {[]RuleSpec{{Host: "api.github.com", Ports: []uint16{443}}}, pol},
		"port 22":              {[]RuleSpec{{Host: "api.github.com", Ports: []uint16{22}, Inspect: true}}, pol},
		"host with port":       {[]RuleSpec{{Host: "api.github.com:443", Inspect: true}}, pol},
		"cidr host":            {[]RuleSpec{{Host: "10.0.0.0/8"}}, pol},
		"lower-case method":    {[]RuleSpec{{Host: "plain.example.org", Methods: []string{"get"}}}, pol},
		"relative path":        {[]RuleSpec{{Host: "plain.example.org", Paths: []string{"repos/*"}}}, pol},
		"partial **":           {[]RuleSpec{{Host: "plain.example.org", Paths: []string{"/a**"}}}, pol},
		"escape in path":       {[]RuleSpec{{Host: "plain.example.org", Paths: []string{"/a%2Fb"}}}, pol},
		"too many rules":       {tooMany, pol},
		"learn mode":           {[]RuleSpec{{Host: "plain.example.org"}}, learn},
		"block-all":            {[]RuleSpec{{Host: "plain.example.org"}}, block},
		"too many methods":     {[]RuleSpec{{Host: "plain.example.org", Methods: strings.Fields(strings.Repeat("GET ", 17))}}, pol},
		"too many paths":       {[]RuleSpec{{Host: "plain.example.org", Paths: strings.Fields(strings.Repeat("/a ", 33))}}, pol},
		"wildcard not allowed": {[]RuleSpec{{Host: "*.github.com", Inspect: true}}, pol},
	} {
		if _, err := CompileRules(tc.rules, tc.pol); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

// TestRulesDecide (EF-52): a ruled host admits only what some rule allows;
// an unruled host is left to the connection-level decision.
func TestRulesDecide(t *testing.T) {
	rs, err := CompileRules([]RuleSpec{
		{Host: "api.github.com", Inspect: true, Methods: []string{"GET"}, Paths: []string{"/repos/acme/*", "/user"}},
		{Host: "api.github.com", Inspect: true, Methods: []string{"POST"}, Paths: []string{"/repos/acme/*/issues"}},
		{Host: "*.example.com", Inspect: true, Paths: []string{"/v1/**"}},
	}, rulesPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, method, path string
		port               uint16
		ruled, allowed     bool
		rule               int
	}{
		{"api.github.com", "GET", "/repos/acme/widget", 443, true, true, 0},
		{"API.GitHub.com", "GET", "/user", 443, true, true, 0},
		{"api.github.com", "POST", "/repos/acme/widget", 443, true, false, -1},
		{"api.github.com", "POST", "/repos/acme/widget/issues", 443, true, true, 1},
		{"api.github.com", "GET", "/repos/acme/widget/issues", 443, true, false, -1},
		{"api.github.com", "GET", "/repos/acme/widget", 80, false, false, -1},
		{"cdn.example.com", "DELETE", "/v1/a/b/c", 443, true, true, 2},
		{"cdn.example.com", "GET", "/v2/a", 443, true, false, -1},
		{"other.org", "GET", "/", 443, false, false, -1},
	} {
		d := rs.Decide(tc.host, tc.port, tc.method, tc.path)
		if d.Ruled != tc.ruled || d.Allowed != tc.allowed || (tc.rule >= 0) != (d.Rule != nil) || (d.Rule != nil && d.Rule.Index != tc.rule) {
			t.Fatalf("%s %s %s:%d = %+v", tc.method, tc.path, tc.host, tc.port, d)
		}
	}
	if !rs.Inspected("api.github.com") || !rs.Inspected("x.example.com") || rs.Inspected("example.com") || rs.Inspected("other.org") {
		t.Fatal("Inspected")
	}
	if !rs.Has("api.github.com", 443) || rs.Has("api.github.com", 80) || !rs.Inspects() {
		t.Fatal("Has")
	}
	// The gateway compiles without the policy: a rule whose host a profile
	// change dropped is inert, not an error.
	if lenient, err := CompileRules([]RuleSpec{{Host: "gone.example.net", Methods: []string{"GET"}}}, nil); err != nil || lenient.Inspects() {
		t.Fatalf("lenient compile = %v", err)
	}
	var none *Rules
	if none.Inspected("x") || none.Has("x", 80) || none.Decide("x", 80, "GET", "/").Ruled || none.Inspects() {
		t.Fatal("nil rules rule nothing")
	}
	if got := rs.Decide("api.github.com", 443, "GET", "/user").Rule.Name(); got != "rules[0] api.github.com" {
		t.Fatalf("name = %q", got)
	}
}

func TestPathGlob(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"/", "/", true},
		{"/**", "/", true},
		{"/**", "/a/b/c", true},
		{"/a/*", "/a/b", true},
		{"/a/*", "/a/b/c", false},
		{"/a/*", "/a/", true},
		{"/a/**/z", "/a/z", true},
		{"/a/**/z", "/a/b/c/z", true},
		{"/a/**/z", "/a/b/c/y", false},
		{"/a/b*c", "/a/bxxc", true},
		{"/a/b*c", "/a/bxxd", false},
		{"/a/*.json", "/a/x.json", true},
		{"/a", "/a/", false},
		{"/a/", "/a/", true},
	} {
		if got := matchPathGlob(tc.pattern, tc.path); got != tc.want {
			t.Fatalf("%s ~ %s = %v", tc.pattern, tc.path, got)
		}
	}
}

// TestCanonicalRequestPath: paths an upstream could read differently are
// refused, so a rule can't be walked around.
func TestCanonicalRequestPath(t *testing.T) {
	for raw, want := range map[string]string{"/a/b": "/a/b", "/a/b/": "/a/b/", "/a%20b": "/a b", "/": "/"} {
		if got, ok := CanonicalRequestPath(raw); !ok || got != want {
			t.Fatalf("%s = %q %v", raw, got, ok)
		}
	}
	for _, raw := range []string{"", "a", "/a/../b", "/a/./b", "/a//b", "/a%2fb", "/a%5Cb", `/a\b`, "/a%zz", "/" + strings.Repeat("a", maxRequestPathLen)} {
		if _, ok := CanonicalRequestPath(raw); ok {
			t.Fatalf("%q must be refused", raw)
		}
	}
}

// TestRuleInject (P3-2): an inject rule names a header and an env key, needs
// inspection, and never on port 80; its audit name carries the secret_ref,
// never a value.
func TestRuleInject(t *testing.T) {
	pol := rulesPolicy(t)
	inj := &InjectSpec{Header: "authorization", SecretRef: "env:GITHUB_TOKEN"}
	rs, err := CompileRules([]RuleSpec{{Host: "api.github.com", Inspect: true, Paths: []string{"/repos/**"}, Inject: inj}}, pol)
	if err != nil {
		t.Fatal(err)
	}
	d := rs.Decide("api.github.com", 443, "GET", "/repos/acme/x")
	h, key, ok := d.Rule.Inject()
	if !ok || h != "Authorization" || key != "GITHUB_TOKEN" {
		t.Fatalf("inject = %q %q %v", h, key, ok)
	}
	if name := d.Rule.Name(); name != "rules[0] api.github.com (inject Authorization from env:GITHUB_TOKEN)" {
		t.Fatalf("name = %q", name)
	}
	var none *Rule
	if _, _, ok := none.Inject(); ok {
		t.Fatal("nil rule injects nothing")
	}
	for name, spec := range map[string]RuleSpec{
		"no inspect":   {Host: "plain.example.org", Inject: inj},
		"port 80":      {Host: "api.github.com", Inspect: true, Ports: []uint16{80, 443}, Inject: inj},
		"bad ref":      {Host: "api.github.com", Inspect: true, Inject: &InjectSpec{Header: "Authorization", SecretRef: "GITHUB_TOKEN"}},
		"bad key":      {Host: "api.github.com", Inspect: true, Inject: &InjectSpec{Header: "Authorization", SecretRef: "env:1BAD"}},
		"reserved":     {Host: "api.github.com", Inspect: true, Inject: &InjectSpec{Header: "Host", SecretRef: "env:K"}},
		"bad header":   {Host: "api.github.com", Inspect: true, Inject: &InjectSpec{Header: "X Bad", SecretRef: "env:K"}},
		"empty header": {Host: "api.github.com", Inspect: true, Inject: &InjectSpec{Header: "", SecretRef: "env:K"}},
		"long header":  {Host: "api.github.com", Inspect: true, Inject: &InjectSpec{Header: strings.Repeat("x", 65), SecretRef: "env:K"}},
	} {
		if _, err := CompileRules([]RuleSpec{spec}, pol); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	keys := InjectEnvKeys([]RuleSpec{{Inject: inj}, {}, {Inject: inj}, {Inject: &InjectSpec{SecretRef: "env:B_2"}}, {Inject: &InjectSpec{SecretRef: "nope"}}})
	if strings.Join(keys, ",") != "GITHUB_TOKEN,B_2" {
		t.Fatalf("keys = %v", keys)
	}
	if InjectPlaceholder("K") != "aerolvm-placeholder:K" {
		t.Fatal("placeholder")
	}
	if _, ok := InjectEnvKey("env:" + strings.Repeat("A", 129)); ok {
		t.Fatal("over-long key")
	}
}
