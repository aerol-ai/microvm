package egresspolicy

import "testing"

// TestRulesFingerprint: equal for the same rules; different when a binary,
// inspection, a method or an injection deciding host:port changes; and a
// change to another host's rules leaves host:port's alone.
func TestRulesFingerprint(t *testing.T) {
	pol, err := Compile(Spec{AllowOut: []string{"pypi.org", "api.example.com", "other.org"}})
	if err != nil {
		t.Fatal(err)
	}
	compile := func(specs ...RuleSpec) *Rules {
		t.Helper()
		rs, err := CompileRules(specs, pol)
		if err != nil {
			t.Fatal(err)
		}
		return rs
	}
	curl := RuleSpec{Host: "pypi.org", Ports: []uint16{443}, Binaries: []string{"/usr/bin/curl"}}
	wget := RuleSpec{Host: "pypi.org", Ports: []uint16{443}, Binaries: []string{"/usr/bin/wget"}}
	get := RuleSpec{Host: "api.example.com", Inspect: true, Methods: []string{"GET"}}
	post := RuleSpec{Host: "api.example.com", Inspect: true, Methods: []string{"POST"}}
	other := RuleSpec{Host: "other.org", Ports: []uint16{443}, Binaries: []string{"/usr/bin/git"}}

	if a, b := compile(curl).Fingerprint("pypi.org", 443), compile(curl).Fingerprint("pypi.org", 443); a == "" || a != b {
		t.Fatalf("same rules: %q vs %q", a, b)
	}
	cases := []struct {
		name       string
		old, nu    *Rules
		host       string
		port       uint16
		wantChange bool
	}{
		{"binary changed", compile(curl), compile(wget), "pypi.org", 443, true},
		{"rule added", nil, compile(curl), "pypi.org", 443, true},
		{"inspection added", nil, compile(get), "api.example.com", 443, true},
		{"method changed", compile(get), compile(post), "api.example.com", 443, true},
		{"other host changed", compile(curl), compile(curl, other), "pypi.org", 443, false},
		{"other port", compile(curl), compile(wget), "pypi.org", 80, false},
		{"none", nil, nil, "pypi.org", 443, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if changed := c.old.Fingerprint(c.host, c.port) != c.nu.Fingerprint(c.host, c.port); changed != c.wantChange {
				t.Fatalf("changed = %v, want %v", changed, c.wantChange)
			}
		})
	}
	inj := RuleSpec{Host: "api.example.com", Inspect: true, Inject: &InjectSpec{Header: "Authorization", SecretRef: "env:TOKEN"}}
	if compile(inj).Fingerprint("api.example.com", 443) == compile(get).Fingerprint("api.example.com", 443) {
		t.Fatal("an injection must change the fingerprint")
	}
}
