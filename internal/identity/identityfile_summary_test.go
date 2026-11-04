package identity

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

func TestSummaryLines(t *testing.T) {
	c, err := Parse([]byte(planExample))
	if err != nil {
		t.Fatal(err)
	}
	s := c.Summary()
	if s.Hash != c.Hash() {
		t.Fatalf("summary hash = %s", s.Hash)
	}
	wantBindings := []string{
		`okta group="platform-admins" -> admin/*`,
		`okta group="secops" -> auditor/*`,
		`okta group="payments-eng" -> runner/payments`,
		`github-actions claim:ref="refs/heads/main",repository="acme/payments" -> runner/payments`,
		`eks-prod claim:sub="system:serviceaccount:payments:ci" -> runner/payments`,
	}
	if !reflect.DeepEqual(s.Bindings, wantBindings) {
		t.Fatalf("binding lines =\n %q\nwant\n %q", s.Bindings, wantBindings)
	}
	if len(s.Issuers) != 5 || !strings.HasPrefix(s.Issuers[0], `okta url="https://acme.okta.com/oauth2/default" audiences=["0oa1cli" "0oa1dash"] mcp_audiences=["api://aerolvm-mcp"]`) ||
		!strings.HasSuffix(s.Issuers[0], "max_token_lifetime=12h0m0s mcp=true") || s.Issuers[4] != `mcp.resource="https://api.acme.dev/mcp"` {
		t.Fatalf("issuer lines = %q", s.Issuers)
	}
	app, err := Parse([]byte(minimalIssuer + "    jwks_file: /etc/keys.json\nbindings:\n  - {issuer: okta, app_role: AerolVM.Runner, role: runner, team: payments}\ndeny_subjects: [\"okta:b\", \"okta:a\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	as := app.Summary()
	if as.Bindings[0] != `okta app_role="AerolVM.Runner" -> runner/payments` || !strings.Contains(as.Issuers[0], `jwks_file="/etc/keys.json"`) ||
		!reflect.DeepEqual(as.Deny, []string{"okta:a", "okta:b"}) {
		t.Fatalf("summary = %+v", as)
	}
}

// TestDiff is the D20 binding diff: added and removed binding, deny and
// issuer lines, a pure reorder flagged, the old hash empty for the first
// file, and nothing at all for an unchanged one.
func TestDiff(t *testing.T) {
	base := Summary{
		Hash:     "h1",
		Issuers:  []string{"okta url=a"},
		Bindings: []string{"okta group=a -> admin/*", "okta group=b -> runner/pay"},
		Deny:     []string{"okta:x"},
	}
	cases := []struct {
		name string
		old  Summary
		new  Summary
		want func(t *testing.T, d diffView)
	}{
		{
			name: "first file: everything added, no old hash",
			old:  Summary{},
			new:  base,
			want: func(t *testing.T, d diffView) {
				d.expect(t, "", "h1", base.Bindings, nil, false, []string{"okta:x"}, nil, []string{"okta url=a"}, nil)
			},
		},
		{
			name: "unchanged",
			old:  base,
			new:  base,
			want: func(t *testing.T, d diffView) { d.expect(t, "h1", "h1", nil, nil, false, nil, nil, nil, nil) },
		},
		{
			name: "binding added and removed, deny changed",
			old:  base,
			new: Summary{Hash: "h2", Issuers: base.Issuers,
				Bindings: []string{"okta group=a -> admin/*", "okta group=c -> viewer/pay"},
				Deny:     []string{"okta:y"}},
			want: func(t *testing.T, d diffView) {
				d.expect(t, "h1", "h2", []string{"okta group=c -> viewer/pay"}, []string{"okta group=b -> runner/pay"}, false,
					[]string{"okta:y"}, []string{"okta:x"}, nil, nil)
			},
		},
		{
			name: "pure reorder changes who gets what under first match",
			old:  base,
			new:  Summary{Hash: "h3", Issuers: base.Issuers, Bindings: []string{base.Bindings[1], base.Bindings[0]}, Deny: base.Deny},
			want: func(t *testing.T, d diffView) { d.expect(t, "h1", "h3", nil, nil, true, nil, nil, nil, nil) },
		},
		{
			name: "issuer url changed",
			old:  base,
			new:  Summary{Hash: "h4", Issuers: []string{"okta url=b"}, Bindings: base.Bindings, Deny: base.Deny},
			want: func(t *testing.T, d diffView) {
				d.expect(t, "h1", "h4", nil, nil, false, nil, nil, []string{"okta url=b"}, []string{"okta url=a"})
			},
		},
		{
			name: "a repeated line counts twice",
			old:  Summary{Hash: "a", Bindings: []string{"x", "x"}},
			new:  Summary{Hash: "b", Bindings: []string{"x"}},
			want: func(t *testing.T, d diffView) { d.expect(t, "a", "b", nil, []string{"x"}, false, nil, nil, nil, nil) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.want(t, diffView{Diff(tc.old, tc.new)})
		})
	}
}

type diffView struct{ d *auditlog.IdentityConfig }

func (v diffView) expect(t *testing.T, oldHash, newHash string, added, removed []string, reordered bool, denyAdded, denyRemoved, issAdded, issRemoved []string) {
	t.Helper()
	d := v.d
	if d.OldHash != oldHash || d.NewHash != newHash || d.Reordered != reordered || d.Omitted != 0 ||
		!sameLines(d.BindingsAdded, added) || !sameLines(d.BindingsRemoved, removed) ||
		!sameLines(d.DenyAdded, denyAdded) || !sameLines(d.DenyRemoved, denyRemoved) ||
		!sameLines(d.IssuersAdded, issAdded) || !sameLines(d.IssuersRemoved, issRemoved) {
		t.Fatalf("diff = %+v", d)
	}
}

func sameLines(got, want []string) bool {
	if len(got) == 0 && len(want) == 0 {
		return true
	}
	return reflect.DeepEqual(got, want)
}

// TestDiffCaps: a wholesale rewrite of a huge file keeps the record bounded
// (at most maxDiffLines lines of at most maxDiffLineBytes), bindings first,
// and counts what it left out.
func TestDiffCaps(t *testing.T) {
	var old, next Summary
	old.Hash, next.Hash = "a", "b"
	for i := 0; i < 900; i++ {
		old.Bindings = append(old.Bindings, "old "+strconv.Itoa(i))
		next.Bindings = append(next.Bindings, "new "+strconv.Itoa(i)+" "+strings.Repeat("é", 400))
	}
	next.Deny = []string{"okta:a"}
	d := Diff(old, next)
	lines := len(d.BindingsAdded) + len(d.BindingsRemoved) + len(d.DenyAdded)
	if lines != maxDiffLines || d.Omitted != 1800+1-maxDiffLines {
		t.Fatalf("lines = %d, omitted = %d", lines, d.Omitted)
	}
	if len(d.BindingsAdded) != 900 || len(d.DenyAdded) != 0 {
		t.Fatalf("bindings must take the budget first: added %d deny %d", len(d.BindingsAdded), len(d.DenyAdded))
	}
	for _, l := range d.BindingsAdded {
		if len(l) > maxDiffLineBytes+len("…") || !utf8.ValidString(l) {
			t.Fatalf("line not clipped on a rune boundary: %d bytes", len(l))
		}
	}
	if got := clipLine("a\x1bb\nc"); got != "abc" {
		t.Fatalf("clipLine strips control characters: %q", got)
	}
}
