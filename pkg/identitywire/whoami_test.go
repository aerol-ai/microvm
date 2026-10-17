package identitywire

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// TestWhoAmIExplainWireShape pins the JSON `aerolvm whoami --explain`
// decodes: matched is always an array, in_effect and the claims are left
// out when unset, and the field names don't drift.
func TestWhoAmIExplainWireShape(t *testing.T) {
	cases := []struct {
		name string
		doc  WhoAmIExplain
		want string
	}{
		{
			name: "an API token",
			doc:  WhoAmIExplain{Matched: []ExplainBinding{}},
			want: `{"matched":[]}`,
		},
		{
			name: "an SSO caller with two matches",
			doc: WhoAmIExplain{
				Matched: []ExplainBinding{
					{Index: 3, Text: `okta group="payments-eng" -> runner/payments`, InEffect: true},
					{Index: 5, Text: `okta group="everyone" -> viewer/*`},
				},
				Claims: &ExplainClaims{Issuer: "okta", Username: "alice@acme.com", Groups: []string{"everyone", "payments-eng"}},
			},
			want: `{"matched":[{"index":3,"text":"okta group=\"payments-eng\" -> runner/payments","in_effect":true},` +
				`{"index":5,"text":"okta group=\"everyone\" -> viewer/*"}],` +
				`"claims":{"issuer":"okta","username":"alice@acme.com","groups":["everyone","payments-eng"]}}`,
		},
		{
			name: "overage",
			doc:  WhoAmIExplain{Matched: []ExplainBinding{}, Claims: &ExplainClaims{Issuer: "entra", Roles: []string{"AerolVM.Runner"}, GroupOverage: true}},
			want: `{"matched":[],"claims":{"issuer":"entra","roles":["AerolVM.Runner"],"group_overage":true}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// HTML escaping off, so the canonical "->" reads as written; it
			// changes how ">" is spelled, never the shape.
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(tc.doc); err != nil {
				t.Fatal(err)
			}
			raw := bytes.TrimSpace(buf.Bytes())
			if string(raw) != tc.want {
				t.Fatalf("marshal =\n %s\nwant\n %s", raw, tc.want)
			}
			var back WhoAmIExplain
			if err := json.Unmarshal(raw, &back); err != nil || !reflect.DeepEqual(back, tc.doc) {
				t.Fatalf("round trip = %+v, %v", back, err)
			}
		})
	}
	if TeamHeader != "X-AerolVM-Team" || WhoAmIExplainQuery != "explain" {
		t.Fatal("the header and query names are wire contracts; they must not change")
	}
}
