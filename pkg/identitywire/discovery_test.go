package identitywire

import (
	"encoding/json"
	"testing"
)

func TestUIURL(t *testing.T) {
	cases := map[string]string{
		"":                "",
		"   ":             "",
		"api.acme.dev":    "https://api.acme.dev/ui",
		" api.acme.dev  ": "https://api.acme.dev/ui",
	}
	for domain, want := range cases {
		if got := UIURL(domain); got != want {
			t.Errorf("UIURL(%q) = %q, want %q", domain, got, want)
		}
	}
}

// TestAuthDiscoveryWireShape pins the JSON the CLI and the dashboard decode:
// ui_url is omitted without a domain, issuers is always an array, and the
// per-issuer fields keep their names.
func TestAuthDiscoveryWireShape(t *testing.T) {
	cases := []struct {
		name string
		doc  AuthDiscovery
		want string
	}{
		{
			name: "identity off",
			doc:  AuthDiscovery{Version: AuthDiscoveryVersion, Issuers: []DiscoveryIssuer{}},
			want: `{"version":1,"identity_enabled":false,"issuers":[]}`,
		},
		{
			name: "one issuer with a domain",
			doc: AuthDiscovery{
				Version:         AuthDiscoveryVersion,
				IdentityEnabled: true,
				Issuers: []DiscoveryIssuer{{
					Name: "okta", DisplayName: "Acme Okta", Kind: IssuerKindOIDC, URL: "https://acme.okta.com",
					Clients: DiscoveryClients{CLI: "0oa1cli", Dashboard: "0oa1dash"},
				}},
				UIURL: UIURL("api.acme.dev"),
			},
			want: `{"version":1,"identity_enabled":true,"issuers":[{"name":"okta","display_name":"Acme Okta","kind":"oidc","url":"https://acme.okta.com","clients":{"cli":"0oa1cli","dashboard":"0oa1dash"}}],"ui_url":"https://api.acme.dev/ui"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.doc)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != tc.want {
				t.Fatalf("marshal =\n %s\nwant\n %s", raw, tc.want)
			}
			var back AuthDiscovery
			if err := json.Unmarshal(raw, &back); err != nil || back.Version != tc.doc.Version || len(back.Issuers) != len(tc.doc.Issuers) {
				t.Fatalf("round trip = %+v, %v", back, err)
			}
		})
	}
}
