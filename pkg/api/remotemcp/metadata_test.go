package remotemcp

import (
	"encoding/json"
	"testing"
)

// TestMetadataURL is RFC 9728 §3.1: the well-known path goes between the
// host and the resource's path.
func TestMetadataURL(t *testing.T) {
	for resource, want := range map[string]string{
		"https://api.acme.dev/mcp":       "https://api.acme.dev/.well-known/oauth-protected-resource/mcp",
		"https://api.acme.dev:8443/mcp":  "https://api.acme.dev:8443/.well-known/oauth-protected-resource/mcp",
		"https://api.acme.dev/mcp/":      "https://api.acme.dev/.well-known/oauth-protected-resource/mcp",
		"https://api.acme.dev":           "https://api.acme.dev/.well-known/oauth-protected-resource",
		"https://api.acme.dev/a b":       "https://api.acme.dev/.well-known/oauth-protected-resource/a%20b",
		"/mcp":                           "",
		"api.acme.dev/mcp":               "",
		"":                               "",
		"https://%zz":                    "",
		"https://api.acme.dev/mcp?x=1#f": "https://api.acme.dev/.well-known/oauth-protected-resource/mcp",
	} {
		if got := MetadataURL(resource); got != want {
			t.Errorf("MetadataURL(%q) = %q, want %q", resource, got, want)
		}
	}
}

// TestChallengeParams: resource_metadata always, scope only when the
// identity file lists scopes, space-separated (RFC 6750 §3).
func TestChallengeParams(t *testing.T) {
	cases := []struct {
		resource string
		scopes   []string
		want     string
	}{
		{"https://api.acme.dev/mcp", nil, `resource_metadata="https://api.acme.dev/.well-known/oauth-protected-resource/mcp"`},
		{"https://api.acme.dev/mcp", []string{"api://aerolvm-mcp/mcp", "offline_access"},
			`resource_metadata="https://api.acme.dev/.well-known/oauth-protected-resource/mcp", scope="api://aerolvm-mcp/mcp offline_access"`},
		{"", []string{"a"}, ""},
		{"not a url", nil, ""},
	}
	for _, tc := range cases {
		if got := ChallengeParams(tc.resource, tc.scopes); got != tc.want {
			t.Errorf("ChallengeParams(%q, %v) = %q, want %q", tc.resource, tc.scopes, got, tc.want)
		}
	}
}

// TestResourceMetadataJSON pins the document's field names (RFC 9728 §2):
// scopes_supported is left out when none is configured.
func TestResourceMetadataJSON(t *testing.T) {
	raw, err := json.Marshal(ResourceMetadata{
		Resource: "https://api.acme.dev/mcp", AuthorizationServers: []string{"https://acme.okta.com/oauth2/default"},
		BearerMethodsSupported: []string{BearerMethodHeader},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"resource":"https://api.acme.dev/mcp","authorization_servers":["https://acme.okta.com/oauth2/default"],"bearer_methods_supported":["header"]}`
	if string(raw) != want {
		t.Fatalf("metadata = %s\nwant %s", raw, want)
	}
}
