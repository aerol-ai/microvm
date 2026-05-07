package docker

import "testing"

func TestSandboxIDFromContainerNameCases(t *testing.T) {
	tests := []struct {
		name          string
		containerName string
		want          string
	}{
		{name: "strips_leading_slash", containerName: "/sandbox-abc123def456", want: "sandbox-abc123def456"},
		{name: "trims_whitespace", containerName: "  /sandbox-abc123  ", want: "sandbox-abc123"},
		{name: "no_slash_returns_as_is", containerName: "sandbox-abc123", want: "sandbox-abc123"},
		{name: "returns_empty_for_blank", containerName: "", want: ""},
		{name: "returns_empty_for_only_slash", containerName: "/", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sandboxIDFromContainerName(tc.containerName); got != tc.want {
				t.Fatalf("sandboxIDFromContainerName(%q) = %q, want %q", tc.containerName, got, tc.want)
			}
		})
	}
}
