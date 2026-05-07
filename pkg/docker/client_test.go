package docker

import "testing"

func TestSandboxIDFromContainerIDCases(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
		want        string
	}{
		{name: "truncates_full_container_id", containerID: "7f3c2a1b9d4e55aa00112233445566778899aabbccddeeff0011223344556677", want: "7f3c2a1b9d4e"},
		{name: "keeps_short_container_id", containerID: "7f3c2a1b9d4e", want: "7f3c2a1b9d4e"},
		{name: "trims_whitespace", containerID: "  7f3c2a1b9d4e55aa  ", want: "7f3c2a1b9d4e"},
		{name: "returns_empty_for_blank", containerID: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sandboxIDFromContainerID(tc.containerID); got != tc.want {
				t.Fatalf("sandboxIDFromContainerID(%q) = %q, want %q", tc.containerID, got, tc.want)
			}
		})
	}
}
