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

func TestSplitSnapshotImageRefCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantRepo string
		wantTag  string
		wantErr  bool
	}{
		{name: "repo only", input: "snapshot-alpha", wantRepo: "snapshot-alpha"},
		{name: "repo with tag", input: "snapshot-alpha:v1", wantRepo: "snapshot-alpha", wantTag: "v1"},
		{name: "registry port without tag", input: "localhost:5000/snapshot-alpha", wantRepo: "localhost:5000/snapshot-alpha"},
		{name: "registry port with tag", input: "localhost:5000/snapshot-alpha:v2", wantRepo: "localhost:5000/snapshot-alpha", wantTag: "v2"},
		{name: "reject digest", input: "snapshot@sha256:abc", wantErr: true},
		{name: "reject blank", input: " ", wantErr: true},
		{name: "reject trailing colon", input: "snapshot:", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo, tag, err := splitSnapshotImageRef(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("splitSnapshotImageRef(%q) expected error", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitSnapshotImageRef(%q) error = %v", tc.input, err)
			}
			if repo != tc.wantRepo || tag != tc.wantTag {
				t.Fatalf("splitSnapshotImageRef(%q) = (%q, %q), want (%q, %q)", tc.input, repo, tag, tc.wantRepo, tc.wantTag)
			}
		})
	}
}
