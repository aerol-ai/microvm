package daytona

import "testing"

func TestNormalizeToolboxPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "empty path stays empty", path: "", want: ""},
		{name: "leading slash trimmed", path: "/process/execute", want: "process/execute"},
		{name: "generated toolbox prefix stripped", path: "toolbox/process/execute", want: "process/execute"},
		{name: "generated toolbox prefix stripped with slashes", path: "/toolbox/files/info/", want: "files/info"},
		{name: "bare toolbox maps to root", path: "toolbox", want: ""},
		{name: "plain path preserved", path: "git/status", want: "git/status"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeToolboxPath(tc.path); got != tc.want {
				t.Fatalf("normalizeToolboxPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}
