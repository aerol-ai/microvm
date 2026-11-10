package release

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in      string
		want    Version
		wantErr string
	}{
		{in: "v0.6.11", want: Version{Major: 0, Minor: 6, Patch: 11}},
		{in: "v10.20.30", want: Version{Major: 10, Minor: 20, Patch: 30}},
		{in: "v0.7.0-rc.1", want: Version{Minor: 7, Prerelease: []string{"rc", "1"}}},
		{in: "v1.0.0-alpha-beta.0", want: Version{Major: 1, Prerelease: []string{"alpha-beta", "0"}}},
		{in: "0.6.11", wantErr: "does not start with v"},
		{in: "", wantErr: "does not start with v"},
		{in: "v0.6", wantErr: "vMAJOR.MINOR.PATCH"},
		{in: "v0.6.11.1", wantErr: "vMAJOR.MINOR.PATCH"},
		{in: "v0..1", wantErr: "empty number"},
		{in: "v01.2.3", wantErr: "leading zero"},
		{in: "v1.2.x", wantErr: "number"},
		{in: "v1.2.3-", wantErr: "empty prerelease identifier"},
		{in: "v1.2.3-rc..1", wantErr: "empty prerelease identifier"},
		{in: "v1.2.3-rc_1", wantErr: "has '_'"},
		{in: "v1.2.3-01", wantErr: "leading zero"},
		{in: "v1.2.3+build", wantErr: "number"},
		{in: "v99999999999999999999.0.0", wantErr: "number"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseVersion(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseVersion(%q) = %v, %v; want an error containing %q", tt.in, got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseVersion(%q): %v", tt.in, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseVersion(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
			if got.String() != tt.in {
				t.Fatalf("String() = %q, want %q", got.String(), tt.in)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	// Each entry is older than the next (semver.org §11's example order plus
	// the shapes our tags take).
	ordered := []string{
		"v0.6.9",
		"v0.6.10",
		"v0.6.11",
		"v0.7.0-alpha",
		"v0.7.0-alpha.1",
		"v0.7.0-alpha.beta",
		"v0.7.0-beta",
		"v0.7.0-beta.2",
		"v0.7.0-beta.11",
		"v0.7.0-rc.1",
		"v0.7.0",
		"v0.10.0",
		"v1.0.0",
	}
	for i := range ordered {
		for j := range ordered {
			got, err := CompareVersions(ordered[i], ordered[j])
			if err != nil {
				t.Fatalf("CompareVersions(%s, %s): %v", ordered[i], ordered[j], err)
			}
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got != want {
				t.Errorf("CompareVersions(%s, %s) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	if _, err := CompareVersions("bad", "v1.0.0"); err == nil {
		t.Fatal("CompareVersions accepted a bad first version")
	}
	if _, err := CompareVersions("v1.0.0", "bad"); err == nil {
		t.Fatal("CompareVersions accepted a bad second version")
	}
}
