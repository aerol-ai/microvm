package daytona

import "testing"

// The Daytona platform default is public preview links, so an omitted
// "public" field must opt in to allow_public_traffic even though the core
// create default is private; an explicit false maps to a fully private
// sandbox.
func TestDaytonaPublicFlag(t *testing.T) {
	truth := true
	falsity := false
	cases := []struct {
		name string
		in   *bool
		want bool
	}{
		{name: "omitted defaults to public", in: nil, want: true},
		{name: "explicit true stays public", in: &truth, want: true},
		{name: "explicit false goes private", in: &falsity, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := daytonaPublicFlag(tc.in)
			if got == nil {
				t.Fatal("daytonaPublicFlag returned nil; the service must receive an explicit value")
			}
			if *got != tc.want {
				t.Fatalf("daytonaPublicFlag(%v) = %v, want %v", tc.in, *got, tc.want)
			}
		})
	}
}
