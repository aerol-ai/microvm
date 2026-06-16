package validate

import "testing"

func TestNodeArchFromExplicit(t *testing.T) {
	if got := NodeArch("arm64", "c5.metal"); got != "arm64" {
		t.Fatalf("explicit arm64 = %q", got)
	}
}

func TestNodeArchFromGravitonInstanceType(t *testing.T) {
	if got := NodeArch("", "c7g.metal"); got != "arm64" {
		t.Fatalf("c7g.metal = %q, want arm64", got)
	}
	if got := NodeArch("", "t4g.medium"); got != "arm64" {
		t.Fatalf("t4g.medium = %q, want arm64", got)
	}
}

func TestNodeArchFromX86InstanceType(t *testing.T) {
	if got := NodeArch("", "c5.metal"); got != "amd64" {
		t.Fatalf("c5.metal = %q, want amd64", got)
	}
}

func TestExplicitArchMatchesInstance(t *testing.T) {
	cases := []struct {
		name         string
		explicitArch string
		instanceType string
		want         bool
	}{
		{name: "unset uses derived", instanceType: "c7g.metal", want: true},
		{name: "arm matches graviton", explicitArch: "arm64", instanceType: "c7g.metal", want: true},
		{name: "amd matches x86", explicitArch: "amd64", instanceType: "c5.metal", want: true},
		{name: "arm on x86 rejected", explicitArch: "arm64", instanceType: "c5.metal", want: false},
		{name: "amd on graviton rejected", explicitArch: "amd64", instanceType: "c7g.metal", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExplicitArchMatchesInstance(tc.explicitArch, tc.instanceType); got != tc.want {
				t.Fatalf("ExplicitArchMatchesInstance(%q, %q) = %v, want %v", tc.explicitArch, tc.instanceType, got, tc.want)
			}
		})
	}
}

func TestHomogeneousClusterArchPassesSingleArch(t *testing.T) {
	if got := HomogeneousClusterArch(map[string]string{
		"a": "arm64",
		"b": "arm64",
	}); got != "arm64" {
		t.Fatalf("homogeneous arm64 = %q", got)
	}
}

func TestHomogeneousClusterArchRejectsMixedArch(t *testing.T) {
	if got := HomogeneousClusterArch(map[string]string{
		"x86": "amd64",
		"arm": "arm64",
	}); got != "" {
		t.Fatalf("mixed arch cluster should fail validation, got %q", got)
	}
}

func TestFirecrackerUpstreamArch(t *testing.T) {
	if got := FirecrackerUpstreamArch("arm64"); got != "aarch64" {
		t.Fatalf("arm64 upstream = %q", got)
	}
	if got := FirecrackerUpstreamArch("amd64"); got != "x86_64" {
		t.Fatalf("amd64 upstream = %q", got)
	}
}
