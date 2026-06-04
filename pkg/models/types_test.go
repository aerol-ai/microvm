package models

import (
	"testing"
	"time"
)

// --- GPURequest.Validate ---

func TestGPURequest_Validate_Nil(t *testing.T) {
	var g *GPURequest
	if err := g.Validate(); err != nil {
		t.Errorf("nil.Validate() = %v, want nil", err)
	}
}

func TestGPURequest_Validate_ValidVendors(t *testing.T) {
	for _, vendor := range []GPUVendor{GPUVendorNVIDIA, GPUVendorAMD, GPUVendorApple} {
		g := &GPURequest{Vendor: vendor, Count: 1}
		if err := g.Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", vendor, err)
		}
	}
}

func TestGPURequest_Validate_InvalidVendor(t *testing.T) {
	g := &GPURequest{Vendor: "unknown-vendor"}
	if err := g.Validate(); err == nil {
		t.Error("Validate(unknown vendor) = nil, want error")
	}
}

func TestGPURequest_Validate_InvalidCount(t *testing.T) {
	g := &GPURequest{Vendor: GPUVendorNVIDIA, Count: -2}
	if err := g.Validate(); err == nil {
		t.Error("Validate(count=-2) = nil, want error")
	}
}

func TestGPURequest_Validate_AllCount(t *testing.T) {
	g := &GPURequest{Vendor: GPUVendorNVIDIA, Count: -1} // -1 = all
	if err := g.Validate(); err != nil {
		t.Errorf("Validate(count=-1) = %v, want nil", err)
	}
}

// --- NormalizeFailoverPolicy ---

func TestNormalizeFailoverPolicy(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", FailoverPolicyNone, false},
		{"none", FailoverPolicyNone, false},
		{"NONE", FailoverPolicyNone, false},
		{" none ", FailoverPolicyNone, false},
		{"recreate", FailoverPolicyRecreate, false},
		{"RECREATE", FailoverPolicyRecreate, false},
		{"invalid", "", true},
		{"destroy", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeFailoverPolicy(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeFailoverPolicy(%q) = %q, nil; want error", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("NormalizeFailoverPolicy(%q) = %q, %v; want %q, nil", c.in, got, err, c.want)
		}
	}
}

func TestFailover_NormalizedPolicy(t *testing.T) {
	f := Failover{Policy: "recreate"}
	if got := f.NormalizedPolicy(); got != FailoverPolicyRecreate {
		t.Errorf("NormalizedPolicy() = %q, want %q", got, FailoverPolicyRecreate)
	}

	f2 := Failover{Policy: "bad"}
	if got := f2.NormalizedPolicy(); got != "" {
		t.Errorf("NormalizedPolicy(bad) = %q, want empty", got)
	}
}

func TestFailover_ShouldRecreate(t *testing.T) {
	if (Failover{Policy: "recreate"}).ShouldRecreate() != true {
		t.Error("ShouldRecreate(recreate) = false, want true")
	}
	if (Failover{Policy: "none"}).ShouldRecreate() != false {
		t.Error("ShouldRecreate(none) = true, want false")
	}
}

func TestFailover_Validate(t *testing.T) {
	if err := (Failover{Policy: "recreate"}).Validate(); err != nil {
		t.Errorf("Validate(recreate) = %v, want nil", err)
	}
	if err := (Failover{Policy: "bad"}).Validate(); err == nil {
		t.Error("Validate(bad) = nil, want error")
	}
}

// --- NormalizeImageDistributionMode ---

func TestNormalizeImageDistributionMode(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{ImageDistributionExternalRegistry, ImageDistributionExternalRegistry, false},
		{ImageDistributionAOCR, ImageDistributionAOCR, false},
		{ImageDistributionAOCRImported, ImageDistributionAOCRImported, false},
		{ImageDistributionLocalOnly, ImageDistributionLocalOnly, false},
		{"AOCR", ImageDistributionAOCR, false},
		{"unknown", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeImageDistributionMode(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeImageDistributionMode(%q) = %q, nil; want error", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("NormalizeImageDistributionMode(%q) = %q, %v; want %q, nil", c.in, got, err, c.want)
		}
	}
}

// --- ImageDistributionMetadata.IsZero ---

func TestImageDistributionMetadata_IsZero(t *testing.T) {
	if !((ImageDistributionMetadata{}).IsZero()) {
		t.Error("zero value should IsZero() == true")
	}
	if (ImageDistributionMetadata{Mode: "aocr"}).IsZero() {
		t.Error("non-zero mode should IsZero() == false")
	}
	if (ImageDistributionMetadata{Digest: "sha256:abc"}).IsZero() {
		t.Error("non-zero digest should IsZero() == false")
	}
	now := time.Now()
	if (ImageDistributionMetadata{VerifiedAt: &now}).IsZero() {
		t.Error("non-zero verified_at should IsZero() == false")
	}
	// whitespace-only fields count as zero
	if !((ImageDistributionMetadata{Mode: "  ", Digest: ""}).IsZero()) {
		t.Error("whitespace-only mode should still IsZero() == true")
	}
}

// --- CreateSandboxRequest ImageDistribution methods ---

func TestCreateSandboxRequest_ImageDistribution(t *testing.T) {
	now := time.Now()
	r := CreateSandboxRequest{
		ImageDistributionMode: "aocr",
		ImageDigest:           "sha256:abc",
		ImageRegistryRef:      "registry.example.com/img",
		ImageVerifiedAt:       &now,
	}
	got := r.ImageDistribution()
	if got.Mode != "aocr" || got.Digest != "sha256:abc" || got.RegistryRef != "registry.example.com/img" || got.VerifiedAt != &now {
		t.Errorf("ImageDistribution() = %+v, unexpected values", got)
	}
}

func TestCreateSandboxRequest_ApplyImageDistribution_Nil(t *testing.T) {
	var r *CreateSandboxRequest
	r.ApplyImageDistribution(ImageDistributionMetadata{Mode: "aocr"}) // must not panic
}

func TestCreateSandboxRequest_ApplyImageDistribution(t *testing.T) {
	r := &CreateSandboxRequest{}
	now := time.Now()
	r.ApplyImageDistribution(ImageDistributionMetadata{
		Mode:        " aocr ",
		Digest:      " sha256:abc ",
		RegistryRef: " reg.io/img ",
		VerifiedAt:  &now,
	})
	if r.ImageDistributionMode != "aocr" {
		t.Errorf("Mode = %q, want aocr (trimmed)", r.ImageDistributionMode)
	}
	if r.ImageDigest != "sha256:abc" {
		t.Errorf("Digest = %q, want sha256:abc (trimmed)", r.ImageDigest)
	}
}

func TestCreateSandboxRequest_ShouldRecreateOnFailover(t *testing.T) {
	r := CreateSandboxRequest{}
	if r.ShouldRecreateOnFailover() {
		t.Error("nil Failover should not recreate on failover")
	}
	r.Failover = &Failover{Policy: "recreate"}
	if !r.ShouldRecreateOnFailover() {
		t.Error("Failover=recreate should recreate on failover")
	}
}

// --- SandboxSnapshot ImageDistribution methods ---

func TestSandboxSnapshot_ImageDistribution(t *testing.T) {
	now := time.Now()
	s := SandboxSnapshot{
		ImageDistributionMode: "external_registry",
		ImageDigest:           "sha256:def",
		ImageRegistryRef:      "docker.io/lib/alpine",
		ImageVerifiedAt:       &now,
	}
	got := s.ImageDistribution()
	if got.Mode != "external_registry" || got.Digest != "sha256:def" {
		t.Errorf("ImageDistribution() = %+v, unexpected", got)
	}
}

func TestSandboxSnapshot_ApplyImageDistribution_Nil(t *testing.T) {
	var s *SandboxSnapshot
	s.ApplyImageDistribution(ImageDistributionMetadata{Mode: "aocr"}) // must not panic
}

func TestSandboxSnapshot_ApplyImageDistribution(t *testing.T) {
	s := &SandboxSnapshot{}
	s.ApplyImageDistribution(ImageDistributionMetadata{Mode: "local_only", Digest: " sha256:xyz "})
	if s.ImageDistributionMode != "local_only" {
		t.Errorf("Mode = %q, want local_only", s.ImageDistributionMode)
	}
	if s.ImageDigest != "sha256:xyz" {
		t.Errorf("Digest = %q, want sha256:xyz (trimmed)", s.ImageDigest)
	}
}

// --- ValidExposedPortProtocol ---

func TestValidExposedPortProtocol(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", ExposedPortProtocolHTTP, false},
		{"http", ExposedPortProtocolHTTP, false},
		{"tcp", ExposedPortProtocolTCP, false},
		{"tls", ExposedPortProtocolTLS, false},
		{"HTTP", "", true},
		{"grpc", "", true},
	}
	for _, c := range cases {
		got, err := ValidExposedPortProtocol(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ValidExposedPortProtocol(%q) = %q, nil; want error", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("ValidExposedPortProtocol(%q) = %q, %v; want %q, nil", c.in, got, err, c.want)
		}
	}
}
