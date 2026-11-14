package containerd

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/aerol-ai/microvm/pkg/models"
)

// imageWithUser builds a content provider and image whose config says USER
// user, the way containerd resolves it for the client platform.
func imageWithUser(t *testing.T, user string) (*memProvider, *configFakeImage) {
	t.Helper()
	cfgBody, err := json.Marshal(ocispec.Image{Config: ocispec.ImageConfig{User: user, Cmd: []string{"sleep", "inf"}}})
	if err != nil {
		t.Fatal(err)
	}
	cfgDigest := digest.FromBytes(cfgBody)
	desc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig, Digest: cfgDigest, Size: int64(len(cfgBody))}
	return &memProvider{blobs: map[digest.Digest][]byte{cfgDigest: cfgBody}}, &configFakeImage{manifestDesc: desc, configDesc: desc}
}

// TestCreate_RequireNonRootUser: with the create policy's require_non_root
// rule on, the image config's USER decides before any container exists.
func TestCreate_RequireNonRootUser(t *testing.T) {
	cases := []struct {
		name     string
		user     string
		require  bool
		wantDeny bool
	}{
		{"root image, rule off", "", false, false},
		{"root image, rule on", "", true, true},
		{"named user, rule on", "nobody", true, true},
		{"numeric non-root, rule on", "1000", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubToolboxProbe(t)
			provider, img := imageWithUser(t, tc.user)
			tr := newFakeTransport()
			tr.provider = provider
			tr.image = img
			d := newTestDriver(t)
			d.SetClient(NewTestClient("aerolvm", tr))
			_, err := d.Create(context.Background(), models.CreateSandboxRequest{
				Image: "acme/app:1", ContainerCommand: []string{"sleep"}, RequireNonRootUser: tc.require,
			}, "sb-nr", "tok", nil)
			var pe *models.CreatePolicyError
			denied := errors.As(err, &pe) && pe.Rule == models.CreatePolicyRuleRequireNonRoot
			if denied != tc.wantDeny {
				t.Fatalf("Create = %v, want denied=%v", err, tc.wantDeny)
			}
			if tc.wantDeny && len(tr.containers) != 0 {
				t.Fatal("a refused image must not reach NewContainer")
			}
		})
	}
}

// TestCreate_RequireNonRootUserUnreadableConfig: an image config the driver
// cannot read fails the create rather than skipping the check.
func TestCreate_RequireNonRootUserUnreadableConfig(t *testing.T) {
	stubToolboxProbe(t)
	_, img := imageWithUser(t, "1000")
	tr := newFakeTransport()
	tr.provider = &memProvider{blobs: map[digest.Digest][]byte{}}
	tr.image = img
	d := newTestDriver(t)
	d.SetClient(NewTestClient("aerolvm", tr))
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "acme/app:1", ContainerCommand: []string{"sleep"}, RequireNonRootUser: true,
	}, "sb-nr", "tok", nil)
	if err == nil || len(tr.containers) != 0 {
		t.Fatalf("Create = %v, want an image-user read failure before any container", err)
	}
	if _, err := imageUser(context.Background(), nil, img); err == nil {
		t.Fatal("imageUser with no client must fail")
	}
}

func TestPoolEligible_RequireNonRootUser(t *testing.T) {
	if poolEligible(models.CreateSandboxRequest{Image: "alpine:3.20", RequireNonRootUser: true}, nil) {
		t.Fatal("require_non_root must make a create ineligible for a parked slot")
	}
}
