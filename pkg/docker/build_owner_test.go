package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/distribution/reference"
)

// An owner's build tag carries its namespace after the node segment: two
// owners never share a tag, the node affinity still decodes, and an
// operator's tag is the one it always was.
func TestBuildTagForOwner(t *testing.T) {
	const dockerfile = "FROM alpine\nRUN true"
	digest := strings.TrimPrefix(BuildTagFor(dockerfile, nil), BuiltImageNamespace+"/")
	if got := BuildTagForOwner(dockerfile, nil, "", ""); got != BuildTagFor(dockerfile, nil) {
		t.Fatalf("operator tag = %q", got)
	}
	if got := BuildTagForOwner(dockerfile, nil, "", "tenant-abc"); got != BuiltImageNamespace+"/tenant-abc/"+digest {
		t.Fatalf("owner tag = %q", got)
	}
	bound := BuildTagForOwner(dockerfile, nil, "worker-a", "tenant-abc")
	if node, ok := BuiltImagePlacementNode(bound); !ok || node != "worker-a" || BuiltImageOwnerNamespace(bound) != "tenant-abc" {
		t.Fatalf("node-bound owner tag %q: node %q %v, owner %q", bound, node, ok, BuiltImageOwnerNamespace(bound))
	}
	if BuildTagForOwner(dockerfile, nil, "", "tenant-a") == BuildTagForOwner(dockerfile, nil, "", "tenant-b") {
		t.Fatal("two owners got one tag")
	}
	for _, tag := range []string{bound, BuildTagForOwner(dockerfile, nil, "", "tenant-abc")} {
		if _, err := reference.ParseNormalizedNamed(tag); err != nil || !IsBuiltImageRef(tag) || !IsLocalOnlyImageRef(tag) {
			t.Errorf("tag %q: %v, built %v, local %v", tag, err, IsBuiltImageRef(tag), IsLocalOnlyImageRef(tag))
		}
	}
}

func TestBuiltImageRefs(t *testing.T) {
	for ref, want := range map[string]string{
		"aerolvm-build/tenant-abc/0123:latest":                    "tenant-abc",
		"docker.io/aerolvm-build/tenant-abc/0123":                 "tenant-abc",
		"aerolvm-build/node-mzxw6/tenant-abc/0123:latest":         "tenant-abc",
		"aerolvm-build/0123:latest":                               "",
		"aerolvm-build/node-mzxw6/0123:latest":                    "",
		"aerolvm-build/tenant-abc:latest":                         "",
		"ghcr.io/aerolvm-build/tenant-abc/0123":                   "",
		"python:3.12":                                             "",
		"Not A Ref":                                               "",
		"index.docker.io/aerolvm-build/node-mzxw6/tenant-x/0:tag": "tenant-x",
	} {
		if got := BuiltImageOwnerNamespace(ref); got != want {
			t.Errorf("BuiltImageOwnerNamespace(%q) = %q, want %q", ref, got, want)
		}
	}
	for ref, want := range map[string]bool{
		"aerolvm-build/0123:latest":       true,
		"docker.io/aerolvm-build/0123":    true,
		"ghcr.io/aerolvm-build/0123":      false,
		"aerolvm-builds/0123":             false,
		"aerolvm-snapshot/0123:latest":    false,
		"":                                false,
		"index.docker.io/aerolvm-build/x": true,
	} {
		if got := IsBuiltImageRef(ref); got != want {
			t.Errorf("IsBuiltImageRef(%q) = %v, want %v", ref, got, want)
		}
	}
}

// A forced-pull build asks the engine to pull every image it names; an
// ordinary one does not.
func TestBuildImageForcePull(t *testing.T) {
	var pulls []string
	c := &Client{streamClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		pulls = append(pulls, r.URL.Query().Get("pull"))
		return textResponse(http.StatusOK, `{"stream":"ok"}`), nil
	})}}
	for _, force := range []bool{true, false} {
		tag := "aerolvm-build/force-" + map[bool]string{true: "on", false: "off"}[force] + ":latest"
		if err := c.BuildImage(context.Background(), BuildImageRequest{Tag: tag, DockerfileContent: "FROM alpine", ForcePull: force}); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(pulls, []string{"1", ""}) {
		t.Fatalf("pull parameters = %q; want forced then not", pulls)
	}
}

// The janitor's listing asks for every tag depth — plain, node-bound, and
// with an owner — since the reference filter's "*" stops at "/".
func TestListBuiltImagesListsEveryDepth(t *testing.T) {
	var filters map[string][]string
	c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/images/json" {
			_ = json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters)
			return textResponse(http.StatusOK, `[{"RepoTags":["aerolvm-build/node-mzxw6/tenant-x/0123:latest","python:3.12"]}]`), nil
		}
		return textResponse(http.StatusOK, `{"Id":"sha256:1","Metadata":{"LastTagTime":"2026-01-01T00:00:00Z"}}`), nil
	})}}
	images, err := c.ListBuiltImages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"aerolvm-build/*", "aerolvm-build/*/*", "aerolvm-build/*/*/*"}; !slices.Equal(filters["reference"], want) {
		t.Fatalf("reference filters = %q, want %q", filters["reference"], want)
	}
	if len(images) != 1 || images[0].Tag != "aerolvm-build/node-mzxw6/tenant-x/0123:latest" {
		t.Fatalf("listed %+v; want only the nested build", images)
	}
}
