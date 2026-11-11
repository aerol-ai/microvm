package safety

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The Kubernetes images (plans/kubernetes-v2-architecture.md P1) download
// containerd, runc, gVisor and the CNI plugins at build time. A pin with a
// hash for one CPU type only would build amd64 and fail arm64 at release
// time, and an unpinned base image would change under a tag. These checks
// keep packaging/images/versions.env, the Dockerfiles, the build script and
// the release job in step.

func readVersionsEnv(t *testing.T, root string) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(root, "packaging", "images", "versions.env"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("versions.env: %q is not KEY=value", line)
		}
		out[k] = v
	}
	return out
}

func TestKubernetesImagePins(t *testing.T) {
	root := repoRoot(t)
	pins := readVersionsEnv(t, root)
	sha256Hex := regexp.MustCompile(`^[0-9a-f]{64}$`)
	sha512Hex := regexp.MustCompile(`^[0-9a-f]{128}$`)
	for _, c := range []struct{ name, hash string }{
		{"CONTAINERD", "SHA256"}, {"RUNC", "SHA256"}, {"CNI_PLUGINS", "SHA256"}, {"GVISOR", "SHA512"},
	} {
		version := pins[c.name+"_VERSION"] + pins[c.name+"_RELEASE"]
		if version == "" {
			t.Errorf("%s has no version", c.name)
		}
		for _, arch := range []string{"AMD64", "ARM64"} {
			key := c.name + "_" + c.hash + "_" + arch
			re := sha256Hex
			if c.hash == "SHA512" {
				re = sha512Hex
			}
			if !re.MatchString(pins[key]) {
				t.Errorf("%s = %q, want a %s hash", key, pins[key], strings.ToLower(c.hash))
			}
		}
	}
	for _, base := range []string{"DEBIAN_IMAGE", "DISTROLESS_IMAGE"} {
		if !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(pins[base]) {
			t.Errorf("%s = %q, want a reference pinned by digest", base, pins[base])
		}
	}

	argRE := regexp.MustCompile(`(?m)^ARG ([A-Z0-9_]+)`)
	fromRE := regexp.MustCompile(`(?m)^FROM (\S+)`)
	script, err := os.ReadFile(filepath.Join(root, "scripts", "build-images.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, image := range []string{"aerolvm", "aerolvm-runtime", "aerolvm-edge"} {
		if !strings.Contains(string(script), image) {
			t.Errorf("build-images.sh does not build %s", image)
		}
		file := strings.TrimPrefix(image, "aerolvm-") + ".Dockerfile"
		raw, err := os.ReadFile(filepath.Join(root, "packaging", "images", file))
		if err != nil {
			t.Fatalf("%s: %v", image, err)
		}
		for _, m := range argRE.FindAllStringSubmatch(string(raw), -1) {
			switch arg := m[1]; arg {
			case "TARGETARCH", "VERSION", "REVISION":
			default:
				if _, ok := pins[arg]; !ok {
					t.Errorf("%s: ARG %s is not pinned in versions.env", file, arg)
				}
			}
		}
		for _, m := range fromRE.FindAllStringSubmatch(string(raw), -1) {
			if m[1] != "${DEBIAN_IMAGE}" && m[1] != "${DISTROLESS_IMAGE}" {
				t.Errorf("%s: FROM %s is not a pinned base from versions.env", file, m[1])
			}
		}
	}
}

func TestReleaseWorkflowShipsKubernetesImages(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(raw)
	for _, want := range []string{
		"-o dist/aerolvm-supervisor_${{ matrix.suffix }} ./cmd/aerolvm-supervisor",
		"scripts/build-images.sh --dist dist",
		"cosign sign --yes",
		"subject-name: ghcr.io/aerol-ai/aerolvm\n",
		"subject-name: ghcr.io/aerol-ai/aerolvm-runtime\n",
		"subject-name: ghcr.io/aerol-ai/aerolvm-edge\n",
		"packages: write",
	} {
		if !strings.Contains(wf, want) {
			t.Errorf("release.yml lacks %q", want)
		}
	}
}
