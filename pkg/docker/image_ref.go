package docker

import (
	"strings"

	"github.com/distribution/reference"
)

// LooksLikeImageID reports a reference the engine would resolve by image id
// rather than by name: "sha256:<hex>", or a bare lowercase hex string with
// no registry, path or tag. Docker resolves such a string against image ids
// by prefix when no image of that name exists, so even a few hex digits can
// pick out an image the caller was never given a name for.
func LooksLikeImageID(ref string) bool {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(strings.ToLower(ref), "sha256:") {
		return true
	}
	if ref == "" {
		return false
	}
	for _, c := range ref {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// EquivalentImageNames returns the spellings the engine treats as the same
// local image as ref, ref itself first: with and without the implicit
// docker.io registry (or its index.docker.io alias), with and without the
// implicit library/ path of an official image, and with and without the
// implicit :latest tag. A ref that does not parse as a name, or pins a
// digest, has only itself.
func EquivalentImageNames(ref string) []string {
	ref = strings.TrimSpace(ref)
	names := []string{ref}
	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return names
	}
	if _, digested := named.(reference.Digested); digested {
		return names
	}
	tag := "latest"
	if tagged, ok := named.(reference.Tagged); ok {
		tag = tagged.Tag()
	}
	domain, path := reference.Domain(named), reference.Path(named)
	domains := []string{domain + "/"}
	if domain == "docker.io" {
		domains = []string{"", "docker.io/", "index.docker.io/"}
	}
	paths := []string{path}
	if short, ok := strings.CutPrefix(path, "library/"); ok && domain == "docker.io" {
		paths = append(paths, short)
	}
	tags := []string{":" + tag}
	if tag == "latest" {
		tags = append(tags, "")
	}
	seen := map[string]bool{ref: true}
	for _, d := range domains {
		for _, p := range paths {
			for _, t := range tags {
				name := d + p + t
				if !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
	}
	return names
}
