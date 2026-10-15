package docker

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/distribution/reference"
)

// SnapshotImageNamespace is the local repository namespace committed
// snapshots live under. Only SnapshotImageTag names images in it, so a
// snapshot never shares a tag with an ordinary image or with another
// snapshot, whatever it is called. (Snapshot names like "snapshots/demo:v1"
// are a convention callers already use, so that namespace stays theirs.)
const SnapshotImageNamespace = "aerolvm-snapshot"

// SnapshotImageTag is the local tag a snapshot called name is committed
// under: `aerolvm-snapshot/<hash of the name>:latest`. The name a caller chooses is
// only a catalog entry; were it the tag, a snapshot called "python" would
// replace the python image on its node for everyone. The hash is of the
// name's canonical spelling, so every spelling of one name (which the
// catalog treats as one snapshot) gets one tag, and a retried commit lands
// on the tag the first attempt used.
func SnapshotImageTag(name string) string {
	canonical := strings.TrimSpace(name)
	if named, err := reference.ParseNormalizedNamed(canonical); err == nil {
		if _, digested := named.(reference.Digested); !digested {
			canonical = reference.TagNameOnly(named).String()
		}
	}
	sum := sha256.Sum256([]byte(canonical))
	return SnapshotImageNamespace + "/" + hex.EncodeToString(sum[:])[:32] + ":latest"
}

// IsSnapshotImageRef reports whether ref names an image in the snapshot
// namespace, in any spelling the engine resolves to it:
// "aerolvm-snapshot/x", "docker.io/aerolvm-snapshot/x" and
// "index.docker.io/aerolvm-snapshot/x:latest" are all the same local image.
func IsSnapshotImageRef(ref string) bool {
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(ref))
	if err != nil {
		return false
	}
	return reference.Domain(named) == "docker.io" && strings.HasPrefix(reference.Path(named), SnapshotImageNamespace+"/")
}

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
