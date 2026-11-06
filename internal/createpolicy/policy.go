// Package createpolicy loads the operator's create policy
// (SB_CREATE_POLICY_FILE, plans/agent-sandbox-feature-parity.md T3): which
// images, registries and runtimes a create may use, how big a sandbox may
// be, whether its image must run as a non-root user and whether it may ask
// for a GPU. sandboxd checks it in memory at create and resize; the file is
// read at boot and on reload, never on the create path. Unset means today's
// behavior: every rule is off.
package createpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/distribution/reference"
	"gopkg.in/yaml.v3"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Version is the only file format version this build accepts.
const Version = 1

// Rule names, as a refusal and the aerolvm_create_policy_denied_total
// metric name them. Each is the YAML path of the setting that refused.
const (
	RuleImages         = "images"
	RuleRuntimes       = "runtimes"
	RuleMaxCPU         = "limits.max_cpu"
	RuleMaxMemoryMB    = "limits.max_memory_mb"
	RuleMaxDiskGB      = "limits.max_disk_gb"
	RuleRequireNonRoot = models.CreatePolicyRuleRequireNonRoot
	RuleAllowGPU       = "allow_gpu"
)

// maxListEntries bounds each list: the image check walks the lists on every
// create, so a file can't make that unbounded.
const maxListEntries = 1024

// File is the YAML document.
type File struct {
	Version int `yaml:"version"`
	Images  struct {
		// AllowedRegistries are registry hosts (with a port when the
		// registry has one); an image from one of them passes.
		AllowedRegistries []string `yaml:"allowed_registries"`
		// Allowed are image patterns; "*" matches any run of characters,
		// "/" included.
		Allowed []string `yaml:"allowed"`
	} `yaml:"images"`
	Runtimes []string `yaml:"runtimes"`
	Limits   struct {
		MaxCPU      float64 `yaml:"max_cpu"`
		MaxMemoryMB int     `yaml:"max_memory_mb"`
		MaxDiskGB   int     `yaml:"max_disk_gb"`
	} `yaml:"limits"`
	RequireNonRoot bool  `yaml:"require_non_root"`
	AllowGPU       *bool `yaml:"allow_gpu"`
}

// Policy is a validated create policy. A nil *Policy allows everything, so
// callers never branch on "is there a file".
type Policy struct {
	registries map[string]bool
	patterns   []string
	runtimes   map[string]bool
	maxCPU     float64
	maxMemory  int
	maxDisk    int
	nonRoot    bool
	gpu        bool
	hash       string
}

// Load reads and validates path.
func Load(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("create policy file: %w", err)
	}
	return Parse(raw)
}

// Parse validates a policy document. Unknown keys and explicitly empty lists
// are errors: in a security file a typo, or "allowed: []" meant as "allow
// nothing", must not silently mean "no rule".
func Parse(raw []byte) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("create policy file: %w", err)
	}
	if f.Version != Version {
		return nil, fmt.Errorf("create policy file: version %d, want %d", f.Version, Version)
	}
	sum := sha256.Sum256(raw)
	p := &Policy{hash: hex.EncodeToString(sum[:8]), gpu: true, nonRoot: f.RequireNonRoot}
	if f.AllowGPU != nil {
		p.gpu = *f.AllowGPU
	}

	if f.Images.AllowedRegistries != nil {
		if err := checkList("images.allowed_registries", f.Images.AllowedRegistries); err != nil {
			return nil, err
		}
		p.registries = map[string]bool{}
		for _, r := range f.Images.AllowedRegistries {
			host, err := normalizeRegistry(r)
			if err != nil {
				return nil, fmt.Errorf("create policy file: images.allowed_registries: %w", err)
			}
			p.registries[host] = true
		}
	}
	if f.Images.Allowed != nil {
		if err := checkList("images.allowed", f.Images.Allowed); err != nil {
			return nil, err
		}
		for _, pat := range f.Images.Allowed {
			pat = strings.TrimSpace(pat)
			if pat == "" || strings.ContainsAny(pat, " \t\r\n") {
				return nil, fmt.Errorf("create policy file: images.allowed: %q is not an image pattern", pat)
			}
			p.patterns = append(p.patterns, pat)
		}
	}
	if f.Runtimes != nil {
		if err := checkList("runtimes", f.Runtimes); err != nil {
			return nil, err
		}
		p.runtimes = map[string]bool{}
		for _, r := range f.Runtimes {
			r = strings.TrimSpace(r)
			if r == "" {
				return nil, fmt.Errorf("create policy file: runtimes: empty entry")
			}
			if _, err := models.ValidRuntime(r); err != nil {
				return nil, fmt.Errorf("create policy file: runtimes: %w", err)
			}
			p.runtimes[r] = true
		}
	}

	l := f.Limits
	if math.IsNaN(l.MaxCPU) || math.IsInf(l.MaxCPU, 0) || l.MaxCPU < 0 {
		return nil, fmt.Errorf("create policy file: limits.max_cpu must be a number >= 0 (0 = no limit)")
	}
	if l.MaxMemoryMB < 0 || l.MaxDiskGB < 0 {
		return nil, fmt.Errorf("create policy file: limits.max_memory_mb and limits.max_disk_gb must be >= 0 (0 = no limit)")
	}
	p.maxCPU, p.maxMemory, p.maxDisk = l.MaxCPU, l.MaxMemoryMB, l.MaxDiskGB
	return p, nil
}

func checkList(field string, list []string) error {
	if len(list) == 0 {
		return fmt.Errorf("create policy file: %s is empty; remove it to turn the rule off", field)
	}
	if len(list) > maxListEntries {
		return fmt.Errorf("create policy file: %s has %d entries, at most %d", field, len(list), maxListEntries)
	}
	return nil
}

// normalizeRegistry turns "Docker.io", "index.docker.io" or
// "registry.corp:5000" into the lowercase host[:port] reference.Domain
// reports, so the file and a parsed image spell Docker Hub the same way.
func normalizeRegistry(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(raw))
	if host == "" || strings.ContainsAny(host, "/*@ \t") || strings.Contains(host, "://") {
		return "", fmt.Errorf("%q is not a registry host (write it like ghcr.io or registry.corp:5000)", raw)
	}
	if host == "index.docker.io" || host == "registry-1.docker.io" {
		host = "docker.io"
	}
	return host, nil
}

// Hash identifies the file's content.
func (p *Policy) Hash() string {
	if p == nil {
		return ""
	}
	return p.hash
}

// RequireNonRoot reports whether container images must run as a non-root
// user. The runtime checks it once it has the image config
// (models.CheckImageUserNonRoot).
func (p *Policy) RequireNonRoot() bool { return p != nil && p.nonRoot }

// HasImageRules reports whether an image or registry list is set.
func (p *Policy) HasImageRules() bool {
	return p != nil && (p.registries != nil || p.patterns != nil)
}

// Create is what a create is checked on: the values after the server's
// defaults are filled in, so a create that leaves a field out is held to
// the same limit as one that sets it.
type Create struct {
	// Image is the image the runtime will start, after snapshot names are
	// resolved; empty for a runtime that runs no image.
	Image string
	// ImageRules is false for runtimes that run a module or a bundle, not an
	// image (wasm, isolate): the image rules do not apply to them.
	ImageRules bool
	// LocalOnly marks an image only this node can have (a snapshot commit
	// or a build): it was never pulled from a registry, so only an image
	// pattern can allow it.
	LocalOnly bool
	// ImageID marks a reference the engine resolves by image id: it names
	// no repository, so no rule can allow it.
	ImageID  bool
	Runtime  string
	CPU      float64
	MemoryMB int
	DiskGB   int
	GPU      bool
}

// CheckCreate applies every rule and returns the first refusal
// (*models.CreatePolicyError): the runtime first, since it decides whether
// the image rules apply, then the image, the size and the GPU.
func (p *Policy) CheckCreate(c Create) error {
	if p == nil {
		return nil
	}
	if p.runtimes != nil && !p.runtimes[c.Runtime] {
		return deny(RuleRuntimes, "runtime %q is not allowed on this server", c.Runtime)
	}
	if c.ImageRules {
		if err := p.CheckImage(c.Image, c.LocalOnly, c.ImageID); err != nil {
			return err
		}
	}
	if err := p.CheckSize(c.CPU, c.MemoryMB, c.DiskGB); err != nil {
		return err
	}
	if c.GPU && !p.gpu {
		return deny(RuleAllowGPU, "GPUs are not allowed on this server")
	}
	return nil
}

// CheckSize holds a size to the limits. A zero value is "not changing" (a
// resize names only what it changes) and always passes.
func (p *Policy) CheckSize(cpu float64, memoryMB, diskGB int) error {
	if p == nil {
		return nil
	}
	if p.maxCPU > 0 && cpu > p.maxCPU {
		return deny(RuleMaxCPU, "cpu %g is above this server's limit of %g", cpu, p.maxCPU)
	}
	if p.maxMemory > 0 && memoryMB > p.maxMemory {
		return deny(RuleMaxMemoryMB, "memory_mb %d is above this server's limit of %d", memoryMB, p.maxMemory)
	}
	if p.maxDisk > 0 && diskGB > p.maxDisk {
		return deny(RuleMaxDiskGB, "disk %d GB is above this server's limit of %d GB", diskGB, p.maxDisk)
	}
	return nil
}

// CheckImage holds an image reference to the image rules. It matches the
// parsed reference, never the caller's spelling: "python:3.12",
// "docker.io/library/python:3.12" and "index.docker.io/library/python:3.12"
// are one image and get one answer. A pattern is tried against both the
// full name (docker.io/library/python:3.12) and the short one
// (python:3.12), which name the same image, so either style works in the
// file.
func (p *Policy) CheckImage(image string, localOnly, imageID bool) error {
	if !p.HasImageRules() {
		return nil
	}
	image = strings.TrimSpace(image)
	if imageID {
		return deny(RuleImages, "image %q is an image id; start an allowed image by its name", image)
	}
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return deny(RuleImages, "image %q is not a valid image reference", image)
	}
	if _, digested := named.(reference.Digested); !digested {
		named = reference.TagNameOnly(named)
	}
	full, short := named.String(), reference.FamiliarString(named)
	if !localOnly && p.registries[strings.ToLower(reference.Domain(named))] {
		return nil
	}
	for _, pat := range p.patterns {
		if globMatch(pat, full) || globMatch(pat, short) {
			return nil
		}
	}
	return deny(RuleImages, "image %q is not on this server's list of allowed images", full)
}

func deny(rule, format string, args ...any) error {
	return &models.CreatePolicyError{Rule: rule, Detail: fmt.Sprintf(format, args...)}
}

// globMatch reports whether s matches pattern, where "*" matches any run of
// characters ("/" and ":" included) and everything else matches itself.
// Iterative with one backtrack point, so it is linear in practice and never
// exponential, whatever the file holds.
func globMatch(pattern, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pattern) && pattern[px] == '*':
			star, mark = px, sx
			px++
		case px < len(pattern) && pattern[px] == s[sx]:
			px++
			sx++
		case star >= 0:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
