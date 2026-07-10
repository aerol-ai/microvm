package dockerpool

import (
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Key identifies a warm-pool target by resolved image identity + runtime.
type Key struct {
	Image                 string
	ImageDigest           string
	ImageRegistryRef      string
	ImageDistributionMode string
	Runtime               string
}

// KeyString returns a stable map key for the pool. It canonicalizes through
// the same defaulting rule the service's image-distribution normalization
// applies (empty mode → external_registry, empty ref → image), because keys
// reach the pool from two sides that MUST collide: boot-time pins are built
// bare (Key{Image, Runtime}), while create-path keys are computed after
// NormalizeCreateImageDistribution filled the metadata. Without this, pinned
// slots sit under a keystring no create ever computes — permanently
// unreachable and, being pinned, never idle-reaped.
func (k Key) KeyString() string {
	mode := strings.TrimSpace(k.ImageDistributionMode)
	ref := strings.TrimSpace(k.ImageRegistryRef)
	image := strings.TrimSpace(k.Image)
	if mode == "" && image != "" {
		mode = models.ImageDistributionExternalRegistry
	}
	if (mode == models.ImageDistributionExternalRegistry || mode == models.ImageDistributionAOCR) && ref == "" {
		ref = image
	}
	return strings.Join([]string{
		image,
		strings.TrimSpace(k.ImageDigest),
		ref,
		mode,
		strings.TrimSpace(k.Runtime),
	}, "\x00")
}

// KeyFromRequest builds a pool key from a create request and resolved runtime.
func KeyFromRequest(req models.CreateSandboxRequest, runtime string) Key {
	return Key{
		Image:                 strings.TrimSpace(req.Image),
		ImageDigest:           strings.TrimSpace(req.ImageDigest),
		ImageRegistryRef:      strings.TrimSpace(req.ImageRegistryRef),
		ImageDistributionMode: strings.TrimSpace(req.ImageDistributionMode),
		Runtime:               strings.TrimSpace(runtime),
	}
}

// ParkReservationID is the capacity admitter key for a parked slot.
func ParkReservationID(slotID string) string {
	return "park:" + strings.TrimSpace(slotID)
}
