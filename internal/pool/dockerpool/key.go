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

// KeyString returns a stable map key for the pool.
func (k Key) KeyString() string {
	return strings.Join([]string{
		k.Image,
		k.ImageDigest,
		k.ImageRegistryRef,
		k.ImageDistributionMode,
		k.Runtime,
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
