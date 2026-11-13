package cluster

import "github.com/aerol-ai/microvm/pkg/models"

// KubeClaimTag marks a sandbox made by an agent-sandbox SandboxClaim
// (internal/kubeapi): its value is "true".
const KubeClaimTag = "agents.x-k8s.io/claim"

// KubeClaimMark is Placement.KubeClaim.
type KubeClaimMark uint8

const (
	// KubeClaimUnknown is a row with no mark: written by an older build,
	// or rewritten by one, which drops a field it does not know. A reader
	// reads the spec, as before the mark.
	KubeClaimUnknown KubeClaimMark = iota
	// KubeClaimNo is a sandbox no claim made.
	KubeClaimNo
	// KubeClaimYes is a claim's sandbox.
	KubeClaimYes
)

func kubeClaimMarkOf(spec *models.CreateSandboxRequest) KubeClaimMark {
	if spec != nil && spec.Tags[KubeClaimTag] == "true" {
		return KubeClaimYes
	}
	return KubeClaimNo
}
