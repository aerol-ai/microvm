package cluster

import "github.com/aerol-ai/microvm/pkg/models"

func placementWantsFailoverRecreate(p Placement) bool {
	return specWantsFailoverRecreate(p.Spec)
}

func specWantsFailoverRecreate(spec *models.CreateSandboxRequest) bool {
	return spec != nil && spec.ShouldRecreateOnFailover()
}
