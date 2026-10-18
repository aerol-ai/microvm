package daemon

import (
	"errors"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// errIdentityWithProviderValidator refuses sandboxd's own identity next to a
// provider that validates caller tokens itself (plans/identity-and-access.md
// §5.2). Both would resolve callers into one owner namespace, and the
// managed build already has its own login; this mirrors how a
// provider-supplied witness wins over the open-source one.
var errIdentityWithProviderValidator = errors.New("SB_IDENTITY_ENABLED=true cannot run with a control-plane provider that validates caller tokens: two identity sources would share one owner namespace; leave SB_IDENTITY_ENABLED off in the managed build")

// identityBootGuard is the boot-time check on identity sources: with
// identity on, sandboxd's API tokens (and later OIDC) are the only identity
// source besides the PAT.
func identityBootGuard(cfg config.Config, cp controlplane.Provider) error {
	if cfg.IdentityEnabled && cp.HasExternalValidator() {
		return errIdentityWithProviderValidator
	}
	return nil
}
