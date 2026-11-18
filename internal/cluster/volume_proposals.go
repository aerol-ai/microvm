package cluster

import (
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// Tenant volume rows and attachments, from a worker or gateway (least
// privilege; peer_proposals.go). A volume's row names the storage location
// every node mounts and reclaims (its frozen source), so only a server makes
// one, from its own platform-volume settings: a volume's API create and
// delete go to a server (the Daytona facade sends them there), and so does
// a create that names a platform volume (clustercreate.Prepare), which makes
// the rows its volumes need before the create goes to its node. What a
// worker or gateway still writes is what its own sandboxes need:
//
//	row upsert      only a row that exists (the get half of get-or-create);
//	                the leader writes the existing row into the command
//	                (stampProposal), so nothing of the sender's reaches it
//	row delete      a delete_with_sandbox row (its last sandbox is gone);
//	                any reclaim it records is drained by the sender, from
//	                the row's own source
//	attach          each attachment's sandbox is the sender's, its tenant
//	                is that sandbox's, its source the row's
//	detach          the sandbox is the sender's
//
// The rules apply once every member runs a build that sends those creates
// to a server (servers sign: fsm_server_signing.go); before that every node
// writes as it always did.

// volumeTenantOf reports whether tenant is the volume scope of a sandbox
// owned by ownerRef: its team's, or for an operator's sandbox an operator
// scope.
func volumeTenantOf(tenant, ownerRef string) bool {
	tenant = strings.TrimSpace(tenant)
	if want := volumes.TenantForOwnerRef(ownerRef); want != "" {
		return tenant == want
	}
	return strings.HasPrefix(tenant, "op-") && volumes.ValidateOperatorScope(tenant) == nil
}

// volumeWriteBound reports whether a worker's or gateway's volume write is
// bound to a sandbox it owns (see above). Only the volume ops reach it.
func volumeWriteBound(cmd command, sender string, st proposalState) bool {
	is := func(id string) bool { return strings.TrimSpace(id) == sender }
	owned := func(id string) (Placement, bool) {
		p, ok := st.placementForProposal(id, false)
		return p, ok && is(p.OwnerNodeID)
	}
	switch cmd.Op {
	case opUpsertVolume:
		if cmd.Volume == nil {
			return false
		}
		_, ok := st.volumeByNameForProposal(cmd.Volume.Tenant, cmd.Volume.Name)
		return ok
	case opDeleteVolume:
		if r := strings.TrimSpace(cmd.VolumeReclaimNodeID); r != "" && !is(r) {
			return false
		}
		row, ok := st.volumeForProposal(cmd.VolumeTenant, cmd.VolumeID)
		if !ok {
			return true // the FSM answers ErrUnknownVolume
		}
		if src := strings.TrimSpace(cmd.VolumeReclaimSource); src != "" && src != row.Source {
			return false
		}
		return row.DeleteWithSandbox
	case opPutVolumeAttach:
		if len(cmd.VolumeAttachments) == 0 {
			return false
		}
		for _, a := range cmd.VolumeAttachments {
			p, ok := owned(a.SandboxID)
			if !ok || !volumeTenantOf(a.Tenant, p.OwnerRef) {
				return false
			}
			if row, ok := st.volumeForProposal(a.Tenant, a.VolumeID); ok && row.Source != "" && row.Source != a.Source {
				return false
			}
		}
		return true
	case opDeleteVolumeAttach:
		p, ok := st.placementForProposal(cmd.VolumeSandboxID, false)
		return !ok || is(p.OwnerNodeID)
	}
	return true
}

// volumeForProposal reads one volume row for the rule.
func (f *placementFSM) volumeForProposal(tenant, id string) (models.Volume, bool) {
	if f == nil {
		return models.Volume{}, false
	}
	v, err := f.VolumeByID(tenant, id)
	return v, err == nil
}

// volumeByNameForProposal reads one volume row by its name for the rule.
func (f *placementFSM) volumeByNameForProposal(tenant, name string) (models.Volume, bool) {
	if f == nil {
		return models.Volume{}, false
	}
	v, err := f.VolumeByName(tenant, name)
	return v, err == nil
}
