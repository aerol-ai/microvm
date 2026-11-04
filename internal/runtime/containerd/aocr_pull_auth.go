package containerd

import (
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ConfigureAOCRPullAuth installs the node-local cluster-PAT pull credential,
// with the same signature and no-op rules as docker.Client.ConfigureAOCRPullAuth
// so the daemon wires both engines through one helper.
//
// Why containerd needs it at all: a cross-node create-from-snapshot hands the
// driver an AOCR ref (`<aocr>/cluster/<id>/snapshots/<name>:...`) with no
// caller credential, and AOCR rejects anonymous pulls of `cluster/<id>/*`.
// dockerd got this back-fill in pullImageDedup; without it a containerd node
// fails every such create with "failed to fetch anonymous token: 401".
//
// Must be called before the driver serves creates or the warm pool refills:
// the field is read without a lock on the pull path.
func (d *Driver) ConfigureAOCRPullAuth(hosts []string, clusterID, patPath string) {
	if a := dockerpkg.NewAOCRPullAuth(hosts, clusterID, patPath); a != nil {
		d.aocrPullAuth = a
	}
}

// pullAuthFor picks the credential for a registry pull of ref.
//
// The caller's credential always wins. containerd's pull treats an auth with
// an empty username as anonymous (see ensureImage), so the back-fill keys on
// that same predicate: whenever this pull would otherwise go out anonymous, an
// in-scope AOCR `cluster/` ref gets the cluster PAT instead.
//
// A PAT read failure returns (nil, err) after a warning, and the caller still
// attempts the pull anonymously — the same policy as the docker engine's
// resolveAOCRPullAuth, so both engines fail or succeed identically for a given
// node config. The caller uses err only to annotate a failed pull.
func (d *Driver) pullAuthFor(ref string, auth *models.RegistryAuth) (*models.RegistryAuth, error) {
	if auth != nil && auth.Username != "" {
		return auth, nil
	}
	aocr, err := d.aocrPullAuth.Resolve(ref)
	if err != nil {
		if d.logger != nil {
			d.logger.Warn("aocr pull auth: read PAT failed; pulling anonymously",
				"ref", ref, "error", err)
		}
		return nil, err
	}
	return aocr, nil
}
