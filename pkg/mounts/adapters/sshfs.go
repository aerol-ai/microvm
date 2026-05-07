package adapters

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/aerol-ai/microvm/pkg/models"
)

// SSHFS mounts a remote directory over SSH using the user-supplied private
// key. The key file lives in the credentials directory for the lifetime of
// the mount; sshfs may re-read it on reconnect, so we do not unlink it after
// the mount becomes ready.
type SSHFS struct{}

func (SSHFS) Build(sandboxID string, index int, spec models.MountSpec, hostTarget, credDir string) (Plan, error) {
	pem := spec.Credentials["private_key_pem"]
	if pem == "" {
		return Plan{}, errors.New("sshfs requires credentials.private_key_pem")
	}

	credFile := filepath.Join(credDir, fmt.Sprintf("%s-%d.id", sandboxID, index))
	opts := "IdentityFile=" + credFile +
		",StrictHostKeyChecking=accept-new" +
		",ServerAliveInterval=15,ServerAliveCountMax=3" +
		",reconnect,allow_other,foreground"
	if spec.ReadOnly {
		opts += ",ro"
	}

	argv := []string{"sshfs", "-o", opts, spec.Source, hostTarget}

	return Plan{
		Argv:       argv,
		CredFile:   credFile,
		CredBody:   []byte(pem),
		UnlinkCred: false,
	}, nil
}
