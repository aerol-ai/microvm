// Package scripts carries install.sh inside sandboxd
// (plans/kubectl-style-cluster-ops.md §7). `sandboxd host apply` runs this
// copy with --config-only, so a node re-renders its configuration with the
// installer of the release it runs, with no checkout and no download. Its
// hash is the host_setup_sha256 that release.json publishes (release.yml
// ships this same file, byte for byte), which is how the upgrader tells
// whether a release changes host setup.
package scripts

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

// InstallSh is scripts/install.sh as this binary was built with it.
//
//go:embed install.sh
var InstallSh []byte

// InstallShSHA256 is the hex SHA-256 of InstallSh.
func InstallShSHA256() string {
	sum := sha256.Sum256(InstallSh)
	return hex.EncodeToString(sum[:])
}
