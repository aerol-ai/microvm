// Command releasemeta prints release.json for the current tree: the
// pkg/release fields every release ships beside its binaries
// (plans/kubectl-style-cluster-ops.md §6.5). release.yml runs it, so the
// published file always matches the code it describes:
//
//	go run ./cmd/releasemeta -version v0.6.12 -install-script dist/install.sh -o dist/release.json
//
// Where each field comes from:
//
//   - version: -version, else $VERSION (release.yml's tag).
//   - upgrade_from_min, host_setup_needs_network: policy.go, overridable
//     with -upgrade-from-min and -host-setup-needs-network.
//   - one_way_migrations: store.OneWayMigrations, the finalize-gated schema
//     migrations this tree's store knows.
//   - host_setup_sha256: the SHA-256 of -install-script.
//   - egress_gateway_protocol: egress.ProtocolVersion and the version below
//     it, both of which the gateway accepts.
//   - fsm_ops_version: the fsmOpsVersion constant, read from the source of
//     -cluster-dir. Importing internal/cluster for one integer would build
//     Raft, gossip and the rest of the server into a release helper.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/release"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("releasemeta", flag.ContinueOnError)
	fs.SetOutput(stderr)
	version := fs.String("version", getenv("VERSION"), "release tag (default $VERSION)")
	upgradeFrom := fs.String("upgrade-from-min", upgradeFromMin, "oldest version that may upgrade straight to this one")
	needsNetwork := fs.Bool("host-setup-needs-network", hostSetupNeedsNetwork, "the release's host changes need packages or network access")
	installScript := fs.String("install-script", "scripts/install.sh", "the install.sh this release ships")
	clusterDir := fs.String("cluster-dir", "internal/cluster", "source directory holding the fsmOpsVersion constant")
	out := fs.String("o", "", "write release.json here instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "releasemeta: unexpected arguments %v\n", fs.Args())
		return 2
	}

	data, err := build(*version, *upgradeFrom, *needsNetwork, *installScript, *clusterDir)
	if err != nil {
		fmt.Fprintf(stderr, "releasemeta: %v\n", err)
		return 1
	}
	if *out == "" {
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintf(stderr, "releasemeta: %v\n", err)
			return 1
		}
		return 0
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "releasemeta: %v\n", err)
		return 1
	}
	return 0
}

func build(version, upgradeFrom string, needsNetwork bool, installScript, clusterDir string) ([]byte, error) {
	script, err := os.ReadFile(installScript)
	if err != nil {
		return nil, fmt.Errorf("read install script: %w", err)
	}
	sum := sha256.Sum256(script)
	fsmOps, err := readIntConst(clusterDir, "fsmOpsVersion")
	if err != nil {
		return nil, err
	}
	return release.Marshal(release.Metadata{
		Version:               version,
		UpgradeFromMin:        upgradeFrom,
		OneWayMigrations:      store.OneWayMigrations(),
		HostSetupSHA256:       hex.EncodeToString(sum[:]),
		HostSetupNeedsNetwork: needsNetwork,
		EgressGatewayProtocol: gatewayProtocols(egress.ProtocolVersion),
		FSMOpsVersion:         fsmOps,
	})
}

// gatewayProtocols lists the versions a sandboxd speaking current accepts:
// current and the one before it (internal/egress negotiate), lowest first.
func gatewayProtocols(current int) []int {
	if current <= 1 {
		return []int{current}
	}
	return []int{current - 1, current}
}
