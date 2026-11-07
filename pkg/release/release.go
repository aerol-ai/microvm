// Package release is the one Go type for release.json, the file every
// AerolVM release ships beside its binaries (plans/kubectl-style-cluster-ops.md
// §6.5). It says which versions may upgrade straight to the release and what
// the upgrade changes, so `aerolvm upgrade plan`, the node upgrader and
// release.yml (through cmd/releasemeta) all read and write the same fields.
//
// The package imports nothing outside the standard library: the aerolvm CLI
// links it and must stay a thin, CGO-free client (cmd/aerolvm/deps_test.go).
package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// FileName is the release asset name.
const FileName = "release.json"

// Metadata is release.json.
type Metadata struct {
	// Version is the release tag, such as v0.6.12.
	Version string `json:"version"`
	// UpgradeFromMin is the oldest version that may upgrade straight to
	// Version. `upgrade plan` refuses a jump from below it.
	UpgradeFromMin string `json:"upgrade_from_min"`
	// OneWayMigrations are the numbers of the release's non-n1_safe schema
	// migrations, which run only once the cluster is finalized (CEO D16).
	OneWayMigrations []int `json:"one_way_migrations"`
	// HostSetupSHA256 is the hex SHA-256 of the release's install.sh.
	HostSetupSHA256 string `json:"host_setup_sha256"`
	// HostSetupNeedsNetwork is true when the release's host changes need
	// packages or network access; an offline rollout of it is refused.
	HostSetupNeedsNetwork bool `json:"host_setup_needs_network"`
	// EgressGatewayProtocol lists the egress gateway protocol versions the
	// release's sandboxd speaks, lowest first.
	EgressGatewayProtocol []int `json:"egress_gateway_protocol"`
	// FSMOpsVersion is the cluster FSM op set the release applies (gossip
	// "fv").
	FSMOpsVersion int `json:"fsm_ops_version"`
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate reports the first field that is missing or malformed.
func (m Metadata) Validate() error {
	version, err := ParseVersion(m.Version)
	if err != nil {
		return fmt.Errorf("release: version: %w", err)
	}
	from, err := ParseVersion(m.UpgradeFromMin)
	if err != nil {
		return fmt.Errorf("release: upgrade_from_min: %w", err)
	}
	if from.Compare(version) > 0 {
		return fmt.Errorf("release: upgrade_from_min %s is newer than version %s", m.UpgradeFromMin, m.Version)
	}
	if m.OneWayMigrations == nil {
		return errors.New("release: one_way_migrations is missing (an empty list is [])")
	}
	if err := strictlyAscendingPositive(m.OneWayMigrations); err != nil {
		return fmt.Errorf("release: one_way_migrations: %w", err)
	}
	if !sha256Hex.MatchString(m.HostSetupSHA256) {
		return fmt.Errorf("release: host_setup_sha256 %q is not a lowercase hex SHA-256", m.HostSetupSHA256)
	}
	if len(m.EgressGatewayProtocol) == 0 {
		return errors.New("release: egress_gateway_protocol is empty")
	}
	if err := strictlyAscendingPositive(m.EgressGatewayProtocol); err != nil {
		return fmt.Errorf("release: egress_gateway_protocol: %w", err)
	}
	if m.FSMOpsVersion <= 0 {
		return fmt.Errorf("release: fsm_ops_version %d is not positive", m.FSMOpsVersion)
	}
	return nil
}

func strictlyAscendingPositive(xs []int) error {
	for i, x := range xs {
		if x <= 0 {
			return fmt.Errorf("%d is not positive", x)
		}
		if i > 0 && x <= xs[i-1] {
			return fmt.Errorf("%v is not strictly ascending", xs)
		}
	}
	return nil
}

// Parse decodes and validates release.json. Fields it does not know are
// ignored, so an older aerolvm can still read a newer release's file.
func Parse(data []byte) (Metadata, error) {
	var m Metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return Metadata{}, fmt.Errorf("release: decode %s: %w", FileName, err)
	}
	if err := m.Validate(); err != nil {
		return Metadata{}, err
	}
	return m, nil
}

// Marshal validates m and encodes it as indented JSON with a trailing
// newline, the bytes release.yml publishes.
func Marshal(m Metadata) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("release: encode %s: %w", FileName, err)
	}
	return buf.Bytes(), nil
}

// ErrUpgradeFromTooOld is UpgradeAllowedFrom's error for a version below
// upgrade_from_min.
var ErrUpgradeFromTooOld = errors.New("release: version is older than upgrade_from_min")

// UpgradeAllowedFrom reports whether a node on current may upgrade straight
// to m.Version: current must be at least m.UpgradeFromMin. It says nothing
// about downgrades; a rollback is its own path.
func (m Metadata) UpgradeAllowedFrom(current string) error {
	cur, err := ParseVersion(current)
	if err != nil {
		return fmt.Errorf("release: current version: %w", err)
	}
	floor, err := ParseVersion(m.UpgradeFromMin)
	if err != nil {
		return fmt.Errorf("release: upgrade_from_min: %w", err)
	}
	if cur.Compare(floor) < 0 {
		return fmt.Errorf("%w: %s cannot upgrade straight to %s; upgrade to %s or later first", ErrUpgradeFromTooOld, current, m.Version, m.UpgradeFromMin)
	}
	return nil
}
