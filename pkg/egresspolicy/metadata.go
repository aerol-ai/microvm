package egresspolicy

import (
	"net/netip"
	"slices"
)

// MetadataPrefixes are cloud instance-metadata and workload-credential
// endpoints. They hand out the node's own cloud credentials (on AWS, the
// instance role that reads the cluster's S3 bundles and calls KMS), and
// IMDSv2's default hop limit of 2 answers a sandbox one NAT hop away. No
// sandbox may reach them, whatever its policy or the operator file says:
// they are on every deny floor, the host firewall's and every dial guard's.
var MetadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"), // AWS, GCP, Azure, OpenStack, Oracle, DigitalOcean IMDS
	netip.MustParsePrefix("169.254.170.2/32"),   // AWS ECS task credentials
	netip.MustParsePrefix("169.254.170.23/32"),  // AWS EKS Pod Identity
	netip.MustParsePrefix("168.63.129.16/32"),   // Azure WireServer
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IMDS over IPv6
	netip.MustParsePrefix("fd00:ec2::23/128"),   // AWS EKS Pod Identity over IPv6
}

// WithFixedFloor returns floor with everything no setting can take off the
// floor: the metadata endpoints and the node's extra floor (DenyFloorEnv).
// It is the floor the host firewall and the egress gateway's kernel set
// install, so they drop the same addresses the dial guards refuse.
func WithFixedFloor(floor []netip.Prefix) []netip.Prefix {
	return withEach(WithMetadataFloor(floor), ExtraDenyFloor())
}

// WithMetadataFloor returns floor with MetadataPrefixes added (each once).
func WithMetadataFloor(floor []netip.Prefix) []netip.Prefix {
	return withEach(floor, MetadataPrefixes)
}

// withEach returns floor with each of add appended that it lacks, leaving
// the caller's slice alone.
func withEach(floor, add []netip.Prefix) []netip.Prefix {
	out := append([]netip.Prefix(nil), floor...)
	for _, m := range add {
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}
