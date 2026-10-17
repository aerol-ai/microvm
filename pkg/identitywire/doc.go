// Package identitywire holds the identity formats that sandboxd and the
// aerolvm CLI must agree on byte for byte (plans/identity-and-access.md,
// eng review D2): the avm_ API token format with its checksum, and the
// names and lifetimes a token request carries.
//
// It is the one identity package the CLI may import. It depends only on the
// standard library, so it never drags a server package (containerd, Raft,
// SQLite) into the CGO-free CLI build, and cmd/aerolvm/deps_test.go keeps
// it that way. Everything here is pure: parsing and formatting, no I/O and
// no clock.
package identitywire
