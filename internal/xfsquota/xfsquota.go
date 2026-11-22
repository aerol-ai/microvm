// Package xfsquota sets hard block limits on folders with XFS project
// quotas: a folder and everything under it join a project, and the
// project gets a limit. Both a sandbox's disk limit in privilege mode
// single (internal/runtime/containerd, as root) and the root helper's
// disk_quota part in split mode (internal/rootd) drive it, so the two
// write the same limits the same way.
//
// It needs Linux 5.14 or later (quotactl_fd) and an XFS filesystem
// mounted with prjquota. Off Linux every call fails.
package xfsquota
