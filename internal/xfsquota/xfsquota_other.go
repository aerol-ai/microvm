//go:build !linux

package xfsquota

import "errors"

// ErrNeedsLinux is every call's answer off Linux.
var ErrNeedsLinux = errors.New("XFS project quotas need Linux")

// Ops has nothing to drive off Linux; every call fails, so a create with
// a disk limit fails instead of running without it.
type Ops struct{}

func (Ops) Enforced(string) error              { return ErrNeedsLinux }
func (Ops) Assign(string, uint32) error        { return ErrNeedsLinux }
func (Ops) Limit(string, uint32, uint64) error { return ErrNeedsLinux }

// InProject has nothing to read off Linux.
func InProject(string, uint32) (bool, error) { return false, ErrNeedsLinux }
