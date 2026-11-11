//go:build !linux

package containerd

import "errors"

var errDiskQuotaNeedsLinux = errors.New("XFS project quotas need Linux")

// xfsProjectQuota has nothing to drive off Linux; every call fails, so a
// create with the setting on fails instead of running without its limit.
type xfsProjectQuota struct{}

func (xfsProjectQuota) Enforced(string) error              { return errDiskQuotaNeedsLinux }
func (xfsProjectQuota) Assign(string, uint32) error        { return errDiskQuotaNeedsLinux }
func (xfsProjectQuota) Limit(string, uint32, uint64) error { return errDiskQuotaNeedsLinux }
