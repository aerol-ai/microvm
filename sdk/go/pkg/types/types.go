package types

import "github.com/aerol-ai/microvm/pkg/models"

type CreateSandboxOptions = models.CreateSandboxRequest
type ResizeSandboxOptions = models.ResizeSandboxRequest
type ExecRequest = models.ExecRequest
type ExecResult = models.ExecResult
type ExposedPort = models.ExposedPort
type HealthStatus = models.HealthStatus
type Sandbox = models.Sandbox
type MountSpec = models.MountSpec
type MountSpecRedacted = models.MountSpecRedacted
type MountType = models.MountType

const (
	MountTypeS3     = models.MountTypeS3
	MountTypeNFS    = models.MountTypeNFS
	MountTypeSSHFS  = models.MountTypeSSHFS
	MountTypeRclone = models.MountTypeRclone
)
