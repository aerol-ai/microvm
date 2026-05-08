package types

import "github.com/aerol-ai/microvm/pkg/models"

type CreateSandboxOptions = models.CreateSandboxRequest
type ResizeSandboxOptions = models.ResizeSandboxRequest
type Lifecycle = models.Lifecycle
type UpdateLifecycleOptions = models.UpdateLifecycleRequest
type ExecRequest = models.ExecRequest
type ExecResult = models.ExecResult
type ExposedPort = models.ExposedPort
type HealthStatus = models.HealthStatus
type Sandbox = models.Sandbox
type MountSpec = models.MountSpec
type MountSpecRedacted = models.MountSpecRedacted
type MountType = models.MountType
type CreateSessionOptions = models.CreateSessionRequest
type Session = models.Session
type SessionStatus = models.SessionStatus

const (
	SessionStatusRunning = models.SessionStatusRunning
	SessionStatusExited  = models.SessionStatusExited
	SessionStatusKilled  = models.SessionStatusKilled
	SessionStatusFailed  = models.SessionStatusFailed
)

const (
	MountTypeS3     = models.MountTypeS3
	MountTypeNFS    = models.MountTypeNFS
	MountTypeSSHFS  = models.MountTypeSSHFS
	MountTypeRclone = models.MountTypeRclone
)

const (
	RuntimeDocker = models.RuntimeDocker
	RuntimeGvisor = models.RuntimeGvisor
	RuntimeKata   = models.RuntimeKata
)
