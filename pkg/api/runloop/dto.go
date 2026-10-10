package runloop

import "encoding/json"

// Wire types for the Runloop REST API subset the facade serves. Field names
// match @runloop/api-client / runloop_api_client 2.0.0 exactly. Both SDKs
// send explicit nulls for unset optional fields, so every optional request
// field is a pointer, map, slice, or RawMessage that decodes null cleanly.

// Devbox statuses (DevboxView.status).
const (
	statusProvisioning = "provisioning"
	statusRunning      = "running"
	statusSuspended    = "suspended"
	statusFailure      = "failure"
	statusShutdown     = "shutdown"
)

// Execution statuses. Runloop has no failed or killed state: a killed
// command is `completed` with its exit status.
const (
	execStatusRunning   = "running"
	execStatusCompleted = "completed"
)

type afterIdle struct {
	IdleTimeSeconds int    `json:"idle_time_seconds"`
	OnIdle          string `json:"on_idle"`
}

type resumeTriggers struct {
	HTTP      *bool `json:"http,omitempty"`
	AxonEvent *bool `json:"axon_event,omitempty"`
}

type lifecycleParams struct {
	AfterIdle      *afterIdle      `json:"after_idle,omitempty"`
	ResumeTriggers *resumeTriggers `json:"resume_triggers,omitempty"`
	LifecycleHooks json.RawMessage `json:"lifecycle_hooks,omitempty"`
}

// launchParameters is both the request field and the echo in DevboxView,
// so a GET returns what the caller asked for.
type launchParameters struct {
	ResourceSizeRequest  *string          `json:"resource_size_request,omitempty"`
	CustomCPUCores       *float64         `json:"custom_cpu_cores,omitempty"`
	CustomGBMemory       *int             `json:"custom_gb_memory,omitempty"`
	CustomDiskSize       *int             `json:"custom_disk_size,omitempty"`
	Architecture         *string          `json:"architecture,omitempty"`
	KeepAliveTimeSeconds *int             `json:"keep_alive_time_seconds,omitempty"`
	AfterIdle            *afterIdle       `json:"after_idle,omitempty"`
	Lifecycle            *lifecycleParams `json:"lifecycle,omitempty"`
	LaunchCommands       []string         `json:"launch_commands,omitempty"`
	UserParameters       json.RawMessage  `json:"user_parameters,omitempty"`
	NetworkPolicyID      *string          `json:"network_policy_id,omitempty"`
	ProvisioningTier     *string          `json:"provisioning_tier,omitempty"`
	RequiredServices     []string         `json:"required_services,omitempty"`
	AvailablePorts       []int            `json:"available_ports,omitempty"`
}

type createDevboxRequest struct {
	BlueprintID          *string           `json:"blueprint_id"`
	BlueprintName        *string           `json:"blueprint_name"`
	SnapshotID           *string           `json:"snapshot_id"`
	Name                 *string           `json:"name"`
	Metadata             map[string]string `json:"metadata"`
	Entrypoint           *string           `json:"entrypoint"`
	EnvironmentVariables map[string]string `json:"environment_variables"`
	Secrets              map[string]string `json:"secrets"`
	LaunchParameters     *launchParameters `json:"launch_parameters"`
	Mounts               json.RawMessage   `json:"mounts"`
	CodeMounts           json.RawMessage   `json:"code_mounts"`
	FileMounts           map[string]string `json:"file_mounts"`
	Tunnel               json.RawMessage   `json:"tunnel"`
	Gateways             json.RawMessage   `json:"gateways"`
	MCP                  json.RawMessage   `json:"mcp"`
}

type updateDevboxRequest struct {
	Name     *string           `json:"name"`
	Metadata map[string]string `json:"metadata"`
}

type waitForStatusRequest struct {
	Statuses       []string `json:"statuses"`
	TimeoutSeconds *float64 `json:"timeout_seconds"`
}

type stateTransition struct {
	Status           string `json:"status"`
	TransitionTimeMs int64  `json:"transition_time_ms"`
}

type devboxView struct {
	ID               string            `json:"id"`
	Status           string            `json:"status"`
	CreateTimeMs     int64             `json:"create_time_ms"`
	EndTimeMs        *int64            `json:"end_time_ms"`
	Capabilities     []string          `json:"capabilities"`
	LaunchParameters launchParameters  `json:"launch_parameters"`
	Metadata         map[string]string `json:"metadata"`
	StateTransitions []stateTransition `json:"state_transitions"`
	Name             *string           `json:"name"`
	BlueprintID      *string           `json:"blueprint_id"`
	SnapshotID       *string           `json:"snapshot_id"`
	FailureReason    *string           `json:"failure_reason"`
	ShutdownReason   *string           `json:"shutdown_reason"`
	InitiatorType    string            `json:"initiator_type"`
	Tunnel           *json.RawMessage  `json:"tunnel"`
}

type listDevboxesResponse struct {
	Devboxes   []devboxView `json:"devboxes"`
	HasMore    bool         `json:"has_more"`
	TotalCount *int         `json:"total_count"`
}

type executeRequest struct {
	Command           string   `json:"command"`
	CommandID         *string  `json:"command_id"`
	OptimisticTimeout *float64 `json:"optimistic_timeout"`
	ShellName         *string  `json:"shell_name"`
	AttachStdin       *bool    `json:"attach_stdin"`
}

type killExecutionRequest struct {
	KillProcessGroup *bool `json:"kill_process_group"`
}

type sendStdinRequest struct {
	Text   *string `json:"text"`
	Signal *string `json:"signal"`
}

type sendStdinResponse struct {
	DevboxID    string `json:"devbox_id"`
	ExecutionID string `json:"execution_id"`
	Success     bool   `json:"success"`
}

type executionView struct {
	DevboxID        string  `json:"devbox_id"`
	ExecutionID     string  `json:"execution_id"`
	Status          string  `json:"status"`
	ExitStatus      *int    `json:"exit_status"`
	Stdout          *string `json:"stdout"`
	Stderr          *string `json:"stderr"`
	StdoutTruncated *bool   `json:"stdout_truncated"`
	StderrTruncated *bool   `json:"stderr_truncated"`
	ShellName       *string `json:"shell_name"`
}

// executionDetailView is the synchronous execution shape; write_file_contents
// answers with it too.
type executionDetailView struct {
	DevboxID   string  `json:"devbox_id"`
	ExitStatus int     `json:"exit_status"`
	Stdout     string  `json:"stdout"`
	Stderr     string  `json:"stderr"`
	ShellName  *string `json:"shell_name"`
}

type executionUpdateChunk struct {
	Output string `json:"output"`
	Offset int    `json:"offset"`
}

type readFileRequest struct {
	FilePath string `json:"file_path"`
}

type writeFileRequest struct {
	FilePath string `json:"file_path"`
	Contents string `json:"contents"`
}

type downloadFileRequest struct {
	Path string `json:"path"`
}

type snapshotRequest struct {
	Name          *string           `json:"name"`
	Metadata      map[string]string `json:"metadata"`
	CommitMessage *string           `json:"commit_message"`
}

type snapshotView struct {
	ID                string            `json:"id"`
	CreateTimeMs      int64             `json:"create_time_ms"`
	Metadata          map[string]string `json:"metadata"`
	SourceDevboxID    string            `json:"source_devbox_id"`
	Name              *string           `json:"name"`
	CommitMessage     *string           `json:"commit_message"`
	SizeBytes         *int64            `json:"size_bytes"`
	SourceBlueprintID *string           `json:"source_blueprint_id"`
}

type snapshotStatusView struct {
	Status       string        `json:"status"`
	ErrorMessage *string       `json:"error_message"`
	Snapshot     *snapshotView `json:"snapshot"`
}

type listSnapshotsResponse struct {
	Snapshots  []snapshotView `json:"snapshots"`
	HasMore    bool           `json:"has_more"`
	TotalCount *int           `json:"total_count"`
}
