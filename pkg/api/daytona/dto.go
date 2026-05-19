package daytona

type buildInfoRequest struct {
	DockerfileContent *string  `json:"dockerfileContent,omitempty"`
	ContextHashes     []string `json:"contextHashes,omitempty"`
}

type createSandboxRequest struct {
	Name                *string            `json:"name,omitempty"`
	Snapshot            *string            `json:"snapshot,omitempty"`
	User                *string            `json:"user,omitempty"`
	Env                 *map[string]string `json:"env,omitempty"`
	Labels              *map[string]string `json:"labels,omitempty"`
	Public              *bool              `json:"public,omitempty"`
	NetworkBlockAll     *bool              `json:"networkBlockAll,omitempty"`
	NetworkAllowList    *string            `json:"networkAllowList,omitempty"`
	Class               *string            `json:"class,omitempty"`
	Target              *string            `json:"target,omitempty"`
	Cpu                 *int32             `json:"cpu,omitempty"`
	Gpu                 *int32             `json:"gpu,omitempty"`
	Memory              *int32             `json:"memory,omitempty"`
	Disk                *int32             `json:"disk,omitempty"`
	AutoStopInterval    *int32             `json:"autoStopInterval,omitempty"`
	AutoArchiveInterval *int32             `json:"autoArchiveInterval,omitempty"`
	AutoDeleteInterval  *int32             `json:"autoDeleteInterval,omitempty"`
	Volumes             []map[string]any   `json:"volumes,omitempty"`
	BuildInfo           *buildInfoRequest  `json:"buildInfo,omitempty"`
}

type resizeSandboxRequest struct {
	Cpu    *int32 `json:"cpu,omitempty"`
	Memory *int32 `json:"memory,omitempty"`
	Disk   *int32 `json:"disk,omitempty"`
}

type createSandboxSnapshotRequest struct {
	Name string `json:"name"`
}

// createSnapshotRequest matches the Daytona SDK CreateSnapshot DTO sent to
// POST /daytona/snapshots. Either ImageName (pre-built image reference) or
// BuildInfo (Dockerfile + optional context hashes) must be present.
type createSnapshotRequest struct {
	Name       string            `json:"name"`
	ImageName  *string           `json:"imageName,omitempty"`
	Entrypoint []string          `json:"entrypoint,omitempty"`
	CPU        *float32          `json:"cpu,omitempty"`
	GPU        *float32          `json:"gpu,omitempty"`
	Memory     *float32          `json:"memory,omitempty"`
	Disk       *float32          `json:"disk,omitempty"`
	BuildInfo  *buildInfoRequest `json:"buildInfo,omitempty"`
	RegionID   *string           `json:"regionId,omitempty"`
}

type snapshotResponse struct {
	ID             string   `json:"id"`
	OrganizationID *string  `json:"organizationId,omitempty"`
	General        bool     `json:"general"`
	Name           string   `json:"name"`
	ImageName      *string  `json:"imageName,omitempty"`
	State          string   `json:"state"`
	Size           *float32 `json:"size"`
	Entrypoint     []string `json:"entrypoint"`
	CPU            float32  `json:"cpu"`
	GPU            float32  `json:"gpu"`
	Mem            float32  `json:"mem"`
	Disk           float32  `json:"disk"`
	ErrorReason    *string  `json:"errorReason"`
	CreatedAt      string   `json:"createdAt"`
	UpdatedAt      string   `json:"updatedAt"`
	LastUsedAt     *string  `json:"lastUsedAt"`
	Ref            *string  `json:"ref,omitempty"`
	RegionIDs      []string `json:"regionIds,omitempty"`
}

type paginatedSnapshotsResponse struct {
	Items      []snapshotResponse `json:"items"`
	Total      float32            `json:"total"`
	Page       float32            `json:"page"`
	TotalPages float32            `json:"totalPages"`
}

type sandboxResponse struct {
	ID                  string            `json:"id"`
	OrganizationID      string            `json:"organizationId"`
	Name                string            `json:"name"`
	Snapshot            *string           `json:"snapshot,omitempty"`
	User                string            `json:"user"`
	Env                 map[string]string `json:"env"`
	Labels              map[string]string `json:"labels"`
	Public              bool              `json:"public"`
	NetworkBlockAll     bool              `json:"networkBlockAll"`
	NetworkAllowList    *string           `json:"networkAllowList,omitempty"`
	Target              string            `json:"target"`
	CPU                 float32           `json:"cpu"`
	GPU                 float32           `json:"gpu"`
	Memory              float32           `json:"memory"`
	Disk                float32           `json:"disk"`
	State               *string           `json:"state,omitempty"`
	ErrorReason         *string           `json:"errorReason,omitempty"`
	AutoStopInterval    *float32          `json:"autoStopInterval,omitempty"`
	AutoArchiveInterval *float32          `json:"autoArchiveInterval,omitempty"`
	AutoDeleteInterval  *float32          `json:"autoDeleteInterval,omitempty"`
	CreatedAt           *string           `json:"createdAt,omitempty"`
	UpdatedAt           *string           `json:"updatedAt,omitempty"`
	LastActivityAt      *string           `json:"lastActivityAt,omitempty"`
	ToolboxProxyURL     string            `json:"toolboxProxyUrl"`
}

type paginatedSandboxesResponse struct {
	Items      []sandboxResponse `json:"items"`
	Total      float32           `json:"total"`
	Page       float32           `json:"page"`
	TotalPages float32           `json:"totalPages"`
}

type toolboxProxyURLResponse struct {
	URL string `json:"url"`
}

type portPreviewURLResponse struct {
	SandboxID string `json:"sandboxId"`
	URL       string `json:"url"`
	Token     string `json:"token"`
}

type sandboxLabelsResponse struct {
	Labels map[string]string `json:"labels"`
}

type executeRequest struct {
	Command string             `json:"command"`
	Cwd     *string            `json:"cwd,omitempty"`
	Envs    *map[string]string `json:"envs,omitempty"`
	Timeout *int32             `json:"timeout,omitempty"`
}

type executeResponse struct {
	ExitCode *int32 `json:"exitCode,omitempty"`
	Result   string `json:"result"`
}

type filesDownloadRequest struct {
	Paths []string `json:"paths"`
}

type dirResponse struct {
	Dir string `json:"dir"`
}

type listFilters struct {
	ID     string
	Name   string
	Labels map[string]string
	States map[string]struct{}
}

type snapshotListFilters struct {
	Name  string
	Sort  string
	Order string
}
