package e2b

type createSandboxRequest struct {
	TemplateID          string                     `json:"templateID"`
	AllowInternetAccess *bool                      `json:"allow_internet_access,omitempty"`
	AutoPause           *bool                      `json:"autoPause,omitempty"`
	AutoResume          *sandboxAutoResumeRequest  `json:"autoResume,omitempty"`
	EnvVars             map[string]any             `json:"envVars,omitempty"`
	MCP                 any                        `json:"mcp,omitempty"`
	Metadata            map[string]any             `json:"metadata,omitempty"`
	Network             *sandboxNetworkRequest     `json:"network,omitempty"`
	Secure              *bool                      `json:"secure,omitempty"`
	Timeout             *int                       `json:"timeout,omitempty"`
	VolumeMounts        []sandboxVolumeMountCreate `json:"volumeMounts,omitempty"`
}

type sandboxAutoResumeRequest struct {
	Enabled bool `json:"enabled"`
}

type sandboxNetworkRequest struct {
	AllowOut           []string `json:"allowOut,omitempty"`
	AllowPublicTraffic *bool    `json:"allowPublicTraffic,omitempty"`
	DenyOut            []string `json:"denyOut,omitempty"`
	MaskRequestHost    string   `json:"maskRequestHost,omitempty"`
}

type sandboxVolumeMountCreate struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type connectSandboxRequest struct {
	Timeout int `json:"timeout"`
}

type timeoutRequest struct {
	Timeout int `json:"timeout"`
}

type createSnapshotRequest struct {
	Name string `json:"name,omitempty"`
}

type sandboxResponse struct {
	ClientID           string  `json:"clientID"`
	EnvdVersion        string  `json:"envdVersion"`
	SandboxID          string  `json:"sandboxID"`
	TemplateID         string  `json:"templateID"`
	Alias              string  `json:"alias,omitempty"`
	Domain             *string `json:"domain,omitempty"`
	EnvdAccessToken    string  `json:"envdAccessToken,omitempty"`
	TrafficAccessToken *string `json:"trafficAccessToken,omitempty"`
}

type listedSandboxResponse struct {
	ClientID     string                      `json:"clientID"`
	CPUCount     int                         `json:"cpuCount"`
	DiskSizeMB   int                         `json:"diskSizeMB"`
	EndAt        string                      `json:"endAt"`
	EnvdVersion  string                      `json:"envdVersion"`
	MemoryMB     int                         `json:"memoryMB"`
	SandboxID    string                      `json:"sandboxID"`
	StartedAt    string                      `json:"startedAt"`
	State        string                      `json:"state"`
	TemplateID   string                      `json:"templateID"`
	Alias        string                      `json:"alias,omitempty"`
	Metadata     map[string]string           `json:"metadata,omitempty"`
	VolumeMounts []sandboxVolumeMountPayload `json:"volumeMounts,omitempty"`
}

type sandboxDetailResponse struct {
	ClientID            string                      `json:"clientID"`
	CPUCount            int                         `json:"cpuCount"`
	DiskSizeMB          int                         `json:"diskSizeMB"`
	EndAt               string                      `json:"endAt"`
	EnvdVersion         string                      `json:"envdVersion"`
	MemoryMB            int                         `json:"memoryMB"`
	SandboxID           string                      `json:"sandboxID"`
	StartedAt           string                      `json:"startedAt"`
	State               string                      `json:"state"`
	TemplateID          string                      `json:"templateID"`
	Alias               string                      `json:"alias,omitempty"`
	AllowInternetAccess *bool                       `json:"allowInternetAccess,omitempty"`
	Domain              *string                     `json:"domain,omitempty"`
	EnvdAccessToken     string                      `json:"envdAccessToken,omitempty"`
	Lifecycle           *sandboxLifecyclePayload    `json:"lifecycle,omitempty"`
	Metadata            map[string]string           `json:"metadata,omitempty"`
	Network             *sandboxNetworkPayload      `json:"network,omitempty"`
	VolumeMounts        []sandboxVolumeMountPayload `json:"volumeMounts,omitempty"`
}

type sandboxLifecyclePayload struct {
	AutoResume bool   `json:"autoResume"`
	OnTimeout  string `json:"onTimeout"`
}

type sandboxNetworkPayload struct {
	AllowOut           []string `json:"allowOut,omitempty"`
	AllowPublicTraffic *bool    `json:"allowPublicTraffic,omitempty"`
	DenyOut            []string `json:"denyOut,omitempty"`
	MaskRequestHost    string   `json:"maskRequestHost,omitempty"`
}

type sandboxVolumeMountPayload struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type snapshotInfoResponse struct {
	Names      []string `json:"names"`
	SnapshotID string   `json:"snapshotID"`
}
