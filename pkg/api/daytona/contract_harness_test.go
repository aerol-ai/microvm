package daytona

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	internalruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	apiclient "github.com/daytonaio/daytona/libs/api-client-go"
	daytonasdk "github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	sdktypes "github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
)

const (
	contractAPIKey     = "contract-api-key"
	contractOrgID      = "org-contract"
	contractPublicHost = "sandbox.test"
)

var _ internalruntime.Runtime = (*fakeDaytonaContractRuntime)(nil)

type fakeDaytonaContractRuntime struct {
	mu            sync.Mutex
	states        map[string]*models.SandboxRuntimeState
	removedImages []string
	allowedPorts  map[string][]int
	imageSeq      int
	ipSeq         int
}

func newFakeDaytonaContractRuntime() *fakeDaytonaContractRuntime {
	return &fakeDaytonaContractRuntime{
		states:       make(map[string]*models.SandboxRuntimeState),
		allowedPorts: make(map[string][]int),
		ipSeq:        20,
	}
}

func (f *fakeDaytonaContractRuntime) Create(_ context.Context, _ models.CreateSandboxRequest, sandboxID, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.ipSeq++
	state := &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: "ctr-" + sandboxID,
		ContainerIP: fmt.Sprintf("10.42.0.%d", f.ipSeq),
		Status:      models.SandboxStatusStarted,
	}
	f.states[sandboxID] = cloneRuntimeState(state)
	return cloneRuntimeState(state), nil
}

func (f *fakeDaytonaContractRuntime) Start(_ context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	state, ok := f.lookupLocked(containerRef)
	if !ok {
		return nil, fmt.Errorf("sandbox %q not found", containerRef)
	}
	state.Status = models.SandboxStatusStarted
	return cloneRuntimeState(state), nil
}

func (f *fakeDaytonaContractRuntime) Stop(_ context.Context, containerRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	state, ok := f.lookupLocked(containerRef)
	if !ok {
		return fmt.Errorf("sandbox %q not found", containerRef)
	}
	state.Status = models.SandboxStatusStopped
	return nil
}

func (f *fakeDaytonaContractRuntime) Destroy(_ context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.states, sandbox.ID)
	return nil
}

func (f *fakeDaytonaContractRuntime) CreateSnapshot(_ context.Context, _ string, imageRef string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.imageSeq++
	return fmt.Sprintf("sha256:%s-%03d", sanitizeContractID(imageRef), f.imageSeq), nil
}

func (f *fakeDaytonaContractRuntime) Resize(_ context.Context, containerRef string, _ models.ResizeSandboxRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.lookupLocked(containerRef); !ok {
		return fmt.Errorf("sandbox %q not found", containerRef)
	}
	return nil
}

func (f *fakeDaytonaContractRuntime) Inspect(_ context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	state, ok := f.lookupLocked(containerRef)
	if !ok {
		return nil, fmt.Errorf("sandbox %q not found", containerRef)
	}
	return cloneRuntimeState(state), nil
}

func (f *fakeDaytonaContractRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	items := make(map[string]*models.SandboxRuntimeState, len(f.states))
	for sandboxID, state := range f.states {
		items[sandboxID] = cloneRuntimeState(state)
	}
	return items, nil
}

func (f *fakeDaytonaContractRuntime) Ping(context.Context) error { return nil }

func (f *fakeDaytonaContractRuntime) RemoveImage(_ context.Context, imageRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.removedImages = append(f.removedImages, imageRef)
	return nil
}

func (f *fakeDaytonaContractRuntime) PushAllowedPorts(_ context.Context, containerIP, _ string, ports []int) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	cloned := slices.Clone(ports)
	slices.Sort(cloned)
	f.allowedPorts[containerIP] = cloned
	return nil
}

func (f *fakeDaytonaContractRuntime) ClearNetworkRules(string) error    { return nil }
func (f *fakeDaytonaContractRuntime) ApplyNetworkBlockAll(string) error { return nil }

func (f *fakeDaytonaContractRuntime) seedSandbox(sandbox *models.Sandbox) {
	if sandbox == nil {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.states[sandbox.ID] = &models.SandboxRuntimeState{
		SandboxID:   sandbox.ID,
		ContainerID: sandbox.ContainerID,
		ContainerIP: sandbox.ContainerIP,
		Status:      sandbox.Status,
	}
	if sandbox.ContainerIP != "" {
		ports := make([]int, 0, len(sandbox.ExposedPorts))
		for _, port := range sandbox.ExposedPorts {
			ports = append(ports, port.Port)
		}
		slices.Sort(ports)
		f.allowedPorts[sandbox.ContainerIP] = ports
	}
}

func (f *fakeDaytonaContractRuntime) removedImageRefs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.removedImages)
}

func (f *fakeDaytonaContractRuntime) lookupLocked(containerRef string) (*models.SandboxRuntimeState, bool) {
	if state, ok := f.states[containerRef]; ok {
		return state, true
	}
	for _, state := range f.states {
		if state.ContainerID == containerRef {
			return state, true
		}
	}
	return nil, false
}

func cloneRuntimeState(state *models.SandboxRuntimeState) *models.SandboxRuntimeState {
	if state == nil {
		return nil
	}
	cloned := *state
	return &cloned
}

type daytonaContractEnv struct {
	t       *testing.T
	ctx     context.Context
	store   *store.Store
	service *service.Service
	runtime *fakeDaytonaContractRuntime
	server  *httptest.Server
	api     *apiclient.APIClient
	sdk     *daytonasdk.Client
	baseURL string
}

type contractSandboxSeed struct {
	ID                  string
	Name                string
	Image               string
	Status              models.SandboxStatus
	CPU                 float64
	MemoryMB            int
	DiskGB              int
	OSUser              string
	Env                 map[string]string
	Labels              map[string]string
	Snapshot            string
	Target              string
	PublicURL           string
	ContainerID         string
	ContainerIP         string
	NetworkBlockAll     bool
	NetworkAllowList    string
	AutoStopInterval    *float32
	AutoArchiveInterval *float32
	AutoDeleteInterval  *float32
	ExposedPorts        []models.ExposedPort
	CreatedAt           time.Time
	UpdatedAt           time.Time
	LastActiveAt        time.Time
	LastError           string
	Runtime             string
	ToolboxToken        string
	ToolboxEnabled      *bool
	SSHPublicKey        string
	ContainerCommand    []string
	Lifecycle           models.Lifecycle
}

type contractSnapshotSeed struct {
	Name            string
	Image           string
	ImageID         string
	SourceSandboxID string
	CreatedAt       time.Time
}

func newDaytonaContractEnv(t *testing.T) *daytonaContractEnv {
	t.Helper()

	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mountManager, err := mounts.New(logger, mounts.Config{
		RootDir:     filepath.Join(tmpDir, "mounts"),
		CredDir:     filepath.Join(tmpDir, "mount-credentials"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New() error = %v", err)
	}
	t.Cleanup(mountManager.Close)

	cfg := config.Config{
		PATToken:                    contractAPIKey,
		DBPath:                      dbPath,
		PublicHost:                  contractPublicHost,
		CaddyAdminURL:               "http://127.0.0.1:2019",
		CaddyServerID:               "srv0",
		ToolboxMountPath:            "/usr/local/bin/toolboxd",
		ToolboxPort:                 2280,
		Runtime:                     models.RuntimeDocker,
		EnableCaddy:                 false,
		MountsRootPath:              filepath.Join(tmpDir, "mounts"),
		MountsCredentialsRuntimeDir: filepath.Join(tmpDir, "mount-credentials"),
		MountWaitTimeout:            time.Second,
		HTTPClientTimeout:           5 * time.Second,
	}

	runtimeDriver := newFakeDaytonaContractRuntime()
	svc := service.New(cfg, logger, st, runtimeDriver, nil, caddy.New(cfg), nil, mountManager, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth: func(next http.Handler) http.Handler {
			return next
		},
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	apiCfg := apiclient.NewConfiguration()
	apiCfg.Servers = apiclient.ServerConfigurations{{URL: server.URL + PathPrefix, Description: "daytona-contract-test"}}
	apiCfg.HTTPClient = server.Client()
	api := apiclient.NewAPIClient(apiCfg)

	sdk, err := daytonasdk.NewClientWithConfig(&sdktypes.DaytonaConfig{
		APIKey: contractAPIKey,
		APIUrl: server.URL + PathPrefix,
	})
	if err != nil {
		t.Fatalf("daytonasdk.NewClientWithConfig() error = %v", err)
	}
	t.Cleanup(func() { _ = sdk.Close(context.Background()) })

	return &daytonaContractEnv{
		t:       t,
		ctx:     ctx,
		store:   st,
		service: svc,
		runtime: runtimeDriver,
		server:  server,
		api:     api,
		sdk:     sdk,
		baseURL: server.URL + PathPrefix,
	}
}

func (e *daytonaContractEnv) seedSandbox(seed contractSandboxSeed) *models.Sandbox {
	e.t.Helper()

	name := seed.Name
	id := seed.ID
	if id == "" {
		if name != "" {
			id = sanitizeContractID(name)
		} else {
			id = sanitizeContractID(fmt.Sprintf("sandbox-%d", time.Now().UnixNano()))
		}
	}
	if name == "" {
		name = id
	}
	now := time.Now().UTC().Round(time.Second)
	createdAt := seed.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	updatedAt := seed.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = createdAt
	}
	lastActiveAt := seed.LastActiveAt
	if lastActiveAt.IsZero() {
		lastActiveAt = updatedAt
	}
	status := seed.Status
	if status == "" {
		status = models.SandboxStatusStarted
	}
	containerID := seed.ContainerID
	if containerID == "" {
		containerID = "ctr-" + id
	}
	containerIP := seed.ContainerIP
	if containerIP == "" {
		containerIP = fmt.Sprintf("10.55.0.%d", len(id)+20)
	}
	image := seed.Image
	if image == "" {
		image = "ubuntu:22.04"
	}
	osUser := seed.OSUser
	if osUser == "" {
		osUser = "daytona"
	}
	toolboxToken := seed.ToolboxToken
	if toolboxToken == "" {
		toolboxToken = "token-" + id
	}
	runtimeName := seed.Runtime
	if runtimeName == "" {
		runtimeName = models.RuntimeDocker
	}
	toolboxEnabled := true
	if seed.ToolboxEnabled != nil {
		toolboxEnabled = *seed.ToolboxEnabled
	}
	publicURL := seed.PublicURL
	if publicURL == "" {
		publicURL = fmt.Sprintf("http://%s/%s/", contractPublicHost, id)
	}

	exposedPorts := slices.Clone(seed.ExposedPorts)
	for i := range exposedPorts {
		exposedPorts[i].SandboxID = id
	}

	// Daytona's Name and Labels live on the native sandbox row now —
	// the facade derives them on read. Auto-stop / auto-delete intervals
	// likewise round-trip through Lifecycle.
	lifecycle := seed.Lifecycle
	if seed.AutoStopInterval != nil && *seed.AutoStopInterval > 0 && lifecycle.StopIfIdleFor == 0 {
		lifecycle.StopIfIdleFor = time.Duration(float64(*seed.AutoStopInterval) * float64(time.Minute))
	}
	if seed.AutoDeleteInterval != nil && *seed.AutoDeleteInterval > 0 && lifecycle.DestroyIfIdleFor == 0 {
		lifecycle.DestroyIfIdleFor = time.Duration(float64(*seed.AutoDeleteInterval) * float64(time.Minute))
	}

	sandbox := &models.Sandbox{
		ID:               id,
		Name:             name,
		Image:            image,
		Status:           status,
		PublicURL:        publicURL,
		ContainerID:      containerID,
		ContainerIP:      containerIP,
		CPU:              firstNonZeroFloat64(seed.CPU, 2),
		MemoryMB:         firstNonZeroInt(seed.MemoryMB, 2048),
		DiskGB:           firstNonZeroInt(seed.DiskGB, 10),
		OSUser:           osUser,
		Env:              maps.Clone(seed.Env),
		Tags:             maps.Clone(seed.Labels),
		NetworkBlockAll:  seed.NetworkBlockAll,
		ToolboxEnabled:   toolboxEnabled,
		ToolboxToken:     toolboxToken,
		SSHPublicKey:     seed.SSHPublicKey,
		ExposedPorts:     exposedPorts,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
		LastActiveAt:     lastActiveAt,
		LastError:        seed.LastError,
		ContainerCommand: slices.Clone(seed.ContainerCommand),
		Lifecycle:        lifecycle,
		Runtime:          runtimeName,
	}
	if err := e.store.Upsert(e.ctx, sandbox); err != nil {
		e.t.Fatalf("store.Upsert(%s) error = %v", sandbox.ID, err)
	}

	// Persist the Daytona-private fields (snapshot, target, allow-list,
	// auto-archive interval) into sandbox_compat_state — the same path
	// the live facade write code uses.
	stateBlob, err := sandboxMetaToState(sandboxMeta{
		Snapshot:            emptyStringToPtr(seed.Snapshot),
		Target:              seed.Target,
		NetworkAllowList:    emptyStringToPtr(seed.NetworkAllowList),
		AutoArchiveInterval: cloneContractFloat32Ptr(seed.AutoArchiveInterval),
	})
	if err != nil {
		e.t.Fatalf("sandboxMetaToState(%s) error = %v", sandbox.ID, err)
	}
	if err := e.service.UpsertCompatState(e.ctx, sandbox.ID, models.FacadeDaytona, stateBlob); err != nil {
		e.t.Fatalf("service.UpsertCompatState(%s) error = %v", sandbox.ID, err)
	}

	e.runtime.seedSandbox(sandbox)
	return sandbox
}

// loadDaytonaMeta is the test-side equivalent of the old GetDaytonaMetadata
// helper: read the native sandbox row plus its Daytona compat blob and
// combine them through the facade's own meta builder, so contract tests
// keep asserting against the same in-memory shape they did before.
func (e *daytonaContractEnv) loadDaytonaMeta(sandboxID string) (sandboxMeta, error) {
	sandbox, err := e.store.Get(e.ctx, sandboxID)
	if err != nil {
		return sandboxMeta{}, err
	}
	state, err := e.service.GetCompatState(e.ctx, sandboxID, models.FacadeDaytona)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return sandboxMeta{}, err
	}
	return sandboxMetaFromState(state, sandbox)
}

func (e *daytonaContractEnv) seedSnapshot(seed contractSnapshotSeed) *models.SandboxSnapshot {
	e.t.Helper()

	createdAt := seed.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC().Round(time.Second)
	}
	image := seed.Image
	if image == "" {
		image = seed.Name
	}
	imageID := seed.ImageID
	if imageID == "" {
		imageID = fmt.Sprintf("sha256:%s", sanitizeContractID(seed.Name))
	}
	snapshot := &models.SandboxSnapshot{
		Name:            seed.Name,
		Image:           image,
		ImageID:         imageID,
		SourceSandboxID: seed.SourceSandboxID,
		CreatedAt:       createdAt,
	}
	if err := e.store.CreateSnapshot(e.ctx, snapshot); err != nil {
		e.t.Fatalf("store.CreateSnapshot(%s) error = %v", snapshot.Name, err)
	}
	return snapshot
}

func (e *daytonaContractEnv) removedImages() []string {
	e.t.Helper()
	return e.runtime.removedImageRefs()
}

func sanitizeContractID(value string) string {
	trimmed := value
	if trimmed == "" {
		return "sandbox"
	}
	b := make([]rune, 0, len(trimmed))
	for _, ch := range trimmed {
		switch {
		case ch >= 'a' && ch <= 'z':
			b = append(b, ch)
		case ch >= 'A' && ch <= 'Z':
			b = append(b, ch+('a'-'A'))
		case ch >= '0' && ch <= '9':
			b = append(b, ch)
		default:
			b = append(b, '-')
		}
	}
	result := string(b)
	for len(result) > 1 && result[0] == '-' {
		result = result[1:]
	}
	for len(result) > 1 && result[len(result)-1] == '-' {
		result = result[:len(result)-1]
	}
	if result == "" {
		return "sandbox"
	}
	return result
}

func firstNonZeroInt(value, fallback int) int {
	if value != 0 {
		return value
	}
	return fallback
}

func firstNonZeroFloat64(value, fallback float64) float64 {
	if value != 0 {
		return value
	}
	return fallback
}

func cloneContractFloat32Ptr(value *float32) *float32 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
