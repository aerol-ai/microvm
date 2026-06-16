package service

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"golang.org/x/crypto/ssh"
)

type allowedPortsPush struct {
	containerIP string
	token       string
	ports       []int
}

type recordingRuntime struct {
	createCalls      int
	createState      *models.SandboxRuntimeState
	createErr        error
	lastCreateReq    models.CreateSandboxRequest
	lastCreateID     string
	lastToolboxToken string

	startState *models.SandboxRuntimeState
	startErr   error
	startRefs  []string

	stopErr  error
	stopRefs []string

	destroyErr error
	destroyIDs []string

	pingErr error
	health  string

	pushes []allowedPortsPush

	applyNetworkBlockAllCalls  []string
	applyNetworkBlockIngresses []string
	clearNetworkBlockIngresses []string
	clearNetworkBlockEgresses  []string
	removeImages               []string

	inspect map[string]*models.SandboxRuntimeState
	managed map[string]*models.SandboxRuntimeState
}

type leaderCluster struct {
	*cluster.Noop
	leader string
}

func (c *leaderCluster) Leader() string { return c.leader }

func (r *recordingRuntime) Create(_ context.Context, req models.CreateSandboxRequest, sandboxID, toolboxToken string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	r.createCalls++
	r.lastCreateReq = req
	r.lastCreateID = sandboxID
	r.lastToolboxToken = toolboxToken
	if r.createErr != nil {
		return nil, r.createErr
	}
	if r.createState != nil {
		state := *r.createState
		return &state, nil
	}
	return &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: "ctr-" + sandboxID,
		ContainerIP: "10.0.0.2",
		Status:      models.SandboxStatusStarted,
	}, nil
}

func (r *recordingRuntime) Start(_ context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	r.startRefs = append(r.startRefs, containerRef)
	if r.startErr != nil {
		return nil, r.startErr
	}
	if r.startState != nil {
		state := *r.startState
		return &state, nil
	}
	return &models.SandboxRuntimeState{ContainerID: containerRef, ContainerIP: "10.0.0.3", Status: models.SandboxStatusStarted}, nil
}

func (r *recordingRuntime) Stop(_ context.Context, containerRef string) error {
	r.stopRefs = append(r.stopRefs, containerRef)
	return r.stopErr
}

func (r *recordingRuntime) Destroy(_ context.Context, sandbox *models.Sandbox) error {
	if sandbox != nil {
		r.destroyIDs = append(r.destroyIDs, sandbox.ID)
	}
	return r.destroyErr
}

func (r *recordingRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	panic("unexpected CreateSnapshot")
}

func (r *recordingRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	panic("unexpected Resize")
}

func (r *recordingRuntime) Inspect(_ context.Context, ref string) (*models.SandboxRuntimeState, error) {
	if r.inspect != nil {
		if state, ok := r.inspect[ref]; ok {
			copy := *state
			return &copy, nil
		}
	}
	return &models.SandboxRuntimeState{}, nil
}

func (r *recordingRuntime) ListManaged(_ context.Context) (map[string]*models.SandboxRuntimeState, error) {
	out := make(map[string]*models.SandboxRuntimeState, len(r.managed))
	for id, state := range r.managed {
		copy := *state
		out[id] = &copy
	}
	return out, nil
}

func (r *recordingRuntime) Ping(context.Context) error { return r.pingErr }

func (r *recordingRuntime) RuntimeHealth(context.Context) string {
	if r.health == "" {
		return "ok"
	}
	return r.health
}

func (r *recordingRuntime) RemoveImage(_ context.Context, imageRef string) error {
	r.removeImages = append(r.removeImages, imageRef)
	return nil
}

func (r *recordingRuntime) PushAllowedPorts(_ context.Context, containerIP, toolboxToken string, ports []int) error {
	copyPorts := append([]int(nil), ports...)
	r.pushes = append(r.pushes, allowedPortsPush{containerIP: containerIP, token: toolboxToken, ports: copyPorts})
	return nil
}

func (r *recordingRuntime) ClearNetworkRules(string) error { return nil }

func (r *recordingRuntime) ApplyEgressPolicy(string, []string, []string) error { return nil }
func (r *recordingRuntime) ClearEgressPolicy(string, []string, []string) error { return nil }
func (r *recordingRuntime) ApplyNetworkBlockAll(containerIP string) error {
	r.applyNetworkBlockAllCalls = append(r.applyNetworkBlockAllCalls, containerIP)
	return nil
}

func (r *recordingRuntime) ApplyNetworkBlockIngress(containerIP string) error {
	r.applyNetworkBlockIngresses = append(r.applyNetworkBlockIngresses, containerIP)
	return nil
}

func (r *recordingRuntime) ClearNetworkBlockIngress(containerIP string) error {
	r.clearNetworkBlockIngresses = append(r.clearNetworkBlockIngresses, containerIP)
	return nil
}

func (r *recordingRuntime) ClearNetworkBlockEgress(containerIP string) error {
	r.clearNetworkBlockEgresses = append(r.clearNetworkBlockEgresses, containerIP)
	return nil
}

func TestServiceCreateWithIDAndAccessors(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	resp, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20",
		Name:  "alpha",
		Tags:  map[string]string{"team": "platform", "env": "test"},
	}, "sb-fixed")
	if err != nil {
		t.Fatalf("CreateSandboxWithID() error = %v", err)
	}
	if rt.createCalls != 1 {
		t.Fatalf("runtime Create calls = %d, want 1", rt.createCalls)
	}
	if rt.lastCreateID != "sb-fixed" {
		t.Fatalf("runtime create id = %q, want sb-fixed", rt.lastCreateID)
	}
	if rt.lastCreateReq.Runtime != models.RuntimeDocker {
		t.Fatalf("runtime create request runtime = %q, want %q", rt.lastCreateReq.Runtime, models.RuntimeDocker)
	}
	if len(rt.lastToolboxToken) != 64 {
		t.Fatalf("toolbox token length = %d, want 64 hex chars", len(rt.lastToolboxToken))
	}
	if _, err := hex.DecodeString(rt.lastToolboxToken); err != nil {
		t.Fatalf("toolbox token is not hex: %v", err)
	}
	if resp.ID != "sb-fixed" {
		t.Fatalf("response sandbox id = %q, want sb-fixed", resp.ID)
	}
	if resp.Runtime != models.RuntimeDocker {
		t.Fatalf("response runtime = %q, want %q", resp.Runtime, models.RuntimeDocker)
	}
	if resp.CPU != models.DefaultCPU || resp.MemoryMB != models.DefaultMemoryMB || resp.DiskGB != models.DefaultDiskGB {
		t.Fatalf("normalized defaults = cpu:%v mem:%d disk:%d, want %v/%d/%d", resp.CPU, resp.MemoryMB, resp.DiskGB, models.DefaultCPU, models.DefaultMemoryMB, models.DefaultDiskGB)
	}
	if resp.OSUser != "root" {
		t.Fatalf("os user = %q, want root", resp.OSUser)
	}
	if !strings.Contains(resp.SSHPrivateKey, "PRIVATE KEY") {
		t.Fatalf("ssh private key missing PEM block: %q", resp.SSHPrivateKey)
	}

	got, err := svc.GetSandbox(ctx, resp.ID)
	if err != nil {
		t.Fatalf("GetSandbox() error = %v", err)
	}
	if got.ToolboxToken != rt.lastToolboxToken {
		t.Fatalf("stored toolbox token = %q, want runtime token", got.ToolboxToken)
	}

	filtered, err := svc.ListSandboxes(ctx, map[string]string{"team": "platform"})
	if err != nil {
		t.Fatalf("ListSandboxes() error = %v", err)
	}
	if len(filtered) != 1 || filtered[0].ID != resp.ID {
		t.Fatalf("filtered sandboxes = %+v, want only %q", filtered, resp.ID)
	}

	now := got.LastActiveAt
	time.Sleep(10 * time.Millisecond)
	if err := svc.TouchSandbox(ctx, resp.ID); err != nil {
		t.Fatalf("TouchSandbox() error = %v", err)
	}
	touched, err := st.Get(ctx, resp.ID)
	if err != nil {
		t.Fatalf("store.Get() after touch error = %v", err)
	}
	if !touched.LastActiveAt.After(now) {
		t.Fatalf("last active time did not advance: before=%v after=%v", now, touched.LastActiveAt)
	}

	endpoint, err := svc.ToolboxTarget(ctx, resp.ID)
	if err != nil {
		t.Fatalf("ToolboxTarget() error = %v", err)
	}
	if endpoint.URL != "http://10.0.0.2:4321" {
		t.Fatalf("toolbox url = %q, want http://10.0.0.2:4321", endpoint.URL)
	}
	if endpoint.Token != rt.lastToolboxToken {
		t.Fatalf("toolbox token = %q, want %q", endpoint.Token, rt.lastToolboxToken)
	}

	cap := svc.Capacity()
	if cap.SandboxesActive != 1 || cap.ReservedCPU != models.DefaultCPU {
		t.Fatalf("capacity snapshot = %+v, want one active sandbox reserving default CPU", cap)
	}

	again, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "busybox:latest"}, resp.ID)
	if err != nil {
		t.Fatalf("CreateSandboxWithID() on existing sandbox error = %v", err)
	}
	if rt.createCalls != 1 {
		t.Fatalf("runtime Create calls after no-op recreate = %d, want 1", rt.createCalls)
	}
	if again.Image != resp.Image {
		t.Fatalf("existing sandbox image = %q, want original %q", again.Image, resp.Image)
	}
}

func TestServiceLifecycleStopStartDestroyAndHealth(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	resp, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "ubuntu:22.04"}, "sb-life")
	if err != nil {
		t.Fatalf("CreateSandboxWithID() error = %v", err)
	}

	health, err := svc.Health(ctx)
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.Status != "ok" || health.Sandboxes != 1 || health.Docker != "ok" || health.Caddy != "ok" || health.Firecracker != "disabled" {
		t.Fatalf("initial health = %+v, want ok with one live sandbox", health)
	}

	stopped, err := svc.StopSandbox(ctx, resp.ID)
	if err != nil {
		t.Fatalf("StopSandbox() error = %v", err)
	}
	if len(rt.stopRefs) != 1 || rt.stopRefs[0] != resp.ContainerID {
		t.Fatalf("runtime stop refs = %v, want [%s]", rt.stopRefs, resp.ContainerID)
	}
	if stopped.Status != models.SandboxStatusStopped {
		t.Fatalf("stopped sandbox status = %q, want stopped", stopped.Status)
	}
	if got := svc.Capacity().SandboxesActive; got != 0 {
		t.Fatalf("active sandboxes after stop = %d, want 0", got)
	}

	rt.startState = &models.SandboxRuntimeState{
		SandboxID:   resp.ID,
		ContainerID: "ctr-restart",
		ContainerIP: "10.0.0.9",
		Status:      models.SandboxStatusStarted,
	}
	restarted, err := svc.StartSandbox(ctx, resp.ID)
	if err != nil {
		t.Fatalf("StartSandbox() error = %v", err)
	}
	if restarted.ContainerID != "ctr-restart" || restarted.ContainerIP != "10.0.0.9" {
		t.Fatalf("restarted sandbox runtime identity = %q/%q, want ctr-restart/10.0.0.9", restarted.ContainerID, restarted.ContainerIP)
	}
	if len(rt.pushes) == 0 {
		t.Fatal("expected StartSandbox to sync allowed ports")
	}
	if last := rt.pushes[len(rt.pushes)-1]; last.containerIP != "10.0.0.9" || last.token == "" || len(last.ports) != 0 {
		t.Fatalf("allowed ports push = %+v, want restart ip with empty port list", last)
	}

	rt.pingErr = errors.New("docker down")
	degraded, err := svc.Health(ctx)
	if err != nil {
		t.Fatalf("Health() with docker failure error = %v", err)
	}
	if degraded.Status != "degraded" || degraded.Docker != "docker down" {
		t.Fatalf("degraded health = %+v, want docker-down degraded state", degraded)
	}

	if err := svc.DestroySandbox(ctx, resp.ID); err != nil {
		t.Fatalf("DestroySandbox() error = %v", err)
	}
	if len(rt.destroyIDs) != 1 || rt.destroyIDs[0] != resp.ID {
		t.Fatalf("runtime destroy ids = %v, want [%s]", rt.destroyIDs, resp.ID)
	}
	// Inline image removal was replaced by a pending_image_gc schedule
	// in DestroySandbox; the janitor (StartPendingImageGC) handles the
	// actual docker.RemoveImage after ImageBuildGCTTL.
	if len(rt.removeImages) != 0 {
		t.Fatalf("RemoveImage must NOT run inline on destroy, got %v", rt.removeImages)
	}
	due, err := st.ListPendingImageGCDue(ctx, time.Now().UTC().Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("ListPendingImageGCDue: %v", err)
	}
	if len(due) != 1 || due[0].Image != resp.Image {
		t.Fatalf("pending_image_gc = %v, want [%s]", due, resp.Image)
	}
	if _, err := st.Get(ctx, resp.ID); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("sandbox still present after destroy: %v", err)
	}
}

func TestHealthReportsFirecrackerCapabilityDegraded(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{health: "firecracker runtime: vmgenid capability check could not find a kernel config"}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableFirecracker = true
	svc.SetFirecrackerRuntime(rt)

	health, err := svc.Health(ctx)
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.Status != "degraded" {
		t.Fatalf("health status = %q, want degraded", health.Status)
	}
	if health.Firecracker != rt.health {
		t.Fatalf("firecracker status = %q, want %q", health.Firecracker, rt.health)
	}
}

func TestStartSandboxReleasesAdmissionWhenMountLoadFails(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	sealCipher := newTestCipher(t)
	svc.cipher = sealCipher
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-start-mount-error",
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStopped,
		ContainerID:  "ctr-start-mount-error",
		ContainerIP:  "10.0.0.20",
		Runtime:      models.RuntimeDocker,
		CPU:          2,
		MemoryMB:     1024,
		DiskGB:       10,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	sealed, err := svc.sealMounts([]models.MountSpec{{
		Type:        models.MountTypeS3,
		Target:      "/data",
		Source:      "bucket",
		Credentials: map[string]string{"access_key": "key", "secret_key": "secret"},
	}})
	if err != nil {
		t.Fatalf("sealMounts() error = %v", err)
	}
	if err := st.PutMounts(ctx, "sb-start-mount-error", sealed); err != nil {
		t.Fatalf("PutMounts() error = %v", err)
	}
	// Swap to a different key so loadMounts fails before docker.Start runs.
	svc.cipher = newTestCipher(t)

	_, err = svc.StartSandbox(ctx, "sb-start-mount-error")
	if err == nil || !strings.Contains(err.Error(), "decrypt mounts") {
		t.Fatalf("StartSandbox() error = %v, want mount decrypt failure", err)
	}
	if len(rt.startRefs) != 0 {
		t.Fatalf("runtime Start refs = %v, want none when mount load fails first", rt.startRefs)
	}
	if cap := svc.Capacity(); cap.SandboxesActive != 0 || cap.ReservedCPU != 0 || cap.ReservedMemoryMB != 0 {
		t.Fatalf("capacity snapshot after failed start = %+v, want released admission", cap)
	}
	got, err := st.Get(ctx, "sb-start-mount-error")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if got.Status != models.SandboxStatusStopped {
		t.Fatalf("sandbox status = %q, want stopped after failed start", got.Status)
	}
}

func TestToolboxTargetRequiresContainerIP(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:             "sb-no-ip",
		Image:          "alpine:3.20",
		Status:         models.SandboxStatusStarted,
		ContainerID:    "ctr-no-ip",
		ContainerIP:    "",
		CPU:            1,
		MemoryMB:       256,
		DiskGB:         5,
		OSUser:         "root",
		ToolboxEnabled: true,
		ToolboxToken:   "toolbox-token",
		CreatedAt:      now,
		UpdatedAt:      now,
		LastActiveAt:   now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	_, err := svc.ToolboxTarget(ctx, "sb-no-ip")
	if err == nil || !strings.Contains(err.Error(), "container IP is not available") {
		t.Fatalf("ToolboxTarget() error = %v, want missing container IP", err)
	}
}

func TestServiceHelperUtilities(t *testing.T) {
	authorizedKey, privateKey, err := generateSandboxSSHKeys()
	if err != nil {
		t.Fatalf("generateSandboxSSHKeys() error = %v", err)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey)); err != nil {
		t.Fatalf("authorized key is not parseable: %v", err)
	}
	if !strings.Contains(privateKey, "PRIVATE KEY") {
		t.Fatalf("private key missing PEM block: %q", privateKey)
	}

	token, err := generateToolboxToken()
	if err != nil {
		t.Fatalf("generateToolboxToken() error = %v", err)
	}
	if len(token) != 64 {
		t.Fatalf("toolbox token length = %d, want 64", len(token))
	}
	if _, err := hex.DecodeString(token); err != nil {
		t.Fatalf("toolbox token is not hex: %v", err)
	}

	id, err := GenerateSandboxID()
	if err != nil {
		t.Fatalf("GenerateSandboxID() error = %v", err)
	}
	if !strings.HasPrefix(id, "sb-") || len(id) != 19 {
		t.Fatalf("sandbox id = %q, want sb- prefix plus 16 hex chars", id)
	}

	if got := (&Service{}).Capacity(); !got.CanAdmit {
		t.Fatalf("zero-value capacity snapshot = %+v, want CanAdmit=true", got)
	}

	hostCases := map[string]string{
		"https://sandbox.example.com/path": "sandbox.example.com",
		"127.0.0.1:8443":                   "127.0.0.1",
		"[2001:db8::1]:443":                "2001:db8::1",
		"plain-host":                       "plain-host",
	}
	for input, want := range hostCases {
		if got := hostFromURL(input); got != want {
			t.Fatalf("hostFromURL(%q) = %q, want %q", input, got, want)
		}
	}

	portCases := map[string]int{
		":443":           443,
		"8443":           8443,
		"127.0.0.1:9443": 9443,
		"not-a-port":     0,
		"":               0,
	}
	for input, want := range portCases {
		if got := l4ListenPort(input); got != want {
			t.Fatalf("l4ListenPort(%q) = %d, want %d", input, got, want)
		}
	}
}

func TestHealthReportsClusterTopologyDegraded(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableCluster = true
	svc.AttachCluster(&topologyCluster{
		Noop: cluster.NewNoop("node-01", "http://node-01", ""),
		members: []cluster.Member{
			{NodeID: "server-1", Role: config.NodeRoleServer, Alive: true},
			{NodeID: "server-2", Role: config.NodeRoleServer, Alive: true},
			{NodeID: "server-3", Role: config.NodeRoleServer, Alive: true},
			{NodeID: "worker-1", Role: config.NodeRoleWorker, Alive: true},
			{NodeID: "worker-2", Role: config.NodeRoleWorker, Alive: true},
			{NodeID: "worker-3", Role: config.NodeRoleWorker, Alive: true},
			{NodeID: "worker-4", Role: config.NodeRoleWorker, Alive: true},
			{NodeID: "worker-5", Role: config.NodeRoleWorker, Alive: true},
			{NodeID: "worker-6", Role: config.NodeRoleWorker, Alive: true},
			{NodeID: "ingress-1", Role: config.NodeRoleIngress, Alive: true},
			{NodeID: "edge-1", Role: "worker,ingress", Alive: true},
		},
	})

	health, err := svc.Health(ctx)
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.Status != "degraded" {
		t.Fatalf("health status = %q, want degraded", health.Status)
	}
	if health.ClusterTopology == "" {
		t.Fatal("cluster topology error should be populated")
	}
	if health.ClusterNodes != 11 {
		t.Fatalf("cluster nodes = %d, want 11 live members", health.ClusterNodes)
	}
}

func TestHealthReportsShardAwareIngressViolation(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableCluster = true

	members := []cluster.Member{
		{NodeID: "server-1", Role: config.NodeRoleServer, Alive: true},
		{NodeID: "server-2", Role: config.NodeRoleServer, Alive: true},
		{NodeID: "server-3", Role: config.NodeRoleServer, Alive: true},
		{NodeID: "worker-1", Role: config.NodeRoleWorker, Alive: true},
		{NodeID: "worker-2", Role: config.NodeRoleWorker, Alive: true},
		{NodeID: "worker-3", Role: config.NodeRoleWorker, Alive: true},
	}
	for i := 0; i < cluster.MaxReplicatedIngressRouteNodes+1; i++ {
		members = append(members, cluster.Member{
			NodeID: fmt.Sprintf("ingress-%02d", i),
			Role:   config.NodeRoleIngress,
			Alive:  true,
		})
	}
	svc.AttachCluster(&topologyCluster{
		Noop:    cluster.NewNoop("node-01", "http://node-01", ""),
		members: members,
	})

	health, err := svc.Health(ctx)
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.Status != "degraded" {
		t.Fatalf("health status = %q, want degraded", health.Status)
	}
	if !strings.Contains(health.ClusterTopology, "SB_CLUSTER_SHARD_AWARE_INGRESS") {
		t.Fatalf("cluster topology = %q, want shard-aware-ingress error", health.ClusterTopology)
	}

	svc.cfg.ClusterShardAwareIngress = true
	health, err = svc.Health(ctx)
	if err != nil {
		t.Fatalf("Health() with shard-aware flag error = %v", err)
	}
	if health.Status == "degraded" {
		t.Fatalf("health status with shard-aware flag = %q, want ok", health.Status)
	}
	if health.ClusterTopology != "ok" {
		t.Fatalf("cluster topology with shard-aware flag = %q, want ok", health.ClusterTopology)
	}
}

func TestEnsureClusterReadyCoversInitAndLeaderPaths(t *testing.T) {
	t.Run("missing cluster", func(t *testing.T) {
		svc := &Service{}
		if err := svc.EnsureClusterReady(context.Background()); err == nil || !strings.Contains(err.Error(), "not initialized") {
			t.Fatalf("EnsureClusterReady() error = %v, want not initialized", err)
		}
	})

	t.Run("context canceled before leader election", func(t *testing.T) {
		svc := &Service{}
		svc.AttachCluster(&leaderCluster{Noop: cluster.NewNoop("self", "http://self", ""), leader: ""})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := svc.EnsureClusterReady(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("EnsureClusterReady() error = %v, want context.Canceled", err)
		}
	})

	t.Run("leader available latches readiness", func(t *testing.T) {
		svc := &Service{}
		svc.AttachCluster(&leaderCluster{Noop: cluster.NewNoop("self", "http://self", ""), leader: "leader-1"})
		if err := svc.EnsureClusterReady(context.Background()); err != nil {
			t.Fatalf("EnsureClusterReady() error = %v", err)
		}
		if !svc.clusterReady.Load() {
			t.Fatal("cluster ready latch should be set after a successful readiness check")
		}
	})
}

func TestListMountsReturnsRedactedSpecs(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cipher = newTestCipher(t)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:             "sb-mounts",
		Image:          "alpine:3.20",
		Status:         models.SandboxStatusStarted,
		ContainerID:    "ctr-mounts",
		ContainerIP:    "10.0.0.14",
		CPU:            1,
		MemoryMB:       256,
		DiskGB:         5,
		OSUser:         "root",
		ToolboxEnabled: true,
		CreatedAt:      now,
		UpdatedAt:      now,
		LastActiveAt:   now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	sealed, err := svc.sealMounts([]models.MountSpec{{
		Type:        models.MountTypeS3,
		Target:      "/data",
		Source:      "my-bucket",
		Options:     map[string]string{"region": "us-east-1"},
		Credentials: map[string]string{"access_key": "key", "secret_key": "secret"},
		ReadOnly:    true,
	}})
	if err != nil {
		t.Fatalf("sealMounts() error = %v", err)
	}
	if err := st.PutMounts(ctx, "sb-mounts", sealed); err != nil {
		t.Fatalf("PutMounts() error = %v", err)
	}

	mounts, err := svc.ListMounts(ctx, "sb-mounts")
	if err != nil {
		t.Fatalf("ListMounts() error = %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("mount count = %d, want 1", len(mounts))
	}
	if mounts[0].Target != "/data" || mounts[0].Source != "my-bucket" || !mounts[0].HasCredentials || !mounts[0].ReadOnly {
		t.Fatalf("redacted mount = %+v, want redacted data mount with credentials flag", mounts[0])
	}
}

func TestCreateSandboxValidationAndRollbackPaths(t *testing.T) {
	t.Run("validation failures", func(t *testing.T) {
		cases := []struct {
			name string
			req  models.CreateSandboxRequest
			want string
		}{
			{name: "missing image", req: models.CreateSandboxRequest{}, want: "image is required"},
			{name: "runtime not implemented", req: models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeKata}, want: models.ErrRuntimeNotImplemented.Error()},
			{name: "too many mounts", req: models.CreateSandboxRequest{Image: "alpine:3.20", Mounts: make([]models.MountSpec, models.MaxMountsPerSandbox+1)}, want: "too many mounts"},
			{name: "invalid lifecycle", req: models.CreateSandboxRequest{Image: "alpine:3.20", Lifecycle: &models.Lifecycle{StopIfIdleFor: -time.Second}}, want: "invalid lifecycle"},
			{name: "invalid gpu", req: models.CreateSandboxRequest{Image: "alpine:3.20", GPUs: &models.GPURequest{Vendor: "bogus"}}, want: "invalid gpu request"},
			{name: "negative network limit", req: models.CreateSandboxRequest{Image: "alpine:3.20", NetworkBytesInLimit: -1}, want: "network byte limits must be >= 0"},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rt := &recordingRuntime{}
				svc, _, _ := newServiceRuntimeHarness(t, rt)
				_, err := svc.CreateSandbox(context.Background(), tc.req)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("CreateSandbox() error = %v, want substring %q", err, tc.want)
				}
				if rt.createCalls != 0 {
					t.Fatalf("runtime Create calls = %d, want 0 on validation failure", rt.createCalls)
				}
			})
		}
	})

	t.Run("runtime create failure releases admission", func(t *testing.T) {
		rt := &recordingRuntime{createErr: errors.New("create failed")}
		svc, _, _ := newServiceRuntimeHarness(t, rt)
		_, err := svc.CreateSandboxWithID(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-runtime-fail")
		if err == nil || !strings.Contains(err.Error(), "create failed") {
			t.Fatalf("CreateSandboxWithID() error = %v, want runtime create failure", err)
		}
		if got := svc.Capacity().SandboxesActive; got != 0 {
			t.Fatalf("active sandboxes after runtime failure = %d, want 0", got)
		}
	})

	t.Run("name conflict destroys created runtime artifact", func(t *testing.T) {
		ctx := context.Background()
		rt := &recordingRuntime{createState: &models.SandboxRuntimeState{SandboxID: "sb-conflict", ContainerID: "ctr-conflict", ContainerIP: "10.0.0.30", Status: models.SandboxStatusStarted}}
		svc, st, _ := newServiceRuntimeHarness(t, rt)
		now := time.Now().UTC()
		if err := st.Create(ctx, &models.Sandbox{
			ID:             "sb-existing",
			Image:          "alpine:3.20",
			Status:         models.SandboxStatusStarted,
			ContainerID:    "ctr-existing",
			ContainerIP:    "10.0.0.31",
			CPU:            1,
			MemoryMB:       256,
			DiskGB:         5,
			OSUser:         "root",
			ToolboxEnabled: true,
			Name:           "dup-name",
			CreatedAt:      now,
			UpdatedAt:      now,
			LastActiveAt:   now,
		}); err != nil {
			t.Fatalf("seed existing sandbox: %v", err)
		}

		_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", Name: "dup-name"}, "sb-conflict")
		if !errors.Is(err, storepkg.ErrSandboxNameConflict) {
			t.Fatalf("CreateSandboxWithID() error = %v, want ErrSandboxNameConflict", err)
		}
		if len(rt.destroyIDs) != 1 || rt.destroyIDs[0] != "sb-conflict" {
			t.Fatalf("runtime destroy ids after conflict = %v, want [sb-conflict]", rt.destroyIDs)
		}
		if _, err := st.Get(ctx, "sb-conflict"); !errors.Is(err, storepkg.ErrNotFound) {
			t.Fatalf("conflicting sandbox leaked into store: %v", err)
		}
	})
}

func TestCreateSandboxSealMountsFailure(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.admitter = nil
	svc.cipher = &secrets.Cipher{}

	_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20",
		Mounts: []models.MountSpec{
			{Type: models.MountTypeS3, Target: "/data", Source: "bucket"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "encrypt mounts") {
		t.Fatalf("CreateSandbox() error = %v, want mount sealing failure", err)
	}
	if rt.createCalls != 0 {
		t.Fatalf("runtime Create calls = %d, want 0 when mount sealing fails", rt.createCalls)
	}
}

func TestCreateSandboxSealRegistryFailureRollsBackRuntime(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.admitter = nil
	svc.cipher = &secrets.Cipher{}

	_, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20",
		Registry: &models.RegistryAuth{
			Server:   "ghcr.io",
			Username: "alice",
			Password: "top-secret",
		},
	}, "sb-registry-fail")
	if err == nil || !strings.Contains(err.Error(), "encrypt registry auth") {
		t.Fatalf("CreateSandboxWithID() error = %v, want registry sealing failure", err)
	}
	if rt.createCalls != 1 {
		t.Fatalf("runtime Create calls = %d, want 1 before seal failure", rt.createCalls)
	}
	if len(rt.destroyIDs) != 1 || rt.destroyIDs[0] != "sb-registry-fail" {
		t.Fatalf("runtime Destroy ids = %v, want [sb-registry-fail]", rt.destroyIDs)
	}
	if _, err := st.Get(ctx, "sb-registry-fail"); err == nil {
		t.Fatal("failed create should not leave a sandbox row")
	}
}

func TestCreateSandboxWithCustomDomainsPersistsRows(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.test"

	resp, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{
		Image:         "alpine:3.20",
		Name:          "custom-domains",
		CustomDomains: []string{"api.external.test", "www.external.test"},
	}, "sb-custom-domains")
	if err != nil {
		t.Fatalf("CreateSandboxWithID() error = %v", err)
	}
	if rt.createCalls != 1 {
		t.Fatalf("runtime Create calls = %d, want 1", rt.createCalls)
	}
	if resp.Runtime != models.RuntimeDocker {
		t.Fatalf("response runtime = %q, want docker", resp.Runtime)
	}
	stored, err := st.Get(ctx, resp.ID)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if len(stored.CustomDomains) != 2 {
		t.Fatalf("stored custom domains = %+v, want 2 rows", stored.CustomDomains)
	}
	gotHosts := map[string]struct{}{}
	for _, cd := range stored.CustomDomains {
		gotHosts[cd.Hostname] = struct{}{}
		if cd.TargetPort != 0 {
			t.Fatalf("custom domain target_port = %d, want toolbox default 0", cd.TargetPort)
		}
	}
	for _, host := range []string{"api.external.test", "www.external.test"} {
		if _, ok := gotHosts[host]; !ok {
			t.Fatalf("missing persisted custom domain %q in %+v", host, stored.CustomDomains)
		}
	}
}

func TestExposeAndUnexposePortProtocols(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg = config.Config{
		Runtime:           models.RuntimeDocker,
		ToolboxPort:       4321,
		EnableCaddy:       false,
		PublicHost:        "203.0.113.10",
		Domain:            "sandbox.example.com",
		L4TLSListen:       ":443",
		L4PortRangeStart:  32000,
		L4PortRangeEnd:    32010,
		HTTPClientTimeout: time.Second,
	}
	svc.caddy = caddy.New(svc.cfg)

	resp, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-ports")
	if err != nil {
		t.Fatalf("CreateSandboxWithID() error = %v", err)
	}

	httpExposure, err := svc.ExposePort(ctx, resp.ID, 8080, models.ExposedPortProtocolHTTP)
	if err != nil {
		t.Fatalf("ExposePort(http) error = %v", err)
	}
	if httpExposure.PublicURL != "https://sb-ports-8080.sandbox.example.com" {
		t.Fatalf("http exposure URL = %q, want domain-mode HTTP URL", httpExposure.PublicURL)
	}

	tcpExposure, err := svc.ExposePort(ctx, resp.ID, 5432, models.ExposedPortProtocolTCP)
	if err != nil {
		t.Fatalf("ExposePort(tcp) error = %v", err)
	}
	if tcpExposure.HostPort < 32000 || tcpExposure.HostPort > 32010 {
		t.Fatalf("tcp host port = %d, want configured range [32000,32010]", tcpExposure.HostPort)
	}
	if !strings.HasPrefix(tcpExposure.PublicURL, "tcp://sandbox.example.com:") {
		t.Fatalf("tcp exposure URL = %q, want tcp://sandbox.example.com:<port>", tcpExposure.PublicURL)
	}

	tcpExposureAgain, err := svc.ExposePort(ctx, resp.ID, 5432, models.ExposedPortProtocolTCP)
	if err != nil {
		t.Fatalf("ExposePort(tcp replay) error = %v", err)
	}
	if tcpExposureAgain.HostPort != tcpExposure.HostPort {
		t.Fatalf("tcp replay host port = %d, want original %d", tcpExposureAgain.HostPort, tcpExposure.HostPort)
	}

	tlsExposure, err := svc.ExposePort(ctx, resp.ID, 8443, models.ExposedPortProtocolTLS)
	if err != nil {
		t.Fatalf("ExposePort(tls) error = %v", err)
	}
	if tlsExposure.PublicURL != "tls://sb-ports-8443.sandbox.example.com:443" {
		t.Fatalf("tls exposure URL = %q, want TLS-SNI endpoint", tlsExposure.PublicURL)
	}

	stored, err := st.Get(ctx, resp.ID)
	if err != nil {
		t.Fatalf("store.Get() after expose error = %v", err)
	}
	if len(stored.ExposedPorts) != 3 {
		t.Fatalf("exposed port count = %d, want 3", len(stored.ExposedPorts))
	}

	for _, port := range []int{8080, 5432, 8443} {
		if err := svc.UnexposePort(ctx, resp.ID, port); err != nil {
			t.Fatalf("UnexposePort(%d) error = %v", port, err)
		}
	}
	updated, err := st.Get(ctx, resp.ID)
	if err != nil {
		t.Fatalf("store.Get() after unexpose error = %v", err)
	}
	if len(updated.ExposedPorts) != 0 {
		t.Fatalf("remaining exposed ports = %+v, want none", updated.ExposedPorts)
	}
	if len(rt.pushes) < 4 {
		t.Fatalf("expected allowlist pushes during expose/unexpose, got %d", len(rt.pushes))
	}
	if !svc.l4Ready.Load() {
		t.Fatal("L4 readiness latch should flip after TCP/TLS exposure")
	}
}

func newServiceRuntimeHarness(t *testing.T, rt *recordingRuntime) (*Service, *storepkg.Store, *capacity.Admitter) {
	t.Helper()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
	})

	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir:     filepath.Join(t.TempDir(), "mounts"),
		CredDir:     filepath.Join(t.TempDir(), "cred"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384, SupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeWasm, models.RuntimeFirecracker}},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)

	svc := &Service{
		cfg: config.Config{
			Runtime:           models.RuntimeDocker,
			ToolboxPort:       4321,
			EnableCaddy:       false,
			HTTPClientTimeout: time.Second,
			// Required for the destroy-side assertion that DestroySandbox
			// enqueues a pending_image_gc row.
			ImageBuildGCEnabled: true,
		},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:    st,
		docker:   rt,
		caddy:    caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second}),
		mounts:   mgr,
		admitter: admitter,
		images:   newDefaultImageDistributionProvider(""),
	}
	return svc, st, admitter
}
