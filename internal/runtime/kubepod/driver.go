// Package kubepod is the pod-mode runtime driver
// (plans/security-gaps-m1-m4.md M4, §6.2): each sandbox is a Kubernetes pod
// of its own, made with a RuntimeClass (gVisor, Kata, or the cluster's
// own), so the worker that makes them needs no privilege at all. The
// worker's only rights are pods create, delete, get, list and watch in the
// sandbox namespace.
//
// The pod is named after the sandbox ID. The API server keeps one object
// per name, so it refuses a second pod for a sandbox while an earlier one
// still exists, on this worker or any other (plan D17).
//
// Nothing secret goes into a pod spec, which etcd stores in the clear: the
// toolbox token and env reach toolboxd over the worker's mTLS link instead
// (plan D8). That link is a later PR of the M4 stack; until it lands, a
// create with env is refused and the driver is not wired into sandboxd.
package kubepod

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Config is the driver's settings.
type Config struct {
	// Namespace holds the sandbox pods, and nothing else of AerolVM's.
	Namespace string
	// WorkerID is this worker's node ID. It labels every pod the worker
	// makes, so the worker lists only its own.
	WorkerID string
	// RuntimeClasses maps an AerolVM runtime name (gvisor, kata, ...) to
	// the RuntimeClass its pods get. A runtime not listed is refused,
	// never run under another class (plan R18).
	RuntimeClasses map[string]string
	// DefaultRuntime is the runtime of a create that names none. Empty is
	// allowed only when RuntimeClasses has one entry, which is then the
	// default.
	DefaultRuntime string
	// ToolboxImage holds toolboxd at ToolboxPath. Its init container
	// copies toolboxd into each sandbox pod.
	ToolboxImage string
	ToolboxPath  string
	// ToolboxPort is where toolboxd listens in the pod.
	ToolboxPort int
	// SpecDir keeps each sandbox's pod spec on the worker's state volume
	// (specs.go).
	SpecDir string
	// StartTimeout bounds the wait for a new pod to run with an address:
	// scheduling and the image pull happen inside it.
	StartTimeout time.Duration
	// StopTimeout bounds the wait for a deleted pod to be gone.
	StopTimeout time.Duration
	// StopGrace is the pod's termination grace period: how long a stop
	// gives the sandbox's processes after SIGTERM.
	StopGrace time.Duration
}

const (
	// defaultToolboxPort is toolboxd's own default (SB_TOOLBOX_PORT).
	defaultToolboxPort  = 2280
	defaultToolboxPath  = "/usr/local/bin/toolboxd"
	defaultStartTimeout = 3 * time.Minute
	defaultStopTimeout  = time.Minute
	defaultStopGrace    = 10 * time.Second
	// destroyGrace is the grace a destroy gives: nothing of the sandbox is
	// kept, so there is nothing to finish. Never zero (Client.DeletePod).
	destroyGrace = time.Second
	// undoTimeout bounds the clean-up of a create or start that failed. It
	// runs on a context of its own: the caller's may be what ran out.
	undoTimeout = 30 * time.Second
)

// ErrOldPodPresent is a create or start that found an earlier pod of the
// same sandbox still there: another worker's, or one still stopping. The
// new pod is made only once that one is gone, so two copies of a sandbox
// never run at once (plan D17). A later try may succeed.
var ErrOldPodPresent = errors.New("kubepod: an earlier pod of this sandbox still exists")

// Driver implements runtime.Runtime with one pod per sandbox. Safe for
// concurrent use; the service serializes calls for one sandbox.
type Driver struct {
	cfg    Config
	client *Client
	specs  *specStore
	logger *slog.Logger
	// cache is the watch's view of this worker's pods (watch.go), used
	// while RunWatch keeps it live.
	cache *podCache
	// pollMin and pollMax bound the backoff of the waits for a pod to run
	// or to go while there is no live watch; retryMin and retryMax, the
	// watch's own retries. Tests shrink them.
	pollMin, pollMax   time.Duration
	retryMin, retryMax time.Duration
	// undoWait bounds a failed create's clean-up (undoTimeout; tests
	// shrink it).
	undoWait time.Duration
}

var _ sbruntime.Runtime = (*Driver)(nil)

var (
	labelValue = regexp.MustCompile(`^([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)$`)
	dnsName    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// New checks cfg and returns a driver that talks to the API server through
// client.
func New(cfg Config, client *Client, logger *slog.Logger) (*Driver, error) {
	if client == nil {
		return nil, errors.New("kubepod: a Kubernetes client is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	cfg.Namespace = strings.TrimSpace(cfg.Namespace)
	if len(cfg.Namespace) > 63 || !dnsLabel.MatchString(cfg.Namespace) {
		return nil, fmt.Errorf("kubepod: namespace %q is not a Kubernetes namespace name", cfg.Namespace)
	}
	cfg.WorkerID = strings.TrimSpace(cfg.WorkerID)
	if len(cfg.WorkerID) > 63 || !labelValue.MatchString(cfg.WorkerID) {
		return nil, fmt.Errorf("kubepod: worker ID %q cannot be a label value (63 characters at most: letters, digits, '-', '_', '.')", cfg.WorkerID)
	}
	if len(cfg.RuntimeClasses) == 0 {
		return nil, errors.New("kubepod: no runtime is offered: map at least one runtime to a RuntimeClass")
	}
	classes := make(map[string]string, len(cfg.RuntimeClasses))
	for rt, class := range cfg.RuntimeClasses {
		rt, class = strings.TrimSpace(rt), strings.TrimSpace(class)
		if rt == "" {
			return nil, errors.New("kubepod: a runtime name in the RuntimeClass map is empty")
		}
		if len(class) > 253 || !dnsName.MatchString(class) {
			return nil, fmt.Errorf("kubepod: runtime %q maps to %q, which is not a RuntimeClass name", rt, class)
		}
		classes[rt] = class
	}
	cfg.RuntimeClasses = classes
	cfg.DefaultRuntime = strings.TrimSpace(cfg.DefaultRuntime)
	if cfg.DefaultRuntime == "" && len(classes) == 1 {
		for rt := range classes {
			cfg.DefaultRuntime = rt
		}
	}
	if _, ok := classes[cfg.DefaultRuntime]; !ok {
		return nil, fmt.Errorf("kubepod: the default runtime %q has no RuntimeClass (offered: %s)", cfg.DefaultRuntime, strings.Join(sortedKeys(classes), ", "))
	}
	if strings.TrimSpace(cfg.ToolboxImage) == "" {
		return nil, errors.New("kubepod: the toolbox image is required")
	}
	if cfg.ToolboxPath == "" {
		cfg.ToolboxPath = defaultToolboxPath
	}
	if !filepath.IsAbs(cfg.ToolboxPath) {
		return nil, fmt.Errorf("kubepod: the toolbox path %q must be absolute", cfg.ToolboxPath)
	}
	if cfg.ToolboxPort == 0 {
		cfg.ToolboxPort = defaultToolboxPort
	}
	if cfg.ToolboxPort < 1 || cfg.ToolboxPort > 65535 {
		return nil, fmt.Errorf("kubepod: toolbox port %d is out of range", cfg.ToolboxPort)
	}
	if cfg.StartTimeout <= 0 {
		cfg.StartTimeout = defaultStartTimeout
	}
	if cfg.StopTimeout <= 0 {
		cfg.StopTimeout = defaultStopTimeout
	}
	if cfg.StopGrace <= 0 {
		cfg.StopGrace = defaultStopGrace
	}
	if cfg.StopGrace < time.Second {
		cfg.StopGrace = time.Second
	}
	specs, err := newSpecStore(cfg.SpecDir)
	if err != nil {
		return nil, err
	}
	return &Driver{
		cfg:      cfg,
		client:   client,
		specs:    specs,
		logger:   logger,
		cache:    newPodCache(),
		pollMin:  100 * time.Millisecond,
		pollMax:  time.Second,
		retryMin: watchRetryMin,
		retryMax: watchRetryMax,
		undoWait: undoTimeout,
	}, nil
}

// notFound is the answer of the watch's view for a pod it does not hold:
// the same as the API server's 404, so callers need not tell them apart.
func notFound(name string) error {
	return &APIError{Method: "GET", Path: "(watch view) " + name, Code: 404, Reason: "NotFound", Message: "not in this worker's pods"}
}

// getPod reads one of this worker's pods: from the watch's view while it
// is live, else from the API server. The view holds only this worker's
// pods, so another worker's pod of the name reads as not found; callers
// treat the two alike.
func (d *Driver) getPod(ctx context.Context, name string) (*Pod, error) {
	if p, found, live := d.cache.lookup(name); live {
		if !found {
			return nil, notFound(name)
		}
		return p, nil
	}
	return d.client.GetPod(ctx, d.cfg.Namespace, name)
}

// pause waits for the next change while the watch is live (wake was taken
// before the read the caller is acting on), else for delay.
func (d *Driver) pause(ctx context.Context, wake <-chan struct{}, live bool, delay time.Duration) error {
	if live {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
			return nil
		}
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func (d *Driver) offeredRuntimes() []string { return sortedKeys(d.cfg.RuntimeClasses) }

// selector picks this worker's sandbox pods.
func (d *Driver) selector() string {
	return LabelComponent + "=" + componentSandbox + "," + LabelWorker + "=" + d.cfg.WorkerID
}

// owns reports whether p is a sandbox pod this worker made.
func (d *Driver) owns(p *Pod) bool {
	return p.Metadata.Labels[LabelWorker] == d.cfg.WorkerID &&
		p.Metadata.Labels[LabelComponent] == componentSandbox
}

func sandboxIDOf(p *Pod) string {
	if id := p.Metadata.Annotations[AnnotationSandboxID]; id != "" {
		return id
	}
	return p.Metadata.Name
}

// Create makes the sandbox's pod and waits until it runs with an address.
// The pod's spec is kept first, so a crash after the API call still leaves
// the worker knowing the pod. On a failed start the pod is deleted and its
// spec forgotten.
func (d *Driver) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID, _ string, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	// The toolbox token is not used here: it never goes into a pod spec
	// (plan D8). The worker hands it to toolboxd over mTLS (a later PR).
	sandboxID = strings.TrimSpace(sandboxID)
	if err := rootpolicy.ValidateID(sandboxID); err != nil {
		return nil, err
	}
	if len(hostMounts) > 0 {
		return nil, ErrHostMountsNotSupported
	}
	p, err := d.renderPod(req, sandboxID)
	if err != nil {
		return nil, err
	}
	name := p.Metadata.Name
	kept, err := d.specs.has(name)
	if err != nil {
		return nil, err
	}
	if kept {
		// This worker made this sandbox before; it is running or stopped.
		return nil, fmt.Errorf("%w: sandbox %s already has a pod on this worker", dockerpkg.ErrSandboxContainerExists, sandboxID)
	}
	if err := d.specs.put(p); err != nil {
		return nil, err
	}
	created, err := d.client.CreatePod(ctx, d.cfg.Namespace, p)
	if err != nil {
		if isAlreadyExists(err) {
			return nil, d.nameTaken(ctx, name, sandboxID)
		}
		d.undoUnanswered(ctx, err, name, sandboxID)
		d.forget(name)
		return nil, err
	}
	state, err := d.waitRunning(ctx, name, created.Metadata.UID)
	if err != nil {
		d.undo(ctx, name, created.Metadata.UID, true)
		return nil, err
	}
	return state, nil
}

// nameTaken explains a create the API server refused because a pod of that
// name exists. Only this worker's own running pod for the same sandbox is a
// duplicate create, the error the service answers with the sandbox it
// already has; anything else is refused without touching that pod.
func (d *Driver) nameTaken(ctx context.Context, name, sandboxID string) error {
	existing, err := d.client.GetPod(ctx, d.cfg.Namespace, name)
	if err != nil {
		d.forget(name)
		if isNotFound(err) {
			return fmt.Errorf("%w: pod %s went away during the create; try again", ErrOldPodPresent, name)
		}
		return err
	}
	switch other := sandboxIDOf(existing); {
	case other != sandboxID:
		d.forget(name)
		return fmt.Errorf("kubepod: pod name %s is held by sandbox %q", name, other)
	case !d.owns(existing):
		d.forget(name)
		return fmt.Errorf("%w: pod %s belongs to worker %q", ErrOldPodPresent, name, existing.Metadata.Labels[LabelWorker])
	case existing.Metadata.DeletionTimestamp != nil:
		d.forget(name)
		return fmt.Errorf("%w: pod %s is still stopping", ErrOldPodPresent, name)
	}
	// Ours and live: a retried or concurrent create. The spec just kept is
	// the same sandbox's, so it stays.
	return fmt.Errorf("%w: pod %s already exists", dockerpkg.ErrSandboxContainerExists, name)
}

// Start makes a stopped sandbox's pod again from its kept spec. A pod that
// still runs is left alone (Start is idempotent); one that ended, or is
// stopping, must be gone first, since the new one takes its name.
func (d *Driver) Start(ctx context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	name := podName(strings.TrimSpace(containerRef))
	p, err := d.getPod(ctx, name)
	switch {
	case err == nil:
		if !d.owns(p) {
			return nil, fmt.Errorf("%w: pod %s belongs to worker %q", ErrOldPodPresent, name, p.Metadata.Labels[LabelWorker])
		}
		if p.Metadata.DeletionTimestamp == nil && !ended(p) {
			return d.waitRunning(ctx, name, p.Metadata.UID)
		}
		if p.Metadata.DeletionTimestamp == nil {
			if err := d.client.DeletePod(ctx, d.cfg.Namespace, name, p.Metadata.UID, d.cfg.StopGrace); err != nil && !isNotFound(err) && !isConflict(err) {
				return nil, err
			}
		}
		if err := d.waitGone(ctx, name, p.Metadata.UID, d.cfg.StopTimeout); err != nil {
			return nil, err
		}
	case !isNotFound(err):
		return nil, err
	}
	kept, err := d.specs.get(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("kubepod: sandbox %s has no pod and no kept spec: %w", containerRef, sbruntime.ErrInstanceNotFound)
	}
	if err != nil {
		return nil, err
	}
	fresh, err := d.rebuild(kept, name)
	if err != nil {
		return nil, err
	}
	created, err := d.client.CreatePod(ctx, d.cfg.Namespace, fresh)
	if err != nil {
		if isAlreadyExists(err) {
			return nil, fmt.Errorf("%w: pod %s came back while starting", ErrOldPodPresent, name)
		}
		d.undoUnanswered(ctx, err, name, sandboxIDOf(fresh))
		return nil, err
	}
	state, err := d.waitRunning(ctx, name, created.Metadata.UID)
	if err != nil {
		// The sandbox still exists, stopped: keep its spec.
		d.undo(ctx, name, created.Metadata.UID, false)
		return nil, err
	}
	return state, nil
}

// rebuild makes a start's pod from a kept spec: it reads back only the
// sandbox's own inputs (sandboxRequestOf) and renders the pod again with
// renderPod, so the pod sent is never the file's other content. The pod
// gets this worker's label, its toolbox image (a sandbox started after a
// worker upgrade gets the new toolboxd, as a restarted container on the
// default install does) and the current security settings; whatever else
// the file holds is not sent. The new spec is kept in place of the old.
func (d *Driver) rebuild(kept *Pod, name string) (*Pod, error) {
	req, id, err := sandboxRequestOf(kept)
	if err == nil && podName(id) != name {
		err = fmt.Errorf("it names sandbox %q, whose pod is %s", id, podName(id))
	}
	if err != nil {
		return nil, fmt.Errorf("kubepod: the kept spec %s cannot be used: %w", name, err)
	}
	fresh, err := d.renderPod(req, id)
	if err != nil {
		return nil, fmt.Errorf("kubepod: sandbox %s cannot start here as it was made: %w", id, err)
	}
	if err := d.specs.put(fresh); err != nil {
		return nil, err
	}
	return fresh, nil
}

// Stop deletes the sandbox's pod and waits until it is gone, so a stopped
// sandbox runs nowhere. Its memory and files go with the pod; its spec is
// kept for Start. Stopping a sandbox with no pod here is a no-op.
func (d *Driver) Stop(ctx context.Context, containerRef string) error {
	name := podName(strings.TrimSpace(containerRef))
	p, err := d.getPod(ctx, name)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !d.owns(p) {
		// Another worker's pod of this name (the sandbox was recreated
		// there): not this worker's to stop.
		return nil
	}
	return d.deleteAndWait(ctx, p, d.cfg.StopGrace)
}

// Destroy deletes the sandbox's pod, waits until it is gone, and forgets
// its spec. A retry after any failure starts over and converges.
func (d *Driver) Destroy(ctx context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil {
		return nil
	}
	ref := strings.TrimSpace(sandbox.ContainerID)
	if ref == "" {
		ref = strings.TrimSpace(sandbox.ID)
	}
	name := podName(ref)
	p, err := d.getPod(ctx, name)
	switch {
	case isNotFound(err):
	case err != nil:
		return err
	case d.owns(p):
		if err := d.deleteAndWait(ctx, p, destroyGrace); err != nil {
			return err
		}
	}
	return d.specs.remove(name)
}

// Inspect reads the sandbox's pod. With no pod of this worker's, a kept
// spec is a stopped sandbox and no spec is a sandbox that is gone.
func (d *Driver) Inspect(ctx context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	name := podName(strings.TrimSpace(containerRef))
	p, err := d.getPod(ctx, name)
	if err == nil && d.owns(p) {
		return stateOf(p), nil
	}
	if err != nil && !isNotFound(err) {
		return nil, err
	}
	kept, err := d.specs.get(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("kubepod: pod %s: %w", name, sbruntime.ErrInstanceNotFound)
	}
	if err != nil {
		return nil, err
	}
	return &models.SandboxRuntimeState{SandboxID: sandboxIDOf(kept), ContainerID: name, Status: models.SandboxStatusStopped}, nil
}

// ListManaged returns this worker's sandboxes: its pods (from the watch's
// view while it is live, else one list), and its kept specs with no pod as
// stopped.
func (d *Driver) ListManaged(ctx context.Context) (map[string]*models.SandboxRuntimeState, error) {
	pods, live := d.cache.all()
	if !live {
		listed, _, err := d.client.ListPods(ctx, d.cfg.Namespace, d.selector())
		if err != nil {
			return nil, err
		}
		pods = make([]*Pod, len(listed))
		for i := range listed {
			pods[i] = &listed[i]
		}
	}
	out := make(map[string]*models.SandboxRuntimeState, len(pods))
	for _, p := range pods {
		if d.owns(p) {
			st := stateOf(p)
			out[st.SandboxID] = st
		}
	}
	kept, bad, err := d.specs.list()
	if err != nil {
		return nil, err
	}
	for _, name := range bad {
		// Left out, not fatal: reconcile asks Inspect about a row the list
		// misses, and Inspect answers "unknown" for this file, so the row
		// stays.
		d.logger.Warn("kubepod: a kept pod spec cannot be read; its sandbox cannot start until it is fixed", "pod", name)
	}
	for _, k := range kept {
		id := sandboxIDOf(k)
		if _, ok := out[id]; !ok {
			out[id] = &models.SandboxRuntimeState{SandboxID: id, ContainerID: k.Metadata.Name, Status: models.SandboxStatusStopped}
		}
	}
	return out, nil
}

// Ping lists one pod: it proves the API server answers and that this
// worker may list pods in the sandbox namespace.
func (d *Driver) Ping(ctx context.Context) error {
	return d.client.CanList(ctx, d.cfg.Namespace, d.selector())
}

// CreateSnapshot is refused: a pod has no snapshot to take.
func (d *Driver) CreateSnapshot(context.Context, string, string) (string, error) {
	return "", fmt.Errorf("kubepod: pod mode has no snapshots: %w", models.ErrRuntimeNotImplemented)
}

// Resize is refused: the worker's Role has no right to resize pods.
func (d *Driver) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return fmt.Errorf("kubepod: pod mode cannot resize a running sandbox: %w", models.ErrRuntimeNotImplemented)
}

// RemoveImage does nothing: the kubelet of each machine owns its images and
// removes unused ones itself.
func (d *Driver) RemoveImage(context.Context, string) error { return nil }

var _ sbruntime.NetRulesReporter = (*Driver)(nil)

// NetRulesEnabled is false: pod mode has no host firewall, so the service
// refuses a create's network policy (network_policy_enforcement.go) before
// it reaches the driver, which refuses it too (networkRuleFields).
func (d *Driver) NetRulesEnabled() bool { return false }

// stateOf maps a pod to a sandbox state. A pod still starting, or one whose
// node stopped reporting (phase Unknown), still exists: it is started with
// no address, never gone (runtime.InstanceGone). A pod being deleted that
// is not running is stopped: nothing of it runs, and it is on its way out.
func stateOf(p *Pod) *models.SandboxRuntimeState {
	st := &models.SandboxRuntimeState{SandboxID: sandboxIDOf(p), ContainerID: p.Metadata.Name, Status: models.SandboxStatusStarted}
	if p.Status == nil {
		if p.Metadata.DeletionTimestamp != nil {
			st.Status = models.SandboxStatusStopped
		}
		return st
	}
	switch p.Status.Phase {
	case PhaseSucceeded, PhaseFailed:
		st.Status = models.SandboxStatusStopped
	case PhasePending, "":
		if p.Metadata.DeletionTimestamp != nil {
			st.Status = models.SandboxStatusStopped
		}
	case PhaseRunning:
		st.ContainerIP = p.Status.PodIP
		for _, cs := range p.Status.ContainerStatuses {
			if cs.Name == sandboxContainer && cs.State.Running != nil && cs.State.Running.StartedAt != nil {
				st.StartedAt = *cs.State.Running.StartedAt
			}
		}
	}
	return st
}

// ended reports a pod whose toolboxd has exited. With restartPolicy Never
// it never runs again; a start makes a new one.
func ended(p *Pod) bool {
	return p.Status != nil && (p.Status.Phase == PhaseSucceeded || p.Status.Phase == PhaseFailed)
}

// cannotStart are the waiting reasons of a container the kubelet will not
// start however long the create waits. ErrImagePull is the first failed
// pull: the kubelet would retry with backoff, but the default install also
// fails a create on a failed pull.
var cannotStart = map[string]bool{
	"ErrImagePull":               true,
	"ImagePullBackOff":           true,
	"InvalidImageName":           true,
	"ErrImageNeverPull":          true,
	"CreateContainerConfigError": true,
	"CreateContainerError":       true,
	"RunContainerError":          true,
}

// progress reads a starting pod: its state once it runs with an address, an
// error once it cannot run, or else what it is waiting for.
func progress(p *Pod) (*models.SandboxRuntimeState, string, error) {
	name := p.Metadata.Name
	if p.Metadata.DeletionTimestamp != nil {
		return nil, "", fmt.Errorf("kubepod: pod %s is being deleted", name)
	}
	if p.Status == nil {
		return nil, "no status yet", nil
	}
	switch p.Status.Phase {
	case PhaseRunning:
		if p.Status.PodIP != "" {
			return stateOf(p), "", nil
		}
		return nil, "running, no address yet", nil
	case PhaseSucceeded, PhaseFailed:
		return nil, "", fmt.Errorf("kubepod: pod %s ended before it was ready: %s", name, endReason(p))
	}
	waiting := "pending"
	for _, c := range p.Status.Conditions {
		if c.Type == "PodScheduled" && c.Status == "False" {
			waiting = fmt.Sprintf("not scheduled: %s: %s", c.Reason, c.Message)
		}
	}
	for _, cs := range append(slices.Clone(p.Status.InitContainerStatuses), p.Status.ContainerStatuses...) {
		w := cs.State.Waiting
		if w == nil {
			continue
		}
		if cannotStart[w.Reason] {
			return nil, "", fmt.Errorf("kubepod: container %s of pod %s cannot start: %s: %s", cs.Name, name, w.Reason, w.Message)
		}
		if w.Reason != "" {
			waiting = cs.Name + ": " + w.Reason
		}
	}
	return nil, waiting, nil
}

// endReason says why an ended pod ended: the first container that ended
// with an error, else the pod's own reason.
func endReason(p *Pod) string {
	for _, cs := range append(slices.Clone(p.Status.InitContainerStatuses), p.Status.ContainerStatuses...) {
		if t := cs.State.Terminated; t != nil && (t.ExitCode != 0 || t.Reason != "Completed") {
			return fmt.Sprintf("container %s: exit %d %s %s", cs.Name, t.ExitCode, t.Reason, strings.TrimSpace(t.Message))
		}
	}
	return strings.TrimSpace(p.Status.Phase + " " + p.Status.Reason + " " + p.Status.Message)
}

// waitRunning waits until the pod (uid) runs with an address, it cannot,
// or StartTimeout passes: on the watch's changes while it is live, else by
// reading the pod with backoff. A failed read is tried again until then:
// one API server hiccup must not fail a create.
func (d *Driver) waitRunning(ctx context.Context, name, uid string) (*models.SandboxRuntimeState, error) {
	ctx, cancel := context.WithTimeout(ctx, d.cfg.StartTimeout)
	defer cancel()
	waiting := "not read yet"
	for delay := d.pollMin; ; delay = min(delay*2, d.pollMax) {
		wake, live := d.cache.changes()
		p, err := d.getPod(ctx, name)
		switch {
		case err != nil && ctx.Err() != nil:
			// The read was cut short by the deadline: what the pod was
			// waiting for is the answer worth giving.
			return nil, fmt.Errorf("kubepod: pod %s did not start (%s): %w", name, waiting, ctx.Err())
		case isNotFound(err) && live && !d.cache.deleted(uid):
			// Made, but its first watch event has not come yet.
			waiting = "not shown by the watch yet"
		case isNotFound(err):
			return nil, fmt.Errorf("kubepod: pod %s was deleted while it started", name)
		case err != nil:
			waiting = err.Error()
		case p.Metadata.UID != uid:
			return nil, fmt.Errorf("%w: pod %s was replaced while it started", ErrOldPodPresent, name)
		default:
			state, why, err := progress(p)
			if err != nil || state != nil {
				return state, err
			}
			waiting = why
		}
		if d.pause(ctx, wake, live, delay) != nil {
			return nil, fmt.Errorf("kubepod: pod %s did not start (%s): %w", name, waiting, ctx.Err())
		}
	}
}

// deleteAndWait deletes p (by UID, so never a newer pod of its name) and
// waits until it is gone.
func (d *Driver) deleteAndWait(ctx context.Context, p *Pod, grace time.Duration) error {
	err := d.client.DeletePod(ctx, d.cfg.Namespace, p.Metadata.Name, p.Metadata.UID, grace)
	if isNotFound(err) || isConflict(err) {
		// Gone, or already replaced by another pod: the one meant is gone.
		return nil
	}
	if err != nil {
		return err
	}
	return d.waitGone(ctx, p.Metadata.Name, p.Metadata.UID, d.cfg.StopTimeout)
}

// waitGone waits until the pod (uid) no longer exists, on the watch's
// changes while it is live, else by reading with backoff. The view holds
// every pod of this worker's from the list on, so a pod of uid missing
// from it is gone. A pod on a node that cannot be reached stays until its
// node answers or someone removes it; the wait then ends with an error and
// the sandbox is not reported stopped.
func (d *Driver) waitGone(ctx context.Context, name, uid string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	last := "still there"
	for delay := d.pollMin; ; delay = min(delay*2, d.pollMax) {
		wake, live := d.cache.changes()
		p, err := d.getPod(ctx, name)
		switch {
		case err != nil && ctx.Err() != nil:
			return fmt.Errorf("kubepod: pod %s is still stopping (%s); is its node reachable?: %w", name, last, ctx.Err())
		case isNotFound(err):
			return nil
		case err != nil:
			last = err.Error()
		case p.Metadata.UID != uid:
			return nil
		}
		if d.pause(ctx, wake, live, delay) != nil {
			return fmt.Errorf("kubepod: pod %s is still stopping (%s); is its node reachable?: %w", name, last, ctx.Err())
		}
	}
}

// undo deletes the pod of a create or start that failed and waits, up to
// undoTimeout, until it is gone; with forgetSpec it also forgets its spec.
// So a failed create leaves nothing behind when it returns, and a retry of
// the same sandbox ID is not refused as "old pod still stopping". A pod
// that outlives the wait (its node cannot be reached) is listed, and
// reconcile's orphan sweep finishes it. It runs on a context of its own:
// the caller's may be the one that ran out.
func (d *Driver) undo(ctx context.Context, name, uid string, forgetSpec bool) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.undoWait)
	defer cancel()
	err := d.client.DeletePod(ctx, d.cfg.Namespace, name, uid, destroyGrace)
	if err == nil {
		err = d.waitGone(ctx, name, uid, d.undoWait)
	} else if isNotFound(err) || isConflict(err) {
		err = nil
	}
	if err != nil {
		d.logger.Warn("kubepod: the pod of a failed start is not gone yet; the worker's list still shows it",
			"pod", name, "error", err)
	}
	if forgetSpec {
		d.forget(name)
	}
}

// undoUnanswered cleans up after a pod create that got no answer: the call
// ended (the caller's context, a dropped connection) after the API server
// may have made the pod. A pod of that name for this sandbox that this
// worker made can only be that one: there was no kept spec before the
// create, and Start's spec is this sandbox's. So it is deleted, by its
// UID, and the caller is told the create failed. An answer from the API
// server (an *APIError) means nothing was made.
//
// The API server may store the pod only after this read found nothing.
// That pod is this worker's, with no spec and no store row: ListManaged
// lists it (it lists every pod with this worker's label), and reconcile's
// orphan sweep destroys every listed instance that has no row, so it goes
// at the next pass (TestLatePodIsListedAndDestroyed).
func (d *Driver) undoUnanswered(ctx context.Context, createErr error, name, sandboxID string) {
	var answered *APIError
	if errors.As(createErr, &answered) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.undoWait)
	defer cancel()
	p, err := d.client.GetPod(ctx, d.cfg.Namespace, name)
	switch {
	case isNotFound(err):
		return
	case err != nil:
		d.logger.Warn("kubepod: a pod create got no answer, and the pod cannot be read to clean it up; the worker's list still shows it",
			"pod", name, "error", err)
		return
	case !d.owns(p) || sandboxIDOf(p) != sandboxID:
		return
	}
	d.undo(ctx, name, p.Metadata.UID, false)
}

// forget drops a kept spec, logging a failure: the caller is already
// returning an error of its own.
func (d *Driver) forget(name string) {
	if err := d.specs.remove(name); err != nil {
		d.logger.Warn("kubepod: could not forget a pod spec", "pod", name, "error", err)
	}
}
