package service

import (
	"errors"
	"expvar"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/aerol-ai/microvm/internal/createpolicy"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ErrCreatePolicyInvalid refuses every create and resize while the create
// policy file (SB_CREATE_POLICY_FILE) is set but has not loaded since boot:
// its limits are unknown, so the only safe answer is no (503, code
// create_policy_invalid). A bad reload keeps the last good file instead and
// never lands here.
var ErrCreatePolicyInvalid = errors.New("create policy file is invalid; creates are refused until it is fixed")

// Create-policy metrics. Refusals are counted by rule, so an operator can
// see which line of the file is doing the refusing.
var (
	createPolicyDenied       = expvar.NewMap("aerolvm_create_policy_denied_total")
	activeCreatePolicyWatchr atomic.Pointer[createpolicy.Watcher]
)

func init() {
	expvar.Publish("aerolvm_create_policy_load_failures_total", expvar.Func(func() any {
		return activeCreatePolicyWatchr.Load().Failures()
	}))
}

// SetCreatePolicy wires the create-policy watcher (nil: no file, today's
// behavior). The daemon runs the watcher's poll loop.
func (s *Service) SetCreatePolicy(w *createpolicy.Watcher) {
	s.createPolicyWatcher = w
	if w != nil {
		activeCreatePolicyWatchr.Store(w)
	}
}

// createPolicy returns the policy in force (nil: none), or
// ErrCreatePolicyInvalid while a set file has never loaded. One atomic load:
// the file is read at boot and on reload, never here.
func (s *Service) createPolicy() (*createpolicy.Policy, error) {
	if s == nil || s.createPolicyWatcher == nil {
		return nil, nil
	}
	if err := s.createPolicyWatcher.BootError(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCreatePolicyInvalid, err)
	}
	return s.createPolicyWatcher.Current(), nil
}

// CheckCreatePolicy holds a create to the operator's create policy before
// a cluster places it. In a cluster the router picks a node first, and a
// create too big for every node was answered 503 "no placement target"
// before the owner's own check could name the rule it broke (UC-410 live,
// 2026-11-06). It judges a copy with the same defaults and runtime
// resolution createSandbox applies, so the router and the owner judge the
// same create; the owner still checks again. In memory only.
func (s *Service) CheckCreatePolicy(req models.CreateSandboxRequest) error {
	if s == nil {
		return nil
	}
	memoryOmitted := req.MemoryMB <= 0
	req = normalizeCreateRequest(req)
	runtime, err := models.ValidRuntime(req.Runtime)
	if err != nil {
		// Not this check's to answer: the owner reports an invalid runtime.
		return nil
	}
	if strings.TrimSpace(req.TemplateID) != "" {
		runtime = models.RuntimeFirecracker
	}
	if runtime == "" {
		runtime = s.cfg.Runtime
	}
	return s.applyCreatePolicy(&req, runtime, memoryOmitted, false)
}

// applyCreatePolicy holds a create to the operator's create policy, once the
// runtime and the image it will start are settled and before any work, so
// every way a sandbox is made (native creates, the Daytona, E2B and Runloop
// facades, starts from a snapshot, the CLI and MCP, which call the native
// API) gets the same answer. It also tells a container runtime to refuse a
// root image (require_non_root), which only the runtime can see once it
// has the image config.
//
// A failover replay is exempt, like the egress ceiling: its stored spec was
// accepted when the sandbox was made, and a policy tightened since must not
// strand a running sandbox on its way to another node.
func (s *Service) applyCreatePolicy(req *models.CreateSandboxRequest, chosenRuntime string, memoryOmitted, replay bool) error {
	p, err := s.createPolicy()
	if err != nil {
		return err
	}
	if p == nil || replay {
		return nil
	}
	memory := req.MemoryMB
	if chosenRuntime == models.RuntimeWasm && memoryOmitted {
		// WASM sizes a module that names no memory itself; the default the
		// create was normalized to is not what it will get.
		memory = 0
	}
	disk := req.DiskGB
	if chosenRuntime == models.RuntimeFirecracker && req.OverlaySizeGB > 0 {
		// The overlay is disk the VM gets on top of its root disk, the same
		// sum capacity admission charges.
		disk += req.OverlaySizeGB
	}
	imageRules := chosenRuntime != models.RuntimeWasm && chosenRuntime != models.RuntimeIsolate
	err = p.CheckCreate(createpolicy.Create{
		Image:      req.Image,
		ImageRules: imageRules,
		LocalOnly:  docker.IsLocalOnlyImageRef(req.Image) || req.ImageDistributionMode == models.ImageDistributionLocalOnly,
		ImageID:    docker.LooksLikeImageID(req.Image),
		Runtime:    chosenRuntime,
		CPU:        req.CPU,
		MemoryMB:   memory,
		DiskGB:     disk,
		GPU:        req.GPUs != nil,
	})
	if err != nil {
		noteCreatePolicyDenied(err)
		return err
	}
	// Root inside a container is user 0 on the server's kernel; a VM has its
	// own kernel, and WASM and isolate sandboxes have no OS user at all.
	if p.RequireNonRoot() && runsContainer(chosenRuntime) {
		req.RequireNonRootUser = true
	}
	return nil
}

// runsContainer reports the runtimes that start the image as a container,
// so the image's USER is the user its program runs as: Docker and gVisor on
// the server's own kernel (gVisor's image user is the container's). Kata is
// still reserved (a create refuses it), so the docs name only Docker and
// gVisor; it is listed so the rule holds the day it lands. Its VM has its
// own kernel, but the rule is about the image, and stricter is safer.
func runsContainer(runtime string) bool {
	switch runtime {
	case models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeKata:
		return true
	}
	return false
}

// checkResizePolicy holds a resize to the policy's size limits. Only the
// dimensions the resize changes are checked, so a sandbox made before a
// limit was tightened can still be resized down in another dimension.
func (s *Service) checkResizePolicy(req models.ResizeSandboxRequest) error {
	p, err := s.createPolicy()
	if err != nil {
		return err
	}
	if err := p.CheckSize(req.CPU, req.MemoryMB, req.DiskGB); err != nil {
		noteCreatePolicyDenied(err)
		return err
	}
	return nil
}

// noteCreatePolicyDenied counts a refusal under its rule.
func noteCreatePolicyDenied(err error) {
	var pe *models.CreatePolicyError
	if errors.As(err, &pe) {
		createPolicyDenied.Add(pe.Rule, 1)
	}
}

// noteNonRootRefusal counts the runtime's require_non_root refusal, which is
// raised below the service once the runtime has read the image; the service's
// own rules were counted when applyCreatePolicy refused them.
func noteNonRootRefusal(err *error) {
	var pe *models.CreatePolicyError
	if err != nil && errors.As(*err, &pe) && pe.Rule == models.CreatePolicyRuleRequireNonRoot {
		createPolicyDenied.Add(pe.Rule, 1)
	}
}
