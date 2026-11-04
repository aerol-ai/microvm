package agenttools

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// CreateSpec is a get-or-create request. Zero fields take the server default.
type CreateSpec struct {
	// Name is the sandbox name. Empty generates "agent-<12 base32>" before
	// the first attempt, so every retry targets the same name.
	Name     string
	Image    string
	Runtime  string
	CPU      float64
	MemoryMB int
	Env      map[string]string
	Tags     map[string]string
	// Lifecycle sets idle stop/destroy timers. The MCP server passes its
	// defaults here (stop after 30m idle, destroy after 24h, eng review D7).
	Lifecycle    *models.Lifecycle
	BlockNetwork bool
	// AllowOut limits outbound traffic to these hosts, *.domain wildcards,
	// host:port pairs and CIDRs; everything else is refused
	// (plans/egress-domain-filtering.md P2-3).
	AllowOut []string
}

// HostList is a repeatable egress-destination flag (CreateSpec.AllowOut) that
// also takes a comma list, so the flags a printed MCP client config carries
// parse back the same.
type HostList []string

func (l *HostList) String() string { return strings.Join(*l, ",") }

// Set appends each non-empty comma-separated entry.
func (l *HostList) Set(s string) error {
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

// CreateResult reports which sandbox a get-or-create landed on.
type CreateResult struct {
	Sandbox *microvm.Sandbox
	// Created is true only when this call's POST created the sandbox. A
	// name that already existed, or a 409 that resolved to the same name,
	// reports false.
	Created bool
}

// GetOrCreate returns the caller's sandbox called spec.Name, creating it if
// it doesn't exist. It is safe to retry and to run concurrently (§5.4):
//
//	create(name?)
//	  name := given ?: "agent-" + rand12                     (D5: before any attempt)
//	  reject reserved names (owner: prefix, sb-<16 hex>)     (D9, D12)
//	  GET ?name=name ── hit ──► {created:false}  (warn if the image or runtime differs)
//	        │ miss
//	  POST {name, tags + aerolvm.created_by}                  (C6)
//	        ├─ 201 ──────────────► {created:true}
//	        ├─ 409 ─► GET ?name= ─► the caller's sandbox   (names are unique per owner, D4)
//	        └─ lost reply ─► SDK retries the same POST ─► 201, or 409 as above
//
// A plain create retried after a lost reply would make a duplicate; keying
// every create by name is what makes the retry land on the same row. A
// server that ignores ?name= fails with server_unsupported: without a
// trustworthy lookup the create can't be made idempotent.
func (t *Tools) GetOrCreate(ctx context.Context, spec CreateSpec) (CreateResult, error) {
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		generated, err := t.newName()
		if err != nil {
			return CreateResult{}, Classify(err)
		}
		name = generated
	}
	if err := models.ValidateSandboxName(name); err != nil {
		return CreateResult{}, &Error{Code: CodeInvalidArgument, Message: err.Error(), cause: err}
	}

	if existing, err := t.client.GetByName(ctx, name); err == nil {
		t.warnIfDifferent(existing, spec)
		return CreateResult{Sandbox: existing}, nil
	} else if !errors.Is(err, microvm.ErrNotFound) {
		return CreateResult{}, Classify(err)
	}

	created, err := t.client.Create(ctx, t.createOptions(name, spec))
	if err == nil {
		return CreateResult{Sandbox: created, Created: true}, nil
	}
	if !errors.Is(err, microvm.ErrConflict) {
		return CreateResult{}, Classify(err)
	}
	existing, lookupErr := t.client.GetByName(ctx, name)
	if lookupErr != nil {
		// A 409 whose name then can't be found is a conflict on something
		// other than the name (the ID, a reservation); report the create's
		// own error.
		return CreateResult{}, Classify(err)
	}
	return CreateResult{Sandbox: existing}, nil
}

func (t *Tools) createOptions(name string, spec CreateSpec) sdktypes.CreateSandboxOptions {
	tags := make(map[string]string, len(spec.Tags)+1)
	for k, v := range spec.Tags {
		tags[k] = v
	}
	if _, set := tags[CreatedByTag]; !set {
		tags[CreatedByTag] = string(t.source)
	}
	return sdktypes.CreateSandboxOptions{
		Name:            name,
		Image:           strings.TrimSpace(spec.Image),
		Runtime:         strings.TrimSpace(spec.Runtime),
		CPU:             spec.CPU,
		MemoryMB:        spec.MemoryMB,
		Env:             spec.Env,
		Tags:            tags,
		Lifecycle:       spec.Lifecycle,
		NetworkBlockAll: spec.BlockNetwork,
		NetworkAllowOut: spec.AllowOut,
	}
}

func (t *Tools) warnIfDifferent(existing *microvm.Sandbox, spec CreateSpec) {
	if existing == nil {
		return
	}
	if image := strings.TrimSpace(spec.Image); image != "" && image != existing.Image {
		t.warn(fmt.Sprintf("sandbox %q already exists with image %s (requested %s); using the existing sandbox", existing.Name, existing.Image, image))
	}
	if rt := strings.TrimSpace(spec.Runtime); rt != "" && existing.Runtime != "" && rt != existing.Runtime {
		t.warn(fmt.Sprintf("sandbox %q already exists with runtime %s (requested %s); using the existing sandbox", existing.Name, existing.Runtime, rt))
	}
}

// autoName returns "agent-" plus 12 random lowercase base32 characters: 60
// bits, so two agents racing to auto-name never collide in practice.
func autoName() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate sandbox name: %w", err)
	}
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
	return "agent-" + encoded[:12], nil
}

// DefaultMCPLifecycle is the cleanup policy for sandboxes the MCP server
// creates (eng review D7): stop after 30 minutes idle (files are kept), and
// destroy after 24 hours idle. The server-side timers are the cleanup
// guarantee; MCP hosts often SIGKILL their servers, so process exit is not.
func DefaultMCPLifecycle() *models.Lifecycle {
	return &models.Lifecycle{
		StopIfIdleFor:    30 * time.Minute,
		DestroyIfIdleFor: 24 * time.Hour,
	}
}
