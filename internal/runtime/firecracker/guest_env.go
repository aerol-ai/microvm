package firecracker

// guest_env.go delivers a sandbox's create-time env to the guest agent.
//
// A container runtime hands the env to the container engine, and toolboxd
// inherits it. A Firecracker guest boots from a per-sandbox rootfs or a
// template snapshot that never saw the create request, so until this file
// existed the env was dropped: `printenv` in the guest came back empty, and
// env is how users pass secrets (UC-331).
//
// Delivery is one vsock op, set_env, sent after the boot handshake on every
// path that boots a guest for a create request (cold boot, template cold
// boot, snapshot load, warm-pool acquire). toolboxd keeps the env in memory
// (cmd/toolboxd/sandboxenv) and lays it under every child's per-request env.
//
// Why vsock and not the rootfs: baking the env into /etc/toolboxd.env would
// leave the secrets in plaintext in rootfs.ext4 on the host for the life of
// the sandbox (and in Stop's rootfs copy), and a template snapshot cannot
// carry per-sandbox values at all. The vsock channel is host-local: only a
// process that can open the VMM's Unix socket inside its run directory can
// reach the guest agent through it, and nothing in between touches a disk.
//
// Why it is not best-effort like post_resume: a guest that never got its env
// still answers exec, so a lost push is a silently wrong sandbox. A failed
// delivery fails the create, and the caller's rollback tears the VM down.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	// guestEnvOp is cmd/toolboxd's OpSetEnv. Payload {"env":{...}}; the
	// agent replaces its sandbox env with exactly that map.
	guestEnvOp = "set_env"
	// guestEnvTimeout bounds the whole delivery, retries included. The op
	// is an in-memory map swap in the guest; the budget is for a host
	// under load, not for the guest's work.
	guestEnvTimeout = 5 * time.Second
	// guestEnvAttempts caps how many times a push (set_env, and adopt in
	// guest_identity.go) is sent when the vsock connection fails before an
	// ack. Re-sending is safe because the agent applies both idempotently:
	// it replaces the env rather than merging, and keeps the first token,
	// so a push it applied but whose ack was lost converges on the next
	// attempt.
	guestEnvAttempts = 3
	// guestEnvRetryDelay spaces those attempts.
	guestEnvRetryDelay = 25 * time.Millisecond
)

// errGuestEnvInvalid is returned before any resource is allocated for an env
// the guest could not apply. It names neither the key nor the value.
var errGuestEnvInvalid = errors.New("env has an empty key, a key containing '=', or a NUL byte")

// validateGuestEnv mirrors cmd/toolboxd/sandboxenv.Validate so a bad env
// fails the create up front instead of after a VM has booted.
func validateGuestEnv(env map[string]string) error {
	for k, v := range env {
		if k == "" || strings.ContainsAny(k, "=\x00") || strings.ContainsRune(v, 0) {
			return errGuestEnvInvalid
		}
	}
	return nil
}

// guestRejectedError is the guest agent's explicit refusal of an op. It is
// final: re-sending the same op gets the same answer.
type guestRejectedError struct{ msg string }

func (e *guestRejectedError) Error() string { return "guest agent rejected the op: " + e.msg }

// deliverGuestEnv pushes env to the guest agent behind socketPath/guestCID.
// A nil or empty env sends nothing: a freshly booted guest already has an
// empty sandbox env, so skipping the op keeps env-less creates at their
// current latency and keeps them working on templates captured before the
// agent knew set_env.
//
// Nothing here logs or returns a key or a value; the log line carries only
// the key count.
func (d *Driver) deliverGuestEnv(ctx context.Context, socketPath string, guestCID uint32, sandboxID string, env map[string]string) error {
	if len(env) == 0 {
		return nil
	}
	start := time.Now()
	defer func() {
		createtiming.From(ctx).RecordStage("fc_env", time.Since(start))
	}()
	ctx, cancel := context.WithTimeout(ctx, guestEnvTimeout)
	defer cancel()
	payload := map[string]any{"env": env}
	attempt, err := d.sendVsockOpAckRetry(ctx, socketPath, guestCID, guestEnvOp, payload)
	if err == nil {
		d.logger.Info("firecracker: sandbox env delivered to guest",
			"sandbox_id", sandboxID, "keys", len(env), "attempts", attempt)
		return nil
	}
	var rejected *guestRejectedError
	if errors.As(err, &rejected) && strings.Contains(rejected.msg, "unknown op") {
		// The agent in this guest predates set_env: it came from a template
		// whose disk was built with an older toolboxd (the binary is copied
		// into the template's rootfs at build time, so every boot of that
		// template, snapshot or not, runs it). A snapshot rebuild reuses the
		// same disk and does not help; re-creating the template does.
		// Booting without the env is the bug this delivery closes, so
		// refuse, and say how to fix it.
		return fmt.Errorf("firecracker runtime: deliver sandbox env: the guest agent predates env delivery; delete and re-create the template so its disk gets the current toolboxd: %w",
			models.ErrRuntimeNotImplemented)
	}
	return fmt.Errorf("firecracker runtime: deliver sandbox env (%d keys, %d attempts): %w", len(env), attempt, err)
}

// sendVsockOpAck sends one op and waits for its ack, unlike sendVsockOp,
// which discards the ack. Returns *guestRejectedError when the agent answers
// {"error": ...} or anything but {"ok": true}.
func (d *Driver) sendVsockOpAck(ctx context.Context, socketPath string, guestCID uint32, op string, data any) error {
	conn, cancel, err := d.openVsockOp(ctx, socketPath, guestCID, op, data)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()
	// Stop at the newline: the agent keeps the connection open for further
	// ops and never sends EOF (see sendVsockOp).
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read ack: %w", err)
	}
	var resp struct {
		Ok    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return fmt.Errorf("decode ack: %w", err)
	}
	if !resp.Ok {
		if resp.Error == "" {
			resp.Error = "ok=false"
		}
		return &guestRejectedError{msg: resp.Error}
	}
	return nil
}
