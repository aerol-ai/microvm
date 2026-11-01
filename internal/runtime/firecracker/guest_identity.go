package firecracker

// guest_identity.go hands a guest agent its sandbox's identity: the sandbox
// ID and the per-sandbox toolbox token the host's proxy authenticates with.
//
// A cold boot bakes the token into the rootfs it builds for that one sandbox
// (/etc/toolboxd.env). Every other boot path starts from something built
// before the sandbox existed: a template's rootfs, a template snapshot, a
// warm-pool slot loaded from that snapshot. None of them may carry a token,
// or every clone would share it, so their agent boots token-less. Until this
// file existed it then served exec, files and sessions on port 2280 to any
// caller. toolboxd now fails closed without a token (cmd/toolboxd
// servingRequests), and the host adopts it with one vsock op, adopt, on every
// path that boots a guest for a sandbox, cold boot included so the rule has
// no exceptions.
//
// Why vsock: only a process that can open the VMM's Unix socket in its run
// directory reaches the agent through it, nothing in between touches a disk,
// and the template snapshot never sees the token. Why mandatory: a guest that
// was not adopted serves nothing, so a lost adopt is a broken sandbox; the
// create (or start) fails and its rollback tears the VM down.
//
// The guest keeps the first token it is given. Re-sending it converges, which
// makes the retries below safe; any other token is refused, so a guest can
// belong to one sandbox only.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	// guestAdoptOp is cmd/toolboxd's OpAdopt. Payload
	// {"sandbox_id":"...","token":"..."}.
	guestAdoptOp = "adopt"
	// guestAdoptTimeout bounds the whole delivery, retries included. The
	// guest's work is a field swap under a mutex.
	guestAdoptTimeout = 5 * time.Second
)

// errGuestTokenMissing refuses to boot a guest that could never be adopted.
// The service always mints a token; this catches a caller that did not.
var errGuestTokenMissing = errors.New("a toolbox token is required: a guest without one serves nothing")

// errGuestAgentPredatesAdopt is a guest whose toolboxd answers adopt with
// "unknown op": a binary from before identity delivery. Such an agent serves
// its API without a token, so the boot is refused rather than handed out.
var errGuestAgentPredatesAdopt = fmt.Errorf("the guest's toolboxd predates identity delivery and would serve its API without a token: %w",
	models.ErrRuntimeNotImplemented)

// Remedies for errGuestAgentPredatesAdopt, by boot path.
const (
	adoptRemedyCreate = "rebuild the template (delete and re-create it) so its disk gets the current toolboxd, and make sure SB_TOOLBOX_BINARY_PATH is the current release"
	adoptRemedyStart  = "this stopped sandbox's memory holds the old agent; destroy it and create a new one"
)

// adoptGuest sends the adopt op to the agent behind socketPath/guestCID and
// waits for its ack. The token is the sandbox's credential: no log line or
// error here carries it.
func (d *Driver) adoptGuest(ctx context.Context, socketPath string, guestCID uint32, sandboxID, token, remedy string) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("firecracker runtime: adopt guest: %w", errGuestTokenMissing)
	}
	start := time.Now()
	defer func() {
		createtiming.From(ctx).RecordStage("fc_adopt", time.Since(start))
	}()
	ctx, cancel := context.WithTimeout(ctx, guestAdoptTimeout)
	defer cancel()
	payload := map[string]string{"sandbox_id": sandboxID, "token": token}
	attempt, err := d.sendVsockOpAckRetry(ctx, socketPath, guestCID, guestAdoptOp, payload)
	if err == nil {
		d.logger.Info("firecracker: guest adopted", "sandbox_id", sandboxID, "attempts", attempt)
		return nil
	}
	var rejected *guestRejectedError
	if errors.As(err, &rejected) {
		if strings.Contains(rejected.msg, "unknown op") {
			return fmt.Errorf("firecracker runtime: adopt guest: %w; %s", errGuestAgentPredatesAdopt, remedy)
		}
		return fmt.Errorf("firecracker runtime: adopt guest: %w", err)
	}
	return fmt.Errorf("firecracker runtime: adopt guest (%d attempts): %w", attempt, err)
}

// sendVsockOpAckRetry sends op until the agent acks it, re-sending after a
// transport failure (a lost ack) up to guestEnvAttempts times. An explicit
// refusal is final and returned at once. Only ops the agent applies
// idempotently (set_env replaces, adopt keeps the first token) may use it.
func (d *Driver) sendVsockOpAckRetry(ctx context.Context, socketPath string, guestCID uint32, op string, payload any) (int, error) {
	var err error
	attempt := 0
	for attempt < guestEnvAttempts {
		attempt++
		err = d.sendVsockOpAck(ctx, socketPath, guestCID, op, payload)
		if err == nil {
			return attempt, nil
		}
		var rejected *guestRejectedError
		if errors.As(err, &rejected) || ctx.Err() != nil {
			return attempt, err
		}
		select {
		case <-ctx.Done():
		case <-time.After(guestEnvRetryDelay):
		}
	}
	return attempt, err
}
