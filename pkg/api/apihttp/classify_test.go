package apihttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// Classify is the single table every surface shares. These are the cases the
// E2B and Runloop copies used to miss (defaulting them to 400) or map with a
// literal Retry-After; pinning them here keeps the surfaces from drifting
// again.
func TestClassify(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		status     int
		retryAfter int
		code       string
		kind       ErrKind
	}{
		{"not found", store.ErrNotFound, http.StatusNotFound, 0, "", ErrKindNotFound},
		{"admission denied", controlplane.ErrAdmissionDenied, http.StatusForbidden, 0, "", ErrKindOther},
		{"admission unavailable", controlplane.ErrAdmissionUnavailable, http.StatusServiceUnavailable, admissionRetryAfterSeconds, "", ErrKindOther},
		{"engine not registered", models.ErrContainerEngineNotRegistered, http.StatusServiceUnavailable, admissionRetryAfterSeconds, "", ErrKindOther},
		{"cluster finalization", service.ErrClusterFinalizationUnavailable, http.StatusServiceUnavailable, 5, "", ErrKindOther},
		{"wake circuit open", service.ErrWakeCircuitOpen, http.StatusServiceUnavailable, 60, "", ErrKindOther},
		{"manually stopped", service.ErrSandboxManuallyStopped, http.StatusConflict, 0, "", ErrKindOther},
		{"not running", service.ErrSandboxNotRunning, http.StatusConflict, 0, "", ErrKindSandboxNotRunning},
		{"not resumable", service.ErrSandboxNotResumable, http.StatusConflict, 0, "", ErrKindSandboxNotResumable},
		{"runtime not implemented", models.ErrRuntimeNotImplemented, http.StatusNotImplemented, 0, "", ErrKindOther},
		// The service's refusal matches both sentinels; it keeps its code.
		{"network policy unenforced", errors.Join(service.ErrNetworkPolicyUnenforced, models.ErrRuntimeNotImplemented), http.StatusNotImplemented, 0, models.ErrorCodeNetworkPolicyUnenforced, ErrKindOther},
		{"build timeout", service.ErrBuildTimeout, http.StatusGatewayTimeout, 0, "", ErrKindOther},
		{"build failed", service.ErrBuildFailed, http.StatusBadGateway, 0, "", ErrKindOther},
		{"builder unavailable", service.ErrBuilderUnavailable, http.StatusServiceUnavailable, 0, "", ErrKindOther},
		{"build not implemented", service.ErrBuildNotImplemented, http.StatusNotImplemented, 0, "", ErrKindOther},
		{"build invalid", service.ErrBuildInvalid, http.StatusBadRequest, 0, "", ErrKindOther},
		{"egress gateway", service.ErrEgressGatewayUnavailable, http.StatusServiceUnavailable, 5, models.ErrorCodeEgressGatewayUnavailable, ErrKindOther},
		{"egress inspect recreate", service.ErrEgressInspectRecreate, http.StatusConflict, 0, "", ErrKindOther},
		{"capacity", cluster.ErrCapacityExceeded, http.StatusServiceUnavailable, cluster.CapacityRetryAfterSeconds, "", ErrKindOther},
		{"backpressure", cluster.ErrCreateBackpressure, http.StatusTooManyRequests, cluster.CreateBackpressureRetryAfterSeconds, "", ErrKindOther},
		{"not leader", cluster.ErrNotLeader, http.StatusServiceUnavailable, cluster.LeaderChangeRetryAfterSeconds, "", ErrKindOther},
		{"no leader", fmt.Errorf("storage retirement: %w", cluster.ErrNoLeader), http.StatusServiceUnavailable, cluster.LeaderChangeRetryAfterSeconds, "", ErrKindOther},
		{"leader gone mid-forward", fmt.Errorf("%w: leader-forward apply: dial tcp 10.42.1.198:7002: connect: connection refused", cluster.ErrNotLeader), http.StatusServiceUnavailable, cluster.LeaderChangeRetryAfterSeconds, "", ErrKindOther},
		{"snapshot name conflict", store.ErrSnapshotNameConflict, http.StatusConflict, 0, "", ErrKindSnapshotNameConflict},
		{"sandbox exists", models.ErrSandboxExists, http.StatusConflict, 0, "", ErrKindSandboxExists},
		{"token request invalid", service.ErrAPITokenInvalid, http.StatusBadRequest, 0, "", ErrKindOther},
		{"token name taken", service.ErrAPITokenNameTaken, http.StatusConflict, 0, "", ErrKindOther},
		{"token ops not on every server", service.ErrAPITokenClusterVersion, http.StatusConflict, 0, "", ErrKindOther},
		{"token store unavailable", service.ErrAPITokensUnavailable, http.StatusServiceUnavailable, 5, "", ErrKindOther},
		{"key revoked", secrets.ErrKeyRevoked, http.StatusServiceUnavailable, 0, models.ErrorCodeKeyRevoked, ErrKindOther},
		{"key version retired", secrets.ErrKeyVersionRetired, http.StatusServiceUnavailable, 0, models.ErrorCodeKeyVersionRetired, ErrKindOther},
		{"key store denied", secrets.ErrProviderDenied, http.StatusServiceUnavailable, 0, models.ErrorCodeKeyStoreDenied, ErrKindOther},
		{"key store throttled", secrets.ErrProviderThrottled, http.StatusServiceUnavailable, keyStoreThrottledRetryAfterSeconds, models.ErrorCodeKeyStoreThrottled, ErrKindOther},
		{"key store unavailable", secrets.ErrProviderUnavailable, http.StatusServiceUnavailable, keyStoreUnavailableRetryAfterSeconds, models.ErrorCodeKeyStoreUnavailable, ErrKindOther},
		{"unclassified", errors.New("boom"), http.StatusBadRequest, 0, "", ErrKindUnclassified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Wrapped, as handlers surface them.
			c := Classify(fmt.Errorf("context: %w", tc.err))
			if c.Status != tc.status || c.RetryAfter != tc.retryAfter || c.Code != tc.code || c.Kind != tc.kind {
				t.Fatalf("Classify = status %d retry %d code %q kind %d; want %d %d %q %d",
					c.Status, c.RetryAfter, c.Code, c.Kind, tc.status, tc.retryAfter, tc.code, tc.kind)
			}
		})
	}
}

// A key-store error reaches the client as fixed text with its code: the key
// store's own error text (here a stand-in for a provider message) stays in
// the server log.
func TestWriteStoreAwareErrorKeyStoreClasses(t *testing.T) {
	for _, class := range []error{secrets.ErrKeyRevoked, secrets.ErrKeyVersionRetired, secrets.ErrProviderDenied, secrets.ErrProviderThrottled, secrets.ErrProviderUnavailable} {
		rec := httptest.NewRecorder()
		WriteStoreAwareError(nil, rec, fmt.Errorf("open: %w: provider said key arn:aws:kms:secret-detail", class))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%v: status %d", class, rec.Code)
		}
		var body models.ErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Code == "" || strings.Contains(rec.Body.String(), "secret-detail") {
			t.Fatalf("%v: body %s", class, rec.Body.String())
		}
		wantRetry := errors.Is(class, secrets.ErrProviderThrottled) || errors.Is(class, secrets.ErrProviderUnavailable)
		if got := rec.Header().Get("Retry-After") != ""; got != wantRetry {
			t.Fatalf("%v: Retry-After %q", class, rec.Header().Get("Retry-After"))
		}
	}
}

// A leader change is answered in fixed words: the forward's error names the
// old leader's internal address, which is not the caller's business.
func TestClassifyLeaderChangeHidesTheInternalAddress(t *testing.T) {
	err := fmt.Errorf("%w: leader-forward apply: Post \"https://10.42.1.198:7002/internal/apply\": dial tcp 10.42.1.198:7002: connect: connection refused", cluster.ErrNotLeader)
	c := Classify(err)
	if c.Status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", c.Status)
	}
	if strings.Contains(c.Message, "10.42.1.198") || strings.Contains(c.Message, "7002") {
		t.Fatalf("message leaks the internal address: %q", c.Message)
	}
}

// A network policy the node's firewall can't enforce reaches the client as
// 501 with its stable code and the service's message, which names the
// refused field and the flag that fixes the node.
func TestWriteStoreAwareErrorNetworkPolicyUnenforced(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteStoreAwareError(nil, rec, fmt.Errorf("network_block_all refused, see SB_ENABLE_NETWORK_RULES: %w",
		errors.Join(service.ErrNetworkPolicyUnenforced, models.ErrRuntimeNotImplemented)))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status %d, want 501", rec.Code)
	}
	var body models.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != models.ErrorCodeNetworkPolicyUnenforced || !strings.Contains(body.Error, "SB_ENABLE_NETWORK_RULES") {
		t.Fatalf("body %s", rec.Body.String())
	}
	if rec.Header().Get("Retry-After") != "" {
		t.Fatal("retrying cannot help: no Retry-After")
	}
}
