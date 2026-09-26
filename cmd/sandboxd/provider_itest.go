//go:build itestwitness

// This file is compiled ONLY with `-tags itestwitness`, which nothing in
// release.yml or the Makefile passes. It exists because enterprise mode
// (SB_ENTERPRISE_MODE=true) forces SB_SECRET_AUDIT_EXTERNAL_WITNESS, and
// pkg/daemon then refuses to boot without a non-noop controlplane.Witness:
//
//	"tamper-evidence cannot be claimed from local JSONL alone"
//
// That gate is correct and must stay. But it also means the open-source binary
// can never run an enterprise scenario, so S4/S6 and use-case group I of
// plans/integration-test-security.md would be untestable. Rather than weaken
// the gate in the shipped binary, the harness builds with this tag and
// supplies the HTTP witness that the integration audit-receiver implements.
//
// It lives in package main next to the real entrypoint, not in a separate
// cmd/, so the wasm-worker / isolate-jail-shim / resident-host re-exec paths
// are shared rather than duplicated — a test daemon missing one of those
// would break the wasm and isolate scenarios in a way nothing else would
// catch.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/daemon"
)

func init() { providerFactory = itestProviderFactory }

// itestProviderFactory wires ONLY the Witness. Provider.WithDefaults() fills
// every other capability with its noop, so the harness daemon stays identical
// to the shipped one in all other respects — the point is to unblock the
// witness gate, not to become a different daemon.
func itestProviderFactory(context.Context, daemon.FleetConfig) (controlplane.Provider, error) {
	base := strings.TrimSpace(os.Getenv("AEROL_ITEST_WITNESS_URL"))
	if base == "" {
		// No witness configured: behave exactly like the shipped binary, so one
		// artifact serves both the enterprise and non-enterprise scenarios.
		return controlplane.Noop(), nil
	}
	return controlplane.Provider{
		Witness: &httpWitness{
			base:   strings.TrimSuffix(base, "/"),
			token:  strings.TrimSpace(os.Getenv("AEROL_ITEST_WITNESS_TOKEN")),
			client: &http.Client{Timeout: 10 * time.Second},
		},
	}, nil
}

// httpWitness speaks the integration audit-receiver's witness surface.
type httpWitness struct {
	base   string
	token  string
	client *http.Client
}

func (w *httpWitness) auth(req *http.Request) {
	if w.token != "" {
		req.Header.Set("Authorization", "Bearer "+w.token)
	}
}

func (w *httpWitness) WitnessHeads(ctx context.Context, heads []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	body, err := json.Marshal(heads)
	if err != nil {
		return controlplane.WitnessReceipt{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.base+"/witness", bytes.NewReader(body))
	if err != nil {
		return controlplane.WitnessReceipt{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	w.auth(req)
	resp, err := w.client.Do(req)
	if err != nil {
		return controlplane.WitnessReceipt{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Returned, never swallowed: a witness that silently "succeeded" would
		// let a scenario claim tamper-evidence it never had, which is the one
		// lie this whole mechanism exists to prevent.
		return controlplane.WitnessReceipt{}, fmt.Errorf("witness status %d", resp.StatusCode)
	}
	var rcpt controlplane.WitnessReceipt
	if err := json.NewDecoder(resp.Body).Decode(&rcpt); err != nil {
		return controlplane.WitnessReceipt{}, err
	}
	return rcpt, nil
}

func (w *httpWitness) LastWitnessedHead(ctx context.Context, nodeID string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.base+"/witness/"+nodeID, nil)
	if err != nil {
		return "", false, err
	}
	w.auth(req)
	resp, err := w.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	// 404 is "never recorded for this node", which the interface requires be
	// distinguishable from a transport error.
	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false, fmt.Errorf("witness status %d", resp.StatusCode)
	}
	var head controlplane.AuditHead
	if err := json.NewDecoder(resp.Body).Decode(&head); err != nil {
		return "", false, err
	}
	return head.HeadHex, true, nil
}
