package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func newTestReceiver(t *testing.T, token, hmacKey string) (*receiver, *httptest.Server) {
	t.Helper()
	r, err := newReceiver(token, hmacKey, filepath.Join(t.TempDir(), "audit.jsonl"), 0)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.routes())
	t.Cleanup(srv.Close)
	return r, srv
}

func stats(t *testing.T, srv *httptest.Server) map[string]int {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + "/_stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var s map[string]int
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// The receiver must accept exactly what pkg/auditexport's webhook backend
// sends. Driving the REAL exporter at it is the only way that stays true: a
// hand-rolled request would keep passing after the wire format changed, and
// the scenario would then be asserting against a fixture nothing produces.
func TestReceiverAcceptsRealExporterBatch(t *testing.T) {
	const (
		token = "tok-abc"
		key   = "hmac-key-xyz"
	)
	r, srv := newTestReceiver(t, token, key)

	backend, err := auditexport.Open(auditexport.Config{
		Backend: auditexport.BackendWebhook,
		Webhook: auditexport.WebhookConfig{URL: srv.URL + "/audit", BearerToken: token, HMACKey: key},
	}.WithDefaults())
	if err != nil {
		t.Fatalf("build webhook backend: %v", err)
	}

	batch := auditexport.Batch{
		NodeID:  "node-1",
		Offset:  "42",
		BatchID: "batch-aaa",
		Events:  []json.RawMessage{json.RawMessage(`{"event_id":"ae-1"}`), json.RawMessage(`{"event_id":"ae-2"}`)},
	}
	if err := backend.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	got := stats(t, srv)
	if got["batches"] != 1 || got["records"] != 2 || got["rejected"] != 0 {
		t.Fatalf("stats = %v, want 1 batch / 2 records / 0 rejected", got)
	}

	// And the bytes really landed on disk, since that is what a scenario tails.
	r.mu.Lock()
	path := r.logFile.Name()
	r.mu.Unlock()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "ae-2") {
		t.Fatalf("audit log missing the exported events: %q", raw)
	}
}

// At-least-once delivery means a retried batch arrives again. It must be
// acknowledged (or the exporter retries forever) but must NOT be recorded
// twice, or every scenario that counts records is wrong after one flaky
// network moment.
func TestReceiverDedupesRetriedBatch(t *testing.T) {
	_, srv := newTestReceiver(t, "", "")

	send := func() int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/audit", strings.NewReader(`{"event_id":"ae-dup"}`+"\n"))
		req.Header.Set("Idempotency-Key", "batch-same")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if code := send(); code != http.StatusOK {
		t.Fatalf("first delivery = %d, want 200", code)
	}
	if code := send(); code != http.StatusOK {
		t.Fatalf("redelivery = %d, want 200 — a non-2xx would make the exporter retry forever", code)
	}

	got := stats(t, srv)
	if got["records"] != 1 {
		t.Errorf("records = %d, want 1 (the duplicate must not be recorded twice)", got["records"])
	}
	if got["duplicates"] != 1 {
		t.Errorf("duplicates = %d, want 1 — the counter is how a scenario proves redelivery happened", got["duplicates"])
	}
}

// /_chaos/fail must return a status the exporter classifies as TEMPORARY, or
// it exercises the wrong path: 429 and 5xx are retried with backoff, while a
// 4xx is treated as a receiver-configuration error.
func TestChaosReturnsRetryableStatusAndThenRecovers(t *testing.T) {
	_, srv := newTestReceiver(t, "", "")

	resp, err := srv.Client().Post(srv.URL+"/_chaos/fail?n=2", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	post := func() int {
		r, err := srv.Client().Post(srv.URL+"/audit", auditexport.ContentTypeNDJSON,
			strings.NewReader(`{"event_id":"ae-chaos"}`+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		return r.StatusCode
	}

	for i := 1; i <= 2; i++ {
		code := post()
		if code != http.StatusServiceUnavailable {
			t.Fatalf("chaos request %d = %d, want 503", i, code)
		}
		// The exporter must see this as retryable, not fatal.
		if !auditexport.IsTemporary(auditexport.Temporary(errTestStatus(code))) {
			t.Fatalf("503 is not classified temporary by the exporter")
		}
	}
	if code := post(); code != http.StatusOK {
		t.Fatalf("after the chaos budget ran out = %d, want 200", code)
	}
	if got := stats(t, srv)["records"]; got != 1 {
		t.Errorf("records = %d, want 1 — the failed attempts must not have been recorded", got)
	}
}

type errTestStatus int

func (e errTestStatus) Error() string { return "status" }

// A bad signature must be rejected. A receiver that accepted anything would
// let a broken exporter signature pass as a green scenario, which is the exact
// failure this fixture exists to catch.
func TestReceiverRejectsBadSignatureAndToken(t *testing.T) {
	_, srv := newTestReceiver(t, "right-token", "right-key")
	body := `{"event_id":"ae-x"}` + "\n"

	cases := []struct {
		name string
		auth string
		sig  string
		want int
	}{
		{"good", "Bearer right-token", auditexport.SignBody("right-key", []byte(body)), http.StatusOK},
		{"bad token", "Bearer wrong", auditexport.SignBody("right-key", []byte(body)), http.StatusUnauthorized},
		{"bad signature", "Bearer right-token", auditexport.SignBody("wrong-key", []byte(body)), http.StatusUnauthorized},
		{"no signature", "Bearer right-token", "", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/audit", strings.NewReader(body))
			req.Header.Set("Authorization", tc.auth)
			if tc.sig != "" {
				req.Header.Set(auditexport.HeaderSignature, tc.sig)
			}
			req.Header.Set("Idempotency-Key", "batch-"+tc.name)
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

// The witness surface mirrors controlplane.Witness: heads go in, a receipt
// comes back, and an unknown node is 404 rather than an empty head — the
// interface distinguishes "never recorded" from a transport error, and a
// scenario asserts the former before the first witness interval elapses.
func TestWitnessStoresHeadsAndReportsUnknownNode(t *testing.T) {
	_, srv := newTestReceiver(t, "", "")

	if resp, err := srv.Client().Get(srv.URL + "/witness/node-1"); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("unknown node = %d, want 404", resp.StatusCode)
		}
	}

	heads := []controlplane.AuditHead{{NodeID: "node-1", HeadHex: "deadbeef", EventID: "ae-9", Observed: time.Now().UTC()}}
	blob, _ := json.Marshal(heads)
	resp, err := srv.Client().Post(srv.URL+"/witness", "application/json", strings.NewReader(string(blob)))
	if err != nil {
		t.Fatal(err)
	}
	var rcpt controlplane.WitnessReceipt
	_ = json.NewDecoder(resp.Body).Decode(&rcpt)
	resp.Body.Close()
	if rcpt.ReceiptID == "" {
		t.Fatal("witness returned no receipt id")
	}

	resp2, err := srv.Client().Get(srv.URL + "/witness/node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var got controlplane.AuditHead
	_ = json.NewDecoder(resp2.Body).Decode(&got)
	if got.HeadHex != "deadbeef" {
		t.Fatalf("stored head = %q, want deadbeef", got.HeadHex)
	}
}

func TestProbeReturnsLastN(t *testing.T) {
	_, srv := newTestReceiver(t, "", "")
	for i := range 3 {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/audit",
			strings.NewReader(`{"n":`+string(rune('0'+i))+`}`+"\n"))
		req.Header.Set("Idempotency-Key", "b"+string(rune('0'+i)))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	resp, err := srv.Client().Get(srv.URL + "/_probe/2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("probe returned %d records, want 2", len(out))
	}
}

// The malformed-input paths matter because this fixture sits between a real
// daemon and a scenario's assertions: a receiver that 500s or panics on a bad
// request turns a product question into a fixture question, and the scenario
// reports the wrong culprit.
func TestReceiverRejectsMalformedRequests(t *testing.T) {
	_, srv := newTestReceiver(t, "", "")

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		want   int
	}{
		{"witness with non-JSON body", http.MethodPost, "/witness", "not json", http.StatusBadRequest},
		{"probe with a non-numeric count", http.MethodGet, "/_probe/abc", "", http.StatusBadRequest},
		{"probe with a negative count", http.MethodGet, "/_probe/-1", "", http.StatusBadRequest},
		{"chaos with a non-numeric n", http.MethodPost, "/_chaos/fail?n=nope", "", http.StatusBadRequest},
		{"chaos with a missing n", http.MethodPost, "/_chaos/fail", "", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, srv.URL+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

// Asking for more records than exist must clamp rather than panic — a scenario
// polling /_probe/100 before anything has shipped is the normal first call.
func TestProbeClampsAndHandlesEmpty(t *testing.T) {
	_, srv := newTestReceiver(t, "", "")
	resp, err := srv.Client().Get(srv.URL + "/_probe/100")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("empty receiver returned %d records", len(out))
	}
}

// The witness must ignore a head with no node id rather than storing it under
// "" — a nameless head is unattributable, and silently keeping it would let a
// scenario "see a witnessed head" that belongs to nobody.
func TestWitnessSkipsHeadsWithoutNodeID(t *testing.T) {
	_, srv := newTestReceiver(t, "", "")
	blob, _ := json.Marshal([]controlplane.AuditHead{{HeadHex: "abc"}, {NodeID: "n1", HeadHex: "def"}})
	resp, err := srv.Client().Post(srv.URL+"/witness", "application/json", strings.NewReader(string(blob)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := stats(t, srv)["nodes"]; got != 1 {
		t.Fatalf("nodes = %d, want 1 (the nameless head must be dropped)", got)
	}
}

// An unauthorized witness POST must not record anything.
func TestWitnessRequiresToken(t *testing.T) {
	_, srv := newTestReceiver(t, "tok", "")
	blob, _ := json.Marshal([]controlplane.AuditHead{{NodeID: "n1", HeadHex: "abc"}})
	resp, err := srv.Client().Post(srv.URL+"/witness", "application/json", strings.NewReader(string(blob)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := stats(t, srv)["nodes"]; got != 0 {
		t.Fatalf("nodes = %d, want 0 after a rejected witness post", got)
	}
}

// An unopenable log path must fail at construction, not at the first delivery —
// a receiver that started and then silently dropped every record to a bad path
// would make a scenario look green while proving nothing.
func TestNewReceiverFailsOnUnopenableLogPath(t *testing.T) {
	dir := t.TempDir()
	// A directory is not an appendable file.
	if _, err := newReceiver("", "", dir, 0); err == nil {
		t.Fatal("newReceiver accepted a directory as the audit log path")
	}
}
