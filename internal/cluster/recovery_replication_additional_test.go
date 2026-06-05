package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCommandCarriesRecoveryPayload(t *testing.T) {
	if commandCarriesRecoveryPayload(nil, "", 0, nil) {
		t.Errorf("expected false")
	}
	if !commandCarriesRecoveryPayload(&models.CreateSandboxRequest{}, "", 0, nil) {
		t.Errorf("expected true")
	}
}

func TestExternalizeCommandRecovery(t *testing.T) {
	put := func(ctx context.Context, blob RecoveryBlob) error {
		return nil
	}

	cmd := command{
		Op:        opPlace,
		Spec:      &models.CreateSandboxRequest{},
		SandboxID: "sb1",
	}

	out, err := externalizeCommandRecovery(context.Background(), cmd, put)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out.Spec != nil {
		t.Errorf("expected spec to be nil")
	}
	if out.RecoveryRef == "" {
		t.Errorf("expected recovery ref")
	}

	cmd2 := command{
		Op: opReserveBatch,
		Reservations: []reservationCommand{
			{SandboxID: "sb2", Spec: &models.CreateSandboxRequest{}},
		},
	}
	out2, err := externalizeCommandRecovery(context.Background(), cmd2, put)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out2.Reservations[0].Spec != nil {
		t.Errorf("expected spec to be nil")
	}
	if out2.Reservations[0].RecoveryRef == "" {
		t.Errorf("expected recovery ref")
	}
}

func TestDoRecoveryHTTPRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(RecoveryBlob{Ref: "test-ref"})
		} else if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer ts.Close()

	ctx := context.Background()

	// GET success
	var out RecoveryBlob
	err := doRecoveryHTTPRequest(ctx, ts.Client(), ts.URL, http.MethodGet, "test-token", nil, &out)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if out.Ref != "test-ref" {
		t.Errorf("unexpected blob ref: %s", out.Ref)
	}

	// PUT success
	err = doRecoveryHTTPRequest(ctx, ts.Client(), ts.URL, http.MethodPut, "test-token", []byte(`{}`), nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// GET auth fail
	err = doRecoveryHTTPRequest(ctx, ts.Client(), ts.URL, http.MethodGet, "bad-token", nil, &out)
	if err == nil {
		t.Errorf("expected error")
	}

	// GET body fail (bad url)
	err = doRecoveryHTTPRequest(ctx, ts.Client(), "http://127.0.0.1:0", http.MethodGet, "", nil, nil)
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestStoreRecoveryBlobAndMethods(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.recoveryStore = newPlacementRecoveryMemoryStore()
	c := &Cluster{
		fsm: fsm,
	}

	ctx := context.Background()
	blob, err := newRecoveryBlob("sb1", placementRecovery{})
	if err != nil {
		t.Fatalf("failed to create blob")
	}

	err = c.StoreRecoveryBlob(ctx, blob)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out, ok, err := c.RecoveryBlob(ctx, blob.Ref)
	if err != nil || !ok {
		t.Fatalf("failed to get blob")
	}
	if out.Ref != blob.Ref {
		t.Errorf("expected ref %s, got %s", blob.Ref, out.Ref)
	}

	// test without fsm
	c2 := &Cluster{}
	_, ok, _ = c2.RecoveryBlob(ctx, blob.Ref)
	if ok {
		t.Errorf("expected not ok")
	}
}
