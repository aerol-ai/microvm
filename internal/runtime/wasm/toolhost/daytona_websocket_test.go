package toolhost

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Test handleDaytonaSessionCommandInput error cases.
func TestDaytonaCommandInputErrors(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)

	// Create a Daytona session
	rec := httptest.NewRecorder()
	payload, _ := json.Marshal(map[string]string{"sessionId": "ds-input-err"})
	req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("session create failed: %d", rec.Code)
	}

	// Exec an async command so it runs and accepts input
	execPayload, _ := json.Marshal(map[string]interface{}{
		"command":  "sleep 10",
		"runAsync": true,
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-input-err/exec", bytes.NewReader(execPayload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("exec failed: %d", rec.Code)
	}

	var execResp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &execResp)
	cmdID := execResp["cmdId"].(string)

	// Wait briefly for the command to become active
	time.Sleep(100 * time.Millisecond)

	// Case 1: invalid JSON body in input
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-input-err/command/"+cmdID+"/input", strings.NewReader("invalid-json"))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad json body, got %d", rec.Code)
	}

	// Case 2: stdin write fails
	// Get the underlying session, close its stdin so Write will fail
	sess, err := mgr.GetByName("ds-input-err")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	_ = sess.CloseStdin()

	rec = httptest.NewRecorder()
	inputPayload, _ := json.Marshal(daytonaSessionInputRequest{Data: "hello"})
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-input-err/command/"+cmdID+"/input", bytes.NewReader(inputPayload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	// Stdin is closed, so sess.Write returns an error -> 500
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for closed stdin write, got %d", rec.Code)
	}
}

// Test handleDaytonaSessionDelete and lookupDaytonaSession error cases.
func TestDaytonaSessionDeleteAndLookupErrors(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)

	// Create a Daytona session
	rec := httptest.NewRecorder()
	payload, _ := json.Marshal(map[string]string{"sessionId": "ds-del-err"})
	req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	sess, err := mgr.GetByName("ds-del-err")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}

	// Deleting the session from mgr directly, so lookupDaytonaSession's GetByName returns ErrNotFound
	_ = mgr.Delete(sess.ID())

	// Call GET to trigger lookupDaytonaSession with ErrNotFound -> 404
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/process/session/ds-del-err", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	// Re-create session
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	sess, err = mgr.GetByName("ds-del-err")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}

	// Delete from mgr again so handleDaytonaSessionDelete fails with sessions.ErrNotFound
	_ = mgr.Delete(sess.ID())

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/process/session/ds-del-err", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on delete, got %d", rec.Code)
	}
}

// Test streamDaytonaSessionCommandLogs.
func TestDaytonaStreamCommandLogs(t *testing.T) {
	h, _ := newHostWithRealSessions(t)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	// 1. Create session
	rec := httptest.NewRecorder()
	payload, _ := json.Marshal(map[string]string{"sessionId": "ds-stream"})
	req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	// 2. Exec async command that produces output after a delay
	execPayload, _ := json.Marshal(map[string]interface{}{
		"command":  "sleep 0.5 && echo hello-stream-logs",
		"runAsync": true,
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-stream/exec", bytes.NewReader(execPayload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	var execResp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &execResp)
	cmdID := execResp["cmdId"].(string)

	// 3. Connect to WebSocket log stream endpoint: /process/session/{sid}/command/{cid}/logs?follow=true
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/process/session/ds-stream/command/" + cmdID + "/logs?follow=true"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial logs ws failed: %v", err)
	}
	defer conn.Close()

	// Read messages until connection is closed by the server (command finished)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hasOutput := false
	for {
		_, p, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if len(p) > 3 {
			// Skip the 3-byte prefix (stdout/stderr marker) and check output
			content := string(p[3:])
			if strings.Contains(content, "hello-stream-logs") {
				hasOutput = true
			}
		}
	}
	if !hasOutput {
		t.Fatal("expected to stream logs output, but didn't receive it")
	}
}

func TestDaytonaAdditionalErrorsAndEdgeCases(t *testing.T) {
	h, mgr := newHostWithRealSessions(t)

	// Create a Daytona session
	rec := httptest.NewRecorder()
	payload, _ := json.Marshal(map[string]string{"sessionId": "ds-edge"})
	req := httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	// 1. handleDaytonaSessionCommandGet session not found -> 404
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/process/session/nonexistent-session/command/some-cmd", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	// 2. handleDaytonaSessionCommandLogs session not found -> 404
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/process/session/nonexistent-session/command/some-cmd/logs", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	// 3. handleDaytonaSessionCommandLogs command not found with follow=true -> 404
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/process/session/ds-edge/command/nonexistent-cmd/logs?follow=true", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	// 4. streamDaytonaSessionCommandLogs upgrade fails (regular GET request)
	// Create an async command first
	execPayload, _ := json.Marshal(map[string]interface{}{
		"command":  "sleep 10",
		"runAsync": true,
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-edge/exec", bytes.NewReader(execPayload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)

	var execResp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &execResp)
	cmdID := execResp["cmdId"].(string)

	// Request logs with follow=true but as a regular GET request (not WS) -> returns 400 Bad Request
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/process/session/ds-edge/command/"+cmdID+"/logs?follow=true", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on non-websocket upgrade follow logs, got %d", rec.Code)
	}

	// 5. handleDaytonaSessionExec session not found -> 404
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/nonexistent-session/exec", bytes.NewReader(execPayload))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	// 6. handleDaytonaSessionExec command execution fails (sess.Write fails) -> 500
	// Get the underlying session, close its stdin
	sess, err := mgr.GetByName("ds-edge")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	_ = sess.CloseStdin()

	// Execute synchronous command -> should fail because stdin is closed
	execPayloadSync, _ := json.Marshal(map[string]interface{}{
		"command": "echo hello",
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/process/session/ds-edge/exec", bytes.NewReader(execPayloadSync))
	req.Header.Set("Content-Type", "application/json")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on closed stdin command exec, got %d", rec.Code)
	}
}
