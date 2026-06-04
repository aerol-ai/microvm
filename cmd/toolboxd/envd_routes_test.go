package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnvdFilesystemRoutes(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()
	root := t.TempDir()
	createdDir := filepath.Join(root, "subdir")
	movedDir := filepath.Join(root, "moved")
	createdFile := filepath.Join(createdDir, "data.txt")

	t.Run("health", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, envdPrefix+"/health", nil)
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("mkdir_stat_move_remove", func(t *testing.T) {
		mkdirBody := `{"path":"` + createdDir + `"}`
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/MakeDir", strings.NewReader(mkdirBody))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("mkdir status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}

		if err := os.WriteFile(createdFile, []byte("payload"), 0o644); err != nil {
			t.Fatalf("WriteFile(createdFile): %v", err)
		}

		statBody := `{"path":"` + createdFile + `"}`
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Stat", strings.NewReader(statBody))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("stat status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var statResp envdStatResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &statResp); err != nil {
			t.Fatalf("decode stat response: %v", err)
		}
		if statResp.Entry.Path != createdFile || statResp.Entry.Type != envdFileTypeFile {
			t.Fatalf("unexpected stat response: %+v", statResp)
		}

		moveBody := `{"source":"` + createdDir + `","destination":"` + movedDir + `"}`
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Move", strings.NewReader(moveBody))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("move status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}

		removeBody := `{"path":"` + movedDir + `"}`
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Remove", strings.NewReader(removeBody))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("remove status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		if _, err := os.Stat(movedDir); !os.IsNotExist(err) {
			t.Fatalf("expected removed dir, stat err=%v", err)
		}
	})

	t.Run("octet_stream_write_plain_and_gzip", func(t *testing.T) {
		plainPath := filepath.Join(root, "plain.txt")
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/files?path="+plainPath, strings.NewReader("plain-body"))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		req.Header.Set("Content-Type", "application/octet-stream")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("plain octet status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		if got, err := os.ReadFile(plainPath); err != nil || string(got) != "plain-body" {
			t.Fatalf("plain write mismatch got=%q err=%v", string(got), err)
		}

		gzPath := filepath.Join(root, "gzip.txt")
		var compressed bytes.Buffer
		zw := gzip.NewWriter(&compressed)
		_, _ = zw.Write([]byte("gzip-body"))
		_ = zw.Close()

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/files?path="+gzPath, bytes.NewReader(compressed.Bytes()))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Encoding", "gzip")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("gzip octet status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		if got, err := os.ReadFile(gzPath); err != nil || string(got) != "gzip-body" {
			t.Fatalf("gzip write mismatch got=%q err=%v", string(got), err)
		}
	})

	t.Run("filesystem_error_mapping", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Stat", strings.NewReader(`{"path":"/definitely/missing/file"}`))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("stat missing status = %d, want 404; body=%s", rr.Code, rr.Body.String())
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/Remove", strings.NewReader(`{"path":"/definitely/missing/file"}`))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("remove missing status = %d, want 404; body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestEnvdProcessRoutes(t *testing.T) {
	srv := newEnvdTestServer(t)
	h := srv.routes()

	startBody := map[string]any{
		"process": map[string]any{
			"cmd":  "/bin/sh",
			"args": []string{"-c", "read line; printf '%s' \"$line\""},
		},
		"tag":   "connectable",
		"stdin": true,
	}
	startJSON, _ := json.Marshal(startBody)
	startReq := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(encodeConnectEnvelopeForTest(startJSON)))
	startReq.Header.Set("Authorization", "Bearer toolbox-token")
	startReq.Header.Set("Content-Type", "application/connect+json")
	startResp := httptest.NewRecorder()
	go h.ServeHTTP(startResp, startReq)

	waitForEnvdState(t, srv, "connectable")

	t.Run("process_list", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/List", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("list status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var list envdListResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
			t.Fatalf("decode list response: %v", err)
		}
		if len(list.Processes) == 0 {
			t.Fatalf("expected at least one process: %+v", list)
		}
	})

	t.Run("process_update_send_input_and_connect", func(t *testing.T) {
		updateBody := `{"process":{"tag":"connectable"}}`
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Update", strings.NewReader(updateBody))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("update status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}

		inputBody := map[string]any{
			"process": map[string]any{"tag": "connectable"},
			"input":   map[string]any{"stdin": base64.StdEncoding.EncodeToString([]byte("hello-from-input\n"))},
		}
		inputJSON, _ := json.Marshal(inputBody)
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendInput", bytes.NewReader(inputJSON))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("send input status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}

		connectReqBody, _ := json.Marshal(map[string]any{"process": map[string]any{"tag": "connectable"}})
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Connect", bytes.NewReader(encodeConnectEnvelopeForTest(connectReqBody)))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		req.Header.Set("Content-Type", "application/connect+json")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("connect status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		envelopes := decodeConnectEnvelopesForTest(t, rr.Body.Bytes())
		if len(envelopes) < 2 {
			t.Fatalf("connect envelopes len = %d, want >=2", len(envelopes))
		}
	})

	t.Run("process_signal_close_stdin_and_errors", func(t *testing.T) {
		runningTag := "signalable"
		startNoStdin := map[string]any{
			"process": map[string]any{"cmd": "/bin/sh", "args": []string{"-c", "sleep 30"}},
			"tag":     runningTag,
		}
		startNoStdinJSON, _ := json.Marshal(startNoStdin)
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(encodeConnectEnvelopeForTest(startNoStdinJSON)))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		req.Header.Set("Content-Type", "application/connect+json")
		go h.ServeHTTP(rr, req)
		waitForEnvdStateTag(t, srv, runningTag)

		badInput := map[string]any{
			"process": map[string]any{"tag": runningTag},
			"input":   map[string]any{"stdin": base64.StdEncoding.EncodeToString([]byte("x"))},
		}
		badInputJSON, _ := json.Marshal(badInput)
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendInput", bytes.NewReader(badInputJSON))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusFailedDependency {
			t.Fatalf("send input (stdin disabled) status = %d, want 424; body=%s", rr.Code, rr.Body.String())
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/CloseStdin", strings.NewReader(`{"process":{"tag":"`+runningTag+`"}}`))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("close stdin status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendSignal", strings.NewReader(`{"process":{"tag":"`+runningTag+`"},"signal":"TERM"}`))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("send signal status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/SendSignal", strings.NewReader(`{"process":{"tag":"`+runningTag+`"},"signal":"BOGUS"}`))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("unsupported signal status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("process_not_found_and_bad_connect_envelope", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Connect", bytes.NewReader(encodeConnectEnvelopeForTest([]byte(`{"process":{"tag":"missing"}}`))))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		req.Header.Set("Content-Type", "application/connect+json")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("connect missing status = %d, want 404; body=%s", rr.Code, rr.Body.String())
		}

		header := make([]byte, connectEnvelopeHeaderLen)
		header[0] = connectFlagCompressed
		binary.BigEndian.PutUint32(header[1:], 2)
		payload := append(header, []byte("{}")...)
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Connect", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer toolbox-token")
		req.Header.Set("Content-Type", "application/connect+json")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("compressed envelope status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
	})
}

func waitForEnvdState(t *testing.T, srv *server, tag string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := srv.envd.lookup(envdProcessSelector{Tag: tag}); ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for envd state for tag %q", tag)
}

func waitForEnvdStateTag(t *testing.T, srv *server, tag string) {
	t.Helper()
	waitForEnvdState(t, srv, tag)
}
