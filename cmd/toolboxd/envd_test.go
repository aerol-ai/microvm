package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
)

func TestEnvdFilesystemRoundTrip(t *testing.T) {
	srv := newEnvdTestServer(t)
	handler := srv.routes()
	root := t.TempDir()
	targetPath := filepath.Join(root, "notes.txt")

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	fileWriter, err := writer.CreateFormFile("file", targetPath)
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := io.WriteString(fileWriter, "hello envd"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("multipart close error = %v", err)
	}

	writeReq := httptest.NewRequest(http.MethodPost, envdPrefix+"/files?path="+targetPath, &body)
	writeReq.Header.Set("Authorization", "Bearer toolbox-token")
	writeReq.Header.Set("Content-Type", writer.FormDataContentType())
	writeResp := httptest.NewRecorder()
	handler.ServeHTTP(writeResp, writeReq)
	if writeResp.Code != http.StatusOK {
		t.Fatalf("write status = %d, want %d; body=%s", writeResp.Code, http.StatusOK, writeResp.Body.String())
	}
	var writes []envdWriteInfo
	if err := json.NewDecoder(writeResp.Body).Decode(&writes); err != nil {
		t.Fatalf("decode write response error = %v", err)
	}
	if len(writes) != 1 || writes[0].Path != targetPath {
		t.Fatalf("unexpected write response: %+v", writes)
	}

	readReq := httptest.NewRequest(http.MethodGet, envdPrefix+"/files?path="+targetPath, nil)
	readReq.Header.Set("Authorization", "Bearer toolbox-token")
	readResp := httptest.NewRecorder()
	handler.ServeHTTP(readResp, readReq)
	if readResp.Code != http.StatusOK {
		t.Fatalf("read status = %d, want %d; body=%s", readResp.Code, http.StatusOK, readResp.Body.String())
	}
	if got := readResp.Body.String(); got != "hello envd" {
		t.Fatalf("read body = %q, want %q", got, "hello envd")
	}

	listBody, err := json.Marshal(envdListDirRequest{Path: root, Depth: 1})
	if err != nil {
		t.Fatalf("marshal list request error = %v", err)
	}
	listReq := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/ListDir", bytes.NewReader(listBody))
	listReq.Header.Set("Authorization", "Bearer toolbox-token")
	listResp := httptest.NewRecorder()
	handler.ServeHTTP(listResp, listReq)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d; body=%s", listResp.Code, http.StatusOK, listResp.Body.String())
	}
	var listed envdListDirResponse
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list response error = %v", err)
	}
	if len(listed.Entries) != 1 || listed.Entries[0].Path != targetPath {
		t.Fatalf("unexpected listed entries: %+v", listed.Entries)
	}
}

func TestListEnvdEntriesFollowsSymlinkRoot(t *testing.T) {
	realRoot := t.TempDir()
	linkRoot := filepath.Join(t.TempDir(), "tmp-link")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := os.WriteFile(filepath.Join(realRoot, "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write file error = %v", err)
	}

	entries, err := listEnvdEntries(linkRoot, 1)
	if err != nil {
		t.Fatalf("listEnvdEntries error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(entries))
	}
	if entries[0].Path != filepath.Join(linkRoot, "hello.txt") {
		t.Fatalf("entry path = %q, want %q", entries[0].Path, filepath.Join(linkRoot, "hello.txt"))
	}
}

func TestEnvdProcessStartStreamsConnectJSON(t *testing.T) {
	srv := newEnvdTestServer(t)
	handler := srv.routes()

	payload, err := json.Marshal(envdStartRequest{
		Process: envdProcessConfig{
			Cmd:  "/bin/sh",
			Args: []string{"-c", "printf hello"},
		},
	})
	if err != nil {
		t.Fatalf("marshal start request error = %v", err)
	}
	startReq := httptest.NewRequest(http.MethodPost, envdPrefix+"/process.Process/Start", bytes.NewReader(encodeConnectEnvelopeForTest(payload)))
	startReq.Header.Set("Authorization", "Bearer toolbox-token")
	startReq.Header.Set("Content-Type", "application/connect+json")
	startResp := httptest.NewRecorder()
	handler.ServeHTTP(startResp, startReq)
	if startResp.Code != http.StatusOK {
		t.Fatalf("start status = %d, want %d; body=%s", startResp.Code, http.StatusOK, startResp.Body.String())
	}

	envelopes := decodeConnectEnvelopesForTest(t, startResp.Body.Bytes())
	if len(envelopes) < 4 {
		t.Fatalf("envelope count = %d, want at least 4", len(envelopes))
	}
	var start envdProcessStreamResponse
	if err := json.Unmarshal(envelopes[0].Payload, &start); err != nil {
		t.Fatalf("decode start envelope error = %v", err)
	}
	if start.Event.Start == nil || start.Event.Start.PID <= 0 {
		t.Fatalf("unexpected start event: %+v", start)
	}

	stdout := ""
	ended := false
	for _, envelope := range envelopes[1:] {
		if envelope.Flags&connectFlagEndStream != 0 {
			continue
		}
		var event envdProcessStreamResponse
		if err := json.Unmarshal(envelope.Payload, &event); err != nil {
			t.Fatalf("decode event envelope error = %v", err)
		}
		if event.Event.Data != nil && event.Event.Data.Stdout != "" {
			decoded, err := base64.StdEncoding.DecodeString(event.Event.Data.Stdout)
			if err != nil {
				t.Fatalf("decode stdout error = %v", err)
			}
			stdout += string(decoded)
		}
		if event.Event.End != nil {
			ended = true
			if event.Event.End.ExitCode != 0 {
				t.Fatalf("end exit code = %d, want 0", event.Event.End.ExitCode)
			}
		}
	}
	if !strings.Contains(stdout, "hello") {
		t.Fatalf("stdout = %q, want to contain %q", stdout, "hello")
	}
	if !ended {
		t.Fatal("expected end event in process stream")
	}
	last := envelopes[len(envelopes)-1]
	if last.Flags&connectFlagEndStream == 0 {
		t.Fatalf("last envelope flags = %d, want end stream flag", last.Flags)
	}
}

func TestEnvdRejectsUnsupportedRequestedUser(t *testing.T) {
	srv := newEnvdTestServer(t)
	handler := srv.routes()

	req := httptest.NewRequest(http.MethodGet, envdPrefix+"/files?path=/tmp/missing", nil)
	req.Header.Set("Authorization", "Bearer toolbox-token")
	req.Header.Set("X-E2B-User-Authorization", basicUserHeaderForTest("aerolvm-unsupported-user"))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d; body=%s", resp.Code, http.StatusNotImplemented, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "aerolvm-unsupported-user") {
		t.Fatalf("body = %q, want unsupported user message", resp.Body.String())
	}
}

type decodedConnectEnvelope struct {
	Flags   byte
	Payload []byte
}

func newEnvdTestServer(t *testing.T) *server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sessionsMgr, err := sessions.New(logger, sessions.Config{
		SandboxID:    "sb-test",
		RecordingDir: filepath.Join(t.TempDir(), "recordings"),
		BufferBytes:  1 << 20,
	})
	if err != nil {
		t.Fatalf("sessions.New() error = %v", err)
	}
	t.Cleanup(sessionsMgr.Close)
	return &server{
		logger:       logger,
		sandboxID:    "sb-test",
		authToken:    "toolbox-token",
		allowedPorts: map[int]struct{}{},
		sessions:     sessionsMgr,
		daytona:      newDaytonaCompat(),
		envd:         newEnvdCompat(),
	}
}

func encodeConnectEnvelopeForTest(payload []byte) []byte {
	header := make([]byte, connectEnvelopeHeaderLen)
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	return append(header, payload...)
}

func TestReadConnectJSONRequestRejectsOversizedEnvelope(t *testing.T) {
	header := make([]byte, connectEnvelopeHeaderLen)
	binary.BigEndian.PutUint32(header[1:], uint32(connectJSONMaxPayloadLen+1))
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/processes/start", bytes.NewReader(header))

	var dst envdStartRequest
	err := readConnectJSONRequest(req, &dst)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readConnectJSONRequest() error = %v, want oversized envelope error", err)
	}
}

func basicUserHeaderForTest(username string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"))
}

func decodeConnectEnvelopesForTest(t *testing.T, body []byte) []decodedConnectEnvelope {
	t.Helper()
	items := []decodedConnectEnvelope{}
	for len(body) > 0 {
		if len(body) < connectEnvelopeHeaderLen {
			t.Fatalf("short connect envelope header: %d bytes", len(body))
		}
		flags := body[0]
		size := binary.BigEndian.Uint32(body[1:connectEnvelopeHeaderLen])
		body = body[connectEnvelopeHeaderLen:]
		if int(size) > len(body) {
			t.Fatalf("truncated connect envelope payload: size=%d remaining=%d", size, len(body))
		}
		payload := append([]byte(nil), body[:size]...)
		body = body[size:]
		items = append(items, decodedConnectEnvelope{Flags: flags, Payload: payload})
	}
	return items
}
