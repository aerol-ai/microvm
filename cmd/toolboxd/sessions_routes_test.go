package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
)

func TestSessionsRoute_DispatchAndErrors(t *testing.T) {
	srv := newDaytonaTestServer(t)
	h := srv.routes()

	t.Run("create_list_get_log_delete", func(t *testing.T) {
		createReq := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(`{"name":"alpha","command":"printf hello"}`))
		createRec := httptest.NewRecorder()
		h.ServeHTTP(createRec, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d body=%s", createRec.Code, createRec.Body.String())
		}

		var created models.Session
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create response: %v", err)
		}
		if created.ID == "" {
			t.Fatalf("expected created session id")
		}

		listRec := httptest.NewRecorder()
		listReq := httptest.NewRequest(http.MethodGet, "/sessions", nil)
		h.ServeHTTP(listRec, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d body=%s", listRec.Code, listRec.Body.String())
		}

		getRec := httptest.NewRecorder()
		getReq := httptest.NewRequest(http.MethodGet, "/sessions/"+created.ID, nil)
		h.ServeHTTP(getRec, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d body=%s", getRec.Code, getRec.Body.String())
		}

		logRec := httptest.NewRecorder()
		logReq := httptest.NewRequest(http.MethodGet, "/sessions/"+created.ID+"/log", nil)
		h.ServeHTTP(logRec, logReq)
		if logRec.Code != http.StatusOK {
			t.Fatalf("log status = %d body=%s", logRec.Code, logRec.Body.String())
		}

		recRec := httptest.NewRecorder()
		recReq := httptest.NewRequest(http.MethodGet, "/sessions/"+created.ID+"/recording", nil)
		h.ServeHTTP(recRec, recReq)
		if recRec.Code != http.StatusNotFound {
			if recRec.Code != http.StatusOK {
				t.Fatalf("recording status = %d, want 200 or 404 body=%s", recRec.Code, recRec.Body.String())
			}
		}

		delRec := httptest.NewRecorder()
		delReq := httptest.NewRequest(http.MethodDelete, "/sessions/"+created.ID, nil)
		h.ServeHTTP(delRec, delReq)
		if delRec.Code != http.StatusNoContent {
			t.Fatalf("delete status = %d body=%s", delRec.Code, delRec.Body.String())
		}
	})

	t.Run("invalid_json_paths", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader("{bad"))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("create invalid json status = %d", rr.Code)
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/sessions/missing/signal", strings.NewReader("{bad"))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("signal missing status = %d", rr.Code)
		}

		createReq := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(`{"name":"beta","command":"sleep 1"}`))
		createRec := httptest.NewRecorder()
		h.ServeHTTP(createRec, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d body=%s", createRec.Code, createRec.Body.String())
		}
		var created models.Session
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create response: %v", err)
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/sessions/"+created.ID+"/signal", strings.NewReader("{bad"))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("signal invalid json status = %d", rr.Code)
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/sessions/"+created.ID+"/resize", strings.NewReader("{bad"))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("resize invalid json status = %d", rr.Code)
		}
	})

	t.Run("signal_and_resize_success", func(t *testing.T) {
		createReq := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(`{"name":"gamma","command":"sleep 5","pty":true,"cols":80,"rows":24}`))
		createRec := httptest.NewRecorder()
		h.ServeHTTP(createRec, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d body=%s", createRec.Code, createRec.Body.String())
		}
		var created models.Session
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create response: %v", err)
		}

		resizeRec := httptest.NewRecorder()
		resizeReq := httptest.NewRequest(http.MethodPost, "/sessions/"+created.ID+"/resize", strings.NewReader(`{"cols":100,"rows":40}`))
		h.ServeHTTP(resizeRec, resizeReq)
		if resizeRec.Code != http.StatusOK {
			t.Fatalf("resize status = %d body=%s", resizeRec.Code, resizeRec.Body.String())
		}

		signalRec := httptest.NewRecorder()
		signalReq := httptest.NewRequest(http.MethodPost, "/sessions/"+created.ID+"/signal", strings.NewReader(`{"signal":"TERM"}`))
		h.ServeHTTP(signalRec, signalReq)
		if signalRec.Code != http.StatusOK {
			t.Fatalf("signal status = %d body=%s", signalRec.Code, signalRec.Body.String())
		}
	})

	t.Run("method_and_not_found_paths", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPatch, "/sessions", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("/sessions method status = %d", rr.Code)
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/sessions/id/unknown-action", nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("unknown action status = %d", rr.Code)
		}
	})
}

func TestSessionsRoute_DisabledManagerBranches(t *testing.T) {
	srv := &server{}
	h := srv.routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list with disabled sessions status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{"name":"x","command":"echo hi"}`)))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("create with disabled sessions status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sessions/abc", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("get with disabled sessions status = %d", rr.Code)
	}
}

func TestSessionsRoute_DisabledManagerAdditionalBranches(t *testing.T) {
	srv := &server{}
	h := srv.routes()

	cases := []struct {
		name string
		req  *http.Request
		want int
	}{
		{name: "delete", req: httptest.NewRequest(http.MethodDelete, "/sessions/abc", nil), want: http.StatusNotFound},
		{name: "signal", req: httptest.NewRequest(http.MethodPost, "/sessions/abc/signal", strings.NewReader(`{"signal":"TERM"}`)), want: http.StatusNotFound},
		{name: "resize", req: httptest.NewRequest(http.MethodPost, "/sessions/abc/resize", strings.NewReader(`{"cols":1,"rows":1}`)), want: http.StatusNotFound},
		{name: "log", req: httptest.NewRequest(http.MethodGet, "/sessions/abc/log", nil), want: http.StatusNotFound},
		{name: "recording", req: httptest.NewRequest(http.MethodGet, "/sessions/abc/recording", nil), want: http.StatusNotFound},
		{name: "attach", req: httptest.NewRequest(http.MethodGet, "/sessions/abc/attach", nil), want: http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, tc.req)
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d", rr.Code, tc.want)
			}
		})
	}
}

type errWriter struct{}

func (errWriter) Header() http.Header         { return http.Header{} }
func (errWriter) WriteHeader(statusCode int)  {}
func (errWriter) Write(p []byte) (int, error) { return 0, errors.New("write failed") }

func TestCopyToResponseAndAttachmentErrorBranches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record.cast")
	if err := os.WriteFile(path, []byte("abcdef"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	if total, err := copyToResponse(errWriter{}, f); err == nil || total != 0 {
		t.Fatalf("copyToResponse error branch = (%d, %v), want write failure", total, err)
	}

	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	rec := httptest.NewRecorder()
	if total, err := copyToResponse(rec, f); !errors.Is(err, io.EOF) || total == 0 {
		t.Fatalf("copyToResponse success = (%d, %v), want bytes with EOF", total, err)
	}

	srv := newDaytonaTestServer(t)
	sess, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{Name: "attach-me", Command: "sleep 1"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = srv.sessions.Delete(sess.ID()) }()

	attachReq := httptest.NewRequest(http.MethodGet, "/sessions/"+sess.ID()+"/attach", nil)
	attachRec := httptest.NewRecorder()
	srv.handleSessionAttach(attachRec, attachReq, sess.ID())
}

func TestHandleSessionRecordingMissingFile(t *testing.T) {
	srv := newDaytonaTestServer(t)
	sess, err := srv.sessions.Create(context.Background(), models.CreateSessionRequest{Name: "rec", Command: "true"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	path := sess.RecordingPath()
	if path == "" {
		t.Fatal("expected recording path")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatalf("Remove: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sessions/"+sess.ID()+"/recording", nil)
	rec := httptest.NewRecorder()
	srv.handleSessionRecording(rec, req, sess.ID())
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("handleSessionRecording missing file status = %d, want 500", rec.Code)
	}
}

func TestSessionAttachStreamsAndExits(t *testing.T) {
	srv := newDaytonaTestServer(t)
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !srv.handleSessionsRoute(w, r) {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(httpSrv.Close)

	createReq := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(`{"name":"attach","command":"printf first; sleep 0.2; printf second"}`))
	createRec := httptest.NewRecorder()
	httpSrv.Config.Handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createRec.Code, createRec.Body.String())
	}
	var created models.Session
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	wsURL := strings.Replace(httpSrv.URL, "http://", "ws://", 1) + "/sessions/" + created.ID + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	var collected []byte
	seenExit := false
	for !seenExit {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read attach frame: %v", err)
		}
		switch msgType {
		case websocket.BinaryMessage:
			collected = append(collected, payload...)
		case websocket.TextMessage:
			var ctrl sessionAttachControlOut
			if err := json.Unmarshal(payload, &ctrl); err != nil {
				t.Fatalf("decode exit control: %v", err)
			}
			if ctrl.Type == "exit" {
				seenExit = true
			}
		}
	}
	payload := bytes.ReplaceAll(collected, []byte{streamFramePrefixStdoutSession}, nil)
	payload = bytes.ReplaceAll(payload, []byte{streamFramePrefixStderrSession}, nil)
	if !strings.Contains(string(payload), "first") || !strings.Contains(string(payload), "second") {
		t.Fatalf("attach payload = %q", payload)
	}
}
