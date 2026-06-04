package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
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
