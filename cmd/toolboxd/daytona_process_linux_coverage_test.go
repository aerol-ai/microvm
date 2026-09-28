//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

func TestLinuxDaytonaStderrAfterStart(t *testing.T) {
	srv := newDaytonaTestServer(t)
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"stderr2"}`)))
	cmd := `sleep 0.05; echo out-line; echo err-line >&2; true`
	execRec := httptest.NewRecorder()
	srv.handleDaytonaSessionExec(execRec, httptest.NewRequest(http.MethodPost, "/process/session/stderr2/exec", bytes.NewBufferString(`{"command":`+jsonString(cmd)+`}`)), "stderr2")
	if execRec.Code != http.StatusOK {
		t.Fatalf("exec = %d body=%s", execRec.Code, execRec.Body.String())
	}
}

func TestLinuxDaytonaDeleteNotFoundRaceHeavy(t *testing.T) {
	srv := newDaytonaTestServer(t)
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("heavy-%d", i)
		createRec := httptest.NewRecorder()
		srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"`+id+`"}`)))
		sess, _, ok := srv.lookupDaytonaSession(id)
		if !ok {
			continue
		}
		go func(sid string) {
			runtime.Gosched()
			_ = srv.sessions.Delete(sid)
		}(sess.ID())
		runtime.Gosched()
		delRec := httptest.NewRecorder()
		srv.handleDaytonaSessionDelete(delRec, httptest.NewRequest(http.MethodDelete, "/", nil), id)
	}
}

func TestLinuxBadExitCodeAndPartialMarker(t *testing.T) {
	srv := newDaytonaTestServer(t)
	createRec := httptest.NewRecorder()
	srv.handleDaytonaSessionCreate(createRec, httptest.NewRequest(http.MethodPost, "/process/session", bytes.NewBufferString(`{"sessionId":"partial"}`)))
	sess, _, ok := srv.lookupDaytonaSession("partial")
	if !ok {
		t.Fatal("missing session")
	}
	body, _ := json.Marshal(map[string]any{"command": "sleep 2", "runAsync": true})
	execRec := httptest.NewRecorder()
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = srv.sessions.Delete(sess.ID())
	}()
	srv.handleDaytonaSessionExec(execRec, httptest.NewRequest(http.MethodPost, "/process/session/partial/exec", bytes.NewReader(body)), "partial")
	time.Sleep(300 * time.Millisecond)
}
