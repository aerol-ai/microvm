package agenttoolstest

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestFakeSandboxLifecycleAndListFilters(t *testing.T) {
	s := New(t)

	if code, _ := do(t, s, http.MethodGet, "/v1/sandboxes", nil, ""); code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d", code)
	}
	if code, _ := do(t, s, http.MethodGet, "/health", nil, ""); code != http.StatusOK {
		t.Fatalf("health without a token = %d, want 200 like sandboxd", code)
	}
	if code, _ := do(t, s, http.MethodGet, "/v1/nope", nil, Token); code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d", code)
	}
	if code, body := do(t, s, http.MethodGet, "/v1/health", nil, Token); code != http.StatusOK || !strings.Contains(body, "fake") {
		t.Fatalf("health = %d %s", code, body)
	}

	// Bad intake, then the knobs that fail a create before a row exists.
	if code, _ := do(t, s, http.MethodPost, "/v1/sandboxes", strings.NewReader("{"), Token); code != http.StatusBadRequest {
		t.Fatalf("bad json status = %d", code)
	}
	if code, _ := doJSON(t, s, http.MethodPost, "/v1/sandboxes", models.CreateSandboxRequest{Name: "owner:reserved"}); code != http.StatusBadRequest {
		t.Fatalf("reserved name status = %d", code)
	}
	s.ConflictAlways = true
	if code, _ := doJSON(t, s, http.MethodPost, "/v1/sandboxes", models.CreateSandboxRequest{Name: "box", Image: "img"}); code != http.StatusConflict {
		t.Fatalf("conflict-always status = %d", code)
	}
	s.ConflictAlways = false
	s.FailCreates = 1
	if code, _ := doJSON(t, s, http.MethodPost, "/v1/sandboxes", models.CreateSandboxRequest{Name: "box"}); code != http.StatusInternalServerError {
		t.Fatalf("fail-creates status = %d", code)
	}

	s.CreateDelay = time.Millisecond
	s.DropAfterCreate = 1
	// The reply is hijacked and the socket closed, so the client either
	// errors or sees a truncated body. Either way the row was stored.
	dropReq, err := http.NewRequest(http.MethodPost, s.URL+"/v1/sandboxes", strings.NewReader(`{"name":"dropped","image":"img","lifecycle":{"stop_if_idle_for":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	dropReq.Header.Set("Authorization", "Bearer "+Token)
	dropReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(dropReq)
	if err == nil {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusCreated && len(raw) > 0 {
			t.Fatalf("dropped create returned a body: %s", raw)
		}
	}
	// The dropped reply is a hijack, so the client returning does not
	// happen-before the handler's read of CreateDelay. Take the same lock.
	s.Observe(func(sv *Server) { sv.CreateDelay = 0 })
	if s.Count() != 1 {
		t.Fatalf("dropped create still stored a sandbox, count = %d", s.Count())
	}
	s.Observe(func(sv *Server) {
		for id, sb := range sv.sandboxes {
			if sb.Name == "dropped" {
				delete(sv.sandboxes, id)
			}
		}
	})

	code, body := doJSON(t, s, http.MethodPost, "/v1/sandboxes", models.CreateSandboxRequest{
		Name: "box", Image: "img", Tags: map[string]string{"env": "test"}, CPU: 1, MemoryMB: 128,
	})
	if code != http.StatusCreated {
		t.Fatalf("create = %d %s", code, body)
	}
	var created models.CreateSandboxResponse
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	if created.Runtime != models.RuntimeDocker || created.ID == "" {
		t.Fatalf("created = %+v", created.Sandbox)
	}
	if code, _ := doJSON(t, s, http.MethodPost, "/v1/sandboxes", models.CreateSandboxRequest{Name: "box"}); code != http.StatusConflict {
		t.Fatalf("duplicate name status = %d", code)
	}

	preset := s.AddSandbox(models.Sandbox{ID: "preset", Name: "preset", Status: models.SandboxStatusStopped, Runtime: models.RuntimeWasm})
	if preset.ID != "preset" {
		t.Fatalf("preset id = %s", preset.ID)
	}
	if _, ok := s.Sandbox("missing"); ok {
		t.Fatal("missing sandbox reported present")
	}
	row, ok := s.Sandbox(created.ID)
	if !ok || row.Name != "box" {
		t.Fatalf("sandbox lookup = %+v %v", row, ok)
	}

	code, body = do(t, s, http.MethodGet, "/v1/sandboxes?name=box&tag.env=test", nil, Token)
	if code != http.StatusOK || !strings.Contains(body, created.ID) {
		t.Fatalf("filtered list = %d %s", code, body)
	}
	if code, body = do(t, s, http.MethodGet, "/v1/sandboxes?tag.env=other", nil, Token); code != http.StatusOK || strings.Contains(body, created.ID) {
		t.Fatalf("tag mismatch list = %d %s", code, body)
	}
	s.IgnoreNameFilter = true
	code, body = do(t, s, http.MethodGet, "/v1/sandboxes?name=nobody&limit=1&page_token=99", nil, Token)
	if code != http.StatusOK {
		t.Fatalf("ignore-name list = %d %s", code, body)
	}
	code, _ = do(t, s, http.MethodGet, "/v1/sandboxes?limit=1", nil, Token)
	if code != http.StatusOK {
		t.Fatalf("paged list status = %d", code)
	}
	s.IgnoreNameFilter = false

	if code, _ = do(t, s, http.MethodGet, "/v1/sandboxes/missing", nil, Token); code != http.StatusNotFound {
		t.Fatalf("missing get = %d", code)
	}
	if code, body = do(t, s, http.MethodGet, "/v1/sandboxes/"+created.ID, nil, Token); code != http.StatusOK || !strings.Contains(body, "box") {
		t.Fatalf("get = %d %s", code, body)
	}
	s.FailStart = true
	if code, _ = do(t, s, http.MethodPost, "/v1/sandboxes/"+created.ID+"/start", nil, Token); code != http.StatusInternalServerError {
		t.Fatalf("fail start = %d", code)
	}
	s.FailStart = false
	if code, _ = do(t, s, http.MethodPost, "/v1/sandboxes/"+created.ID+"/start", nil, Token); code != http.StatusOK {
		t.Fatalf("start = %d", code)
	}
	if code, _ = do(t, s, http.MethodPost, "/v1/sandboxes/"+created.ID+"/stop", nil, Token); code != http.StatusOK {
		t.Fatalf("stop = %d", code)
	}
	s.SetStatus(created.ID, models.SandboxStatusStarted)
	if code, body = do(t, s, http.MethodPost, "/v1/sandboxes/"+created.ID+"/ports/8080", nil, Token); code != http.StatusOK || !strings.Contains(body, "8080") {
		t.Fatalf("expose = %d %s", code, body)
	}
	if code, body = doJSON(t, s, http.MethodPost, "/v1/sandboxes/"+created.ID+"/snapshot", models.CreateSandboxSnapshotRequest{Name: "snap"}); code != http.StatusCreated || !strings.Contains(body, "snap") {
		t.Fatalf("snapshot = %d %s", code, body)
	}
	if code, _ = do(t, s, http.MethodPost, "/v1/sandboxes/"+created.ID+"/nope", nil, Token); code != http.StatusNotFound {
		t.Fatalf("unknown subroute = %d", code)
	}

	s.Remove(created.ID)
	if s.Count() == 0 {
		t.Fatal("preset sandbox should remain")
	}
	if code, _ = do(t, s, http.MethodDelete, "/v1/sandboxes/preset", nil, Token); code != http.StatusNoContent {
		t.Fatalf("delete = %d", code)
	}
	if s.Count() != 0 {
		t.Fatalf("count after delete = %d", s.Count())
	}
	s.Observe(func(sv *Server) {
		if sv.StartCalls == 0 || sv.DestroyCalls == 0 || len(sv.CreatedIDs) == 0 {
			t.Fatalf("observations start=%d destroy=%d created=%d", sv.StartCalls, sv.DestroyCalls, len(sv.CreatedIDs))
		}
	})
}

func TestFakeToolboxFilesAndExec(t *testing.T) {
	s := New(t)
	docker := s.AddSandbox(models.Sandbox{Name: "box", Runtime: models.RuntimeDocker})
	wasm := s.AddSandbox(models.Sandbox{Name: "w", Runtime: models.RuntimeWasm})
	iso := s.AddSandbox(models.Sandbox{Name: "iso", Runtime: models.RuntimeIsolate})

	if code, _ := do(t, s, http.MethodGet, "/v1/sandboxes/"+iso.ID+"/toolbox/files", nil, Token); code != http.StatusNotImplemented {
		t.Fatalf("isolate toolbox = %d", code)
	}
	base := "/v1/sandboxes/" + docker.ID + "/toolbox"
	if code, _ := do(t, s, http.MethodGet, base+"/files/download?path=/missing", nil, Token); code != http.StatusNotFound {
		t.Fatalf("missing download = %d", code)
	}
	if code, _ := do(t, s, http.MethodGet, base+"/nope", nil, Token); code != http.StatusNotFound {
		t.Fatalf("unknown toolbox = %d", code)
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if code, _ := do(t, s, http.MethodPost, base+"/files/upload", &buf, Token); code != http.StatusBadRequest {
		// content-type is unset, so the form is rejected
		t.Fatalf("upload without form = %d", code)
	}
	buf.Reset()
	w = multipart.NewWriter(&buf)
	pw, err := w.CreateFormField("other")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pw.Write([]byte("x"))
	_ = w.Close()
	req, err := http.NewRequest(http.MethodPost, s.URL+base+"/files/upload", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+Token)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("upload without path = %d", resp.StatusCode)
	}

	buf.Reset()
	w = multipart.NewWriter(&buf)
	pw, _ = w.CreateFormField("path")
	_, _ = pw.Write([]byte("/tmp/a.txt"))
	fw, _ := w.CreateFormFile("file", "a.txt")
	_, _ = fw.Write([]byte("alpha\nbeta"))
	_ = w.Close()
	req, _ = http.NewRequest(http.MethodPost, s.URL+base+"/files/upload", &buf)
	req.Header.Set("Authorization", "Bearer "+Token)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload = %d", resp.StatusCode)
	}
	got, ok := s.File(docker.ID, "/tmp/a.txt")
	if !ok || string(got) != "alpha\nbeta" {
		t.Fatalf("stored file = %q %v", got, ok)
	}
	if _, ok := s.File("missing", "/tmp/a.txt"); ok {
		t.Fatal("file on missing sandbox")
	}
	s.PutFile(docker.ID, "/tmp/dir/b.txt", []byte("only-b"))
	s.PutFile(wasm.ID, "/tmp/a.txt", []byte("wasm"))

	if code, body := do(t, s, http.MethodGet, base+"/files/download?path=/tmp/a.txt", nil, Token); code != http.StatusOK || body != "alpha\nbeta" {
		t.Fatalf("download = %d %q", code, body)
	}
	if code, body := do(t, s, http.MethodGet, base+"/files?path=/tmp", nil, Token); code != http.StatusOK || !strings.Contains(body, "a.txt") {
		t.Fatalf("list = %d %s", code, body)
	}
	if code, body := do(t, s, http.MethodGet, "/v1/sandboxes/"+wasm.ID+"/toolbox/files?path=/tmp", nil, Token); code != http.StatusOK || !strings.Contains(body, "a.txt") {
		t.Fatalf("wasm list = %d %s", code, body)
	}
	if code, _ := do(t, s, http.MethodGet, base+"/files/info?path=/missing", nil, Token); code != http.StatusNotFound {
		t.Fatalf("missing info = %d", code)
	}
	if code, body := do(t, s, http.MethodGet, base+"/files/info?path=/tmp/a.txt", nil, Token); code != http.StatusOK || !strings.Contains(body, "size") {
		t.Fatalf("info = %d %s", code, body)
	}
	if code, _ := do(t, s, http.MethodGet, "/v1/sandboxes/"+wasm.ID+"/toolbox/files/info?path=/tmp/a.txt", nil, Token); code != http.StatusNotFound {
		t.Fatalf("wasm info falls through = %d", code)
	}
	if code, body := do(t, s, http.MethodGet, base+"/files/search?pattern=*.txt", nil, Token); code != http.StatusOK || !strings.Contains(body, "a.txt") {
		t.Fatalf("search = %d %s", code, body)
	}
	if code, body := do(t, s, http.MethodGet, base+"/files/find?pattern=alpha", nil, Token); code != http.StatusOK || !strings.Contains(body, "alpha") {
		t.Fatalf("find = %d %s", code, body)
	}

	if code, _ := do(t, s, http.MethodPost, base+"/process/execute", strings.NewReader("{"), Token); code != http.StatusBadRequest {
		t.Fatalf("bad exec = %d", code)
	}
	s.BufferedPad = 3
	if code, body := doJSON(t, s, http.MethodPost, base+"/process/execute", models.ExecRequest{Command: "echo hi"}); code != http.StatusOK || !strings.Contains(body, "ppp") {
		t.Fatalf("buffered echo = %d %s", code, body)
	}
	s.BufferedPad = 0
	s.ExecFunc = func(cmd string, in io.Reader, out func(byte, []byte), killed <-chan struct{}) (int, string) {
		return -1, "killed"
	}
	if code, body := doJSON(t, s, http.MethodPost, base+"/process/execute", models.ExecRequest{Command: "sleep"}); code != http.StatusOK || !strings.Contains(body, "-1") {
		t.Fatalf("buffered signal = %d %s", code, body)
	}
	s.ExecFunc = nil

	if code, _ := do(t, s, http.MethodGet, "/v1/sandboxes/"+wasm.ID+"/toolbox/process/exec/stream", nil, Token); code != http.StatusNotImplemented {
		t.Fatalf("wasm stream = %d", code)
	}
	// A non-websocket GET fails the upgrade and returns without a status.
	if code, _ := do(t, s, http.MethodGet, base+"/process/exec/stream", nil, Token); code != http.StatusBadRequest && code != 0 {
		// gorilla writes 400 when the handshake is missing
		if code != http.StatusBadRequest {
			t.Fatalf("plain stream get = %d", code)
		}
	}

	stream(t, s, docker.ID, "echo hi", nil, nil)
	stream(t, s, docker.ID, "stderr oops", nil, nil)
	stream(t, s, docker.ID, "exit 2", nil, nil)
	stream(t, s, docker.ID, "cat", []wsMsg{{bin: []byte("piped")}}, []string{`{"type":"resize","cols":90,"rows":20}`, "close"})
	s.Observe(func(s *Server) {
		if len(s.Resizes) != 1 || s.Resizes[0] != "90x20" {
			t.Fatalf("exec stream resizes = %v", s.Resizes)
		}
	})
	stream(t, s, docker.ID, "yes 5000", nil, nil)
	stream(t, s, docker.ID, "other", nil, nil)
	stream(t, s, docker.ID, "sleep", nil, []string{`{"type":"signal","signal":"TERM"}`, `{"type":"signal","signal":"KILL"}`})
	stream(t, s, docker.ID, "signal terminated", nil, nil)
	stream(t, s, docker.ID, "echo x", nil, []string{"not-json"})

	// Dial and hang up before a start frame: the server returns on the read error.
	wsURL := "ws" + strings.TrimPrefix(s.URL, "http") + base + "/process/exec/stream"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + Token}})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	s.ExecFunc = func(cmd string, in io.Reader, out func(byte, []byte), killed <-chan struct{}) (int, string) {
		return 0, DropStream
	}
	conn, _, err = websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + Token}})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.WriteJSON(map[string]string{"command": "drop"})
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("dropped stream should close")
	}
	conn.Close()
}

func TestFakeSessions(t *testing.T) {
	s := New(t)
	sb := s.AddSandbox(models.Sandbox{Name: "box"})
	base := "/v1/sandboxes/" + sb.ID + "/sessions"

	if code, _ := do(t, s, http.MethodPost, base, strings.NewReader("{"), Token); code != http.StatusBadRequest {
		t.Fatalf("bad session = %d", code)
	}
	code, body := doJSON(t, s, http.MethodPost, base, models.CreateSessionRequest{Name: "dev", Command: "sleep 1"})
	if code != http.StatusCreated || !strings.Contains(body, "ses-") {
		t.Fatalf("create session = %d %s", code, body)
	}
	var session models.Session
	if err := json.Unmarshal([]byte(body), &session); err != nil {
		t.Fatal(err)
	}
	// A second create with the name starts another session, as toolboxd
	// does; the list shows both, oldest first.
	if code, body = doJSON(t, s, http.MethodPost, base, models.CreateSessionRequest{Name: "dev", PTY: true}); code != http.StatusCreated || strings.Contains(body, `"id":"`+session.ID+`"`) || !strings.Contains(body, `"pty":true`) || !strings.Contains(body, "bash") {
		t.Fatalf("second session = %d %s", code, body)
	}
	var list models.SessionList
	if code, body = do(t, s, http.MethodGet, base, nil, Token); code != http.StatusOK || json.Unmarshal([]byte(body), &list) != nil || len(list.Sessions) != 2 || list.Sessions[0].ID != session.ID {
		t.Fatalf("list sessions = %d %s", code, body)
	}
	if len(s.SessionCreates) != 2 || s.SessionCreates[1].Name != "dev" {
		t.Fatalf("SessionCreates = %+v", s.SessionCreates)
	}
	if code, _ = do(t, s, http.MethodGet, base+"/missing", nil, Token); code != http.StatusNotFound {
		t.Fatalf("missing session = %d", code)
	}
	if code, body = do(t, s, http.MethodGet, base+"/"+session.ID, nil, Token); code != http.StatusOK || !strings.Contains(body, "dev") {
		t.Fatalf("get session = %d %s", code, body)
	}
	if code, _ = do(t, s, http.MethodGet, base+"/missing/log", nil, Token); code != http.StatusNotFound {
		t.Fatalf("missing log = %d", code)
	}
	s.AppendSessionLog(sb.ID, session.ID, []byte("more\n"))
	if code, body = do(t, s, http.MethodGet, base+"/"+session.ID+"/log", nil, Token); code != http.StatusOK || !strings.Contains(body, "more") {
		t.Fatalf("log = %d %s", code, body)
	}
	if code, _ = do(t, s, http.MethodDelete, base+"/missing", nil, Token); code != http.StatusNotFound {
		t.Fatalf("delete missing = %d", code)
	}
	if code, _ = do(t, s, http.MethodGet, base+"/"+session.ID+"/nope", nil, Token); code != http.StatusNotFound {
		t.Fatalf("bad session route = %d", code)
	}

	wsURL := "ws" + strings.TrimPrefix(s.URL, "http") + "/v1/sandboxes/" + sb.ID + "/sessions/missing/attach"
	if _, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + Token}}); err == nil {
		t.Fatal("missing attach should fail")
	}
	wsURL = "ws" + strings.TrimPrefix(s.URL, "http") + base + "/" + session.ID + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + Token}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, msg, err := conn.ReadMessage(); err != nil || !bytes.Contains(msg, []byte("more")) {
		t.Fatalf("attach replay = %q %v", msg, err)
	}
	if _, msg, err := conn.ReadMessage(); err != nil || !bytes.Contains(msg, []byte("exit")) {
		t.Fatalf("attach exit = %q %v", msg, err)
	}

	if code, _ = do(t, s, http.MethodDelete, base+"/"+session.ID, nil, Token); code != http.StatusNoContent {
		t.Fatalf("delete session = %d", code)
	}

	code, body = doJSON(t, s, http.MethodPost, base, models.CreateSessionRequest{Name: "done", Command: "exit 3"})
	if code != http.StatusCreated || !strings.Contains(body, `"status":"exited"`) || !strings.Contains(body, `"exit_code":3`) {
		t.Fatalf("exited session = %d %s", code, body)
	}
}

func TestFakeAttachSignalAndHang(t *testing.T) {
	s := New(t)
	sb := s.AddSandbox(models.Sandbox{Name: "box"})
	s.AttachExitSignal = "TERM"
	code, body := doJSON(t, s, http.MethodPost, "/v1/sandboxes/"+sb.ID+"/sessions", models.CreateSessionRequest{Name: "job", Command: "sleep 1"})
	if code != http.StatusCreated {
		t.Fatalf("create = %d %s", code, body)
	}
	var session models.Session
	if err := json.Unmarshal([]byte(body), &session); err != nil {
		t.Fatal(err)
	}
	wsURL := "ws" + strings.TrimPrefix(s.URL, "http") + "/v1/sandboxes/" + sb.ID + "/sessions/" + session.ID + "/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + Token}})
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, _ = conn.ReadMessage()
	_, msg, err := conn.ReadMessage()
	conn.Close()
	if err != nil || !bytes.Contains(msg, []byte("TERM")) {
		t.Fatalf("exit signal = %q %v", msg, err)
	}

	ready := make(chan struct{})
	s.Observe(func(sv *Server) {
		sv.HangAttach = true
		sv.AttachReady = ready
	})
	hung := make(chan struct{})
	go func() {
		defer close(hung)
		c, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + Token}})
		if err != nil {
			return
		}
		<-ready
		c.Close()
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("hanging attach did not start")
	}
	select {
	case <-hung:
	case <-time.After(2 * time.Second):
		t.Fatal("hanging attach did not return after the client left")
	}
}

func TestFakeLimitInfoAndTCPKnobs(t *testing.T) {
	s := New(t)
	s.AddSandbox(models.Sandbox{Name: "a"})
	s.AddSandbox(models.Sandbox{Name: "b"})
	s.IgnoreLimit = true
	if code, body := do(t, s, http.MethodGet, "/v1/sandboxes?limit=1", nil, Token); code != http.StatusOK || !strings.Contains(body, "a") || !strings.Contains(body, "b") {
		t.Fatalf("ignore limit = %d %s", code, body)
	}
	sb := s.AddSandbox(models.Sandbox{Name: "box"})
	if code, body := doJSON(t, s, http.MethodPost, "/v1/sandboxes/"+sb.ID+"/ports/9", map[string]string{"protocol": "tcp"}); code != http.StatusOK || !strings.Contains(body, "127.0.0.1") {
		t.Fatalf("tcp expose = %d %s", code, body)
	}
	s.PutFile(sb.ID, "/work/sub/", nil)
	s.BadFileInfo = true
	if code, body := do(t, s, http.MethodGet, "/v1/sandboxes/"+sb.ID+"/toolbox/files/info?path=/work/sub/", nil, Token); code != http.StatusOK || body != "not-json" {
		t.Fatalf("bad info = %d %q", code, body)
	}
	s.BadFileInfo = false
	if code, body := do(t, s, http.MethodGet, "/v1/sandboxes/"+sb.ID+"/toolbox/files?path=/work", nil, Token); code != http.StatusOK || !strings.Contains(body, `"isDir":true`) {
		t.Fatalf("dir entry = %d %s", code, body)
	}
}

func TestInterpretAndHijackGuard(t *testing.T) {
	var stdout, stderr bytes.Buffer
	out := func(stream byte, b []byte) {
		if stream == 2 {
			stderr.Write(b)
		} else {
			stdout.Write(b)
		}
	}
	if code, sig := Interpret("echo hi", nil, out, nil); code != 0 || sig != "" || stdout.String() != "hi\n" {
		t.Fatalf("echo = %d %q %q", code, sig, stdout.String())
	}
	if _, sig := Interpret("stderr err", nil, out, nil); sig != "" || stderr.String() != "err\n" {
		t.Fatalf("stderr = %q %q", sig, stderr.String())
	}
	if code, _ := Interpret("exit 4", nil, out, nil); code != 4 {
		t.Fatalf("exit = %d", code)
	}
	if code, _ := Interpret("cat", strings.NewReader("zz"), out, nil); code != 0 || !bytes.Contains(stdout.Bytes(), []byte("zz")) {
		t.Fatalf("cat = %d %q", code, stdout.String())
	}
	killed := make(chan struct{})
	close(killed)
	if _, sig := Interpret("sleep", nil, out, killed); sig != "killed" {
		t.Fatalf("sleep signal = %q", sig)
	}
	if _, sig := Interpret("signal TERM", nil, out, nil); sig != "TERM" {
		t.Fatalf("signal = %q", sig)
	}
	// yes larger than one chunk exercises the copy loop.
	if code, _ := Interpret("yes 10000", nil, out, nil); code != 0 || stdout.Len() < 10000 {
		t.Fatalf("yes wrote %d", stdout.Len())
	}

	defer func() {
		if recover() == nil {
			t.Fatal("hijack of a recorder should panic")
		}
	}()
	hijackAndClose(httptest.NewRecorder())
}

func TestFakeFailureKnobs(t *testing.T) {
	s := New(t)
	sb := s.AddSandbox(models.Sandbox{Name: "box", Status: models.SandboxStatusStarted})
	s.FailDestroy = true
	if code, body := do(t, s, http.MethodDelete, "/v1/sandboxes/"+sb.ID, nil, Token); code != http.StatusInternalServerError || !strings.Contains(body, "destroy failed") {
		t.Fatalf("destroy = %d %s", code, body)
	}
	if _, ok := s.Sandbox(sb.ID); !ok {
		t.Fatal("failed destroy removed the sandbox")
	}
	s.FailExpose = true
	if code, _ := doJSON(t, s, http.MethodPost, "/v1/sandboxes/"+sb.ID+"/ports/80", map[string]string{"protocol": "http"}); code != http.StatusInternalServerError {
		t.Fatalf("expose = %d", code)
	}
	s.FailToolbox = true
	if code, _ := do(t, s, http.MethodGet, "/v1/sandboxes/"+sb.ID+"/toolbox/files?path=/", nil, Token); code != http.StatusInternalServerError {
		t.Fatalf("toolbox = %d", code)
	}
	s.FailSessions = true
	if code, _ := doJSON(t, s, http.MethodPost, "/v1/sandboxes/"+sb.ID+"/sessions", map[string]string{"command": "true"}); code != http.StatusInternalServerError {
		t.Fatalf("sessions = %d", code)
	}
	s.FailSessions = false
	if code, _ := doJSON(t, s, http.MethodPost, "/v1/sandboxes/"+sb.ID+"/sessions", map[string]string{"command": "true", "name": "drop"}); code != http.StatusCreated {
		t.Fatalf("session create = %d", code)
	}
	s.DropAttach = true
	wsURL := "ws" + strings.TrimPrefix(s.URL, "http") + "/v1/sandboxes/" + sb.ID + "/sessions/ses-1/attach"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + Token}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("dropped attach stayed open")
	}
	_ = conn.Close()
}

type wsMsg struct {
	bin  []byte
	text string
}

func stream(t *testing.T, s *Server, id, command string, bins []wsMsg, texts []string) {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(s.URL, "http") + "/v1/sandboxes/" + id + "/toolbox/process/exec/stream"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + Token}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.WriteJSON(map[string]string{"command": command}); err != nil {
		t.Fatal(err)
	}
	for _, m := range bins {
		if err := conn.WriteMessage(websocket.BinaryMessage, m.bin); err != nil {
			t.Fatal(err)
		}
	}
	for _, text := range texts {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			return
		}
	}
}

func do(t *testing.T, s *Server, method, path string, body io.Reader, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, s.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func doJSON(t *testing.T, s *Server, method, path string, v any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, s.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func TestFakeLiveAttach(t *testing.T) {
	s := New(t)
	sb := s.AddSandbox(models.Sandbox{Name: "box"})
	s.AddSession(sb.ID, models.Session{ID: "ses-sh", Name: "default", PTY: true, Argv: []string{"/bin/bash", "-l"}, Status: models.SessionStatusRunning})
	s.Observe(func(s *Server) {
		s.LiveAttach = true
		s.ExecFunc = func(cmd string, in io.Reader, out func(byte, []byte), _ <-chan struct{}) (int, string) {
			buf := make([]byte, 64)
			n, err := in.Read(buf)
			if err != nil {
				return 0, "" // stdin closed: the client detached
			}
			out(1, buf[:n])
			return 2, ""
		}
	})
	s.AppendSessionLog(sb.ID, "ses-sh", []byte("earlier output"))
	attach := func() *websocket.Conn {
		t.Helper()
		wsURL := "ws" + strings.TrimPrefix(s.URL, "http") + "/v1/sandboxes/" + sb.ID + "/sessions/ses-sh/attach"
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + Token}})
		if err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, msg, err := conn.ReadMessage(); err != nil || string(msg[1:]) != "earlier output" {
			t.Fatalf("replay = %q %v", msg, err)
		}
		return conn
	}

	// Typing: resize and signal frames are recorded, stdin reaches the
	// command, and its exit is reported.
	conn := attach()
	for _, ctrl := range []string{`{"type":"resize","cols":80,"rows":24}`, `{"type":"signal","signal":"INT"}`, "not-json"} {
		_ = conn.WriteMessage(websocket.TextMessage, []byte(ctrl))
	}
	_ = conn.WriteMessage(websocket.BinaryMessage, []byte("ls\n"))
	if _, msg, err := conn.ReadMessage(); err != nil || string(msg) != "\x01ls\n" {
		t.Fatalf("echo = %q %v", msg, err)
	}
	if _, msg, err := conn.ReadMessage(); err != nil || !bytes.Contains(msg, []byte(`"code":2`)) {
		t.Fatalf("exit = %q %v", msg, err)
	}
	conn.Close()

	// Detaching: no exit message, and the detach is counted.
	conn = attach()
	_ = conn.WriteJSON(map[string]string{"type": "close"})
	if _, msg, err := conn.ReadMessage(); err == nil {
		t.Fatalf("a detach was answered with %q", msg)
	}
	conn.Close()
	s.Observe(func(s *Server) {
		if s.Detaches != 1 || len(s.Resizes) != 1 || s.Resizes[0] != "80x24" || len(s.Signals) != 1 || s.Signals[0] != "INT" {
			t.Fatalf("detaches %d resizes %v signals %v", s.Detaches, s.Resizes, s.Signals)
		}
	})

	s.Observe(func(s *Server) { s.FailAttach = true })
	wsURL := "ws" + strings.TrimPrefix(s.URL, "http") + "/v1/sandboxes/" + sb.ID + "/sessions/ses-sh/attach"
	if _, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": []string{"Bearer " + Token}}); err == nil || resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("FailAttach handshake = %v", err)
	}
}
