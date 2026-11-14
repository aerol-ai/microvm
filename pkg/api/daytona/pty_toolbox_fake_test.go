package daytona

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakePTYToolbox is a toolboxd that speaks the Daytona terminal routes
// (plan E8) closely enough for the facade contract cases: they prove the
// Daytona SDK's terminal calls, the WebSocket included, pass through the
// facade with their method, path and body, the sandbox's own toolbox
// token, and toolboxd's status. toolboxd's real behaviour is tested against
// the same SDK in cmd/toolboxd/daytona_pty_test.go.
//
// A terminal echoes each input message back as "echo:<input>", sends
// "replay:<id>" first on every connect (a reattach sees it again), ends with
// exit code 0 on the input "exit\n", and ends with a signal when killed.
type fakePTYToolbox struct {
	t     *testing.T
	token string
	limit int

	mu        sync.Mutex
	terminals map[string]*fakePTY
	connects  []string // paths of the WebSocket upgrades that arrived
	creates   []map[string]any
}

type fakePTY struct {
	ID        string            `json:"id"`
	Cols      int               `json:"cols"`
	Rows      int               `json:"rows"`
	Cwd       string            `json:"cwd"`
	Envs      map[string]string `json:"envs"`
	CreatedAt string            `json:"createdAt"`
	Active    bool              `json:"active"`
	LazyStart bool              `json:"lazyStart"`

	killed chan struct{}
}

func newFakePTYToolbox(t *testing.T, token string, limit int) *fakePTYToolbox {
	return &fakePTYToolbox{t: t, token: token, limit: limit, terminals: map[string]*fakePTY{}}
}

func (f *fakePTYToolbox) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakePTYToolbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		f.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.URL.Path == "/process/pty" {
		switch r.Method {
		case http.MethodPost:
			f.create(w, r)
		case http.MethodGet:
			f.mu.Lock()
			list := make([]*fakePTY, 0, len(f.terminals))
			for _, term := range f.terminals {
				list = append(list, term)
			}
			f.mu.Unlock()
			sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
			f.writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
		default:
			f.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}
	id, action, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/process/pty/"), "/")
	f.mu.Lock()
	term := f.terminals[id]
	f.mu.Unlock()
	if term == nil {
		f.writeJSON(w, http.StatusNotFound, map[string]string{"error": "terminal " + id + " not found"})
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		f.writeJSON(w, http.StatusOK, term)
	case action == "" && r.Method == http.MethodDelete:
		f.mu.Lock()
		delete(f.terminals, id)
		f.mu.Unlock()
		close(term.killed)
		f.writeJSON(w, http.StatusOK, map[string]any{})
	case action == "resize" && r.Method == http.MethodPost:
		var size struct{ Cols, Rows int }
		if err := json.NewDecoder(r.Body).Decode(&size); err != nil {
			f.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		f.mu.Lock()
		term.Cols, term.Rows = size.Cols, size.Rows
		f.mu.Unlock()
		f.writeJSON(w, http.StatusOK, term)
	case action == "connect" && r.Method == http.MethodGet:
		f.connect(w, r, term)
	default:
		f.writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (f *fakePTYToolbox) create(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	var req struct {
		ID         string
		Cols, Rows int
		Cwd        string
		Envs       map[string]string
	}
	raw, _ := json.Marshal(body)
	_ = json.Unmarshal(raw, &req)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates = append(f.creates, body)
	if len(f.terminals) >= f.limit {
		f.writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "this sandbox already has 2 terminals"})
		return
	}
	if req.Envs == nil {
		req.Envs = map[string]string{}
	}
	f.terminals[req.ID] = &fakePTY{
		ID: req.ID, Cols: req.Cols, Rows: req.Rows, Cwd: req.Cwd, Envs: req.Envs,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Active: true,
		killed: make(chan struct{}),
	}
	f.writeJSON(w, http.StatusCreated, map[string]string{"sessionId": req.ID})
}

var fakePTYUpgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

func (f *fakePTYToolbox) connect(w http.ResponseWriter, r *http.Request, term *fakePTY) {
	conn, err := fakePTYUpgrader.Upgrade(w, r, nil)
	if err != nil {
		f.t.Errorf("fake toolbox upgrade %s: %v", r.URL.Path, err)
		return
	}
	defer conn.Close()
	f.mu.Lock()
	f.connects = append(f.connects, r.URL.Path)
	f.mu.Unlock()

	closeWith := func(reason string) {
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason), time.Now().Add(time.Second))
	}
	go func() {
		<-term.killed
		closeWith(`{"exitCode":-1,"exitReason":"terminated by signal: hangup"}`)
	}()
	if err := conn.WriteJSON(map[string]string{"type": "control", "status": "connected"}); err != nil {
		return
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("replay:"+term.ID)); err != nil {
		return
	}
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if string(data) == "exit\n" {
			closeWith(`{"exitCode":0}`)
			return
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte("echo:"), data...)); err != nil {
			return
		}
	}
}

func (f *fakePTYToolbox) connectPaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.connects...)
}

func (f *fakePTYToolbox) createBodies() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.creates...)
}
