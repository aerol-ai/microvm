package toolboxwire

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWireJSONShapes(t *testing.T) {
	var start ExecStreamStart
	if err := json.Unmarshal([]byte(`{"command":"ls","argv":["a"],"workdir":"/w","env":{"K":"v"},"tty":true,"cols":80,"rows":24}`), &start); err != nil {
		t.Fatal(err)
	}
	if start.Command != "ls" || start.Argv[0] != "a" || start.Workdir != "/w" || start.Env["K"] != "v" || !start.TTY || start.Cols != 80 || start.Rows != 24 {
		t.Fatalf("start = %+v", start)
	}
	var in ExecStreamControlIn
	if err := json.Unmarshal([]byte(`{"type":"signal","signal":"INT","cols":1,"rows":2}`), &in); err != nil || in.Signal != "INT" || in.Rows != 2 {
		t.Fatalf("control in = %+v %v", in, err)
	}
	// A clean exit omits code and signal, exactly as toolboxd always sent it.
	for _, tc := range []struct {
		out  ExecStreamControlOut
		want string
	}{
		{ExecStreamControlOut{Type: "exit"}, `{"type":"exit"}`},
		{ExecStreamControlOut{Type: "exit", Code: -1, Signal: "killed"}, `{"type":"exit","code":-1,"signal":"killed"}`},
		{ExecStreamControlOut{Type: "error", Message: "boom"}, `{"type":"error","message":"boom"}`},
	} {
		b, err := json.Marshal(tc.out)
		if err != nil || string(b) != tc.want {
			t.Fatalf("marshal %+v = %s %v, want %s", tc.out, b, err, tc.want)
		}
	}
}

func TestUpgraderEchoesBearerAndLivenessPings(t *testing.T) {
	var pings atomic.Int32
	upgrader := NewExecStreamUpgrader()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		extend, stop := ArmLiveness(conn, Liveness{PingInterval: 20 * time.Millisecond, PongWait: 200 * time.Millisecond, PingWriteWait: time.Second})
		defer stop()
		defer stop() // safe twice
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			extend()
		}
	}))
	defer srv.Close()

	dialer := websocket.Dialer{Subprotocols: []string{BearerSubprotocol, "tok"}}
	conn, resp, err := dialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), http.Header{"Origin": {"https://elsewhere.example"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := resp.Header.Get("Sec-WebSocket-Protocol"); got != BearerSubprotocol {
		t.Fatalf("subprotocol = %q", got)
	}
	conn.SetPingHandler(func(string) error {
		pings.Add(1)
		return conn.WriteControl(websocket.PongMessage, nil, time.Now().Add(time.Second))
	})
	// Read in the background so pings are answered; the pongs keep the
	// server's 200ms read deadline moving well past it.
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	time.Sleep(500 * time.Millisecond)
	if pings.Load() < 3 {
		t.Fatalf("pings = %d", pings.Load())
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte("still here")); err != nil {
		t.Fatalf("server dropped a live stream: %v", err)
	}
}
