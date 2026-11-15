package toolboxwire

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// A log window never ends inside a UTF-8 character, so its text decodes
// whole and the reader's next window starts on a character. Bytes that are
// not valid UTF-8 become '?', one for one, so the text is as long as the
// bytes it stands for and end agrees with it.
func TestCutLogWindowKeepsCharactersWhole(t *testing.T) {
	const smile = "\U0001F642" // four bytes
	tests := []struct {
		name        string
		text        string
		from, limit int64
		final       bool
		want        string
		wantEnd     int64
	}{
		{name: "limit inside a character stops before it", text: "ab" + smile + "c", limit: 3, final: true, want: "ab", wantEnd: 2},
		{name: "the next window starts on it", text: "ab" + smile + "c", from: 2, limit: 5, final: true, want: smile + "c", wantEnd: 7},
		{name: "a limit shorter than a character still moves", text: "ab" + smile, from: 2, limit: 3, final: true, want: "???", wantEnd: 5},
		{name: "running: a character still being written waits", text: "ok" + smile[:2], want: "ok", wantEnd: 2},
		{name: "running: nothing whole yet", text: smile[:1], want: "", wantEnd: 0},
		{name: "finished: a cut-off character is all there is", text: "ok" + smile[:2], final: true, want: "ok??", wantEnd: 4},
		{name: "invalid bytes are whole, one '?' each", text: "a\xffb\x80", want: "a?b?", wantEnd: 4},
		{name: "a real replacement character is kept", text: "�", want: "�", wantEnd: 3},
		{name: "a character ending at the limit", text: "ab" + smile, limit: 6, final: true, want: "ab" + smile, wantEnd: 6},
		{name: "past the end", text: "abc", from: 9, want: "", wantEnd: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, got := range []LogWindow{
				CutLogWindow(tt.text, tt.from, tt.limit, tt.final),
				CutLogWindow([]byte(tt.text), tt.from, tt.limit, tt.final),
			} {
				if got.Text != tt.want || got.End != tt.wantEnd || got.Length != int64(len(tt.text)) {
					t.Fatalf("CutLogWindow = %q end %d length %d; want %q end %d", got.Text, got.End, got.Length, tt.want, tt.wantEnd)
				}
			}
		})
	}
}

// A stream whose head was dropped keeps its own offsets: a read from inside
// the dropped part starts at the oldest byte kept, and end and length count
// every byte the stream ever had.
func TestCutLogWindowAtDroppedHead(t *testing.T) {
	const kept = "fghij" // bytes 5..9 of "abcdefghij"
	tests := []struct {
		name        string
		from, limit int64
		want        string
		wantEnd     int64
	}{
		{name: "from zero reads what is kept", from: 0, want: "fghij", wantEnd: 10},
		{name: "from inside the dropped head", from: 3, limit: 2, want: "fg", wantEnd: 7},
		{name: "from inside what is kept", from: 7, want: "hij", wantEnd: 10},
		{name: "at the end", from: 10, want: "", wantEnd: 10},
		{name: "past the end", from: 99, want: "", wantEnd: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CutLogWindowAt([]byte(kept), 5, tt.from, tt.limit, true)
			if got.Text != tt.want || got.End != tt.wantEnd || got.Length != 10 {
				t.Fatalf("CutLogWindowAt = %+v, want %q end %d length 10", got, tt.want, tt.wantEnd)
			}
		})
	}
	// A head cut inside a character leaves its tail bytes, which read as '?'
	// one for one, so offsets still line up.
	if got := CutLogWindowAt([]byte("\x9f\x99\x82!"), 2, 0, 0, true); got.Text != "???!" || got.End != 6 {
		t.Fatalf("split head = %+v", got)
	}
}

func TestParseLogQuery(t *testing.T) {
	q, err := ParseLogQuery(url.Values{"stdoutOffset": {"2"}, "stderrOffset": {" 9 "}, "limit": {"3"}})
	if err != nil || q != (LogQuery{StdoutOffset: 2, StderrOffset: 9, Limit: 3}) {
		t.Fatalf("query = %+v %v", q, err)
	}
	if q, err := ParseLogQuery(url.Values{}); err != nil || q != (LogQuery{}) {
		t.Fatalf("empty query = %+v %v", q, err)
	}
	for _, bad := range []string{"stdoutOffset=-1", "limit=x", "stderrOffset=1.5"} {
		values, _ := url.ParseQuery(bad)
		name, _, _ := strings.Cut(bad, "=")
		if _, err := ParseLogQuery(values); err == nil || err.Error() != name+" must be a non-negative integer" {
			t.Errorf("%s: err = %v", bad, err)
		}
	}
}

func TestSessionBodies(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		req  SessionExecuteRequest
		want bool
	}{
		{SessionExecuteRequest{}, false},
		{SessionExecuteRequest{RunAsync: &yes}, true},
		{SessionExecuteRequest{Async: &yes}, true},
		{SessionExecuteRequest{RunAsync: &no, Async: &no}, false},
	} {
		if got := tc.req.RunsAsync(); got != tc.want {
			t.Errorf("RunsAsync(%+v) = %v", tc.req, got)
		}
	}
	for data, want := range map[string]string{"Alice": "Alice\n", "a\n": "a\n", "a\r": "a\r", "": "\n", "a\nb": "a\nb\n"} {
		if got := (SessionInputRequest{Data: data}).Line(); got != want {
			t.Errorf("Line(%q) = %q, want %q", data, got, want)
		}
	}

	// A sync exec's empty streams are absent, as toolboxd always sent them.
	for _, tc := range []struct {
		resp *SessionExecuteResponse
		want string
	}{
		{NewSessionExecuteResponse("c1", 0, "", ""), `{"cmdId":"c1","exitCode":0}`},
		{NewSessionExecuteResponse("c1", 2, "out", "err"), `{"cmdId":"c1","exitCode":2,"output":"outerr","stderr":"err","stdout":"out"}`},
		{&SessionExecuteResponse{CmdID: "c2"}, `{"cmdId":"c2"}`},
	} {
		if b, _ := json.Marshal(tc.resp); string(b) != tc.want {
			t.Errorf("exec response = %s, want %s", b, tc.want)
		}
	}
	logs := NewSessionLogsResponse(LogWindow{Text: "o", End: 3, Length: 4}, LogWindow{Text: "e", End: 1, Length: 1})
	b, _ := json.Marshal(logs)
	if string(b) != `{"output":"oe","stderr":"e","stdout":"o","stdoutLength":4,"stderrLength":1,"stdoutEnd":3,"stderrEnd":1}` {
		t.Fatalf("logs response = %s", b)
	}
	b, _ = json.Marshal(SessionResponse{SessionID: "s", Commands: []CommandResponse{{Command: "ls", ID: "c"}}})
	if string(b) != `{"commands":[{"command":"ls","id":"c"}],"sessionId":"s"}` {
		t.Fatalf("session response = %s", b)
	}
}

func TestLogFraming(t *testing.T) {
	if got := FrameLog(false, []byte("hi")); !bytes.Equal(got, []byte("\x01\x01\x01hi")) {
		t.Fatalf("stdout frame = %q", got)
	}
	if got := FrameLog(true, nil); !bytes.Equal(got, []byte("\x02\x02\x02")) {
		t.Fatalf("stderr frame = %q", got)
	}
	if got := LogReplay([]byte("o"), []byte("e")); !bytes.Equal(got, []byte("\x01\x01\x01o\x02\x02\x02e")) {
		t.Fatalf("replay = %q", got)
	}
	if got := LogReplay(nil, []byte("e")); !bytes.Equal(got, []byte("\x02\x02\x02e")) {
		t.Fatalf("stderr-only replay = %q", got)
	}
	if got := LogReplay(nil, nil); got != nil {
		t.Fatalf("empty replay = %q", got)
	}
}

// FollowLogs sends the replay and every frame, and says whether the command
// ended (frames closed) or the client went away.
func TestFollowLogs(t *testing.T) {
	frames := make(chan []byte, 4)
	ended := make(chan bool, 1)
	upgrader := NewLogsUpgrader()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		ended <- FollowLogs(conn, []byte("replay"), frames)
	}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": {"https://elsewhere.example"}})
	if err != nil {
		t.Fatal(err)
	}
	frames <- []byte("live")
	close(frames)
	for _, want := range []string{"replay", "live"} {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		typ, data, err := conn.ReadMessage()
		if err != nil || typ != websocket.BinaryMessage || string(data) != want {
			t.Fatalf("frame = %d %q %v, want %q", typ, data, err, want)
		}
	}
	if !<-ended {
		t.Fatal("closed frames did not end the follow")
	}
	conn.Close()

	// A client that leaves ends the follow of a command still running.
	live := make(chan []byte)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		ended <- FollowLogs(conn, nil, live)
	}))
	defer srv2.Close()
	conn, _, err = websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv2.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case got := <-ended:
		if got {
			t.Fatal("a client that left reads as an ended command")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follow did not notice the client leave")
	}
}
