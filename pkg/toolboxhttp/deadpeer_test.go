package toolboxhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// withDeadPeerTimeout sets the bound for one test and puts the old one back.
func withDeadPeerTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := DeadPeerTimeout()
	SetDeadPeerTimeout(d)
	t.Cleanup(func() { deadPeerTimeout.Store(int64(old)) })
}

func TestDeadPeerSettingsSplitTheBound(t *testing.T) {
	cases := []struct {
		bound                    time.Duration
		idle, interval, userTime time.Duration
	}{
		{bound: DefaultDeadPeerTimeout, idle: 15 * time.Second, interval: 5 * time.Second, userTime: 30 * time.Second},
		{bound: MinDeadPeerTimeout, idle: 3 * time.Second, interval: time.Second, userTime: 6 * time.Second},
		{bound: time.Minute, idle: 30 * time.Second, interval: 10 * time.Second, userTime: time.Minute},
	}
	for _, tc := range cases {
		ka, user := deadPeerSettings(tc.bound)
		if !ka.Enable || ka.Idle != tc.idle || ka.Interval != tc.interval || ka.Count != deadPeerKeepAliveCount || user != tc.userTime {
			t.Errorf("bound %v: keepalive %+v user timeout %v, want idle %v interval %v count %d user %v",
				tc.bound, ka, user, tc.idle, tc.interval, deadPeerKeepAliveCount, tc.userTime)
		}
		// The last probe goes unanswered exactly at the bound.
		if got := ka.Idle + time.Duration(ka.Count)*ka.Interval; got != tc.bound {
			t.Errorf("bound %v: idle + count*interval = %v", tc.bound, got)
		}
	}
}

func TestSetDeadPeerTimeoutClamps(t *testing.T) {
	cases := []struct{ in, want time.Duration }{
		{in: -time.Second, want: 0},
		{in: 0, want: 0},
		{in: time.Second, want: MinDeadPeerTimeout},
		{in: MinDeadPeerTimeout, want: MinDeadPeerTimeout},
		{in: 45 * time.Second, want: 45 * time.Second},
	}
	for _, tc := range cases {
		withDeadPeerTimeout(t, tc.in)
		if got := DeadPeerTimeout(); got != tc.want {
			t.Errorf("SetDeadPeerTimeout(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestDialerFollowsTheBound(t *testing.T) {
	withDeadPeerTimeout(t, DefaultDeadPeerTimeout)
	d := dialer()
	if d.Timeout != dialTimeout || !d.KeepAliveConfig.Enable || d.KeepAliveConfig.Idle != 15*time.Second {
		t.Fatalf("bounded dialer = %+v", d)
	}
	if (d.Control != nil) != (userTimeoutControl(time.Second) != nil) {
		t.Fatal("the bounded dialer does not set TCP_USER_TIMEOUT where the platform has it")
	}

	// Off: the dialer http.DefaultTransport used, untouched.
	SetDeadPeerTimeout(0)
	d = dialer()
	if d.Timeout != dialTimeout || d.KeepAlive != 30*time.Second || d.KeepAliveConfig.Enable || d.Control != nil {
		t.Fatalf("unbounded dialer = %+v", d)
	}
}

// TestTransportDialsThroughDialContext: the shared transport (and so every
// toolbox call) gets the bounded dialer.
func TestTransportDialsThroughDialContext(t *testing.T) {
	if Transport.DialContext == nil {
		t.Fatal("Transport has no DialContext")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	resp, err := Client(5 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
}

// TestDialContextHonoursContext: a cancelled dial fails instead of waiting
// out the connect timeout.
func TestDialContextHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := DialContext(ctx, "tcp", "127.0.0.1:1"); err == nil {
		conn.Close()
		t.Fatal("a dial with a cancelled context succeeded")
	}
}

// TestDialContextReachesAListener: the dialer connects (and, on Linux, its
// Control hook accepts the socket).
func TestDialContextReachesAListener(t *testing.T) {
	for _, bound := range []time.Duration{0, DefaultDeadPeerTimeout} {
		withDeadPeerTimeout(t, bound)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		conn, err := DialContext(context.Background(), "tcp", ln.Addr().String())
		if err != nil {
			ln.Close()
			t.Fatalf("bound %v: %v", bound, err)
		}
		conn.Close()
		ln.Close()
	}
}
