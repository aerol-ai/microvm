package harness

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestParseServerTimingCreate(t *testing.T) {
	tests := []struct {
		name   string
		header string
		wantMS float64
		wantOK bool
	}{
		{"simple float", "create;dur=1234.5", 1234.5, true},
		{"integer dur", "create;dur=42", 42, true},
		{"among other metrics", "db;dur=3, create;dur=900.25, total;dur=950", 900.25, true},
		{"desc before dur", `create;desc="sandbox";dur=12`, 12, true},
		{"surrounding spaces", "  create ; dur=7.5 ", 7.5, true},
		{"no create metric", "db;dur=3, total;dur=10", 0, false},
		{"create without dur", "create;desc=x", 0, false},
		{"name prefix is not a match", "created;dur=5", 0, false},
		{"empty header", "", 0, false},
		{"unparseable dur", "create;dur=abc", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms, ok := parseServerTimingCreate(tt.header)
			if ok != tt.wantOK {
				t.Fatalf("parseServerTimingCreate(%q) ok = %v, want %v", tt.header, ok, tt.wantOK)
			}
			if ok && ms != tt.wantMS {
				t.Fatalf("parseServerTimingCreate(%q) ms = %v, want %v", tt.header, ms, tt.wantMS)
			}
		})
	}
}

// stubRoundTripper returns a canned response (status code + optional
// Server-Timing header) so the transport can be exercised without a server.
type stubRoundTripper struct {
	header string
	code   int
}

func (s stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	h := make(http.Header)
	if s.header != "" {
		h.Set("Server-Timing", s.header)
	}
	return &http.Response{
		StatusCode: s.code,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

func newReq(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

// TestServerTimingTransportRecordsCreate verifies the transport captures the
// create duration from a 2xx POST .../sandboxes and that takeCreateMS consumes
// it (so a later create with no header reads absent, not stale).
func TestServerTimingTransportRecordsCreate(t *testing.T) {
	tr := &serverTimingTransport{base: stubRoundTripper{header: "create;dur=321.5", code: 201}}
	if _, err := tr.RoundTrip(newReq(t, http.MethodPost, "https://x/v1/sandboxes")); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	ms, ok := tr.takeCreateMS()
	if !ok || ms != 321.5 {
		t.Fatalf("takeCreateMS() = (%v, %v), want (321.5, true)", ms, ok)
	}
	if _, ok := tr.takeCreateMS(); ok {
		t.Fatal("takeCreateMS() should be empty after consumption")
	}
}

// TestServerTimingTransportIgnoresNonCreate confirms a GET (list) and a non-2xx
// response never record, even with a Server-Timing header present.
func TestServerTimingTransportIgnoresNonCreate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		code   int
	}{
		{"list GET", http.MethodGet, 200},
		{"failed create", http.MethodPost, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &serverTimingTransport{base: stubRoundTripper{header: "create;dur=99", code: tc.code}}
			if _, err := tr.RoundTrip(newReq(t, tc.method, "https://x/v1/sandboxes")); err != nil {
				t.Fatalf("round trip: %v", err)
			}
			if _, ok := tr.takeCreateMS(); ok {
				t.Fatalf("%s: should not have recorded a create time", tc.name)
			}
		})
	}
}

func TestParseServerTimingReadinessSource(t *testing.T) {
	src, ok := parseServerTimingReadinessSource(`create;dur=1, readiness;desc=socket, runtime_wait;dur=2`)
	if !ok || src != "socket" {
		t.Fatalf("got (%q, %v)", src, ok)
	}
}

// TestParseServerTimingStages verifies the full-header stage map used by
// the bench's latency[].stages block: every dur-carrying metric lands
// under its name, desc-only metrics are skipped, and attributes beyond
// dur (fc_warm;dur=…;desc=hit) don't confuse the parse.
func TestParseServerTimingStages(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   map[string]float64
	}{
		{
			name: "firecracker stage set",
			header: "create;dur=3452.1, fc_driver;dur=3120.0, fc_verify;dur=1650.4, " +
				"fc_spawn;dur=95.2, fc_load;dur=140.0, fc_resume;dur=4.5, " +
				"fc_handshake;dur=61.0, fc_post_resume;dur=180.7, readiness;desc=socket",
			want: map[string]float64{
				"create": 3452.1, "fc_driver": 3120.0, "fc_verify": 1650.4,
				"fc_spawn": 95.2, "fc_load": 140.0, "fc_resume": 4.5,
				"fc_handshake": 61.0, "fc_post_resume": 180.7,
			},
		},
		{
			name:   "warm hit marker keeps dur despite desc",
			header: "create;dur=500, fc_warm;dur=142.3;desc=hit, fc_driver;dur=150.0",
			want:   map[string]float64{"create": 500, "fc_warm": 142.3, "fc_driver": 150.0},
		},
		{
			name:   "docker header",
			header: "create;dur=291.0, runtime_wait;dur=120.5, toolbox_wait;dur=88.0, readiness;desc=socket",
			want:   map[string]float64{"create": 291.0, "runtime_wait": 120.5, "toolbox_wait": 88.0},
		},
		{
			name:   "desc-only and empty metrics skipped",
			header: "readiness;desc=health, ;dur=5",
			want:   nil,
		},
		{
			name:   "empty header",
			header: "",
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseServerTimingStages(tt.header)
			if len(got) != len(tt.want) {
				t.Fatalf("parseServerTimingStages(%q) = %v, want %v", tt.header, got, tt.want)
			}
			for name, ms := range tt.want {
				if got[name] != ms {
					t.Fatalf("stage %q = %v, want %v (full: %v)", name, got[name], ms, got)
				}
			}
		})
	}
}

// TestServerTimingTransportRecordsStages verifies the transport captures
// the stage map on a 2xx create and that takeCreateStages consumes it.
func TestServerTimingTransportRecordsStages(t *testing.T) {
	tr := &serverTimingTransport{base: stubRoundTripper{
		header: "create;dur=321.5, fc_driver;dur=300.0, fc_verify;dur=150.2", code: 201}}
	if _, err := tr.RoundTrip(newReq(t, http.MethodPost, "https://x/v1/sandboxes")); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	stages, ok := tr.takeCreateStages()
	if !ok || stages["fc_driver"] != 300.0 || stages["fc_verify"] != 150.2 || stages["create"] != 321.5 {
		t.Fatalf("takeCreateStages() = (%v, %v), want full stage map", stages, ok)
	}
	if _, ok := tr.takeCreateStages(); ok {
		t.Fatal("takeCreateStages() should be empty after consumption")
	}
}
