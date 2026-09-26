package harness

import (
	"errors"
	"strings"
	"testing"
)

// peerProbeFromOutput has been wrong three times in a row on live clusters
// (exit 60 hostname mismatch, 401 missing operator token, 400 missing
// min_generation, 56 handshake refusal), and each time the misreading showed
// up as a test failure against a product that was behaving correctly. The
// parser now decides "refused" vs "broken" from curl's exit code, so it is
// worth pinning that decision down offline.
func TestPeerProbeFromOutputClassification(t *testing.T) {
	for _, tc := range []struct {
		name         string
		out          string
		err          error
		wantStatus   int
		wantRejected bool
		wantErr      bool
	}{
		{
			name:       "a served answer is a status, and curl's exit is irrelevant",
			out:        "200|0",
			wantStatus: 200,
		},
		{
			name: "an HTTP refusal keeps its status and drops the transport error",
			out:  "403|22", err: errors.New("exit status 22"),
			wantStatus: 403,
		},
		{
			name: "a torn-down handshake is a refusal, not a broken probe",
			out:  "000|56", err: errors.New("exit status 56"),
			wantRejected: true, wantErr: true,
		},
		{
			name: "a hostname-verification failure is also a refusal",
			out:  "000|60", err: errors.New("exit status 60"),
			wantRejected: true, wantErr: true,
		},
		{
			// The false pass this guard exists to prevent: a probe that never
			// ran must NOT read as "the server refused me".
			name: "a broken invocation is an error, never a refusal",
			out:  "000|127", err: errors.New("exit status 127"),
			wantErr: true,
		},
		{
			name: "a connection refused outright is an error, not a TLS refusal",
			out:  "000|7", err: errors.New("exit status 7"),
			wantErr: true,
		},
		{
			// A stale script on the node emits a bare status. Degrade to the
			// old behaviour rather than inventing a refusal.
			name:    "output without an exit code still parses, and claims nothing",
			out:     "000",
			wantErr: true,
		},
		{
			name:    "no output at all is an error",
			out:     "",
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := peerProbeFromOutput("node1", tc.out, tc.err)
			if p.Status != tc.wantStatus {
				t.Errorf("status = %d, want %d", p.Status, tc.wantStatus)
			}
			if p.HandshakeRejected != tc.wantRejected {
				t.Errorf("HandshakeRejected = %v, want %v", p.HandshakeRejected, tc.wantRejected)
			}
			if (p.Err != nil) != tc.wantErr {
				t.Errorf("Err = %v, want error: %v", p.Err, tc.wantErr)
			}
		})
	}
}

// The probe scripts must actually emit the exit code the parser now reads.
// Without this, the suffix could be dropped from one call site and every
// handshake refusal would quietly become "could not connect".
func TestProbeCurlSuffixEmitsTheExitCode(t *testing.T) {
	if !strings.Contains(probeCurlSuffix, `"$?"`) {
		t.Fatalf("probeCurlSuffix does not emit curl's exit code: %q", probeCurlSuffix)
	}
	if !strings.HasSuffix(probeCurlSuffix, "'") {
		t.Fatalf("probeCurlSuffix must close the `bash -c` quote: %q", probeCurlSuffix)
	}
}
