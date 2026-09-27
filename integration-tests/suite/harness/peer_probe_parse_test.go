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
			out:        "\nPROBE_CODE=200\n\nPROBE_RC=0\n",
			wantStatus: 200,
		},
		{
			name: "an HTTP refusal keeps its status and drops the transport error",
			out:  "\nPROBE_CODE=403\n\nPROBE_RC=22\n", err: errors.New("exit status 22"),
			wantStatus: 403,
		},
		{
			name: "a torn-down handshake is a refusal, not a broken probe",
			out:  "\nPROBE_CODE=000\n\nPROBE_RC=56\n", err: errors.New("exit status 56"),
			wantRejected: true, wantErr: true,
		},
		{
			// The exact live output that broke the previous parser: curl -sS
			// writes its diagnostic into the same stream, so "the last
			// whitespace-separated field" was not the status.
			name: "curl's own error prose does not confuse the markers",
			out: "curl: (00056) OpenSSL SSL_read: error:0A00045C:SSL routines::tlsv13 alert certificate required, errno 0\n" +
				"\nPROBE_CODE=000\n\nPROBE_RC=56\n",
			err:          errors.New("exit status 56"),
			wantRejected: true, wantErr: true,
		},
		{
			name: "a hostname-verification failure is also a refusal",
			out:  "\nPROBE_CODE=000\n\nPROBE_RC=60\n", err: errors.New("exit status 60"),
			wantRejected: true, wantErr: true,
		},
		{
			// The false pass this guard exists to prevent: a probe that never
			// ran must NOT read as "the server refused me".
			name:    "a broken invocation is an error, never a refusal",
			out:     "bash: curl: command not found\n\nPROBE_CODE=\n\nPROBE_RC=127\n",
			err:     errors.New("exit status 127"),
			wantErr: true,
		},
		{
			name: "a connection refused outright is an error, not a TLS refusal",
			out:  "\nPROBE_CODE=000\n\nPROBE_RC=7\n", err: errors.New("exit status 7"),
			wantErr: true,
		},
		{
			// Sourcing the node's env files can echo before curl runs, so the
			// LAST marker is the one that counts.
			name:       "an earlier stray marker does not win over the real one",
			out:        "PROBE_CODE=500\nsome noise\n\nPROBE_CODE=204\n\nPROBE_RC=0\n",
			wantStatus: 204,
		},
		{
			name:    "no marker at all is an error",
			out:     "some unrelated ssh banner\n",
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
	if !strings.Contains(probeCurlSuffix, `"$?"`) || !strings.Contains(probeCurlSuffix, "PROBE_RC=") {
		t.Fatalf("probeCurlSuffix does not emit curl's exit code as a PROBE_RC marker: %q", probeCurlSuffix)
	}
	if !strings.Contains(internalCurlPrefix, "PROBE_CODE=%{http_code}") {
		t.Fatalf("internalCurlPrefix does not emit the status as a PROBE_CODE marker; curl's own prose would be parsed as the status")
	}
	if !strings.HasSuffix(probeCurlSuffix, "'") {
		t.Fatalf("probeCurlSuffix must close the `bash -c` quote: %q", probeCurlSuffix)
	}
}
