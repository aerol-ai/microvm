package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeJoinPortCurl answers each call with the next HTTP code from the file
// in FAKE_JOIN_CODES (one per line; the last repeats), the way curl
// -o /dev/null -w '%{http_code}' prints it. 000 is a port that does not
// answer, so curl also exits non-zero then.
const fakeJoinPortCurl = `#!/usr/bin/env bash
n=$(cat "$FAKE_JOIN_COUNT" 2>/dev/null || echo 0)
echo $((n + 1)) >"$FAKE_JOIN_COUNT"
code=$(sed -n "$((n + 1))p" "$FAKE_JOIN_CODES")
[ -n "$code" ] || code=$(tail -n 1 "$FAKE_JOIN_CODES")
printf '%s' "$code"
[ "$code" = 000 ] && exit 7
exit 0
`

// TestBootstrapJoinWaitStopsOnARefusedToken runs the rendered joiner's
// wait_for_join_port against a fake join port. A token the port keeps
// refusing stops the wait with what to do (a fresh token through
// node_join_tokens) instead of waiting out seed_wait_max_seconds; a port
// that is down, or a refusal that clears within the grace (the seed still
// registering the module's tokens), still waits as before.
func TestBootstrapJoinWaitStopsOnARefusedToken(t *testing.T) {
	out := renderBootstrap(t, "joiner_join")
	start := strings.Index(out, "wait_for_join_port() {")
	end := strings.Index(out, "\nwait_for_join_port || exit 1")
	if start < 0 || end <= start {
		t.Fatal("the rendered joiner has no wait_for_join_port")
	}
	fn := out[start:end]
	if !strings.Contains(out, "\nwait_for_join_port || exit 1\njoined=0") {
		t.Fatal("the joiner must stop when wait_for_join_port fails, before it runs install.sh join")
	}
	bin := filepath.Join(t.TempDir(), "bin")
	writeStageFile(t, filepath.Join(bin, "curl"), fakeJoinPortCurl, 0o755)
	cases := []struct {
		name      string
		codes     []string
		grace     string
		wantOK    bool
		wantCalls int
		wantErr   []string
		maxTime   time.Duration
	}{
		{name: "port down, then the token is accepted", codes: []string{"000", "000", "200"}, grace: "60",
			wantOK: true, wantCalls: 3, maxTime: 10 * time.Second},
		{name: "refused while the seed registers its tokens, then accepted", codes: []string{"403", "403", "200"}, grace: "60",
			wantOK: true, wantCalls: 3, maxTime: 10 * time.Second},
		{name: "a token the port keeps refusing stops the wait", codes: []string{"403"}, grace: "2",
			wantErr: []string{"refused this node's join token", "unknown, expired or revoked", "lasts 24h",
				"sudo sandboxd join-command --role server --ttl 2h --json", `node_join_tokens["x"]`},
			maxTime: 15 * time.Second},
		{name: "a port going down restarts the refusal clock", codes: []string{"403", "000", "403", "403", "200"}, grace: "60",
			wantOK: true, wantCalls: 5, maxTime: 10 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			codes, count := filepath.Join(dir, "codes"), filepath.Join(dir, "count")
			writeStageFile(t, codes, strings.Join(tc.codes, "\n")+"\n", 0o644)
			script := "JOIN_TOKEN='aaaaaa.00000000000000000000000000000000'\n" + fn + "\nwait_for_join_port\n"
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(),
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"FAKE_JOIN_CODES="+codes, "FAKE_JOIN_COUNT="+count,
				"JOIN_REFUSED_GRACE="+tc.grace, "JOIN_POLL_SECONDS=0.2")
			began := time.Now()
			outb, err := cmd.CombinedOutput()
			if took := time.Since(began); took > tc.maxTime {
				t.Fatalf("took %s, want under %s\n%s", took, tc.maxTime, outb)
			}
			if (err == nil) != tc.wantOK {
				t.Fatalf("err=%v, want ok=%v\n%s", err, tc.wantOK, outb)
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(string(outb), want) {
					t.Fatalf("output lacks %q:\n%s", want, outb)
				}
			}
			if tc.wantCalls > 0 {
				raw, _ := os.ReadFile(count)
				if got := strings.TrimSpace(string(raw)); got != strconv.Itoa(tc.wantCalls) {
					t.Fatalf("join port asked %s times, want %d\n%s", got, tc.wantCalls, outb)
				}
			}
			if strings.Contains(string(outb), "aaaaaa.00000000000000000000000000000000") {
				t.Fatalf("the wait printed the token:\n%s", outb)
			}
		})
	}
}
