//go:build integration

package suite

// Live checks for plan E8 (plans/agent-sandbox-feature-parity.md): Daytona
// SDK terminals, driven by the Daytona Go SDK pinned in go.mod through the
// live /daytona facade, so the WebSocket runs through the ingress, the
// facade (and a cluster forward, when the sandbox lives on another node)
// to toolboxd.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	daytonasdk "github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	daytonaerrors "github.com/daytonaio/daytona/libs/sdk-go/pkg/errors"
	daytonaoptions "github.com/daytonaio/daytona/libs/sdk-go/pkg/options"
	daytonatypes "github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
)

// ptyDaytonaLimit is toolboxd's per-sandbox terminal limit
// (cmd/toolboxd/daytona_pty.go, daytonaPTYLimit).
const ptyDaytonaLimit = 32

// ptySandbox makes a sandbox and opens it with the Daytona Go SDK.
func ptySandbox(t *testing.T, ctx context.Context) *daytonasdk.Sandbox {
	t.Helper()
	sb := paritySandbox(t)
	client, err := daytonasdk.NewClientWithConfig(&daytonatypes.DaytonaConfig{
		APIKey: sc.PAT,
		APIUrl: strings.TrimRight(sc.BaseURL, "/") + "/daytona",
	})
	if err != nil {
		t.Fatalf("Daytona SDK client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	dsb, err := client.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Daytona SDK Get(%s): %v", sb.ID, err)
	}
	return dsb
}

// ptyOpen creates (or reattaches to) a terminal and waits for toolboxd's
// "connected" message.
func ptyOpen(t *testing.T, ctx context.Context, dsb *daytonasdk.Sandbox, id string, create bool, opts ...func(*daytonaoptions.CreatePty)) *daytonasdk.PtyHandle {
	t.Helper()
	var handle *daytonasdk.PtyHandle
	var err error
	if create {
		handle, err = dsb.Process.CreatePty(ctx, id, opts...)
	} else {
		handle, err = dsb.Process.ConnectPty(ctx, id)
	}
	if err != nil {
		t.Fatalf("terminal %s (create=%v): %v", id, create, err)
	}
	t.Cleanup(func() { _ = handle.Disconnect() })
	if err := handle.WaitForConnection(ctx); err != nil {
		t.Fatalf("terminal %s: WaitForConnection: %v", id, err)
	}
	return handle
}

// ptyReadUntil reads terminal output until want matches and returns its
// last group. want is written so the echoed command line cannot match it.
func ptyReadUntil(t *testing.T, handle *daytonasdk.PtyHandle, want *regexp.Regexp) string {
	t.Helper()
	var out strings.Builder
	timeout := time.After(60 * time.Second)
	for {
		if m := want.FindStringSubmatch(out.String()); m != nil {
			return m[len(m)-1]
		}
		select {
		case data, ok := <-handle.DataChan():
			if !ok {
				t.Fatalf("terminal closed before %s; output %q", want, out.String())
			}
			out.Write(data)
		case <-timeout:
			t.Fatalf("no %s in 60s; output %q", want, out.String())
		}
	}
}

func ptySend(t *testing.T, handle *daytonasdk.PtyHandle, line string) {
	t.Helper()
	if err := handle.SendInput([]byte(line + "\n")); err != nil {
		t.Fatalf("SendInput(%q): %v", line, err)
	}
}

// ptySettle waits until the terminal has been quiet for a moment and answers
// a cursor-position query, as a real terminal does. Some shells (busybox
// ash on Alpine) end each prompt with ESC[6n and read the reply before they
// read the next line; a command typed in that window is swallowed, which is
// how UC-389 lost its background job live on the docker cluster.
func ptySettle(t *testing.T, handle *daytonasdk.PtyHandle) {
	t.Helper()
	var out strings.Builder
	deadline := time.After(5 * time.Second)
	for {
		select {
		case data, ok := <-handle.DataChan():
			if !ok {
				t.Fatalf("terminal closed while settling; output %q", out.String())
			}
			out.Write(data)
			continue
		case <-time.After(300 * time.Millisecond):
		case <-deadline:
		}
		break
	}
	if strings.Contains(out.String(), "\x1b[6n") {
		if err := handle.SendInput([]byte("\x1b[1;1R")); err != nil {
			t.Fatalf("answer the cursor-position query: %v", err)
		}
	}
}

// UC-386 — the Daytona Go SDK creates a terminal, connects, runs a command
// and reads its output; get and list describe it.
func TestParityDaytonaTerminalLive(t *testing.T) {
	harness.Require(t, sc, "UC-386")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dsb := ptySandbox(t, ctx)

	handle := ptyOpen(t, ctx, dsb, "uc386", true,
		daytonaoptions.WithCreatePtySize(daytonatypes.PtySize{Cols: 100, Rows: 30}),
		daytonaoptions.WithCreatePtyEnv(map[string]string{"UC": "386"}))
	t.Cleanup(func() { _ = dsb.Process.KillPtySession(context.Background(), "uc386") })
	ptySend(t, handle, `echo "out=$UC-$((40+2))-$TERM"`)
	if got := ptyReadUntil(t, handle, regexp.MustCompile(`out=(386-42-\S+)`)); got != "386-42-xterm-256color" {
		t.Fatalf("command output = %q, want the env, the arithmetic and the default TERM", got)
	}

	info, err := dsb.Process.GetPtySessionInfo(ctx, "uc386")
	if err != nil || info.ID != "uc386" || info.Cols != 100 || info.Rows != 30 {
		t.Fatalf("GetPtySessionInfo = %+v, %v", info, err)
	}
	list, err := dsb.Process.ListPtySessions(ctx)
	if err != nil || len(list) != 1 || list[0].ID != "uc386" {
		t.Fatalf("ListPtySessions = %+v, %v", list, err)
	}
}

// UC-387 — resize changes the terminal's real size, and kill ends the shell
// and a job it started, and forgets the terminal.
func TestParityDaytonaTerminalResizeKillLive(t *testing.T) {
	harness.Require(t, sc, "UC-387")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dsb := ptySandbox(t, ctx)

	handle := ptyOpen(t, ctx, dsb, "uc387", true)
	resized, err := handle.Resize(ctx, 120, 40)
	if err != nil || resized.Cols != 120 || resized.Rows != 40 {
		t.Fatalf("Resize = %+v, %v", resized, err)
	}
	ptySend(t, handle, `echo "size=$(stty size | tr ' ' x)"`)
	if got := ptyReadUntil(t, handle, regexp.MustCompile(`size=(\d+x\d+)`)); got != "40x120" {
		t.Fatalf("stty size after resize = %q, want 40x120", got)
	}

	ptySend(t, handle, `sleep 300 & echo "job=$!"`)
	job := ptyReadUntil(t, handle, regexp.MustCompile(`job=(\d+)`))
	if err := dsb.Process.KillPtySession(ctx, "uc387"); err != nil {
		t.Fatalf("KillPtySession: %v", err)
	}
	result, err := handle.Wait(ctx)
	if err != nil || result.ExitCode == nil {
		t.Fatalf("Wait after kill = %+v, %v; want the end of the terminal", result, err)
	}
	var notFound *daytonaerrors.DaytonaNotFoundError
	if _, err := dsb.Process.GetPtySessionInfo(ctx, "uc387"); !errors.As(err, &notFound) {
		t.Fatalf("GetPtySessionInfo after kill = %v, want not found", err)
	}
	gone := false
	for i := 0; i < 20 && !gone; i++ {
		res, err := dsb.Process.ExecuteCommand(ctx, "kill -0 "+job+" 2>/dev/null && echo alive || echo gone")
		if err != nil {
			t.Fatalf("check the job: %v", err)
		}
		gone = strings.TrimSpace(res.Result) == "gone"
		if !gone {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if !gone {
		t.Fatalf("job %s outlived the killed terminal", job)
	}
}

// UC-388 — terminal 33 is refused with 429; killing one makes room.
func TestParityDaytonaTerminalLimitLive(t *testing.T) {
	harness.Require(t, sc, "UC-388")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	dsb := ptySandbox(t, ctx)

	t.Cleanup(func() {
		for i := 0; i <= ptyDaytonaLimit; i++ {
			_ = dsb.Process.KillPtySession(context.Background(), fmt.Sprintf("uc388-%d", i))
		}
	})
	for i := 0; i < ptyDaytonaLimit; i++ {
		if _, err := dsb.Process.CreatePtySession(ctx, fmt.Sprintf("uc388-%d", i)); err != nil {
			t.Fatalf("terminal %d of %d: %v", i+1, ptyDaytonaLimit, err)
		}
	}
	var limited *daytonaerrors.DaytonaRateLimitError
	over := fmt.Sprintf("uc388-%d", ptyDaytonaLimit)
	if _, err := dsb.Process.CreatePtySession(ctx, over); !errors.As(err, &limited) || !strings.Contains(err.Error(), "terminals") {
		t.Fatalf("terminal %d = %v, want 429 naming the terminal limit", ptyDaytonaLimit+1, err)
	}
	if err := dsb.Process.KillPtySession(ctx, "uc388-0"); err != nil {
		t.Fatalf("kill: %v", err)
	}
	if _, err := dsb.Process.CreatePtySession(ctx, over); err != nil {
		t.Fatalf("create after a kill: %v", err)
	}
}

// UC-389 — a terminal keeps running when its client disconnects, keeps
// writing, and the client reconnects to the same shell and sees what it
// missed.
func TestParityDaytonaTerminalReconnectLive(t *testing.T) {
	harness.Require(t, sc, "UC-389")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dsb := ptySandbox(t, ctx)

	handle := ptyOpen(t, ctx, dsb, "uc389", true)
	t.Cleanup(func() { _ = dsb.Process.KillPtySession(context.Background(), "uc389") })
	ptySend(t, handle, `MARK=$((6*7)); echo "pid=$$"`)
	pid := ptyReadUntil(t, handle, regexp.MustCompile(`pid=(\d+)`))
	ptySettle(t, handle)
	ptySend(t, handle, `(sleep 3; echo "away=$((MARK+1))") &`)
	ptySettle(t, handle)
	if err := handle.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}

	time.Sleep(6 * time.Second) // the job writes while no client is connected
	if info, err := dsb.Process.GetPtySessionInfo(ctx, "uc389"); err != nil || info.ID != "uc389" {
		t.Fatalf("GetPtySessionInfo while disconnected = %+v, %v", info, err)
	}

	again := ptyOpen(t, ctx, dsb, "uc389", false)
	ptyReadUntil(t, again, regexp.MustCompile(`away=(43)`))
	ptySettle(t, again)
	ptySend(t, again, `echo "again=$MARK-$$"`)
	if got := ptyReadUntil(t, again, regexp.MustCompile(`again=(\d+-\d+)`)); got != "42-"+pid {
		t.Fatalf("after reconnect = %q, want the same shell (42-%s)", got, pid)
	}
}
