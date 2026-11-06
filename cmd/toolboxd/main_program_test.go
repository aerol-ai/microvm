package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"
)

// TestMainProgramStateTransitions pins what /health reports through a main
// program's life (plan L5): none, running, then exited with its code or
// killed with its signal as 128+n, or a start that failed as 127. Only the
// running main program's pid is its end.
func TestMainProgramStateTransitions(t *testing.T) {
	at := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	old := mainProgramClock
	mainProgramClock = func() time.Time { return at }
	t.Cleanup(func() { mainProgramClock = old })

	exited := syscall.WaitStatus(3 << 8)          // exit status 3
	killed := syscall.WaitStatus(syscall.SIGTERM) // terminated by SIGTERM
	cases := []struct {
		name string
		run  func(m *mainProgramState) bool
		want map[string]any
		hit  bool
	}{
		{name: "no command", run: func(*mainProgramState) bool { return false },
			want: map[string]any{"state": "none"}},
		{name: "running", run: func(m *mainProgramState) bool { m.lockForStart(); m.started(42); return false },
			want: map[string]any{"state": "running", "started_at": at.Format(time.RFC3339Nano)}},
		{name: "exited", hit: true, run: func(m *mainProgramState) bool { m.lockForStart(); m.started(42); return m.noteExit(42, exited) },
			want: map[string]any{"state": "exited", "exit_code": 3, "started_at": at.Format(time.RFC3339Nano), "ended_at": at.Format(time.RFC3339Nano)}},
		{name: "killed", hit: true, run: func(m *mainProgramState) bool { m.lockForStart(); m.started(42); return m.noteExit(42, killed) },
			want: map[string]any{"state": "killed", "exit_code": 128 + int(syscall.SIGTERM), "signal": "SIGTERM", "started_at": at.Format(time.RFC3339Nano), "ended_at": at.Format(time.RFC3339Nano)}},
		{name: "another pid is not the main program", run: func(m *mainProgramState) bool { m.lockForStart(); m.started(42); return m.noteExit(43, exited) },
			want: map[string]any{"state": "running", "started_at": at.Format(time.RFC3339Nano)}},
		{name: "ended once", hit: false, run: func(m *mainProgramState) bool {
			m.lockForStart()
			m.started(42)
			m.noteExit(42, exited)
			return m.noteExit(42, killed)
		}, want: map[string]any{"state": "exited", "exit_code": 3, "started_at": at.Format(time.RFC3339Nano), "ended_at": at.Format(time.RFC3339Nano)}},
		{name: "failed to start", run: func(m *mainProgramState) bool { m.lockForStart(); m.failedToStart(); return false },
			want: map[string]any{"state": "exited", "exit_code": 127, "started_at": at.Format(time.RFC3339Nano), "ended_at": at.Format(time.RFC3339Nano)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &mainProgramState{state: mainProgramNone}
			if hit := tc.run(m); hit != tc.hit {
				t.Fatalf("noteExit = %v, want %v", hit, tc.hit)
			}
			got := m.snapshot()
			if len(got) != len(tc.want) {
				t.Fatalf("snapshot = %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("snapshot[%s] = %v, want %v (all: %v)", k, got[k], v, got)
				}
			}
		})
	}
}

// TestHealthShowsTheMainProgram: /health keeps its fields and adds
// main_program, and answers before adoption like the rest of /health.
func TestHealthShowsTheMainProgram(t *testing.T) {
	old := mainProgram
	mainProgram = &mainProgramState{state: mainProgramNone}
	t.Cleanup(func() { mainProgram = old })
	mainProgram.lockForStart()
	mainProgram.started(99)
	mainProgram.noteExit(99, syscall.WaitStatus(0))

	srv := &server{}
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("/health = %d %s", rec.Code, rec.Body.String())
	}
	for _, field := range []string{"status", "version", "exec_drainers", "exec_drainers_at_cap"} {
		if _, ok := body[field]; !ok {
			t.Fatalf("/health lost %s: %v", field, body)
		}
	}
	mp, _ := body["main_program"].(map[string]any)
	if mp["state"] != "exited" || mp["exit_code"] != float64(0) || mp["ended_at"] == nil {
		t.Fatalf("main_program = %v", body["main_program"])
	}
}

// TestStartUserCommandRecordsTheMainProgram: a command that starts is
// running; one that cannot start has ended with 127.
func TestStartUserCommandRecordsTheMainProgram(t *testing.T) {
	old := mainProgram
	t.Cleanup(func() { mainProgram = old; userCommandPID.Store(0) })

	mainProgram = &mainProgramState{state: mainProgramNone}
	startUserCommand(slog.New(slog.NewTextHandler(io.Discard, nil)), []string{"/nonexistent/aerolvm-no-such-binary"})
	if snap := mainProgram.snapshot(); snap["state"] != "exited" || snap["exit_code"] != 127 {
		t.Fatalf("failed start: %v", snap)
	}

	mainProgram = &mainProgramState{state: mainProgramNone}
	startUserCommand(slog.New(slog.NewTextHandler(io.Discard, nil)), []string{"/bin/sh", "-c", "sleep 30"})
	pid := int(userCommandPID.Load())
	t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
	if snap := mainProgram.snapshot(); snap["state"] != "running" || pid <= 0 {
		t.Fatalf("started: %v pid %d", snap, pid)
	}
}
