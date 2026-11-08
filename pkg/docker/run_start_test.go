package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestStartReportsTheRunStart: a start reports Docker's State.StartedAt, the
// clock its die and stop events carry, so the service can tell an exit of an
// earlier run (internal/service/run_starts.go). A value Docker does not give,
// or one that cannot be read, is zero and never fails the start.
func TestStartReportsTheRunStart(t *testing.T) {
	const startedAt = "2026-11-07T10:11:12.123456789Z"
	cases := []struct {
		name  string
		state string // the State.StartedAt member, "" for none
		want  time.Time
	}{
		{name: "nanoseconds", state: `,"StartedAt":"` + startedAt + `"`, want: time.Date(2026, 11, 7, 10, 11, 12, 123456789, time.UTC)},
		{name: "offset is kept as the same instant", state: `,"StartedAt":"2026-11-07T15:41:12.5+05:30"`, want: time.Date(2026, 11, 7, 10, 11, 12, 500000000, time.UTC)},
		{name: "never started", state: `,"StartedAt":"0001-01-01T00:00:00Z"`},
		{name: "unreadable", state: `,"StartedAt":"yesterday"`},
		{name: "absent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
			defer closeFn()
			body := strings.Replace(inspectBody("cid", "/sb", ip, true, "running", 7), `"Pid":7`, `"Pid":7`+tc.state, 1)
			d := &fakeDaemon{
				t:            t,
				start:        func() *http.Response { return textResponse(http.StatusNoContent, "") },
				containerGet: func() *http.Response { return textResponse(http.StatusOK, body) },
			}
			c := &Client{
				httpClient:         &http.Client{Transport: d.transport()},
				toolboxClient:      &http.Client{Timeout: 2 * time.Second},
				toolboxPort:        port,
				waitTimeout:        2 * time.Second,
				toolboxWaitTimeout: 2 * time.Second,
			}
			rt, err := c.Start(context.Background(), "sb")
			if err != nil {
				t.Fatalf("Start() = %v", err)
			}
			if !rt.StartedAt.Equal(tc.want) || rt.StartedAt.IsZero() != tc.want.IsZero() {
				t.Fatalf("StartedAt = %v, want %v", rt.StartedAt, tc.want)
			}
		})
	}

	if got := runStartedAt(containerInspect{}); !got.IsZero() {
		t.Fatalf("runStartedAt without a State = %v, want zero", got)
	}
}

// TestEventTimeIsNanoseconds: an event is stamped with timeNano. The legacy
// whole-second "time" alone is left unknown: truncated, a crash just after a
// start would read as before it.
func TestEventTimeIsNanoseconds(t *testing.T) {
	const nano = int64(1762510272123456789)
	cases := []struct {
		name  string
		times string
		want  time.Time
	}{
		{name: "timeNano", times: fmt.Sprintf(`"time":%d,"timeNano":%d`, nano/int64(time.Second), nano), want: time.Unix(0, nano).UTC()},
		{name: "whole seconds only", times: `"time":1762510272`},
		{name: "none", times: `"scope":"local"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := `{"Action":"die","Actor":{"ID":"abcd1234ef567890","Attributes":{"name":"/sb-a","exitCode":"1"}},` + tc.times + `}`
			var raw rawDockerEvent
			if err := json.Unmarshal([]byte(payload), &raw); err != nil {
				t.Fatal(err)
			}
			ev, ok := raw.normalize()
			if !ok {
				t.Fatal("normalize dropped the event")
			}
			if !ev.Time.Equal(tc.want) || ev.Time.IsZero() != tc.want.IsZero() {
				t.Fatalf("Time = %v, want %v", ev.Time, tc.want)
			}
		})
	}
}
