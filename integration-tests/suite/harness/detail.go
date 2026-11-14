package harness

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// A use case's measurements, for its report row.
//
// report/gen.go gives a pass row no text of its own: the reason column is
// for skips and fails. A case whose numbers are the point (UC-171's
// latency, read side by side across the routing A/B) logs them as one
// marker line, and gen joins that line to the row the same way it joins the
// ucid= and invariant= markers. The line is the only channel from a
// flat-named test to its row.

// detailMarkerRE matches the line ReportDetail logs anywhere in an output
// line (go test prefixes t.Log output with "file.go:NN: "). Keep the prefix
// in sync with FormatDetailMarker; gen parses with ParseDetailMarker, so
// the two cannot drift apart.
var detailMarkerRE = regexp.MustCompile(`ucdetail=(.*)$`)

// FormatDetailMarker renders the marker line. The detail is flattened to one
// line: go test -json splits output on newlines, and a second line would
// reach the report as a stray reason.
func FormatDetailMarker(detail string) string {
	return "ucdetail=" + oneLine(detail)
}

// ParseDetailMarker returns the detail a marker line carries.
func ParseDetailMarker(line string) (string, bool) {
	m := detailMarkerRE.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
	if m == nil {
		return "", false
	}
	d := strings.TrimSpace(m[1])
	return d, d != ""
}

// ReportDetail logs a measurement for the use case's report row. Call it
// before the case's assertions, so a failing row carries its numbers too.
func ReportDetail(t testing.TB, format string, args ...any) {
	t.Helper()
	t.Log(FormatDetailMarker(fmt.Sprintf(format, args...)))
}
