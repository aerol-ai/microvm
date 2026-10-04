package agenttools

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// DefaultMaxOutputBytes bounds the output kept per stream (stdout, stderr)
// for one exec: head 4 KiB + tail 12 KiB. Errors and summaries live at the
// end of output, so the tail gets the larger share. The bound protects the
// model's context window and the MCP process's memory against `yes`-style
// floods (§5.3).
const DefaultMaxOutputBytes = 16 * 1024

// headTail keeps the first quarter and the last three quarters of a byte
// stream within a fixed budget, counting what it drops in between. Memory is
// fixed at the budget no matter how much is written.
type headTail struct {
	headCap int
	tailCap int
	head    []byte
	tail    []byte // ring buffer once full
	tailPos int    // next write index into tail when full
	tailFul bool
	total   int64
}

func newHeadTail(max int) *headTail {
	if max <= 0 {
		max = DefaultMaxOutputBytes
	}
	headCap := max / 4
	return &headTail{headCap: headCap, tailCap: max - headCap}
}

func (h *headTail) Write(p []byte) (int, error) {
	n := len(p)
	h.total += int64(n)
	if room := h.headCap - len(h.head); room > 0 {
		take := min(room, len(p))
		h.head = append(h.head, p[:take]...)
		p = p[take:]
	}
	if len(p) == 0 || h.tailCap == 0 {
		return n, nil
	}
	if len(p) >= h.tailCap {
		h.tail = append(h.tail[:0], p[len(p)-h.tailCap:]...)
		h.tailPos = 0
		h.tailFul = true
		return n, nil
	}
	if !h.tailFul {
		room := h.tailCap - len(h.tail)
		if len(p) <= room {
			h.tail = append(h.tail, p...)
			if len(h.tail) == h.tailCap {
				h.tailFul = true
				h.tailPos = 0
			}
			return n, nil
		}
		h.tail = append(h.tail, p[:room]...)
		p = p[room:]
		h.tailFul = true
		h.tailPos = 0
	}
	for len(p) > 0 {
		c := copy(h.tail[h.tailPos:], p)
		p = p[c:]
		h.tailPos = (h.tailPos + c) % h.tailCap
	}
	return n, nil
}

// kept is the number of bytes held (head + tail).
func (h *headTail) kept() int64 { return int64(len(h.head) + len(h.tail)) }

// Dropped is how many bytes were discarded between head and tail.
func (h *headTail) Dropped() int64 { return h.total - h.kept() }

// String renders head, a marker if anything was dropped, then tail. Cut
// points are moved to rune boundaries so the result is valid UTF-8 when the
// input was.
func (h *headTail) String() string {
	tail := h.tail
	if h.tailFul && h.tailPos != 0 {
		tail = append(append([]byte(nil), h.tail[h.tailPos:]...), h.tail[:h.tailPos]...)
	}
	dropped := h.Dropped()
	if dropped == 0 {
		return string(h.head) + string(tail)
	}
	head := trimIncompleteRuneEnd(h.head)
	tail = trimIncompleteRuneStart(tail)
	var b strings.Builder
	b.Grow(len(head) + len(tail) + 64)
	b.Write(head)
	b.WriteString("\n[... ")
	b.WriteString(formatBytes(dropped))
	b.WriteString(" omitted ...]\n")
	b.Write(tail)
	return b.String()
}

// Truncated reports whether output was dropped.
func (h *headTail) Truncated() bool { return h.Dropped() > 0 }

// boundText applies the head/tail bound to text that arrived whole (the
// buffered exec path, process logs).
func boundText(s string, max int) (string, bool, int64) {
	h := newHeadTail(max)
	_, _ = h.Write([]byte(s))
	return h.String(), h.Truncated(), h.Dropped()
}

func trimIncompleteRuneEnd(b []byte) []byte {
	for i := 0; i < utf8.UTFMax && len(b) > 0; i++ {
		r, size := utf8.DecodeLastRune(b)
		if r != utf8.RuneError || size > 1 {
			return b
		}
		b = b[:len(b)-1]
	}
	return b
}

func trimIncompleteRuneStart(b []byte) []byte {
	for i := 0; i < utf8.UTFMax && len(b) > 0; i++ {
		r, size := utf8.DecodeRune(b)
		if r != utf8.RuneError || size > 1 {
			return b
		}
		b = b[1:]
	}
	return b
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return formatUnit(n, 1<<20, "MiB")
	case n >= 1<<10:
		return formatUnit(n, 1<<10, "KiB")
	}
	return strconv.FormatInt(n, 10) + " bytes"
}

func formatUnit(n, unit int64, suffix string) string {
	whole := n / unit
	tenth := (n % unit) * 10 / unit
	if tenth == 0 {
		return strconv.FormatInt(whole, 10) + " " + suffix
	}
	return strconv.FormatInt(whole, 10) + "." + strconv.FormatInt(tenth, 10) + " " + suffix
}

// linuxSignalNumbers maps the signal names toolboxd reports for a killed
// command onto their Linux numbers, for the 128+n exit code agents know from
// shells and `docker exec`. toolboxd reports Go's syscall.Signal String()
// ("killed", "terminated"); SIG-prefixed and bare forms are accepted too.
// Sandboxes are Linux; the table is fixed so the CLI computes the same code
// when it runs on macOS or Windows.
var linuxSignalNumbers = map[string]int{
	"hangup": 1, "hup": 1,
	"interrupt": 2, "int": 2,
	"quit":                3,
	"illegal instruction": 4, "ill": 4,
	"trace/breakpoint trap": 5, "trap": 5,
	"aborted": 6, "abrt": 6, "abort": 6,
	"bus error": 7, "bus": 7,
	"floating point exception": 8, "fpe": 8,
	"killed": 9, "kill": 9,
	"user defined signal 1": 10, "usr1": 10,
	"segmentation fault": 11, "segv": 11,
	"user defined signal 2": 12, "usr2": 12,
	"broken pipe": 13, "pipe": 13,
	"alarm clock": 14, "alrm": 14,
	"terminated": 15, "term": 15,
}

// signalExitCode returns 128+n for a known signal name, or 0 if unknown.
func signalExitCode(signal string) int {
	name := strings.ToLower(strings.TrimSpace(signal))
	name = strings.TrimPrefix(name, "sig")
	if n, ok := linuxSignalNumbers[name]; ok {
		return 128 + n
	}
	return 0
}
