package auditlog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Offline verification of one node's audit chain against the heads its
// witness recorded (plans/open-audit-witness.md, D5, D15, D21, D22).
//
// The daemon's boot check compares the local chain with the LATEST
// witnessed head only, so a node that rewrote its history and then
// witnessed a new head matching the rewrite passes it. This verifier closes
// that gap: every head witnessed inside the auditor's window must be
// reached, in witness order, by one walk over the chain records, and the
// records come from the off-node export first and the local log last,
// because retention prunes the local log and leaves only a checkpoint the
// node writes about itself.
//
// Memory is bounded by the witness head list plus one day's batch index,
// never by the record count: the walk streams records through the same
// ChainVerifier the daemon uses.

// Result is a node's verdict.
type Result string

const (
	// ResultPass means every head in the window links to the next one.
	ResultPass Result = "PASS"
	// ResultFail means the evidence contradicts the witness, or is missing
	// for part of the window.
	ResultFail Result = "FAIL"
	// ResultIncomplete means some heads are newer than the evidence and have
	// been waiting for it longer than the allowed lag. Never a pass: a node
	// that stopped exporting could otherwise hide a forged newest head.
	ResultIncomplete Result = "INCOMPLETE"
)

// pendingSkew absorbs the gap between the node's clock (record times) and
// the witness's clock (head times) when deciding whether a head is newer
// than the evidence. A head inside it is pending, never failed.
const pendingSkew = 2 * time.Minute

// maxProblems caps the problems a report lists, so a badly broken history
// still produces a readable report.
const maxProblems = 50

// WitnessedHead is one head as the witness recorded it.
type WitnessedHead struct {
	HeadHex string
	// At is the witness's own time for the head (S3 LastModified).
	At time.Time
	// Ref says where the head is stored, for messages.
	Ref string
}

// ExportSource reads a node's exported batches in the export layout:
// node=<id>/YYYY/MM/DD/<batch>.jsonl. Batch names are never used for order;
// the walk follows the chain itself.
type ExportSource interface {
	// Days lists the UTC dates ("2006-01-02") holding batches for nodeID,
	// ascending, starting at from.
	Days(ctx context.Context, nodeID, from string) ([]string, error)
	// Batches lists one day's batch names.
	Batches(ctx context.Context, nodeID, day string) ([]string, error)
	// Open reads one batch: one JSON event per line.
	Open(ctx context.Context, nodeID, day, batch string) (io.ReadCloser, error)
}

// NodeInput is everything the verifier knows about one node.
type NodeInput struct {
	NodeID string
	// Heads are the witnessed heads in witness order, oldest first. Heads
	// before Since may be included; they are listed, not checked.
	Heads []WitnessedHead
	// Prior is the newest head witnessed before the earliest of Heads, when
	// known: a head equal to it needs no records to link.
	Prior *WitnessedHead
	// Since is the window start the auditor chose. It must come from the
	// auditor, never from the evidence: a node that deletes its oldest
	// records must not shrink what gets checked (D22).
	Since time.Time
	// Now is the verification time; zero means time.Now.
	Now time.Time
	// MaxLag is how long a head may wait for its records to be exported.
	MaxLag time.Duration
	// Export supplies exported batches; nil means none.
	Export ExportSource
	// Local is a copy of the node's secrets.jsonl; nil means none.
	Local io.Reader
	// HiddenKeys are witness keys that carry a delete marker.
	HiddenKeys []string
	// NewestWitnessDay is the newest day with any witnessed version.
	NewestWitnessDay string
}

// PendingHead is a head newer than the evidence.
type PendingHead struct {
	HeadHex string    `json:"head"`
	At      time.Time `json:"witnessed_at"`
	Ref     string    `json:"ref,omitempty"`
	// Stale is true once the head has waited longer than MaxLag.
	Stale bool `json:"stale"`
}

// NodeReport is the verdict for one node and what it rests on.
type NodeReport struct {
	NodeID            string        `json:"node_id"`
	Result            Result        `json:"result"`
	WindowStart       time.Time     `json:"window_start"`
	HeadsBeforeWindow int           `json:"heads_before_window"`
	HeadsInWindow     int           `json:"heads_in_window"`
	HeadsLinked       int           `json:"heads_linked"`
	Pending           []PendingHead `json:"pending,omitempty"`
	Problems          []string      `json:"problems,omitempty"`
	Warnings          []string      `json:"warnings,omitempty"`
	Silent            bool          `json:"silent"`
	RecordsChecked    int64         `json:"records_checked"`
	EvidenceFrom      *time.Time    `json:"evidence_from,omitempty"`
	EvidenceTo        *time.Time    `json:"evidence_to,omitempty"`
	ExportBatches     int           `json:"export_batches"`
	// UnreachedBatches were never on the walk: re-sends and overlapping
	// re-exports of records already checked, or forks.
	UnreachedBatches int `json:"export_batches_unreached"`

	problems int
}

// VerifyNode checks one node. An error means the inputs could not be read;
// a contradiction in what was read is a FAIL in the report instead.
func VerifyNode(ctx context.Context, in NodeInput) (NodeReport, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	v := newNodeVerifier(in)
	if in.Export != nil {
		if err := v.walkExport(ctx); err != nil {
			return v.rep, err
		}
	}
	if in.Local != nil {
		if err := v.walkLocal(in.Local); err != nil {
			return v.rep, err
		}
	}
	v.finish()
	return v.rep, nil
}

type nodeVerifier struct {
	in  NodeInput
	rep NodeReport

	// heads is the in-window list that needs chain evidence: each head that
	// differs from the one witnessed before it. A head equal to its
	// predecessor is linked by definition (a zero-length segment): daily
	// re-ships of an unchanged head (D20) and repairs need no records.
	heads     []WitnessedHead
	positions map[string][]int
	reached   []bool
	cursor    int
	// passed holds the hashes of reached heads, so a head witnessed again
	// after later heads is reported as a rollback rather than as missing.
	passed map[string]bool

	started     bool
	chain       ChainVerifier
	tip         string
	tipTime     time.Time
	gapPending  bool
	lastReached int
	evidenceEnd time.Time

	// peakIndexed is the most batches held in one day's index: the memory
	// bound the tests pin.
	peakIndexed int
}

func newNodeVerifier(in NodeInput) *nodeVerifier {
	v := &nodeVerifier{
		in:          in,
		positions:   map[string][]int{},
		passed:      map[string]bool{},
		lastReached: -1,
		rep:         NodeReport{NodeID: in.NodeID, WindowStart: in.Since.UTC()},
	}
	prev := ""
	if in.Prior != nil {
		prev = in.Prior.HeadHex
	}
	for _, h := range in.Heads {
		inWindow := !h.At.Before(in.Since)
		if !inWindow {
			v.rep.HeadsBeforeWindow++
		} else {
			v.rep.HeadsInWindow++
			if h.HeadHex == prev {
				v.rep.HeadsLinked++
			} else {
				v.positions[h.HeadHex] = append(v.positions[h.HeadHex], len(v.heads))
				v.heads = append(v.heads, h)
			}
		}
		prev = h.HeadHex
	}
	v.reached = make([]bool, len(v.heads))
	for _, k := range in.HiddenKeys {
		v.fail("%s carries a delete marker: the daemon never deletes, so someone tried to hide a witnessed head", k)
	}
	if day := in.NewestWitnessDay; day == "" || day < in.Now.UTC().AddDate(0, 0, -1).Format("2006-01-02") {
		// A running node writes at least one head a day (D20), so a node
		// with none since yesterday stopped shipping: retired, down, or
		// switched to another id to dodge the erasure check (D5).
		v.rep.Silent = true
		v.warn("no head witnessed since %s: the node is silent; reconcile it with the node inventory", orNone(day))
	}
	return v
}

func orNone(s string) string {
	if s == "" {
		return "ever"
	}
	return s
}

func (v *nodeVerifier) fail(format string, args ...any) {
	v.rep.problems++
	if len(v.rep.Problems) < maxProblems {
		v.rep.Problems = append(v.rep.Problems, fmt.Sprintf(format, args...))
	}
}

func (v *nodeVerifier) warn(format string, args ...any) {
	if len(v.rep.Warnings) < maxProblems {
		v.rep.Warnings = append(v.rep.Warnings, fmt.Sprintf(format, args...))
	}
}

func headLabel(h WitnessedHead) string {
	s := short(h.HeadHex) + " (witnessed " + h.At.UTC().Format(time.RFC3339)
	if h.Ref != "" {
		s += ", " + h.Ref
	}
	return s + ")"
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

// feed checks one record in walk order and advances the chain. It returns
// false when the record does not link, which ends the batch it came from.
func (v *nodeVerifier) feed(ev Event, where string) bool {
	if ev.Kind == KindRetentionCheckpoint {
		// A checkpoint is the node's own note about a prune; its prev_hash
		// names a dropped record, which the next real record names too. It
		// is not a link in the chain, and its claims are exactly what this
		// verifier must not trust (D5): check its own hash and step over it.
		if ev.EventHash != HashEvent(strings.TrimSpace(ev.PrevHash), ev) {
			v.fail("%s: retention checkpoint %s has a wrong event_hash", where, ev.EventID)
		}
		return true
	}
	if !v.started {
		v.chain = ResumeChainVerifier(strings.TrimSpace(ev.PrevHash), false)
		v.started = true
		t := ev.Time.UTC()
		v.rep.EvidenceFrom = &t
	}
	if err := v.chain.Add(ev); err != nil {
		v.fail("%s: record %s does not link: %v", where, ev.EventID, err)
		return false
	}
	v.tip = ev.EventHash
	if ev.Time.After(v.tipTime) {
		v.tipTime = ev.Time
	}
	if ev.Time.After(v.evidenceEnd) {
		v.evidenceEnd = ev.Time
		t := ev.Time.UTC()
		v.rep.EvidenceTo = &t
	}
	v.rep.RecordsChecked++
	v.match(ev.EventHash)
	return true
}

// match marks the witnessed head that hash completes, if any. Heads must be
// reached in witness order: one skipped over was never on the chain between
// its neighbours (a rollback, a forged head, or missing evidence).
func (v *nodeVerifier) match(hash string) {
	ps := v.positions[hash]
	i := sort.SearchInts(ps, v.cursor)
	if i == len(ps) {
		return
	}
	p := ps[i]
	for k := v.cursor; k < p; k++ {
		switch {
		case v.reached[k]:
		case v.passed[v.heads[k].HeadHex]:
			v.fail("witnessed head %s was already passed on the chain and was witnessed again before head %s: a rollback, or a node re-shipping its own head over a foreign one", headLabel(v.heads[k]), headLabel(v.heads[p]))
		default:
			v.fail("witnessed head %s is not on the chain before head %s: a forged head, or missing evidence", headLabel(v.heads[k]), headLabel(v.heads[p]))
		}
	}
	if v.gapPending && v.lastReached >= 0 {
		v.fail("no records link witnessed head %s to %s: the export is missing the records between them", headLabel(v.heads[v.lastReached]), headLabel(v.heads[p]))
	}
	v.gapPending = false
	v.reach(p)
	for v.cursor < len(v.heads) && v.heads[v.cursor].HeadHex == hash {
		v.reach(v.cursor)
	}
}

func (v *nodeVerifier) reach(p int) {
	v.reached[p] = true
	v.passed[v.heads[p].HeadHex] = true
	v.lastReached = p
	v.cursor = p + 1
	v.rep.HeadsLinked++
}

// batchInfo is what a day's index keeps per batch: its two ends, never its
// records.
type batchInfo struct {
	name                 string
	firstPrev, firstHash string
	lastHash             string
	firstTime            time.Time
	count                int
	startsWithCheckpoint bool
	consumed             bool
}

func (v *nodeVerifier) walkExport(ctx context.Context) error {
	src := v.in.Export
	// The day before the window holds the records behind its first heads.
	from := v.in.Since.UTC().AddDate(0, 0, -1).Format("2006-01-02")
	days, err := src.Days(ctx, v.in.NodeID, from)
	if err != nil {
		return fmt.Errorf("list export days for node %s: %w", v.in.NodeID, err)
	}
	for _, day := range days {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := v.walkDay(ctx, day); err != nil {
			return err
		}
	}
	return nil
}

func (v *nodeVerifier) walkDay(ctx context.Context, day string) error {
	names, err := v.in.Export.Batches(ctx, v.in.NodeID, day)
	if err != nil {
		return fmt.Errorf("list export batches for node %s on %s: %w", v.in.NodeID, day, err)
	}
	var infos []*batchInfo
	byPrev := map[string][]*batchInfo{}
	linkedTo := map[string]bool{}
	for _, name := range names {
		b, err := v.indexBatch(ctx, day, name)
		if err != nil {
			return err
		}
		if b == nil {
			continue
		}
		infos = append(infos, b)
		byPrev[b.firstPrev] = append(byPrev[b.firstPrev], b)
		linkedTo[b.lastHash] = true
	}
	v.rep.ExportBatches += len(infos)
	if len(infos) > v.peakIndexed {
		v.peakIndexed = len(infos)
	}
	// Earliest first, so every choice below is deterministic.
	sort.SliceStable(infos, func(i, j int) bool {
		if !infos[i].firstTime.Equal(infos[j].firstTime) {
			return infos[i].firstTime.Before(infos[j].firstTime)
		}
		return infos[i].name < infos[j].name
	})
	for {
		var next *batchInfo
		from := 0
		switch {
		case !v.started:
			next = firstRoot(infos, linkedTo)
		default:
			if cands := unconsumed(byPrev[v.tip]); len(cands) > 0 {
				next = v.pick(cands, day)
				break
			}
			b, at, err := v.findContaining(ctx, day, infos)
			if err != nil {
				return err
			}
			if b != nil {
				next, from = b, at
				break
			}
			// Records newer than the tip that do not link to it: the export
			// is missing what joins them. Resume there so later heads are
			// still checked, and remember the gap.
			if r := firstNewer(infos, v.tipTime); r != nil {
				if !v.tipTime.Before(v.in.Since) {
					v.warn("export for node %s has a gap on %s: nothing links record %s (%s) to the batches after it", v.in.NodeID, day, short(v.tip), v.tipTime.UTC().Format(time.RFC3339))
					v.gapPending = true
				}
				v.chain = ResumeChainVerifier(r.firstPrev, false)
				next = r
			}
		}
		if next == nil {
			break
		}
		if err := v.consume(ctx, day, next, from); err != nil {
			return err
		}
	}
	for _, b := range infos {
		if !b.consumed {
			v.rep.UnreachedBatches++
		}
	}
	return nil
}

func unconsumed(bs []*batchInfo) []*batchInfo {
	var out []*batchInfo
	for _, b := range bs {
		if !b.consumed {
			out = append(out, b)
		}
	}
	return out
}

// firstRoot is where evidence starts: the earliest batch that no other batch
// of the day leads into.
func firstRoot(infos []*batchInfo, linkedTo map[string]bool) *batchInfo {
	for _, b := range infos {
		if !b.consumed && !b.startsWithCheckpoint && !linkedTo[b.firstPrev] {
			return b
		}
	}
	// Evidence that starts with a checkpoint (a generation re-exported from
	// its first byte) still starts somewhere: feed steps over the
	// checkpoint and the chain begins at the record after it.
	for _, b := range infos {
		if !b.consumed {
			return b
		}
	}
	return nil
}

// firstNewer is the earliest unconsumed batch whose records start after t.
// Older ones are re-sends of records already checked, not new evidence.
func firstNewer(infos []*batchInfo, t time.Time) *batchInfo {
	for _, b := range infos {
		if !b.consumed && !b.startsWithCheckpoint && b.firstTime.After(t) {
			return b
		}
	}
	return nil
}

// pick chooses among batches that all continue from the tip. Honest
// batches that share a predecessor carry the same records (a re-send, or a
// re-export cut at other offsets), so the longest covers the rest. Two that
// start with different records are a fork: someone exported a second
// history.
//
// A batch that starts with a retention checkpoint names the tip only
// because the checkpoint and the first kept record share a predecessor. It
// is used when nothing else continues the chain (a generation re-exported
// from its first byte), and is otherwise left for findContaining, since it
// may hold records the chosen batch does not.
func (v *nodeVerifier) pick(cands []*batchInfo, day string) *batchInfo {
	var best, fallback *batchInfo
	for _, b := range cands {
		switch {
		case b.startsWithCheckpoint:
			if fallback == nil || b.count > fallback.count {
				fallback = b
			}
		case best == nil || b.count > best.count:
			best = b
		}
	}
	if best == nil {
		return fallback
	}
	for _, b := range cands {
		switch {
		case b == best, b.startsWithCheckpoint:
		case b.firstHash == best.firstHash:
			b.consumed = true
		default:
			v.fail("export for node %s forks on %s: batches %s and %s both follow record %s with different records", v.in.NodeID, day, best.name, b.name, short(v.tip))
		}
	}
	return best
}

// findContaining looks for the tip's successor inside a batch that starts
// earlier: a re-export after a cursor reset cuts batches at new offsets, so
// the record after the tip can sit mid-batch. Only reached when no batch
// starts at the tip, which is rare, so re-reading is fine.
func (v *nodeVerifier) findContaining(ctx context.Context, day string, infos []*batchInfo) (*batchInfo, int, error) {
	for _, b := range infos {
		if b.consumed {
			continue
		}
		at := -1
		err := v.readBatch(ctx, day, b.name, func(i int, ev Event) bool {
			if ev.Kind != KindRetentionCheckpoint && strings.TrimSpace(ev.PrevHash) == v.tip {
				at = i
				return false
			}
			return true
		})
		if err != nil {
			return nil, 0, err
		}
		if at >= 0 {
			return b, at, nil
		}
	}
	return nil, 0, nil
}

func (v *nodeVerifier) consume(ctx context.Context, day string, b *batchInfo, from int) error {
	b.consumed = true
	where := "export " + day + "/" + b.name
	return v.readBatch(ctx, day, b.name, func(i int, ev Event) bool {
		if i < from {
			return true
		}
		return v.feed(ev, where)
	})
}

// indexBatch reads a batch once for its ends. A batch that cannot be parsed
// is a FAIL, not an error: the export store is evidence, and a corrupt or
// overwritten batch is exactly what an attacker with export write access
// would leave.
func (v *nodeVerifier) indexBatch(ctx context.Context, day, name string) (*batchInfo, error) {
	b := &batchInfo{name: name}
	bad := false
	err := v.readBatch(ctx, day, name, func(i int, ev Event) bool {
		if i == 0 {
			b.firstPrev = strings.TrimSpace(ev.PrevHash)
			b.firstHash = ev.EventHash
			b.firstTime = ev.Time
			b.startsWithCheckpoint = ev.Kind == KindRetentionCheckpoint
		}
		b.lastHash = ev.EventHash
		b.count++
		return true
	})
	var pe *batchParseError
	if errors.As(err, &pe) {
		v.fail("export %s/%s: %v", day, name, pe)
		bad = true
		err = nil
	}
	if err != nil || bad || b.count == 0 {
		return nil, err
	}
	return b, nil
}

type batchParseError struct{ msg string }

func (e *batchParseError) Error() string { return e.msg }

// readBatch streams a batch's events to fn until fn returns false.
func (v *nodeVerifier) readBatch(ctx context.Context, day, name string, fn func(int, Event) bool) error {
	rc, err := v.in.Export.Open(ctx, v.in.NodeID, day, name)
	if err != nil {
		return fmt.Errorf("read export batch %s/%s for node %s: %w", day, name, v.in.NodeID, err)
	}
	defer rc.Close()
	br := bufio.NewReaderSize(rc, 64*1024)
	i := 0
	for line := 1; ; line++ {
		raw, consumed, _, tooLong, err := ReadLine(br, MaxLineBytes)
		if err != nil {
			return fmt.Errorf("read export batch %s/%s for node %s: %w", day, name, v.in.NodeID, err)
		}
		if consumed == 0 {
			return nil
		}
		if tooLong {
			return &batchParseError{fmt.Sprintf("line %d is longer than %d bytes", line, MaxLineBytes)}
		}
		text := bytes.TrimSpace(raw)
		if len(text) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(text, &ev); err != nil {
			return &batchParseError{fmt.Sprintf("line %d is not a JSON event: %v", line, err)}
		}
		if !fn(i, ev) {
			return nil
		}
		i++
	}
}

// walkLocal continues the walk through a copy of the node's local log: the
// records not exported yet. Records it shares with the export are skipped;
// the export is the copy the node could not rewrite. With no export at all
// the local log is the whole of the evidence.
func (v *nodeVerifier) walkLocal(r io.Reader) error {
	br := bufio.NewReaderSize(r, 64*1024)
	continuing := !v.started
	var lastTime time.Time
	for line := 1; ; line++ {
		raw, consumed, terminated, tooLong, err := ReadLine(br, MaxLineBytes)
		if err != nil {
			return fmt.Errorf("read the local log: %w", err)
		}
		if consumed == 0 {
			break
		}
		if tooLong {
			v.fail("local log: line %d is longer than %d bytes", line, MaxLineBytes)
			break
		}
		text := bytes.TrimSpace(raw)
		if len(text) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(text, &ev); err != nil {
			if !terminated {
				// A copy taken while the daemon was appending can end in half
				// a line. No witnessed head can name it, so it proves nothing
				// either way.
				v.warn("local log ends in an unterminated, unparseable line (a copy taken mid-write); it was ignored")
				break
			}
			v.fail("local log: line %d is not a JSON event: %v", line, err)
			break
		}
		if ev.Time.After(lastTime) {
			lastTime = ev.Time
		}
		if ev.Kind == KindRetentionCheckpoint {
			// Checked wherever it sits, even where the walk skips over the
			// overlap with the export: a checkpoint with a wrong hash is a
			// tampered local log.
			v.feed(ev, "local log")
			continue
		}
		if !continuing {
			switch {
			case strings.TrimSpace(ev.PrevHash) == v.tip:
				continuing = true
			case ev.EventHash == v.tip:
				continuing = true
				continue
			default:
				continue
			}
		}
		if !v.feed(ev, "local log") {
			break
		}
	}
	if v.started && !continuing && lastTime.After(v.tipTime) {
		v.fail("the local log does not continue the exported chain from record %s (%s): it holds records after that point that link to something else", short(v.tip), v.tipTime.UTC().Format(time.RFC3339))
	}
	return nil
}

// finish classifies every head the walk did not reach and sets the verdict.
func (v *nodeVerifier) finish() {
	for k := v.cursor; k < len(v.heads); k++ {
		h := v.heads[k]
		switch {
		case v.reached[k]:
		case v.passed[h.HeadHex]:
			v.fail("witnessed head %s was already passed on the chain and was witnessed again after later heads: a rollback, or a node re-shipping its own head over a foreign one", headLabel(h))
		case v.evidenceEnd.IsZero() || h.At.After(v.evidenceEnd.Add(-pendingSkew)):
			p := PendingHead{HeadHex: h.HeadHex, At: h.At.UTC(), Ref: h.Ref, Stale: v.in.Now.Sub(h.At) > v.in.MaxLag}
			v.rep.Pending = append(v.rep.Pending, p)
		default:
			v.fail("witnessed head %s is not in the evidence, which runs to %s: a forged head, or records missing from the export and the local log", headLabel(h), v.evidenceEnd.UTC().Format(time.RFC3339))
		}
	}
	switch {
	case v.rep.problems > 0:
		v.rep.Result = ResultFail
		if extra := v.rep.problems - len(v.rep.Problems); extra > 0 {
			v.rep.Problems = append(v.rep.Problems, fmt.Sprintf("... and %d more problems", extra))
		}
	case hasStale(v.rep.Pending):
		v.rep.Result = ResultIncomplete
	default:
		v.rep.Result = ResultPass
	}
}

func hasStale(ps []PendingHead) bool {
	for _, p := range ps {
		if p.Stale {
			return true
		}
	}
	return false
}
