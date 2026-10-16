package auditlog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The chain rules live here, not in the daemon, because two programs must
// judge a chain identically: sandboxd at boot and on every witness check,
// and the offline verifier an auditor runs off the node. A second copy of
// these rules would drift, and the verifier would pass chains the daemon
// rejects (or the reverse). Everything below is standard library only so
// the CLI can import it without the daemon's dependency tree.

const (
	// KindRetentionCheckpoint is the immutable record retention inserts
	// where it dropped a prefix: its PrevHash is the last dropped EventHash,
	// and WitnessedThrough (when set) names the last externally witnessed
	// head the prefix carried.
	KindRetentionCheckpoint = "retention_checkpoint"
	// KindRetentionRedacted is what retention leaves of an expired record
	// it cannot cut out of the chain: its two link hashes and nothing that
	// says who opened what. See RedactForRetention.
	KindRetentionRedacted = "retention_redacted"

	// MaxLineBytes bounds one JSONL record during chain scans; audit lines
	// are metadata-only, so anything larger is corruption, not evidence.
	MaxLineBytes = 1024 * 1024
)

// RedactForRetention is what retention leaves of an expired record that
// sits behind a newer one and so cannot be cut out of the chain: the two link
// hashes, the time and id (so a later prune reclaims it with the prefix and
// an operator can place it), and nothing that says who opened what.
// EventHash is the original — it is what the successor's prev_hash names —
// so the chain still verifies through the stub; the verifier links a stub by
// its stored hashes because the payload that produced them is gone, and
// refuses one that still carries any other field.
func RedactForRetention(ev Event) Event {
	return Event{
		Time:      ev.Time,
		EventID:   ev.EventID,
		Result:    "success",
		Reason:    "prune",
		Kind:      KindRetentionRedacted,
		PrevHash:  ev.PrevHash,
		EventHash: ev.EventHash,
	}
}

// ChainVerifier checks one chain in stream order with O(1) state: the head
// so far, whether the next link may break (right after a retention
// checkpoint), and whether any record has been seen. The zero value is not
// ready; start from NewChainVerifier, or ResumeChainVerifier to continue a
// chain someone already verified up to a known head.
type ChainVerifier struct {
	prev       string
	allowBreak bool
	started    bool
}

// NewChainVerifier starts a verifier at genesis. It is a value so a caller
// can hand a copy to ScanChain and keep its own state unchanged.
func NewChainVerifier() ChainVerifier {
	return ChainVerifier{prev: GenesisPrevHash}
}

// ResumeChainVerifier primes a verifier mid-chain: head is the EventHash of
// the last record already verified, and allowBreak is whether that record
// was a retention checkpoint (whose successor may name a dropped
// predecessor). Checkpoint boot, the export tailer and the read index all
// carry exactly this state across passes instead of re-reading the prefix,
// and a resumed verifier refuses a later retention checkpoint just as one
// that read the prefix itself would.
func ResumeChainVerifier(head string, allowBreak bool) ChainVerifier {
	return ChainVerifier{prev: head, allowBreak: allowBreak, started: true}
}

// Head is the EventHash of the last accepted record, or GenesisPrevHash
// when none has been accepted yet: what the next record's prev_hash must
// name.
func (v *ChainVerifier) Head() string {
	if v == nil {
		return ""
	}
	return v.prev
}

// AllowBreak reports whether the next record may name a predecessor other
// than Head — true only right after a retention checkpoint. Callers persist
// it alongside Head so a resumed pass keeps the same rule.
func (v *ChainVerifier) AllowBreak() bool {
	return v != nil && v.allowBreak
}

// Add validates one immutable event in stream order. The only permitted link
// discontinuity is the first retained event after a retention checkpoint,
// whose predecessor was deliberately removed. Missing hash fields are never
// interpreted as a legacy format: this audit format is intentionally one-way.
func (v *ChainVerifier) Add(ev Event) error {
	if v == nil {
		return errors.New("secret audit chain verifier unavailable")
	}
	storedPrev := strings.TrimSpace(ev.PrevHash)
	if storedPrev == "" {
		return errors.New("prev_hash is missing")
	}
	if ev.EventHash == "" {
		return errors.New("event_hash is missing")
	}
	if ev.Kind == KindRetentionRedacted {
		// Retention kept only this record's links. Its payload is gone, so
		// event_hash cannot be recomputed; the stub is verified by position
		// instead: prev_hash must be the chain so far and event_hash is what
		// the next record must name. A stub can therefore stand only where a
		// record stood — none can be inserted or removed — but its content is
		// no longer provable, which is why one that still carries a payload
		// is rejected rather than trusted.
		if RedactForRetention(ev) != ev {
			return errors.New("retention stub carries payload")
		}
		if storedPrev != v.prev && !v.allowBreak {
			return fmt.Errorf("prev_hash mismatch (got %q want %q)", storedPrev, v.prev)
		}
		v.prev = ev.EventHash
		v.allowBreak = false
		v.started = true
		return nil
	}
	if ev.EventHash != HashEvent(storedPrev, ev) {
		return errors.New("event_hash mismatch")
	}
	if ev.Kind == KindRetentionCheckpoint {
		if v.started {
			return errors.New("retention checkpoint must be the first event")
		}
		v.prev = ev.EventHash
		v.allowBreak = true
		v.started = true
		return nil
	}
	if storedPrev != v.prev && !v.allowBreak {
		return fmt.Errorf("prev_hash mismatch (got %q want %q)", storedPrev, v.prev)
	}
	v.prev = ev.EventHash
	v.allowBreak = false
	v.started = true
	return nil
}

// ScanOptions parameterize one pass. A nil Verifier starts at genesis; a
// primed one continues a chain from Base (checkpoint boot).
type ScanOptions struct {
	// Base is the byte offset in the underlying file where the reader
	// starts; every offset in ChainScan is reported in file coordinates.
	Base int64
	// Verifier, when set, is copied (never mutated) and continued from.
	Verifier *ChainVerifier
	// StartEventID and StartLineOffset describe the record carrying the
	// primed verifier's head, reported back when nothing follows it.
	StartEventID    string
	StartLineOffset int64
	// Probe lists hashes whose presence the scan should report (witness
	// ancestry) — O(len(Probe)) memory instead of O(records).
	Probe []string
}

// ChainScan is one verified pass over an audit JSONL stream.
type ChainScan struct {
	Head    string
	EventID string
	// LastLineStart is the offset of the record carrying Head.
	LastLineStart int64
	// Found reports which probed hashes the pass saw.
	Found map[string]bool
	// WitnessedThrough is the newest retention checkpoint's WitnessedThrough.
	WitnessedThrough string
	// ValidEnd is the byte offset just past the last complete, verified line.
	ValidEnd int64
	// TornBytes is the length of an unterminated, unparseable tail after
	// ValidEnd — what a crash leaves when it interrupts one append write. The
	// writer emits line+'\n' in a single write, so a crash leaves a strict
	// byte-prefix, and no proper prefix of a JSON object is itself valid JSON;
	// that is what makes this the only defect safe to classify as a tear.
	// ScanChain reports a tear rather than failing on it so the daemon's
	// boot repair can cut it back; every other reader must treat a non-zero
	// value as a chain it cannot verify, never quietly trim evidence.
	TornBytes int64
	// MissingNewline reports a complete, verified final record without its
	// terminator (the write stopped exactly between '}' and '\n').
	MissingNewline bool
	// Records counts verified records (blank lines excluded).
	Records int64
	// Redacted counts retention stubs among them: records whose payload
	// retention removed in place. The node never produces one inside the
	// retention window.
	Redacted int64
}

func (scan *ChainScan) markFound(hash string) {
	if scan.Found == nil {
		scan.Found = map[string]bool{}
	}
	scan.Found[hash] = true
}

// ScanChain walks r once, verifying every record against its predecessor.
// Blank lines are tolerated but never alter the chain. r should be
// already bounded (a size snapshot taken under the audit flock) so a
// verification can run while the writer keeps appending. Memory is O(1) in
// the number of records.
func ScanChain(r io.Reader, opts ScanOptions) (ChainScan, error) {
	scan := ChainScan{Head: GenesisPrevHash, ValidEnd: opts.Base, LastLineStart: opts.StartLineOffset}
	br := bufio.NewReaderSize(r, 64*1024)
	verifier := NewChainVerifier()
	if opts.Verifier != nil {
		verifier = *opts.Verifier
		scan.Head = verifier.prev
		scan.EventID = opts.StartEventID
	}
	probe := make(map[string]struct{}, len(opts.Probe))
	for _, h := range opts.Probe {
		if h != "" {
			probe[h] = struct{}{}
		}
	}
	offset := opts.Base
	lineNo := 0
	for {
		line, consumed, terminated, tooLong, err := ReadLine(br, MaxLineBytes)
		if err != nil {
			return scan, err
		}
		if consumed == 0 {
			return scan, nil
		}
		offset += consumed
		if tooLong {
			if !terminated {
				scan.TornBytes = offset - scan.ValidEnd
				return scan, nil
			}
			return scan, fmt.Errorf("secret audit chain line %d exceeds %d bytes", lineNo+1, MaxLineBytes)
		}
		text := bytes.TrimSpace(line)
		if len(text) == 0 {
			// Whitespace is harmless in either position: a terminated blank line
			// is kept, and unterminated trailing whitespace is left for the
			// next append to follow (TrimSpace on read absorbs it).
			if terminated {
				scan.ValidEnd = offset
			}
			continue
		}
		lineNo++
		var ev Event
		if err := json.Unmarshal(text, &ev); err != nil {
			if !terminated {
				scan.TornBytes = offset - scan.ValidEnd
				return scan, nil
			}
			return scan, fmt.Errorf("secret audit chain line %d: malformed json: %w", lineNo, err)
		}
		// A parseable record that does not link is never a tear (see
		// TornBytes) — fail regardless of whether its terminator is present.
		if err := verifier.Add(ev); err != nil {
			return scan, fmt.Errorf("secret audit chain line %d: %w", lineNo, err)
		}
		scan.Head = ev.EventHash
		scan.EventID = ev.EventID
		scan.Records++
		if ev.Kind == KindRetentionRedacted {
			scan.Redacted++
		}
		scan.LastLineStart = offset - consumed
		if _, want := probe[ev.EventHash]; want {
			scan.markFound(ev.EventHash)
		}
		if ev.Kind == KindRetentionCheckpoint && strings.TrimSpace(ev.WitnessedThrough) != "" {
			scan.WitnessedThrough = strings.TrimSpace(ev.WitnessedThrough)
		}
		scan.ValidEnd = offset
		if !terminated {
			scan.MissingNewline = true
			return scan, nil
		}
	}
}

// ReadLine returns one line (terminator included when present) and the
// bytes consumed. A line past max is counted but not retained so a
// NUL-filled or runaway tail cannot balloon the scan. max <= 0 means
// MaxLineBytes; the daemon's spill drain passes its ingest body cap so a
// worker cannot plant a line that fails strict boot.
func ReadLine(br *bufio.Reader, max int64) (line []byte, consumed int64, terminated, tooLong bool, err error) {
	if max <= 0 {
		max = MaxLineBytes
	}
	for {
		chunk, readErr := br.ReadSlice('\n')
		consumed += int64(len(chunk))
		if !tooLong {
			if int64(len(line))+int64(len(chunk)) > max {
				tooLong = true
				line = nil
			} else {
				line = append(line, chunk...)
			}
		}
		switch {
		case readErr == nil:
			return line, consumed, true, tooLong, nil
		case errors.Is(readErr, bufio.ErrBufferFull):
			continue
		case errors.Is(readErr, io.EOF):
			return line, consumed, false, tooLong, nil
		default:
			return nil, consumed, false, tooLong, readErr
		}
	}
}
