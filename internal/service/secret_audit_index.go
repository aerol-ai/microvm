package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// The audit read path used to answer "the next page for sandbox X" by
// scanning and hash-verifying every retained record on the node — O(fleet
// events) per request, at 8 concurrent slots. The index below turns that into
// O(page): the writer records where each line landed, the reader asks the
// index which lines a page needs and reads only those. It is strictly
// derived data. The JSONL and its hash chain remain the evidence; the index
// never changes what is returned, only how much of the file is touched to
// find it, and any disagreement between the two throws the index away and
// rebuilds it from the file in the background while reads fall back to the
// scan.
//
// Write path: the sink appends a batch under the audit flock, then (outside
// the lock, on the writer goroutine, never on a request path) hands the
// batch's offsets to onAppended, which extends the affected posting lists in
// one SQLite transaction. Retention drops a byte prefix and prepends a
// checkpoint, so it re-bases the index by a constant delta instead of
// rebuilding it (onPruned). Anything the hooks cannot handle inline — a gap
// between what is indexed and what was appended, a failed transaction, a
// rewrite that was not a pure prefix drop — degrades the index to not-ready
// and wakes the maintainer, which is the single recovery path.

const (
	// secretAuditIndexChunkEntries bounds one posting-list row. Large enough
	// that a hot sandbox rewrites one ~16KB row per append batch, small
	// enough that trimming a straddling chunk after retention is cheap.
	secretAuditIndexChunkEntries = 2048
	// secretAuditIndexSliceBytes is how much file a rebuild indexes per
	// transaction. The commit holds the audit flock (so a concurrent
	// retention rename cannot slip between "read this generation" and
	// "record offsets for it"); a slice this size commits in milliseconds.
	secretAuditIndexSliceBytes = 8 << 20
	secretAuditIndexRetryMin   = time.Second
	secretAuditIndexRetryMax   = time.Minute
)

var (
	secretAuditIndexReadyGauge    = expvar.NewInt("aerolvm_audit_index_ready")
	secretAuditIndexLagBytes      = expvar.NewInt("aerolvm_audit_index_lag_bytes")
	secretAuditIndexRebuildsTotal = expvar.NewInt("aerolvm_audit_index_rebuilds_total")
	secretAuditIndexWriteFailures = expvar.NewInt("aerolvm_audit_index_write_failures_total")
	secretAuditIndexChainBreaks   = expvar.NewInt("aerolvm_audit_index_chain_breaks_total")

	errSecretAuditIndexGenerationChanged = errors.New("secret audit file generation changed during indexing")
	errSecretAuditIndexChainBreak        = errors.New("secret audit chain break while indexing")
)

// secretAuditIndexedLine is one appended record with where it landed.
type secretAuditIndexedLine struct {
	offset, length int64
	raw            []byte
	ev             SecretAuditEvent
}

func (l secretAuditIndexedLine) end() int64 { return l.offset + l.length }

// secretAuditPruneShift describes what retention did to the file so the
// index can follow it without re-reading the kept lines.
type secretAuditPruneShift struct {
	generation     string // of the rewritten file
	floor          int64  // old offset of the first kept line (everything below was dropped)
	delta          int64  // new offset - old offset for every kept line
	checkpointLen  int64  // bytes of the checkpoint line now at offset 0
	checkpointHash string
	// exact is false when the rewrite was not a pure prefix drop (a kept
	// line was re-normalized), in which case offsets moved unevenly and the
	// index must be rebuilt instead of shifted.
	exact bool
}

type secretAuditIndexer struct {
	st     *store.Store
	sink   *fileAuditSink
	logger *slog.Logger
	// mu serializes every index writer: the append hook, the retention
	// shift, and the maintainer's commits.
	mu sync.Mutex
	// meta mirrors the stored coverage while ready. Guarded by mu.
	meta  store.SecretAuditIndexMeta
	ready atomic.Bool
	// broken latches a hash-chain break seen while indexing. The index stays
	// off until restart: the file needs an operator, not a retry loop.
	broken atomic.Bool
	// forceRebuild makes the maintainer discard the stored index even if it
	// still validates: set when a read proved an entry wrong, which the
	// boundary checks cannot see.
	forceRebuild atomic.Bool
	closed       atomic.Bool
	kick         chan struct{}
	stop         chan struct{}
	done         sync.WaitGroup
	// retryDelay backs off maintainer retries after a failed pass.
	retryDelay time.Duration
	// testSleep, when set, replaces the maintainer's retry sleep.
	testSleep func(time.Duration)
}

func newSecretAuditIndexer(st *store.Store, sink *fileAuditSink, logger *slog.Logger) *secretAuditIndexer {
	return &secretAuditIndexer{
		st:     st,
		sink:   sink,
		logger: logger,
		kick:   make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}
}

// start launches the maintainer and asks it to validate the stored index
// against the file. Reads fall back to the scan until it reports ready.
func (i *secretAuditIndexer) start() {
	i.done.Add(1)
	go i.run()
	i.wake()
}

func (i *secretAuditIndexer) Close() {
	if i == nil || !i.closed.CompareAndSwap(false, true) {
		return
	}
	close(i.stop)
	i.done.Wait()
}

func (i *secretAuditIndexer) isReady() bool { return i != nil && i.ready.Load() }

func (i *secretAuditIndexer) wake() {
	select {
	case i.kick <- struct{}{}:
	default:
	}
}

func (i *secretAuditIndexer) setReady(meta store.SecretAuditIndexMeta, lag int64) {
	i.meta = meta
	i.ready.Store(true)
	secretAuditIndexReadyGauge.Set(1)
	secretAuditIndexLagBytes.Set(lag)
}

// degradeLocked takes the index out of service and hands recovery to the
// maintainer. Caller holds mu.
func (i *secretAuditIndexer) degradeLocked(reason string, err error) {
	i.ready.Store(false)
	secretAuditIndexReadyGauge.Set(0)
	if i.logger != nil {
		i.logger.Warn("secret audit index degraded; rebuilding in background", "reason", reason, "err", err)
	}
	if !i.broken.Load() {
		i.wake()
	}
}

// onAppended extends the index with one appended batch. Runs on the audit
// writer goroutine after the flock is released; never on a request path.
func (i *secretAuditIndexer) onAppended(lines []secretAuditIndexedLine) {
	if i == nil || len(lines) == 0 || i.closed.Load() {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.ready.Load() {
		return // the maintainer's catch-up covers whatever we skip here
	}
	first, last := lines[0], lines[len(lines)-1]
	switch {
	case first.offset == i.meta.IndexedThrough:
	case last.end() <= i.meta.IndexedThrough:
		return // the maintainer already indexed this batch (ready flipped mid-append)
	default:
		i.degradeLocked("append offset does not continue the index", fmt.Errorf("indexed through %d, batch starts at %d", i.meta.IndexedThrough, first.offset))
		return
	}
	ctx := context.Background()
	next, chunks, err := i.buildLocked(ctx, i.meta, lines)
	if err != nil {
		if errors.Is(err, errSecretAuditIndexChainBreak) {
			i.markBrokenLocked(err)
			return
		}
		secretAuditIndexWriteFailures.Add(1)
		i.degradeLocked("build index entries", err)
		return
	}
	if err := i.st.WriteSecretAuditIndex(ctx, i.meta, next, chunks); err != nil {
		secretAuditIndexWriteFailures.Add(1)
		i.degradeLocked("write index", err)
		return
	}
	i.setReady(next, 0)
}

// markBroken latches the chain-break state from outside the indexer (the
// boot-time background verification).
func (i *secretAuditIndexer) markBroken(err error) {
	if i == nil {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.broken.Load() {
		i.markBrokenLocked(err)
	}
}

func (i *secretAuditIndexer) markBrokenLocked(err error) {
	secretAuditIndexChainBreaks.Add(1)
	i.broken.Store(true)
	i.ready.Store(false)
	secretAuditIndexReadyGauge.Set(0)
	if i.logger != nil {
		i.logger.Error("secret audit chain break detected while indexing; index disabled until restart", "err", err)
	}
}

// onPruned re-bases the index after retention rewrote the file. Runs on the
// audit writer goroutine inside the flock that performed the rename, so no
// reader or maintainer can observe the new file with the old offsets.
func (i *secretAuditIndexer) onPruned(shift secretAuditPruneShift) {
	if i == nil || i.closed.Load() {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.ready.Load() {
		return // an in-flight rebuild re-checks the generation before each commit
	}
	if !shift.exact {
		i.degradeLocked("retention rewrite was not a pure prefix drop", nil)
		return
	}
	next := store.SecretAuditIndexMeta{Generation: shift.generation}
	if i.meta.IndexedThrough <= shift.floor {
		// Every indexed byte was dropped; the next line to index is the
		// first retained one, which legitimately does not link to the
		// checkpoint's predecessor.
		next.IndexedThrough = shift.checkpointLen
		next.LastLineOffset = 0
		next.LastEventHash = shift.checkpointHash
		next.AllowBreak = true
	} else {
		next.IndexedThrough = i.meta.IndexedThrough + shift.delta
		next.LastLineOffset = i.meta.LastLineOffset + shift.delta
		next.LastEventHash = i.meta.LastEventHash
		next.AllowBreak = i.meta.AllowBreak
	}
	if err := i.st.ShiftSecretAuditIndex(context.Background(), shift.floor, shift.delta, next); err != nil {
		secretAuditIndexWriteFailures.Add(1)
		i.degradeLocked("shift index after retention", err)
		return
	}
	i.setReady(next, 0)
}

// lookup returns the posting lists a page may need, or ok=false when the
// index cannot serve (not ready). The caller checks meta.Generation against
// the file it holds open.
func (i *secretAuditIndexer) lookup(ctx context.Context, key store.SecretAuditIndexKey, minTime int64) (store.SecretAuditIndexMeta, []store.SecretAuditIndexChunk, bool, error) {
	if !i.isReady() {
		return store.SecretAuditIndexMeta{}, nil, false, nil
	}
	return i.st.ReadSecretAuditIndex(ctx, key, minTime)
}

// reportCorrupt is the read path telling us an entry pointed at something
// that was not the record it promised. The request falls back to the scan;
// we rebuild.
func (i *secretAuditIndexer) reportCorrupt(err error) {
	if i == nil {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.forceRebuild.Store(true)
	if i.ready.Load() {
		i.degradeLocked("index entry did not match the file", err)
	} else {
		i.wake()
	}
}

func (i *secretAuditIndexer) run() {
	defer i.done.Done()
	for {
		select {
		case <-i.stop:
			return
		case <-i.kick:
		}
		select {
		case <-i.stop:
			return // stop wins over a pending kick
		default:
		}
		if i.broken.Load() || i.isReady() {
			continue
		}
		err := i.catchUp()
		if err == nil {
			i.retryDelay = 0
			continue
		}
		if errors.Is(err, errSecretAuditIndexChainBreak) {
			continue // latched broken; nothing to retry
		}
		if i.retryDelay == 0 {
			i.retryDelay = secretAuditIndexRetryMin
		} else {
			i.retryDelay = min(i.retryDelay*2, secretAuditIndexRetryMax)
		}
		if i.logger != nil {
			i.logger.Warn("secret audit index maintenance failed; retrying", "err", err, "retry_in", i.retryDelay)
		}
		if i.testSleep != nil {
			i.testSleep(i.retryDelay)
		} else {
			select {
			case <-i.stop:
				return
			case <-time.After(i.retryDelay):
			}
		}
		i.wake()
	}
}

// catchUp validates the stored index against the file and indexes whatever
// the file has beyond it, a slice per transaction, until they agree; then
// flips ready. A stored index for another file generation, or one whose
// last record no longer sits where it says, is dropped and rebuilt.
func (i *secretAuditIndexer) catchUp() error {
	ctx := context.Background()
	for {
		select {
		case <-i.stop:
			return nil
		default:
		}
		var (
			f    *os.File
			gen  string
			size int64
		)
		err := i.sink.withAuditFileLock(func() error {
			var err error
			f, gen, size, err = openSecretAuditGeneration(i.sink.path)
			return err
		})
		if err != nil {
			if os.IsNotExist(err) {
				// Nothing to index yet. The first append starts the file and
				// the hook records its generation from the first line.
				i.mu.Lock()
				i.setReady(store.SecretAuditIndexMeta{Generation: secretAuditEmptyGeneration, LastEventHash: auditlog.GenesisPrevHash}, 0)
				i.mu.Unlock()
				return nil
			}
			return err
		}
		meta, err := i.validateOrResetLocked(ctx, f, gen, size)
		if err != nil {
			_ = f.Close()
			return err
		}
		if meta.IndexedThrough == size {
			_ = f.Close()
			i.mu.Lock()
			i.setReady(meta, 0)
			i.mu.Unlock()
			return nil
		}
		secretAuditIndexLagBytes.Set(size - meta.IndexedThrough)
		lines, err := readSecretAuditLinesBetween(f, meta.IndexedThrough, size, secretAuditIndexSliceBytes)
		_ = f.Close()
		if err != nil {
			return err
		}
		if len(lines) == 0 {
			// The unindexed tail holds no complete record (a torn tail the
			// sink will cut at its next open). Nothing more to do.
			i.mu.Lock()
			i.setReady(meta, size-meta.IndexedThrough)
			i.mu.Unlock()
			return nil
		}
		// Commit under the flock so retention cannot rename the file between
		// reading this generation and recording offsets for it.
		err = i.sink.withAuditFileLock(func() error {
			cur, err := os.Open(i.sink.path)
			if err != nil {
				return err
			}
			curGen, err := auditFileGeneration(cur)
			_ = cur.Close()
			if err != nil {
				return err
			}
			if curGen != gen {
				return errSecretAuditIndexGenerationChanged
			}
			i.mu.Lock()
			defer i.mu.Unlock()
			next, chunks, err := i.buildLocked(ctx, meta, lines)
			if err != nil {
				return err
			}
			return i.st.WriteSecretAuditIndex(ctx, meta, next, chunks)
		})
		switch {
		case err == nil:
		case errors.Is(err, errSecretAuditIndexGenerationChanged), errors.Is(err, store.ErrSecretAuditIndexStale):
			continue // re-snapshot; validate will reset for the new generation
		case errors.Is(err, errSecretAuditIndexChainBreak):
			i.mu.Lock()
			i.markBrokenLocked(err)
			i.mu.Unlock()
			return err
		default:
			secretAuditIndexWriteFailures.Add(1)
			return err
		}
	}
}

// secretAuditEmptyGeneration is auditFileGeneration's answer for a file
// with no records yet.
const secretAuditEmptyGeneration = "empty"

func (i *secretAuditIndexer) validateOrResetLocked(ctx context.Context, f *os.File, gen string, size int64) (store.SecretAuditIndexMeta, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	meta, ok, err := i.st.GetSecretAuditIndexMeta(ctx)
	if err != nil {
		return meta, err
	}
	force := i.forceRebuild.Swap(false)
	if ok && !force && meta.Generation == gen && meta.IndexedThrough <= size && secretAuditIndexLastLineMatches(f, meta) {
		return meta, nil
	}
	fresh := store.SecretAuditIndexMeta{Generation: gen, LastEventHash: auditlog.GenesisPrevHash}
	if err := i.st.ResetSecretAuditIndex(ctx, fresh); err != nil {
		return fresh, err
	}
	if ok {
		// Only a discarded index counts as a rebuild; the first build on a
		// node that never had one is not an incident.
		secretAuditIndexRebuildsTotal.Add(1)
	}
	if i.logger != nil {
		i.logger.Info("building secret audit index from the local log", "generation", gen, "bytes", size, "had_index", ok, "forced", force)
	}
	return fresh, nil
}

// secretAuditIndexLastLineMatches re-reads the last indexed record and
// checks its hash: one bounded read proves the file still holds what the
// index describes, without scanning either.
func secretAuditIndexLastLineMatches(f *os.File, meta store.SecretAuditIndexMeta) bool {
	if meta.IndexedThrough == 0 {
		return true
	}
	length := meta.IndexedThrough - meta.LastLineOffset
	if length <= 0 || length > secretAuditMaxLineBytes {
		return false
	}
	buf := make([]byte, length)
	if _, err := f.ReadAt(buf, meta.LastLineOffset); err != nil {
		return false
	}
	var ev SecretAuditEvent
	if err := json.Unmarshal(bytes.TrimSpace(buf), &ev); err != nil {
		return false
	}
	return ev.EventHash != "" && ev.EventHash == meta.LastEventHash
}

// buildLocked verifies lines against the chain state carried in meta and
// turns them into posting-list chunk updates plus the meta that follows.
// Caller holds mu.
func (i *secretAuditIndexer) buildLocked(ctx context.Context, meta store.SecretAuditIndexMeta, lines []secretAuditIndexedLine) (store.SecretAuditIndexMeta, []store.SecretAuditIndexChunk, error) {
	verifier := newSecretAuditChainVerifier()
	if meta.IndexedThrough > 0 {
		verifier.prev = meta.LastEventHash
		verifier.allowBreak = meta.AllowBreak
		verifier.started = true
	}
	next := meta
	if next.Generation == secretAuditEmptyGeneration && lines[0].offset == 0 {
		next.Generation = auditGenerationOfLine(lines[0].raw)
	}
	type pending struct {
		key     store.SecretAuditIndexKey
		entries []auditlog.IndexEntry
	}
	var order []store.SecretAuditIndexKey
	byKey := map[store.SecretAuditIndexKey]*pending{}
	for _, l := range lines {
		if err := verifier.Add(l.ev); err != nil {
			return meta, nil, fmt.Errorf("%w at offset %d: %v", errSecretAuditIndexChainBreak, l.offset, err)
		}
		next.IndexedThrough = l.end()
		next.LastLineOffset = l.offset
		next.LastEventHash = l.ev.EventHash
		key, ok := secretAuditIndexKeyFor(l.ev)
		if !ok {
			continue
		}
		p := byKey[key]
		if p == nil {
			p = &pending{key: key}
			byKey[key] = p
			order = append(order, key)
		}
		p.entries = append(p.entries, auditlog.IndexEntry{
			Offset:   l.offset,
			Length:   l.length,
			TimeNano: l.ev.Time.UnixNano(),
			Kind:     secretAuditIndexKind(l.ev),
		})
	}
	next.AllowBreak = verifier.allowBreak
	if len(order) == 0 {
		return next, nil, nil
	}
	tails, err := i.st.LatestSecretAuditIndexChunks(ctx, order)
	if err != nil {
		return meta, nil, err
	}
	var chunks []store.SecretAuditIndexChunk
	for _, key := range order {
		entries := byKey[key].entries
		tail, ok := tails[key]
		if !ok {
			tail = store.SecretAuditIndexChunk{SecretAuditIndexKey: key, Seq: -1}
		}
		for len(entries) > 0 {
			if tail.N >= secretAuditIndexChunkEntries || tail.Seq < 0 {
				tail = store.SecretAuditIndexChunk{SecretAuditIndexKey: key, Seq: tail.Seq + 1}
			}
			take := min(len(entries), secretAuditIndexChunkEntries-tail.N)
			if tail.N == 0 {
				fresh, err := store.NewSecretAuditIndexChunk(key, tail.Seq, entries[:take])
				if err != nil {
					return meta, nil, err
				}
				tail = fresh
			} else if err := tail.Append(entries[:take]); err != nil {
				return meta, nil, err
			}
			chunks = append(chunks, tail)
			entries = entries[take:]
		}
	}
	return next, chunks, nil
}

// secretAuditIndexKeyFor decides which posting list a record belongs to.
// Gap markers go under the empty sandbox id because every page must surface
// them; records that no query can return (a checkpoint, an event with no
// sandbox) are not indexed at all, though the index still advances past them.
func secretAuditIndexKeyFor(ev SecretAuditEvent) (store.SecretAuditIndexKey, bool) {
	if ev.Result == secretAuditResultGap || ev.Kind == secretAuditKindGap {
		return store.SecretAuditIndexKey{}, true
	}
	if ev.SandboxID == "" {
		return store.SecretAuditIndexKey{}, false
	}
	return store.SecretAuditIndexKey{SandboxID: ev.SandboxID, IncarnationID: ev.IncarnationID}, true
}

func secretAuditIndexKind(ev SecretAuditEvent) byte {
	if ev.Result == secretAuditResultGap {
		return auditlog.IndexKindGap
	}
	switch ev.Kind {
	case secretAuditKindSecretOpen:
		return auditlog.IndexKindSecretOpen
	case secretAuditKindEgress:
		return auditlog.IndexKindEgress
	case secretAuditKindGap:
		return auditlog.IndexKindGap
	case secretAuditKindRetentionCheckpoint:
		return auditlog.IndexKindRetentionCheckpoint
	}
	return auditlog.IndexKindOther
}

// secretAuditIndexKindFilter maps a query's kind filter onto the index class
// it may exclude on. Zero means "cannot exclude anything from the index".
func secretAuditIndexKindFilter(kind string) byte {
	switch kind {
	case secretAuditKindSecretOpen:
		return auditlog.IndexKindSecretOpen
	case secretAuditKindEgress:
		return auditlog.IndexKindEgress
	}
	return auditlog.IndexKindOther
}

// openSecretAuditGeneration opens the audit file and reports its generation
// and size. Caller holds the flock so the pair describes one file.
func openSecretAuditGeneration(path string) (*os.File, string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", 0, err
	}
	gen, err := auditFileGeneration(f)
	if err != nil {
		_ = f.Close()
		return nil, "", 0, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, "", 0, err
	}
	return f, gen, st.Size(), nil
}

// readSecretAuditLinesBetween parses the complete records in [from, to),
// stopping after roughly maxBytes so one transaction stays bounded. Records
// are read without the flock: bytes below a size observed under it never
// change (the file is append-only and retention replaces it by rename).
func readSecretAuditLinesBetween(f *os.File, from, to, maxBytes int64) ([]secretAuditIndexedLine, error) {
	if from >= to {
		return nil, nil
	}
	br := bufio.NewReaderSize(io.NewSectionReader(f, from, to-from), 64*1024)
	var (
		lines  []secretAuditIndexedLine
		offset = from
		read   int64
	)
	for read < maxBytes {
		line, consumed, terminated, tooLong, err := readSecretAuditLine(br)
		if err != nil {
			return nil, err
		}
		if consumed == 0 || !terminated {
			break // an unterminated tail is the sink's to repair, never ours to index
		}
		if tooLong {
			return nil, fmt.Errorf("secret audit record at offset %d exceeds %d bytes", offset, secretAuditMaxLineBytes)
		}
		text := bytes.TrimSpace(line)
		start := offset
		offset += consumed
		read += consumed
		if len(text) == 0 {
			continue
		}
		var ev SecretAuditEvent
		if err := json.Unmarshal(text, &ev); err != nil {
			return nil, fmt.Errorf("secret audit record at offset %d is malformed: %w", start, err)
		}
		lines = append(lines, secretAuditIndexedLine{offset: start, length: consumed, raw: text, ev: ev})
	}
	if len(lines) > 0 {
		// Blank lines at the end of the slice are covered by the last
		// record's extent only if they precede it; keep IndexedThrough on
		// a record boundary.
		last := &lines[len(lines)-1]
		if trailing := offset - last.end(); trailing > 0 {
			last.length += trailing
		}
	}
	return lines, nil
}
