package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// The exporter writes one object per flushed batch, up to one a second per
// node, so a busy node-day is tens of thousands of objects. Read one GET at
// a time that is hours per node-day from outside the region: the cost is
// round trips, not bytes. The S3 source therefore downloads ahead of the
// verifier, a bounded number at a time.
//
// It changes when a batch is read, never which: every batch of every day
// the verifier asks for is still downloaded and handed over, in the order
// it asks. Nothing is skipped by name or time. A batch's name is
// <node>_<offset>_<hash>.jsonl and says nothing about when its records were
// written, and the verifier needs every batch of a day anyway: the day's
// index (both ends of every batch) is how it tells where the evidence
// starts from a re-send that starts inside another batch (auditlog
// chainStart), and a tampered batch it never reads cannot fail.

const (
	// auditFetchDefaultConcurrency is how many batches one node's walk
	// downloads at once. 32 parallel GETs hide a 30 ms round trip behind
	// local parsing and stay far below S3's per-prefix request rate.
	auditFetchDefaultConcurrency = 32
	// auditFetchMaxConcurrency bounds --fetch-concurrency: each download
	// holds a connection and a spool file open.
	auditFetchMaxConcurrency = 256
	// auditFetchAheadFactor sets the read-ahead cap, per worker: batches
	// downloaded or downloading but not yet handed to the verifier. Two
	// keeps every worker busy while the verifier waits on one slow GET, and
	// stops a slow verifier from spooling the whole day ahead of itself.
	auditFetchAheadFactor = 2
)

// s3Export reads an S3 export a day at a time. A day's batches are spooled
// to a temporary directory as they are downloaded, because the verifier
// reads each batch twice (once for its ends, once to walk it) and may read
// some a third time; the spool is dropped when the next day starts and the
// directory when the walk ends.
//
// One goroutine, the walk's, calls every method; it alone decides what to
// download next, so nothing but the hand-off of a finished download is
// shared with the workers.
type s3Export struct {
	api            *s3.Client
	bucket, prefix string
	now            time.Time
	dir            string
	workers        int
	ahead          int
	cur            *spoolDay
}

// spoolDay is one day's batches: listed, downloading, or spooled.
type spoolDay struct {
	nodeID, day string
	ctx         context.Context
	stop        context.CancelFunc
	wg          sync.WaitGroup
	// jobs holds batches handed to the workers and not yet started. Never
	// more than ahead are outstanding, so a send never blocks.
	jobs  chan *spoolSlot
	order []*spoolSlot
	slots map[string]*spoolSlot
	// next is the first batch in order not yet considered for download;
	// outstanding counts the prefetched batches the verifier has not
	// opened yet, which the read-ahead cap bounds.
	next, outstanding int
}

// spoolSlot is one batch. A worker sets path or err and then closes ready,
// which publishes them; the other fields belong to the walk's goroutine.
type spoolSlot struct {
	name  string
	ready chan struct{}
	path  string
	err   error
	// claimed: a worker or the verifier itself is downloading it, so no
	// one else may. prefetched: by a worker, counted in outstanding.
	claimed, prefetched bool
	// opened: the verifier has had it at least once.
	opened bool
}

func newS3Export(api *s3.Client, bucket, prefix string, now time.Time, concurrency int) (auditlog.ExportSource, func(), error) {
	dir, err := os.MkdirTemp("", "aerolvm-audit-verify-")
	if err != nil {
		return nil, nil, err
	}
	concurrency = max(concurrency, 1)
	e := &s3Export{api: api, bucket: bucket, prefix: prefix, now: now, dir: dir, workers: concurrency, ahead: auditFetchAheadFactor * concurrency}
	return e, e.close, nil
}

// close stops any download still running, then removes everything spooled.
// The walk calls it on every exit: success, an error, or a cancelled ctx.
func (e *s3Export) close() {
	e.endDay()
	_ = os.RemoveAll(e.dir)
}

// Days walks the calendar rather than listing: the layout puts each day
// under its own prefix, so an empty day costs one empty list.
func (e *s3Export) Days(_ context.Context, _, from string) ([]string, error) {
	return calendarDays(from, e.now)
}

// Batches lists one day and starts downloading it, in the order listed:
// the order the verifier indexes the day in. The downloads run under ctx,
// so cancelling the walk cancels them.
func (e *s3Export) Batches(ctx context.Context, nodeID, day string) ([]string, error) {
	if d := e.cur; d != nil && (d.nodeID != nodeID || d.day != day) {
		e.endDay()
	}
	t, err := time.Parse("2006-01-02", day)
	if err != nil {
		return nil, err
	}
	prefix := auditexport.DayPrefix(e.prefix, nodeID, t)
	in := &s3.ListObjectsV2Input{Bucket: aws.String(e.bucket), Prefix: aws.String(prefix)}
	var names []string
	for {
		out, err := e.api.ListObjectsV2(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("list s3://%s/%s: %w", e.bucket, prefix, err)
		}
		for _, o := range out.Contents {
			if name := strings.TrimPrefix(aws.ToString(o.Key), prefix); strings.HasSuffix(name, ".jsonl") {
				names = append(names, name)
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		in.ContinuationToken = out.NextContinuationToken
	}
	if e.cur == nil {
		e.startDay(ctx, nodeID, day, names)
	}
	return names, nil
}

// startDay starts the workers and hands them the first ahead batches.
func (e *s3Export) startDay(ctx context.Context, nodeID, day string, names []string) {
	ctx, stop := context.WithCancel(ctx)
	d := &spoolDay{nodeID: nodeID, day: day, ctx: ctx, stop: stop, jobs: make(chan *spoolSlot, e.ahead), slots: make(map[string]*spoolSlot, len(names))}
	for _, name := range names {
		if _, dup := d.slots[name]; !dup {
			s := &spoolSlot{name: name, ready: make(chan struct{})}
			d.slots[name] = s
			d.order = append(d.order, s)
		}
	}
	e.cur = d
	workers := min(e.workers, len(d.order))
	d.wg.Add(workers)
	for range workers {
		go func() {
			defer d.wg.Done()
			for {
				select {
				case s := <-d.jobs:
					s.path, s.err = e.fetch(ctx, nodeID, day, s.name)
					close(s.ready)
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	e.dispatch(d)
}

// dispatch hands the workers the next batches in order until ahead of them
// are outstanding.
func (e *s3Export) dispatch(d *spoolDay) {
	for d.outstanding < e.ahead && d.next < len(d.order) {
		s := d.order[d.next]
		d.next++
		if s.claimed {
			// The verifier asked for it out of order and read it itself.
			continue
		}
		s.claimed, s.prefetched = true, true
		d.outstanding++
		d.jobs <- s
	}
}

// endDay stops the day's downloads, waits for them, and removes its spool.
func (e *s3Export) endDay() {
	d := e.cur
	if d == nil {
		return
	}
	e.cur = nil
	d.stop()
	d.wg.Wait()
	for _, s := range d.slots {
		if s.path != "" {
			_ = os.Remove(s.path)
		}
	}
}

// Open hands over one batch: from the spool when it is there, after its
// download when one is running, and otherwise by downloading it here and
// now. A batch is downloaded at most once a day, and the error of a failed
// download is the error every Open of it returns.
func (e *s3Export) Open(ctx context.Context, nodeID, day, name string) (io.ReadCloser, error) {
	d := e.cur
	if d == nil || d.nodeID != nodeID || d.day != day {
		// Not the day being walked (the verifier never asks for one): read
		// it through a file that goes when it is closed.
		p, err := e.fetch(ctx, nodeID, day, name)
		if err != nil {
			return nil, err
		}
		f, err := os.Open(p)
		if err != nil {
			_ = os.Remove(p)
			return nil, err
		}
		return removeOnClose{f}, nil
	}
	s, ok := d.slots[name]
	if !ok {
		// Not in the listing (written since): read it here, and keep it.
		s = &spoolSlot{name: name, ready: make(chan struct{})}
		d.slots[name] = s
	}
	if !s.claimed {
		s.claimed = true
		s.path, s.err = e.fetch(ctx, nodeID, day, name)
		close(s.ready)
	}
	select {
	case <-s.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.ctx.Done():
		return nil, d.ctx.Err()
	}
	if !s.opened {
		s.opened = true
		if s.prefetched {
			// Handed over: the workers may start one more.
			d.outstanding--
			e.dispatch(d)
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	return os.Open(s.path)
}

// fetch downloads one batch into a new spool file and returns its path. It
// streams, so memory does not grow with the batch, and leaves no file
// behind when it fails.
func (e *s3Export) fetch(ctx context.Context, nodeID, day, name string) (string, error) {
	t, err := time.Parse("2006-01-02", day)
	if err != nil {
		return "", err
	}
	key := auditexport.DayPrefix(e.prefix, nodeID, t) + name
	out, err := e.api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(e.bucket), Key: aws.String(key)})
	if err != nil {
		return "", fmt.Errorf("read s3://%s/%s: %w", e.bucket, key, err)
	}
	defer out.Body.Close()
	f, err := os.CreateTemp(e.dir, "batch-")
	if err != nil {
		return "", err
	}
	_, err = io.Copy(f, out.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("read s3://%s/%s: %w", e.bucket, key, err)
	}
	return f.Name(), nil
}

// removeOnClose is a spool file nothing else refers to.
type removeOnClose struct{ *os.File }

func (r removeOnClose) Close() error {
	err := r.File.Close()
	_ = os.Remove(r.File.Name())
	return err
}
