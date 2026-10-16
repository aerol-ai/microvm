package auditwitness

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// WitnessedHead is one locked version of a node's head key: what the
// offline verifier checks against the chain.
type WitnessedHead struct {
	HeadHex string
	// LastModified is S3's clock, not the node's: a node can neither choose
	// nor change it, which is what makes it the witness time.
	LastModified time.Time
	Key          string
	VersionID    string
	// Day is the UTC date in the key, as the node's clock saw it.
	Day string
}

// History is one node's witnessed heads in witness order, oldest first.
type History struct {
	NodeID string
	Heads  []WitnessedHead
	// HiddenKeys are head keys that carry a delete marker. The daemon never
	// deletes, so each one is an attempt to hide a head.
	HiddenKeys []string
	// NewestDay is the newest day prefix with any version, "" when none: the
	// verifier's "silent node" check, since a live node writes at least one
	// head a day (D20).
	NewestDay string
	// Prior is the newest head from before the days History read, when one
	// exists. A node that was down across the window's start comes back
	// re-shipping that same head, and a head equal to its predecessor needs
	// no records to link; without Prior the verifier would demand records
	// older than its evidence and fail an honest node.
	Prior *WitnessedHead
}

// defaultHistoryConcurrency bounds parallel version reads. Each node ships
// up to 2,880 versions a day; one at a time is far too slow for an audit,
// unbounded is rude to the bucket.
const defaultHistoryConcurrency = 16

// Nodes lists the node ids that have heads under the prefix.
func (r *Reader) Nodes(ctx context.Context) ([]string, error) {
	w := r.w
	prefix := cleanPrefix(w.prefix)
	if prefix != "" {
		prefix += "/"
	}
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(w.bucket), Prefix: aws.String(prefix + "node="), Delimiter: aws.String("/")}
	var ids []string
	for {
		out, err := w.api.ListObjectVersions(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("audit witness reader: list nodes in s3://%s/%s: %w", w.bucket, prefix, err)
		}
		for _, cp := range out.CommonPrefixes {
			id := strings.TrimSuffix(strings.TrimPrefix(aws.ToString(cp.Prefix), prefix+"node="), "/")
			if id != "" {
				ids = append(ids, id)
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		in.KeyMarker, in.VersionIdMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
	sort.Strings(ids)
	return ids, nil
}

// History reads nodeID's heads from the day before since onward, in witness
// order: S3's own version order inside a key, LastModified across keys, ties
// broken by the day key. LastModified alone is not enough: list results
// carry it only to the second, and a re-ship can land in the same second as
// the ship before it (D22). Heads older than the day before since are not
// read at all; the verifier would only list them.
func (r *Reader) History(ctx context.Context, nodeID string, since time.Time) (History, error) {
	w := r.w
	h := History{NodeID: nodeID}
	days, err := w.dayPrefixes(ctx, nodeID)
	if err != nil {
		return h, err
	}
	if len(days) == 0 {
		return h, nil
	}
	h.NewestDay = strings.TrimSuffix(strings.TrimPrefix(days[len(days)-1], "day="), "/")

	prefix := NodePrefix(w.prefix, nodeID)
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(w.bucket), Prefix: aws.String(prefix)}
	if !since.IsZero() {
		// Keys sort by day, so a key marker skips every older day without
		// reading it.
		start := "day=" + since.UTC().AddDate(0, 0, -1).Format("2006-01-02")
		in.KeyMarker = aws.String(prefix + start)
		if prior := newestBefore(days, start); prior != "" {
			if h.Prior, err = w.currentHead(ctx, nodeID, prefix+prior+headFile); err != nil {
				return h, err
			}
		}
	}
	type version struct {
		head WitnessedHead
		etag string
	}
	var (
		perKey  []version
		lastKey string
		all     []version
		hidden  = map[string]bool{}
	)
	flush := func() {
		// S3 lists a key's versions newest first; witness order is oldest
		// first.
		for i := len(perKey) - 1; i >= 0; i-- {
			all = append(all, perKey[i])
		}
		perKey = perKey[:0]
	}
	for {
		out, err := w.api.ListObjectVersions(ctx, in)
		if err != nil {
			return h, fmt.Errorf("audit witness reader: list versions in s3://%s/%s: %w", w.bucket, prefix, err)
		}
		for _, v := range out.Versions {
			key := aws.ToString(v.Key)
			if !strings.HasSuffix(key, "/"+headFile) {
				continue
			}
			if key != lastKey {
				flush()
				lastKey = key
			}
			perKey = append(perKey, version{
				head: WitnessedHead{
					LastModified: aws.ToTime(v.LastModified).UTC(),
					Key:          key,
					VersionID:    aws.ToString(v.VersionId),
					Day:          dayOfKey(key),
				},
				etag: aws.ToString(v.ETag),
			})
		}
		for _, m := range out.DeleteMarkers {
			hidden[aws.ToString(m.Key)] = true
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		in.KeyMarker, in.VersionIdMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
	flush()
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i].head, all[j].head
		if !a.LastModified.Equal(b.LastModified) {
			return a.LastModified.Before(b.LastModified)
		}
		return a.Day < b.Day
	})
	for k := range hidden {
		h.HiddenKeys = append(h.HiddenKeys, k)
	}
	sort.Strings(h.HiddenKeys)

	// Read every distinct body once. Identical bodies share an ETag, so a
	// head re-shipped unchanged (D20, D23) costs no extra read.
	heads := make([]WitnessedHead, len(all))
	groups := map[string][]int{}
	var order []string
	for i, v := range all {
		heads[i] = v.head
		key := v.etag
		if key == "" {
			// No ETag to share: read this version on its own.
			key = v.head.Key + "#" + v.head.VersionID
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], i)
	}
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
		sem      = make(chan struct{}, defaultHistoryConcurrency)
	)
	for _, key := range order {
		idx := groups[key]
		first := all[idx[0]].head
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			hex, err := w.readVersion(ctx, nodeID, first.Key, first.VersionID)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			for _, i := range idx {
				heads[i].HeadHex = hex
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return h, firstErr
	}
	h.Heads = heads
	return h, nil
}

// dayPrefixes lists nodeID's day prefixes ("day=2026-10-11/"), oldest first,
// with ListObjectVersions so a day hidden behind a delete marker still
// counts (C2).
func (w *s3Witness) dayPrefixes(ctx context.Context, nodeID string) ([]string, error) {
	prefix := NodePrefix(w.prefix, nodeID)
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(w.bucket), Prefix: aws.String(prefix), Delimiter: aws.String("/")}
	var days []string
	for {
		out, err := w.api.ListObjectVersions(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("audit witness reader: list days in s3://%s/%s: %w", w.bucket, prefix, err)
		}
		for _, cp := range out.CommonPrefixes {
			if day := strings.TrimPrefix(aws.ToString(cp.Prefix), prefix); strings.HasPrefix(day, "day=") {
				days = append(days, day)
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		in.KeyMarker, in.VersionIdMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
	sort.Strings(days)
	return days, nil
}

// newestBefore is the newest day prefix strictly before start.
func newestBefore(days []string, start string) string {
	i := sort.SearchStrings(days, start)
	if i == 0 {
		return ""
	}
	return days[i-1]
}

// currentHead reads a key's current version. A key with no current version
// is hidden behind a delete marker (the daemon never deletes); the window's
// own listing reports hidden keys, so here it just means no prior head.
func (w *s3Witness) currentHead(ctx context.Context, nodeID, key string) (*WitnessedHead, error) {
	out, err := w.api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(w.bucket), Key: aws.String(key)})
	if err != nil {
		if apiCode(err) == "NoSuchKey" {
			return nil, nil
		}
		return nil, fmt.Errorf("audit witness reader: read %s: %w", key, err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(io.LimitReader(out.Body, maxHeadBody+1))
	if err != nil {
		return nil, fmt.Errorf("audit witness reader: read %s: %w", key, err)
	}
	if len(body) > maxHeadBody {
		return nil, fmt.Errorf("audit witness reader: %s is larger than any head record", key)
	}
	rec, err := ParseHeadRecord(body, nodeID)
	if err != nil {
		return nil, fmt.Errorf("audit witness reader: %s: %w", key, err)
	}
	return &WitnessedHead{HeadHex: rec.HeadHex, LastModified: aws.ToTime(out.LastModified).UTC(), Key: key, VersionID: aws.ToString(out.VersionId), Day: dayOfKey(key)}, nil
}

func (w *s3Witness) readVersion(ctx context.Context, nodeID, key, versionID string) (string, error) {
	out, err := w.api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(w.bucket), Key: aws.String(key), VersionId: aws.String(versionID)})
	if err != nil {
		return "", fmt.Errorf("audit witness reader: read %s version %s: %w", key, versionID, err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(io.LimitReader(out.Body, maxHeadBody+1))
	if err != nil {
		return "", fmt.Errorf("audit witness reader: read %s version %s: %w", key, versionID, err)
	}
	if len(body) > maxHeadBody {
		return "", fmt.Errorf("audit witness reader: %s version %s is larger than any head record", key, versionID)
	}
	rec, err := ParseHeadRecord(body, nodeID)
	if err != nil {
		return "", fmt.Errorf("audit witness reader: %s version %s: %w", key, versionID, err)
	}
	return rec.HeadHex, nil
}

// dayOfKey returns the date in ".../day=<date>/head.json".
func dayOfKey(key string) string {
	i := strings.LastIndex(key, "/day=")
	if i < 0 {
		return ""
	}
	return strings.TrimSuffix(key[i+len("/day="):], "/"+headFile)
}
