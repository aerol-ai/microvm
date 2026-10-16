package auditwitness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// s3API is the slice of the S3 client the witness uses; *s3.Client
// satisfies it.
type s3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	ListObjectVersions(ctx context.Context, in *s3.ListObjectVersionsInput, optFns ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
	GetBucketVersioning(ctx context.Context, in *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetObjectLockConfiguration(ctx context.Context, in *s3.GetObjectLockConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
}

// headFile is the object name inside each day's prefix.
const headFile = "head.json"

// maxHeadBody bounds a head read. A real body is about 300 bytes; anything
// near this limit was not written by a node.
const maxHeadBody = 64 << 10

// HeadRecord is the body of every witnessed version. It never holds audit
// payloads, only the chain head and where it came from.
type HeadRecord struct {
	NodeID          string    `json:"node_id"`
	HeadHex         string    `json:"head_hex"`
	EventID         string    `json:"event_id,omitempty"`
	Observed        time.Time `json:"observed"`
	SandboxdVersion string    `json:"sandboxd_version,omitempty"`
}

// HeadKey is where nodeID's heads for day's UTC date live.
//
// One key per node per day (D2): Object Lock needs versioning, so every
// ship adds a locked version, and AWS throttles the whole bucket once one
// object passes about 100,000 versions. A day holds at most 2,880 ships at
// the 30 s default, whatever the retention. path.Join keeps a prefix set
// with or without a trailing slash from changing the layout.
func HeadKey(prefix, nodeID string, day time.Time) string {
	return path.Join(cleanPrefix(prefix), "node="+nodeID, "day="+day.UTC().Format("2006-01-02"), headFile)
}

// NodePrefix is the listing prefix that holds every day of nodeID's heads.
func NodePrefix(prefix, nodeID string) string {
	return path.Join(cleanPrefix(prefix), "node="+nodeID) + "/"
}

// CanaryKey is where nodeID's boot canary writes. Every boot leaves one
// locked version there and no delete marker, because both of the canary's
// deletes must be refused before the node may start; the integration suite
// reads the key back to prove that on a real bucket.
func CanaryKey(prefix, nodeID string) string {
	return path.Join(cleanPrefix(prefix), "canary", "node="+nodeID)
}

func cleanPrefix(prefix string) string {
	return strings.Trim(strings.TrimSpace(prefix), "/")
}

// ParseHeadRecord decodes and checks one witnessed body for nodeID.
func ParseHeadRecord(body []byte, nodeID string) (HeadRecord, error) {
	var rec HeadRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return HeadRecord{}, fmt.Errorf("malformed head record: %w", err)
	}
	rec.HeadHex = strings.TrimSpace(rec.HeadHex)
	if rec.NodeID != nodeID {
		return HeadRecord{}, fmt.Errorf("head record names node %q, not %q", rec.NodeID, nodeID)
	}
	if !isHex(rec.HeadHex) {
		return HeadRecord{}, fmt.Errorf("head record for node %q has no valid head_hex", nodeID)
	}
	return rec, nil
}

func isHex(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

type s3Witness struct {
	api    s3API
	bucket string
	prefix string
	nodeID string
	retain int
	// now is the clock that picks today's key. Tests in this package move it
	// across midnight; production never sets it.
	now func() time.Time
}

func newS3Witness(api s3API, cfg Config) *s3Witness {
	prefix := cfg.S3.Prefix
	if strings.TrimSpace(prefix) == "" {
		prefix = DefaultPrefix
	}
	return &s3Witness{
		api:    api,
		bucket: strings.TrimSpace(cfg.S3.Bucket),
		prefix: prefix,
		nodeID: strings.TrimSpace(cfg.NodeID),
		retain: cfg.RetentionDays,
		now:    time.Now,
	}
}

// WitnessHeads writes the head as a new locked version of today's key.
//
// Exactly one head per call (D11): the only caller ships one, and a loop
// would leave partial failure undefined, with an earlier version already
// locked forever while the caller is told the call failed.
//
// The receipt is the S3 version id. RecordedAt stays zero, so the service
// stores its own ship time; the time that matters is the version's
// LastModified in the bucket, which the node cannot change and the offline
// verifier reads. Fetching it here would cost a second request per ship and
// a failure path that re-ships a head S3 already holds (D10).
func (w *s3Witness) WitnessHeads(ctx context.Context, heads []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	if len(heads) != 1 {
		return controlplane.WitnessReceipt{}, fmt.Errorf("audit witness s3: exactly one head per call, got %d", len(heads))
	}
	h := heads[0]
	nodeID := strings.TrimSpace(h.NodeID)
	if err := validateNodeID(nodeID); err != nil {
		return controlplane.WitnessReceipt{}, err
	}
	head := strings.TrimSpace(h.HeadHex)
	if !isHex(head) {
		return controlplane.WitnessReceipt{}, fmt.Errorf("audit witness s3: head %q is not a hex digest", head)
	}
	observed := h.Observed
	if observed.IsZero() {
		observed = w.now()
	}
	body, err := json.Marshal(HeadRecord{
		NodeID: nodeID, HeadHex: head, EventID: h.EventID,
		Observed: observed.UTC(), SandboxdVersion: version.Version,
	})
	if err != nil {
		return controlplane.WitnessReceipt{}, err
	}
	key := HeadKey(w.prefix, nodeID, w.now())
	out, err := w.put(ctx, key, body)
	if err != nil {
		return controlplane.WitnessReceipt{}, fmt.Errorf("audit witness s3: write %s: %w", key, err)
	}
	vid := aws.ToString(out.VersionId)
	if vid == "" || vid == "null" {
		// An unversioned write replaced the previous head instead of adding
		// to the locked history; never call that witnessed.
		return controlplane.WitnessReceipt{}, fmt.Errorf("audit witness s3: bucket %q returned no version id for %s; the witness bucket must be versioned with Object Lock", w.bucket, key)
	}
	return controlplane.WitnessReceipt{ReceiptID: vid}, nil
}

// put uploads with an explicit SHA-256 checksum. S3 refuses any upload to a
// bucket with default Object Lock retention unless it carries Content-MD5
// or an SDK checksum, and the shared client only adds one when an API
// requires it (RequestChecksumCalculationWhenRequired), which PutObject
// does not.
func (w *s3Witness) put(ctx context.Context, key string, body []byte) (*s3.PutObjectOutput, error) {
	return w.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket:            aws.String(w.bucket),
		Key:               aws.String(key),
		Body:              bytes.NewReader(body),
		ContentType:       aws.String("application/json"),
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
	})
}

// LastWitnessedHead returns the newest head for nodeID: one GET of today's
// key on every running node, since the service re-ships an unchanged head
// once a day (D20). Only a node that was down across midnight falls back to
// listing its days.
func (w *s3Witness) LastWitnessedHead(ctx context.Context, nodeID string) (string, bool, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || nodeID == StandaloneNodeID {
		// D3 means no S3 head can exist under "standalone". The service still
		// asks for it as a legacy id on single servers, and answering from
		// the bucket would read a key any node's role can write (D24).
		return "", false, nil
	}
	key := HeadKey(w.prefix, nodeID, w.now())
	rec, found, err := w.getHead(ctx, key, nodeID)
	if err != nil || found {
		return rec.HeadHex, found, err
	}
	day, ok, err := w.newestDay(ctx, nodeID)
	if err != nil || !ok {
		return "", false, err
	}
	key = NodePrefix(w.prefix, nodeID) + day + headFile
	rec, found, err = w.getHead(ctx, key, nodeID)
	if err != nil || found {
		return rec.HeadHex, found, err
	}
	hidden, err := w.latestIsDeleteMarker(ctx, key)
	if err != nil {
		return "", false, err
	}
	if hidden {
		// The daemon never deletes, so a delete marker on the newest day is
		// someone hiding a head. Falling back to the previous day would
		// validate against an older head and let the hiding work (C2).
		return "", false, fmt.Errorf("audit witness s3: the newest head for node %q (%s) is hidden by a delete marker; the daemon never deletes, so treat this as tampering", nodeID, key)
	}
	return "", false, nil
}

// getHead reads the current version of key. found is false when the key
// has no current version (missing, or hidden by a delete marker).
func (w *s3Witness) getHead(ctx context.Context, key, nodeID string) (HeadRecord, bool, error) {
	out, err := w.api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(w.bucket), Key: aws.String(key)})
	if err != nil {
		if apiCode(err) == "NoSuchKey" {
			return HeadRecord{}, false, nil
		}
		return HeadRecord{}, false, fmt.Errorf("audit witness s3: read %s: %w%s", key, err, accessDeniedHint(err))
	}
	defer out.Body.Close()
	body, err := io.ReadAll(io.LimitReader(out.Body, maxHeadBody+1))
	if err != nil {
		return HeadRecord{}, false, fmt.Errorf("audit witness s3: read %s: %w", key, err)
	}
	if len(body) > maxHeadBody {
		return HeadRecord{}, false, fmt.Errorf("audit witness s3: %s is larger than any head record", key)
	}
	rec, err := ParseHeadRecord(body, nodeID)
	if err != nil {
		return HeadRecord{}, false, fmt.Errorf("audit witness s3: %s: %w", key, err)
	}
	return rec, true, nil
}

// newestDay lists nodeID's day prefixes and returns the newest, such as
// "day=2026-10-11/". It must be ListObjectVersions: ListObjectsV2 hides a
// key whose current version is a delete marker, and the newest day would
// then silently become the day before (C2).
func (w *s3Witness) newestDay(ctx context.Context, nodeID string) (string, bool, error) {
	prefix := NodePrefix(w.prefix, nodeID)
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(w.bucket), Prefix: aws.String(prefix), Delimiter: aws.String("/")}
	newest := ""
	for {
		out, err := w.api.ListObjectVersions(ctx, in)
		if err != nil {
			return "", false, fmt.Errorf("audit witness s3: list %s: %w", prefix, err)
		}
		for _, cp := range out.CommonPrefixes {
			day := strings.TrimPrefix(aws.ToString(cp.Prefix), prefix)
			if strings.HasPrefix(day, "day=") && day > newest {
				newest = day
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		in.KeyMarker, in.VersionIdMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
	return newest, newest != "", nil
}

func (w *s3Witness) latestIsDeleteMarker(ctx context.Context, key string) (bool, error) {
	out, err := w.api.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(w.bucket), Prefix: aws.String(key)})
	if err != nil {
		return false, fmt.Errorf("audit witness s3: list versions of %s: %w", key, err)
	}
	for _, m := range out.DeleteMarkers {
		if aws.ToString(m.Key) == key && aws.ToBool(m.IsLatest) {
			return true, nil
		}
	}
	return false, nil
}

func apiCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

// accessDeniedHint names the usual cause of a 403 on a read: without
// s3:ListBucket, S3 answers a missing key with AccessDenied instead of
// NoSuchKey (D19).
func accessDeniedHint(err error) string {
	if apiCode(err) == "AccessDenied" {
		return " (if the key may not exist, the role needs s3:ListBucket so S3 can answer NoSuchKey)"
	}
	return ""
}

var (
	_ controlplane.Witness = (*s3Witness)(nil)
	_ s3API                = (*s3.Client)(nil)
)
