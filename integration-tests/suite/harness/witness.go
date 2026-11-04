package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/auditwitness"
)

// Env vars run.sh exports when the scenario provisions the S3 Object Lock
// audit witness (Terraform audit_witness_enabled). Bucket and prefix come from
// the scenario's own Terraform outputs, because the bucket name carries a
// random suffix; the region comes from the same var-file chain Terraform
// applied with.
const (
	EnvAuditWitnessBucket = "AEROL_AUDIT_WITNESS_BUCKET"
	EnvAuditWitnessPrefix = "AEROL_AUDIT_WITNESS_PREFIX"
	EnvAuditWitnessRegion = "AEROL_AUDIT_WITNESS_REGION"
)

// witnessCallTimeout bounds one witness call from the operator's machine. A
// call that hangs past it is a network problem, and failing the case names it;
// waiting out the suite timeout would not.
const witnessCallTimeout = time.Minute

// WitnessBucket is a scenario's audit-witness bucket, read with the operator's
// credentials (the SDK's default chain, which run.sh points at Terraform's
// profile), never through a node.
//
// Reading it directly is the point. The witness exists so that what a node
// says about its own history can be checked against a store the node cannot
// rewrite; asking the node what the witness holds would test nothing.
type WitnessBucket struct {
	Bucket string
	Prefix string
	Region string
	// Endpoint and PathStyle point the client at an S3-compatible endpoint.
	// Only this package's unit tests set them, against pkg/auditwitness/s3fake.
	Endpoint  string
	PathStyle bool
}

// LoadWitnessBucket reads the witness coordinates run.sh exported. ok is
// false when no bucket was handed over.
func LoadWitnessBucket() (WitnessBucket, bool) {
	w := WitnessBucket{
		Bucket: strings.TrimSpace(os.Getenv(EnvAuditWitnessBucket)),
		Prefix: strings.TrimSpace(os.Getenv(EnvAuditWitnessPrefix)),
		Region: strings.TrimSpace(os.Getenv(EnvAuditWitnessRegion)),
	}
	return w, w.Bucket != ""
}

// RequireWitnessBucket returns the scenario's witness bucket, or fails the
// case when there is none.
//
// A failure, not a skip: callers have already passed harness.Require on
// CapAuditWitness, so the scenario CLAIMS an external witness. A missing
// bucket then means run.sh never read Terraform's output or Terraform never
// made the bucket, and a skip would let the matrix go green over a witness
// nothing checked.
func RequireWitnessBucket(t *testing.T) WitnessBucket {
	t.Helper()
	w, ok := LoadWitnessBucket()
	if !ok {
		t.Fatalf("the scenario advertises audit-witness but %s is not set: run.sh exports it from `terraform output audit_witness_bucket`, so either the scenario's tfvars lack audit_witness_enabled = true or the run did not go through integration-tests/run.sh", EnvAuditWitnessBucket)
	}
	return w
}

func (w WitnessBucket) prefix() string {
	if w.Prefix == "" {
		return auditwitness.DefaultPrefix
	}
	return w.Prefix
}

func (w WitnessBucket) s3Config() auditexport.S3Config {
	return auditexport.S3Config{
		Bucket:    w.Bucket,
		Prefix:    w.prefix(),
		Region:    w.Region,
		Endpoint:  w.Endpoint,
		PathStyle: w.PathStyle,
	}
}

// WitnessedHeadFor reads the newest head the witness holds for nodeID, the
// way the node's own boot check reads it (auditwitness.Reader shares that
// code, delete-marker rule included). ok=false means "never recorded", which
// is distinct from an error.
func WitnessedHeadFor(t *testing.T, w WitnessBucket, nodeID string) (headHex string, ok bool, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), witnessCallTimeout)
	defer cancel()
	r, err := auditwitness.NewReader(ctx, w.s3Config())
	if err != nil {
		return "", false, err
	}
	return r.LatestHead(ctx, nodeID)
}

// PlantWitnessHead writes headHex as the newest version of nodeID's key for
// today, bypassing the node that would normally ship it.
//
// This is the only honest way to test the witness boot gate (UC-144): the
// gate reads the witness at boot and refuses to start when the external
// record disagrees with the local chain, so the fault has to be injected at
// the witness, not at the node. Object Lock forbids changing or deleting a
// version, so a plant is never undone; it is buried under a newer version
// (the restore is another plant, of a head the node's chain holds).
//
// The checksum is not optional: S3 refuses any upload to a bucket with a
// default Object Lock retention unless it carries Content-MD5 or an SDK
// checksum, and the shared client adds one only when an API requires it.
//
// The key's day comes from this machine's clock, and the node reads the key
// for its own clock's day. Both clocks are NTP-synced, so they disagree about
// the date only within their skew of UTC midnight; that window is accepted
// rather than planting on neighbouring days' keys, which would leave heads
// under days the node has not reached yet.
func PlantWitnessHead(t *testing.T, w WitnessBucket, nodeID, headHex string) error {
	t.Helper()
	now := time.Now().UTC()
	body, err := json.Marshal(auditwitness.HeadRecord{
		NodeID:          nodeID,
		HeadHex:         headHex,
		EventID:         "itest-planted",
		Observed:        now,
		SandboxdVersion: "itest-harness",
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), witnessCallTimeout)
	defer cancel()
	client, err := auditexport.NewS3Client(ctx, w.s3Config())
	if err != nil {
		return fmt.Errorf("witness client: %w", err)
	}
	key := auditwitness.HeadKey(w.prefix(), nodeID, now)
	out, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:            aws.String(w.Bucket),
		Key:               aws.String(key),
		Body:              bytes.NewReader(body),
		ContentType:       aws.String("application/json"),
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
	})
	if err != nil {
		return fmt.Errorf("plant head for %s at s3://%s/%s: %w", nodeID, w.Bucket, key, err)
	}
	// The version id is what CloudTrail and the offline verifier name, so
	// log it: a later reader of the bucket can tell the suite's plants from
	// a node's own ships.
	t.Logf("witness: planted head %s for %s as version %s of s3://%s/%s",
		headHex, nodeID, aws.ToString(out.VersionId), w.Bucket, key)
	return nil
}

// WitnessCanary counts the versions and delete markers on nodeID's boot
// canary key (auditwitness.CanaryKey).
//
// Every boot writes one locked version there, then tries to delete it with
// the governance bypass header and to hide it behind a delete marker, and
// refuses to start unless both are denied. A running node with versions > 0
// and deleteMarkers == 0 therefore proves, on the real bucket and the real
// node role, that the role could neither delete a witnessed version nor hide
// one. Only keys equal to the canary key count: a listing by prefix would
// also return node=<id>0's canary.
func WitnessCanary(t *testing.T, w WitnessBucket, nodeID string) (versions, deleteMarkers int, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), witnessCallTimeout)
	defer cancel()
	client, err := auditexport.NewS3Client(ctx, w.s3Config())
	if err != nil {
		return 0, 0, fmt.Errorf("witness client: %w", err)
	}
	key := auditwitness.CanaryKey(w.prefix(), nodeID)
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(w.Bucket), Prefix: aws.String(key)}
	for {
		out, err := client.ListObjectVersions(ctx, in)
		if err != nil {
			return 0, 0, fmt.Errorf("list versions of s3://%s/%s: %w", w.Bucket, key, err)
		}
		for _, v := range out.Versions {
			if aws.ToString(v.Key) == key {
				versions++
			}
		}
		for _, m := range out.DeleteMarkers {
			if aws.ToString(m.Key) == key {
				deleteMarkers++
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			return versions, deleteMarkers, nil
		}
		in.KeyMarker, in.VersionIdMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
}
