package auditwitness

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// bootChecks refuses a bucket that is not really WORM. Without them a
// witness on an ordinary bucket would look healthy while protecting nothing,
// the one outcome the witness gate exists to prevent.
func (w *s3Witness) bootChecks(ctx context.Context, deadline time.Duration) error {
	checks := []struct {
		name string
		run  func(context.Context) error
	}{
		{"versioning", w.checkVersioning},
		{"object lock configuration", w.checkObjectLock},
		{"missing-key probe", w.checkMissingKeyProbe},
		{"canary", w.checkCanary},
	}
	for _, c := range checks {
		if err := c.run(ctx); err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("audit witness s3: the %s check on bucket %q timed out after %s: %w", c.name, w.bucket, deadline, err)
			}
			return err
		}
	}
	return nil
}

func (w *s3Witness) checkVersioning(ctx context.Context) error {
	out, err := w.api.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(w.bucket)})
	if err != nil {
		return fmt.Errorf("audit witness s3: read versioning of bucket %q: %w", w.bucket, err)
	}
	if out.Status != types.BucketVersioningStatusEnabled {
		return fmt.Errorf("audit witness s3: bucket %q has versioning %q; the witness needs a bucket created with Object Lock, which turns versioning on for good", w.bucket, statusOrOff(string(out.Status)))
	}
	return nil
}

func statusOrOff(s string) string {
	if s == "" {
		return "off"
	}
	return s
}

func (w *s3Witness) checkObjectLock(ctx context.Context) error {
	out, err := w.api.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: aws.String(w.bucket)})
	if err != nil {
		if apiCode(err) == "ObjectLockConfigurationNotFoundError" {
			return fmt.Errorf("audit witness s3: bucket %q does not have Object Lock; create the witness bucket with Object Lock enabled (it cannot be added to a bucket that has heads in it without AWS support)", w.bucket)
		}
		return fmt.Errorf("audit witness s3: read the Object Lock configuration of bucket %q: %w", w.bucket, err)
	}
	cfg := out.ObjectLockConfiguration
	if cfg == nil || cfg.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
		return fmt.Errorf("audit witness s3: bucket %q does not have Object Lock enabled", w.bucket)
	}
	if cfg.Rule == nil || cfg.Rule.DefaultRetention == nil || cfg.Rule.DefaultRetention.Mode == "" {
		return fmt.Errorf("audit witness s3: bucket %q has Object Lock but no default retention rule, so new heads are not locked; set a default retention (COMPLIANCE for production, GOVERNANCE for trials)", w.bucket)
	}
	ret := cfg.Rule.DefaultRetention
	days := int(aws.ToInt32(ret.Days))
	if years := int(aws.ToInt32(ret.Years)); years > 0 {
		days = years * 365
	}
	// A head must stay locked at least as long as the local records it
	// vouches for, or retention could outlive the only evidence that the
	// pruned history was ever witnessed.
	if w.retain > 0 && days < w.retain {
		return fmt.Errorf("audit witness s3: bucket %q locks heads for %d days, shorter than SB_SECRET_AUDIT_RETENTION_DAYS=%d; raise the bucket's default retention to at least %d days", w.bucket, days, w.retain, w.retain)
	}
	if days < 1 {
		return fmt.Errorf("audit witness s3: bucket %q has a default retention of %d days; it must lock heads for at least one day", w.bucket, days)
	}
	return nil
}

// checkMissingKeyProbe proves S3 will answer a missing key with NoSuchKey.
// Without s3:ListBucket it answers 403 instead, so the latest-head read
// could never tell "no head today" from "denied": a fresh bucket would fail
// the first boot, and every node would fail a boot after an idle midnight
// (D19). The key is random so no writer can make it exist.
func (w *s3Witness) checkMissingKeyProbe(ctx context.Context) error {
	var r [16]byte
	if _, err := rand.Read(r[:]); err != nil {
		return fmt.Errorf("audit witness s3: probe key: %w", err)
	}
	key := path.Join(cleanPrefix(w.prefix), "probe", hex.EncodeToString(r[:]))
	out, err := w.api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(w.bucket), Key: aws.String(key)})
	if err == nil {
		_ = out.Body.Close()
		return fmt.Errorf("audit witness s3: random probe key %s unexpectedly exists in bucket %q", key, w.bucket)
	}
	switch apiCode(err) {
	case "NoSuchKey":
		return nil
	case "AccessDenied":
		return fmt.Errorf("audit witness s3: bucket %q answered a missing key with AccessDenied: grant the node role s3:ListBucket on the bucket, without an s3:prefix condition (a read carries no prefix, so a conditioned grant does not count), or S3 cannot report a missing head as missing", w.bucket)
	}
	return fmt.Errorf("audit witness s3: probe a missing key in bucket %q: %w", w.bucket, err)
}

// checkCanary writes a version and tries to remove it the two ways an
// attacker on this node would.
//
// First by version id, with the governance bypass header. A governance lock
// refuses even a bypass-holding role when the header is absent, so a canary
// without it would pass the one misconfiguration that leaves every head
// deletable (D7). Then with a plain delete, which on a versioned bucket
// leaves the versions but hides the key behind a delete marker: Object Lock
// does not stop that, only IAM does, and a node that can do it can hide its
// newest head. Denied by IAM or by the lock, both mean the evidence is safe;
// anything else is not proof that it is.
func (w *s3Witness) checkCanary(ctx context.Context) error {
	key := CanaryKey(w.prefix, w.nodeID)
	body := fmt.Appendf(nil, `{"node_id":%q,"canary":%q}`, w.nodeID, w.now().UTC().Format(time.RFC3339))
	out, err := w.put(ctx, key, body)
	if err != nil {
		return fmt.Errorf("audit witness s3: write the canary %s to bucket %q: %w", key, w.bucket, err)
	}
	vid := aws.ToString(out.VersionId)
	if vid == "" || vid == "null" {
		return fmt.Errorf("audit witness s3: bucket %q returned no version id for the canary; the witness bucket must be versioned with Object Lock", w.bucket)
	}
	_, err = w.api.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:                    aws.String(w.bucket),
		Key:                       aws.String(key),
		VersionId:                 aws.String(vid),
		BypassGovernanceRetention: aws.Bool(true),
	})
	if err == nil {
		return fmt.Errorf("audit witness s3: this node deleted a locked version in bucket %q using the governance bypass header, so it could delete every head it wrote; remove s3:BypassGovernanceRetention (and s3:DeleteObjectVersion) from the node role, or use COMPLIANCE mode", w.bucket)
	}
	if apiCode(err) != "AccessDenied" {
		return fmt.Errorf("audit witness s3: the canary delete in bucket %q returned %v; an unknown result is not proof that the lock holds", w.bucket, strings.TrimSpace(err.Error()))
	}
	_, err = w.api.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(w.bucket), Key: aws.String(key)})
	if err == nil {
		return fmt.Errorf("audit witness s3: this node put a delete marker on %s in bucket %q, so it could hide its newest head; deny s3:DeleteObject on the node role", key, w.bucket)
	}
	if apiCode(err) != "AccessDenied" {
		return fmt.Errorf("audit witness s3: the canary delete-marker check in bucket %q returned %v; an unknown result is not proof that a head cannot be hidden", w.bucket, strings.TrimSpace(err.Error()))
	}
	return nil
}
