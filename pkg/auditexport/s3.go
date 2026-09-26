package auditexport

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// s3PutObjectAPI is the one call the backend needs; tests inject a fake and
// the production client is s3.Client.
type s3PutObjectAPI interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// s3Backend writes one NDJSON object per batch. The key embeds the batch id,
// so an at-least-once re-send after a crash overwrites the same object
// instead of duplicating it — idempotency falls out of the key layout rather
// than receiver logic. Any S3-compatible store works (endpoint + path-style);
// GCS/Azure would register their own backend with the same key contract.
type s3Backend struct {
	api    s3PutObjectAPI
	bucket string
	prefix string
	h      *health
}

func init() {
	Register(BackendS3, func(cfg Config) (Backend, error) {
		api, err := newS3Client(context.Background(), cfg.S3)
		if err != nil {
			return nil, err
		}
		return newS3Backend(api, cfg.S3), nil
	})
}

func newS3Backend(api s3PutObjectAPI, cfg S3Config) *s3Backend {
	return &s3Backend{api: api, bucket: cfg.Bucket, prefix: cfg.Prefix, h: newHealth(BackendS3)}
}

func newS3Client(ctx context.Context, cfg S3Config) (*s3.Client, error) {
	var loadOpts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("audit export s3: load aws config: %w", err)
	}
	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.PathStyle
		// Trailing-checksum (aws-chunked) uploads break older S3-compatible
		// stores; the object is small and the SDK still validates when the
		// store requires it.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	}), nil
}

func (b *s3Backend) Name() string { return BackendS3 }

// ObjectKey is the deterministic layout: <prefix>/node=<id>/<yyyy>/<mm>/<dd>/<batch>.jsonl.
// Date partitions keep listing and lifecycle rules cheap; the batch id makes
// re-sends idempotent. Exported so receivers/tests can compute it.
func ObjectKey(prefix, nodeID, batchID string, shippedAt time.Time) string {
	if shippedAt.IsZero() {
		shippedAt = time.Now().UTC()
	}
	shippedAt = shippedAt.UTC()
	node := strings.TrimSpace(nodeID)
	if node == "" {
		node = "unknown"
	}
	safeBatch := strings.NewReplacer("/", "_", ":", "_").Replace(strings.TrimSpace(batchID))
	if safeBatch == "" {
		safeBatch = fmt.Sprintf("%d", shippedAt.UnixNano())
	}
	return path.Join(prefix, "node="+node, shippedAt.Format("2006/01/02"), safeBatch+".jsonl")
}

func (b *s3Backend) Export(ctx context.Context, batch Batch) error {
	body := EncodeNDJSON(batch)
	key := ObjectKey(b.prefix, batch.NodeID, batch.BatchID, batch.ShippedAt)
	_, err := b.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(b.bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(body),
		ContentType:   aws.String(ContentTypeNDJSON),
		ContentLength: aws.Int64(int64(len(body))),
		Metadata: map[string]string{
			"aerol-node-id":  strings.TrimSpace(batch.NodeID),
			"aerol-offset":   strings.TrimSpace(batch.Offset),
			"aerol-batch-id": strings.TrimSpace(batch.BatchID),
		},
	})
	if err != nil {
		// Object stores fail for transport, throttling, and IAM reasons alike;
		// none of them are the evidence's fault, so all are retried.
		return b.h.markErr(Temporary(err))
	}
	b.h.markOK(len(batch.Events))
	return nil
}

func (b *s3Backend) Healthy(context.Context) error { return b.h.Healthy() }
