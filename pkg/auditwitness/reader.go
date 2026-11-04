package auditwitness

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/pkg/auditexport"
)

// Reader reads a witness bucket the way a node does, without a node's boot
// checks or any write: the integration suite and the offline verifier use
// it, so "the latest head" means exactly what the daemon's boot check means
// by it, delete-marker rule included.
type Reader struct {
	w *s3Witness
}

// NewReader builds a Reader over cfg's bucket and prefix (DefaultPrefix when
// empty), with the same S3 client the witness and the exporter use.
func NewReader(ctx context.Context, cfg auditexport.S3Config) (*Reader, error) {
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, errors.New("audit witness reader: a bucket is required")
	}
	client, err := auditexport.NewS3Client(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("audit witness reader: %w", err)
	}
	return newReader(client, cfg), nil
}

func newReader(api s3API, cfg auditexport.S3Config) *Reader {
	return &Reader{w: newS3Witness(api, Config{S3: cfg})}
}

// LatestHead returns the newest head witnessed for nodeID; ok is false when
// none was ever recorded.
func (r *Reader) LatestHead(ctx context.Context, nodeID string) (headHex string, ok bool, err error) {
	return r.w.LastWitnessedHead(ctx, nodeID)
}
