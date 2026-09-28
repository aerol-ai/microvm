package netns

import (
	"context"
	"testing"
	"time"
)

func TestPoolSeedRejectsZeroSizeCoverage95(t *testing.T) {
	st := openTestStore(t)
	p := New(st)
	err := p.Seed(context.Background(), SeedConfig{PoolSize: 0}, time.Unix(1, 0).UTC())
	if err == nil {
		t.Fatal("want seed size error")
	}
}
