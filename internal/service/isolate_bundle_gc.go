package service

import (
	"context"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// RunJSBundleGCLoop periodically deletes content-addressed bundles that no
// live isolate sandbox pins and that no catalogue name points at
// (plans/isolate-runtime.md Phase 2 leftover). Interval <= 0 disables.
func (s *Service) RunJSBundleGCLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 || s.isolateBundles == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := s.gcUnreferencedJSBundles(ctx); err != nil {
				s.logger.Warn("js-bundle GC failed", "error", err)
			} else if n > 0 {
				s.logger.Info("js-bundle GC removed unreferenced digests", "count", n)
			}
		}
	}
}

// GCUnreferencedJSBundles is the single sweep used by the loop, operators, and tests.
func (s *Service) GCUnreferencedJSBundles(ctx context.Context) (int, error) {
	return s.gcUnreferencedJSBundles(ctx)
}

func (s *Service) gcUnreferencedJSBundles(ctx context.Context) (int, error) {
	if s.isolateBundles == nil || s.store == nil {
		return 0, nil
	}
	sandboxes, err := s.store.ListByRuntime(ctx, models.RuntimeIsolate)
	if err != nil {
		return 0, err
	}
	pinned := make(map[string]struct{}, len(sandboxes))
	for _, sb := range sandboxes {
		if sb == nil {
			continue
		}
		d := strings.TrimPrefix(strings.TrimSpace(sb.ModuleDigest), "sha256:")
		if d == "" {
			d = strings.TrimPrefix(strings.TrimSpace(sb.ModuleRef), "sha256:")
		}
		if d != "" {
			pinned[d] = struct{}{}
		}
	}
	removed, err := s.isolateBundles.GCUnreferenced(pinned)
	return len(removed), err
}
