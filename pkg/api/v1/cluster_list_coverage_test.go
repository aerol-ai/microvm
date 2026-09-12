package v1

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestTemplateListCacheHit(t *testing.T) {
	h := &handlers{deps: Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	h.templateLists.put(time.Now(), clusterListAggregate[*models.Template]{rows: []*models.Template{{ID: "cached"}}})
	got, ok := h.templateLists.get(time.Now())
	if !ok || len(got.rows) != 1 {
		t.Fatalf("cache hit = %+v ok=%v", got, ok)
	}
}
