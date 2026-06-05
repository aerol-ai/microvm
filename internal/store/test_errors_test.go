package store

import (
	"context"
	"fmt"
	"github.com/aerol-ai/microvm/pkg/models"
	"testing"
	"time"
)

func TestCheckCreateErrorsAll(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.Create(ctx, sampleSandbox("sb-list")); err != nil {
		fmt.Printf("sb err: %v\n", err)
	}
	if err := st.CreateTemplate(ctx, &models.Template{ID: "tpl-list", Image: "img"}); err != nil {
		fmt.Printf("tpl err: %v\n", err)
	}
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{SourceSandboxID: "sb-list", Name: "snap-list"}); err != nil {
		fmt.Printf("snap err: %v\n", err)
	}
	if err := st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{Alias: "alias-list", SnapshotName: "snap-list"}); err != nil {
		fmt.Printf("alias err: %v\n", err)
	}
	if err := st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "slot-1", TemplateID: "tpl-list"}, time.Now()); err != nil {
		fmt.Printf("slot err: %v\n", err)
	}
}
