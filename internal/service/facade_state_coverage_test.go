package service

import (
	"context"
	"testing"
)

func TestFacadeUpdateTagsMissingSandbox(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if err := svc.UpdateTags(context.Background(), "missing", map[string]string{"a": "b"}); err == nil {
		t.Fatal("UpdateTags missing sandbox should fail")
	}
}
