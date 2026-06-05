package v1

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
)

func TestSingleLineFROM(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"FROM alpine:3.20", "alpine:3.20", true},
		{"# comment\nFROM debian:bookworm", "debian:bookworm", true},
		{"FROM a\nRUN true", "", false},
		{"RUN true", "", false},
		{"FROM ", "", false},
	}
	for _, tc := range cases {
		got, ok := singleLineFROM(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("singleLineFROM(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestBuildContextWithTimeout(t *testing.T) {
	ctx, cancel := buildContextWithTimeout(context.Background(), 0)
	cancel()
	ctx2, cancel2 := buildContextWithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	deadline, ok := ctx2.Deadline()
	if !ok || deadline.IsZero() {
		t.Fatalf("expected timeout deadline, got ok=%v deadline=%v", ok, deadline)
	}
	_ = ctx
}

func TestResolveSnapshotImage_ImageExistsRefreshError(t *testing.T) {
	dockerfile := "FROM alpine:3.20\nRUN echo hi"
	tag := docker.BuildTagFor(dockerfile, nil)
	builder := &fakeImageBuilder{
		exists:     map[string]bool{tag: true},
		refreshErr: errors.New("refresh failed"),
	}
	h := &handlers{deps: Deps{Builder: builder, Build: BuildConfig{}}}
	got, built, err := h.resolveSnapshotImage(context.Background(), dockerfile, nil)
	if err != nil || got != tag || built != "" {
		t.Fatalf("resolveSnapshotImage = (%q, %q, %v), want (%q, \"\", nil)", got, built, err, tag)
	}
	if len(builder.refreshes) != 1 {
		t.Fatalf("refreshes = %+v, want one refresh on cache hit", builder.refreshes)
	}
}
