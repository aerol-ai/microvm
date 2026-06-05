//go:build !linux

package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func TestNonLinuxStubs(t *testing.T) {
	q := newQuiesceOps()
	if err := q.ReseedRandom(); err == nil {
		t.Fatal("ReseedRandom expected error on non-linux stub")
	}
	if err := q.SetWallclock(123); err == nil {
		t.Fatal("SetWallclock expected error on non-linux stub")
	}

	vs, err := newVsockServer(1024, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || vs != nil {
		t.Fatalf("newVsockServer = (%v, %v), want nil + error", vs, err)
	}
	stub := &vsockServer{}
	if err := stub.Serve(context.Background()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if err := stub.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
