package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// sync_fs is what makes a stopped Firecracker sandbox's saved disk hold
// every write made before Stop, so a snapshot taken from that disk alone
// loses nothing.

func syncRoundTrip(t *testing.T, h VsockHandler) VsockResponse {
	t.Helper()
	host, guest := newPipePair()
	done := runHandlerInBackground(t, guest, h)
	msg, _ := json.Marshal(VsockMessage{Op: OpSyncFS})
	if _, err := host.Write(append(msg, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
	var resp VsockResponse
	if err := json.NewDecoder(host).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	closePipeWriter(host)
	<-done
	return resp
}

func TestVsock_SyncFSFlushesTheGuestFilesystems(t *testing.T) {
	q := &fakeQuiesceOps{}
	h := newQuiesceHandler(nil, nil, nil)
	h.quiesce = q
	if resp := syncRoundTrip(t, h); !resp.Ok {
		t.Fatalf("sync_fs = %+v, want Ok", resp)
	}
	if q.syncCalls != 1 {
		t.Fatalf("SyncFilesystems called %d times, want 1", q.syncCalls)
	}
}

// The host reads "unknown op" as an agent from before sync_fs and records
// the saved disk as unflushed; a snapshot of it is then refused.
func TestVsock_SyncFSWithoutTheCapabilityIsAnUnknownOp(t *testing.T) {
	resp := syncRoundTrip(t, &recordingHandler{})
	if resp.Ok || !strings.Contains(resp.Error, `unknown op "sync_fs"`) {
		t.Fatalf("sync_fs to an agent without it = %+v, want unknown op", resp)
	}
}

func TestQuiesceHandler_SyncFSReportsAFailure(t *testing.T) {
	h := newQuiesceHandler(nil, nil, nil)
	h.quiesce = &fakeQuiesceOps{syncErr: errors.New("EIO")}
	err := h.OnSyncFS(context.Background())
	if err == nil || !strings.Contains(err.Error(), "sync filesystems: EIO") {
		t.Fatalf("OnSyncFS = %v, want the sync error", err)
	}
	resp := syncRoundTrip(t, h)
	if resp.Ok || !strings.Contains(resp.Error, "sync filesystems") {
		t.Fatalf("sync_fs with a failing sync = %+v, want the error back", resp)
	}
}
