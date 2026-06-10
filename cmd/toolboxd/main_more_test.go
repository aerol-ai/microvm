package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeVsockServer struct {
	served chan struct{}
	closed chan struct{}
}

func (f *fakeVsockServer) Serve(context.Context) error {
	close(f.served)
	return nil
}

func (f *fakeVsockServer) Close() error {
	close(f.closed)
	return nil
}

func TestSandboxIDAndShellHelperBranches(t *testing.T) {
	oldHostnameFn := hostnameFn
	oldStatFn := statFn
	oldLookPathFn := lookPathFn
	t.Cleanup(func() {
		hostnameFn = oldHostnameFn
		statFn = oldStatFn
		lookPathFn = oldLookPathFn
	})

	hostnameFn = func() (string, error) { return "", errors.New("hostname failed") }
	if got := readSandboxID(); got != "" {
		t.Fatalf("readSandboxID error branch = %q, want empty", got)
	}

	statFn = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	lookPathFn = func(name string) (string, error) {
		if name == "sh" {
			return "/custom/sh", nil
		}
		return "", os.ErrNotExist
	}
	if shell, err := detectShell(); err != nil || shell != "/custom/sh" {
		t.Fatalf("detectShell fallback = (%q, %v), want /custom/sh,nil", shell, err)
	}

	lookPathFn = func(string) (string, error) { return "", os.ErrNotExist }
	if shell, err := detectShell(); err == nil || shell != "" {
		t.Fatalf("detectShell error branch = (%q, %v), want error", shell, err)
	}
}

func TestHandleExecShellErrorBranch(t *testing.T) {
	oldStatFn := statFn
	oldLookPathFn := lookPathFn
	t.Cleanup(func() {
		statFn = oldStatFn
		lookPathFn = oldLookPathFn
	})
	statFn = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	lookPathFn = func(string) (string, error) { return "", os.ErrNotExist }

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, allowedPorts: map[int]struct{}{}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/execute", bytes.NewReader([]byte(`{"command":"echo hi"}`)))
	s.handleExec(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("handleExec shell error status = %d, want 500", rr.Code)
	}
}

func TestHandleUploadWriteFailureBranch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &server{logger: logger, allowedPorts: map[int]struct{}{}}
	dir := t.TempDir()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("path", dir); err != nil {
		t.Fatalf("WriteField: %v", err)
	}
	part, err := mw.CreateFormFile("file", "upload.txt")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write([]byte("payload")); err != nil {
		t.Fatalf("part.Write: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("mw.Close: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/files/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	s.handleUpload(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("handleUpload write failure status = %d, want 500", rr.Code)
	}

	if _, err := os.Stat(filepath.Join(dir, "upload.txt")); !os.IsNotExist(err) {
		t.Fatalf("unexpected upload file state: %v", err)
	}
}

func TestMainStartupBranchesWithStubs(t *testing.T) {
	oldArgs := os.Args
	oldSessionsNewFn := sessionsNewFn
	oldStartReaperFn := startReaperFn
	oldStartUserCommandFn := startUserCommandFn
	oldForwardShutdownSignalsFn := forwardShutdownSignalsFn
	oldServeHTTPFn := serveHTTPFn
	oldNewVsockServerFn := newVsockServerFn
	t.Cleanup(func() {
		os.Args = oldArgs
		sessionsNewFn = oldSessionsNewFn
		startReaperFn = oldStartReaperFn
		startUserCommandFn = oldStartUserCommandFn
		forwardShutdownSignalsFn = oldForwardShutdownSignalsFn
		serveHTTPFn = oldServeHTTPFn
		newVsockServerFn = oldNewVsockServerFn
	})

	tmp := t.TempDir()
	t.Setenv("SB_RECORDING_DIR", filepath.Join(tmp, "recordings"))
	t.Setenv("SB_CLONE_GEN_PATH", filepath.Join(tmp, "clonegen"))
	t.Setenv("SB_TOOLBOX_TOKEN", "token")

	startReaperFn = func(*slog.Logger) {}
	startUserCommandFn = func(_ *slog.Logger, args []string) {
		if len(args) == 0 {
			t.Fatal("expected user command args")
		}
	}
	forwardShutdownSignalsFn = func(*slog.Logger, *http.Server) {}
	serveHTTPFn = func(*http.Server) error { return http.ErrServerClosed }
	fakeVsock := &fakeVsockServer{served: make(chan struct{}), closed: make(chan struct{})}
	newVsockServerFn = func(uint32, VsockHandler, *slog.Logger) (vsockServerAPI, error) {
		return fakeVsock, nil
	}

	os.Args = []string{"toolboxd", "echo", "hello"}
	main()

	select {
	case <-fakeVsock.served:
	case <-time.After(2 * time.Second):
		t.Fatal("fake vsock Serve was not called")
	}
	select {
	case <-fakeVsock.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("fake vsock Close was not called")
	}
}
