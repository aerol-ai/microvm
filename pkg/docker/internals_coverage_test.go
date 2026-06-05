package docker

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

func TestQueryValuesEmpty(t *testing.T) {
	if got := queryValues(nil); got != nil {
		t.Fatalf("queryValues(nil) = %v, want nil", got)
	}
	if got := queryValues(map[string]string{}); got != nil {
		t.Fatalf("queryValues(empty) = %v, want nil", got)
	}
}

func TestContainerStatusUnknownIsError(t *testing.T) {
	in := containerInspect{}
	in.State = &struct {
		Running bool   `json:"Running"`
		Status  string `json:"Status"`
		Pid     int    `json:"Pid"`
	}{Running: false, Status: "restarting"}
	if got := containerStatus(in); got != models.SandboxStatusError {
		t.Fatalf("containerStatus(restarting) = %q, want error", got)
	}
}

func TestRefreshTagMissingRepo(t *testing.T) {
	c := &Client{}
	if err := c.RefreshTag(context.Background(), ""); err == nil {
		t.Fatal("RefreshTag(\"\") expected missing-repo error")
	}
}

func TestNewDefaultSocketNoPullCap(t *testing.T) {
	// No DOCKER_HOST → default socket path; ImagePullMaxConcurrent=0 → nil slots.
	t.Setenv("DOCKER_HOST", "")
	c, err := New(slog.Default(), config.Config{ToolboxBinaryPath: "/usr/local/bin/toolboxd"}, disabledRules(t))
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	if c.socketPath != "/var/run/docker.sock" {
		t.Fatalf("socketPath = %q", c.socketPath)
	}
	if c.pullSlots != nil {
		t.Fatalf("pullSlots should be nil when no concurrency cap set")
	}
}

func TestNewDialsConfiguredSocket(t *testing.T) {
	// Point New at a real unix socket so the transport's DialContext closure
	// runs on the first request, exercising the wiring end-to-end.
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { _ = srv.Close() })

	t.Setenv("DOCKER_HOST", "unix://"+sock)
	c, err := New(slog.Default(), config.Config{ToolboxBinaryPath: "/usr/local/bin/toolboxd", HTTPClientTimeout: 2 * time.Second}, disabledRules(t))
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() over configured socket = %v", err)
	}
}

func TestDoRequestSetsCustomHeaders(t *testing.T) {
	var gotHeader string
	c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotHeader = r.Header.Get("X-Test")
		return textResponse(http.StatusOK, "{}"), nil
	})}}
	resp, err := c.doRequest(context.Background(), http.MethodGet, "/x", nil, nil, map[string]string{"X-Test": "yes"})
	if err != nil {
		t.Fatalf("doRequest() = %v", err)
	}
	resp.Body.Close()
	if gotHeader != "yes" {
		t.Fatalf("custom header not set, got %q", gotHeader)
	}
}

// ---------------------------------------------------------------------------
// waitForRuntime → waitForToolbox error path
// ---------------------------------------------------------------------------

func TestWaitForRuntimeToolboxUnhealthy(t *testing.T) {
	ip, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	defer closeFn()
	c := &Client{
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, inspectBody("cid", "/sb", ip, true, "running", 1)), nil
		})},
		toolboxClient:      &http.Client{Timeout: time.Second},
		toolboxPort:        port,
		waitTimeout:        time.Second,
		toolboxWaitTimeout: 250 * time.Millisecond,
	}
	if _, err := c.waitForRuntime(context.Background(), "cid"); err == nil {
		t.Fatal("waitForRuntime() expected toolbox-unhealthy error")
	}
}

// ---------------------------------------------------------------------------
// pullImage error branches (transport / status / decode)
// ---------------------------------------------------------------------------

func newPullClient(rt roundTripFunc) *Client {
	return &Client{
		logger:       slog.Default(),
		streamClient: &http.Client{Transport: rt},
		httpClient:   &http.Client{Transport: rt},
		pulls:        map[string]*imagePull{},
		pullFailures: map[string]imagePullFailure{},
	}
}

func TestPullImageErrorBranches(t *testing.T) {
	t.Run("transport_error", func(t *testing.T) {
		c := newPullClient(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF })
		if err := c.pullImage(context.Background(), "busybox:latest", nil); err == nil {
			t.Fatal("pullImage() expected transport error")
		}
	})
	t.Run("status_error", func(t *testing.T) {
		c := newPullClient(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusUnauthorized, "denied"), nil
		})
		if err := c.pullImage(context.Background(), "busybox:latest", nil); err == nil {
			t.Fatal("pullImage() expected status error")
		}
	})
	t.Run("decode_error", func(t *testing.T) {
		c := newPullClient(func(*http.Request) (*http.Response, error) { return textResponse(http.StatusOK, `{bad json`), nil })
		if err := c.pullImage(context.Background(), "busybox:latest", nil); err == nil {
			t.Fatal("pullImage() expected decode error")
		}
	})
	t.Run("stream_reports_error_field", func(t *testing.T) {
		c := newPullClient(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, `{"error":"nope"}`), nil
		})
		if err := c.pullImage(context.Background(), "busybox:latest", nil); err == nil {
			t.Fatal("pullImage() expected stream error field")
		}
	})
}

// ---------------------------------------------------------------------------
// aliasMirrorPull: tag failure surfaces; digest ref is skipped
// ---------------------------------------------------------------------------

func TestAliasMirrorPull(t *testing.T) {
	t.Run("tag_failure_propagates", func(t *testing.T) {
		// Mirror rewrite fires for ghcr.io; pull succeeds (EOF) then the alias
		// retag (/tag) fails with 500 → pullImage returns that error.
		c := newPullClient(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/tag") {
				return textResponse(http.StatusInternalServerError, "boom"), nil
			}
			return textResponse(http.StatusOK, `{"status":"done"}`), nil
		})
		c.ConfigureMirror(defaultMirrorCfg(), nil)
		if err := c.pullImage(context.Background(), "ghcr.io/aerol-ai/sandbox:v1", nil); err == nil {
			t.Fatal("pullImage() expected alias retag error")
		}
	})

	t.Run("digest_ref_skips_alias", func(t *testing.T) {
		rewrite := MirrorRewrite{Rewritten: true, OriginalRef: "ghcr.io/x@sha256:abc"}
		c := &Client{}
		if err := c.aliasMirrorPull(context.Background(), rewrite); err != nil {
			t.Fatalf("aliasMirrorPull(digest) = %v", err)
		}
	})

	t.Run("not_rewritten_noop", func(t *testing.T) {
		c := &Client{}
		if err := c.aliasMirrorPull(context.Background(), MirrorRewrite{Rewritten: false}); err != nil {
			t.Fatalf("aliasMirrorPull(noop) = %v", err)
		}
	})

	t.Run("empty_repo_skips_alias", func(t *testing.T) {
		// An OriginalRef that splitDestRef resolves to an empty repo (":v1")
		// short-circuits before any /tag call.
		c := &Client{}
		if err := c.aliasMirrorPull(context.Background(), MirrorRewrite{Rewritten: true, OriginalRef: ":v1"}); err != nil {
			t.Fatalf("aliasMirrorPull(empty repo) = %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// pullImageDedup: ctx-done on wait, slot acquire error, slot release
// ---------------------------------------------------------------------------

func TestPullImageDedupContextDoneWhileWaiting(t *testing.T) {
	release := make(chan struct{})
	c := newPullClient(func(*http.Request) (*http.Response, error) {
		<-release
		return textResponse(http.StatusOK, `{"status":"done"}`), nil
	})
	c.pullBackoff = time.Minute

	// First caller occupies the in-flight slot and blocks on release.
	go func() { _ = c.pullImageDedup(context.Background(), "busybox:latest", nil) }()
	for deadline := time.Now().Add(time.Second); ; {
		c.pullMu.Lock()
		n := len(c.pulls)
		c.pullMu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Second caller waits on the same in-flight pull but its ctx is cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.pullImageDedup(ctx, "busybox:latest", nil); err == nil {
		t.Fatal("pullImageDedup() expected ctx cancellation while waiting")
	}
	close(release)
}

func TestPullImageDedupSlotAcquireError(t *testing.T) {
	c := newPullClient(func(*http.Request) (*http.Response, error) {
		return textResponse(http.StatusOK, `{"status":"done"}`), nil
	})
	c.pullSlots = make(chan struct{}, 1)
	c.pullSlots <- struct{}{} // saturate so acquire blocks
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.pullImageDedup(ctx, "busybox:latest", nil); err == nil {
		t.Fatal("pullImageDedup() expected slot-acquire ctx error")
	}
}

func TestPullImageDedupAcquiresAndReleasesSlot(t *testing.T) {
	c := newPullClient(func(*http.Request) (*http.Response, error) {
		return textResponse(http.StatusOK, `{"status":"done"}`), nil
	})
	c.pullSlots = make(chan struct{}, 1) // empty → acquire succeeds, then releases
	if err := c.pullImageDedup(context.Background(), "busybox:latest", nil); err != nil {
		t.Fatalf("pullImageDedup() = %v", err)
	}
	if len(c.pullSlots) != 0 {
		t.Fatalf("slot not released, len = %d", len(c.pullSlots))
	}
}

// ---------------------------------------------------------------------------
// Backoff bookkeeping internals
// ---------------------------------------------------------------------------

func TestPullBackoffFailureLockedExpiry(t *testing.T) {
	c := &Client{pullBackoff: time.Minute, pullFailures: map[string]imagePullFailure{}}
	key := "k"
	c.pullFailures[key] = imagePullFailure{err: io.EOF, retryAt: time.Now().Add(-time.Minute)}
	failure, blocked := c.pullBackoffFailureLocked(key, time.Now())
	if blocked {
		t.Fatalf("expired entry should not block: %+v", failure)
	}
	if _, ok := c.pullFailures[key]; ok {
		t.Fatal("expired entry should be deleted")
	}
}

func TestRecordPullFailureLocked(t *testing.T) {
	t.Run("nil_map_init_and_store", func(t *testing.T) {
		c := &Client{pullBackoff: time.Minute} // pullFailures nil
		c.recordPullFailureLocked("k", io.ErrUnexpectedEOF)
		if _, ok := c.pullFailures["k"]; !ok {
			t.Fatal("expected failure recorded after nil-map init")
		}
	})
	t.Run("context_canceled_deletes", func(t *testing.T) {
		c := &Client{pullBackoff: time.Minute, pullFailures: map[string]imagePullFailure{"k": {}}}
		c.recordPullFailureLocked("k", context.Canceled)
		if _, ok := c.pullFailures["k"]; ok {
			t.Fatal("context.Canceled should not be recorded as a failure")
		}
	})
	t.Run("nil_err_clears", func(t *testing.T) {
		c := &Client{pullBackoff: time.Minute, pullFailures: map[string]imagePullFailure{"k": {}}}
		c.recordPullFailureLocked("k", nil)
		if _, ok := c.pullFailures["k"]; ok {
			t.Fatal("nil error should clear prior failure")
		}
	})
}

func TestPruneExpiredPullFailuresLocked(t *testing.T) {
	now := time.Now()
	t.Run("zero_budget_noop", func(t *testing.T) {
		failures := map[string]imagePullFailure{"k": {retryAt: now.Add(-time.Hour)}}
		pruneExpiredPullFailuresLocked(failures, now, 0)
		if len(failures) != 1 {
			t.Fatal("zero budget must not prune")
		}
	})
	t.Run("budget_caps_deletions", func(t *testing.T) {
		failures := map[string]imagePullFailure{
			"a": {retryAt: now.Add(-time.Hour)},
			"b": {retryAt: now.Add(-time.Hour)},
			"c": {retryAt: now.Add(time.Hour)}, // not expired
		}
		pruneExpiredPullFailuresLocked(failures, now, 1)
		// Exactly one expired entry removed; the future one stays.
		if len(failures) != 2 {
			t.Fatalf("expected one deletion under budget=1, len=%d", len(failures))
		}
		if _, ok := failures["c"]; !ok {
			t.Fatal("non-expired entry must survive")
		}
	})
}

// ---------------------------------------------------------------------------
// Pull-slot acquire/release edge cases
// ---------------------------------------------------------------------------

func TestAcquirePullSlotQueuedThenAcquires(t *testing.T) {
	c := &Client{pullSlots: make(chan struct{}, 1)}
	c.pullSlots <- struct{}{} // full → first select default, fall into queued select

	acquired := make(chan bool, 1)
	go func() {
		ok, err := c.acquirePullSlot(context.Background())
		if err == nil && ok {
			c.releasePullSlot()
		}
		acquired <- ok
	}()

	// Let the goroutine reach the blocking queued select, then free a slot.
	time.Sleep(50 * time.Millisecond)
	<-c.pullSlots
	select {
	case ok := <-acquired:
		if !ok {
			t.Fatal("expected queued acquire to succeed")
		}
	case <-time.After(time.Second):
		t.Fatal("queued acquire did not complete")
	}
}

func TestReleasePullSlotVariants(t *testing.T) {
	// nil slots → no-op.
	(&Client{}).releasePullSlot()
	// empty (non-nil) slots → default branch, no panic.
	(&Client{pullSlots: make(chan struct{}, 1)}).releasePullSlot()
	// held slot → received.
	c := &Client{pullSlots: make(chan struct{}, 1)}
	c.pullSlots <- struct{}{}
	c.releasePullSlot()
	if len(c.pullSlots) != 0 {
		t.Fatal("held slot should have been released")
	}
}

// ---------------------------------------------------------------------------
// decodePushStream: decode error + plain error field
// ---------------------------------------------------------------------------

func TestDecodePushStreamErrors(t *testing.T) {
	if err := decodePushStream(strings.NewReader(`{bad json`), nil, nil); err == nil {
		t.Fatal("decodePushStream() expected decode error")
	}
	if err := decodePushStream(strings.NewReader(`{"error":"denied"}`), nil, nil); err == nil {
		t.Fatal("decodePushStream() expected error field")
	}
}

// ---------------------------------------------------------------------------
// PushImage extra branches: missing repo, untag warn, transport error
// ---------------------------------------------------------------------------

func TestPushImageExtraBranches(t *testing.T) {
	auth := models.RegistryAuth{Username: "u", Password: "p"}

	t.Run("dest_missing_repository", func(t *testing.T) {
		c := &Client{logger: slog.Default()}
		// ":v1" → splitDestRef yields an empty repo.
		if _, err := c.PushImage(context.Background(), PushImageRequest{SourceTag: "s", DestRef: ":v1", Auth: auth}); err == nil {
			t.Fatal("PushImage() expected missing-repository error")
		}
	})

	t.Run("untag_warn_on_remove_failure", func(t *testing.T) {
		// tag (POST) succeeds, push succeeds, untag (DELETE) fails → warn branch.
		c := &Client{
			logger: slog.Default(),
			httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodDelete {
					return textResponse(http.StatusInternalServerError, "boom"), nil
				}
				return textResponse(http.StatusOK, "{}"), nil
			})},
			streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return textResponse(http.StatusOK, `{"status":"Pushed"}`), nil
			})},
		}
		if _, err := c.PushImage(context.Background(), PushImageRequest{SourceTag: "s:latest", DestRef: "ghcr.io/o/i:v1", Auth: auth}); err != nil {
			t.Fatalf("PushImage() = %v (warn path should not fail the push)", err)
		}
	})

	t.Run("push_transport_error", func(t *testing.T) {
		c := &Client{
			logger:     slog.Default(),
			httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return textResponse(http.StatusOK, "{}"), nil })},
			streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, io.ErrUnexpectedEOF
			})},
		}
		if _, err := c.PushImage(context.Background(), PushImageRequest{SourceTag: "s:latest", DestRef: "ghcr.io/o/i:v1", Auth: auth}); err == nil {
			t.Fatal("PushImage() expected push transport error")
		}
	})
}

// ---------------------------------------------------------------------------
// assembleBuildContext: non-zero tar trailer (not stripped)
// ---------------------------------------------------------------------------

func TestAssembleBuildContextNonZeroTrailer(t *testing.T) {
	// 1024 trailing bytes that are NOT all zero → the strip is skipped, the
	// extra is concatenated verbatim, and our Dockerfile is appended.
	extra := make([]byte, 1100)
	for i := range extra {
		extra[i] = 0x41 // 'A'
	}
	out, err := assembleBuildContext("FROM scratch\n", extra)
	if err != nil {
		t.Fatalf("assembleBuildContext() = %v", err)
	}
	if len(out) <= len(extra) {
		t.Fatalf("expected Dockerfile appended after extra, len=%d", len(out))
	}
}

// ---------------------------------------------------------------------------
// ExportImageTar transport error
// ---------------------------------------------------------------------------

func TestExportImageTarTransportError(t *testing.T) {
	c := &Client{logger: slog.Default(), streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	})}}
	if _, err := c.ExportImageTar(context.Background(), "img:v1"); err == nil {
		t.Fatal("ExportImageTar() expected transport error")
	}
}

// ---------------------------------------------------------------------------
// ImportImage extra branches: missing repo, transport error, stream errors
// ---------------------------------------------------------------------------

func TestImportImageExtraBranches(t *testing.T) {
	t.Run("dest_missing_repository", func(t *testing.T) {
		c := &Client{}
		if err := c.ImportImage(context.Background(), ImportImageRequest{DestTag: ":v1", Tar: strings.NewReader("x")}); err == nil {
			t.Fatal("ImportImage() expected missing-repository error")
		}
	})
	t.Run("transport_error", func(t *testing.T) {
		c := &Client{streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, io.ErrUnexpectedEOF
		})}}
		if err := c.ImportImage(context.Background(), ImportImageRequest{DestTag: "repo/img:v1", Tar: strings.NewReader("x")}); err == nil {
			t.Fatal("ImportImage() expected transport error")
		}
	})
	t.Run("decode_error", func(t *testing.T) {
		c := &Client{streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, `{bad json`), nil
		})}}
		if err := c.ImportImage(context.Background(), ImportImageRequest{DestTag: "repo/img:v1", Tar: strings.NewReader("x")}); err == nil {
			t.Fatal("ImportImage() expected decode error")
		}
	})
	t.Run("stream_error_field", func(t *testing.T) {
		c := &Client{streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, `{"error":"import failed"}`), nil
		})}}
		if err := c.ImportImage(context.Background(), ImportImageRequest{DestTag: "repo/img:v1", Tar: strings.NewReader("x")}); err == nil {
			t.Fatal("ImportImage() expected stream error field")
		}
	})
}

// ---------------------------------------------------------------------------
// ContainerStats error branch
// ---------------------------------------------------------------------------

func TestContainerStatsError(t *testing.T) {
	c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return textResponse(http.StatusInternalServerError, "boom"), nil
	})}}
	if _, err := c.ContainerStats(context.Background(), "cid"); err == nil {
		t.Fatal("ContainerStats() expected error")
	}
}

// ---------------------------------------------------------------------------
// ExecStart: response read failure (server closes after reading request)
// ---------------------------------------------------------------------------

func TestExecStartReadResponseError(t *testing.T) {
	sock := execSocketServer(t, "") // server reads then closes without responding
	c := &Client{socketPath: sock}
	if _, err := c.ExecStart(context.Background(), "exec-1", false); err == nil {
		t.Fatal("ExecStart() expected read-response error")
	}
}

// ---------------------------------------------------------------------------
// mirror_rewrite: empty repo after host → passthrough
// ---------------------------------------------------------------------------

func TestRewriteImageRefForMirrorEmptyRepo(t *testing.T) {
	cfg := defaultMirrorCfg()
	for _, ref := range []string{"ghcr.io/", "ghcr.io/:tag"} {
		got := RewriteImageRefForMirror(ref, cfg)
		if got.Rewritten {
			t.Fatalf("RewriteImageRefForMirror(%q) should pass through, got %+v", ref, got)
		}
	}
}

// keep imports referenced regardless of branch edits.
var (
	_ = net.Dial
	_ = secrets.IdentityTokenPrefix
)
