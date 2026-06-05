package docker

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// ---------------------------------------------------------------------------
// exec.go
// ---------------------------------------------------------------------------

func TestExecCreate(t *testing.T) {
	t.Run("empty_container", func(t *testing.T) {
		c := &Client{}
		if _, err := c.ExecCreate(context.Background(), "", []string{"sh"}, nil, "", false); err == nil {
			t.Fatal("ExecCreate() expected empty-container error")
		}
	})
	t.Run("empty_cmd", func(t *testing.T) {
		c := &Client{}
		if _, err := c.ExecCreate(context.Background(), "cid", nil, nil, "", false); err == nil {
			t.Fatal("ExecCreate() expected empty-cmd error")
		}
	})
	t.Run("success_with_env_and_workdir", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if !strings.HasSuffix(r.URL.Path, "/exec") {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			return jsonResponse(http.StatusCreated, map[string]string{"Id": "exec-1"}), nil
		})}}
		id, err := c.ExecCreate(context.Background(), "cid", []string{"sh", "-c", "ls"}, []string{"A=B"}, "/work", true)
		if err != nil || id != "exec-1" {
			t.Fatalf("ExecCreate() = %q, %v", id, err)
		}
	})
	t.Run("empty_exec_id_returned", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusCreated, map[string]string{"Id": ""}), nil
		})}}
		if _, err := c.ExecCreate(context.Background(), "cid", []string{"sh"}, nil, "", false); err == nil {
			t.Fatal("ExecCreate() expected empty-ID error")
		}
	})
	t.Run("api_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "boom"), nil
		})}}
		if _, err := c.ExecCreate(context.Background(), "cid", []string{"sh"}, nil, "", false); err == nil {
			t.Fatal("ExecCreate() expected API error")
		}
	})
}

func TestExecResize(t *testing.T) {
	t.Run("empty_exec_id", func(t *testing.T) {
		c := &Client{}
		if err := c.ExecResize(context.Background(), "", 24, 80); err == nil {
			t.Fatal("ExecResize() expected empty-ID error")
		}
	})
	t.Run("non_positive_dims_noop", func(t *testing.T) {
		c := &Client{}
		if err := c.ExecResize(context.Background(), "exec-1", 0, 80); err != nil {
			t.Fatalf("ExecResize() noop = %v", err)
		}
	})
	t.Run("success", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if !strings.HasSuffix(r.URL.Path, "/resize") {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			return textResponse(http.StatusOK, "{}"), nil
		})}}
		if err := c.ExecResize(context.Background(), "exec-1", 24, 80); err != nil {
			t.Fatalf("ExecResize() = %v", err)
		}
	})
	t.Run("api_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "boom"), nil
		})}}
		if err := c.ExecResize(context.Background(), "exec-1", 24, 80); err == nil {
			t.Fatal("ExecResize() expected API error")
		}
	})
}

func TestExecInspect(t *testing.T) {
	t.Run("empty_exec_id", func(t *testing.T) {
		c := &Client{}
		if _, _, err := c.ExecInspect(context.Background(), ""); err == nil {
			t.Fatal("ExecInspect() expected empty-ID error")
		}
	})
	t.Run("success", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, map[string]any{"ExitCode": 3, "Running": false}), nil
		})}}
		code, running, err := c.ExecInspect(context.Background(), "exec-1")
		if err != nil || code != 3 || running {
			t.Fatalf("ExecInspect() = %d, %v, %v", code, running, err)
		}
	})
	t.Run("api_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "boom"), nil
		})}}
		if _, _, err := c.ExecInspect(context.Background(), "exec-1"); err == nil {
			t.Fatal("ExecInspect() expected API error")
		}
	})
}

func TestExecSessionClose(t *testing.T) {
	// nil receiver and nil conn are both no-ops.
	var nilSession *ExecSession
	if err := nilSession.Close(); err != nil {
		t.Fatalf("nil session Close() = %v", err)
	}
	if err := (&ExecSession{}).Close(); err != nil {
		t.Fatalf("nil conn Close() = %v", err)
	}

	// A real (piped) conn is closed.
	server, client := net.Pipe()
	defer server.Close()
	s := &ExecSession{Conn: client}
	if err := s.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
}

func TestExecStart(t *testing.T) {
	t.Run("empty_exec_id", func(t *testing.T) {
		c := &Client{}
		if _, err := c.ExecStart(context.Background(), "", false); err == nil {
			t.Fatal("ExecStart() expected empty-ID error")
		}
	})

	t.Run("dial_failure", func(t *testing.T) {
		c := &Client{socketPath: filepath.Join(t.TempDir(), "nonexistent.sock")}
		if _, err := c.ExecStart(context.Background(), "exec-1", false); err == nil {
			t.Fatal("ExecStart() expected dial error")
		}
	})

	t.Run("success_101", func(t *testing.T) {
		sock := execSocketServer(t, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
		c := &Client{socketPath: sock}
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(2*time.Second))
		defer cancel()
		sess, err := c.ExecStart(ctx, "exec-1", true)
		if err != nil {
			t.Fatalf("ExecStart() = %v", err)
		}
		if sess.ID != "exec-1" {
			t.Fatalf("ExecStart() session ID = %q", sess.ID)
		}
		sess.Close()
	})

	t.Run("non_101_status", func(t *testing.T) {
		sock := execSocketServer(t, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\n\r\nboom")
		c := &Client{socketPath: sock}
		if _, err := c.ExecStart(context.Background(), "exec-1", false); err == nil {
			t.Fatal("ExecStart() expected non-101 error")
		}
	})
}

// execSocketServer listens on a unix socket, reads one HTTP request, and writes
// the canned response back. Returns the socket path.
func execSocketServer(t *testing.T, response string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "exec.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Drain the request line + headers so the client's write doesn't block.
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		// The exec start body follows; we don't need to read it to respond.
		_, _ = conn.Write([]byte(response))
		// Give the client time to read before the deferred Close tears down.
		time.Sleep(200 * time.Millisecond)
	}()
	return sock
}

// ---------------------------------------------------------------------------
// events.go: StreamEvents
// ---------------------------------------------------------------------------

func TestStreamEvents(t *testing.T) {
	t.Run("subscribe_error", func(t *testing.T) {
		c := &Client{streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, io.ErrUnexpectedEOF
		})}}
		out := make(chan DockerEvent, 1)
		if err := c.StreamEvents(context.Background(), out); err == nil {
			t.Fatal("StreamEvents() expected subscribe error")
		}
	})

	t.Run("non_200", func(t *testing.T) {
		c := &Client{streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "boom"), nil
		})}}
		out := make(chan DockerEvent, 1)
		if err := c.StreamEvents(context.Background(), out); err == nil {
			t.Fatal("StreamEvents() expected non-200 error")
		}
	})

	t.Run("streams_events_then_eof", func(t *testing.T) {
		// One event that normalizes (has name+action), one that doesn't (no id).
		body := `{"Action":"die","id":"cid","time":1700000000,"Actor":{"Attributes":{"name":"/sb-1","exitCode":"0"}}}` +
			`{"Action":"start","id":"","Actor":{"Attributes":{}}}`
		c := &Client{streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, body), nil
		})}}
		out := make(chan DockerEvent, 4)
		if err := c.StreamEvents(context.Background(), out); err != nil {
			t.Fatalf("StreamEvents() = %v", err)
		}
		select {
		case ev := <-out:
			if ev.SandboxID != "sb-1" || ev.Action != "die" {
				t.Fatalf("unexpected event %+v", ev)
			}
		default:
			t.Fatal("expected at least one event")
		}
	})

	t.Run("decode_error", func(t *testing.T) {
		c := &Client{streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, `{not json`), nil
		})}}
		out := make(chan DockerEvent, 1)
		if err := c.StreamEvents(context.Background(), out); err == nil {
			t.Fatal("StreamEvents() expected decode error")
		}
	})

	t.Run("ctx_done_on_send", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // already cancelled → the send select hits <-ctx.Done()
		body := `{"Action":"die","id":"cid","time":1700000000,"Actor":{"Attributes":{"name":"/sb-1"}}}`
		c := &Client{streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, body), nil
		})}}
		out := make(chan DockerEvent) // unbuffered → send would block, forcing ctx branch
		if err := c.StreamEvents(ctx, out); err != nil {
			t.Fatalf("StreamEvents() = %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// build.go: BuildImage, PushImage, ImageExists, ListBuiltImages, RefreshTag
// ---------------------------------------------------------------------------

func TestBuildImage(t *testing.T) {
	t.Run("empty_tag", func(t *testing.T) {
		c := &Client{}
		if err := c.BuildImage(context.Background(), BuildImageRequest{}); err == nil {
			t.Fatal("BuildImage() expected empty-tag error")
		}
	})

	t.Run("empty_dockerfile", func(t *testing.T) {
		c := &Client{}
		if err := c.BuildImage(context.Background(), BuildImageRequest{Tag: "t:1", DockerfileContent: "   "}); err == nil {
			t.Fatal("BuildImage() expected empty-dockerfile error")
		}
	})

	t.Run("success_with_context_and_logs", func(t *testing.T) {
		var logs []string
		c := &Client{streamClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/build" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			return textResponse(http.StatusOK, `{"stream":"Step 1/2\nStep 2/2\n"}`), nil
		})}}
		req := BuildImageRequest{
			Tag:               "aerolvm-build/x:latest",
			DockerfileContent: "FROM scratch",
			ContextTar:        makeTar(t, map[string]string{"a.txt": "hi"}),
			OnLog:             func(line string) { logs = append(logs, line) },
		}
		if err := c.BuildImage(context.Background(), req); err != nil {
			t.Fatalf("BuildImage() = %v", err)
		}
		if len(logs) == 0 {
			t.Fatal("BuildImage() expected forwarded log lines")
		}
	})

	t.Run("http_error", func(t *testing.T) {
		c := &Client{streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusBadRequest, "bad dockerfile"), nil
		})}}
		req := BuildImageRequest{Tag: "t:1", DockerfileContent: "FROM scratch"}
		if err := c.BuildImage(context.Background(), req); err == nil {
			t.Fatal("BuildImage() expected HTTP error")
		}
	})

	t.Run("stream_error", func(t *testing.T) {
		c := &Client{streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, `{"error":"build failed"}`), nil
		})}}
		req := BuildImageRequest{Tag: "t:2", DockerfileContent: "FROM scratch"}
		if err := c.BuildImage(context.Background(), req); err == nil {
			t.Fatal("BuildImage() expected stream error")
		}
	})

	t.Run("transport_error", func(t *testing.T) {
		c := &Client{streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, io.ErrUnexpectedEOF
		})}}
		req := BuildImageRequest{Tag: "t:3", DockerfileContent: "FROM scratch"}
		if err := c.BuildImage(context.Background(), req); err == nil {
			t.Fatal("BuildImage() expected transport error")
		}
	})
}

func TestPushImage(t *testing.T) {
	validAuth := models.RegistryAuth{Username: "u", Password: "p", Server: "ghcr.io"}

	t.Run("validations", func(t *testing.T) {
		c := &Client{}
		cases := []PushImageRequest{
			{SourceTag: "", DestRef: "d"},
			{SourceTag: "s", DestRef: ""},
			{SourceTag: "s", DestRef: "d", Auth: models.RegistryAuth{}},
		}
		for i, req := range cases {
			if _, err := c.PushImage(context.Background(), req); err == nil {
				t.Fatalf("PushImage() case %d expected validation error", i)
			}
		}
	})

	t.Run("tag_error", func(t *testing.T) {
		c := &Client{
			logger: slog.Default(),
			httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return textResponse(http.StatusInternalServerError, "boom"), nil
			})},
		}
		req := PushImageRequest{SourceTag: "src:latest", DestRef: "ghcr.io/org/img:v1", Auth: validAuth}
		if _, err := c.PushImage(context.Background(), req); err == nil {
			t.Fatal("PushImage() expected tag error")
		}
	})

	t.Run("success_with_log_and_digest", func(t *testing.T) {
		var gotLog, gotDigest string
		c := &Client{
			logger: slog.Default(),
			httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				// tag + untag (DELETE) both go through httpClient.
				return textResponse(http.StatusOK, "{}"), nil
			})},
			streamClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if !strings.Contains(r.URL.Path, "/push") {
					t.Fatalf("unexpected stream path %s", r.URL.Path)
				}
				return textResponse(http.StatusOK, `{"status":"Pushing"}`+"\n"+`{"aux":{"Digest":"sha256:abc"}}`), nil
			})},
		}
		req := PushImageRequest{
			SourceTag: "src:latest",
			DestRef:   "ghcr.io/org/img:v1",
			Auth:      validAuth,
			OnLog:     func(line string) { gotLog = line },
			OnDigest:  func(d string) { gotDigest = d },
		}
		pushed, err := c.PushImage(context.Background(), req)
		if err != nil {
			t.Fatalf("PushImage() = %v", err)
		}
		if pushed != "ghcr.io/org/img:v1" {
			t.Fatalf("PushImage() returned %q", pushed)
		}
		if gotLog == "" || gotDigest != "sha256:abc" {
			t.Fatalf("PushImage() log=%q digest=%q", gotLog, gotDigest)
		}
	})

	t.Run("push_http_error", func(t *testing.T) {
		c := &Client{
			logger:     slog.Default(),
			httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return textResponse(http.StatusOK, "{}"), nil })},
			streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return textResponse(http.StatusUnauthorized, "denied"), nil
			})},
		}
		req := PushImageRequest{SourceTag: "src:latest", DestRef: "ghcr.io/org/img:v1", Auth: validAuth}
		if _, err := c.PushImage(context.Background(), req); err == nil {
			t.Fatal("PushImage() expected push HTTP error")
		}
	})

	t.Run("push_stream_error", func(t *testing.T) {
		c := &Client{
			logger:     slog.Default(),
			httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return textResponse(http.StatusOK, "{}"), nil })},
			streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return textResponse(http.StatusOK, `{"errorDetail":{"message":"quota exceeded"}}`), nil
			})},
		}
		req := PushImageRequest{SourceTag: "src:latest", DestRef: "ghcr.io/org/img:v1", Auth: validAuth}
		if _, err := c.PushImage(context.Background(), req); err == nil {
			t.Fatal("PushImage() expected push stream error")
		}
	})
}

func TestImageExists(t *testing.T) {
	t.Run("exists", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, "{}"), nil
		})}}
		ok, err := c.ImageExists(context.Background(), "img")
		if err != nil || !ok {
			t.Fatalf("ImageExists() = %v, %v", ok, err)
		}
	})
	t.Run("not_found_no_such_image", func(t *testing.T) {
		// The "no such image" substring branch (distinct from the bare 404 path).
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "no such image: img"), nil
		})}}
		ok, err := c.ImageExists(context.Background(), "img")
		if err != nil || ok {
			t.Fatalf("ImageExists() = %v, %v", ok, err)
		}
	})
	t.Run("not_found_404", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusNotFound, "boom"), nil
		})}}
		ok, err := c.ImageExists(context.Background(), "img")
		if err != nil || ok {
			t.Fatalf("ImageExists() = %v, %v", ok, err)
		}
	})
	t.Run("other_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, io.ErrUnexpectedEOF
		})}}
		if _, err := c.ImageExists(context.Background(), "img"); err == nil {
			t.Fatal("ImageExists() expected transport error")
		}
	})
}

func TestListBuiltImages(t *testing.T) {
	t.Run("filters_and_inspects", func(t *testing.T) {
		c := &Client{
			logger: slog.Default(),
			httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.URL.Path == "/images/json":
					return jsonResponse(http.StatusOK, []map[string]any{
						{"RepoTags": []string{BuiltImageNamespace + "/keep:latest", "other/img:latest"}},
						{"RepoTags": []string{BuiltImageNamespace + "/inspect-fails:latest"}},
					}), nil
				case strings.Contains(r.URL.Path, "inspect-fails"):
					return textResponse(http.StatusInternalServerError, "boom"), nil
				case strings.HasPrefix(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/json"):
					return jsonResponse(http.StatusOK, map[string]any{
						"Metadata": map[string]any{"LastTagTime": "2024-01-01T00:00:00Z"},
					}), nil
				default:
					t.Fatalf("unexpected path %s", r.URL.Path)
					return nil, nil
				}
			})},
		}
		images, err := c.ListBuiltImages(context.Background())
		if err != nil {
			t.Fatalf("ListBuiltImages() = %v", err)
		}
		if len(images) != 1 || images[0].Tag != BuiltImageNamespace+"/keep:latest" {
			t.Fatalf("ListBuiltImages() = %+v", images)
		}
	})

	t.Run("list_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "boom"), nil
		})}}
		if _, err := c.ListBuiltImages(context.Background()); err == nil {
			t.Fatal("ListBuiltImages() expected list error")
		}
	})
}

func TestRefreshTag(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if !strings.HasSuffix(r.URL.Path, "/tag") {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			return textResponse(http.StatusCreated, ""), nil
		})}}
		if err := c.RefreshTag(context.Background(), "aerolvm-build/x:latest"); err != nil {
			t.Fatalf("RefreshTag() = %v", err)
		}
	})

	t.Run("tag_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "boom"), nil
		})}}
		if err := c.RefreshTag(context.Background(), "aerolvm-build/x:latest"); err == nil {
			t.Fatal("RefreshTag() expected tag error")
		}
	})
}

// ---------------------------------------------------------------------------
// export.go: PullImage
// ---------------------------------------------------------------------------

func TestPullImageWrapper(t *testing.T) {
	t.Run("empty_ref", func(t *testing.T) {
		c := &Client{}
		if err := c.PullImage(context.Background(), "  ", nil); err == nil {
			t.Fatal("PullImage() expected empty-ref error")
		}
	})

	t.Run("success", func(t *testing.T) {
		c := &Client{
			logger: slog.Default(),
			streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return textResponse(http.StatusOK, `{"status":"done"}`), nil
			})},
			pulls:        map[string]*imagePull{},
			pullFailures: map[string]imagePullFailure{},
		}
		if err := c.PullImage(context.Background(), "busybox:latest", &models.RegistryAuth{}); err != nil {
			t.Fatalf("PullImage() = %v", err)
		}
	})
}

// keep os import used even if all other refs change.
var _ = os.WriteFile
