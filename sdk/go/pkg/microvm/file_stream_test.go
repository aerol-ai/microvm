package microvm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestSandboxFileStreamsAndListLimit(t *testing.T) {
	var uploaded string
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sandboxes":
			queries = append(queries, r.URL.RawQuery)
			_, _ = w.Write([]byte(`[{"id":"sb-1"}]`))
		case strings.HasSuffix(r.URL.Path, "/files/upload"):
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			f, _, err := r.FormFile("file")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			b, _ := io.ReadAll(f)
			uploaded = r.FormValue("path") + "=" + string(b)
			w.WriteHeader(http.StatusCreated)
		case strings.HasSuffix(r.URL.Path, "/files/download"):
			_, _ = w.Write([]byte("contents of " + r.URL.Query().Get("path")))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}
	ctx := context.Background()
	sb := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb-1"}, client: client}

	if err := sb.UploadFileStream(ctx, "/work/a.txt", strings.NewReader("hello")); err != nil {
		t.Fatalf("UploadFileStream: %v", err)
	}
	if uploaded != "/work/a.txt=hello" {
		t.Fatalf("uploaded = %q", uploaded)
	}
	body, err := sb.DownloadFileStream(ctx, "/work/a.txt")
	if err != nil {
		t.Fatalf("DownloadFileStream: %v", err)
	}
	got, _ := io.ReadAll(body)
	_ = body.Close()
	if string(got) != "contents of /work/a.txt" {
		t.Fatalf("downloaded %q", got)
	}

	if _, _, err := client.ListPage(ctx, "", WithLimit(20)); err != nil {
		t.Fatalf("ListPage(WithLimit): %v", err)
	}
	if _, _, err := client.ListPage(ctx, "", WithLimit(0)); err != nil {
		t.Fatalf("ListPage(WithLimit(0)): %v", err)
	}
	if len(queries) != 2 || queries[0] != "limit=20" || queries[1] != "" {
		t.Fatalf("queries = %q, want [limit=20 \"\"]", queries)
	}
}
