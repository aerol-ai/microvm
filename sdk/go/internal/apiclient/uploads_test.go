package apiclient

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// readUpload returns the file part of a multipart upload.
func readUpload(t *testing.T, r *http.Request) string {
	t.Helper()
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("content type: %v", err)
	}
	reader := multipart.NewReader(r.Body, params["boundary"])
	for {
		part, err := reader.NextPart()
		if err != nil {
			t.Fatalf("no file part: %v", err)
		}
		if part.FormName() == "file" {
			data, _ := io.ReadAll(part)
			return string(data)
		}
	}
}

// Plan F2 and section 10: write options go in the query after a /version
// check; a plain or atomic upload retries like any safe call (the buffered
// Go upload used to be sent once), append and create_only only on 429/503.
func TestUploadFileWithOptionsRetryTiers(t *testing.T) {
	ctx := context.Background()
	var bodies []string
	fake := &fakeToolbox{features: []string{FeatureWriteOptions}}
	fake.reply = func(r *http.Request, n int) (int, any, http.Header) {
		bodies = append(bodies, readUpload(t, r))
		if n == 0 {
			if r.URL.Query().Get("create_only") == "true" {
				return http.StatusBadGateway, nil, nil
			}
			return http.StatusServiceUnavailable, nil, nil
		}
		return http.StatusCreated, map[string]string{"path": "/x"}, nil
	}
	client, _ := fake.serve(t)

	if err := client.UploadFile(ctx, "sb-1", "/w/a.txt", []byte("hello")); err != nil {
		t.Fatalf("plain upload after a 503: %v", err)
	}
	if len(bodies) != 2 || bodies[0] != "hello" || bodies[1] != "hello" {
		t.Fatalf("bodies = %q, want the same body sent twice", bodies)
	}
	if q := fake.recorded()[0].URL.Query(); len(q) != 0 {
		t.Fatalf("plain upload query = %v, want none", q)
	}

	opts := sdktypes.UploadFileOptions{CreateOnly: true, Atomic: true, Mode: 0o600}
	var apiErr *APIError
	if err := client.UploadFileWithOptions(ctx, "sb-2", "/w/b.txt", []byte("once"), opts); !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("create_only through a 502 = %v, want the 502 (not re-sent)", err)
	}
	calls := fake.recorded()
	if len(calls) != 3 {
		t.Fatalf("calls = %d, want the create_only upload sent once", len(calls))
	}
	if q := calls[2].URL.Query(); q.Get("create_only") != "true" || q.Get("atomic") != "true" || q.Get("mode") != "600" || q.Has("append") {
		t.Fatalf("query = %v", q)
	}
	// A 503 means the server did nothing, so even an append is re-sent.
	if err := client.UploadFileWithOptions(ctx, "sb-3", "/w/c.txt", []byte("more"), sdktypes.UploadFileOptions{Append: true}); err != nil {
		t.Fatalf("append after a 503: %v", err)
	}
	calls = fake.recorded()
	if len(calls) != 5 || calls[3].URL.Query().Get("append") != "true" || calls[4].URL.Query().Get("append") != "true" {
		t.Fatalf("append calls = %d", len(calls))
	}
}

func TestUploadOptionsFailClosedOnOlderAgent(t *testing.T) {
	ctx := context.Background()
	fake := &fakeToolbox{features: []string{}}
	client, _ := fake.serve(t)
	if err := client.UploadFileWithOptions(ctx, "sb-1", "/a", []byte("x"), sdktypes.UploadFileOptions{CreateOnly: true}); !errors.Is(err, ErrUnsupportedFeature) {
		t.Fatalf("create_only on an older agent = %v", err)
	}
	if err := client.UploadFileStreamWithOptions(ctx, "sb-1", "/a", strings.NewReader("x"), sdktypes.UploadFileOptions{Mode: 0o600}); !errors.Is(err, ErrUnsupportedFeature) {
		t.Fatalf("stream with a mode on an older agent = %v", err)
	}
	if len(fake.recorded()) != 0 {
		t.Fatal("an older agent was sent an upload with options")
	}
	// A plain upload needs no check.
	if err := client.UploadFile(ctx, "sb-1", "/a", []byte("x")); err != nil {
		t.Fatalf("plain upload: %v", err)
	}
}

// A streamed body is consumed as it is sent, so it is sent once.
func TestUploadFileStreamWithOptionsIsSentOnce(t *testing.T) {
	ctx := context.Background()
	fake := &fakeToolbox{features: []string{FeatureWriteOptions}}
	fake.reply = func(r *http.Request, n int) (int, any, http.Header) {
		if got := readUpload(t, r); got != "streamed" {
			t.Errorf("body = %q", got)
		}
		return http.StatusServiceUnavailable, nil, nil
	}
	client, _ := fake.serve(t)
	err := client.UploadFileStreamWithOptions(ctx, "sb-1", "/a", strings.NewReader("streamed"), sdktypes.UploadFileOptions{Atomic: true})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable || len(fake.recorded()) != 1 {
		t.Fatalf("streamed upload = %v after %d calls, want one 503", err, len(fake.recorded()))
	}
	if fake.recorded()[0].URL.Query().Get("atomic") != "true" {
		t.Fatal("atomic not sent")
	}
}
