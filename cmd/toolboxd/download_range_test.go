package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Plan F4: downloads answer Range and HEAD through http.ServeContent.
func TestDownloadRangeAndHead(t *testing.T) {
	srv := httptest.NewServer(authedRoutes(newDaytonaTestServer(t)))
	t.Cleanup(srv.Close)
	path := filepath.Join(t.TempDir(), "data.bin")
	data := bytes.Repeat([]byte("0123456789"), 100) // 1000 bytes
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	target := srv.URL + "/files/download?path=" + url.QueryEscape(path)
	do := func(method string, header map[string]string) (*http.Response, []byte) {
		req, _ := http.NewRequest(method, target, nil)
		req.Header.Set("Authorization", "Bearer "+testToolboxToken)
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, body
	}

	cases := []struct {
		name         string
		method       string
		header       map[string]string
		status       int
		body         []byte
		contentRange string
	}{
		{name: "whole file", method: http.MethodGet, status: http.StatusOK, body: data},
		{name: "a range", method: http.MethodGet, header: map[string]string{"Range": "bytes=10-19"}, status: http.StatusPartialContent, body: data[10:20], contentRange: "bytes 10-19/1000"},
		{name: "an open range", method: http.MethodGet, header: map[string]string{"Range": "bytes=995-"}, status: http.StatusPartialContent, body: data[995:], contentRange: "bytes 995-999/1000"},
		{name: "the last bytes", method: http.MethodGet, header: map[string]string{"Range": "bytes=-3"}, status: http.StatusPartialContent, body: data[997:], contentRange: "bytes 997-999/1000"},
		{name: "past the end", method: http.MethodGet, header: map[string]string{"Range": "bytes=5000-6000"}, status: http.StatusRequestedRangeNotSatisfiable, contentRange: "bytes */1000"},
		{name: "head", method: http.MethodHead, status: http.StatusOK, body: []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := do(tc.method, tc.header)
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if tc.body != nil && !bytes.Equal(body, tc.body) {
				t.Fatalf("body = %q", body)
			}
			if got := resp.Header.Get("Content-Range"); got != tc.contentRange {
				t.Fatalf("Content-Range = %q, want %q", got, tc.contentRange)
			}
			// A 416 is the standard library's plain-text error.
			if resp.StatusCode/100 == 2 && (resp.Header.Get("Content-Type") != "application/octet-stream" || resp.Header.Get("Accept-Ranges") != "bytes") {
				t.Fatalf("headers = %v", resp.Header)
			}
		})
	}
	resp, _ := do(http.MethodHead, nil)
	if resp.Header.Get("Content-Length") != strconv.Itoa(len(data)) || resp.Header.Get("Last-Modified") == "" {
		t.Fatalf("HEAD headers = %v", resp.Header)
	}
	resp, _ = do(http.MethodGet, map[string]string{"If-Modified-Since": time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)})
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("If-Modified-Since = %d, want 304", resp.StatusCode)
	}
	resp, _ = do(http.MethodHead, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("HEAD not routed")
	}
}

// A file whose length is unknown (a /proc file, whose size reads as 0)
// streams to the end with no Content-Length. A named pipe is refused, not
// streamed: its open waited for a writer (TestFileRoutesRefuseNamedPipes).
func TestDownloadUnknownLengthStreams(t *testing.T) {
	const proc = "/proc/self/status"
	if info, err := os.Stat(proc); err != nil || info.Size() != 0 {
		t.Skip("no /proc file whose size reads as 0 here")
	}
	rr := httptest.NewRecorder()
	authedRoutes(newDaytonaTestServer(t)).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/files/download?path="+url.QueryEscape(proc), nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Name:") || rr.Header().Get("Content-Length") != "" {
		t.Fatalf("/proc download = %d %q %v", rr.Code, rr.Body.String(), rr.Header())
	}
	empty := filepath.Join(t.TempDir(), "empty")
	_ = os.WriteFile(empty, nil, 0o644)
	rr = httptest.NewRecorder()
	authedRoutes(newDaytonaTestServer(t)).ServeHTTP(rr, httptest.NewRequest(http.MethodHead, "/files/download?path="+url.QueryEscape(empty), nil))
	if rr.Code != http.StatusOK || rr.Body.Len() != 0 {
		t.Fatalf("HEAD of an empty file = %d %q", rr.Code, rr.Body.String())
	}
}
