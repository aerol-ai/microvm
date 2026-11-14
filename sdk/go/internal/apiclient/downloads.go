package apiclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// DownloadFileStreamWithOptions opens targetPath for reading without
// buffering it; the caller must Close the body. With MaxBytes, a file the
// server says is larger is refused before any of it is read, and a body
// that grows past the limit (a file of unknown length) fails the read with
// ErrFileTooLarge. The request retries like any GET until the headers
// arrive (plans/agent-sandbox-feature-parity.md, F4).
func (c *Client) DownloadFileStreamWithOptions(ctx context.Context, id, targetPath string, opts sdktypes.DownloadFileOptions) (io.ReadCloser, error) {
	path := c.toolboxPath(id, "/files/download", url.Values{"path": {targetPath}})
	response, err := c.doWithRetry(ctx, retryIdempotent, func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
		if err != nil {
			return nil, err
		}
		c.addAuth(request)
		return request, nil
	})
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		defer response.Body.Close()
		return nil, decodeError(response)
	}
	if opts.MaxBytes <= 0 {
		return response.Body, nil
	}
	if response.ContentLength > opts.MaxBytes {
		response.Body.Close()
		return nil, fmt.Errorf("%w: %s is %d bytes, over %d", ErrFileTooLarge, targetPath, response.ContentLength, opts.MaxBytes)
	}
	return &cappedBody{ReadCloser: response.Body, left: opts.MaxBytes, path: targetPath, max: opts.MaxBytes}, nil
}

// DownloadFileWithOptions reads the whole of targetPath, up to MaxBytes.
func (c *Client) DownloadFileWithOptions(ctx context.Context, id, targetPath string, opts sdktypes.DownloadFileOptions) ([]byte, error) {
	body, err := c.DownloadFileStreamWithOptions(ctx, id, targetPath, opts)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(body)
}

// cappedBody fails the read that would pass the limit, instead of quietly
// cutting the file short.
type cappedBody struct {
	io.ReadCloser
	left, max int64
	path      string
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, fmt.Errorf("%w: %s is over %d bytes", ErrFileTooLarge, b.path, b.max)
	}
	// Read one byte past the limit to tell "exactly the limit" from "more".
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return n + int(b.left), fmt.Errorf("%w: %s is over %d bytes", ErrFileTooLarge, b.path, b.max)
	}
	return n, err
}
