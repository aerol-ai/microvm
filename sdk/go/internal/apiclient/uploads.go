package apiclient

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// FeatureWriteOptions is the toolboxd feature behind the upload write
// options (plans/agent-sandbox-feature-parity.md, F2). An older agent
// ignores them: create_only would replace an existing file, so an upload
// that sets one checks first.
const FeatureWriteOptions = "files.write_options"

// uploadQuery is the upload's write options as query parameters, and
// whether any is set.
func uploadQuery(opts sdktypes.UploadFileOptions) (url.Values, bool) {
	query := url.Values{}
	if opts.Append {
		query.Set("append", "true")
	}
	if opts.CreateOnly {
		query.Set("create_only", "true")
	}
	if opts.Atomic {
		query.Set("atomic", "true")
	}
	if opts.Mode != 0 {
		query.Set("mode", octalMode(opts.Mode))
	}
	return query, len(query) > 0
}

// uploadPolicy is the retry tier of an upload (plan section 10): a plain or
// atomic write leaves the same file however often it is sent, but a second
// append adds the data twice and a second create_only fails on the first
// one's file, so those retry only on 429 and 503.
func uploadPolicy(opts sdktypes.UploadFileOptions) retryPolicy {
	if opts.Append || opts.CreateOnly {
		return retryUnsentOnly
	}
	return retryIdempotent
}

func (c *Client) uploadPrepare(ctx context.Context, id string, opts sdktypes.UploadFileOptions) (string, error) {
	query, set := uploadQuery(opts)
	if set {
		if err := c.RequireToolboxFeatures(ctx, id, FeatureWriteOptions); err != nil {
			return "", err
		}
	}
	return c.baseURL + c.toolboxPath(id, "/files/upload", query), nil
}

// UploadFileWithOptions uploads data to targetPath. The body is in memory,
// so it is re-sent on the upload's retry tier (see uploadPolicy).
func (c *Client) UploadFileWithOptions(ctx context.Context, id, targetPath string, data []byte, opts sdktypes.UploadFileOptions) error {
	target, err := c.uploadPrepare(ctx, id, opts)
	if err != nil {
		return err
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("path", targetPath)
	part, err := writer.CreateFormFile("file", filepath.Base(targetPath))
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	encoded := body.Bytes()
	response, err := c.doWithRetry(ctx, uploadPolicy(opts), func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(encoded))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", writer.FormDataContentType())
		c.addAuth(request)
		return request, nil
	})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return decodeError(response)
	}
	return nil
}

// UploadFileStreamWithOptions uploads r to targetPath without holding the
// file in memory: the multipart body is produced through an io.Pipe while
// the request is sent, so memory stays at the copy buffer no matter the
// file size. It is sent once and never retried: the reader is consumed.
func (c *Client) UploadFileStreamWithOptions(ctx context.Context, id, targetPath string, r io.Reader, opts sdktypes.UploadFileOptions) error {
	target, err := c.uploadPrepare(ctx, id, opts)
	if err != nil {
		return err
	}
	pr, pw := io.Pipe()
	// Closing the read side unblocks the writer goroutine if the request
	// fails before the body is fully read.
	defer pr.Close()
	writer := multipart.NewWriter(pw)
	go func() {
		pw.CloseWithError(func() error {
			if err := writer.WriteField("path", targetPath); err != nil {
				return err
			}
			part, err := writer.CreateFormFile("file", filepath.Base(targetPath))
			if err != nil {
				return err
			}
			if _, err := io.Copy(part, r); err != nil {
				return err
			}
			return writer.Close()
		}())
	}()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, pr)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	c.addAuth(request)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return decodeError(response)
	}
	return nil
}
