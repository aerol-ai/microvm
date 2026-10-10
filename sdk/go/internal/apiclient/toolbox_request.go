package apiclient

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ToolboxRequest sends one authenticated request to the sandbox toolbox
// (path such as "/files" or "/process/execute", relative to
// /sandboxes/{id}/toolbox) and returns the raw response for the caller to
// read and close. It is the escape hatch for toolbox endpoints the SDK has no
// typed method for, and for callers that must bound how much of a response
// they read. A 4xx/5xx comes back as an *APIError with the body consumed.
//
// GET and HEAD retry on transient statuses like every other read. A request
// with a body is sent once: toolbox writes and exec are not idempotent.
func (c *Client) ToolboxRequest(ctx context.Context, sandboxID, method, path string, query url.Values, body []byte, contentType string) (*http.Response, error) {
	target := c.baseURL + c.versionPrefix + "/sandboxes/" + url.PathEscape(sandboxID) + "/toolbox/" + strings.TrimPrefix(path, "/")
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	build := func() (*http.Request, error) {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		request, err := http.NewRequestWithContext(ctx, method, target, reader)
		if err != nil {
			return nil, err
		}
		if body != nil && contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		c.addAuth(request)
		return request, nil
	}
	var response *http.Response
	var err error
	if body == nil && (method == http.MethodGet || method == http.MethodHead) {
		response, err = c.doWithRetry(ctx, retryIdempotent, build)
	} else {
		var request *http.Request
		request, err = build()
		if err != nil {
			return nil, err
		}
		response, err = c.httpClient.Do(request)
	}
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		defer response.Body.Close()
		return nil, decodeError(response)
	}
	return response, nil
}
