package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ImportImageRequest is the input to (*Client).ImportImage. Tar carries
// the artifact bytes that become the image's single layer; DestTag is the
// local repo:tag the daemon assigns on success. The tag MUST be a local
// name (typically under BuiltImageNamespace) so the existing built-image
// GC sweeps it after the subsequent push completes — the Phase 6 PR 6-B.1
// template-push pipeline relies on this.
type ImportImageRequest struct {
	DestTag string
	Tar     io.Reader
}

// ImportImage streams a tarball into the Docker daemon's "import from
// tarball" endpoint (POST /images/create?fromSrc=-&repo=<tag>) and tags
// the result as DestTag. Mirrors the pullImage transport choice
// (streamClient) so a large rootfs.ext4 layer doesn't trip an
// http.Client.Timeout — the import scans the whole tar before the daemon
// flushes its response, so the read can be slow.
//
// The contract is "after a nil return, DestTag exists locally". The
// template push pipeline then hands DestTag to PushImage exactly the
// way the snapshot push pipeline hands its commit-produced tag in;
// keeping the surfaces parallel means a single mental model for both
// halves of "AOCR replication."
func (c *Client) ImportImage(ctx context.Context, req ImportImageRequest) error {
	dest := strings.TrimSpace(req.DestTag)
	if dest == "" {
		return errors.New("import image: dest tag is required")
	}
	if req.Tar == nil {
		return errors.New("import image: tar reader is required")
	}
	repo, tag := splitDestRef(dest)
	if repo == "" {
		return fmt.Errorf("import image: dest tag %q is missing a repository", dest)
	}

	// fromSrc=- tells the daemon the layer is in the request body (any
	// other value is treated as a URL to fetch). repo+tag land the
	// resulting image under our chosen local name in one shot — no
	// follow-up /tag call needed.
	query := url.Values{}
	query.Set("fromSrc", "-")
	query.Set("repo", repo)
	if tag != "" {
		query.Set("tag", tag)
	}
	target := "http://docker/images/create?" + query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, req.Tar)
	if err != nil {
		return fmt.Errorf("import image: %w", err)
	}
	// application/x-tar is what the Docker engine API documents for
	// fromSrc=-; sending application/json (the default for our other
	// helpers) makes the daemon misparse the body as Image-from-URL.
	request.Header.Set("Content-Type", "application/x-tar")

	response, err := c.streamClient.Do(request)
	if err != nil {
		return fmt.Errorf("import image: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		data, _ := io.ReadAll(response.Body)
		return fmt.Errorf("docker API POST /images/create (fromSrc=-) failed with status %d: %s",
			response.StatusCode, strings.TrimSpace(string(data)))
	}
	// Docker reports import failures inside the NDJSON stream with HTTP
	// 200 — same shape as pullImage. Without scanning the body, a
	// malformed tar or daemon-side error silently surfaces as "success
	// followed by a missing local image" at the next inspect, which is
	// painful to debug. Mirror the pull-path decoder shape so the failure
	// surfaces here with the daemon's own error string.
	decoder := json.NewDecoder(response.Body)
	for {
		var msg struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := decoder.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode import stream: %w", err)
		}
		if msg.ErrorDetail.Message != "" {
			return fmt.Errorf("import image %s: %s", dest, msg.ErrorDetail.Message)
		}
		if msg.Error != "" {
			return fmt.Errorf("import image %s: %s", dest, msg.Error)
		}
	}
}
