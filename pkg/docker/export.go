package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// ExportImageTar streams `GET /images/{name}/get` (the daemon-side equivalent
// of `docker save <ref>`) and hands the caller back the raw tar body. The
// returned stream is an uncompressed tar in the docker-save layout
// (manifest.json + repositories + per-layer-sha directories each containing
// layer.tar). Closing the returned stream releases the underlying response.
//
// This is the consumer-side pair to ImportImage in the PR 6-B template-push
// pipeline: a remote node imports a template artifact tar as a single-layer
// image, pushes it to AOCR, and the consumer pulls + exports it to get the
// original tar bytes back out. Uses streamClient (no timeout) because
// rootfs.ext4 can run hundreds of MB and http.Client.Timeout covers the
// entire response body read.
func (c *Client) ExportImageTar(ctx context.Context, ref string) (io.ReadCloser, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("export image: ref is required")
	}
	target := "http://docker/images/" + url.PathEscape(ref) + "/get"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("export image: %w", err)
	}
	response, err := c.streamClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("export image: %w", err)
	}
	if response.StatusCode >= 400 {
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf("docker API GET /images/%s/get failed with status %d: %s",
			ref, response.StatusCode, strings.TrimSpace(string(data)))
	}
	return response.Body, nil
}

// PullImage is the exported single-call pull wrapper the template puller
// uses. Goes through pullImageDedup so concurrent first-callers for the
// same ref collapse to one daemon request — the same dedup that protects
// the create-sandbox pull path. Auth is optional: nil means anonymous,
// except that pullImageDedup back-fills the cluster PAT for AOCR
// `cluster/...` refs when ConfigureAOCRPullAuth has been called (see
// aocr_pull_auth.go), so the template puller can pass nil and still
// authenticate against a private AOCR.
func (c *Client) PullImage(ctx context.Context, ref string, auth *models.RegistryAuth) error {
	if strings.TrimSpace(ref) == "" {
		return errors.New("pull image: ref is required")
	}
	return c.pullImageDedup(ctx, ref, auth)
}
